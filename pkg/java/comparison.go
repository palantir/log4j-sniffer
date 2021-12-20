// Copyright (c) 2021 Palantir Technologies. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package java

import (
	"bytes"
	"sort"
)

type PartialMatch struct {
	Prefix        []byte
	Suffix        []byte
	AmountSkipped int
}

type MethodByteCodeComparison struct {
	FirstClassMethodBytecode     [][]byte
	FirstClassUnmatchedBytecode  [][]byte
	SecondClassMethodBytecode    [][]byte
	SecondClassUnmatchedBytecode [][]byte
	ExactMatches                 [][]byte
	PartialMatches               []PartialMatch
}

func CompareClasses(firstJarName, firstClassName, secondJarName, secondClassName string) (MethodByteCodeComparison, error) {
	firstBytecode, err := ReadMethodByteCode(firstJarName, firstClassName)
	if err != nil {
		return MethodByteCodeComparison{}, err
	}

	secondBytecode, err := ReadMethodByteCode(secondJarName, secondClassName)
	if err != nil {
		return MethodByteCodeComparison{}, err
	}

	var exactMatches [][]byte
	for i, firstClassMethodBytecode := range firstBytecode {
		for j, secondClassMethodBytecode := range secondBytecode {
			if bytes.Compare(firstClassMethodBytecode, secondClassMethodBytecode) == 0 {
				exactMatches = append(exactMatches, firstClassMethodBytecode)
				firstBytecode[i] = nil
				secondBytecode[j] = nil
			}
		}
	}

	sort.SliceStable(firstBytecode, func(i, j int) bool {
		return len(firstBytecode[i]) > len(firstBytecode[j])
	})
	sort.SliceStable(secondBytecode, func(i, j int) bool {
		return len(secondBytecode[i]) > len(secondBytecode[j])
	})

	var partialMatches []PartialMatch
	for i, firstClassMethodBytecode := range firstBytecode {
		if len(firstClassMethodBytecode) < 3 {
			// Can't have a partial match unless there are enough opcodes
			continue
		}
		bestMatchIndex := -1
		bestMatchPrefixLength := 0
		bestMatchSuffixLength := 0
		for j, secondClassMethodBytecode := range secondBytecode {
			if len(secondClassMethodBytecode) < 3 {
				continue
			}
			x := 0
			y := len(firstClassMethodBytecode)
			z := len(secondClassMethodBytecode)
			for x < len(firstClassMethodBytecode) && x < len(secondClassMethodBytecode) && firstClassMethodBytecode[x] == secondClassMethodBytecode[x] {
				x++
			}
			for y > x && z > x && firstClassMethodBytecode[y-1] == secondClassMethodBytecode[z-1] {
				y--
				z--
			}
			if x < 1 || y == len(firstClassMethodBytecode) {
				// No match at one or both of the ends
				continue
			}

			matchLength := x + len(firstClassMethodBytecode) - y
			if matchLength > bestMatchPrefixLength+bestMatchSuffixLength {
				bestMatchIndex = j
				bestMatchPrefixLength = x
				bestMatchSuffixLength = len(firstClassMethodBytecode) - y
			}
		}

		if bestMatchIndex > -1 {
			suffixIndex := len(firstClassMethodBytecode) - bestMatchSuffixLength
			partialMatches = append(partialMatches, PartialMatch{
				Prefix:        firstClassMethodBytecode[:bestMatchPrefixLength],
				Suffix:        firstClassMethodBytecode[suffixIndex:],
				AmountSkipped: len(firstClassMethodBytecode) - bestMatchSuffixLength,
			})
			firstBytecode[i] = nil
			secondBytecode[bestMatchIndex] = nil
		}
	}

	var unmatchedFirstClassBytecode [][]byte
	for _, bytecode := range firstBytecode {
		if bytecode != nil {
			unmatchedFirstClassBytecode = append(unmatchedFirstClassBytecode, bytecode)
		}
	}

	var unmatchedSecondClassBytecode [][]byte
	for _, bytecode := range secondBytecode {
		if bytecode != nil {
			unmatchedFirstClassBytecode = append(unmatchedSecondClassBytecode, bytecode)
		}
	}

	firstBytecode, err = ReadMethodByteCode(firstJarName, firstClassName)
	if err != nil {
		return MethodByteCodeComparison{}, err
	}

	secondBytecode, err = ReadMethodByteCode(secondJarName, secondClassName)
	if err != nil {
		return MethodByteCodeComparison{}, err
	}

	return MethodByteCodeComparison{
		FirstClassMethodBytecode:     firstBytecode,
		FirstClassUnmatchedBytecode:  unmatchedFirstClassBytecode,
		SecondClassMethodBytecode:    secondBytecode,
		SecondClassUnmatchedBytecode: unmatchedSecondClassBytecode,
		ExactMatches:                 exactMatches,
		PartialMatches:               partialMatches,
	}, nil
}
