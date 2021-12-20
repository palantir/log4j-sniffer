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

package crawl

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"

	"github.com/palantir/log4j-sniffer/pkg/java"
)

const maxClassSize = 0xffff

var classByteBuf bytes.Buffer = bytes.Buffer{}

func lookForHashMatch(contents io.Reader, size int64) (Finding, string, bool) {
	if size > maxClassSize {
		return NothingDetected, UnknownVersion, false
	}
	classByteBuf.Reset()
	_, err := classByteBuf.ReadFrom(contents)
	if err != nil {
		return NothingDetected, UnknownVersion, false
	}
	version, md5Match := classMd5Version(classByteBuf.Bytes())
	if md5Match {
		return ClassFileMd5, version, true
	}
	version, md5Match = bytecodeMd5Version(classByteBuf.Bytes())
	if md5Match {
		return ClassBytecodeInstructionMd5, version, true
	}
	version, partialBytecodeMatch := bytecodePartialMatch(classByteBuf.Bytes())
	if partialBytecodeMatch {
		return ClassBytecodePartialMatch, version, true
	}
	return NothingDetected, UnknownVersion, false
}

func classMd5Version(classContents []byte) (string, bool) {
	sum := md5.New()
	if _, err := sum.Write(classContents); err != nil {
		return "", false
	}
	hash := fmt.Sprintf("%x", sum.Sum(nil))
	version, matches := classMd5s[hash]
	return version, matches
}

func bytecodeMd5Version(classContents []byte) (string, bool) {
	hash, err := java.HashClassInstructions(classContents)
	if err != nil {
		return UnknownVersion, false
	}
	version, matches := bytecodeMd5s[hash]
	return version, matches
}

func bytecodePartialMatch(classContents []byte) (string, bool) {
	methodBytecodes, err := java.ExtractBytecode(classContents)
	if err != nil {
		return UnknownVersion, false
	}

	for _, bytecodeSignature := range partialBytecodeSignatures {
		match := bytecodeMatches(methodBytecodes, bytecodeSignature)
		if match {
			return bytecodeSignature.Version, true
		}
	}
	return UnknownVersion, false
}

func bytecodeMatches(methodBytecodes [][]byte, signature PartialBytecodeSignature) bool {
	for _, exactMatch := range signature.ExactMatches {
		matchIndex := -1
		for i, methodBytecode := range methodBytecodes {
			if bytes.Compare(exactMatch, methodBytecode) == 0 {
				matchIndex = i
				break
			}
		}
		if matchIndex == -1 {
			return false
		}
		methodBytecodes[matchIndex] = nil
	}

	for _, partialMatch := range signature.PartialMatches {
		matchIndex := -1
		for i, methodBytecode := range methodBytecodes {
			if len(methodBytecode) < len(partialMatch.Prefix)+len(partialMatch.Suffix) {
				continue
			}
			matched := true
			for x := 0; x < len(partialMatch.Prefix); x++ {
				if partialMatch.Prefix[x] != methodBytecode[x] {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			bytecodeLength, suffixLength := len(methodBytecode), len(partialMatch.Suffix)
			for x := 0; x < suffixLength; x++ {
				if partialMatch.Suffix[suffixLength-x-1] != methodBytecode[bytecodeLength-x-1] {
					matched = false
					break
				}
			}
			if matched {
				matchIndex = i
				break
			}
		}
		if matchIndex == -1 {
			return false
		}
		methodBytecodes[matchIndex] = nil
	}

	return true
}
