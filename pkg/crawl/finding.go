// Copyright (c) 2022 Palantir Technologies. All rights reserved.
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
	"fmt"
	"sort"
	"strings"
)

const (
	UnknownVersion = "unknown"

	NothingDetected                Finding = 0
	JndiLookupClassName            Finding = 1 << iota
	JndiLookupClassPackageAndName  Finding = 1 << iota
	JndiManagerClassName           Finding = 1 << iota
	JarName                        Finding = 1 << iota
	JarNameInsideArchive           Finding = 1 << iota
	JndiManagerClassPackageAndName Finding = 1 << iota
	JarFileObfuscated              Finding = 1 << iota
	ClassBytecodePartialMatch      Finding = 1 << iota
	ClassBytecodeInstructionMd5    Finding = 1 << iota
	ClassFileMd5                   Finding = 1 << iota
)

var (
	// vulnerableFindingStrings contains only the Finding values that are considered vulnerable.
	vulnerableFindingStrings = map[Finding]string{
		JndiLookupClassName:            "JndiLookupClassName",
		JndiLookupClassPackageAndName:  "JndiLookupClassPackageAndName",
		JndiManagerClassName:           "JndiManagerClassName",
		JarName:                        "JarName",
		JarNameInsideArchive:           "JarNameInsideArchive",
		JndiManagerClassPackageAndName: "JndiManagerClassPackageAndName",
		JarFileObfuscated:              "JarFileObfuscated",
		ClassBytecodePartialMatch:      "ClassBytecodePartialMatch",
		ClassBytecodeInstructionMd5:    "ClassBytecodeInstructionMd5",
		ClassFileMd5:                   "ClassFileMd5",
	}

	stringFindings           = invertedFindingStringMap()
	lowercasedStringFindings = lowerCasedInvertedFindingStringMap()
)

type Finding int
type Versions map[string]struct{}

// FindingOf creates a finding from a string, returning an error if a corresponding finding does not exist.
// Conversion is case-insensitive.
func FindingOf(v string) (Finding, error) {
	finding, ok := lowercasedStringFindings[strings.ToLower(v)]
	if !ok {
		return 0, fmt.Errorf("invalid finding-match %s, supported values are %s", v, strings.Join(SupportedVulnerableFindingValues(), ", "))
	}
	return finding, nil
}

func SupportedVulnerableFindingValues() []string {
	var supportedValues []string
	for s := range stringFindings {
		supportedValues = append(supportedValues, s)
	}
	sort.Strings(supportedValues)
	return supportedValues
}

func lowerCasedInvertedFindingStringMap() map[string]Finding {
	out := make(map[string]Finding)
	for s, finding := range invertedFindingStringMap() {
		out[strings.ToLower(s)] = finding
	}
	return out
}

func invertedFindingStringMap() map[string]Finding {
	out := make(map[string]Finding)
	for finding, s := range vulnerableFindingStrings {
		_, exists := out[s]
		if exists {
			panic(fmt.Sprintf("finding already defined when inverting finding strings map: %s", s))
		}
		out[s] = finding
	}
	return out
}

func (f Finding) String() string {
	var out []string
	// For each vulnerable finding type, aka non-zero Finding value,
	// compare single bit against finding and append the string from
	// that finding to the joined list.
	for findingBit := Finding(1); f >= findingBit; findingBit <<= 1 {
		if AllFindingsSatisfiedBy(findingBit, f) {
			if s, ok := vulnerableFindingStrings[findingBit]; ok {
				out = append(out, s)
			}
		}
	}
	return strings.Join(out, ",")
}

// AllFindingsSatisfiedBy returns true if all the findings represented by a are also represented by b
func AllFindingsSatisfiedBy(a, b Finding) bool {
	// after bitwise and, result should equal exactly the requirements
	return a&b == a
}
