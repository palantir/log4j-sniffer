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
	"regexp"
	"strconv"
)

var log4jVersionRegex = regexp.MustCompile(`(?i)^(\d+)\.(\d+)\.?(\d+)?(?:[\./-].*)?$`)

// ParseLog4jVersions parses all Versions represented as strings, returning a slice of all valid versions found.
// A bool is returned that will be true if there were any invalid versions provided and the invalid versions will
// be omitted from the returns Log4jVersion slice.
func ParseLog4jVersions(versions Versions) ([]Log4jVersion, bool) {
	var out []Log4jVersion
	var includesInvalid bool
	for v := range versions {
		parsedV, parsed := ParseLog4jVersion(v)
		if !parsed {
			includesInvalid = true
			continue
		}
		out = append(out, parsedV)
	}
	return out, includesInvalid
}

func ParseLog4jVersion(version string) (Log4jVersion, bool) {
	matches := log4jVersionRegex.FindStringSubmatch(version)
	if len(matches) == 0 {
		return Log4jVersion{}, false
	}
	major, err := strconv.Atoi(matches[1])
	if err != nil {
		// should not be possible due to group of \d+ in regex
		return Log4jVersion{}, false
	}
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		// should not be possible due to group of \d+ in regex
		return Log4jVersion{}, false
	}
	patch, err := strconv.Atoi(matches[3])
	if err != nil {
		patch = 0
	}
	return Log4jVersion{
		Original: version,
		Major:    major,
		Minor:    minor,
		Patch:    patch,
	}, true
}

type Log4jVersion struct {
	Original string
	Major    int
	Minor    int
	Patch    int
}

func (v Log4jVersion) Vulnerable() bool {
	return (v.Major == 2 && v.Minor <= 17) && !(v.Minor == 17 && v.Patch >= 1) && !(v.Minor == 12 && v.Patch >= 4) && !(v.Minor == 3 && v.Patch >= 2)
}
