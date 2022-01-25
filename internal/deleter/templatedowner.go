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

package deleter

import (
	"path/filepath"
	"regexp"
)

// TemplatedOwner provides a Matcher interface with flexible pattern matching behaviour to determine a file
// ownership match based on a templated expression and regular expression.
type TemplatedOwner struct {
	DirectoryExpression *regexp.Regexp
	OwnerTemplate       string
}

// DirectoryMatch returns true when the directory containing path matches the TemplatedOwner DirectoryExpression field.
func (r TemplatedOwner) DirectoryMatch(path string) bool {
	dir, _ := filepath.Split(path)
	return r.DirectoryExpression.MatchString(dir)
}

// OwnerMatch returns true when owner of the file matches the result of the OwnerTemplate being expanded against the
// DirectoryExpression regular expression.
// OwnerTemplate may contain variable names of the form $1 or $name which will be expanded against captured group
// matches from the DirectoryExpression when it is matched against the directory containing the file at path.
// Please refer to the go regexp documentation at https://pkg.go.dev/regexp#Regexp.Expand for more detailed behaviour.
func (r TemplatedOwner) OwnerMatch(path, owner string) bool {
	dir, _ := filepath.Split(path)
	return string(r.DirectoryExpression.ExpandString(nil, r.OwnerTemplate, dir, r.DirectoryExpression.FindStringSubmatchIndex(dir))) == owner
}
