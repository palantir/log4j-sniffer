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

// FileOwnerMatchers matches the owner of a given file against an amount of Matchers,
// using the contained function to resolve the owner of a path.
type FileOwnerMatchers struct {
	Matchers     []Matcher
	ResolveOwner func(path string) (string, error)
}

// Match resolves the owner of the given path and checks ownership of the file against the contained Matchers.
// Match will yield true if more than 0 matchers match the directory that contains the filepath at path, and
// all of those matchers return true from their OwnerMatch method.
func (ms FileOwnerMatchers) Match(path string) (bool, error) {
	var (
		directoryMatches int
		owner            string
	)
	for _, match := range ms.Matchers {
		if !match.DirectoryMatch(path) {
			continue
		}
		directoryMatches++
		if owner == "" {
			var err error
			owner, err = ms.ResolveOwner(path)
			if err != nil {
				return false, err
			}
		}
		if !match.OwnerMatch(path, owner) {
			return false, nil
		}
	}
	return directoryMatches > 0, nil
}

// Matcher determine whether a directory and owner match some given constraints.
type Matcher interface {
	DirectoryMatch(filepath string) bool
	OwnerMatch(filepath, owner string) bool
}
