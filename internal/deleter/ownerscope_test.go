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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileOwnerMatcher_Match(t *testing.T) {
	t.Run("no directory owners does not match anything", func(t *testing.T) {
		match, err := FileOwnerMatchers{}.Match("")
		require.NoError(t, err)
		assert.False(t, match)
	})

	t.Run("errors from resolve owner is returned", func(t *testing.T) {
		expectedErr := errors.New("err")
		_, err := FileOwnerMatchers{
			ResolveOwner: func(path string) (string, error) {
				return "", expectedErr
			},
			Matchers: []Matcher{
				stubMatcher{directoryMatch: func(path string) bool { return true }}},
		}.Match("path")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("passes path and owner to matchers", func(t *testing.T) {
		var calls []string
		_, err := FileOwnerMatchers{
			ResolveOwner: func(path string) (string, error) {
				return "owner", nil
			},
			Matchers: []Matcher{
				stubMatcher{
					directoryMatch: func(path string) bool {
						calls = append(calls, "a")
						assert.Equal(t, "path", path)
						return true
					},
					ownerMatch: func(path, owner string) bool {
						calls = append(calls, "b")
						assert.Equal(t, "path", path)
						assert.Equal(t, "owner", owner)
						return true
					},
				},
				stubMatcher{
					directoryMatch: func(path string) bool {
						calls = append(calls, "c")
						assert.Equal(t, "path", path)
						return true
					},
					ownerMatch: func(path, owner string) bool {
						calls = append(calls, "d")
						assert.Equal(t, "path", path)
						assert.Equal(t, "owner", owner)
						return true
					},
				}},
		}.Match("path")
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c", "d"}, calls, "expected calls to functions to be in order")
	})

	t.Run("does not call owner matchers funcs if directory miss", func(t *testing.T) {
		var calls []string
		_, err := FileOwnerMatchers{
			Matchers: []Matcher{
				stubMatcher{
					directoryMatch: func(path string) bool {
						calls = append(calls, "a")
						return false
					},
					ownerMatch: func(path, owner string) bool {
						require.FailNow(t, "should not have been called")
						return true
					},
				},
				stubMatcher{
					directoryMatch: func(path string) bool {
						calls = append(calls, "b")
						return false
					},
					ownerMatch: func(path, owner string) bool {
						require.FailNow(t, "should not have been called")
						return true
					},
				},
			},
		}.Match("path")
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b"}, calls, "expected calls to functions to be in order")
	})

	t.Run("no directory matches results in no match", func(t *testing.T) {
		match, err := FileOwnerMatchers{
			Matchers: []Matcher{
				stubMatcher{
					directoryMatch: func(path string) bool { return false },
				},
				stubMatcher{
					directoryMatch: func(path string) bool { return false },
				},
			},
		}.Match("path")
		assert.NoError(t, err)
		assert.False(t, match)
	})

	t.Run("single directory match returns result of owner match", func(t *testing.T) {
		match, err := FileOwnerMatchers{
			ResolveOwner: func(path string) (string, error) { return "", nil },
			Matchers: []Matcher{
				stubMatcher{
					directoryMatch: func(path string) bool { return false },
				},
				stubMatcher{
					directoryMatch: func(path string) bool { return true },
					ownerMatch:     func(path, owner string) bool { return true },
				},
			},
		}.Match("path")
		require.NoError(t, err)
		assert.True(t, match)
	})

	t.Run("multiple directory match returns false if any are owner misses", func(t *testing.T) {
		match, err := FileOwnerMatchers{
			ResolveOwner: func(path string) (string, error) { return "", nil },
			Matchers: []Matcher{
				stubMatcher{
					directoryMatch: func(path string) bool { return false },
				},
				stubMatcher{
					directoryMatch: func(path string) bool { return true },
					ownerMatch:     func(path, owner string) bool { return true },
				},
				stubMatcher{
					directoryMatch: func(path string) bool { return true },
					ownerMatch:     func(path, owner string) bool { return false },
				},
			},
		}.Match("path")
		require.NoError(t, err)
		assert.False(t, match)
	})

	t.Run("multiple directory match returns true if all are owner misses", func(t *testing.T) {
		match, err := FileOwnerMatchers{
			ResolveOwner: func(path string) (string, error) { return "", nil },
			Matchers: []Matcher{
				stubMatcher{
					directoryMatch: func(path string) bool { return false },
				},
				stubMatcher{
					directoryMatch: func(path string) bool { return true },
					ownerMatch:     func(path, owner string) bool { return true },
				},
				stubMatcher{
					directoryMatch: func(path string) bool { return true },
					ownerMatch:     func(path, owner string) bool { return true },
				},
			},
		}.Match("path")
		require.NoError(t, err)
		assert.True(t, match)
	})

	t.Run("does not subsequent directory matchers if any directory has an owner miss", func(t *testing.T) {
		match, err := FileOwnerMatchers{
			ResolveOwner: func(path string) (string, error) { return "", nil },
			Matchers: []Matcher{
				stubMatcher{
					directoryMatch: func(path string) bool { return true },
					ownerMatch:     func(path, owner string) bool { return false },
				},
				stubMatcher{
					directoryMatch: func(path string) bool {
						require.FailNow(t, "should not be called")
						return false
					},
				},
			},
		}.Match("path")
		require.NoError(t, err)
		assert.False(t, match)
	})

	t.Run("resolves owner once per file", func(t *testing.T) {
		var resolves int
		_, err := FileOwnerMatchers{
			ResolveOwner: func(path string) (string, error) {
				resolves++
				return "foo", nil
			},
			Matchers: []Matcher{
				stubMatcher{
					directoryMatch: func(path string) bool { return true },
					ownerMatch:     func(path, owner string) bool { return true },
				},
				stubMatcher{
					directoryMatch: func(path string) bool { return true },
					ownerMatch:     func(path, owner string) bool { return true },
				},
			},
		}.Match("path")
		require.NoError(t, err)
		assert.Equal(t, 1, resolves)
	})
}

type stubMatcher struct {
	directoryMatch func(path string) bool
	ownerMatch     func(path, owner string) bool
}

func (s stubMatcher) DirectoryMatch(path string) bool {
	return s.directoryMatch(path)
}

func (s stubMatcher) OwnerMatch(path, owner string) bool {
	return s.ownerMatch(path, owner)
}
