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
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegexWithSubstitutionMatcher(t *testing.T) {
	t.Run("matches regex against path", func(t *testing.T) {
		matcher := TemplatedOwner{
			DirectoryExpression: regexp.MustCompile("/foo/bar/.*"),
		}
		assert.True(t, matcher.DirectoryMatch("someprefix/foo/bar/baz/qux"))
	})

	t.Run("makes substitution for owner match", func(t *testing.T) {
		matcher := TemplatedOwner{
			DirectoryExpression: regexp.MustCompile("/foo/(.+)/"),
			OwnerTemplate:       "owner $1",
		}
		assert.True(t, matcher.OwnerMatch("/foo/bar/baz", "owner bar"))
	})
}
