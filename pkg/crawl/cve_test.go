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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLog4jVersion(t *testing.T) {
	t.Run("no match returns false", func(t *testing.T) {
		_, parsed := ParseLog4jVersion("")
		assert.False(t, parsed)
	})

	for _, tc := range []struct {
		name          string
		version       string
		parsedVersion Log4jVersion
	}{{
		name:    "major, minor",
		version: "98.99",
		parsedVersion: Log4jVersion{
			Major:    98,
			Minor:    99,
			Original: "98.99",
		},
	}, {
		name:    "major, minor, patch",
		version: "97.98.99",
		parsedVersion: Log4jVersion{
			Major:    97,
			Minor:    98,
			Patch:    99,
			Original: "97.98.99",
		},
	}, {
		name:    "major, minor, patch, extra",
		version: "97.98.99-foo",
		parsedVersion: Log4jVersion{
			Major:    97,
			Minor:    98,
			Patch:    99,
			Original: "97.98.99-foo",
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			v, parsed := ParseLog4jVersion(tc.version)
			assert.True(t, parsed)
			assert.Equal(t, tc.parsedVersion, v)
		})
	}
}
