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

package deleter_test

import (
	"testing"

	"github.com/palantir/log4j-sniffer/internal/deleter"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/stretchr/testify/assert"
)

func TestVersionMatcher(t *testing.T) {
	t.Run("no valid versions do not match", func(t *testing.T) {
		assert.False(t, deleter.VersionMatcher(nil)(nil))
	})

	t.Run("nil version resolver returns false", func(t *testing.T) {
		match := deleter.VersionMatcher(nil)
		assert.False(t, match(crawl.Versions{"1.2.3": {}}))
	})

	t.Run("versions passed to resolver", func(t *testing.T) {
		var versions []crawl.Log4jVersion
		match := deleter.VersionMatcher(stubbedCVEResolver(func(vs []crawl.Log4jVersion) []string {
			versions = vs
			return nil
		}))
		assert.False(t, match(crawl.Versions{"1.2.3": {}}))
		assert.Equal(t, []crawl.Log4jVersion{{
			Original: "1.2.3",
			Major:    1,
			Minor:    2,
			Patch:    3,
		}}, versions)
	})

	t.Run("no cves returns false", func(t *testing.T) {
		match := deleter.VersionMatcher(stubbedCVEResolver(func(vs []crawl.Log4jVersion) []string { return nil }))
		assert.False(t, match(crawl.Versions{"1.2.3": {}}))
	})

	t.Run("some cves returns true", func(t *testing.T) {
		match := deleter.VersionMatcher(stubbedCVEResolver(func(vs []crawl.Log4jVersion) []string { return []string{"foo"} }))
		assert.True(t, match(crawl.Versions{"1.2.3": {}}))
	})
}

type stubbedCVEResolver func([]crawl.Log4jVersion) []string

func (s stubbedCVEResolver) CVEs(vs []crawl.Log4jVersion) []string {
	return s(vs)
}
