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

package crawl_test

import (
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/testcontext"
	"github.com/stretchr/testify/assert"
)

func TestUnknownVersions(t *testing.T) {
	t.Run("keep track of number of calls", func(t *testing.T) {
		var r crawl.Reporter
		r.Collect(testcontext.GetTestContext(t), "", stubDirEntry{}, crawl.JarName, nil)
		r.Collect(testcontext.GetTestContext(t), "", stubDirEntry{}, crawl.JarName, nil)
		r.Collect(testcontext.GetTestContext(t), "", stubDirEntry{}, crawl.JarName, nil)
		assert.EqualValues(t, 3, r.Count())
	})
}

func TestVulnerableAndUnknownVersions(t *testing.T) {
	t.Run("keep track of number of calls", func(t *testing.T) {
		var r crawl.Reporter
		r.Collect(testcontext.GetTestContext(t), "", stubDirEntry{}, crawl.JarName, nil)
		r.Collect(testcontext.GetTestContext(t), "", stubDirEntry{}, crawl.JarName, crawl.Versions{"2.15.0": {}})
		r.Collect(testcontext.GetTestContext(t), "", stubDirEntry{}, crawl.JarName, crawl.Versions{"2.12.1": {}})
		r.Collect(testcontext.GetTestContext(t), "", stubDirEntry{}, crawl.JarName, crawl.Versions{"2.10.0": {}})
		r.Collect(testcontext.GetTestContext(t), "", stubDirEntry{}, crawl.JarName, crawl.Versions{"2.15.0-rc1": {}})
		assert.EqualValues(t, 5, r.Count())
	})
}

func TestBadVersionString(t *testing.T) {
	t.Run("keep track of number of calls", func(t *testing.T) {
		var r crawl.Reporter
		r.Collect(testcontext.GetTestContext(t), "", stubDirEntry{}, crawl.JarName, crawl.Versions{"I'm not a version": {}})
		assert.EqualValues(t, 1, r.Count())
	})
}
