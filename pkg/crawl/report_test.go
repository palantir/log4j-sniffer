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
	"bytes"
	"context"
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/stretchr/testify/assert"
)

func TestCountsFilesAndFindingsSeparately(t *testing.T) {
	var r crawl.Reporter

	r.Report(context.Background(), crawl.Path{"foo.jar", "bar"}, crawl.JarName, crawl.Versions{"2.15.0": {}})
	assert.EqualValues(t, 1, r.FileCount())
	assert.EqualValues(t, 1, r.FindingCount())

	r.Report(context.Background(), crawl.Path{"foo.jar", "bar"}, crawl.JarName, crawl.Versions{"2.15.0": {}})
	assert.EqualValues(t, 1, r.FileCount(), "duplicate file should not be counted")
	assert.EqualValues(t, 2, r.FindingCount())

	r.Report(context.Background(), crawl.Path{"baz.jar", "bar"}, crawl.JarName, crawl.Versions{"2.15.0": {}})
	assert.EqualValues(t, 2, r.FileCount(), "duplicate file should not be counted")
	assert.EqualValues(t, 3, r.FindingCount())
}

func TestVulnerableAndUnknownVersions(t *testing.T) {
	t.Run("keep track of number of calls", func(t *testing.T) {
		var r crawl.Reporter
		r.Report(context.Background(), []string{"foo"}, crawl.JarName, nil)
		r.Report(context.Background(), []string{"foo"}, crawl.JarName, crawl.Versions{"2.15.0": {}})
		r.Report(context.Background(), []string{"foo"}, crawl.JarName, crawl.Versions{"2.12.1": {}})
		r.Report(context.Background(), []string{"foo"}, crawl.JarName, crawl.Versions{"2.10.0": {}})
		r.Report(context.Background(), []string{"foo"}, crawl.JarName, crawl.Versions{"2.15.0-rc1": {}})
		assert.EqualValues(t, 1, r.FileCount())
		assert.EqualValues(t, 5, r.FindingCount())
	})
}

func TestBadVersionString(t *testing.T) {
	t.Run("keep track of number of calls", func(t *testing.T) {
		var r crawl.Reporter
		r.Report(context.Background(), []string{"foo"}, crawl.JarName, crawl.Versions{"I'm not a version": {}})
		assert.EqualValues(t, 1, r.FileCount())
	})
}

func TestJndiLookupOnly(t *testing.T) {
	t.Run("keep track of number of calls", func(t *testing.T) {
		r := crawl.Reporter{
			DisableFlaggingJndiLookup: true,
		}
		r.Report(context.Background(), []string{"foo"}, crawl.JndiLookupClassPackageAndName, nil)
		assert.EqualValues(t, 0, r.FileCount())
	})
}

func TestDefaultOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	r := crawl.Reporter{
		OutputWriter: buf,
	}
	r.Report(context.Background(), []string{"test-name.jar"}, crawl.JarName, crawl.Versions{"2.15.0": {}})
	assert.Equal(t, "[MATCH] CVE-2021-44228, CVE-2021-44832, CVE-2021-45046, CVE-2021-45105 detected in file test-name.jar. log4j versions: 2.15.0. Reasons: jar name matched\n", buf.String())
}

func TestJSONOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	r := crawl.Reporter{
		OutputWriter: buf,
		OutputJSON:   true,
	}
	r.Report(context.Background(), crawl.Path{"test-name.jar", "bar"}, crawl.JarName, crawl.Versions{"2.15.0": {}})
	assert.Equal(t, "{\"message\":\"CVE-2021-44228, CVE-2021-44832, CVE-2021-45046, CVE-2021-45105 detected\",\"filePath\":\"test-name.jar\",\"detailedPath\":\"test-name.jar!bar\",\"cvesDetected\":[\"CVE-2021-44228\",\"CVE-2021-44832\",\"CVE-2021-45046\",\"CVE-2021-45105\"],\"findings\":[\"jarName\"],\"log4jVersions\":[\"2.15.0\"]}\n", buf.String())
}

func TestFilePathOnlyOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	r := crawl.Reporter{
		OutputWriter:       buf,
		OutputFilePathOnly: true,
	}
	r.Report(context.Background(), crawl.Path{"test-name.jar", "bar"}, crawl.JarName, crawl.Versions{"2.15.0": {}})
	assert.Equal(t, "test-name.jar\n", buf.String())
	r.Report(context.Background(), crawl.Path{"test-name.jar", "bar"}, crawl.JarName, crawl.Versions{"2.15.0": {}})
	assert.Equal(t, "test-name.jar\n", buf.String(), "printing a finding with the path on disk should not print again")
}

func TestDisableFlaggingUnknownVersions(t *testing.T) {
	buf := &bytes.Buffer{}
	r := crawl.Reporter{
		OutputWriter:                   buf,
		DisableFlaggingUnknownVersions: true,
	}
	r.Report(context.Background(), []string{"test-name.jar"}, crawl.JarName, crawl.Versions{crawl.UnknownVersion: {}})
	assert.Equal(t, "", buf.String())
}
