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

package fs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrawl(t *testing.T) {
	t.Run("returns non-nil error and 0 issues on failed crawl", func(t *testing.T) {
		numIssues, err := Crawl(context.Background(), scan.Config{
			Root: "non-existent-root",
		}, io.Discard, io.Discard)
		require.Error(t, err)

		assert.Equal(t, int64(0), numIssues)
	})

	t.Run("returns nil error and 0 issues on successful crawl with no issues", func(t *testing.T) {
		numIssues, err := Crawl(context.Background(), scan.Config{
			Root: t.TempDir(),
		}, io.Discard, io.Discard)

		require.NoError(t, err)
		assert.Equal(t, int64(0), numIssues)
	})
}

func TestCrawlGoodVersion(t *testing.T) {
	buf := &bytes.Buffer{}
	numIssues, err := Crawl(context.Background(), scan.Config{
		Root:       "../../../examples/good_version",
		OutputJSON: true,
	}, buf, io.Discard)
	require.NoError(t, err)

	assert.Equal(t, int64(0), numIssues)
	assert.Equal(t, "", buf.String())
}

func TestCrawlBadVersions(t *testing.T) {
	for _, currCase := range []struct {
		name      string
		directory string
		count     int64
		finding   crawl.Finding
	}{
		{name: "single bad version", directory: "../../../examples/single_bad_version", count: 1, finding: crawl.JarName | crawl.ClassPackageAndName},
		{name: "multiple bad versions", directory: "../../../examples/multiple_bad_versions", count: 13, finding: crawl.JarName | crawl.ClassPackageAndName},
		{name: "inside a dist", directory: "../../../examples/inside_a_dist", count: 2, finding: crawl.JarNameInsideArchive},
		{name: "inside a par", directory: "../../../examples/inside_a_par", count: 1, finding: crawl.JarNameInsideArchive},
		{name: "fat jar", directory: "../../../examples/fat_jar", count: 1, finding: crawl.ClassPackageAndName},
		{name: "light shading", directory: "../../../examples/light_shading", count: 1, finding: crawl.ClassName},
	} {
		t.Run(currCase.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			numIssues, err := Crawl(context.Background(), scan.Config{
				Root:       currCase.directory,
				OutputJSON: true,
			}, buf, io.Discard)
			require.NoError(t, err)

			assert.Equal(t, currCase.count, numIssues)

			for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				var cveInstance crawl.JavaCVEInstance
				err = json.Unmarshal([]byte(line), &cveInstance)
				require.NoError(t, err)
				assert.Equal(t, currCase.finding&crawl.JarName > 0, cveInstance.JarNameMatched)
				assert.Equal(t, currCase.finding&crawl.JarNameInsideArchive > 0, cveInstance.JarNameInsideArchiveMatched)
				assert.Equal(t, currCase.finding&crawl.ClassPackageAndName > 0, cveInstance.ClassPackageAndNameMatch)
			}
		})
	}
}
