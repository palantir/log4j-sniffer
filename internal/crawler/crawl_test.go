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

package crawler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrawl(t *testing.T) {
	t.Run("returns non-nil error and 0 issues on failed crawl", func(t *testing.T) {
		numIssues, err := Crawl(context.Background(), Config{
			Root: "non-existent-root",
		}, io.Discard, io.Discard)
		require.Error(t, err)

		assert.Equal(t, int64(0), numIssues)
	})

	t.Run("returns nil error and 0 issues on successful crawl with no issues", func(t *testing.T) {
		numIssues, err := Crawl(context.Background(), Config{
			Root: t.TempDir(),
		}, io.Discard, io.Discard)

		require.NoError(t, err)
		assert.Equal(t, int64(0), numIssues)
	})
}

func TestCrawlGoodVersion(t *testing.T) {
	buf := &bytes.Buffer{}
	numIssues, err := Crawl(context.Background(), Config{
		Root:       "../../examples/good_version",
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
		findings  []pathFinding
	}{
		{
			name:      "single bad version",
			directory: "../../examples/single_bad_version",
			count:     1,
			findings: []pathFinding{{
				path:    "../../examples/single_bad_version/log4j-core-2.14.1.jar",
				finding: crawl.JarName | crawl.ClassPackageAndName | crawl.ClassFileMd5,
			}},
		}, {
			name:      "multiple bad versions",
			directory: "../../examples/multiple_bad_versions",
			count:     13,
			findings: multipleBadPathsExampleFindings(
				"2.10.0",
				"2.11.0",
				"2.11.1",
				"2.11.2",
				"2.12.0",
				"2.12.1",
				"2.13.0",
				"2.13.1",
				"2.13.2",
				"2.13.3",
				"2.14.0",
				"2.14.1",
				"2.15.0",
				"2.16.0",
			),
		},
		{
			name:      "inside a dist",
			directory: "../../examples/inside_a_dist",
			count:     2,
			findings: []pathFinding{{
				path:    "../../examples/inside_a_dist/wrapped_log4j.tar.gz",
				finding: crawl.JarNameInsideArchive,
			}, {
				path:    "../../examples/inside_a_dist/wrapped_log4j.zip",
				finding: crawl.JarNameInsideArchive | crawl.ClassPackageAndName | crawl.ClassFileMd5,
			}},
		},
		{
			name:      "inside a par",
			directory: "../../examples/inside_a_par",
			count:     1,
			findings: []pathFinding{{
				path:    "../../examples/inside_a_par/wrapped_in_a_par.par",
				finding: crawl.JarNameInsideArchive | crawl.ClassPackageAndName | crawl.ClassFileMd5,
			}},
		},
		{
			name:      "fat jar",
			directory: "../../examples/fat_jar",
			count:     1, findings: []pathFinding{{
				path:    "../../examples/fat_jar/fat_jar.jar",
				finding: crawl.ClassPackageAndName | crawl.ClassFileMd5,
			}},
		},
		{
			name:      "light shading",
			directory: "../../examples/light_shading",
			count:     1,
			findings: []pathFinding{{
				path:    "../../examples/light_shading/shadow-all.jar",
				finding: crawl.ClassName,
			}},
		},
	} {
		t.Run(currCase.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			var stderr bytes.Buffer
			numIssues, err := Crawl(context.Background(), Config{
				Root:            currCase.directory,
				OutputJSON:      true,
				ArchiveMaxDepth: 5,
				ArchiveMaxSize:  1024 * 1024 * 10,
			}, buf, &stderr)
			require.NoError(t, err, stderr.String())
			assert.Equal(t, currCase.count, numIssues, stderr.String())

			for i, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				var cveInstance crawl.JavaCVEInstance
				err = json.Unmarshal([]byte(line), &cveInstance)
				require.NoError(t, err)
				assert.Equal(t, currCase.findings[i].path, cveInstance.FilePath)
				assert.Equalf(t, currCase.findings[i].finding&crawl.JarName > 0, cveInstance.JarNameMatched, "unexpected finding for path: %s", currCase.findings[i].path)
				assert.Equalf(t, currCase.findings[i].finding&crawl.JarNameInsideArchive > 0, cveInstance.JarNameInsideArchiveMatched, "unexpected finding for path: %s", currCase.findings[i].path)
				assert.Equalf(t, currCase.findings[i].finding&crawl.ClassPackageAndName > 0, cveInstance.ClassPackageAndNameMatch, "unexpected finding for path: %s", currCase.findings[i].path)
				assert.Equalf(t, currCase.findings[i].finding&crawl.ClassFileMd5 > 0, cveInstance.ClassFileMD5Matched, "unexpected finding for path: %s", currCase.findings[i].path)
			}
		})
	}
}

type pathFinding struct {
	path    string
	finding crawl.Finding
}

func multipleBadPathsExampleFindings(versions ...string) []pathFinding {
	var out []pathFinding
	for _, version := range versions {
		out = append(out, pathFinding{
			path:    "../../examples/multiple_bad_versions/log4j-core-" + version + ".jar",
			finding: crawl.JarName | crawl.ClassPackageAndName | crawl.ClassFileMd5,
		})
	}
	return out
}
