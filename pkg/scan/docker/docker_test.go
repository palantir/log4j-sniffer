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

package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner_ScanImages(t *testing.T) {
	currentDir, err := os.Getwd()
	require.NoError(t, err)
	t.Run("returns non-nil, finds matches in image", func(t *testing.T) {
		deferredDockerTest(currentDir, t, func(t *testing.T) {
			client := &mockDockerClient{
				imageFile: "../../../examples/docker/log4j.tar",
				imageSummary: types.ImageSummary{
					ID:       "sha256:0efeedfe8b8beed50fb60d77cefd4b3523f1d6562766aee17b0c064c31bb1921",
					RepoTags: []string{"bad"},
				},
			}
			count, err := ScanImages(context.Background(), scan.Config{}, io.Discard, io.Discard, client, "")
			assert.NoError(t, err)
			assert.Equal(t, int64(2), count)
		})
	})
	t.Run("returns non-nil, finds multiple matches in image", func(t *testing.T) {
		deferredDockerTest(currentDir, t, func(t *testing.T) {
			client := &mockDockerClient{
				imageFile: "../../../examples/docker/multiple_versions.tar",
				imageSummary: types.ImageSummary{
					ID:       "sha256:0efeedfe8b8beed50fb60d77cefd4b3523f1d6562766aee17b0c064c31bb1921",
					RepoTags: []string{"bad"},
				},
			}
			count, err := ScanImages(context.Background(), scan.Config{}, io.Discard, io.Discard, client, "")
			assert.NoError(t, err)
			assert.Equal(t, int64(5), count)
		})
	})
	t.Run("returns non-nil, does not find match in good version", func(t *testing.T) {
		deferredDockerTest(currentDir, t, func(t *testing.T) {
			client := &mockDockerClient{
				imageFile: "../../../examples/docker/good_version.tar",
				imageSummary: types.ImageSummary{
					ID:       "sha256:0efeedfe8b8beed50fb60d77cefd4b3523f1d6562766aee17b0c064c31bb1921",
					RepoTags: []string{"bad"},
				},
			}
			count, err := ScanImages(context.Background(), scan.Config{}, io.Discard, io.Discard, client, "")
			assert.NoError(t, err)
			assert.Equal(t, int64(0), count)
		})
	})
}

func TestScanImagesBadVersions(t *testing.T) {
	currentDir, err := os.Getwd()
	require.NoError(t, err)

	for _, currCase := range []struct {
		name      string
		count     int64
		imageFile string
		findings  []pathFinding
	}{
		{
			name:      "inside a dist inside an image",
			count:     2,
			imageFile: "../../../examples/docker/log4j.tar",
			findings: []pathFinding{
				{
					path:    "opt/examples/wrapped_log4j.tar.gz",
					finding: crawl.JarNameInsideArchive,
				},
				{
					path:    "opt/examples/wrapped_log4j.zip",
					finding: crawl.ClassPackageAndName | crawl.JarNameInsideArchive | crawl.ClassFileMd5,
				},
			},
		},
		{
			name:      "multiple versions inside an image",
			count:     5,
			imageFile: "../../../examples/docker/multiple_versions.tar",
			findings: []pathFinding{
				{
					path:    "opt/shadow-all.jar",
					finding: crawl.ClassName,
				},
				{
					path:    "opt/wrapped_log4j.tar",
					finding: crawl.JarNameInsideArchive,
				},
				{
					path:    "opt/wrapped_log4j.tar.bz2",
					finding: crawl.JarNameInsideArchive,
				},
				{
					path:    "opt/wrapped_log4j.tar.gz",
					finding: crawl.JarNameInsideArchive,
				},
				{
					path:    "opt/wrapped_log4j.zip",
					finding: crawl.ClassPackageAndName | crawl.JarNameInsideArchive | crawl.ClassFileMd5,
				},
			},
		},
	} {
		t.Run(currCase.name, func(t *testing.T) {
			deferredDockerTest(currentDir, t, func(t *testing.T) {
				buf := &bytes.Buffer{}
				var stderr bytes.Buffer
				client := &mockDockerClient{
					imageFile: currCase.imageFile,
					imageSummary: types.ImageSummary{
						ID:       "sha256:0efeedfe8b8beed50fb60d77cefd4b3523f1d6562766aee17b0c064c31bb1921",
						RepoTags: []string{"bad"},
					},
				}
				numIssues, err := ScanImages(context.Background(), scan.Config{
					OutputJSON:      true,
					ArchiveMaxDepth: 5,
					ArchiveMaxSize:  1024 * 1024 * 10,
				}, buf, &stderr, client, "")
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
		})
	}
}

type pathFinding struct {
	path    string
	finding crawl.Finding
}

func deferredDockerTest(dir string, t *testing.T, testFn func(t *testing.T)) {
	// the docker scanner involves moving around directories so we need to reset
	defer func() {
		require.NoError(t, os.Chdir(dir))
	}()
	testFn(t)
}
