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
	"context"
	"io"
	"path/filepath"
	"sort"
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrawl(t *testing.T) {
	t.Run("returns non-nil error and empty result on failed crawl", func(t *testing.T) {
		out, err := Crawl(context.Background(), Config{
			Root: "non-existent-root",
		}, nil, io.Discard, io.Discard)
		require.Error(t, err)

		assert.Equal(t, crawl.Stats{}, out)
	})

	t.Run("returns nil error and 0 issues on successful crawl with no issues", func(t *testing.T) {
		numIssues, err := Crawl(context.Background(), Config{
			Root: t.TempDir(),
		}, nil, io.Discard, io.Discard)

		require.NoError(t, err)
		assert.Equal(t, crawl.Stats{}, numIssues)
	})
}

func TestCrawlExamplesFindings(t *testing.T) {
	type versionedFindings struct {
		finding  crawl.Finding
		versions crawl.Versions
	}

	expected := map[string]versionedFindings{
		"archived_fat_jar/archived_fat_jar.tar.gz": {
			finding:  crawl.JndiLookupClassPackageAndName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{"2.14.0-2.14.1": {}},
		},
		"cve-2021-44832-versions/log4j-core-2.12.3.jar": {
			finding:  crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{"2.12.3": {}},
		},
		"cve-2021-44832-versions/log4j-core-2.17.0.jar": {
			finding:  crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{"2.17.0": {}},
		},
		"cve-2021-44832-versions/log4j-core-2.3.1.jar": {
			finding:  crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{"2.3.1": {}},
		},
		"cve-2021-45105-versions/log4j-core-2.12.2.jar": {
			finding:  crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{"2.12.2": {}},
		},
		"cve-2021-45105-versions/log4j-core-2.16.0.jar": {
			finding:  crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{"2.16.0": {}},
		},
		"fat_jar/fat_jar.jar": {
			finding:  crawl.JndiLookupClassPackageAndName | crawl.JndiManagerClassPackageAndName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{"2.14.0-2.14.1": {}},
		},
		"inside_a_dist/wrapped_log4j.tar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.0-2.14.1": {},
				"2.14.1":        {},
			},
		},
		"inside_a_dist/wrapped_log4j.tar.bz2": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.0-2.14.1": {},
				"2.14.1":        {},
			},
		},
		"inside_a_dist/wrapped_log4j.tar.gz": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.0-2.14.1": {},
				"2.14.1":        {},
			},
		},
		"inside_a_dist/wrapped_log4j.zip": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.0-2.14.1": {},
				"2.14.1":        {},
			},
		},
		"inside_a_par/wrapped_in_a_par.par": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.0-2.14.1": {},
				"2.14.1":        {},
			},
		},
		"light_shading/shadow-all.jar": {
			finding:  crawl.JndiLookupClassName | crawl.JndiManagerClassName | crawl.ClassBytecodeInstructionMd5,
			versions: map[string]struct{}{"2.12.0-2.14.1": {}},
		},
		"multiple_bad_versions/log4j-core-2.10.0.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.10.0":       {},
				"2.9.0-2.11.2": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.11.0.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.11.0":       {},
				"2.9.0-2.11.2": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.11.1.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.11.1":       {},
				"2.9.0-2.11.2": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.11.2.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.11.2":       {},
				"2.9.0-2.11.2": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.12.0.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.12.0":        {},
				"2.12.0-2.12.1": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.12.1.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.12.1":        {},
				"2.12.0-2.12.1": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.13.0.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.13.0":        {},
				"2.13.0-2.13.3": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.13.1.jar": {
			versions: map[string]struct{}{
				"2.13.1":        {},
				"2.13.0-2.13.3": {},
			},
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
		},
		"multiple_bad_versions/log4j-core-2.13.2.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.13.2":        {},
				"2.13.0-2.13.3": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.13.3.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.13.3":        {},
				"2.13.0-2.13.3": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.14.0.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.0":        {},
				"2.14.0-2.14.1": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.14.1.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.1":        {},
				"2.14.0-2.14.1": {},
			},
		},
		"multiple_bad_versions/log4j-core-2.15.0.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.15.0": {},
			},
		},
		"nested_very_deep/nested_thrice.tar.gz": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.1":        {},
				"2.14.0-2.14.1": {},
			},
		},
		"obfuscated/2.14.1-aaaagb.jar": {
			finding: crawl.JarFileObfuscated | crawl.ClassBytecodePartialMatch,
			versions: map[string]struct{}{
				"2.9.0-2.14.1": {},
			},
		},
		"par_in_a_dist/wrapped_par_in_a_dist.zip": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.0-2.14.1": {},
				"2.14.1":        {},
			},
		},
		"single_bad_version/log4j-core-2.14.1.jar": {
			finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.14.0-2.14.1": {},
				"2.14.1":        {},
			},
		},
		"renamed_jar_class_file_extensions/renamed-log4j-class.jar": {
			finding: crawl.ClassFileMd5,
			versions: map[string]struct{}{
				"2.12.0-2.14.1": {},
			},
		},
	}

	findings := make(map[string]versionedFindings)
	examplesDir := "../../examples"

	summary, err := Crawl(context.Background(), Config{
		Root:                               examplesDir,
		ArchiveMaxDepth:                    5,
		ArchiveMaxSize:                     1024 * 1024 * 10,
		ObfuscatedClassNameAverageLength:   3,
		ObfuscatedPackageNameAverageLength: 3,
		PrintDetailedOutput:                true,
	}, func(ctx context.Context, path string, result crawl.Finding, versions crawl.Versions) {
		findings[path] = versionedFindings{
			finding:  result,
			versions: versions,
		}
	}, io.Discard, io.Discard)

	require.NoError(t, err)
	assert.Equal(t, crawl.Stats{
		FilesScanned: 44,
	}, summary)

	var foundPaths []string
	for path := range findings {
		foundPaths = append(foundPaths, path)
	}
	// sort for deterministic test output
	sort.Strings(foundPaths)
	for _, path := range foundPaths {
		relative, err := filepath.Rel(examplesDir, path)
		require.NoError(t, err)
		if _, isExpected := expected[relative]; !isExpected {
			assert.Failf(t, "Unexpected finding", "path: %s, finding: %s, versions: v", relative, findings[path].finding.String(), findings[path].versions)
		}
	}

	var expectedPaths []string
	for path := range expected {
		expectedPaths = append(expectedPaths, path)
	}
	// sort for deterministic test output
	sort.Strings(expectedPaths)
	for _, path := range expectedPaths {
		finding, found := findings[filepath.Join(examplesDir, path)]
		if !found {
			assert.Failf(t, "Expected finding not present", "path: %s, finding: %s, versions: %v", path, expected[path].finding.String(), expected[path].versions)
			continue
		}

		t.Run(path, func(t *testing.T) {
			assert.Equal(t, expected[path].finding.String(), finding.finding.String(), "Unexpected finding")
			assert.Equal(t, expected[path].versions, finding.versions, "Unexpected versions")
		})
	}
}
