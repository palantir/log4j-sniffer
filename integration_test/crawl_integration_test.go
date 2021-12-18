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

package integration_test

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/palantir/godel/v2/pkg/products"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBadVersions(t *testing.T) {
	cli, err := products.Bin("log4j-sniffer")
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		directory string
		count     int
		finding   crawl.Finding
	}{
		{name: "single bad version", directory: "../examples/single_bad_version", count: 1, finding: crawl.JarName | crawl.ClassPackageAndName},
		{name: "multiple bad versions", directory: "../examples/multiple_bad_versions", count: 13, finding: crawl.JarName | crawl.ClassPackageAndName},
		{name: "inside a dist", directory: "../examples/inside_a_dist", count: 2, finding: crawl.JarNameInsideArchive},
		{name: "inside a par", directory: "../examples/inside_a_par", count: 1, finding: crawl.JarNameInsideArchive},
		{name: "fat jar", directory: "../examples/fat_jar", count: 1, finding: crawl.ClassPackageAndName},
		{name: "light shading", directory: "../examples/light_shading", count: 1, finding: crawl.ClassName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(cli, "crawl", tc.directory)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "command %v failed with output:\n%s", cmd.Args, string(output))
			got := string(output)
			assert.Contains(t, got, "Files affected by CVE-2021-45046 detected")
			assert.Contains(t, got, fmt.Sprintf("vulnerableFileCount: %d", tc.count))
			assert.NotContains(t, got, "No files affected by CVE-2021-45046 detected")
			if tc.finding&crawl.JarName > 0 {
				assert.Contains(t, got, "jarNameMatched: true")
			} else {
				assert.NotContains(t, got, "jarNameMatched: true")
			}
			if tc.finding&crawl.JarNameInsideArchive > 0 {
				assert.Contains(t, got, "jarNameInsideArchiveMatched: true")
			} else {
				assert.NotContains(t, got, "jarNameInsideArchiveMatched: true")
			}
			if tc.finding&crawl.ClassPackageAndName > 0 {
				assert.Contains(t, got, "classPackageAndNameMatched: true")
			} else {
				assert.NotContains(t, got, "classPackageAndNameMatched: true")
			}
		})
	}
}

func TestGoodVersion(t *testing.T) {
	cli, err := products.Bin("log4j-sniffer")
	require.NoError(t, err)

	cmd := exec.Command(cli, "crawl", "../examples/good_version")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "command %v failed with output:\n%s", cmd.Args, string(output))
	got := string(output)
	assert.Contains(t, got, "No files affected by CVE-2021-45046 detected")
	assert.NotContains(t, got, "Files affected by CVE-2021-45046 detected")
}
