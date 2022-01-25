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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"
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
		{name: "single bad version", directory: "../examples/single_bad_version", count: 1, finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5},
		{name: "multiple bad versions", directory: "../examples/multiple_bad_versions", count: 13, finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5},
		{name: "inside a dist", directory: "../examples/inside_a_dist", count: 4, finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5},
		{name: "inside a par", directory: "../examples/inside_a_par", count: 1, finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5},
		{name: "nested twice in tars", directory: "../examples/nested_very_deep", count: 1, finding: crawl.JndiLookupClassPackageAndName | crawl.JarNameInsideArchive | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5},
		{name: "fat jar", directory: "../examples/fat_jar", count: 1, finding: crawl.JndiLookupClassPackageAndName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5},
		{name: "light shading", directory: "../examples/light_shading", count: 1, finding: crawl.JndiLookupClassName | crawl.JndiManagerClassName | crawl.ClassBytecodeInstructionMd5},
		{name: "cve-2021-45105 versions", directory: "../examples/cve-2021-45105-versions", count: 2, finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5},
		{name: "cve-2021-44832 versions", directory: "../examples/cve-2021-44832-versions", count: 3, finding: crawl.JndiLookupClassPackageAndName | crawl.JarName | crawl.JndiManagerClassPackageAndName | crawl.ClassFileMd5},
		{name: "obfuscation", directory: "../examples/obfuscated", count: 1, finding: crawl.JarFileObfuscated | crawl.ClassBytecodePartialMatch},
		{name: "renamed classes", directory: "../examples/renamed_jar_class_file_extensions", count: 1, finding: crawl.ClassFileMd5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(cli, "crawl", tc.directory, `--nested-archive-max-depth`, `3`)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "command %v failed with output:\n%s", cmd.Args, string(output))
			got := string(output)
			assert.Contains(t, got, "Files affected by CVE-2021-44228 or CVE-2021-45046 or CVE-2021-45105 or CVE-2021-44832 detected")
			assert.Contains(t, got, fmt.Sprintf("iles affected by CVE-2021-44228 or CVE-2021-45046 or CVE-2021-45105 or CVE-2021-44832 detected: %d file(s)", tc.count))
			assert.NotContains(t, got, "No files affected by CVE-2021-44228 or CVE-2021-45046 or CVE-2021-45105 or CVE-2021-44832 detected")
			assert.NotContains(t, got, "[TRACE]")

			testMatched(t, got, tc.finding, crawl.JndiLookupClassName, "JndiLookup class name matched")
			testMatched(t, got, tc.finding, crawl.JndiLookupClassPackageAndName, "JndiLookup class and package name matched")
			testMatched(t, got, tc.finding, crawl.JarName, "jar name matched")
			testMatched(t, got, tc.finding, crawl.JarNameInsideArchive, "jar name inside archive matched")
			testMatched(t, got, tc.finding, crawl.JndiManagerClassName, "JndiManager class name matched")
			testMatched(t, got, tc.finding, crawl.JndiManagerClassPackageAndName, "JndiManager class and package name matched")
			testMatched(t, got, tc.finding, crawl.ClassFileMd5, "class file MD5 matched")
			testMatched(t, got, tc.finding, crawl.ClassBytecodeInstructionMd5, "byte code instruction MD5 matched")
			testMatched(t, got, tc.finding, crawl.JarFileObfuscated, "jar file appeared obfuscated")
			testMatched(t, got, tc.finding, crawl.ClassBytecodePartialMatch, "byte code partially matched known version")
		})
	}
}

func testMatched(t *testing.T, got string, tcFinding, currFinding crawl.Finding, msg string) {
	if tcFinding&currFinding > 0 {
		assert.Contains(t, got, msg)
	} else {
		assert.NotContains(t, got, msg)
	}
}

func TestGoodVersion(t *testing.T) {
	cli, err := products.Bin("log4j-sniffer")
	require.NoError(t, err)

	cmd := exec.Command(cli, "crawl", "../examples/good_version")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "command %v failed with output:\n%s", cmd.Args, string(output))
	got := string(output)
	assert.Contains(t, got, "No files affected by CVE-2021-44228 or CVE-2021-45046 or CVE-2021-45105 or CVE-2021-44832 detected")
	assert.NotContains(t, got, "Files affected by CVE-2021-44228 or CVE-2021-45046 or CVE-2021-45105 or CVE-2021-44832 detected")
}

func TestCve45105Flag(t *testing.T) {
	cli, err := products.Bin("log4j-sniffer")
	require.NoError(t, err)

	for _, tc := range []struct {
		name             string
		directory        string
		disableExtraCVEs bool
		count            int
		finding          crawl.Finding
	}{
		{name: "cve-2021-45105 and cve-2021-44832 enabled", directory: "../examples/cve-2021-44832-versions"},
		{name: "cve-2021-45105 and cve-2021-44832 disabled on 2.17.0", disableExtraCVEs: true, directory: "../examples/cve-2021-44832-versions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cmd *exec.Cmd
			if tc.disableExtraCVEs {
				cmd = exec.Command(cli, "crawl", "--disable-cve-2021-45105-detection", "--disable-cve-2021-44832-detection", tc.directory)
			} else {
				cmd = exec.Command(cli, "crawl", tc.directory)
			}
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "command %v failed with output:\n%s", cmd.Args, string(output))
			got := string(output)
			if tc.disableExtraCVEs {
				assert.NotContains(t, got, "Files affected by CVE-2021-44228 or CVE-2021-45046 or CVE-2021-45105 detected")
				assert.Contains(t, got, "No files affected by CVE-2021-44228 or CVE-2021-45046 detected")
			} else {
				assert.Contains(t, got, "Files affected by CVE-2021-44228 or CVE-2021-45046 or CVE-2021-45105 or CVE-2021-44832 detected")
				assert.NotContains(t, got, "No files affected by CVE-2021-44228 or CVE-2021-45046 or CVE-2021-45105 or CVE-2021-44832 detected")
			}
		})
	}
}

func TestDisableJNDILookupFlag(t *testing.T) {
	cli, err := products.Bin("log4j-sniffer")
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		directory string
		count     int
		finding   crawl.Finding
	}{
		{name: "issue not reported if --disable-jndi-lookup flag is specified", directory: "../examples/light_shading"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(cli, "crawl", "--json", "--disable-flagging-jndi-lookup", "--summary=false", tc.directory)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "command %v failed with output:\n%s", cmd.Args, string(output))

			var cve crawl.JavaCVEInstance
			err = json.Unmarshal(output, &cve)
			require.NoError(t, err, "Failed to unmarshal as JSON: %q", string(output))

			assert.NotContains(t, cve.Findings, "jndiLookupClassName")
		})
	}
}

func TestSummaryContainsExpectedFields(t *testing.T) {
	cli, err := products.Bin("log4j-sniffer")
	require.NoError(t, err)

	cmd := exec.Command(cli, "crawl", "../examples", "--ignore-dir", "java_projects/", "--summary", "--json")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "command %v failed with output:\n%s", cmd.Args, string(output))
	lines := strings.Split(string(output), "\n")
	summaryLine := lines[len(lines)-2]
	var summary map[string]int
	require.NoError(t, json.Unmarshal([]byte(summaryLine), &summary))
	assert.Equal(t, map[string]int{
		"filesScanned":           37,
		"permissionDeniedErrors": 0,
		"pathErrors":             0,
		"numImpactedFiles":       29,
		"findings":               30,
		"pathsSkipped":           3,
	}, summary)
}

func TestArchiveOpenModeValueError(t *testing.T) {
	cli, err := products.Bin("log4j-sniffer")
	require.NoError(t, err)

	cmd := exec.Command(cli, "crawl", ".", "--archive-open-mode", "nope")
	output, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(output), "unsupported --archive-open-mode: nope")
}

func TestTraceLoggingFlag(t *testing.T) {
	cli, err := products.Bin("log4j-sniffer")
	require.NoError(t, err)

	file, err := ioutil.TempFile(t.TempDir(), "")
	require.NoError(t, err)
	cmd := exec.Command(cli, "crawl", "--enable-trace-logging", file.Name())
	output, err := cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(output), "[TRACE]")
}
