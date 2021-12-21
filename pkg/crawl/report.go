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

package crawl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"github.com/fatih/color"
)

type Reporter struct {
	// if non-nil, reported output is written to this writer
	OutputWriter io.Writer
	// True if reported output should be JSON, false otherwise
	OutputJSON bool
	// Disables results only matching JndiLookup classes
	DisableFlaggingJndiLookup bool
	// Disables detection of CVE-45105
	DisableCVE45105 bool
	// Number of issues that have been found
	count int64
}

type JavaCVEInstance struct {
	Message       string   `json:"message"`
	FilePath      string   `json:"filePath"`
	Findings      []string `json:"findings"`
	Log4JVersions []string `json:"log4jVersions"`
}

// Collect increments the count of number of calls to Reporter.Collect and logs the path of the vulnerable file to disk.
func (r *Reporter) Collect(ctx context.Context, path string, d fs.DirEntry, result Finding, versionSet Versions) {
	versions := sortVersions(versionSet)
	if r.DisableCVE45105 && cve45105VersionsOnly(versions) {
		return
	}
	if r.DisableFlaggingJndiLookup && jndiLookupResultsOnly(result) {
		return
	}
	r.count++

	// if no output writer is specified, nothing more to do
	if r.OutputWriter == nil {
		return
	}

	cveMessage := r.buildCVEMessage(versions)

	var readableReasons []string
	var findingNames []string
	if result&JndiLookupClassName > 0 {
		readableReasons = append(readableReasons, "JndiLookup class name matched")
		findingNames = append(findingNames, "jndiLookupClassName")
	}
	if result&JndiLookupClassPackageAndName > 0 {
		readableReasons = append(readableReasons, "JndiLookup class and package name matched")
		findingNames = append(findingNames, "jndiLookupClassPackageAndName")
	}
	if result&JndiManagerClassName > 0 {
		readableReasons = append(readableReasons, "JndiManager class name matched")
		findingNames = append(findingNames, "jndiManagerClassName")
	}
	if result&JarName > 0 {
		readableReasons = append(readableReasons, "jar name matched")
		findingNames = append(findingNames, "jarName")
	}
	if result&JarNameInsideArchive > 0 {
		readableReasons = append(readableReasons, "jar name inside archive matched")
		findingNames = append(findingNames, "jarNameInsideArchive")
	}
	if result&JndiManagerClassPackageAndName > 0 {
		readableReasons = append(readableReasons, "JndiManager class and package name matched")
		findingNames = append(findingNames, "jndiManagerClassPackageAndName")
	}
	if result&ClassFileMd5 > 0 {
		readableReasons = append(readableReasons, "class file MD5 matched")
		findingNames = append(findingNames, "classFileMd5")
	}
	if result&ClassBytecodeInstructionMd5 > 0 {
		readableReasons = append(readableReasons, "byte code instruction MD5 matched")
		findingNames = append(findingNames, "classBytecodeInstructionMd5")
	}
	if result&JarFileObfuscated > 0 {
		readableReasons = append(readableReasons, "jar file appeared obfuscated")
		findingNames = append(findingNames, "jarFileObfuscated")
	}
	if result&ClassBytecodePartialMatch > 0 {
		readableReasons = append(readableReasons, "byte code partially matched known version")
		findingNames = append(findingNames, "classBytecodePartialMatch")
	}

	if r.OutputJSON {
		cveInfo := JavaCVEInstance{
			Message:       cveMessage,
			FilePath:      path,
			Findings:      findingNames,
			Log4JVersions: versions,
		}
		// should not fail
		jsonBytes, _ := json.Marshal(cveInfo)
		_, _ = fmt.Fprintln(r.OutputWriter, string(jsonBytes))
	} else {
		_, _ = fmt.Fprintln(r.OutputWriter, color.YellowString("[MATCH] "+cveMessage+" in file %s. log4j versions: %s. Reasons: %s", path, strings.Join(versions, ", "), strings.Join(readableReasons, ", ")))
	}
}

func (r *Reporter) buildCVEMessage(versions []string) string {
	if r.DisableCVE45105 {
		return "CVE-2021-45046 detected"
	}
	if cve45105VersionsOnly(versions) {
		return "CVE-2021-45105 detected"
	}
	return "CVE-2021-45046 and CVE-2021-45105 detected"
}

func cve45105VersionsOnly(versions []string) bool {
	if len(versions) == 1 && (versions[0] == "2.16.0" || versions[0] == "2.12.2") {
		return true
	}
	if len(versions) == 2 && versions[0] == "2.12.2" && versions[1] == "2.16.0" {
		return true
	}
	return false
}

func jndiLookupResultsOnly(result Finding) bool {
	return result == JndiLookupClassName || result == JndiLookupClassPackageAndName
}

func sortVersions(versions Versions) []string {
	var out []string
	for v := range versions {
		out = append(out, v)
	}
	// N.B. Lexical sort will mess with base-10 versions, but it's better than random.
	sort.Strings(out)
	return out
}

// Count returns the number of times that Collect has been called
func (r Reporter) Count() int64 {
	return r.count
}
