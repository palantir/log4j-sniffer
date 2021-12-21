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
	Message                              string   `json:"message"`
	FilePath                             string   `json:"filePath"`
	JndiLookupClassNameMatched           bool     `json:"jndiLookupClassNameMatched"`
	JndiLookupClassPackageAndNameMatched bool     `json:"jndiLookupClassPackageAndNameMatched"`
	JndiManagerClassNameMatched          bool     `json:"jndiManagerClassNameMatched"`
	JndiClassPackageAndNameMatch         bool     `json:"jndiManagerClassPackageAndNameMatch"`
	ClassFileMD5Matched                  bool     `json:"classFileMd5Matched"`
	ByteCodeInstructionMD5Matched        bool     `json:"bytecodeInstructionMd5Matched"`
	ByteCodePartialMatch                 bool     `json:"bytecodePartialMatch"`
	JarNameMatched                       bool     `json:"jarNameMatched"`
	JarNameInsideArchiveMatched          bool     `json:"jarNameInsideArchiveMatched"`
	Log4JVersions                        []string `json:"log4jVersions"`
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
	cveInfo := JavaCVEInstance{
		Message:                              cveMessage,
		FilePath:                             path,
		JndiLookupClassNameMatched:           result&JndiLookupClassName > 0,
		JndiLookupClassPackageAndNameMatched: result&JndiLookupClassPackageAndName > 0,
		JndiManagerClassNameMatched:          result&JndiManagerClassName > 0,
		JarNameMatched:                       result&JarName > 0,
		JarNameInsideArchiveMatched:          result&JarNameInsideArchive > 0,
		JndiClassPackageAndNameMatch:         result&JndiManagerClassPackageAndName > 0,
		ClassFileMD5Matched:                  result&ClassFileMd5 > 0,
		ByteCodeInstructionMD5Matched:        result&ClassBytecodeInstructionMd5 > 0,
		ByteCodePartialMatch:                 result&ClassBytecodePartialMatch > 0,
		Log4JVersions:                        versions,
	}

	var output string
	if r.OutputJSON {
		// should not fail
		jsonBytes, _ := json.Marshal(cveInfo)
		output = string(jsonBytes)
	} else {
		var reasons []string
		if cveInfo.JndiLookupClassNameMatched {
			reasons = append(reasons, "JndiLookup class name matched")
		}
		if cveInfo.JndiLookupClassPackageAndNameMatched {
			reasons = append(reasons, "JndiLookup class and package name matched")
		}
		if cveInfo.JndiManagerClassNameMatched {
			reasons = append(reasons, "JndiManager class name matched")
		}
		if cveInfo.JarNameMatched {
			reasons = append(reasons, "jar name matched")
		}
		if cveInfo.JarNameInsideArchiveMatched {
			reasons = append(reasons, "jar name inside archive matched")
		}
		if cveInfo.JndiClassPackageAndNameMatch {
			reasons = append(reasons, "JndiManager class and package name matched")
		}
		if cveInfo.ClassFileMD5Matched {
			reasons = append(reasons, "class file MD5 matched")
		}
		if cveInfo.ByteCodeInstructionMD5Matched {
			reasons = append(reasons, "byte code instruction MD5 matched")
		}
		if cveInfo.ByteCodePartialMatch {
			reasons = append(reasons, "byte code partially matched known version")
		}
		output = fmt.Sprintf(cveMessage+" in file %s. log4j versions: %s. Reasons: %s", path, strings.Join(versions, ", "), strings.Join(reasons, ", "))
	}
	_, _ = fmt.Fprintln(r.OutputWriter, output)
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
