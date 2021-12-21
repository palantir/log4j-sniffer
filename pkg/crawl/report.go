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
	// Disables detection of CVE-45105
	DisableCVE45105 bool
	// Number of issues that have been found
	count int64
	// The tags of the image currently being reported
	imageTags []string
	// The ID of the image currently being reported
	imageID string
}

type JavaCVEInstance struct {
	Message                       string   `json:"message"`
	FilePath                      string   `json:"filePath"`
	ClassNameMatched              bool     `json:"classNameMatched"`
	ClassPackageAndNameMatch      bool     `json:"classPackageAndNameMatch"`
	ClassFileMD5Matched           bool     `json:"classFileMd5Matched"`
	ByteCodeInstructionMD5Matched bool     `json:"bytecodeInstructionMd5Matched"`
	JarNameMatched                bool     `json:"jarNameMatched"`
	JarNameInsideArchiveMatched   bool     `json:"jarNameInsideArchiveMatched"`
	Log4JVersions                 []string `json:"log4jVersions"`
	ImageID                       string   `json:"imageID,omitempty"`
	ImageTags                     []string `json:"imageTags,omitempty"`
}

// Collect increments the count of number of calls to Reporter.Collect and logs the path of the vulnerable file to disk.
func (r *Reporter) Collect(ctx context.Context, path string, d fs.DirEntry, result Finding, versionSet Versions) {
	versions := sortVersions(versionSet)
	if r.DisableCVE45105 && cve45105VersionsOnly(versions) {
		return
	}
	r.count++

	// if no output writer is specified, nothing more to do
	if r.OutputWriter == nil {
		return
	}

	cveMessage := r.buildCVEMessage(versions)
	cveInfo := JavaCVEInstance{
		Message:                       cveMessage,
		FilePath:                      path,
		ClassNameMatched:              result&ClassName > 0,
		JarNameMatched:                result&JarName > 0,
		JarNameInsideArchiveMatched:   result&JarNameInsideArchive > 0,
		ClassPackageAndNameMatch:      result&ClassPackageAndName > 0,
		ClassFileMD5Matched:           result&ClassFileMd5 > 0,
		ByteCodeInstructionMD5Matched: result&ClassBytecodeInstructionMd5 > 0,
		Log4JVersions:                 versions,
		ImageTags:                     r.imageTags,
		ImageID:                       r.imageID,
	}

	var output string
	if r.OutputJSON {
		// should not fail
		jsonBytes, _ := json.Marshal(cveInfo)
		output = string(jsonBytes)
	} else {
		var reasons []string
		if cveInfo.ClassNameMatched {
			reasons = append(reasons, "class name matched")
		}
		if cveInfo.JarNameMatched {
			reasons = append(reasons, "jar name matched")
		}
		if cveInfo.JarNameInsideArchiveMatched {
			reasons = append(reasons, "jar name inside archive matched")
		}
		if cveInfo.ClassPackageAndNameMatch {
			reasons = append(reasons, "class and package name matched")
		}
		if cveInfo.ClassFileMD5Matched {
			reasons = append(reasons, "class file MD5 matched")
		}
		if cveInfo.ByteCodeInstructionMD5Matched {
			reasons = append(reasons, "byte code instruction MD5 matched")
		}
		output = fmt.Sprintf(cveMessage+" in file %s. log4j versions: %s. Reasons: %s", path, strings.Join(versions, ", "), strings.Join(reasons, ", "))
	}
	_, _ = fmt.Fprintln(r.OutputWriter, output)
}

func (r *Reporter) buildCVEMessage(versions []string) string {
	if r.imageID != "" {
		return r.buildCVEDockerMessage(versions)
	}

	if r.DisableCVE45105 {
		return "CVE-2021-45046 detected"
	}
	if cve45105VersionsOnly(versions) {
		return "CVE-2021-45105 detected"
	}
	return "CVE-2021-45046 and CVE-2021-45105 detected"
}

func (r *Reporter) buildCVEDockerMessage(versions []string) string {
	if r.DisableCVE45105 {
		return fmt.Sprintf("CVE-2021-45046 detected in image %s %s", r.imageID, r.imageTags)
	}
	if cve45105VersionsOnly(versions) {
		return fmt.Sprintf("CVE-2021-45105 detected in image %s %s", r.imageID, r.imageTags)
	}
	return fmt.Sprintf("CVE-2021-45046 and CVE-2021-45105 detected in image %s %s", r.imageID, r.imageTags)
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

func (r *Reporter) WithImage(id string, tags []string) *Reporter {
	r.imageID = id
	r.imageTags = tags
	return r
}
