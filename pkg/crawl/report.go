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
	"strings"

	"github.com/fatih/color"
)

type Reporter struct {
	// if non-nil, reported output is written to this writer
	OutputWriter io.Writer
	// True if reported output should be JSON, false otherwise
	OutputJSON bool
	// True if the reported output should consist of only the path to the file with the CVE, false otherwise. Only has
	// an effect if OutputJSON is false.
	OutputFilePathOnly bool
	lastFindingFile    string
	// Disables results only matching JndiLookup classes
	DisableFlaggingJndiLookup bool
	// CVEResolver contains config for ignoring specific CVEs from reporting
	CVEResolver CVEResolver
	// Disables flagging issues where version of log4j is not known
	DisableFlaggingUnknownVersions bool
	// Number of files with issues that have been reported
	fileCount int64
	// Number of individual findings that have been reported
	findingCount int64
}

type JavaCVEInstance struct {
	Message       string   `json:"message"`
	FilePath      string   `json:"filePath"`
	DetailedPath  string   `json:"detailedPath"`
	CVEsDetected  []string `json:"cvesDetected"`
	Findings      []string `json:"findings"`
	Log4JVersions []string `json:"log4jVersions"`
}

// Report the finding based on the configuration of the Reporter.
// The fileCount will be incremented if the finding is a new finding, i.e. a consecutive finding based on the same file when
// The findingCount will be incremented for every finding reported.
// OutputFilePathOnly is set to true will not cause the counter to be incremented.
// The returned boolean will always be true to represent that further inspection of the same file should continue.
func (r *Reporter) Report(ctx context.Context, path Path, result Finding, versions Versions) bool {
	if r.DisableFlaggingUnknownVersions && (len(versions) == 0 || len(versions) == 1 && versions.contains(UnknownVersion)) {
		return true
	}
	var cvesFound []string
	if len(versions) == 0 {
		cvesFound = []string{"unknown version - unknown CVE status"}
	} else {
		vs, includesInvalid := ParseLog4jVersions(versions)
		cvesFound = r.CVEResolver.CVEs(vs)
		if includesInvalid {
			cvesFound = append(cvesFound, "invalid version - unknown CVE status")
		}
	}
	if len(cvesFound) == 0 {
		return true
	}

	if r.DisableFlaggingJndiLookup && jndiLookupResultsOnly(result) {
		return true
	}

	r.findingCount++
	if r.lastFindingFile != path[0] {
		r.fileCount++
	}
	defer func() { r.lastFindingFile = path[0] }()

	// if no output writer is specified, nothing more to do
	if r.OutputWriter == nil {
		return true
	}

	cveMessage := strings.Join(cvesFound, ", ") + " detected"

	var readableReasons []string
	var findingNames []string
	if result&JndiLookupClassName > 0 && !r.DisableFlaggingJndiLookup {
		readableReasons = append(readableReasons, "JndiLookup class name matched")
		findingNames = append(findingNames, lowerCamelCaseFindingString(JndiLookupClassName))
	}
	if result&JndiLookupClassPackageAndName > 0 && !r.DisableFlaggingJndiLookup {
		readableReasons = append(readableReasons, "JndiLookup class and package name matched")
		findingNames = append(findingNames, lowerCamelCaseFindingString(JndiLookupClassPackageAndName))
	}
	if result&JndiManagerClassName > 0 {
		readableReasons = append(readableReasons, "JndiManager class name matched")
		findingNames = append(findingNames, lowerCamelCaseFindingString(JndiManagerClassName))
	}
	if result&JarName > 0 {
		readableReasons = append(readableReasons, "jar name matched")
		findingNames = append(findingNames, lowerCamelCaseFindingString(JarName))
	}
	if result&JarNameInsideArchive > 0 {
		readableReasons = append(readableReasons, "jar name inside archive matched")
		findingNames = append(findingNames, lowerCamelCaseFindingString(JarNameInsideArchive))
	}
	if result&JndiManagerClassPackageAndName > 0 {
		readableReasons = append(readableReasons, "JndiManager class and package name matched")
		findingNames = append(findingNames, lowerCamelCaseFindingString(JndiManagerClassPackageAndName))
	}
	if result&ClassFileMd5 > 0 {
		readableReasons = append(readableReasons, "class file MD5 matched")
		findingNames = append(findingNames, lowerCamelCaseFindingString(ClassFileMd5))
	}
	if result&ClassBytecodeInstructionMd5 > 0 {
		readableReasons = append(readableReasons, "byte code instruction MD5 matched")
		findingNames = append(findingNames, lowerCamelCaseFindingString(ClassBytecodeInstructionMd5))
	}
	if result&JarFileObfuscated > 0 {
		readableReasons = append(readableReasons, "jar file appeared obfuscated")
		findingNames = append(findingNames, lowerCamelCaseFindingString(JarFileObfuscated))
	}
	if result&ClassBytecodePartialMatch > 0 {
		readableReasons = append(readableReasons, "byte code partially matched known version")
		findingNames = append(findingNames, lowerCamelCaseFindingString(ClassBytecodePartialMatch))
	}

	sortedVersions := versions.SortedList()
	var outputToWrite string
	if r.OutputJSON {
		cveInfo := JavaCVEInstance{
			Message:       cveMessage,
			FilePath:      path[0],
			DetailedPath:  path.Joined(),
			CVEsDetected:  cvesFound,
			Findings:      findingNames,
			Log4JVersions: sortedVersions,
		}
		// should not fail
		jsonBytes, _ := json.Marshal(cveInfo)
		outputToWrite = string(jsonBytes)
	} else if r.OutputFilePathOnly {
		if r.lastFindingFile == path[0] {
			return true
		}
		outputToWrite = path[0]
	} else {
		outputToWrite = color.YellowString("[MATCH] "+cveMessage+" in file %s. log4j versions: %s. Reasons: %s", path, strings.Join(sortedVersions, ", "), strings.Join(readableReasons, ", "))
	}
	_, _ = fmt.Fprintln(r.OutputWriter, outputToWrite)
	return true
}

func lowerCamelCaseFindingString(f Finding) string {
	s := f.String()
	if len(s) > 1 {
		return strings.ToLower(string(s[0])) + s[1:]
	}
	return s
}

func jndiLookupResultsOnly(result Finding) bool {
	return result == JndiLookupClassName || result == JndiLookupClassPackageAndName
}

// FileCount returns the number of unique files that have been reported.
func (r Reporter) FileCount() int64 {
	return r.fileCount
}

// FindingCount returns the number of unique findings that have been reported.
func (r Reporter) FindingCount() int64 {
	return r.findingCount
}
