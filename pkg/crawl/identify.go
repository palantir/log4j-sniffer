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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/pkg/errors"
	"go.uber.org/ratelimit"
)

type Finding int
type Versions map[string]struct{}

const (
	NothingDetected                Finding = 0
	JndiLookupClassName            Finding = 1 << iota
	JndiLookupClassPackageAndName  Finding = 1 << iota
	JndiManagerClassName           Finding = 1 << iota
	JarName                        Finding = 1 << iota
	JarNameInsideArchive           Finding = 1 << iota
	JndiManagerClassPackageAndName Finding = 1 << iota
	JarFileObfuscated              Finding = 1 << iota
	ClassBytecodePartialMatch      Finding = 1 << iota
	ClassBytecodeInstructionMd5    Finding = 1 << iota
	ClassFileMd5                   Finding = 1 << iota
)

func (f Finding) String() string {
	var out []string
	if f&JndiLookupClassName > 0 {
		out = append(out, "JndiLookupClassName")
	}
	if f&JndiLookupClassPackageAndName > 0 {
		out = append(out, "JndiLookupClassPackageAndName")
	}
	if f&JndiManagerClassName > 0 {
		out = append(out, "JndiManagerClassName")
	}
	if f&JarName > 0 {
		out = append(out, "JarName")
	}
	if f&JarNameInsideArchive > 0 {
		out = append(out, "JarNameInsideArchive")
	}
	if f&JndiManagerClassPackageAndName > 0 {
		out = append(out, "JndiManagerClassPackageAndName")
	}
	if f&JarFileObfuscated > 0 {
		out = append(out, "JarFileObfuscated")
	}
	if f&ClassBytecodePartialMatch > 0 {
		out = append(out, "ClassBytecodePartialMatch")
	}
	if f&ClassBytecodeInstructionMd5 > 0 {
		out = append(out, "ClassBytecodeInstructionMd5")
	}
	if f&ClassFileMd5 > 0 {
		out = append(out, "ClassFileMd5")
	}
	return strings.Join(out, ",")
}

const (
	UnknownVersion = "unknown"
)

var log4jRegex = regexp.MustCompile(`(?i)^log4j-core-(\d+\.\d+(?:\..*)?)\.jar$`)

type Identifier interface {
	Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, Versions, error)
}

// Log4jIdentifier identifies files that are vulnerable to Log4J-related CVEs.
type Log4jIdentifier struct {
	EnableTraceLogging                 bool
	ErrorWriter                        io.Writer
	DetailedOutputWriter               io.Writer
	Limiter                            ratelimit.Limiter
	IdentifyObfuscation                bool
	ObfuscatedClassNameAverageLength   int
	ObfuscatedPackageNameAverageLength int
	OpenFile                           func(string) (*os.File, error)
	ArchiveWalkTimeout                 time.Duration
	ArchiveMaxDepth                    uint
	ArchiveWalkers                     func(string) (archive.WalkerProvider, int64, bool)
	HandleFinding                      HandleFindingFunc
}

// HandleFindingFunc is called with the given findings and versions when Log4jIdentifier identifies
// a log4j vulnerability whilst crawling the filesystem.
type HandleFindingFunc func(ctx context.Context, path NestedPath, result Finding, version Versions)

// Identify identifies vulnerable files, passing each finding along with its versions to the Log4jIdentifier's HandleFindingFunc.
func (i *Log4jIdentifier) Identify(ctx context.Context, path string, filename string) (skipped uint64, err error) {
	i.printTraceMessage("Identifying file %s", path)

	if i.ArchiveWalkTimeout > 0 {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, i.ArchiveWalkTimeout)
		defer cancel()
		ctx = ctxWithTimeout
	}

	lowercaseFilename := strings.ToLower(filename)

	if strings.HasSuffix(lowercaseFilename, ".jar") {
		var err error
		if err != nil {
			return 0, err
		}
	}

	getWalker, _, ok := i.ArchiveWalkers(lowercaseFilename)
	if !ok {
		return 0, nil
	}

	walker, close, tErr := getWalker.FromFile(path)
	if tErr != nil {
		return 0, tErr
	}
	defer func() {
		if cErr := close(); err == nil && cErr != nil {
			err = cErr
		}
	}()

	nestedPath := []string{path}
	log4jNameMatch, nameVulnerability, nameVersions := i.archiveNameVulnerability(nestedPath)
	inArchive, inZipVs, skipped, err := i.findArchiveContentVulnerabilities(ctx, 0, walker, nestedPath)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to walk archive %s", path)
	}

	reportFindings, reportVersions := resolveNameAndContentFindings(log4jNameMatch, nameVulnerability, nameVersions, inArchive, inZipVs)
	if reportFindings == NothingDetected {
		return skipped, err
	}

	i.HandleFinding(ctx, nestedPath, reportFindings, reportVersions)
	return skipped, err
}

func resolveNameAndContentFindings(nameMatchesLog4jJar bool, nameFinding Finding, nameVersions Versions, archiveFinding Finding, archiveVersions Versions) (Finding, Versions) {
	if archiveFinding == NothingDetected {
		if nameFinding != NothingDetected {
			return nameFinding, nameVersions
		}
		return NothingDetected, nil
	}

	// If detections are made but no clues of any vulnerable versions within the archive,
	// then we determine non-vulnerable if the archive name has been matched but with a
	// non-vulnerable filename.
	if len(archiveVersions) == 0 && nameMatchesLog4jJar && nameFinding == NothingDetected {
		return NothingDetected, nil
	}

	findings := nameFinding | archiveFinding
	if findings == NothingDetected {
		return findings, nil
	}

	versions := archiveVersions
	for v := range nameVersions {
		versions[v] = struct{}{}
	}
	if len(versions) == 0 {
		versions = map[string]struct{}{UnknownVersion: {}}
	}
	return findings, versions
}

func (i *Log4jIdentifier) archiveNameVulnerability(nestedPaths NestedPath) (bool, Finding, Versions) {
	path := nestedPaths[len(nestedPaths)-1]
	var jarNameMatch bool
	var jarVersion string
	var jarFinding Finding
	if len(nestedPaths) == 1 {
		// we are on disk and so need to split using filepath to support different OS separators
		_, filename := filepath.Split(path)
		jarVersion, jarNameMatch = FileNameMatchesLog4jJar(filename)
		jarFinding = JarName
	} else {
		// we are in an archive and so can assume separator is '/'
		jarVersion, jarNameMatch = pathMatchesLog4JVersion(path)
		jarFinding = JarNameInsideArchive
		if jarNameMatch {
			// ???: shall we only report on vulnerable versions here?
			//    : if so, will the version below do or do we want a specific one for nested archives?
			i.printInfoFinding("Found nesting archive matching the log4j-core jar name at %s", nestedPaths.Joined())
		}
	}

	archiveVersionVulnerable := vulnerableVersion(jarVersion)
	if jarNameMatch && archiveVersionVulnerable {
		i.printInfoFinding("Found archive with name matching vulnerable log4j-core format at %s", nestedPaths.Joined())
		return jarNameMatch, jarFinding, map[string]struct{}{jarVersion: {}}
	}
	return jarNameMatch, NothingDetected, nil
}

func (i *Log4jIdentifier) findArchiveContentVulnerabilities(ctx context.Context, depth uint, walk archive.WalkFn, nestedPaths NestedPath) (Finding, Versions, uint64, error) {
	archiveResult := NothingDetected
	versions := make(Versions)

	var skipped uint64
	i.Limiter.Take()
	if err := walk(ctx, i.vulnerabilityFileWalkFunc(depth, &archiveResult, versions, &skipped, nestedPaths)); err != nil {
		return archiveResult, versions, skipped, err
	}

	return archiveResult, versions, skipped, nil
}

func (i *Log4jIdentifier) vulnerabilityFileWalkFunc(depth uint, result *Finding, versions Versions, skipped *uint64, paths []string) archive.FileWalkFn {
	return func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
		nestedPaths := NestedPath(append(paths, path))
		getWalker, maxSize, ok := i.ArchiveWalkers(path)
		if ok {
			if maxSize > -1 && size >= maxSize {
				*skipped = *skipped + 1
				i.printInfoFinding("Skipping nested archive above configured maximum size at %s", nestedPaths.Joined())
			} else if depth >= i.ArchiveMaxDepth {
				_, nameFinding, jarNameVersions := i.archiveNameVulnerability(nestedPaths)
				// If there is a finding from the name we don't consider the file skipped.
				if nameFinding == NothingDetected {
					*skipped = *skipped + 1
					i.printInfoFinding("Skipping nested archive nested beyond configured maximum level at %s", nestedPaths.Joined())
				} else {
					i.HandleFinding(ctx, nestedPaths, nameFinding, jarNameVersions)
				}
			} else {
				walker, close, archiveErr := getWalker.FromReader(contents)
				if archiveErr != nil {
					return false, archiveErr
				}
				defer func() {
					if cErr := close(); err == nil {
						err = cErr
					}
				}()

				archiveContentResult, archiveVersions, innerSkipped, err := i.findArchiveContentVulnerabilities(ctx, depth+1, walker, nestedPaths)
				*skipped = *skipped + innerSkipped
				if err != nil {
					return false, err
				}

				jarNameMatch, nameFinding, jarNameVersions := i.archiveNameVulnerability(nestedPaths)
				findings, vs := resolveNameAndContentFindings(jarNameMatch, nameFinding, jarNameVersions, archiveContentResult, archiveVersions)
				if findings != NothingDetected {
					i.HandleFinding(ctx, nestedPaths, findings, vs)
				}
			}
		}

		filename := filenameFromPathInsideArchive(path)
		if strings.HasSuffix(filename, ".class") || strings.HasPrefix(filename, "JndiManager.") {
			i.printTraceMessage("Looking for class file match %s", path)
			finding, versionInFile, versionMatch := i.lookForClassFileMatch(path, filename, size, contents)
			if finding == NothingDetected {
				return true, nil
			}
			if versionMatch {
				if !vulnerableVersion(versionInFile) {
					return true, nil
				}
				versions[versionInFile] = struct{}{}
			}
			*result |= finding
		}
		return true, nil
	}
}

func (i *Log4jIdentifier) lookForClassFileMatch(path, filename string, size int64, contents io.Reader) (Finding, string, bool) {
	if path == "org/apache/logging/log4j/core/net/JndiManager.class" {
		finding, version, hashMatch := LookForHashMatch(contents, size)
		if hashMatch {
			i.printDetailedHashFinding(path, finding)
			return JndiManagerClassPackageAndName | finding, version, true
		}
		i.printInfoFinding("Found JndiManager class that did not match any known versions at %n", path)
		return JndiManagerClassPackageAndName, "", false
	}
	if path == "org/apache/logging/log4j/core/lookup/JndiLookup.class" {
		i.printInfoFinding("Found JndiLookup class in the log4j package at %s", path)
		return JndiLookupClassPackageAndName, "", false
	}

	obfuscated := i.classMeetsObfuscationThreshold(path, filename)
	hashClass := strings.HasSuffix(path, "JndiManager.class") || strings.HasPrefix(filename, "JndiManager.") || obfuscated
	if hashClass {
		finding, version, hashMatch := LookForHashMatch(contents, size)
		if strings.HasSuffix(path, "JndiManager.class") {
			i.printInfoFinding("Found JndiManager class not in the log4j package at %s", path)
			finding |= JndiManagerClassName
		}
		if hashMatch {
			i.printDetailedHashFinding(path, finding)
			if obfuscated {
				finding |= JarFileObfuscated
			}
			return finding, version, true
		}
		return finding, "", false
	}
	if strings.HasSuffix(path, "JndiLookup.class") {
		i.printInfoFinding("Found JndiLookup class not in the log4j package at %s", path)
		return JndiLookupClassName, "", false
	}
	return NothingDetected, "", false
}

func (i *Log4jIdentifier) classMeetsObfuscationThreshold(path, filename string) bool {
	if !i.IdentifyObfuscation || !strings.HasSuffix(filename, ".class") {
		return false
	}
	if len(filename)-6 > i.ObfuscatedClassNameAverageLength {
		return false
	}
	numPackages := strings.Count(path, "/")
	if numPackages == 0 {
		return true
	}
	averagePackageLength := (len(path) - len(filename)) / numPackages
	return averagePackageLength <= i.ObfuscatedPackageNameAverageLength
}

func (i *Log4jIdentifier) printDetailedHashFinding(path string, finding Finding) {
	if finding&ClassFileMd5 > 0 {
		i.printInfoFinding("Found JndiManager class that was an exact md5 match for a known version at %s", path)
	} else if finding&ClassBytecodeInstructionMd5 > 0 {
		i.printInfoFinding("Found JndiManager class that had identical bytecode instruction as a known version at %s", path)
	} else if finding&ClassBytecodePartialMatch > 0 {
		i.printInfoFinding("Found JndiManager class that partially matched the bytecode of a known version at %s", path)
	}
}

func (i *Log4jIdentifier) printTraceMessage(message, location string) {
	if i.DetailedOutputWriter != nil && i.EnableTraceLogging {
		_, _ = fmt.Fprintln(i.DetailedOutputWriter, fmt.Sprintf("[TRACE] "+message, location))
	}
}

func (i *Log4jIdentifier) printInfoFinding(message, location string) {
	if i.DetailedOutputWriter != nil {
		_, _ = fmt.Fprintln(i.DetailedOutputWriter, color.CyanString("[INFO] "+message, location))
	}
}

func (i *Log4jIdentifier) printErrorFinding(message string, err error) {
	if i.ErrorWriter != nil {
		_, _ = fmt.Fprintln(i.ErrorWriter, color.RedString("[ERROR] "+message, err))
	}
}

func pathMatchesLog4JVersion(path string) (string, bool) {
	return FileNameMatchesLog4jJar(filenameFromPathInsideArchive(path))
}

func filenameFromPathInsideArchive(path string) string {
	filename, finalSlashIndex := path, strings.LastIndex(path, "/")
	if finalSlashIndex > -1 {
		filename = path[finalSlashIndex+1:]
	}
	return filename
}

func FileNameMatchesLog4jJar(filename string) (string, bool) {
	matches := log4jRegex.FindStringSubmatch(strings.ToLower(filename))
	if len(matches) == 0 {
		return "", false
	}
	version := matches[1]
	return version, true
}

func vulnerableVersion(version string) bool {
	major, minor, patch, parsed := ParseLog4jVersion(version)
	if !parsed {
		return true
	}
	return (major == 2 && minor <= 17) && !(major == 2 && minor == 17 && patch >= 1) && !(major == 2 && minor == 12 && patch >= 4) && !(major == 2 && minor == 3 && patch >= 2)
}
