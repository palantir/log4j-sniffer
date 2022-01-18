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
	"archive/zip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/java"
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
	ErrorWriter                        io.Writer
	DetailedOutputWriter               io.Writer
	Limiter                            ratelimit.Limiter
	IdentifyObfuscation                bool
	ObfuscatedClassNameAverageLength   float32
	ObfuscatedPackageNameAverageLength float32
	OpenFile                           func(string) (*os.File, error)
	ArchiveWalkTimeout                 time.Duration
	ArchiveMaxDepth                    uint
	ArchiveWalkers                     func(string) (archive.WalkerProvider, int64, bool)
}

// Identify identifies vulnerable files.
// The function identifies:
// - vulnerable log4j jar files.
// - zipped files containing vulnerable log4j files, using the provided ZipFileLister.
func (i *Log4jIdentifier) Identify(ctx context.Context, path string, d fs.DirEntry) (result Finding, versions Versions, skipped uint64, err error) {
	if i.ArchiveWalkTimeout > 0 {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, i.ArchiveWalkTimeout)
		defer cancel()
		ctx = ctxWithTimeout
	}

	result = NothingDetected
	versions = make(Versions)
	lowercaseFilename := strings.ToLower(d.Name())

	// TODO(glynternet): support checking obfuscation at further nested levels.
	var obfuscated bool
	var log4jMatch bool
	if strings.HasSuffix(lowercaseFilename, ".jar") {
		var err error
		obfuscated, err = i.checkForObfuscation(path)
		if err != nil {
			return NothingDetected, nil, 0, err
		}
		archiveVersion, match := fileNameMatchesLog4jVersion(lowercaseFilename)
		if match && vulnerableVersion(archiveVersion) {
			result |= JarName
			versions[archiveVersion] = struct{}{}
			i.printInfoFinding("Found archive with name matching vulnerable log4j-core format at %s", path)
		}
		log4jMatch = match
	}

	getWalker, _, ok := i.ArchiveWalkers(lowercaseFilename)
	if !ok {
		return result, versions, 0, nil
	}
	file, openErr := i.OpenFile(path)
	if openErr != nil {
		return NothingDetected, nil, 0, openErr
	}
	defer func() {
		if cErr := file.Close(); err == nil && cErr != nil {
			err = cErr
		}
	}()

	walker, close, tErr := getWalker.FromFile(file)
	if tErr != nil {
		return NothingDetected, nil, 0, tErr
	}
	defer func() {
		if cErr := close(); err == nil && cErr != nil {
			err = cErr
		}
	}()
	inZip, inZipVs, skipped, err := i.findArchiveVulnerabilities(ctx, 0, walker, obfuscated)
	if err != nil {
		return 0, nil, 0, errors.Wrapf(err, "failed to walk archive %s", file.Name())
	}
	for v := range inZipVs {
		versions[v] = struct{}{}
	}
	// If file on disk matches log4j but no signs of vulnerable version have been found
	// during identification phase, then we assume non-vulnerable.
	if log4jMatch && len(versions) == 0 {
		return NothingDetected, nil, skipped, nil
	}
	if inZip != NothingDetected && obfuscated {
		result |= JarFileObfuscated
		i.printInfoFinding("Found finding in what appeared to be an obfuscated jar at %s", path)
	}
	result |= inZip
	if result != NothingDetected && len(versions) == 0 {
		versions[UnknownVersion] = struct{}{}
	}
	return result, versions, skipped, err
}

func (i *Log4jIdentifier) findArchiveVulnerabilities(ctx context.Context, depth uint, walk archive.WalkFn, obfuscated bool) (Finding, Versions, uint64, error) {
	archiveResult := NothingDetected
	versions := make(Versions)
	var skipped uint64 = 0
	i.Limiter.Take()
	if err := walk(ctx, i.vulnerabilityFileWalkFunc(depth, &archiveResult, versions, &skipped, obfuscated)); err != nil {
		return NothingDetected, nil, 0, err
	}
	return archiveResult, versions, skipped, nil
}

func (i *Log4jIdentifier) vulnerabilityFileWalkFunc(depth uint, result *Finding, versions Versions, skipped *uint64, obfuscated bool) archive.FileWalkFn {
	return func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
		getWalker, maxSize, ok := i.ArchiveWalkers(path)
		if ok {
			if maxSize > -1 && size >= maxSize {
				*skipped = *skipped + 1
				i.printInfoFinding("Skipping nested archive above configured maximum size at %s", path)
			} else if depth >= i.ArchiveMaxDepth {
				*skipped = *skipped + 1
				i.printInfoFinding("Skipping nested archive nested beyond configured maximum level at %s", path)
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

				finding, innerVersions, innerSkipped, err := i.findArchiveVulnerabilities(ctx, depth+1, walker, obfuscated)
				*skipped = *skipped + innerSkipped
				if err != nil {
					return false, err
				}
				*result |= finding
				for vv := range innerVersions {
					versions[vv] = struct{}{}
				}
			}
		}

		if strings.HasSuffix(path, ".class") {
			finding, versionInFile, versionMatch := i.lookForClassFileMatch(path, size, contents, obfuscated)
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
			return true, nil
		}

		if version, match := pathMatchesLog4JVersion(path); match {
			i.printInfoFinding("Found nesting archive matching the log4j-core jar name at %s", path)
			*result |= JarNameInsideArchive
			versions[version] = struct{}{}
		}
		return true, nil
	}
}

// checkForObfuscation applies a heuristic to determine if a class appears to have been obfuscated.
// Obfuscation typically changes Java class names from e.g. org.apache.logging.log4j.core.net.JndiManager
// to org.a.a.a.a.b.c and it is this sort of result we look for.
//
// The heuristic currently used is that both the average unique package name length and the average class name length
// must be below the configured maximums, which default to 3.
//
// Thus a jar made up of all a.a.a.b.c, a.a.a.d.e etc will match, but a jar full of org.apache.Foo and com.palantir.Bar
// will not.
func (i *Log4jIdentifier) checkForObfuscation(path string) (obfuscated bool, err error) {
	if !i.IdentifyObfuscation {
		return false, nil
	}

	r, oErr := zip.OpenReader(path)
	if oErr != nil {
		return false, oErr
	}

	defer func() {
		if cerr := r.Close(); err == nil {
			err = cerr
		}
	}()

	averageSizes := java.AveragePackageAndClassLength(r.File)
	return 0 < averageSizes.PackageName &&
		averageSizes.PackageName < i.ObfuscatedPackageNameAverageLength &&
		0 < averageSizes.ClassName &&
		averageSizes.ClassName < i.ObfuscatedClassNameAverageLength, nil
}

func (i *Log4jIdentifier) lookForClassFileMatch(path string, size int64, contents io.Reader, obfuscated bool) (Finding, string, bool) {
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

	hashClass := strings.HasSuffix(path, "JndiManager.class") || obfuscated
	if hashClass {
		finding, version, hashMatch := LookForHashMatch(contents, size)
		if strings.HasSuffix(path, "JndiManager.class") {
			i.printInfoFinding("Found JndiManager class not in the log4j package at %s", path)
			finding |= JndiManagerClassName
		}
		if hashMatch {
			i.printDetailedHashFinding(path, finding)
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

func (i *Log4jIdentifier) printDetailedHashFinding(path string, finding Finding) {
	if finding&ClassFileMd5 > 0 {
		i.printInfoFinding("Found JndiManager class that was an exact md5 match for a known version at %s", path)
	} else if finding&ClassBytecodeInstructionMd5 > 0 {
		i.printInfoFinding("Found JndiManager class that had identical bytecode instruction as a known version at %s", path)
	} else if finding&ClassBytecodePartialMatch > 0 {
		i.printInfoFinding("Found JndiManager class that partially matched the bytecode of a known version at %s", path)
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
	filename, finalSlashIndex := path, strings.LastIndex(path, "/")
	if finalSlashIndex > -1 {
		filename = path[finalSlashIndex+1:]
	}
	return fileNameMatchesLog4jVersion(filename)
}

func fileNameMatchesLog4jVersion(filename string) (string, bool) {
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
