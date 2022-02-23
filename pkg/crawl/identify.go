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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/buffer"
	"github.com/palantir/log4j-sniffer/pkg/log"
	"github.com/pkg/errors"
	"go.uber.org/ratelimit"
)

var log4jRegex = regexp.MustCompile(`(?i)^log4j-core-(\d+\.\d+(?:\..*)?)\.jar$`)

type Identifier interface {
	Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, Versions, error)
}

// Log4jIdentifier identifies files that are vulnerable to Log4J-related CVEs.
type Log4jIdentifier struct {
	Logger                             log.Logger
	Limiter                            ratelimit.Limiter
	IdentifyObfuscation                bool
	ObfuscatedClassNameAverageLength   int
	ObfuscatedPackageNameAverageLength int
	OpenFile                           func(string) (*os.File, error)
	ArchiveWalkTimeout                 time.Duration
	ArchiveMaxDepth                    uint
	ArchiveWalkers                     func(string) (archive.WalkerProvider, bool)
	HandleFinding                      HandleFindingFunc
}

// HandleFindingFunc is called with the given findings and versions when Log4jIdentifier identifies
// a log4j vulnerability whilst crawling the filesystem.
// The bool returned by HandleFindingFunc, indicates whether identification within the file should continue or not.
// For example, if the identification of a file has already yielded results that are desired for a given file,
// then there may be no need for the identification of the file to continue.
type HandleFindingFunc func(ctx context.Context, path Path, result Finding, version Versions) bool

// Identify identifies vulnerable files, passing each finding along with its versions to the Log4jIdentifier's HandleFindingFunc.
func (i *Log4jIdentifier) Identify(ctx context.Context, path string, filename string) (skipped uint64, err error) {
	i.Logger.Trace("Identifying file %s", path)
	if i.ArchiveWalkTimeout > 0 {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, i.ArchiveWalkTimeout)
		defer cancel()
		ctx = ctxWithTimeout
	}

	getWalker, ok := i.ArchiveWalkers(strings.ToLower(filename))
	if !ok {
		return 0, nil
	}

	walker, tErr := getWalker.FromFile(path)
	if tErr != nil {
		return 0, tErr
	}
	defer func() {
		if cErr := walker.Close(); err == nil && cErr != nil {
			err = cErr
		}
	}()

	nestedPath := []string{path}
	log4jNameMatch, nameVulnerability, nameVersions := i.archiveNameVulnerability(nestedPath)
	inArchive, inZipVs, skipped, fileLevelProceed, err := i.findArchiveContentVulnerabilities(ctx, 0, walker, nestedPath)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to walk archive %s", path)
	}
	if !fileLevelProceed {
		return skipped, nil
	}

	reportFindings, reportVersions := resolveNameAndContentFindings(log4jNameMatch, nameVulnerability, nameVersions, inArchive, inZipVs)
	if reportFindings == NothingDetected {
		return skipped, err
	}

	_ = i.HandleFinding(ctx, nestedPath, reportFindings, reportVersions)
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

func (i *Log4jIdentifier) archiveNameVulnerability(nestedPaths Path) (bool, Finding, Versions) {
	path := nestedPaths[len(nestedPaths)-1]
	var jarNameMatch bool
	var jarVersion Log4jVersion
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
			i.Logger.Info("Found nesting archive matching the log4j-core jar name at %s", nestedPaths)
		}
	}

	if jarNameMatch && jarVersion.Vulnerable() {
		i.Logger.Info("Found archive with name matching vulnerable log4j-core format at %s", nestedPaths)
		return jarNameMatch, jarFinding, map[string]struct{}{jarVersion.Original: {}}
	}
	return jarNameMatch, NothingDetected, nil
}

func (i *Log4jIdentifier) findArchiveContentVulnerabilities(ctx context.Context, depth uint, walker archive.WalkCloser, nestedPaths Path) (Finding, Versions, uint64, bool, error) {
	archiveResult := NothingDetected
	versions := make(Versions)

	var skipped uint64
	fileLevelProceed := true
	i.Limiter.Take()
	err := walker.Walk(ctx, i.vulnerabilityFileWalkFunc(depth, &archiveResult, versions, &skipped, &fileLevelProceed, nestedPaths))
	return archiveResult, versions, skipped, fileLevelProceed, err
}

func (i *Log4jIdentifier) vulnerabilityFileWalkFunc(depth uint, result *Finding, versions Versions, skipped *uint64, fileLevelProceed *bool, paths []string) archive.FileWalkFn {
	return func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
		nestedPaths := Path(append(paths, path))
		getWalker, ok := i.ArchiveWalkers(path)
		if ok {
			if depth >= i.ArchiveMaxDepth {
				_, nameFinding, jarNameVersions := i.archiveNameVulnerability(nestedPaths)
				// If there is a finding from the name we don't consider the file skipped.
				if nameFinding == NothingDetected {
					*skipped = *skipped + 1
					i.Logger.Info("Skipping nested archive nested beyond configured maximum level at %s", nestedPaths)
				} else {
					*fileLevelProceed = i.HandleFinding(ctx, nestedPaths, nameFinding, jarNameVersions)
					if !*fileLevelProceed {
						return false, nil
					}
				}
			} else {
				walker, archiveErr := getWalker.FromReader(contents, size)
				if oversizedErr, ok := archiveErr.(buffer.ContentsExceedLimitError); ok {
					*skipped = *skipped + 1
					i.Logger.Info("Skipping nested archive over size threshold at %s: %s", nestedPaths, oversizedErr)
				} else if archiveErr != nil {
					return false, archiveErr
				} else {
					defer func() {
						if cErr := walker.Close(); err == nil {
							err = cErr
						}
					}()

					archiveContentResult, archiveVersions, innerSkipped, innerArchiveFileLevelProceed, err := i.findArchiveContentVulnerabilities(ctx, depth+1, walker, nestedPaths)
					*skipped = *skipped + innerSkipped
					if err != nil {
						return false, err
					}
					if !innerArchiveFileLevelProceed {
						*fileLevelProceed = false
						return false, nil
					}

					jarNameMatch, nameFinding, jarNameVersions := i.archiveNameVulnerability(nestedPaths)
					findings, vs := resolveNameAndContentFindings(jarNameMatch, nameFinding, jarNameVersions, archiveContentResult, archiveVersions)
					if findings != NothingDetected {
						*fileLevelProceed = i.HandleFinding(ctx, nestedPaths, findings, vs)
						if !*fileLevelProceed {
							return false, nil
						}
					}
				}
			}
		}

		filename := filenameFromPathInsideArchive(path)
		if strings.HasSuffix(filename, ".class") || strings.HasPrefix(filename, "JndiManager.") {
			i.Logger.Trace("Looking for class file match %s", path)
			finding, versionInFile, versionMatch := i.lookForClassFileMatch(path, filename, size, contents)
			if finding == NothingDetected {
				return true, nil
			}
			if versionMatch {
				version, parsed := ParseLog4jVersion(versionInFile)
				if !parsed || !version.Vulnerable() {
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
		i.Logger.Info("Found JndiManager class that did not match any known versions at %n", path)
		return JndiManagerClassPackageAndName, "", false
	}
	if path == "org/apache/logging/log4j/core/lookup/JndiLookup.class" {
		i.Logger.Info("Found JndiLookup class in the log4j package at %s", path)
		return JndiLookupClassPackageAndName, "", false
	}

	obfuscated := i.classMeetsObfuscationThreshold(path, filename)
	hashClass := strings.HasSuffix(path, "JndiManager.class") || strings.HasPrefix(filename, "JndiManager.") || obfuscated
	if hashClass {
		finding, version, hashMatch := LookForHashMatch(contents, size)
		if strings.HasSuffix(path, "JndiManager.class") {
			i.Logger.Info("Found JndiManager class not in the log4j package at %s", path)
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
		i.Logger.Info("Found JndiLookup class not in the log4j package at %s", path)
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
		i.Logger.Info("Found JndiManager class that was an exact md5 match for a known version at %s", path)
	} else if finding&ClassBytecodeInstructionMd5 > 0 {
		i.Logger.Info("Found JndiManager class that had identical bytecode instruction as a known version at %s", path)
	} else if finding&ClassBytecodePartialMatch > 0 {
		i.Logger.Info("Found JndiManager class that partially matched the bytecode of a known version at %s", path)
	}
}

func pathMatchesLog4JVersion(path string) (Log4jVersion, bool) {
	return FileNameMatchesLog4jJar(filenameFromPathInsideArchive(path))
}

func filenameFromPathInsideArchive(path string) string {
	filename, finalSlashIndex := path, strings.LastIndex(path, "/")
	if finalSlashIndex > -1 {
		filename = path[finalSlashIndex+1:]
	}
	return filename
}

func FileNameMatchesLog4jJar(filename string) (Log4jVersion, bool) {
	matches := log4jRegex.FindStringSubmatch(strings.ToLower(filename))
	if len(matches) == 0 {
		return Log4jVersion{}, false
	}
	return ParseLog4jVersion(matches[1])
}
