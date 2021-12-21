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
	"path/filepath"
	"regexp"
	"strconv"
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

var (
	log4jRegex   = regexp.MustCompile(`(?i)^log4j-core-(\d+\.\d+(?:\..*)?)\.jar$`)
	versionRegex = regexp.MustCompile(`(?i)^(\d+)\.(\d+)\.?(\d+)?(?:\..*)?$`)
)

type Identifier interface {
	Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, Versions, error)
}

// Log4jIdentifier identifies files that are vulnerable to Log4J-related CVEs.
type Log4jIdentifier struct {
	ErrorWriter                        io.Writer
	DetailedOutputWriter               io.Writer
	OpenFileZipReader                  archive.ZipReadCloserProvider
	ZipWalker                          archive.ZipWalkFn
	TarWalker                          archive.WalkFn
	Limiter                            ratelimit.Limiter
	ArchiveWalkTimeout                 time.Duration
	ArchiveMaxDepth                    uint
	ArchiveMaxSize                     uint
	IdentifyObfuscation                bool
	ObfuscatedClassNameAverageLength   float32
	ObfuscatedPackageNameAverageLength float32
}

// Identify identifies vulnerable files.
// The function identifies:
// - vulnerable log4j jar files.
// - zipped files containing vulnerable log4j files, using the provided ZipFileLister.
func (i *Log4jIdentifier) Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, Versions, error) {
	if i.ArchiveWalkTimeout > 0 {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, i.ArchiveWalkTimeout)
		defer cancel()
		ctx = ctxWithTimeout
	}

	lowercaseFilename := strings.ToLower(d.Name())
	archiveType, ok := archive.ParseArchiveFormatFromFile(lowercaseFilename)
	if !ok {
		return NothingDetected, nil, nil
	}
	switch archiveType {
	case archive.ZipArchive:
		versions := make(Versions)
		result := NothingDetected

		archiveVersion, match := fileNameMatchesLog4jVersion(lowercaseFilename)
		if match && vulnerableVersion(archiveVersion) {
			result |= JarName
			versions[archiveVersion] = struct{}{}
		}
		reader, err := i.OpenFileZipReader(path)
		if err != nil {
			i.printErrorFinding("Error opening zip: %v", err)
			return 0, nil, err
		}
		defer func() {
			if cErr := reader.Close(); err == nil && cErr != nil {
				err = cErr
			}
		}()
		obfuscated := i.checkForObfuscation(&reader.Reader)
		inZip, inZipVs, err := i.lookForMatchInZip(ctx, 0, &reader.Reader, obfuscated)
		if err != nil {
			i.printErrorFinding("Error scanning zip file: %v", err)
			return 0, nil, err
		}
		for v := range inZipVs {
			versions[v] = struct{}{}
		}
		// If file on disk matches log4j but no signs of vulnerable version have been found
		// during identification phase, then we assume non-vulnerable.
		if match && len(versions) == 0 {
			return NothingDetected, nil, nil
		}
		if inZip != NothingDetected && !obfuscated {
			result |= inZip
		} else if inZip != NothingDetected {
			i.printInfoFinding("Found finding in what appeared to be an obfuscated jar at %s", path)
			result |= JarFileObfuscated | inZip
		}
		if result != NothingDetected && len(versions) == 0 {
			versions[UnknownVersion] = struct{}{}
		}
		return result, versions, err
	case archive.TarGzArchive:
		return i.lookForMatchInTar(ctx, archive.TarGzipReader, path)
	case archive.TarBz2Archive:
		return i.lookForMatchInTar(ctx, archive.TarBzip2Reader, path)
	case archive.TarArchive:
		return i.lookForMatchInTar(ctx, archive.TarUncompressedReader, path)
	}
	return NothingDetected, nil, nil
}

func (i *Log4jIdentifier) lookForMatchInZip(ctx context.Context, depth uint, r *zip.Reader, obfuscated bool) (Finding, Versions, error) {
	archiveResult := NothingDetected
	versions := Versions{}
	i.Limiter.Take()
	err := i.ZipWalker(ctx, r, func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
		archiveType, ok := archive.ParseArchiveFormatFromFile(path)
		if ok && archiveType == archive.ZipArchive {
			_, filename := filepath.Split(path)
			archiveVersion, match := fileNameMatchesLog4jVersion(strings.ToLower(filename))
			if match {
				if vulnerableVersion(archiveVersion) {
					i.printInfoFinding("Found archive with name matching vulnerable log4j-core format at %s", path)
					archiveResult |= JarNameInsideArchive
					versions[archiveVersion] = struct{}{}
				}
			}
			// Check depth here before recursing because we don't want to create a zip reader unnecessarily.
			if depth+1 < i.ArchiveMaxDepth {
				reader, err := archive.ZipReaderFromReader(contents, int(i.ArchiveMaxSize))
				if err != nil {
					return false, errors.Wrap(err, "creating zip reader from reader")
				}
				innerObfuscated := i.checkForObfuscation(reader)
				finding, innerVersions, err := i.lookForMatchInZip(ctx, depth+1, reader, innerObfuscated)
				if err != nil {
					i.printErrorFinding("Error scanning zip file: %v", err)
					return false, err
				}
				if finding != NothingDetected && !innerObfuscated {
					archiveResult = finding | archiveResult
				} else if finding != NothingDetected {
					i.printInfoFinding("Found finding in what appeared to be an obfuscated jar at %s", path)
					archiveResult = JarFileObfuscated | finding | archiveResult
				}
				for vv := range innerVersions {
					versions[vv] = struct{}{}
				}
			}
		}
		finding, versionInFile, versionMatch := i.lookForMatchInFileInZip(path, size, contents, obfuscated)
		if finding == NothingDetected {
			return true, nil
		}
		if versionMatch {
			if !vulnerableVersion(versionInFile) {
				return true, nil
			}
			versions[versionInFile] = struct{}{}
		}
		archiveResult = finding | archiveResult
		return true, nil
	})
	if err != nil {
		return NothingDetected, Versions{}, err
	}
	return archiveResult, versions, nil
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
func (i *Log4jIdentifier) checkForObfuscation(reader *zip.Reader) bool {
	if !i.IdentifyObfuscation {
		return false
	}
	averageSizes := java.AveragePackageAndClassLength(reader.File)
	if 0 < averageSizes.PackageName && averageSizes.PackageName < i.ObfuscatedPackageNameAverageLength && 0 < averageSizes.ClassName && averageSizes.ClassName < i.ObfuscatedClassNameAverageLength {
		return true
	}
	return false
}

func (i *Log4jIdentifier) lookForMatchInFileInZip(path string, size int64, contents io.Reader, obfuscated bool) (Finding, string, bool) {
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

	if version, match := pathMatchesLog4JVersion(path); match {
		i.printInfoFinding("Found nesting archive matching the log4j-core jar name at %s", path)
		return JarNameInsideArchive, version, true
	}

	hashClass := strings.HasSuffix(path, "JndiManager.class")
	if obfuscated {
		hashClass = hashClass || strings.HasSuffix(path, ".class")
	}
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

func (i *Log4jIdentifier) lookForMatchInTar(ctx context.Context, getTarReader archive.TarReaderProvider, path string) (Finding, Versions, error) {
	archiveResult := NothingDetected
	versions := Versions{}
	if err := i.TarWalker(ctx, path, getTarReader, func(ctx context.Context, filename string, size int64, contents io.Reader) (proceed bool, err error) {
		version, match := pathMatchesLog4JVersion(filename)
		if !match || !vulnerableVersion(version) {
			return true, nil
		}
		i.printInfoFinding("Found archive with name matching vulnerable log4j-core format at %s", path)
		archiveResult = JarNameInsideArchive | archiveResult
		if version != "" {
			versions[version] = struct{}{}
		}
		return false, nil
	}); err != nil {
		return NothingDetected, versions, err
	}
	return archiveResult, versions, nil
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
	matches := versionRegex.FindStringSubmatch(version)
	if len(matches) == 0 {
		return true
	}
	major, err := strconv.Atoi(matches[1])
	if err != nil {
		// should not be possible due to group of \d+ in regex
		return false
	}
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		// should not be possible due to group of \d+ in regex
		return true
	}
	patch, err := strconv.Atoi(matches[3])
	if err != nil {
		patch = 0
	}
	return (major == 2 && minor < 17) && !(major == 2 && minor == 12 && patch >= 3)
}
