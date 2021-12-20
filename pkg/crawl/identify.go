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
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/pkg/errors"
	"go.uber.org/ratelimit"
)

type Finding int
type Versions map[string]struct{}

const (
	NothingDetected             Finding = 0
	ClassName                   Finding = 1 << iota
	JarName                     Finding = 1 << iota
	JarNameInsideArchive        Finding = 1 << iota
	ClassPackageAndName         Finding = 1 << iota
	ClassBytecodePartialMatch   Finding = 1 << iota
	ClassBytecodeInstructionMd5 Finding = 1 << iota
	ClassFileMd5                Finding = 1 << iota
)

func (f Finding) String() string {
	var out []string
	if f&ClassName > 0 {
		out = append(out, "ClassName")
	}
	if f&JarName > 0 {
		out = append(out, "JarName")
	}
	if f&JarNameInsideArchive > 0 {
		out = append(out, "JarNameInsideArchive")
	}
	if f&ClassPackageAndName > 0 {
		out = append(out, "ClassPackageAndName")
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
	OpenFileZipReader  archive.ZipReadCloserProvider
	ZipWalker          archive.ZipWalkFn
	TarWalker          archive.WalkFn
	Limiter            ratelimit.Limiter
	ArchiveWalkTimeout time.Duration
	ArchiveMaxDepth    uint
	ArchiveMaxSize     uint
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
			return 0, nil, err
		}
		defer func() {
			if cErr := reader.Close(); err == nil && cErr != nil {
				err = cErr
			}
		}()
		inZip, inZipVs, err := i.lookForMatchInZip(ctx, 0, &reader.Reader)
		if err != nil {
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
		result |= inZip
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

func (i *Log4jIdentifier) lookForMatchInZip(ctx context.Context, depth uint, r *zip.Reader) (Finding, Versions, error) {
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
				finding, innerVersions, err := i.lookForMatchInZip(ctx, depth+1, reader)
				if err != nil {
					return false, err
				}
				archiveResult = finding | archiveResult
				for vv := range innerVersions {
					versions[vv] = struct{}{}
				}
			}
		}
		finding, versionInFile, versionMatch := lookForMatchInFileInZip(path, size, contents)
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
		return false, nil
	})
	if err != nil {
		return NothingDetected, Versions{}, err
	}
	return archiveResult, versions, nil
}

// boolean returned is whether the version was matched.
func lookForMatchInFileInZip(path string, size int64, contents io.Reader) (Finding, string, bool) {
	if path == "org/apache/logging/log4j/core/net/JndiManager.class" {
		finding, version, hashMatch := lookForHashMatch(contents, size)
		if hashMatch {
			return ClassPackageAndName | finding, version, true
		}
		return ClassPackageAndName, "", false
	}

	if version, match := pathMatchesLog4JVersion(path); match {
		return JarNameInsideArchive, version, true
	}

	if strings.HasSuffix(path, "JndiManager.class") || strings.HasSuffix(path, ".class") {
		finding, version, hashMatch := lookForHashMatch(contents, size)
		if hashMatch {
			return ClassName | finding, version, true
		}
		return ClassName, "", false
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
