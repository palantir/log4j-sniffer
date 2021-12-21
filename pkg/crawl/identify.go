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
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/java"
	"github.com/pkg/errors"
)

type Finding int
type Versions map[string]struct{}

const (
	NothingDetected             Finding = 0
	ClassName                   Finding = 1 << iota
	JarName                     Finding = 1 << iota
	JarNameInsideArchive        Finding = 1 << iota
	ClassPackageAndName         Finding = 1 << iota
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
	// Generated using log4j-sniffer identify
	classMd5s = map[string]string{
		"6b15f42c333ac39abacfeeeb18852a44": "2.1-2.3",
		"8b2260b1cce64144f6310876f94b1638": "2.4-2.5",
		"3bd9f41b89ce4fe8ccbf73e43195a5ce": "2.6-2.6.2",
		"415c13e7c8505fb056d540eac29b72fa": "2.7-2.8.1",
		"a193703904a3f18fb3c90a877eb5c8a7": "2.8.2",
		"04fdd701809d17465c17c7e603b1b202": "2.9.0-2.11.2",
		"5824711d6c68162eb535cc4dbf7485d3": "2.12.0",
		"102cac5b7726457244af1f44e54ff468": "2.12.2",
		"21f055b62c15453f0d7970a9d994cab7": "2.13.0-2.13.3",
		"f1d630c48928096a484e4b95ccb162a0": "2.14.0 - 2.14.1",
		"5d253e53fa993e122ff012221aa49ec3": "2.15.0",
		"ba1cf8f81e7b31c709768561ba8ab558": "2.16.0",
		"3dc5cf97546007be53b2f3d44028fa58": "2.17.0",
	}
	bytecodeMd5s = map[string]string{
		"e873c1367963fad624f7128e74013725-v0": "2.1-2.5",
		"34603528cf70de0e17669acd122ad110-v0": "2.6-2.8.1",
		"bdbc07b787588e54870b5e90933d2306-v0": "2.8.2",
		"bd12d274eef8fa455f303284834ce62b-v0": "2.9.0-2.11.2",
		"81fcf4a9f7dd4dcb4fa0ab6daaed496f-v0": "2.12.2",
		"8139e14cd3955ef709139c3f23d38057-v0": "2.12.0 - 2.14.1",
		"5120cdf3b914bb4347e3235efce4eabf-v0": "2.15.0",
		"0761bbaeee745db2559b6416a3a30712-v0": "2.16.0",
		"79cd7e06b1a00b375f221414f06bbdd6-v0": "2.17.0",
	}
)

type Identifier interface {
	Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, Versions, error)
}

// Log4jIdentifier identifies files that are vulnerable to Log4J-related CVEs.
type Log4jIdentifier struct {
	OpenFileZipReader  archive.ZipReadCloserProvider
	ZipWalker          archive.ZipWalkFn
	TarWalker          archive.WalkFn
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
	versions := make(Versions)
	result := NothingDetected
	archiveVersion, match := fileNameMatchesLog4jVersion(lowercaseFilename)
	if match {
		if vulnerableVersion(archiveVersion) {
			result |= JarName
			versions[archiveVersion] = struct{}{}
		}
	} else {
		archiveVersion = UnknownVersion
	}
	archiveType, ok := archive.ParseArchiveFormatFromFile(lowercaseFilename)
	if !ok {
		return NothingDetected, nil, nil
	}
	switch archiveType {
	case archive.ZipArchive:
		reader, err := i.OpenFileZipReader(path)
		if err != nil {
			return 0, nil, err
		}
		defer func() {
			if cErr := reader.Close(); err == nil && cErr != nil {
				err = cErr
			}
		}()
		inZip, inZipVs, err := i.lookForMatchInZip(ctx, 0, &reader.Reader, archiveVersion)
		for v := range inZipVs {
			versions[v] = struct{}{}
		}
		return result | inZip, versions, err
	case archive.TarGzArchive:
		return i.lookForMatchInTar(ctx, archive.TarGzipReader, path)
	case archive.TarBz2Archive:
		return i.lookForMatchInTar(ctx, archive.TarBzip2Reader, path)
	case archive.TarArchive:
		return i.lookForMatchInTar(ctx, archive.TarUncompressedReader, path)
	}
	return NothingDetected, nil, nil
}

func (i *Log4jIdentifier) lookForMatchInZip(ctx context.Context, depth uint, r *zip.Reader, parentVersion string) (Finding, Versions, error) {
	archiveResult := NothingDetected
	versions := Versions{}
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
				finding, innerVersions, err := i.lookForMatchInZip(ctx, depth+1, reader, parentVersion)
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
		version := parentVersion
		if versionMatch {
			version = versionInFile
		}
		if !vulnerableVersion(version) {
			return true, nil
		}

		archiveResult = finding | archiveResult
		versions[version] = struct{}{}
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

	if strings.HasSuffix(path, "JndiManager.class") {
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

const maxClassSize = 0xffff

var classByteBuf bytes.Buffer = bytes.Buffer{}

func lookForHashMatch(contents io.Reader, size int64) (Finding, string, bool) {
	if size > maxClassSize {
		return NothingDetected, UnknownVersion, false
	}
	classByteBuf.Reset()
	_, err := classByteBuf.ReadFrom(contents)
	if err != nil {
		return NothingDetected, UnknownVersion, false
	}
	version, md5Match := classMd5Version(classByteBuf.Bytes())
	if md5Match {
		return ClassFileMd5, version, true
	}
	version, md5Match = bytecodeMd5Version(classByteBuf.Bytes())
	if md5Match {
		return ClassBytecodeInstructionMd5, version, true
	}
	return NothingDetected, UnknownVersion, false
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

func classMd5Version(classContents []byte) (string, bool) {
	sum := md5.New()
	if _, err := sum.Write(classContents); err != nil {
		return "", false
	}
	hash := fmt.Sprintf("%x", sum.Sum(nil))
	version, matches := classMd5s[hash]
	return version, matches
}

func bytecodeMd5Version(classContents []byte) (string, bool) {
	hash, err := java.HashClassInstructions(classContents)
	if err != nil {
		return UnknownVersion, false
	}
	version, matches := bytecodeMd5s[hash]
	return version, matches
}
