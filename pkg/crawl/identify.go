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
	"crypto/md5"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
)

type Finding int

const (
	NothingDetected      Finding = 0
	ClassName                    = 1 << iota
	JarName                      = 1 << iota
	JarNameInsideArchive         = 1 << iota
	ClassPackageAndName          = 1 << iota
	ClassFileMD5                 = 1 << iota
)

const (
	UnknownVersion = "unknown"
)

var (
	log4jRegex    = regexp.MustCompile(`(?i)^log4j-core-(\d+\.\d+(?:\..*)?)\.jar$`)
	zipExtensions = map[string]struct{}{
		".ear": {}, ".jar": {}, ".par": {}, ".war": {}, ".zip": {},
	}
	badMD5s = map[string]string{
		// JndiManager.class (source: https://github.com/nccgroup/Cyber-Defence/blob/master/Intelligence/CVE-2021-44228/modified-classes/md5sum.txt)
		"04fdd701809d17465c17c7e603b1b202": "log4j 2.9.0 - 2.11.2",
		"21f055b62c15453f0d7970a9d994cab7": "log4j 2.13.0 - 2.13.3",
		"3bd9f41b89ce4fe8ccbf73e43195a5ce": "log4j 2.6 - 2.6.2",
		"415c13e7c8505fb056d540eac29b72fa": "log4j 2.7 - 2.8.1",
		"5824711d6c68162eb535cc4dbf7485d3": "log4j 2.12.0 - 2.12.1",
		"6b15f42c333ac39abacfeeeb18852a44": "log4j 2.1 - 2.3",
		"8b2260b1cce64144f6310876f94b1638": "log4j 2.4 - 2.5",
		"a193703904a3f18fb3c90a877eb5c8a7": "log4j 2.8.2",
		"f1d630c48928096a484e4b95ccb162a0": "log4j 2.14.0 - 2.14.1",
		// 2.15.0 vulnerable to Denial of Service attack (source: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046)
		"5d253e53fa993e122ff012221aa49ec3": "log4j 2.15.0",
	}
)

type Identifier interface {
	Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, string, error)
}

type identifier struct {
	zipWalker   archive.ArchiveWalkFn
	tgzWalker   archive.ArchiveWalkFn
	listTimeout time.Duration
}

func NewIdentifier(archiveListTimeout time.Duration, zipWalker, tgzWalker archive.ArchiveWalkFn) Identifier {
	return &identifier{
		zipWalker:   zipWalker,
		tgzWalker:   tgzWalker,
		listTimeout: archiveListTimeout,
	}
}

// Identify identifies vulnerable files.
// The function identifies:
// - vulnerable log4j jar files.
// - zipped files containing vulnerable log4j files, using the provided ZipFileLister.
func (i *identifier) Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, string, error) {
	ctx, cancel := context.WithTimeout(ctx, i.listTimeout)
	defer cancel()

	lowercaseFilename := strings.ToLower(d.Name())
	if hasZipFileEnding(lowercaseFilename) {
		return i.lookForMatchInZip(ctx, path, lowercaseFilename)
	}
	if hasTgzFileEnding(lowercaseFilename) {
		return i.lookForMatchInTar(ctx, path)
	}
	return NothingDetected, UnknownVersion, nil
}

func (i *identifier) lookForMatchInZip(ctx context.Context, path string, lowercaseFilename string) (Finding, string, error) {
	archiveResult := NothingDetected
	innerArchiveVersion := UnknownVersion
	err := i.zipWalker(ctx, path, func(ctx context.Context, filename string, size int64, contents io.Reader) (proceed bool, err error) {
		finding, version, err := lookForMatchInFile(ctx, filename, size, contents)
		if err != nil {
			return false, err
		}
		if finding == NothingDetected {
			return true, nil
		}
		archiveResult = finding
		innerArchiveVersion = version
		return false, nil
	})
	if err != nil {
		return NothingDetected, UnknownVersion, err
	}
	outerArchiveVersion, match := fileNameMatchesVulnerableLog4jVersion(lowercaseFilename)
	if !match {
		return archiveResult, innerArchiveVersion, nil
	}
	// if no innerArchiveVersion information found in the archive, we use original from filename match
	if innerArchiveVersion != UnknownVersion {
		return JarName | archiveResult, innerArchiveVersion, nil
	}
	return JarName | archiveResult, outerArchiveVersion, nil
}

func (i *identifier) lookForMatchInTar(ctx context.Context, path string) (Finding, string, error) {
	archiveResult := NothingDetected
	innerArchiveVersion := UnknownVersion
	if err := i.tgzWalker(ctx, path, func(ctx context.Context, filename string, size int64, contents io.Reader) (proceed bool, err error) {
		finding, version, err := lookForMatchInFile(ctx, filename, size, contents)
		if err != nil {
			return false, err
		}
		if finding == NothingDetected {
			return true, nil
		}
		archiveResult = finding
		innerArchiveVersion = version
		return false, nil
	}); err != nil {
		return NothingDetected, UnknownVersion, err
	}
	return archiveResult, innerArchiveVersion, nil
}

func lookForMatchInFile(ctx context.Context, path string, size int64, contents io.Reader) (Finding, string, error) {
	if path == "org/apache/logging/log4j/core/lookup/JndiLookup.class" {
		return ClassPackageAndName, UnknownVersion, nil
	}
	filename := stripDirectories(path)

	if version, match := fileNameMatchesVulnerableLog4jVersion(filename); match {
		return JarNameInsideArchive, version, nil
	}
	if filename == "JndiLookup.class" {
		return ClassName, UnknownVersion, nil
	}
	if version, match := fileMD5MatchesVulnerableLog4jVersion(contents); match {
		return ClassFileMD5, version, nil
	}
	return NothingDetected, UnknownVersion, nil
}

func fileNameMatchesVulnerableLog4jVersion(filename string) (string, bool) {
	matches := log4jRegex.FindStringSubmatch(filename)
	if len(matches) == 0 {
		return "", false
	}
	return matches[1], true
}

func fileMD5MatchesVulnerableLog4jVersion(contents io.Reader) (string, bool) {
	sum := md5.New()
	if _, err := io.Copy(sum, contents); err != nil {
		return "", false
	}
	hash := fmt.Sprintf("%x", sum.Sum(nil))
	version, matches := badMD5s[hash]
	return version, matches
}

func hasZipFileEnding(name string) bool {
	_, ok := zipExtensions[filepath.Ext(name)]
	return ok
}

func hasTgzFileEnding(name string) bool {
	switch lastExt := filepath.Ext(name); lastExt {
	case ".tgz":
		return true
	case ".gz":
		return strings.HasSuffix(name, ".tar.gz")
	}
	return false
}

func stripDirectories(fullPath string) string {
	lastIndex := strings.LastIndex(fullPath, "/")
	if lastIndex == -1 {
		return fullPath
	}
	return fullPath[lastIndex+1:]
}
