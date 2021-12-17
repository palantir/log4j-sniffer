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
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Finding int

const (
	NothingDetected      Finding = 0
	ClassName                    = 1 << iota
	JarName                      = 1 << iota
	JarNameInsideArchive         = 1 << iota
	ClassPackageAndName          = 1 << iota
)

const (
	UnknownVersion = "unknown"
)

var (
	log4jRegex    = regexp.MustCompile(`(?i)^log4j-core-(\d+\.\d+(?:\..*)?)\.jar$`)
	zipExtensions = map[string]struct{}{
		".ear": {}, ".jar": {}, ".par": {}, ".war": {}, ".zip": {},
	}
)

type Identifier interface {
	Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, string, error)
}

// ArchiveFileLister lists the files contained within an archive.
type ArchiveFileLister func(ctx context.Context, path string) ([]string, error)

type identifier struct {
	zipLister, tgzLister ArchiveFileLister
	listTimeout          time.Duration
}

func NewIdentifier(archiveListTimeout time.Duration, zipLister, tgzLister ArchiveFileLister) Identifier {
	return &identifier{
		zipLister:   zipLister,
		tgzLister:   tgzLister,
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
		return i.lookForMatchInArchive(ctx, path, i.tgzLister)
	}
	return NothingDetected, UnknownVersion, nil
}

func (i *identifier) lookForMatchInZip(ctx context.Context, path string, lowercaseFilename string) (Finding, string, error) {
	archiveResult, innerArchiveVersion, err := i.lookForMatchInArchive(ctx, path, i.zipLister)
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

func (i *identifier) lookForMatchInArchive(ctx context.Context, path string, lister ArchiveFileLister) (Finding, string, error) {
	paths, err := lister(ctx, path)
	if err != nil {
		return NothingDetected, UnknownVersion, err
	}
	for _, path := range paths {
		if path == "org/apache/logging/log4j/core/lookup/JndiLookup.class" {
			return ClassPackageAndName, UnknownVersion, nil
		}
		filename := stripDirectories(path)
		version, match := fileNameMatchesVulnerableLog4jVersion(filename)
		if match {
			return JarNameInsideArchive, version, nil
		}
		if filename == "JndiLookup.class" {
			return ClassName, UnknownVersion, nil
		}
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
