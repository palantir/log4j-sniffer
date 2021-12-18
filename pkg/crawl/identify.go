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
	gopath "path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Finding int
type Versions map[string]struct{}

const (
	NothingDetected      Finding = 0
	ClassName                    = 1 << iota
	JarName                      = 1 << iota
	JarNameInsideArchive         = 1 << iota
	ClassPackageAndName          = 1 << iota
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
	log4jRegex    = regexp.MustCompile(`(?i)^log4j-core-(\d+\.\d+(?:\..*)?)\.jar$`)
	versionRegex  = regexp.MustCompile(`(?i)^(\d+)\.(\d+)\.?(\d+)?(?:\..*)?$`)
	zipExtensions = map[string]struct{}{
		".ear": {}, ".jar": {}, ".par": {}, ".war": {}, ".zip": {},
	}
)

type Identifier interface {
	Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, Versions, error)
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
func (i *identifier) Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, Versions, error) {
	ctx, cancel := context.WithTimeout(ctx, i.listTimeout)
	defer cancel()

	lowercaseFilename := strings.ToLower(d.Name())
	if hasZipFileEnding(lowercaseFilename) {
		return i.lookForMatchInZip(ctx, path, lowercaseFilename)
	}
	if hasTgzFileEnding(lowercaseFilename) {
		return i.lookForMatchInTar(ctx, path)
	}
	return NothingDetected, nil, nil
}

func (i *identifier) lookForMatchInZip(ctx context.Context, path string, lowercaseFilename string) (Finding, Versions, error) {
	finding := NothingDetected
	versions := Versions{}

	if version, match := fileNameMatchesLog4jVersion(lowercaseFilename); match {
		if !vulnerableVersion(version) {
			// Confirmed we extracted the version and it is not vulnerable
			return NothingDetected, nil, nil
		}
		finding |= JarName
		versions[version] = struct{}{}
	}

	innerFinding, innerVersions, err := i.lookForMatchInArchive(ctx, path, i.zipLister)
	if err != nil {
		return finding, versions, err
	}
	finding |= innerFinding
	for v := range innerVersions {
		versions[v] = struct{}{}
	}
	if finding > NothingDetected && len(versions) == 0 {
		versions[UnknownVersion] = struct{}{}
	}
	return finding, versions, nil
}

func (i *identifier) lookForMatchInTar(ctx context.Context, path string) (Finding, Versions, error) {
	finding, versions, err := i.lookForMatchInArchive(ctx, path, i.tgzLister)
	if err != nil {
		return finding, versions, err
	}
	if finding > NothingDetected && len(versions) == 0 {
		versions[UnknownVersion] = struct{}{}
	}
	return finding, versions, err
}

func (i *identifier) lookForMatchInArchive(ctx context.Context, path string, lister ArchiveFileLister) (Finding, Versions, error) {
	finding := NothingDetected
	versions := Versions{}

	paths, err := lister(ctx, path)
	if err != nil {
		return NothingDetected, nil, err
	}
	for _, innerPath := range paths {
		filename := gopath.Base(innerPath)
		version, match := fileNameMatchesLog4jVersion(filename)
		if match {
			if !vulnerableVersion(version) {
				// Confirmed we extracted the version and it is not vulnerable
				continue
			}
			finding |= JarNameInsideArchive
			versions[version] = struct{}{}
		}
		if innerPath == "org/apache/logging/log4j/core/lookup/JndiLookup.class" {
			finding |= ClassPackageAndName
		} else if filename == "JndiLookup.class" {
			finding |= ClassName
		}
	}
	return finding, versions, nil
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
	return (major == 2 && minor < 16) && !(major == 2 && minor == 12 && patch >= 2)
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
