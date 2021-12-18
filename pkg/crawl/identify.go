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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
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

type identifier struct {
	zipWalker   archive.WalkFn
	tgzWalker   archive.WalkFn
	listTimeout time.Duration
}

func NewIdentifier(archiveListTimeout time.Duration, zipWalker, tgzWalker archive.WalkFn) Identifier {
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
func (i *identifier) Identify(ctx context.Context, path string, d fs.DirEntry) (Finding, Versions, error) {
	ctx, cancel := context.WithTimeout(ctx, i.listTimeout)
	defer cancel()

	lowercaseFilename := strings.ToLower(d.Name())
	if hasZipFileEnding(lowercaseFilename) {
		return i.lookForMatchInZip(ctx, path, lowercaseFilename, UnknownVersion)
	}
	if hasTgzFileEnding(lowercaseFilename) {
		return i.lookForMatchInTar(ctx, path, UnknownVersion)
	}
	return NothingDetected, nil, nil
}

func (i *identifier) lookForMatchInZip(ctx context.Context, path string, lowercaseFilename string, parentVersion string) (Finding, Versions, error) {
	archiveResult := NothingDetected
	versions := Versions{}
	archiveVersion, match := fileNameMatchesLog4jVersion(lowercaseFilename)
	if !match {
		archiveVersion = parentVersion
	} else if vulnerableVersion(archiveVersion) {
		archiveResult |= JarName
		versions[archiveVersion] = struct{}{}
	}
	err := i.zipWalker(ctx, path, func(ctx context.Context, filename string, size int64, contents io.Reader) (proceed bool, err error) {
		finding, version, err := lookForMatchInFile(ctx, filename, size, contents, archiveVersion)
		if err != nil {
			return false, err
		}
		if finding == NothingDetected || !vulnerableVersion(version) {
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

func (i *identifier) lookForMatchInTar(ctx context.Context, path string, parentVersion string) (Finding, Versions, error) {
	archiveResult := NothingDetected
	versions := Versions{}
	if err := i.tgzWalker(ctx, path, func(ctx context.Context, filename string, size int64, contents io.Reader) (proceed bool, err error) {
		finding, version, err := lookForMatchInFile(ctx, filename, size, contents, parentVersion)
		if err != nil {
			return false, err
		}
		if finding == NothingDetected {
			return true, nil
		}
		archiveResult = finding | archiveResult
		if version != "" {
			versions[version] = struct{}{}
		}
		return false, nil
	}); err != nil {
		return NothingDetected, versions, err
	}
	return archiveResult, versions, nil
}

func lookForMatchInFile(ctx context.Context, path string, size int64, contents io.Reader, parentVersion string) (Finding, string, error) {
	if path == "org/apache/logging/log4j/core/lookup/JndiLookup.class" {
		return ClassPackageAndName, parentVersion, nil
	}

	filename, finalSlashIndex := path, strings.LastIndex(path, "/")
	if finalSlashIndex > -1 {
		filename = path[finalSlashIndex+1:]
	}
	if version, match := fileNameMatchesLog4jVersion(filename); match {
		if vulnerableVersion(version) {
			return JarNameInsideArchive, version, nil
		}
		return NothingDetected, parentVersion, nil
	}
	if strings.HasSuffix(path, "JndiLookup.class") {
		return ClassName, parentVersion, nil
	}
	return NothingDetected, parentVersion, nil
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
