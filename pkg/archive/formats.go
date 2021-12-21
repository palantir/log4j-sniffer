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

package archive

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"strings"
)

const (
	UnsupportedArchive FormatType = iota
	TarArchive
	TarGzArchive
	TarBz2Archive
	ZipArchive
)

// FormatType specifies the type of archive format the identifier should expect.
type FormatType int

var (
	extensions = map[string]FormatType{
		"ear":     ZipArchive,
		"jar":     ZipArchive,
		"par":     ZipArchive,
		"war":     ZipArchive,
		"zip":     ZipArchive,
		"tar":     TarArchive,
		"tar.gz":  TarGzArchive,
		"tgz":     TarGzArchive,
		"tar.bz2": TarBz2Archive,
		"tbz2":    TarBz2Archive,
	}
)

// TarGzipReader creates a reader for gzipped tar content.
// The returned function should be called to release all underlying resources.
func TarGzipReader(r io.Reader) (*tar.Reader, func() error, error) {
	gzipReader, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, err
	}
	return tar.NewReader(gzipReader), gzipReader.Close, nil
}

func ParseArchiveFormatFromFile(filename string) (FormatType, bool) {
	fileSplit := strings.Split(filename, ".")
	if len(fileSplit) < 2 {
		return UnsupportedArchive, false
	}

	// only search for a depth of two extension dots
	for i := len(fileSplit) - 1; i >= len(fileSplit)-2; i-- {
		if archive, ok := extensions[strings.Join(fileSplit[i:], ".")]; ok {
			return archive, true
		}
	}
	return UnsupportedArchive, false
}
