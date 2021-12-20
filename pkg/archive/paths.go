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
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	TarArchive FormatType = iota
	TarGzArchive
	TarBz2Archive
	ZipArchive
	UnsupportedArchive
)

var (
	extensions = map[string]FormatType{
		".ear":     ZipArchive,
		".jar":     ZipArchive,
		".par":     ZipArchive,
		".war":     ZipArchive,
		".zip":     ZipArchive,
		".tar":     TarArchive,
		".tar.gz":  TarGzArchive,
		".tgz":     TarGzArchive,
		".tar.bz2": TarBz2Archive,
		".tbz2":    TarBz2Archive,
	}
)

// A WalkFn iterates through an archive, calling FileWalkFn on each member file.
type WalkFn func(ctx context.Context, path string, walkFn FileWalkFn) error

// FileWalkFn is called by a WalkFn on each file contained in an archive.
type FileWalkFn func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error)

type FormatType int

func WalkZipFiles(ctx context.Context, path string, walkFn FileWalkFn) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if cErr := file.Close(); err == nil && cErr != nil {
			err = cErr
		}
	}()
	stat, err := file.Stat()
	if err != nil {
		return err
	}

	r, err := zip.NewReader(file, stat.Size())
	if err != nil {
		return err
	}
	for _, zipFile := range r.File {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		zipReader, err := zipFile.Open()
		if err != nil {
			return err
		}
		if proceed, err := walkFn(ctx, zipFile.Name, int64(zipFile.UncompressedSize64), zipReader); err != nil {
			return err
		} else if !proceed {
			break
		}
	}
	return nil
}

func WalkTarFiles(ctx context.Context, path string, walkFn FileWalkFn) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if cErr := file.Close(); err == nil && cErr != nil {
			err = cErr
		}
	}()
	var reader io.Reader
	switch CheckArchiveType(filepath.Base(path)) {
	case TarGzArchive:
		reader, err = gzip.NewReader(file)
		if err != nil {
			return err
		}
	case TarBz2Archive:
		reader = bzip2.NewReader(file)
	case TarArchive:
		reader = file
	default:
		return fmt.Errorf("could not extract archive: %s (supported: uncompressed, gzip, bzip2)", path)
	}

	tarReader := tar.NewReader(reader)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if proceed, err := walkFn(ctx, header.Name, header.Size, tarReader); err != nil {
			return err
		} else if !proceed {
			break
		}
	}
	return nil

}

func CheckArchiveType(filename string) FormatType {
	fileSplit := strings.Split(filename, ".")
	if len(fileSplit) < 2 {
		return UnsupportedArchive
	}

	for i := len(fileSplit) - 1; i > 0; i-- {
		if archive, ok := extensions[fmt.Sprintf(".%s", strings.Join(fileSplit[i:], "."))]; ok {
			return archive
		}
	}

	return UnsupportedArchive
}
