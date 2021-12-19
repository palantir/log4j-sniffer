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
	"compress/gzip"
	"context"
	"io"
	"os"
)

// A WalkFn iterates through an archive, calling FileWalkFn on each member file.
type WalkFn func(ctx context.Context, path string, walkFn FileWalkFn) error

// A ZipWalkFn iterates through an zip, calling FileWalkFn on each member file.
type ZipWalkFn func(ctx context.Context, r *zip.Reader, walkFn FileWalkFn) error

// ZipReadCloserProvider should open a zip.ReadCloser when provided with the given path.
type ZipReadCloserProvider func(path string) (*zip.ReadCloser, error)

// FileWalkFn is called by a WalkFn on each file contained in an archive.
type FileWalkFn func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error)

func WalkZipFiles(ctx context.Context, r *zip.Reader, walkFn FileWalkFn) (err error) {
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

func WalkTarGzFiles(ctx context.Context, path string, walkFn FileWalkFn) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if cErr := file.Close(); err == nil && cErr != nil {
			err = cErr
		}
	}()

	gzipReader, err := gzip.NewReader(file)

	if err != nil {
		return err
	}
	tarReader := tar.NewReader(gzipReader)
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
