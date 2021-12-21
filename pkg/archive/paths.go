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
	"context"
	"io"
)

// A WalkFn iterates through an archive, calling FileWalkFn on each member file.
type WalkFn func(ctx context.Context, walkFn FileWalkFn) error

// FileWalkFn is called by a WalkFn on each file contained in an archive.
type FileWalkFn func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error)

// WalkZipFiles walks the files in the provided *zip.Reader, calling walkFn on each header.
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

// WalkTarFiles walks the files in the provided *tar.Reader, calling walkFn on each header.
func WalkTarFiles(ctx context.Context, r *tar.Reader, walkFn FileWalkFn) (err error) {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		header, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if proceed, err := walkFn(ctx, header.Name, header.Size, r); err != nil {
			return err
		} else if !proceed {
			break
		}
	}
	return nil
}
