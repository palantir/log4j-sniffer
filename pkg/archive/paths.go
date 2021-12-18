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

func ReadZipFilePaths(ctx context.Context, path string) ([]string, error) {
	var filenames []string
	return filenames, scopedOpenFile(ctx, path, func(ctx context.Context, file *os.File) error {
		stat, err := file.Stat()
		if err != nil {
			return err
		}

		r, err := zip.NewReader(file, stat.Size())
		if err != nil {
			return err
		}
		filenames = make([]string, len(r.File))
		for i, f := range r.File {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			filenames[i] = f.Name
		}
		return nil
	})
}

func ReadTarGzFilePaths(ctx context.Context, path string) ([]string, error) {
	var pathsFound []string
	return pathsFound, scopedOpenFile(ctx, path, func(ctx context.Context, file *os.File) error {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			return err
		}

		tarReader := tar.NewReader(gzipReader)
		pathsFound = make([]string, 0)
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

			pathsFound = append(pathsFound, header.Name)
		}

		return nil
	})
}

// scopedOpenFile opens the file at the provided path and passes it to the do function.
// If either the do function or closing the file returns an error, scopedOpenFile will return an error.
// This is purely for convenient handling of file closing, where we can ALWAYS return a file close error
// rather than just logging it.
func scopedOpenFile(ctx context.Context, path string, do func(ctx context.Context, file *os.File) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	doErr := do(ctx, f)
	closeErr := f.Close()
	// doErr is assumed to be the more important error.
	if doErr != nil {
		return doErr
	}
	return closeErr
}
