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
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Walkers creates a function that will return a WalkerProvider for a file path if there is one supported.
// maxInMemoryArchiveSize configures the maximum buffer size to create for archive that are required to be
// read into memory before being able to walk through them.
// The int64 returned from the function will return -1 if there is no limit for size that archive walker,
// otherwise returning the maximum archive size that should be used when using the WalkerProvider.FromReader
// method.
func Walkers(maxInMemoryArchiveSize int64) func(path string) (WalkerProvider, int64, bool) {
	return func(path string) (WalkerProvider, int64, bool) {
		_, filename := filepath.Split(path)
		fileSplit := strings.Split(filename, ".")
		if len(fileSplit) < 2 {
			return nil, 0, false
		}

		// only search for a depth of two extension dots
		for i := len(fileSplit) - 1; i >= len(fileSplit)-2; i-- {
			switch strings.Join(fileSplit[i:], ".") {
			case "ear", "jar", "par", "war", "zip":
				return ZipArchiveWalkers(), maxInMemoryArchiveSize, true
			case "tar":
				return TarArchiveWalkers(), -1, true
			case "tar.gz", "tgz":
				return TarGzWalkers(), -1, true
			case "tar.bz2", "tbz2":
				return TarBz2Walkers(), -1, true
			}
		}
		return nil, 0, false
	}
}

// WalkerProvider creates WalkFn and closing function from certain resources.
type WalkerProvider interface {
	FromFile(*os.File) (WalkFn, func() error, error)
	FromReader(io.Reader) (WalkFn, func() error, error)
}

// FileWalkerProviderFunc creates a WalkFn and closing function from a file.
type FileWalkerProviderFunc func(f *os.File) (WalkFn, func() error, error)

// ReaderWalkerProviderFunc creates a WalkFn and closing function from a reader.
type ReaderWalkerProviderFunc func(r io.Reader) (WalkFn, func() error, error)

// WalkerProviderFromFuncs creates a WalkerProvider from the given file and reader functions.
func WalkerProviderFromFuncs(file FileWalkerProviderFunc, reader ReaderWalkerProviderFunc) WalkerProvider {
	return walkerProvider{
		fromFile:   file,
		fromReader: reader,
	}
}

// WalkerFromReaderWalkerProvider creates a WalkerProvider where the same function is used for both
// the FromFile and FromReader methods.
// For the FromFile, the file pointer is passed directly to reader.
func WalkerFromReaderWalkerProvider(reader ReaderWalkerProviderFunc) WalkerProvider {
	return walkerProvider{
		fromFile: func(f *os.File) (WalkFn, func() error, error) {
			return reader(f)
		},
		fromReader: reader,
	}
}

type walkerProvider struct {
	fromFile   func(f *os.File) (WalkFn, func() error, error)
	fromReader func(r io.Reader) (WalkFn, func() error, error)
}

func (w walkerProvider) FromFile(f *os.File) (WalkFn, func() error, error) {
	return w.fromFile(f)
}

func (w walkerProvider) FromReader(r io.Reader) (WalkFn, func() error, error) {
	return w.fromReader(r)
}

// ZipArchiveWalkers creates a WalkerProvider for zipped file content.
// maxReadLimit is the maximum amount of data to read from a reader when FromReader is called.
func ZipArchiveWalkers() WalkerProvider {
	return walkerProvider{
		fromFile: func(f *os.File) (WalkFn, func() error, error) {
			stat, err := f.Stat()
			if err != nil {
				return nil, nil, err
			}
			reader, err := zip.NewReader(f, stat.Size())
			return zipArchiveWalker(reader), func() error { return nil }, err
		},
		fromReader: func(r io.Reader) (WalkFn, func() error, error) {
			reader, err := ZipReaderFromReader(r)
			if err != nil {
				return nil, nil, err
			}
			return zipArchiveWalker(reader), noopCloser, nil
		},
	}
}

func zipArchiveWalker(r *zip.Reader) WalkFn {
	return func(ctx context.Context, walkFn FileWalkFn) error {
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
}

// TarGzWalkers creates a WalkerProvider for gzipped tar content.
func TarGzWalkers() WalkerProvider {
	return WalkerFromReaderWalkerProvider(func(f io.Reader) (WalkFn, func() error, error) {
		reader, close, err := TarGzipReader(f)
		if err != nil {
			return nil, nil, err
		}
		return tarArchiveWalker(reader), close, nil
	})
}

// TarBz2Walkers creates a WalkerProvider for bz2 zipped tar content.
func TarBz2Walkers() WalkerProvider {
	return WalkerFromReaderWalkerProvider(func(r io.Reader) (WalkFn, func() error, error) {
		return tarArchiveWalker(tar.NewReader(bzip2.NewReader(r))), func() error { return nil }, nil
	})
}

// TarArchiveWalkers creates a WalkerProvider for tar content.
func TarArchiveWalkers() WalkerProvider {
	return WalkerFromReaderWalkerProvider(func(r io.Reader) (WalkFn, func() error, error) {
		return tarArchiveWalker(tar.NewReader(r)), func() error { return nil }, nil
	})
}

func tarArchiveWalker(r *tar.Reader) WalkFn {
	return func(ctx context.Context, walkFn FileWalkFn) error {
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
}

func noopCloser() error { return nil }
