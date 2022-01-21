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
	"compress/bzip2"
	"context"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strings"

	"github.com/palantir/log4j-sniffer/pkg/archive/zip"
)

// Walkers creates a function that will return a WalkerProvider for a file path if there is one supported.
// maxInMemoryArchiveSize configures the maximum buffer size to create for archive that are required to be
// read into memory before being able to walk through them.
// The int64 returned from the function will return -1 if there is no limit for size that archive walker,
// otherwise returning the maximum archive size that should be used when using the WalkerProvider.FromReader
// method.
// The given FileOpenMode will determine whether a file used standard file opening or direct I/O. Standard file opening
// may put pressure on the filesystem cache under certain circumstances, resulting in extra work for the filesystem
// due to cache eviction. Direct I/O may be enabled which will skip the filesystem cache for operating systems that
// support it. With Direct I/O enabled, it will only be used for archives where reading through the stream is required
// to find file headers rather than for archives where a file table can be located and skipped to at a known place.
// e.g. Direct I/O may be used for tar-based archives, but will not be used for zip-based archives.
func Walkers(maxInMemoryArchiveSize int64, fileOpenMode FileOpenMode) func(path string) (WalkerProvider, int64, bool) {
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
				return TarArchiveWalkers(fileOpenMode), -1, true
			case "tar.gz", "tgz":
				return TarGzWalkers(fileOpenMode), -1, true
			case "tar.bz2", "tbz2":
				return TarBz2Walkers(fileOpenMode), -1, true
			}
		}
		return nil, 0, false
	}
}

// WalkerProvider creates WalkFn and closing function from certain resources.
type WalkerProvider interface {
	FromFile(string) (WalkFn, func() error, error)
	FromReader(io.Reader) (WalkFn, func() error, error)
}

// FileWalkerProviderFunc creates a WalkFn and closing function from a file.
type FileWalkerProviderFunc func(path string) (WalkFn, func() error, error)

// ReaderWalkerProviderFunc creates a WalkFn and closing function from a reader.
type ReaderWalkerProviderFunc func(r io.Reader) (WalkFn, func() error, error)

// WalkerProviderFromFuncs creates a WalkerProvider from the given file and reader functions.
func WalkerProviderFromFuncs(file FileWalkerProviderFunc, reader ReaderWalkerProviderFunc) WalkerProvider {
	return walkerProvider{
		fromFile:   file,
		fromReader: reader,
	}
}

// WalkerFromReaderWalkerProvider creates IntermediateBufferReader WalkerProvider where the same function is used for both
// the FromFile and FromReader methods.
// For the FromFile, the file pointer is passed directly to reader.
func WalkerFromReaderWalkerProvider(mode FileOpenMode, getWalkFn ReaderWalkerProviderFunc) WalkerProvider {
	var fromFile FileWalkerProviderFunc
	if mode == DirectIOOpen {
		fromFile = directIOOpenFileWalker(getWalkFn)
	} else {
		fromFile = standardOpenFileWalker(getWalkFn)
	}
	return walkerProvider{
		fromFile:   fromFile,
		fromReader: getWalkFn,
	}
}

type walkerProvider struct {
	fromFile   FileWalkerProviderFunc
	fromReader ReaderWalkerProviderFunc
}

func (w walkerProvider) FromFile(path string) (WalkFn, func() error, error) {
	return w.fromFile(path)
}

func (w walkerProvider) FromReader(r io.Reader) (WalkFn, func() error, error) {
	return w.fromReader(r)
}

// ZipArchiveWalkers creates a WalkerProvider for zipped file content.
// maxReadLimit is the maximum amount of data to read from a reader when FromReader is called.
func ZipArchiveWalkers() WalkerProvider {
	return walkerProvider{
		fromFile: func(path string) (WalkFn, func() error, error) {
			return func(ctx context.Context, walkFn FileWalkFn) error {
				return zip.WalkZipFile(path, zipFileWalkFn(ctx, walkFn))
			}, noopCloser, nil
		},
		fromReader: func(r io.Reader) (WalkFn, func() error, error) {
			reader, err := BytesReaderFromReader(r)
			if err != nil {
				return nil, nil, err
			}
			return func(ctx context.Context, walkFn FileWalkFn) error {
				return zip.WalkZipReaderAt(reader, reader.Size(), zipFileWalkFn(ctx, walkFn))
			}, noopCloser, nil
		},
	}
}
func zipFileWalkFn(ctx context.Context, walkFn FileWalkFn) zip.WalkFn {
	return func(file *zip.File) (bool, error) {
		if file.FileInfo().IsDir() {
			return true, nil
		}
		rc, err := file.Open()
		if err != nil {
			return false, err
		}
		if math.MaxInt64 < file.UncompressedSize64 {
			return false, fmt.Errorf("filesize over max supported size: %d", file.UncompressedSize64)
		}
		return walkFn(ctx, file.Name, int64(file.UncompressedSize64), rc)
	}
}

// TarGzWalkers creates a WalkerProvider for gzipped tar content.
func TarGzWalkers(mode FileOpenMode) WalkerProvider {
	return WalkerFromReaderWalkerProvider(mode, func(r io.Reader) (WalkFn, func() error, error) {
		reader, close, err := TarGzipReader(r)
		if err != nil {
			return nil, nil, err
		}
		return tarArchiveWalker(reader), close, nil
	})
}

// TarBz2Walkers creates a WalkerProvider for bz2 zipped tar content.
func TarBz2Walkers(mode FileOpenMode) WalkerProvider {
	return WalkerFromReaderWalkerProvider(mode, func(r io.Reader) (WalkFn, func() error, error) {
		return tarArchiveWalker(tar.NewReader(bzip2.NewReader(r))), func() error { return nil }, nil
	})
}

// TarArchiveWalkers creates a WalkerProvider for tar content.
func TarArchiveWalkers(mode FileOpenMode) WalkerProvider {
	return WalkerFromReaderWalkerProvider(mode, func(r io.Reader) (WalkFn, func() error, error) {
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
