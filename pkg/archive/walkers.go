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
	"github.com/palantir/log4j-sniffer/pkg/buffer"
)

// Walkers creates a function that will return a WalkerProvider for a file path if there is one supported.
// The bool returned will be true if the path is supported, false otherwise.
//
// When creating a walker from a reader, if the type of archive requires that the content must be available as a
// ReaderAt, then the buffer.ReaderReaderAtConverter will be used to convert the Reader to a ReaderAt.
//
// The given FileOpenMode will determine whether a file used standard file opening or direct I/O. Standard file opening
// may put pressure on the filesystem cache under certain circumstances, resulting in extra work for the filesystem
// due to cache eviction. Direct I/O may be enabled which will skip the filesystem cache for operating systems that
// support it. With Direct I/O enabled, it will only be used for archives where reading through the stream is required
// to find file headers rather than for archives where a file table can be located and skipped to at a known place.
// e.g. Direct I/O may be used for tar-based archives, but will not be used for zip-based archives.
func Walkers(convertReader buffer.ReaderReaderAtConverter, fileOpenMode FileOpenMode) func(path string) (WalkerProvider, bool) {
	return func(path string) (WalkerProvider, bool) {
		_, filename := filepath.Split(path)
		fileSplit := strings.Split(filename, ".")
		if len(fileSplit) < 2 {
			return nil, false
		}

		// only search for a depth of two extension dots
		for i := len(fileSplit) - 1; i >= len(fileSplit)-2; i-- {
			switch strings.Join(fileSplit[i:], ".") {
			case "ear", "jar", "par", "war", "zip":
				return ZipArchiveWalkers(convertReader), true
			case "tar":
				return TarArchiveWalkers(fileOpenMode), true
			case "tar.gz", "tgz":
				return TarGzWalkers(fileOpenMode), true
			case "tar.bz2", "tbz2":
				return TarBz2Walkers(fileOpenMode), true
			}
		}
		return nil, false
	}
}

// WalkerProvider creates WalkFn and closing function from certain resources.
type WalkerProvider interface {
	FromFile(string) (WalkCloser, error)
	FromReader(io.Reader, int64) (WalkCloser, error)
}

// FileWalkerProviderFunc creates a WalkFn and closing function from a file.
type FileWalkerProviderFunc func(path string) (WalkCloser, error)

// ReaderWalkerProviderFunc creates a WalkFn and closing function from a reader.
type ReaderWalkerProviderFunc func(r io.Reader, size int64) (WalkCloser, error)

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
func WalkerFromReaderWalkerProvider(mode FileOpenMode, getReaderWalker ReaderWalkerProviderFunc) WalkerProvider {
	var fromFile FileWalkerProviderFunc
	if mode == DirectIOOpen {
		fromFile = directIOOpenFileWalker(getReaderWalker)
	} else {
		fromFile = standardOpenFileWalker(getReaderWalker)
	}
	return walkerProvider{
		fromFile:   fromFile,
		fromReader: getReaderWalker,
	}
}

type walkerProvider struct {
	fromFile   FileWalkerProviderFunc
	fromReader ReaderWalkerProviderFunc
}

func (w walkerProvider) FromFile(path string) (WalkCloser, error) {
	return w.fromFile(path)
}

func (w walkerProvider) FromReader(r io.Reader, size int64) (WalkCloser, error) {
	return w.fromReader(r, size)
}

// ZipArchiveWalkers creates a WalkerProvider for zipped file content.
// convertReader is used to convert a Reader to a ReaderAt.
func ZipArchiveWalkers(converter buffer.ReaderReaderAtConverter) WalkerProvider {
	return walkerProvider{
		fromFile: func(path string) (WalkCloser, error) {
			return walkCloser{
				walk: func(ctx context.Context, walkFn FileWalkFn) error {
					return zip.WalkZipFile(path, zipFileWalkFn(ctx, walkFn))
				},
			}, nil
		}, fromReader: func(r io.Reader, contentSize int64) (WalkCloser, error) {
			reader, close, err := converter.ReaderAt(r, contentSize)
			if err != nil {
				return nil, err
			}
			return walkCloser{
				walk: func(ctx context.Context, walkFn FileWalkFn) error {
					return zip.WalkZipReaderAt(reader, contentSize, zipFileWalkFn(ctx, walkFn))
				},
				close: close,
			}, nil
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
	return WalkerFromReaderWalkerProvider(mode, func(r io.Reader, _ int64) (WalkCloser, error) {
		reader, close, err := TarGzipReader(r)
		if err != nil {
			return nil, err
		}
		return walkCloser{
			walk:  tarArchiveWalker(reader),
			close: close,
		}, nil
	})
}

// TarBz2Walkers creates a WalkerProvider for bz2 zipped tar content.
func TarBz2Walkers(mode FileOpenMode) WalkerProvider {
	return WalkerFromReaderWalkerProvider(mode, func(r io.Reader, _ int64) (WalkCloser, error) {
		return walkCloser{
			walk: tarArchiveWalker(tar.NewReader(bzip2.NewReader(r))),
		}, nil
	})
}

// TarArchiveWalkers creates a WalkerProvider for tar content.
func TarArchiveWalkers(mode FileOpenMode) WalkerProvider {
	return WalkerFromReaderWalkerProvider(mode, func(r io.Reader, _ int64) (WalkCloser, error) {
		return walkCloser{
			walk: tarArchiveWalker(tar.NewReader(r)),
		}, nil
	})
}

func tarArchiveWalker(r *tar.Reader) func(ctx context.Context, walkFn FileWalkFn) error {
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
