// Copyright (c) 2022 Palantir Technologies. All rights reserved.
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

package buffer

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// ContentsExceedLimitError is the error implementation returned when the content size of a reader would cause a
// configured maximum limit to be exceeded.
// The string value of the ContentsExceedLimitError describes the details of the circumstance in which the limit would
// be breached.
type ContentsExceedLimitError string

// Error describes the details about the way the limit would be exceeded by the size of some contents.
func (o ContentsExceedLimitError) Error() string {
	if o == "" {
		return "contents size exceeds limit"
	}
	return string("contents size exceeds limit: " + o)
}

// ReaderReaderAtConverter converts a reader with a specific contentSize to a ReaderAt with a CloseFn.
type ReaderReaderAtConverter interface {
	ReaderAt(r io.Reader, contentSize int64) (io.ReaderAt, CloseFn, error)
}

// CloseFn should free any resources after the ReaderAt has been used.
type CloseFn func() error

// InMemoryWithDiskOverflowReaderAtConverter creates a ReaderReaderAtConverter with the following behaviour:
// - Any amount of in-memory buffers can be created where the reader contents size is less or equal to the c.MaxMemorySize.
// - When a ReaderAt is being created with a size above the MaxMemorySize, a temporary file will be created in the Path
//   containing the content of the reader. The temporary file will be deleted upon calling the CloseFn from returned
//   from the call to ReaderAt.
//   If previously temporary files still exist, then new temporary files will only be created if MaxDiskSpace take the
//   size of the space already occupied by the temporary files is enough to fit the new Reader contents into. Otherwise,
//   a ContentsExceedLimitError will be returned outlining the details of the error.
type InMemoryWithDiskOverflowReaderAtConverter struct {
	Path          string
	MaxMemorySize int64
	MaxDiskSpace  int64

	sizeOccupied int64
}

func (c *InMemoryWithDiskOverflowReaderAtConverter) ReaderAt(r io.Reader, contentSize int64) (io.ReaderAt, CloseFn, error) {
	if contentSize <= c.MaxMemorySize {
		return inMemoryReaderAt(r, contentSize)
	}

	if contentSize > (c.MaxDiskSpace - c.sizeOccupied) {
		return nil, nil, ContentsExceedLimitError("over remaining space allowed for disk swap")
	}

	file, err := ioutil.TempFile(c.Path, "log4j-sniffer-tmp")
	if err != nil {
		return nil, nil, err
	}

	c.sizeOccupied += contentSize

	if err := copyExactlyN(file, r, contentSize); err != nil {
		// Only free the number of bytes that we reserved if there is no error deleting the file.
		// Otherwise, we occupy the contentSize, which would be the max number of bytes written by copyExactlyN.
		if rmErr := os.Remove(file.Name()); rmErr == nil {
			c.sizeOccupied -= contentSize
		}
		return nil, nil, err
	}

	var freed bool
	return file, func() error {
		if freed {
			return nil
		}
		if err := os.Remove(file.Name()); err != nil {
			return err
		}
		freed = true
		c.sizeOccupied -= contentSize
		return nil
	}, nil
}

// SizeCappedInMemoryReaderAtConverter will create a ReaderAt from a reader only if the size of the reader is less than
// maxSize
func SizeCappedInMemoryReaderAtConverter(maxSize int64) ReaderReaderAtConverterFunc {
	return func(r io.Reader, contentSize int64) (io.ReaderAt, CloseFn, error) {
		if contentSize > maxSize {
			return nil, nil, ContentsExceedLimitError("over max allowed in-memory buffer size")
		}
		return inMemoryReaderAt(r, contentSize)
	}
}

// ReaderReaderAtConverterFunc is a pure function ReaderReaderAtConverter
type ReaderReaderAtConverterFunc func(r io.Reader, contentSize int64) (io.ReaderAt, CloseFn, error)

func (fn ReaderReaderAtConverterFunc) ReaderAt(r io.Reader, contentSize int64) (io.ReaderAt, CloseFn, error) {
	return fn(r, contentSize)
}

func inMemoryReaderAt(r io.Reader, size int64) (io.ReaderAt, CloseFn, error) {
	var buf bytes.Buffer
	if err := copyExactlyN(&buf, r, size); err != nil {
		return nil, nil, err
	}
	return bytes.NewReader(buf.Bytes()), func() error { return nil }, nil
}

func copyExactlyN(dst io.Writer, src io.Reader, n int64) error {
	actualN, err := io.CopyN(dst, src, n)
	if err == io.EOF {
		return fmt.Errorf("expected content size to be %d but was %d", n, actualN)
	}
	return err
}
