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

package buffer_test

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/buffer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContentsExceedLimitError_Error(t *testing.T) {
	assert.Equal(t, "contents size exceeds limit", buffer.ContentsExceedLimitError("").Error())
	assert.Equal(t, "contents size exceeds limit: foo", buffer.ContentsExceedLimitError("foo").Error())
}

func TestSizeCappedInMemoryReaderAt(t *testing.T) {
	t.Run("errors when content size too large", func(t *testing.T) {
		converter := buffer.SizeCappedInMemoryReaderAtConverter(10)
		_, _, err := converter.ReaderAt(nil, 11)
		require.Equal(t, buffer.ContentsExceedLimitError("over max allowed in-memory buffer size"), err)
	})

	t.Run("reader with more contents that content size specified will read only content size", func(t *testing.T) {
		converter := buffer.SizeCappedInMemoryReaderAtConverter(10)
		ra, close, err := converter.ReaderAt(bytes.NewBufferString("0123456789"), 2)
		require.NoError(t, err)
		assertReaderAtContent(t, ra, []byte("01"))
		assert.NoError(t, close())
	})

	t.Run("errors when reader has less contents that content size specified", func(t *testing.T) {
		converter := buffer.SizeCappedInMemoryReaderAtConverter(10)
		_, _, err := converter.ReaderAt(bytes.NewBufferString("0"), 10)
		require.EqualError(t, err, "expected content size to be 10 but was 1")
	})

	t.Run("creates reader at of correct size when within limit", func(t *testing.T) {
		converter := buffer.SizeCappedInMemoryReaderAtConverter(10)
		ra, close, err := converter.ReaderAt(bytes.NewBufferString("0123456789"), 10)
		require.NoError(t, err)
		assertReaderAtContent(t, ra, []byte("0123456789"))
		assert.NoError(t, close())
	})
}

func TestInMemoryWithDiskOverflowReaderAt(t *testing.T) {
	t.Run("should return oversized error when size is above memory and disk max", func(t *testing.T) {
		_, _, err := (&buffer.InMemoryWithDiskOverflowReaderAtConverter{}).ReaderAt(nil, 1)
		assert.Equal(t, buffer.ContentsExceedLimitError("over remaining space allowed for disk swap"), err)
	})

	t.Run("should not create file when under memory buffer size", func(t *testing.T) {
		dir := t.TempDir()
		r, close, err := (&buffer.InMemoryWithDiskOverflowReaderAtConverter{
			Path:          dir,
			MaxMemorySize: 3,
			MaxDiskSpace:  0,
		}).ReaderAt(bytes.NewBufferString("foo"), 3)
		require.NoError(t, err)
		assertTempFileCountAndSize(t, dir, 0, 0)
		assertReaderAtContent(t, r, []byte("foo"))
		assert.NoError(t, close())
	})

	t.Run("should create file when above memory size but equal to max disk size", func(t *testing.T) {
		dir := t.TempDir()
		r, close, err := (&buffer.InMemoryWithDiskOverflowReaderAtConverter{
			Path:          dir,
			MaxMemorySize: 3,
			MaxDiskSpace:  4,
		}).ReaderAt(bytes.NewBufferString("fooo"), 4)
		require.NoError(t, err)
		assertTempFileCountAndSize(t, dir, 1, 4)
		assertReaderAtContent(t, r, []byte("fooo"))
		assert.NoError(t, close())
		assertTempFileCountAndSize(t, dir, 0, 0)
	})

	t.Run("reader with more contents than content size specified will read only content size", func(t *testing.T) {
		dir := t.TempDir()
		r, close, err := (&buffer.InMemoryWithDiskOverflowReaderAtConverter{
			Path:          dir,
			MaxMemorySize: 3,
			MaxDiskSpace:  4,
		}).ReaderAt(bytes.NewBufferString("foobar"), 4)
		require.NoError(t, err)
		assertTempFileCountAndSize(t, dir, 1, 4)
		assertReaderAtContent(t, r, []byte("foob"))
		assert.NoError(t, close())
	})

	t.Run("errors when reader has less contents that content size specified", func(t *testing.T) {
		dir := t.TempDir()
		_, _, err := (&buffer.InMemoryWithDiskOverflowReaderAtConverter{
			Path:          dir,
			MaxMemorySize: 3,
			MaxDiskSpace:  4,
		}).ReaderAt(bytes.NewBufferString("0"), 4)
		require.EqualError(t, err, "expected content size to be 4 but was 1")
		// file should be deleted
		assertTempFileCountAndSize(t, dir, 0, 0)
	})

	t.Run("should error when second convert would cause space occupied to be over configured maximum", func(t *testing.T) {
		dir := t.TempDir()
		converter := buffer.InMemoryWithDiskOverflowReaderAtConverter{
			Path:          dir,
			MaxMemorySize: 0,
			MaxDiskSpace:  3,
		}

		r, closeA, err := converter.ReaderAt(bytes.NewBufferString("foo"), 3)
		require.NoError(t, err)
		assertTempFileCountAndSize(t, dir, 1, 3)
		assertReaderAtContent(t, r, []byte("foo"))

		_, _, err = converter.ReaderAt(nil, 1)
		assert.Equal(t, buffer.ContentsExceedLimitError("over remaining space allowed for disk swap"), err)

		assert.NoError(t, closeA())
		assertTempFileCountAndSize(t, dir, 0, 0)
	})

	t.Run("total size of files on disk should equal sum of required buffer sizes", func(t *testing.T) {
		dir := t.TempDir()
		converter := buffer.InMemoryWithDiskOverflowReaderAtConverter{
			Path:         dir,
			MaxDiskSpace: 6,
		}

		rA, closeA, errA := converter.ReaderAt(bytes.NewBufferString("foo"), 3)
		require.NoError(t, errA)
		assertTempFileCountAndSize(t, dir, 1, 3)
		assertReaderAtContent(t, rA, []byte("foo"))

		rB, closeB, errB := converter.ReaderAt(bytes.NewBufferString("bar"), 3)
		require.NoError(t, errB)
		assertTempFileCountAndSize(t, dir, 2, 6)
		assertReaderAtContent(t, rB, []byte("bar"))

		assert.NoError(t, closeA())
		assertTempFileCountAndSize(t, dir, 1, 3)
		assert.NoError(t, closeB())
		assertTempFileCountAndSize(t, dir, 0, 0)
	})
}

func assertReaderAtContent(t *testing.T, ra io.ReaderAt, content []byte) {
	t.Helper()
	expectedContentLen := len(content)
	// attempt read into buffer that is oversized by 1 element,
	// expecting an EOF with exactly the content length being written to buffer
	buf := make([]byte, expectedContentLen+1)
	n, err := ra.ReadAt(buf, 0)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, expectedContentLen, n)
	assert.Equal(t, content, buf[:expectedContentLen])
}

func assertTempFileCountAndSize(t *testing.T, dir string, count int, totalSize int) {
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, count)
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		require.NoError(t, err)
		total += info.Size()
	}
	assert.EqualValues(t, totalSize, total)
}
