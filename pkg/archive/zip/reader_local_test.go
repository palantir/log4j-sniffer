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

package zip_test

import (
	"errors"
	"io/ioutil"
	"strconv"
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/archive/zip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type walkedFile struct {
	path     string
	size     uint64
	contents []byte
}

func TestWalkZipFile(t *testing.T) {
	t.Run("single file", func(t *testing.T) {
		var paths []walkedFile
		err := zip.WalkZipFile("./testdata/single-file.zip", func(f *zip.File) (bool, error) {
			paths = append(paths, walkedZipFile(t, f))
			return true, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []walkedFile{{
			path:     "0",
			size:     1,
			contents: []byte("0"),
		}}, paths)
	})

	t.Run("two files with subdirs", func(t *testing.T) {
		var paths []walkedFile
		err := zip.WalkZipFile("./testdata/two-files-with-subdirs.zip", func(f *zip.File) (bool, error) {
			paths = append(paths, walkedZipFile(t, f))
			return true, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []walkedFile{{
			path:     "dir/0",
			size:     1,
			contents: []byte("0"),
		}, {
			path:     "dir/1",
			size:     1,
			contents: []byte("1"),
		}}, paths)
	})

	t.Run("large number of files", func(t *testing.T) {
		var i int
		err := zip.WalkZipFile("./testdata/large-number-of-files.zip", func(f *zip.File) (bool, error) {
			assert.Equal(t, strconv.Itoa(i), f.Name)
			assert.Equal(t, uint64(1), f.UncompressedSize64)
			assert.Equal(t, string(strconv.Itoa(i)[0]), string(mustReadAllContents(t, f)))
			i++
			return true, nil
		})
		require.NoError(t, err)
		assert.Equal(t, 120, i)
	})

	t.Run("stops and returns error from file walk", func(t *testing.T) {
		var paths []walkedFile
		expectedErr := errors.New("err")
		err := zip.WalkZipFile("./testdata/two-files-with-subdirs.zip", func(f *zip.File) (bool, error) {
			paths = append(paths, walkedZipFile(t, f))
			return false, expectedErr
		})
		require.Equal(t, expectedErr, err)
		assert.Equal(t, []walkedFile{{
			path:     "dir/0",
			size:     1,
			contents: []byte("0"),
		}}, paths)
	})

	t.Run("stops when a file walk returns false", func(t *testing.T) {
		var paths []walkedFile
		err := zip.WalkZipFile("./testdata/two-files-with-subdirs.zip", func(f *zip.File) (bool, error) {
			paths = append(paths, walkedZipFile(t, f))
			return false, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []walkedFile{{
			path:     "dir/0",
			size:     1,
			contents: []byte("0"),
		}}, paths)
	})
}

func walkedZipFile(t *testing.T, f *zip.File) walkedFile {
	return walkedFile{
		path:     f.Name,
		size:     f.UncompressedSize64,
		contents: mustReadAllContents(t, f),
	}
}

func mustReadAllContents(t testing.TB, f *zip.File) []byte {
	t.Helper()
	rc, err := f.Open()
	require.NoError(t, err)
	defer func() { assert.NoError(t, rc.Close()) }()
	all, err := ioutil.ReadAll(rc)
	require.NoError(t, err)
	return all
}
