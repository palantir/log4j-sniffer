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
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkTarGzFiles(t *testing.T) {
	t.Run("cancels on context done", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := WalkTarFiles(ctx, "../../examples/archived_fat_jar/archived_fat_jar.tar.gz",
			func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
				return true, nil
			})
		require.Equal(t, ctx.Err(), err)
	})

	t.Run("successfully lists paths", func(t *testing.T) {
		var paths []string
		err := WalkTarFiles(context.Background(), "../../examples/archived_fat_jar/archived_fat_jar.tar.gz",
			func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
				paths = append(paths, path)
				return true, nil
			})
		require.NoError(t, err)
		assert.NotEmpty(t, paths)
	})
}

func TestWalkZipFiles(t *testing.T) {
	t.Run("cancels on context done", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := WalkZipFiles(ctx, "../../examples/fat_jar/fat_jar.jar",
			func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
				return true, nil
			})
		require.Equal(t, ctx.Err(), err)
	})

	t.Run("successfully lists paths", func(t *testing.T) {
		var paths []string
		err := WalkZipFiles(context.Background(), "../../examples/fat_jar/fat_jar.jar",
			func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
				paths = append(paths, path)
				return true, nil
			})
		require.NoError(t, err)
		assert.NotEmpty(t, paths)
	})
}

func TestCheckArchiveType(t *testing.T) {
	t.Run("zip archives", func(t *testing.T) {
		assert.Equal(t, CheckArchiveType("filename.zip"), ZipArchive)
		assert.Equal(t, CheckArchiveType("fat_jar.jar"), ZipArchive)
		assert.Equal(t, CheckArchiveType("many.dots.with.jar"), ZipArchive)
		assert.Equal(t, CheckArchiveType("par_file.par"), ZipArchive)

	})
	t.Run("tar archives", func(t *testing.T) {
		assert.Equal(t, CheckArchiveType("generic.tar"), TarArchive)
		assert.Equal(t, CheckArchiveType("many.dots.tar"), TarArchive)
	})
	t.Run("tar gz archives", func(t *testing.T) {
		assert.Equal(t, CheckArchiveType("compressed.tar.gz"), TarGzArchive)
		assert.Equal(t, CheckArchiveType("many.dots.tar.gz"), TarGzArchive)
		assert.Equal(t, CheckArchiveType("compressed.tgz"), TarGzArchive)

	})
	t.Run("tar bz2 archives", func(t *testing.T) {
		assert.Equal(t, CheckArchiveType("bz2compressed.tar.bz2"), TarBz2Archive)
		assert.Equal(t, CheckArchiveType("many.dots.tar.bz2"), TarBz2Archive)
		assert.Equal(t, CheckArchiveType("bz2compressed.tbz2"), TarBz2Archive)

	})
	t.Run("unsupported archives", func(t *testing.T) {
		assert.Equal(t, CheckArchiveType("unsupported.jpg"), UnsupportedArchive)
		assert.Equal(t, CheckArchiveType("file.with.many.extensions"), UnsupportedArchive)
		assert.Equal(t, CheckArchiveType("no-extension"), UnsupportedArchive)

	})
}
