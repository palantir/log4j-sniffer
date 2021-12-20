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
		err := WalkTarGzFiles(ctx, "../../examples/archived_fat_jar/archived_fat_jar.tar.gz",
			func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
				return true, nil
			})
		require.Equal(t, ctx.Err(), err)
	})

	t.Run("successfully lists paths", func(t *testing.T) {
		var paths []string
		err := WalkTarGzFiles(context.Background(), "../../examples/archived_fat_jar/archived_fat_jar.tar.gz",
			func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
				paths = append(paths, path)
				return true, nil
			})
		require.NoError(t, err)
		assert.NotEmpty(t, paths)
	})
}

func TesWalkZipFiles(t *testing.T) {
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
