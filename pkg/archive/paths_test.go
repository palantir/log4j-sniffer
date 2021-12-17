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
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/testcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadTarGzFilePaths(t *testing.T) {
	t.Run("cancels on context done", func(t *testing.T) {
		ctx, cancel := context.WithCancel(testcontext.GetTestContext(t))
		cancel()
		_, err := ReadTarGzFilePaths(ctx, "../../examples/archived_fat_jar/archived_fat_jar.tar.gz")
		require.Equal(t, ctx.Err(), err)
	})

	t.Run("successfully lists paths", func(t *testing.T) {
		paths, err := ReadTarGzFilePaths(testcontext.GetTestContext(t), "../../examples/archived_fat_jar/archived_fat_jar.tar.gz")
		require.NoError(t, err)
		assert.NotEmpty(t, paths)
	})
}

func TestReadZipFilePaths(t *testing.T) {
	t.Run("cancels on context done", func(t *testing.T) {
		ctx, cancel := context.WithCancel(testcontext.GetTestContext(t))
		cancel()
		_, err := ReadZipFilePaths(ctx, "../../examples/fat_jar/fat_jar.jar")
		require.Equal(t, ctx.Err(), err)
	})

	t.Run("successfully lists paths", func(t *testing.T) {
		paths, err := ReadZipFilePaths(testcontext.GetTestContext(t), "../../examples/fat_jar/fat_jar.jar")
		require.NoError(t, err)
		assert.NotEmpty(t, paths)
	})
}
