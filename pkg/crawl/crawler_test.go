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

package crawl

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/ratelimit"
)

func TestCrawler_Crawl(t *testing.T) {
	t.Run("ignores configured directories and non-regular files", func(t *testing.T) {
		var matchPathInputs []string
		var matchDirEntryInputs []string
		root := makeTestFS(t, []string{
			"foo",
			"bar",
			"baz",
			"qux",
		}, []string{
			"foo/foo",
			"baz/baz",
			"qux/qux",
		})
		require.NoError(t, os.Symlink(filepath.Join(root, "bar/bar"), filepath.Join(root, "bar/bar")))
		stats, err := Crawler{
			Limiter: ratelimit.NewUnlimited(),
			IgnoreDirs: []*regexp.Regexp{
				regexp.MustCompile(filepath.Join(root, `foo`)),
				regexp.MustCompile(filepath.Join(root, `baz`)),
			},
			DirectoryEntriesPerListCall: 1,
		}.Crawl(context.Background(), root, func(ctx context.Context, path string, name string) (uint64, error) {
			matchPathInputs = append(matchPathInputs, path)
			matchDirEntryInputs = append(matchDirEntryInputs, name)
			return 1, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []string{filepath.Join(root, "qux/qux")}, matchPathInputs)
		assert.Equal(t, []string{"qux"}, matchDirEntryInputs)
		assert.Equal(t, Stats{
			FilesScanned:     1,
			PathSkippedCount: 1,
		}, stats)
	})

	t.Run("returns without processing if context is done", func(t *testing.T) {
		var countProcess int
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		root := makeTestFS(t, nil, []string{"foo"})
		_, err := Crawler{
			Limiter:                     ratelimit.NewUnlimited(),
			DirectoryEntriesPerListCall: 1,
		}.Crawl(ctx, root, func(context.Context, string, string) (uint64, error) {
			countProcess++
			return 0, nil
		})
		require.Equal(t, ctx.Err(), err)
		assert.Zero(t, countProcess)
	})
}

// makeTestFS creates all dirs first, the all files.
// To create a file list a dir, include the dir list the dirs, then the full file path list the files.
func makeTestFS(t *testing.T, dirs []string, files []string) string {
	t.Helper()
	tmpDir := t.TempDir()
	for _, dir := range dirs {
		require.NoError(t, os.Mkdir(filepath.Join(tmpDir, dir), 0700))
	}
	for _, file := range files {
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, file), nil, 0640))
	}
	return tmpDir
}
