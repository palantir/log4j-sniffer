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
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/ratelimit"
)

func TestCrawler_Crawl(t *testing.T) {
	t.Run("ignores configured directories and non-regular files", func(t *testing.T) {
		var matchPathInputs []string
		var matchDirEntryInputs []string
		var processInputs []string
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
		_, err := Crawler{
			Limiter: ratelimit.NewUnlimited(),
			IgnoreDirs: []*regexp.Regexp{
				regexp.MustCompile(filepath.Join(root, `foo`)),
				regexp.MustCompile(filepath.Join(root, `baz`)),
			},
			DirectoryEntriesPerListCall: 1,
		}.Crawl(context.Background(), root, func(ctx context.Context, path, name string) (Finding, Versions, uint64, error) {
			matchPathInputs = append(matchPathInputs, path)
			matchDirEntryInputs = append(matchDirEntryInputs, name)
			return JarName, nil, 0, nil
		}, func(ctx context.Context, path string, result Finding, version Versions) {
			processInputs = append(processInputs, path)
		})
		require.NoError(t, err)
		assert.Equal(t, []string{filepath.Join(root, "qux/qux")}, matchPathInputs)
		assert.Equal(t, []string{"qux"}, matchDirEntryInputs)
		assert.Equal(t, []string{filepath.Join(root, "qux/qux")}, processInputs)
	})

	t.Run("returns without processing if context is done", func(t *testing.T) {
		var countMatch int
		var countProcess int
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		root := makeTestFS(t, nil, []string{"foo"})
		_, err := Crawler{
			Limiter:                     ratelimit.NewUnlimited(),
			DirectoryEntriesPerListCall: 1,
		}.Crawl(ctx, root, func(context.Context, string, string) (Finding, Versions, uint64, error) {
			countMatch++
			return JarName, nil, 0, nil
		}, func(context.Context, string, Finding, Versions) {
			countProcess++
		})
		require.Equal(t, ctx.Err(), err)
		assert.Zero(t, countMatch)
		assert.Zero(t, countProcess)
	})

	t.Run("error from match does not process file", func(t *testing.T) {
		var matchInputs []string
		var countProcess int
		root := makeTestFS(t, nil, []string{"foo"})
		_, err := Crawler{
			Limiter:                     ratelimit.NewUnlimited(),
			DirectoryEntriesPerListCall: 1,
		}.Crawl(context.Background(), root,
			func(ctx context.Context, path, name string) (Finding, Versions, uint64, error) {
				matchInputs = append(matchInputs, path)
				return NothingDetected, nil, 0, errors.New("")
			}, func(context.Context, string, Finding, Versions) {
				countProcess++
			})
		require.NoError(t, err)
		assert.Equal(t, []string{filepath.Join(root, "foo")}, matchInputs)
		assert.Zero(t, countProcess)
	})

	t.Run("no match does not process file", func(t *testing.T) {
		var matchInputs []string
		var countProcess int
		root := makeTestFS(t, nil, []string{"foo"})
		_, err := Crawler{
			Limiter:                     ratelimit.NewUnlimited(),
			DirectoryEntriesPerListCall: 1,
		}.Crawl(context.Background(), root,
			func(ctx context.Context, path, name string) (Finding, Versions, uint64, error) {
				matchInputs = append(matchInputs, path)
				return NothingDetected, nil, 0, nil
			}, func(context.Context, string, Finding, Versions) {
				countProcess++
			})
		require.NoError(t, err)
		assert.Equal(t, []string{filepath.Join(root, "foo")}, matchInputs)
		assert.Zero(t, countProcess)
	})

	t.Run("processes files on match", func(t *testing.T) {
		var processInputs []string
		ctx := context.Background()
		root := makeTestFS(t, nil, []string{"foo", "bar"})
		_, err := Crawler{
			Limiter:                     ratelimit.NewUnlimited(),
			DirectoryEntriesPerListCall: 1,
		}.Crawl(ctx, root,
			func(context.Context, string, string) (Finding, Versions, uint64, error) {
				return JarName, nil, 0, nil
			}, func(innerCtx context.Context, path string, result Finding, version Versions) {
				processInputs = append(processInputs, path)
				assert.Equal(t, ctx, innerCtx)
			})
		require.NoError(t, err)
		sort.Strings(processInputs)
		assert.Equal(t, []string{
			filepath.Join(root, "bar"),
			filepath.Join(root, "foo"),
		}, processInputs)
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
