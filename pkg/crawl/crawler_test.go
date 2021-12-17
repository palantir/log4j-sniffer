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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/palantir/log4j-scanner/internal/generated/metrics/metrics"
	"github.com/palantir/log4j-scanner/pkg/testcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrawler_Crawl(t *testing.T) {
	t.Run("ignores configured directories and non-regular files", func(t *testing.T) {
		var matchPathInputs []string
		var matchDirEntryInputs []string
		var processInputs []string
		var processDirEntryInputs []string
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
		require.NoError(t, Crawler{
			IgnoreDirs: []*regexp.Regexp{
				regexp.MustCompile(filepath.Join(root, `foo`)),
				regexp.MustCompile(filepath.Join(root, `baz`)),
			},
		}.Crawl(testcontext.GetTestContext(t), root, func(ctx context.Context, path string, d fs.DirEntry) (Finding, string, error) {
			matchPathInputs = append(matchPathInputs, path)
			matchDirEntryInputs = append(matchDirEntryInputs, d.Name())
			return JarName, UnknownVersion, nil
		}, func(ctx context.Context, path string, d fs.DirEntry, result Finding, version string) {
			processInputs = append(processInputs, path)
			processDirEntryInputs = append(processDirEntryInputs, d.Name())
		}))
		assert.Equal(t, []string{filepath.Join(root, "qux/qux")}, matchPathInputs)
		assert.Equal(t, []string{"qux"}, matchDirEntryInputs)
		assert.Equal(t, []string{filepath.Join(root, "qux/qux")}, processInputs)
		assert.Equal(t, []string{"qux"}, processDirEntryInputs)
	})

	t.Run("updates duration metric", func(t *testing.T) {
		ctx := testcontext.WithCleanMetricsRegistry(t)
		require.NoError(t, Crawler{}.Crawl(ctx, makeTestFS(t, nil, []string{"foo"}), func(context.Context, string, fs.DirEntry) (Finding, string, error) {
			time.Sleep(time.Millisecond)
			return JarName, UnknownVersion, nil
		}, func(ctx context.Context, path string, d fs.DirEntry, result Finding, version string) {}))
		assert.Greater(t, metrics.Crawl(ctx).DurationMilliseconds().Gauge().Value(), int64(0))
	})

	t.Run("returns without processing if context is done", func(t *testing.T) {
		var countMatch int
		var countProcess int
		ctx, cancel := context.WithCancel(testcontext.GetTestContext(t))
		cancel()
		require.Equal(t, ctx.Err(), Crawler{}.Crawl(ctx, t.TempDir(), func(context.Context, string, fs.DirEntry) (Finding, string, error) {
			countMatch++
			return JarName, UnknownVersion, nil
		}, func(context.Context, string, fs.DirEntry, Finding, string) {
			countProcess++
		}))
		assert.Zero(t, countMatch)
		assert.Zero(t, countProcess)
	})

	t.Run("error from match does not process file", func(t *testing.T) {
		var matchInputs []string
		var countProcess int
		root := makeTestFS(t, nil, []string{"foo"})
		require.NoError(t, Crawler{}.Crawl(testcontext.GetTestContext(t), root,
			func(ctx context.Context, path string, entry fs.DirEntry) (Finding, string, error) {
				matchInputs = append(matchInputs, path)
				return NothingDetected, UnknownVersion, errors.New("")
			}, func(context.Context, string, fs.DirEntry, Finding, string) {
				countProcess++
			}))
		assert.Equal(t, []string{filepath.Join(root, "foo")}, matchInputs)
		assert.Zero(t, countProcess)
	})

	t.Run("no match does not process file", func(t *testing.T) {
		var matchInputs []string
		var countProcess int
		root := makeTestFS(t, nil, []string{"foo"})
		require.NoError(t, Crawler{}.Crawl(testcontext.GetTestContext(t), root,
			func(ctx context.Context, path string, entry fs.DirEntry) (Finding, string, error) {
				matchInputs = append(matchInputs, path)
				return NothingDetected, UnknownVersion, nil
			}, func(context.Context, string, fs.DirEntry, Finding, string) {
				countProcess++
			}))
		assert.Equal(t, []string{filepath.Join(root, "foo")}, matchInputs)
		assert.Zero(t, countProcess)
	})

	t.Run("processes files on match", func(t *testing.T) {
		var processInputs []string
		ctx := testcontext.GetTestContext(t)
		root := makeTestFS(t, nil, []string{"foo", "bar"})
		require.NoError(t, Crawler{}.Crawl(ctx, root,
			func(context.Context, string, fs.DirEntry) (Finding, string, error) {
				return JarName, UnknownVersion, nil
			}, func(innerCtx context.Context, path string, entry fs.DirEntry, result Finding, version string) {
				processInputs = append(processInputs, path)
				assert.Equal(t, ctx, innerCtx)
			}))
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
