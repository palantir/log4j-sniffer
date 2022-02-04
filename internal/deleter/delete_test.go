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

package deleter_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/palantir/log4j-sniffer/internal/deleter"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleter_Delete(t *testing.T) {
	t.Run("nil match functions act as match-all", func(t *testing.T) {
		file := mustTempFile(t)
		assert.False(t, deleter.Deleter{}.Process(context.Background(), crawl.Path{file, "bar"}, 1, nil))
		assertDoesntExist(t, file)
	})

	t.Run("logs error on filepath match error", func(t *testing.T) {
		var err bytes.Buffer
		assert.True(t, deleter.Deleter{
			Logger: log.Logger{
				ErrorWriter: &err,
			},
			FilepathMatch: func(string) (bool, error) { return true, errors.New("some err") },
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 0, nil))
		assert.Equal(t, "[ERROR] Error matching file foo: some err\n", err.String())
	})

	t.Run("passes first path segment to FilepathMatch", func(t *testing.T) {
		var path string
		assert.True(t, deleter.Deleter{
			FilepathMatch: func(p string) (bool, error) {
				path = p
				return false, nil
			},
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 0, nil))
		assert.Equal(t, "foo", path)
	})

	t.Run("passes finding to finding matcher if path matches", func(t *testing.T) {
		var finding crawl.Finding
		assert.True(t, deleter.Deleter{
			FilepathMatch: func(string) (bool, error) { return true, nil },
			FindingMatch: func(f crawl.Finding) bool {
				finding = f
				return false
			},
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 600, nil))
		assert.Equal(t, crawl.Finding(600), finding)
	})

	t.Run("passes versions to version matcher if path and finding matches", func(t *testing.T) {
		var versions crawl.Versions
		assert.True(t, deleter.Deleter{
			FilepathMatch: func(string) (bool, error) { return true, nil },
			FindingMatch:  func(f crawl.Finding) bool { return true },
			VersionsMatch: func(vs crawl.Versions) bool {
				versions = vs
				return false
			},
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 600, crawl.Versions{"foo": {}}))
		assert.Equal(t, crawl.Versions{"foo": {}}, versions)
	})

	t.Run("logs dry mode if running in dry mode", func(t *testing.T) {
		file := mustTempFile(t)
		var out bytes.Buffer
		assert.False(t, deleter.Deleter{
			Logger: log.Logger{
				OutputWriter: &out,
			},
			FilepathMatch: func(string) (bool, error) { return true, nil },
			FindingMatch:  func(crawl.Finding) bool { return true },
			DryRun:        true,
		}.Process(context.Background(), crawl.Path{file, "bar"}, 600, nil))
		assert.Equal(t, fmt.Sprintf("[INFO] Dry-run: would delete %s\n", file), out.String())
		_, err := os.Stat(file)
		assert.NoError(t, err)
	})

	t.Run("deletes file if filepath, finding and version match", func(t *testing.T) {
		file := mustTempFile(t)
		var out bytes.Buffer
		deleter.Deleter{
			Logger: log.Logger{
				OutputWriter: &out,
			},
			FilepathMatch: func(string) (bool, error) { return true, nil },
			FindingMatch:  func(crawl.Finding) bool { return true },
			VersionsMatch: func(crawl.Versions) bool { return true },
		}.Process(context.Background(), crawl.Path{file, "bar"}, 600, nil)
		assert.Equal(t, fmt.Sprintf("[INFO] Deleted file %s\n", file), out.String())
		assertDoesntExist(t, file)
	})

	t.Run("logs error if error deleting file", func(t *testing.T) {
		var err bytes.Buffer
		path := filepath.Join(t.TempDir(), "nonexistent")
		deleter.Deleter{
			Logger: log.Logger{
				ErrorWriter: &err,
			},
			FilepathMatch: func(string) (bool, error) { return true, nil },
			FindingMatch:  func(crawl.Finding) bool { return true },
		}.Process(context.Background(), crawl.Path{path, "bar"}, 600, nil)
		assert.True(t, strings.HasPrefix(err.String(), fmt.Sprintf("[ERROR] Error deleting file %s: ", path)))
	})
}

func assertDoesntExist(t *testing.T, file string) {
	t.Helper()
	_, err := os.Stat(file)
	assert.True(t, os.IsNotExist(err))
}

func mustTempFile(t *testing.T) string {
	t.Helper()
	file, err := ioutil.TempFile(t.TempDir(), "")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	return file.Name()
}
