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
	"testing"

	"github.com/palantir/log4j-sniffer/internal/deleter"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/log"
	"github.com/stretchr/testify/assert"
)

func TestDeleter_Delete(t *testing.T) {
	t.Run("nil match functions act as match-all", func(t *testing.T) {
		var filepath string
		deleter.Deleter{
			Delete: func(f string) error {
				filepath = f
				return nil
			},
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 1, nil)
		assert.Equal(t, "foo", filepath)
	})

	t.Run("logs error on filepath match error", func(t *testing.T) {
		var err bytes.Buffer
		deleter.Deleter{
			Logger: log.Logger{
				ErrorWriter: &err,
			},
			FilepathMatch: func(string) (bool, error) { return true, errors.New("some err") },
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 0, nil)
		assert.Equal(t, "[ERROR] Error matching file foo: some err\n", err.String())
	})

	t.Run("logs matchers missing when no matchers configured", func(t *testing.T) {
		var path string
		deleter.Deleter{
			FilepathMatch: func(p string) (bool, error) {
				path = p
				return false, nil
			},
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 0, nil)
		assert.Equal(t, "foo", path)
	})

	t.Run("passes first path segment to FilepathMatch", func(t *testing.T) {
		var path string
		deleter.Deleter{
			FilepathMatch: func(p string) (bool, error) {
				path = p
				return false, nil
			},
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 0, nil)
		assert.Equal(t, "foo", path)
	})

	t.Run("passes finding to finding matcher if path matches", func(t *testing.T) {
		var finding crawl.Finding
		deleter.Deleter{
			FilepathMatch: func(string) (bool, error) { return true, nil },
			FindingMatch: func(f crawl.Finding) bool {
				finding = f
				return false
			},
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 600, nil)
		assert.Equal(t, crawl.Finding(600), finding)
	})

	t.Run("logs dry mode if running in dry mode", func(t *testing.T) {
		var out bytes.Buffer
		deleter.Deleter{
			Logger: log.Logger{
				OutputWriter: &out,
			},
			FilepathMatch: func(string) (bool, error) { return true, nil },
			FindingMatch:  func(crawl.Finding) bool { return true },
			DryRun:        true,
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 600, nil)
		assert.Equal(t, "[INFO] Dry-run: would delete foo\n", out.String())
	})

	t.Run("deletes file if filepath and finding match", func(t *testing.T) {
		var path string
		var out bytes.Buffer
		deleter.Deleter{
			Logger: log.Logger{
				OutputWriter: &out,
			},
			FilepathMatch: func(string) (bool, error) { return true, nil },
			FindingMatch:  func(crawl.Finding) bool { return true },
			Delete: func(p string) error {
				path = p
				return nil
			},
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 600, nil)
		assert.Equal(t, "foo", path)
		assert.Equal(t, "[INFO] Deleted file foo\n", out.String())
	})

	t.Run("logs error if error deleting file", func(t *testing.T) {
		var path string
		var err bytes.Buffer
		deleter.Deleter{
			Logger: log.Logger{
				ErrorWriter: &err,
			},
			FilepathMatch: func(string) (bool, error) { return true, nil },
			FindingMatch:  func(crawl.Finding) bool { return true },
			Delete: func(p string) error {
				path = p
				return errors.New("some error")
			},
		}.Process(context.Background(), crawl.Path{"foo", "bar"}, 600, nil)
		assert.Equal(t, "foo", path)
		assert.Equal(t, "[ERROR] Error deleting file foo: some error\n", err.String())
	})
}
