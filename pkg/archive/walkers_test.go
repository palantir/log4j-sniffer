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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupportedExtensions(t *testing.T) {
	tests := []struct {
		filename string
		ok       bool
		maxSize  int64
	}{
		{filename: "filename.zip", ok: true, maxSize: 99},
		{filename: "fat_jar.jar", ok: true, maxSize: 99},
		{filename: "many.dots.with.jar", ok: true, maxSize: 99},
		{filename: ".dotfile.jar", ok: true, maxSize: 99},
		{filename: "par_file.par", ok: true, maxSize: 99},
		{filename: "generic.tar", ok: true, maxSize: -1},
		{filename: "many.dots.tar", ok: true, maxSize: -1},
		{filename: ".hidden-file.tar", ok: true, maxSize: -1},
		{filename: ".dotfile.many.tar", ok: true, maxSize: -1},
		{filename: "compressed.tar.gz", ok: true, maxSize: -1},
		{filename: "many.dots.tar.gz", ok: true, maxSize: -1},
		{filename: "compressed.tgz", ok: true, maxSize: -1},
		{filename: "bz2compressed.tar.bz2", ok: true, maxSize: -1},
		{filename: "many.dots.tar.bz2", ok: true, maxSize: -1},
		{filename: "bz2compressed.tbz2", ok: true, maxSize: -1},
		{filename: "unsupported.jpg", ok: false, maxSize: -1},
		{filename: "file.with.many.extensions", ok: false, maxSize: -1},
		{filename: "no-extension", ok: false, maxSize: -1},
		{filename: "", ok: false, maxSize: -1},
	}
	for _, tt := range tests {
		walkers := Walkers(99, StandardOpen)
		t.Run(tt.filename, func(t *testing.T) {
			_, maxSize, ok := walkers(tt.filename)
			assert.Equal(t, ok, tt.ok)
			if ok {
				assert.Equal(t, tt.maxSize, maxSize)
			}
		})
	}
}

func TestWalkersCanWalk(t *testing.T) {
	for _, tt := range []struct {
		extension []string
		example   string
	}{{
		extension: []string{".ear", ".jar", ".war", ".zip", ".par"},
		example:   "inside_a_dist/wrapped_log4j.zip",
	}, {
		extension: []string{".tar"},
		example:   "inside_a_dist/wrapped_log4j.tar",
	}, {
		extension: []string{".tar.gz", ".tgz"},
		example:   "inside_a_dist/wrapped_log4j.tar.gz",
	}, {
		extension: []string{".tar.bz2", ".tbz2"},
		example:   "inside_a_dist/wrapped_log4j.tar.bz2",
	}} {
		for _, extension := range tt.extension {
			walkers := Walkers(0, StandardOpen)
			t.Run("standard open file mode-"+extension, func(t *testing.T) {
				getWalker, _, ok := walkers(extension)
				require.True(t, ok)
				assertCanWalkExample(t, getWalker, tt.example)
			})
		}
		for _, extension := range tt.extension {
			walkers := Walkers(0, DirectIOOpen)
			t.Run("direct i/o open file mode-"+extension, func(t *testing.T) {
				getWalker, _, ok := walkers(extension)
				require.True(t, ok)
				assertCanWalkExample(t, getWalker, tt.example)
			})
		}
	}
}

func assertCanWalkExample(t *testing.T, getWalker WalkerProvider, example string) {
	t.Helper()
	walk, close, err := getWalker.FromFile(filepath.Join("../../examples", example))
	require.NoError(t, err)
	require.NoError(t, walk(context.Background(), func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
		return true, nil
	}))
	require.NoError(t, close())
}
