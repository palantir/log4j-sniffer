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
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"

	"github.com/palantir/log4j-sniffer/pkg/buffer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupportedExtensions(t *testing.T) {
	tests := []struct {
		filename string
		ok       bool
	}{
		{filename: "filename.zip", ok: true},
		{filename: "fat_jar.jar", ok: true},
		{filename: "many.dots.with.jar", ok: true},
		{filename: ".dotfile.jar", ok: true},
		{filename: "par_file.par", ok: true},
		{filename: "generic.tar", ok: true},
		{filename: "many.dots.tar", ok: true},
		{filename: ".hidden-file.tar", ok: true},
		{filename: ".dotfile.many.tar", ok: true},
		{filename: "compressed.tar.gz", ok: true},
		{filename: "many.dots.tar.gz", ok: true},
		{filename: "compressed.tgz", ok: true},
		{filename: "bz2compressed.tar.bz2", ok: true},
		{filename: "many.dots.tar.bz2", ok: true},
		{filename: "bz2compressed.tbz2", ok: true},
		{filename: "unsupported.jpg", ok: false},
		{filename: "file.with.many.extensions", ok: false},
		{filename: "no-extension", ok: false},
		{filename: "", ok: false},
	}

	expectedReaderAtErr := errors.New("err")
	walkers := Walkers(buffer.ReaderReaderAtConverterFunc(func(r io.Reader, contentSize int64) (io.ReaderAt, buffer.CloseFn, error) {
		return nil, nil, expectedReaderAtErr
	}), StandardOpen)

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			_, ok := walkers(tt.filename)
			assert.Equal(t, ok, tt.ok)
		})
	}
}

func TestWalkersCanWalk(t *testing.T) {
	for _, tt := range []struct {
		extension []string
		example   string
		readerAt  bool
	}{{
		extension: []string{".ear", ".jar", ".war", ".zip", ".par"},
		example:   "inside_a_dist/wrapped_log4j.zip",
		readerAt:  true,
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
			walkers := Walkers(nil, StandardOpen)
			t.Run("standard open file mode-"+extension, func(t *testing.T) {
				getWalker, ok := walkers(extension)
				require.True(t, ok)
				assertCanWalkExampleFile(t, getWalker, tt.example)
			})
		}
		for _, extension := range tt.extension {
			walkers := Walkers(nil, DirectIOOpen)
			t.Run("direct i/o open file mode-"+extension, func(t *testing.T) {
				getWalker, ok := walkers(extension)
				require.True(t, ok)
				assertCanWalkExampleFile(t, getWalker, tt.example)
			})
		}
		for _, extension := range tt.extension {
			if tt.readerAt {
				t.Run("should pass reader args and return error when creating a reader at", func(t *testing.T) {
					expectedErr := errors.New("err")
					walkers := Walkers(buffer.ReaderReaderAtConverterFunc(func(r io.Reader, contentSize int64) (io.ReaderAt, buffer.CloseFn, error) {
						assert.EqualValues(t, contentSize, 99)
						assert.NoError(t, iotest.TestReader(r, []byte("foo")))
						return nil, nil, expectedErr
					}), DirectIOOpen)
					getWalker, ok := walkers(extension)
					require.True(t, ok)
					_, err := getWalker.FromReader(bytes.NewBufferString("foo"), 99)
					assert.Equal(t, expectedErr, err)
				})

				t.Run("should attempt reader at creation", func(t *testing.T) {
					path := examplePath(tt.example)
					f, err := os.Open(path)
					require.NoError(t, err)
					stat, err := os.Stat(path)
					require.NoError(t, err)

					var called bool
					// fake creating a ReaderAt by actually just providing the example file
					walkers := Walkers(buffer.ReaderReaderAtConverterFunc(func(io.Reader, int64) (io.ReaderAt, buffer.CloseFn, error) {
						called = true
						return f, f.Close, nil
					}), DirectIOOpen)
					getWalker, ok := walkers(extension)
					require.True(t, ok)

					walker, err := getWalker.FromReader(nil, stat.Size())
					assert.True(t, called)
					require.NoError(t, err)
					assertCanWalk(t, walker)
				})
			} else {
				t.Run("should read directly from provided reader", func(t *testing.T) {
					walkers := Walkers(nil, DirectIOOpen)
					getWalker, ok := walkers(extension)
					require.True(t, ok)

					path := examplePath(tt.example)
					f, err := os.Open(path)
					require.NoError(t, err)
					defer func() { assert.NoError(t, f.Close()) }()
					walker, err := getWalker.FromReader(f, 0) // size ignored for stream reading archives, such as tars
					require.NoError(t, err)
					assertCanWalk(t, walker)
				})
			}
		}
	}
}

func assertCanWalkExampleFile(t *testing.T, getWalker WalkerProvider, example string) {
	t.Helper()
	walker, err := getWalker.FromFile(examplePath(example))
	require.NoError(t, err)
	assertCanWalk(t, walker)
}

func assertCanWalk(t *testing.T, walker WalkCloser) {
	t.Helper()
	require.NoError(t, walker.Walk(context.Background(), func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error) {
		return true, nil
	}))
	require.NoError(t, walker.Close())
}

func examplePath(example string) string {
	return filepath.Join("../../examples", example)
}
