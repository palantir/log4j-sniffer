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

package archive

import (
	"os"

	"github.com/ncw/directio"
	"github.com/palantir/log4j-sniffer/pkg/buffer"
)

// FileOpenMode is the behaviour used when opening a file on disk.
type FileOpenMode bool

const (
	// StandardOpen opens files using read only flags.
	StandardOpen FileOpenMode = false
	// DirectIOOpen opens files using flags that allow for direct i/o, skipping filesystem cache.
	DirectIOOpen FileOpenMode = true
)

func standardOpenFileWalker(getWalkFn ReaderWalkerProviderFunc) func(path string) (WalkFn, func() error, error) {
	return func(path string) (WalkFn, func() error, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		walkFn, closeWalker, err := getWalkFn(f)
		if err != nil {
			_ = f.Close()
			return nil, nil, err
		}

		return walkFn, func() error {
			wErr := closeWalker()
			fErr := f.Close()
			if fErr != nil {
				return fErr
			}
			return wErr
		}, nil
	}
}

func directIOOpenFileWalker(reader ReaderWalkerProviderFunc) func(path string) (WalkFn, func() error, error) {
	return func(path string) (WalkFn, func() error, error) {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, nil, err
		}

		var f *os.File
		var walkFn WalkFn
		var closeWalker func() error
		if stat.Size() < directio.BlockSize {
			f, err = os.Open(path)
			if err != nil {
				return nil, nil, err
			}
			walkFn, closeWalker, err = reader(f)
		} else {
			f, err = directio.OpenFile(path, os.O_RDONLY, 0)
			if err != nil {
				return nil, nil, err
			}
			walkFn, closeWalker, err = reader(&buffer.IntermediateBufferReader{
				Reader:      f,
				ContentSize: stat.Size(),
				Buffer:      directio.AlignedBlock(32768),
			})
		}
		if err != nil {
			_ = f.Close()
			return nil, nil, err
		}

		return walkFn, func() error {
			wErr := closeWalker()
			fErr := f.Close()
			if fErr != nil {
				return fErr
			}
			return wErr
		}, nil
	}
}
