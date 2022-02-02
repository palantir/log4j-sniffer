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
)

// WalkCloser iterates through an archive when Walk is called, calling FileWalkFn on each member file.
type WalkCloser interface {
	Walk(ctx context.Context, walkFn FileWalkFn) error
	io.Closer
}

// FileWalkFn is called by a WalkFn on each file contained in an archive.
type FileWalkFn func(ctx context.Context, path string, size int64, contents io.Reader) (proceed bool, err error)

type walkCloser struct {
	walk  func(ctx context.Context, walkFn FileWalkFn) error
	close func() error
}

func (w walkCloser) Walk(ctx context.Context, walkFn FileWalkFn) error {
	return w.walk(ctx, walkFn)
}

func (w walkCloser) Close() error {
	if w.close != nil {
		return w.close()
	}
	return nil
}
