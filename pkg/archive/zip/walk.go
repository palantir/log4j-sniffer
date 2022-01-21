// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Copyright (c) 2022 Palantir Technologies. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"errors"
	"io"
	"os"
)

// WalkFn is called for every file in a zip.
// The file passed to is can be used during the duration of a callback and should
// not be held onto for use after the walk has been completed.
// WalkFn should return a bool for whether the walk of the zip should continue or not,
// along with an error for whether the walk for the given file was successful.
// If an error or false are returned, the walk will no longer proceed to subsequent files.
type WalkFn func(*File) (bool, error)

// WalkZipFile will open the Zip file specified by name and walk the contents of it,
// passing each *File encountered to the given WalkFn.
func WalkZipFile(name string, walkFn WalkFn) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r := new(ReadCloser)
	if err := r.walk(f, fi.Size(), walkFn); err != nil {
		_ = f.Close()
		return err
	}
	r.f = f
	return r.Close()
}

// WalkZipReaderAt will use the given ReaderAt, which is assumed to have the given size in bytes,
// walking the contents of it and passing each *File encountered to the given WalkFn.
func WalkZipReaderAt(r io.ReaderAt, size int64, walkFn WalkFn) error {
	if size < 0 {
		return errors.New("zip: size cannot be negative")
	}
	return (&Reader{}).walk(r, size, walkFn)
}
