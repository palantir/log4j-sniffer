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

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests that involve both reading and writing.

package zip

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestOver65kFiles(t *testing.T) {
	buf := new(bytes.Buffer)

	w := zip.NewWriter(buf)
	const nFiles = (1 << 16) + 42
	for i := 0; i < nFiles; i++ {
		_, err := w.CreateHeader(&zip.FileHeader{
			Name:   fmt.Sprintf("%d.dat", i),
			Method: Store, // avoid Issue 6136 and Issue 6138
		})
		if err != nil {
			t.Fatalf("creating file %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Writer.Close: %v", err)
	}
	s := buf.String()
	err := WalkZipReaderAt(strings.NewReader(s), int64(len(s)), func(file *File) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("WalkZipReaderAt: %v", err)
	}
}

func TestModTime(t *testing.T) {
	var testTime = time.Date(2009, time.November, 10, 23, 45, 58, 0, time.UTC)
	fh := new(FileHeader)
	fh.SetModTime(testTime)
	outTime := fh.ModTime()
	if !outTime.Equal(testTime) {
		t.Errorf("times don't match: got %s, want %s", outTime, testTime)
	}
}

func testHeaderRoundTrip(fh *FileHeader, wantUncompressedSize uint32, wantUncompressedSize64 uint64, t *testing.T) {
	fi := fh.FileInfo()
	fh2, err := FileInfoHeader(fi)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fh2.Name, fh.Name; got != want {
		t.Errorf("Name: got %s, want %s\n", got, want)
	}
	if got, want := fh2.UncompressedSize, wantUncompressedSize; got != want {
		t.Errorf("UncompressedSize: got %d, want %d\n", got, want)
	}
	if got, want := fh2.UncompressedSize64, wantUncompressedSize64; got != want {
		t.Errorf("UncompressedSize64: got %d, want %d\n", got, want)
	}
	if got, want := fh2.ModifiedTime, fh.ModifiedTime; got != want {
		t.Errorf("ModifiedTime: got %d, want %d\n", got, want)
	}
	if got, want := fh2.ModifiedDate, fh.ModifiedDate; got != want {
		t.Errorf("ModifiedDate: got %d, want %d\n", got, want)
	}

	if sysfh, ok := fi.Sys().(*FileHeader); !ok && sysfh != fh {
		t.Errorf("Sys didn't return original *FileHeader")
	}
}

func TestFileHeaderRoundTrip(t *testing.T) {
	fh := &FileHeader{
		Name:             "foo.txt",
		UncompressedSize: 987654321,
		ModifiedTime:     1234,
		ModifiedDate:     5678,
	}
	testHeaderRoundTrip(fh, fh.UncompressedSize, uint64(fh.UncompressedSize), t)
}

func TestFileHeaderRoundTrip64(t *testing.T) {
	fh := &FileHeader{
		Name:               "foo.txt",
		UncompressedSize64: 9876543210,
		ModifiedTime:       1234,
		ModifiedDate:       5678,
	}
	testHeaderRoundTrip(fh, uint32max, fh.UncompressedSize64, t)
}

func TestFileHeaderRoundTripModified(t *testing.T) {
	fh := &FileHeader{
		Name:             "foo.txt",
		UncompressedSize: 987654321,
		Modified:         time.Now().Local(),
		ModifiedTime:     1234,
		ModifiedDate:     5678,
	}
	fi := fh.FileInfo()
	fh2, err := FileInfoHeader(fi)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fh2.Modified, fh.Modified.UTC(); got != want {
		t.Errorf("Modified: got %s, want %s\n", got, want)
	}
	if got, want := fi.ModTime(), fh.Modified.UTC(); got != want {
		t.Errorf("Modified: got %s, want %s\n", got, want)
	}
}

func TestFileHeaderRoundTripWithoutModified(t *testing.T) {
	fh := &FileHeader{
		Name:             "foo.txt",
		UncompressedSize: 987654321,
		ModifiedTime:     1234,
		ModifiedDate:     5678,
	}
	fi := fh.FileInfo()
	fh2, err := FileInfoHeader(fi)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fh2.ModTime(), fh.ModTime(); got != want {
		t.Errorf("Modified: got %s, want %s\n", got, want)
	}
	if got, want := fi.ModTime(), fh.ModTime(); got != want {
		t.Errorf("Modified: got %s, want %s\n", got, want)
	}
}

type repeatedByte struct {
	off int64
	b   byte
	n   int64
}

// rleBuffer is a run-length-encoded byte buffer.
// It's an io.Writer (like a bytes.Buffer) and also an io.ReaderAt,
// allowing random-access reads.
type rleBuffer struct {
	buf []repeatedByte
}

func (r *rleBuffer) Size() int64 {
	if len(r.buf) == 0 {
		return 0
	}
	last := &r.buf[len(r.buf)-1]
	return last.off + last.n
}

func (r *rleBuffer) Write(p []byte) (n int, err error) {
	var rp *repeatedByte
	if len(r.buf) > 0 {
		rp = &r.buf[len(r.buf)-1]
		// Fast path, if p is entirely the same byte repeated.
		if lastByte := rp.b; len(p) > 0 && p[0] == lastByte {
			if bytes.Count(p, []byte{lastByte}) == len(p) {
				rp.n += int64(len(p))
				return len(p), nil
			}
		}
	}

	for _, b := range p {
		if rp == nil || rp.b != b {
			r.buf = append(r.buf, repeatedByte{r.Size(), b, 1})
			rp = &r.buf[len(r.buf)-1]
		} else {
			rp.n++
		}
	}
	return len(p), nil
}

func min(x, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

func memset(a []byte, b byte) {
	if len(a) == 0 {
		return
	}
	// Double, until we reach power of 2 >= len(a), same as bytes.Repeat,
	// but without allocation.
	a[0] = b
	for i, l := 1, len(a); i < l; i *= 2 {
		copy(a[i:], a[:i])
	}
}

func (r *rleBuffer) ReadAt(p []byte, off int64) (n int, err error) {
	if len(p) == 0 {
		return
	}
	skipParts := sort.Search(len(r.buf), func(i int) bool {
		part := &r.buf[i]
		return part.off+part.n > off
	})
	parts := r.buf[skipParts:]
	if len(parts) > 0 {
		skipBytes := off - parts[0].off
		for _, part := range parts {
			repeat := int(min(part.n-skipBytes, int64(len(p)-n)))
			memset(p[n:n+repeat], part.b)
			n += repeat
			if n == len(p) {
				return
			}
			skipBytes = 0
		}
	}
	if n != len(p) {
		err = io.ErrUnexpectedEOF
	}
	return
}

// Just testing the rleBuffer used in the Zip64 test above. Not used by the zip code.
func TestRLEBuffer(t *testing.T) {
	b := new(rleBuffer)
	var all []byte
	writes := []string{"abcdeee", "eeeeeee", "eeeefghaaiii"}
	for _, w := range writes {
		_, _ = b.Write([]byte(w))
		all = append(all, w...)
	}
	if len(b.buf) != 10 {
		t.Fatalf("len(b.buf) = %d; want 10", len(b.buf))
	}

	for i := 0; i < len(all); i++ {
		for j := 0; j < len(all)-i; j++ {
			buf := make([]byte, j)
			n, err := b.ReadAt(buf, int64(i))
			if err != nil || n != len(buf) {
				t.Errorf("ReadAt(%d, %d) = %d, %v; want %d, nil", i, j, n, err, len(buf))
			}
			if !bytes.Equal(buf, all[i:i+j]) {
				t.Errorf("ReadAt(%d, %d) = %q; want %q", i, j, buf, all[i:i+j])
			}
		}
	}
}

// fakeHash32 is a dummy Hash32 that always returns 0.
type fakeHash32 struct {
	hash.Hash32
}

func (fakeHash32) Write(p []byte) (int, error) { return len(p), nil }
func (fakeHash32) Sum32() uint32               { return 0 }

// suffixSaver is an io.Writer & io.ReaderAt that remembers the last 0
// to 'keep' bytes of data written to it. Call Suffix to get the
// suffix bytes.
type suffixSaver struct {
	keep  int
	buf   []byte
	start int
	size  int64
}

func (ss *suffixSaver) Size() int64 { return ss.size }

var errDiscardedBytes = errors.New("ReadAt of discarded bytes")

func (ss *suffixSaver) ReadAt(p []byte, off int64) (n int, err error) {
	back := ss.size - off
	if back > int64(ss.keep) {
		return 0, errDiscardedBytes
	}
	suf := ss.Suffix()
	n = copy(p, suf[len(suf)-int(back):])
	if n != len(p) {
		err = io.EOF
	}
	return
}

func (ss *suffixSaver) Suffix() []byte {
	if len(ss.buf) < ss.keep {
		return ss.buf
	}
	buf := make([]byte, ss.keep)
	n := copy(buf, ss.buf[ss.start:])
	copy(buf[n:], ss.buf[:])
	return buf
}

func (ss *suffixSaver) Write(p []byte) (n int, err error) {
	n = len(p)
	ss.size += int64(len(p))
	if len(ss.buf) < ss.keep {
		space := ss.keep - len(ss.buf)
		add := len(p)
		if add > space {
			add = space
		}
		ss.buf = append(ss.buf, p[:add]...)
		p = p[add:]
	}
	for len(p) > 0 {
		n := copy(ss.buf[ss.start:], p)
		p = p[n:]
		ss.start += n
		if ss.start == ss.keep {
			ss.start = 0
		}
	}
	return
}

type sizedReaderAt interface {
	io.ReaderAt
	Size() int64
}

func TestSuffixSaver(t *testing.T) {
	const keep = 10
	ss := &suffixSaver{keep: keep}
	_, _ = ss.Write([]byte("abc"))
	if got := string(ss.Suffix()); got != "abc" {
		t.Errorf("got = %q; want abc", got)
	}
	_, _ = ss.Write([]byte("defghijklmno"))
	if got := string(ss.Suffix()); got != "fghijklmno" {
		t.Errorf("got = %q; want fghijklmno", got)
	}
	if got, want := ss.Size(), int64(len("abc")+len("defghijklmno")); got != want {
		t.Errorf("Size = %d; want %d", got, want)
	}
	buf := make([]byte, ss.Size())
	for off := int64(0); off < ss.Size(); off++ {
		for size := 1; size <= int(ss.Size()-off); size++ {
			readBuf := buf[:size]
			n, err := ss.ReadAt(readBuf, off)
			if off < ss.Size()-keep {
				if err != errDiscardedBytes {
					t.Errorf("off %d, size %d = %v, %v (%q); want errDiscardedBytes", off, size, n, err, readBuf[:n])
				}
				continue
			}
			want := "abcdefghijklmno"[off : off+int64(size)]
			got := string(readBuf[:n])
			if err != nil || got != want {
				t.Errorf("off %d, size %d = %v, %v (%q); want %q", off, size, n, err, got, want)
			}
		}
	}
}
