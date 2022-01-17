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

package buffer

import (
	"io"
)

// IntermediateBufferReader implements an io.Reader that will read from a configured Reader into an intermediate buffer,
// populating bytes slices passed to the Read method from the intermediate buffer.
type IntermediateBufferReader struct {
	Reader      io.Reader
	ContentSize int64
	Buffer      []byte

	cursor              int
	bufferRangeLimit    int
	totalReadFromReader int64
	totalWritten        int64
}

// Read populates p from the internal buffer, reading from the internal reader to refill the buffer if all of the buffer's
// previous content has already been written out during previous calls to Read.
func (a *IntermediateBufferReader) Read(p []byte) (n int, err error) {
	if a.cursor == a.bufferRangeLimit {
		n, err := a.Reader.Read(a.Buffer)
		a.cursor = 0
		a.bufferRangeLimit = n
		a.totalReadFromReader += int64(n)
		if err != nil {
			if err == io.EOF && a.totalReadFromReader != a.ContentSize {
				// if EOF received but we are not at end of content, switch to ErrUnexpectedEOF
				return 0, io.ErrUnexpectedEOF
			} else if err != io.EOF {
				return 0, err
			}
		}
	}

	lenBufferToWrite := a.lenRemainingBufferToWrite()
	lenContentToWrite := a.lenRemainingContentToWrite()
	if lenContentToWrite <= int64(lenBufferToWrite) && lenContentToWrite <= int64(len(p)) {
		return copy(p, a.Buffer[a.cursor:a.cursor+int(lenContentToWrite)]), io.EOF
	}

	if lenBufferToWrite >= len(p) {
		n = copy(p, a.Buffer[a.cursor:a.cursor+len(p)])
	} else {
		n = copy(p, a.Buffer[a.bufferRangeLimit-lenBufferToWrite:a.bufferRangeLimit])
	}
	a.cursor += n
	a.totalWritten += int64(n)
	return n, nil
}

func (a *IntermediateBufferReader) lenRemainingBufferToWrite() int {
	return a.bufferRangeLimit - a.cursor
}

func (a *IntermediateBufferReader) lenRemainingContentToWrite() int64 {
	return a.ContentSize - a.totalWritten
}
