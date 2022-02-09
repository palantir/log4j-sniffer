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

package buffer_test

import (
	"bytes"
	"errors"
	"io/ioutil"
	"testing"
	"testing/iotest"

	"github.com/palantir/log4j-sniffer/pkg/buffer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntermediateBufferReader_ReadingAllContentFromReader(t *testing.T) {
	t.Run("should error on read error when populating buffer", func(t *testing.T) {
		expectedErr := errors.New("err")
		_, err := ioutil.ReadAll(&buffer.IntermediateBufferReader{
			Reader:      iotest.ErrReader(expectedErr),
			ContentSize: 1,
			Buffer:      make([]byte, 5, 5),
		})
		assert.Equal(t, expectedErr, err)
	})

	for _, tc := range []struct {
		name                   string
		content                string
		intermediateBufferSize int
	}{{
		name: "empty content, zero sized buffer",
	}, {
		name:                   "empty content, non-zero sized buffer buffer",
		intermediateBufferSize: 7,
	}, {
		name:                   "content less than buffer size",
		content:                "012",
		intermediateBufferSize: 7,
	}, {
		name:                   "content length 1 byte less than buffer size",
		content:                "012345",
		intermediateBufferSize: 7,
	}, {
		name:                   "content equal to size",
		content:                "0123456",
		intermediateBufferSize: 7,
	}, {
		name:                   "content length 1 byte greater than buffer size",
		content:                "01234567",
		intermediateBufferSize: 7,
	}, {
		name:                   "content larger than buffer size",
		content:                "01234567",
		intermediateBufferSize: 7,
	}, {
		name:                   "content multiple times larger than buffer size",
		content:                "012345678901234567890123456789",
		intermediateBufferSize: 7,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			r := buffer.IntermediateBufferReader{
				Buffer:      make([]byte, tc.intermediateBufferSize, tc.intermediateBufferSize),
				Reader:      bytes.NewBufferString(tc.content),
				ContentSize: int64(len(tc.content)),
			}
			readContent, err := ioutil.ReadAll(&r)
			require.NoError(t, err)
			assert.Equal(t, tc.content, string(readContent))
		})
	}

	t.Run("should read end content on short reads", func(t *testing.T) {
		// stubbed reader will only populate first 3 bytes of the 5 byte buffer,
		// giving us situation where only part of the buffer is active
		bs, err := ioutil.ReadAll(&buffer.IntermediateBufferReader{
			Reader:      stubbedReader("012"),
			ContentSize: 4,
			Buffer:      make([]byte, 5, 5),
		})
		require.NoError(t, err)
		assert.Equal(t, "0120", string(bs))
	})
}

type stubbedReader string

func (s stubbedReader) Read(p []byte) (n int, err error) {
	return copy(p, s), nil
}
