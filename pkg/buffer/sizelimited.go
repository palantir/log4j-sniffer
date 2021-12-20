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

package buffer

import (
	"bytes"
)

func NewSizeLimitedBuffer(limit int) SizeLimitedBuffer {
	return SizeLimitedBuffer{limit: limit}
}

type SizeLimitedBuffer struct {
	limit   int
	written int
	buffer  bytes.Buffer
}

func (c *SizeLimitedBuffer) Write(p []byte) (int, error) {
	if len(p)+c.written > c.limit {
		return 0, WriteTooLargeError(c.limit)
	}
	n, err := c.buffer.Write(p)
	c.written += n
	return n, err
}

func (c *SizeLimitedBuffer) Bytes() []byte {
	return c.buffer.Bytes()
}
