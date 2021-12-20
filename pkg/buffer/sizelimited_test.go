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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSizeLimitedBuffer(t *testing.T) {
	t.Run("write over size of limit should error", func(t *testing.T) {
		buf := NewSizeLimitedBuffer(2)
		_, err := buf.Write(make([]byte, 3))
		require.Equal(t, WriteTooLargeError(2), err)
	})

	t.Run("write under limit should not error", func(t *testing.T) {
		buf := NewSizeLimitedBuffer(1)
		n, err := buf.Write(make([]byte, 1))
		require.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("subsequent writes that would exceed buffer should error", func(t *testing.T) {
		buf := NewSizeLimitedBuffer(1)
		n, err := buf.Write(make([]byte, 1))
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		_, err = buf.Write(make([]byte, 1))
		require.Equal(t, WriteTooLargeError(1), err)
	})
}
