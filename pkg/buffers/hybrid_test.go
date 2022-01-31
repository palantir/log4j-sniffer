package buffers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	t.Run("writes nothing", func(t *testing.T) {
		buf := NewHybridBuffer(10)
		n, err := buf.Write(nil)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("writes up to buffer size into buffer", func(t *testing.T) {
		buf := NewHybridBuffer(10)
		n, err := buf.Write(make([]byte, 10))
		require.NoError(t, err)
		assert.Equal(t, 10, n)
	})

	t.Run("can read at from in-memory buffer", func(t *testing.T) {
		buf := NewHybridBuffer(10)
		content := make([]byte, 10)
		for i := 0; i < 10; i++ {
			content[i] = byte(i)
		}
		n, err := buf.Write(content)
		require.NoError(t, err)
		assert.Equal(t, 10, n)

		readBytes := make([]byte, 3)
		n, err = buf.ReadAt(readBytes, 3)
		require.NoError(t, err)
		assert.Equal(t, []byte{3, 4, 5}, readBytes)
	})

	t.Run("can write more than max memory amount", func(t *testing.T) {
		buf := NewHybridBuffer(2)
		content := make([]byte, 6)
		for i := 0; i < 6; i++ {
			content[i] = byte(i)
		}
		n, err := buf.Write(content)
		require.NoError(t, err)
		assert.Equal(t, 6, n)

		readBytes := make([]byte, 2)
		n, err = buf.ReadAt(readBytes, 0)
		require.NoError(t, err)
		assert.Equal(t, []byte{0, 1}, readBytes)

		readBytes = make([]byte, 2)
		n, err = buf.ReadAt(readBytes, 2)
		require.NoError(t, err)
		assert.Equal(t, []byte{2, 3}, readBytes)

		readBytes = make([]byte, 2)
		n, err = buf.ReadAt(readBytes, 1)
		require.NoError(t, err)
		assert.Equal(t, []byte{1, 2}, readBytes)
	})

	t.Run("can write more than max memory amount", func(t *testing.T) {
		buf := NewHybridBuffer(3)
		content := make([]byte, 6)
		for i := 0; i < 6; i++ {
			content[i] = byte(i)
		}
		n, err := buf.Write(content)
		require.NoError(t, err)
		assert.Equal(t, 6, n)

		readBytes := make([]byte, 2)
		n, err = buf.ReadAt(readBytes, 0)
		require.NoError(t, err)
		assert.Equal(t, []byte{0, 1}, readBytes)

		readBytes = make([]byte, 2)
		n, err = buf.ReadAt(readBytes, 2)
		require.NoError(t, err)
		assert.Equal(t, []byte{2, 3}, readBytes)

		readBytes = make([]byte, 4)
		n, err = buf.ReadAt(readBytes, 1)
		require.NoError(t, err)
		assert.Equal(t, []byte{1, 2, 3, 4}, readBytes)
	})
}
