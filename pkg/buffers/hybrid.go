package buffers

import (
	"bytes"
	"os"
	"sync"
)

func NewHybridBuffer(memorySize int64) *HybridBuffer {
	return &HybridBuffer{
		maxMemorySize: memorySize,
	}
}

type HybridBuffer struct {
	memory        bytes.Buffer
	maxMemorySize int64

	otherOnce sync.Once
	// when do we close this?
	other *os.File
}

// how to handle that once started reading, the buffer cannot be written to again?
// maybe we have a method ReaderAt, that creates a readerat
func (h *HybridBuffer) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= h.maxMemorySize {
		return h.other.ReadAt(p, off-h.maxMemorySize)
	}
	if off+int64(len(p)) > h.maxMemorySize {
		n, err := bytes.NewReader(h.memory.Bytes()).ReadAt(p[:h.maxMemorySize-off], off)
		if err != nil {
			return n, err
		}
		otherN, err := h.other.ReadAt(p[h.maxMemorySize-off:], 0)
		return n + otherN, err
	}
	// don't create this everytime
	return bytes.NewReader(h.memory.Bytes()).ReadAt(p, off)
}

func (h *HybridBuffer) Write(p []byte) (n int, err error) {
	if int64(len(p)) > h.maxMemorySize {
		n, err := h.memory.Write(p[:h.maxMemorySize])
		if err != nil {
			return n, err
		}
		var otherErr error
		h.otherOnce.Do(func() {
			h.other, otherErr = os.CreateTemp("", "")
		})
		if otherErr != nil {
			return n, err
		}
		otherN, err := h.other.Write(p[h.maxMemorySize:])
		return n + otherN, err
	}
	return h.memory.Write(p)
}
