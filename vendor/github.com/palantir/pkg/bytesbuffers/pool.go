// Copyright (c) 2018 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bytesbuffers provides multiple implementations of a "byte buffer pool" allowing for reuse
// of preallocated memory in the form of a *bytes.Buffer.
//
// Example Usage: Marshal a JSON request body to a buffer, then put it back in the pool after the request.
//
//    pool := bytesbuffers.NewSyncPool(4)
//    var obj MyInput{}
//
//    buffer := pool.Get()
//    defer pool.Put(buffer)
//    _ = json.NewEncoder(buffer).Encode(obj)
//    _, _ = http.Post("http://localhost:1234", "application/json", buffer)
//
package bytesbuffers

import (
	"bytes"
	"sync"
)

// Pool is a type-safe interface for a pool of bytes buffers.
type Pool interface {
	// Get reset bytes buffer from the pool.
	Get() *bytes.Buffer
	// Put adds buf to the pool.
	Put(buf *bytes.Buffer)
}

// NewSyncPool uses the standard library's sync.Pool to store
// reusable bytes buffers until the next GC.
//
// This self-sizes based on the highest concurrent usage per GC period.
//
// Use this for spiky workloads.
func NewSyncPool(defaultBufferCapacity int64) Pool {
	return &syncPool{Pool: &sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, defaultBufferCapacity))
		},
	}}
}

type syncPool struct {
	Pool *sync.Pool
}

func (p *syncPool) Get() *bytes.Buffer {
	return p.Pool.Get().(*bytes.Buffer)
}

func (p *syncPool) Put(buf *bytes.Buffer) {
	buf.Reset()
	p.Pool.Put(buf)
}

// NewSizedPool stores (up to) a fixed size of released bytes buffers in the pool.
//
// Stored bytes buffers are not garbage collected until the reference to the pool is lost.
//
// Use this for steady high-volume workloads.
func NewSizedPool(poolCapacity, defaultBufferCapacity int) Pool {
	return &sizedPool{
		capacity:  poolCapacity,
		allocSize: defaultBufferCapacity,
		buffers:   make(chan *bytes.Buffer, poolCapacity),
	}
}

type sizedPool struct {
	allocSize int
	capacity  int
	buffers   chan *bytes.Buffer
}

func (p *sizedPool) Get() *bytes.Buffer {
	select {
	case b := <-p.buffers:
		// return existing buffer
		return b
	default:
		// no existing buffers, allocate a new one
		return bytes.NewBuffer(make([]byte, 0, p.allocSize))
	}
}

func (p *sizedPool) Put(b *bytes.Buffer) {
	b.Reset()
	select {
	case p.buffers <- b:
		// return to pool
	default:
		// discard, pool is already full
	}
}
