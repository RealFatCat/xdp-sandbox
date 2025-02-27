package main

import (
	"container/ring"
	"slices"
	"sync"
)

type procTimeRingBuffer[T uint32] struct {
	mu sync.RWMutex
	rb *ring.Ring
}

func newProcTimeRingBuffer[T uint32](n int) *procTimeRingBuffer[T] {
	rb := ring.New(n)

	var val uint32
	rbLen := rb.Len()
	for i := 0; i < rbLen; i++ {
		rb.Value = val
		rb = rb.Next()
	}
	return &procTimeRingBuffer[T]{
		rb: rb,
	}
}

func (rb *procTimeRingBuffer[T]) Add(v T) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.rb.Value = v
	rb.rb = rb.rb.Next()
}

func (rb *procTimeRingBuffer[T]) Avg() float32 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	var pt T
	rb.rb.Do(func(v any) {
		pt += v.(T)
	})

	return float32(pt) / float32(rb.rb.Len())
}

func (rb *procTimeRingBuffer[T]) Perc(p float32) T {
	if p <= 0 {
		p = 0.1
	}
	if p > 1 {
		p = 1
	}

	rb.mu.RLock()
	defer rb.mu.RUnlock()

	vals := make([]T, 0, rb.rb.Len())
	rb.rb.Do(func(v any) {
		vals = append(vals, v.(T))
	})

	slices.Sort(vals)
	idx := int(float32(rb.rb.Len()) * p)
	return vals[idx]

}
