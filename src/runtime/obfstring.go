// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "unsafe"

// obfStringData decodes an encrypted literal directly into its final
// heap-backed byte storage. It returns the data pointer and length separately
// so the compiler can construct a string header without a second copy.
//
//go:noinline
func obfStringData(src *byte, n int, key uint64) (*byte, int) {
	if n <= 0 {
		return nil, 0
	}
	p := mallocgc(uintptr(n), nil, false)
	dst := unsafe.Slice((*byte)(p), n)
	srcp := unsafe.Pointer(src)
	for i := 0; i < n; i++ {
		x := key + uint64(i)*0x9e3779b97f4a7c15
		x ^= x >> 30
		x *= 0xbf58476d1ce4e5b9
		x ^= x >> 27
		x *= 0x94d049bb133111eb
		x ^= x >> 31
		dst[i] = *(*byte)(add(srcp, uintptr(i))) ^ byte(x>>uint((i&7)*8))
	}
	return (*byte)(p), n
}
