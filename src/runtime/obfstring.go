// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "unsafe"

// String v2 uses separate decoder bodies selected from the function/literal
// domain. There is no shared plaintext-producing implementation that covers
// every protected literal in the process.

type obfStringKeyV2 [4]uint64

//go:noinline
func obfStringDataV2A(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	if n <= 0 {
		return nil, 0
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	p := mallocgc(uintptr(n), nil, false)
	dst := unsafe.Slice((*byte)(p), n)
	srcp := unsafe.Pointer(src)
	for i := 0; i < n; i++ {
		index := uint64(i)
		x := key[0] + index*0x9e3779b97f4a7c15
		x ^= rotateObf64(key[1]^index, uint(index&63))
		x += key[2] ^ (key[3] + index*0xd1b54a32d192ed03)
		x = mixObfStringV2(x)
		dst[i] = *(*byte)(add(srcp, uintptr(i))) ^ byte(x>>uint((index&7)*8))
	}
	obfStringWipeV2(&key)
	return (*byte)(p), n
}

//go:noinline
func obfStringDataV2B(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	if n <= 0 {
		return nil, 0
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	p := mallocgc(uintptr(n), nil, false)
	dst := unsafe.Slice((*byte)(p), n)
	srcp := unsafe.Pointer(src)
	for i := 0; i < n; i++ {
		index := uint64(i)
		x := key[1] + index*0xd1b54a32d192ed03
		x ^= rotateObf64(key[2]+index, uint((index+17)&63))
		x += key[3] ^ (key[0] + index*0x9e3779b97f4a7c15)
		x = mixObfStringV2(x)
		dst[i] = *(*byte)(add(srcp, uintptr(i))) ^ byte(x>>uint((index&7)*8))
	}
	obfStringWipeV2(&key)
	return (*byte)(p), n
}

//go:noinline
func obfStringDataV2C(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	if n <= 0 {
		return nil, 0
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	p := mallocgc(uintptr(n), nil, false)
	dst := unsafe.Slice((*byte)(p), n)
	srcp := unsafe.Pointer(src)
	for i := 0; i < n; i++ {
		index := uint64(i)
		x := key[2] + index*0x94d049bb133111eb
		x ^= rotateObf64(key[3]^index, uint((index+31)&63))
		x += key[0] ^ (key[1] + index*0xbf58476d1ce4e5b9)
		x = mixObfStringV2(x)
		dst[i] = *(*byte)(add(srcp, uintptr(i))) ^ byte(x>>uint((index&7)*8))
	}
	obfStringWipeV2(&key)
	return (*byte)(p), n
}

//go:noinline
func obfStringDataV2D(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	if n <= 0 {
		return nil, 0
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	p := mallocgc(uintptr(n), nil, false)
	dst := unsafe.Slice((*byte)(p), n)
	srcp := unsafe.Pointer(src)
	for i := 0; i < n; i++ {
		index := uint64(i)
		x := key[3] + index*0xbf58476d1ce4e5b9
		x ^= rotateObf64(key[0]+index, uint((index+47)&63))
		x += key[1] ^ (key[2] + index*0x94d049bb133111eb)
		x = mixObfStringV2(x)
		dst[i] = *(*byte)(add(srcp, uintptr(i))) ^ byte(x>>uint((index&7)*8))
	}
	obfStringWipeV2(&key)
	return (*byte)(p), n
}

func mixObfStringV2(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func rotateObf64(x uint64, n uint) uint64 {
	if n == 0 {
		return x
	}
	return x<<n | x>>(64-n)
}

//go:noinline
func obfStringWipeV2(key *obfStringKeyV2) {
	for i := range key {
		key[i] = 0
	}
}
