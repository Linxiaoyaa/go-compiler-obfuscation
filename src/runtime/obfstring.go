// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "unsafe"

// String v2 uses separate decoder bodies selected from the function/literal
// domain. There is no shared plaintext-producing implementation that covers
// every protected literal in the process.

type obfStringKeyV2 [4]uint64

const (
	obfStringV3HeaderSize = uintptr(16)
	obfStringV3Cookie     = uintptr(0x9e3779b97f4a7c15)
)

type obfStringHeaderV3 struct {
	length uintptr
	cookie uintptr
}

func obfStringAllocV3(src *byte, n int, key *obfStringKeyV2, decoder uint8) (*byte, int) {
	if n <= 0 {
		return nil, 0
	}
	// Stay out of the tiny allocator so the finalizer is tied to this
	// plaintext allocation rather than a shared allocation slot.
	allocationSize := obfStringV3HeaderSize + uintptr(n)
	if allocationSize < maxTinySize {
		allocationSize = maxTinySize
	}
	p := mallocgc(allocationSize, nil, false)
	header := (*obfStringHeaderV3)(p)
	header.length = uintptr(n)
	header.cookie = uintptr(n) ^ obfStringV3Cookie
	data := add(p, obfStringV3HeaderSize)
	dst := unsafe.Slice((*byte)(data), n)
	srcp := unsafe.Pointer(src)
	for i := 0; i < n; i++ {
		dst[i] = *(*byte)(add(srcp, uintptr(i))) ^ obfStringMaskV3(*key, decoder, i)
	}
	SetFinalizer(header, obfStringFinalizeV3)
	obfStringWipeV2(key)
	return (*byte)(data), n
}

func obfStringMaskV3(key obfStringKeyV2, decoder uint8, offset int) byte {
	i := uint64(offset)
	a, b, c, d := key[0], key[1], key[2], key[3]
	var x uint64
	switch decoder & 3 {
	case 0:
		x = a + i*0x9e3779b97f4a7c15
		x ^= rotateObf64(b^i, uint(i&63))
		x += c ^ (d + i*0xd1b54a32d192ed03)
	case 1:
		x = b + i*0xd1b54a32d192ed03
		x ^= rotateObf64(c+i, uint((i+17)&63))
		x += d ^ (a + i*0x9e3779b97f4a7c15)
	case 2:
		x = c + i*0x94d049bb133111eb
		x ^= rotateObf64(d^i, uint((i+31)&63))
		x += a ^ (b + i*0xbf58476d1ce4e5b9)
	default:
		x = d + i*0xbf58476d1ce4e5b9
		x ^= rotateObf64(a+i, uint((i+47)&63))
		x += b ^ (c + i*0x94d049bb133111eb)
	}
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return byte(x >> uint((i&7)*8))
}

//go:noinline
func obfStringDataV3A(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	key := obfStringKeyV2{k0, k1, k2, k3}
	return obfStringAllocV3(src, n, &key, 0)
}

//go:noinline
func obfStringDataV3B(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	key := obfStringKeyV2{k0, k1, k2, k3}
	return obfStringAllocV3(src, n, &key, 1)
}

//go:noinline
func obfStringDataV3C(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	key := obfStringKeyV2{k0, k1, k2, k3}
	return obfStringAllocV3(src, n, &key, 2)
}

//go:noinline
func obfStringDataV3D(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	key := obfStringKeyV2{k0, k1, k2, k3}
	return obfStringAllocV3(src, n, &key, 3)
}

//go:noinline
func obfStringWipeV3(ptr *byte, n int) {
	if ptr == nil || n <= 0 {
		return
	}
	header := (*obfStringHeaderV3)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) - obfStringV3HeaderSize))
	if header.length != uintptr(n) || header.cookie != (uintptr(n)^obfStringV3Cookie) {
		return
	}
	SetFinalizer(header, nil)
	memclrNoHeapPointers(unsafe.Pointer(ptr), uintptr(n))
	header.length = 0
	header.cookie = 0
	KeepAlive(ptr)
}

func obfStringFinalizeV3(header *obfStringHeaderV3) {
	if header == nil || header.cookie != (header.length^obfStringV3Cookie) || header.length == 0 {
		return
	}
	memclrNoHeapPointers(add(unsafe.Pointer(header), obfStringV3HeaderSize), header.length)
	header.length = 0
	header.cookie = 0
}

// String v4 keeps only ciphertext in the string header emitted by the
// compiler. The token calls preserve the existing string ABI while carrying
// the ciphertext pointer, length, key lanes, and decoder choice into the SSA
// stream rewrite. No token call decodes or allocates a complete plaintext.

//go:noinline
func obfStringTokenV4A(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	return obfStringTokenV4(src, n, k0, k1, k2, k3, 0)
}

//go:noinline
func obfStringTokenV4B(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	return obfStringTokenV4(src, n, k0, k1, k2, k3, 1)
}

//go:noinline
func obfStringTokenV4C(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	return obfStringTokenV4(src, n, k0, k1, k2, k3, 2)
}

//go:noinline
func obfStringTokenV4D(src *byte, n int, k0, k1, k2, k3 uint64) (*byte, int) {
	return obfStringTokenV4(src, n, k0, k1, k2, k3, 3)
}

func obfStringTokenV4(src *byte, n int, k0, k1, k2, k3 uint64, decoder uint8) (*byte, int) {
	if n <= 0 {
		return nil, 0
	}
	if src == nil {
		throw("invalid protected string token")
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	// Keep every lane live through this boundary without creating a
	// plaintext-derived value. The unlikely sentinel also catches malformed
	// hand-crafted token invocations before a byte decoder reaches memory.
	if key[0]^key[1]^key[2]^key[3]^uint64(n)^uint64(decoder) == 0x7ac4b5d93e102f61 {
		throw("invalid protected string token")
	}
	obfStringWipeV2(&key)
	return src, n
}

//go:noinline
func obfStringByteV4A(src *byte, n, index int, k0, k1, k2, k3 uint64) byte {
	return obfStringByteV4(src, n, index, k0, k1, k2, k3, 0)
}

//go:noinline
func obfStringByteV4B(src *byte, n, index int, k0, k1, k2, k3 uint64) byte {
	return obfStringByteV4(src, n, index, k0, k1, k2, k3, 1)
}

//go:noinline
func obfStringByteV4C(src *byte, n, index int, k0, k1, k2, k3 uint64) byte {
	return obfStringByteV4(src, n, index, k0, k1, k2, k3, 2)
}

//go:noinline
func obfStringByteV4D(src *byte, n, index int, k0, k1, k2, k3 uint64) byte {
	return obfStringByteV4(src, n, index, k0, k1, k2, k3, 3)
}

func obfStringByteV4(src *byte, n, index int, k0, k1, k2, k3 uint64, decoder uint8) byte {
	if src == nil || n <= 0 || index < 0 || index >= n {
		throw("protected string byte index out of range")
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	value := *(*byte)(add(unsafe.Pointer(src), uintptr(index))) ^ obfStringMaskV3(key, decoder, index)
	obfStringWipeV2(&key)
	return value
}

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
