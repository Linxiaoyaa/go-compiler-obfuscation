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

// String v5 keeps the String v4 no-plaintext representation, but adds an
// independently derived lease word to every token and byte decoder. The lease
// is scoped to a single decoder invocation and wiped with the temporary key
// schedule before the byte result crosses the runtime boundary.

//go:noinline
func obfStringTokenV5A(src *byte, n int, k0, k1, k2, k3, lease uint64) (*byte, int) {
	return obfStringTokenV5(src, n, k0, k1, k2, k3, lease, 0)
}

//go:noinline
func obfStringTokenV5B(src *byte, n int, k0, k1, k2, k3, lease uint64) (*byte, int) {
	return obfStringTokenV5(src, n, k0, k1, k2, k3, lease, 1)
}

//go:noinline
func obfStringTokenV5C(src *byte, n int, k0, k1, k2, k3, lease uint64) (*byte, int) {
	return obfStringTokenV5(src, n, k0, k1, k2, k3, lease, 2)
}

//go:noinline
func obfStringTokenV5D(src *byte, n int, k0, k1, k2, k3, lease uint64) (*byte, int) {
	return obfStringTokenV5(src, n, k0, k1, k2, k3, lease, 3)
}

func obfStringTokenV5(src *byte, n int, k0, k1, k2, k3, lease uint64, decoder uint8) (*byte, int) {
	if n <= 0 {
		return nil, 0
	}
	if src == nil || lease == 0 {
		throw("invalid protected string lease token")
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	if key[0]^key[1]^key[2]^key[3]^lease^uint64(n)^uint64(decoder) == 0x510e527fade682d1 {
		throw("invalid protected string lease token")
	}
	obfStringWipeV2(&key)
	obfStringWipeV5(&lease)
	return src, n
}

//go:noinline
func obfStringByteV5A(src *byte, n, index int, k0, k1, k2, k3, lease uint64) byte {
	return obfStringByteV5(src, n, index, k0, k1, k2, k3, lease, 0)
}

//go:noinline
func obfStringByteV5B(src *byte, n, index int, k0, k1, k2, k3, lease uint64) byte {
	return obfStringByteV5(src, n, index, k0, k1, k2, k3, lease, 1)
}

//go:noinline
func obfStringByteV5C(src *byte, n, index int, k0, k1, k2, k3, lease uint64) byte {
	return obfStringByteV5(src, n, index, k0, k1, k2, k3, lease, 2)
}

//go:noinline
func obfStringByteV5D(src *byte, n, index int, k0, k1, k2, k3, lease uint64) byte {
	return obfStringByteV5(src, n, index, k0, k1, k2, k3, lease, 3)
}

func obfStringByteV5(src *byte, n, index int, k0, k1, k2, k3, lease uint64, decoder uint8) byte {
	if src == nil || n <= 0 || index < 0 || index >= n || lease == 0 {
		throw("protected string lease byte index out of range")
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	value := *(*byte)(add(unsafe.Pointer(src), uintptr(index))) ^ obfStringMaskV5(key, lease, decoder, index)
	obfStringWipeV2(&key)
	obfStringWipeV5(&lease)
	return value
}

func obfStringMaskV5(key obfStringKeyV2, lease uint64, decoder uint8, index int) byte {
	i := uint64(index)
	x := lease ^ key[(uint64(decoder)+i)&3]
	x += i*0xd6e8feb86659fd93 + 0xa4093822299f31d0
	x ^= rotateObf64(key[(uint64(decoder)+i+1)&3]^lease, uint((i+uint64(decoder)*11)&63))
	x ^= x >> 29
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return obfStringMaskV3(key, decoder, index) ^ byte(x>>uint((i&7)*8))
}

//go:noinline
func obfStringWipeV5(lease *uint64) {
	*lease = 0
}

// String v6 extends the lease-bound stream decoder with an independently
// derived ticket. Both capability words are checked at the token boundary and
// every byte boundary, then wiped before the decoded byte can leave runtime.

//go:noinline
func obfStringTokenV6A(src *byte, n int, k0, k1, k2, k3, lease, ticket uint64) (*byte, int) {
	return obfStringTokenV6(src, n, k0, k1, k2, k3, lease, ticket, 0)
}

//go:noinline
func obfStringTokenV6B(src *byte, n int, k0, k1, k2, k3, lease, ticket uint64) (*byte, int) {
	return obfStringTokenV6(src, n, k0, k1, k2, k3, lease, ticket, 1)
}

//go:noinline
func obfStringTokenV6C(src *byte, n int, k0, k1, k2, k3, lease, ticket uint64) (*byte, int) {
	return obfStringTokenV6(src, n, k0, k1, k2, k3, lease, ticket, 2)
}

//go:noinline
func obfStringTokenV6D(src *byte, n int, k0, k1, k2, k3, lease, ticket uint64) (*byte, int) {
	return obfStringTokenV6(src, n, k0, k1, k2, k3, lease, ticket, 3)
}

func obfStringTokenV6(src *byte, n int, k0, k1, k2, k3, lease, ticket uint64, decoder uint8) (*byte, int) {
	if n <= 0 {
		return nil, 0
	}
	if src == nil || lease == 0 || ticket == 0 {
		throw("invalid protected string ticket token")
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	if key[0]^key[1]^key[2]^key[3]^lease^rotateObf64(ticket, uint(decoder*13))^uint64(n) == 0x9b05688c2b3e6c1f {
		throw("invalid protected string ticket token")
	}
	obfStringWipeV2(&key)
	obfStringWipeV5(&lease)
	obfStringWipeV6(&ticket)
	return src, n
}

//go:noinline
func obfStringByteV6A(src *byte, n, index int, k0, k1, k2, k3, lease, ticket uint64) byte {
	return obfStringByteV6(src, n, index, k0, k1, k2, k3, lease, ticket, 0)
}

//go:noinline
func obfStringByteV6B(src *byte, n, index int, k0, k1, k2, k3, lease, ticket uint64) byte {
	return obfStringByteV6(src, n, index, k0, k1, k2, k3, lease, ticket, 1)
}

//go:noinline
func obfStringByteV6C(src *byte, n, index int, k0, k1, k2, k3, lease, ticket uint64) byte {
	return obfStringByteV6(src, n, index, k0, k1, k2, k3, lease, ticket, 2)
}

//go:noinline
func obfStringByteV6D(src *byte, n, index int, k0, k1, k2, k3, lease, ticket uint64) byte {
	return obfStringByteV6(src, n, index, k0, k1, k2, k3, lease, ticket, 3)
}

func obfStringByteV6(src *byte, n, index int, k0, k1, k2, k3, lease, ticket uint64, decoder uint8) byte {
	if src == nil || n <= 0 || index < 0 || index >= n || lease == 0 || ticket == 0 {
		throw("protected string ticket byte index out of range")
	}
	key := obfStringKeyV2{k0, k1, k2, k3}
	value := *(*byte)(add(unsafe.Pointer(src), uintptr(index))) ^ obfStringMaskV6(key, lease, ticket, decoder, index)
	obfStringWipeV2(&key)
	obfStringWipeV5(&lease)
	obfStringWipeV6(&ticket)
	return value
}

func obfStringMaskV6(key obfStringKeyV2, lease, ticket uint64, decoder uint8, index int) byte {
	i := uint64(index)
	x := ticket ^ rotateObf64(lease, uint((i+uint64(decoder)*13)&63))
	x += key[(i+uint64(decoder)*3)&3] + i*0x9e3779b185ebca87
	x ^= rotateObf64(key[(i+uint64(decoder)+2)&3]^ticket, uint((i+29)&63))
	x ^= x >> 27
	x *= 0xd6e8feb86659fd93
	x ^= x >> 33
	return obfStringMaskV5(key, lease, decoder, index) ^ byte(x>>uint((i&7)*8))
}

//go:noinline
func obfStringWipeV6(ticket *uint64) {
	*ticket = 0
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
