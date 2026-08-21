// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"bytes"
	"runtime"
	"testing"
)

func TestObfStringDataV2Variants(t *testing.T) {
	plain := []byte("string-v2-runtime-cross-check")
	lanes := [4]uint64{
		0x0123456789abcdef,
		0xfedcba9876543210,
		0x0f1e2d3c4b5a6978,
		0x8877665544332211,
	}
	for decoder := 0; decoder < 4; decoder++ {
		ciphertext := make([]byte, len(plain))
		for i := range ciphertext {
			ciphertext[i] = plain[i] ^ obfStringMaskForTest(lanes, uint8(decoder), i)
		}
		got := runtime.ObfStringDataV2ForTest(uint8(decoder), ciphertext, lanes)
		if !bytes.Equal(got, plain) {
			t.Fatalf("decoder %d returned %q; want %q", decoder, got, plain)
		}
	}
}

func TestObfStringDataV2Empty(t *testing.T) {
	if got := runtime.ObfStringDataV2ForTest(0, nil, [4]uint64{1, 2, 3, 4}); got != nil {
		t.Fatalf("empty decode = %v; want nil", got)
	}
}

func TestObfStringDataV3ExplicitWipe(t *testing.T) {
	plain := []byte("string-v3-ephemeral-wipe")
	lanes := [4]uint64{0x1234, 0x5678, 0x9abc, 0xdef0}
	for decoder := 0; decoder < 4; decoder++ {
		ciphertext := make([]byte, len(plain))
		for i := range ciphertext {
			ciphertext[i] = plain[i] ^ obfStringMaskForTest(lanes, uint8(decoder), i)
		}
		before, after := runtime.ObfStringDataV3ForTest(uint8(decoder), ciphertext, lanes)
		if !bytes.Equal(before, plain) {
			t.Fatalf("decoder %d before wipe = %q; want %q", decoder, before, plain)
		}
		if !bytes.Equal(after, make([]byte, len(after))) {
			t.Fatalf("decoder %d retained plaintext bytes after wipe: %x", decoder, after)
		}
	}
}

func obfStringMaskForTest(lanes [4]uint64, decoder uint8, index int) byte {
	i := uint64(index)
	a, b, c, d := lanes[0], lanes[1], lanes[2], lanes[3]
	var x uint64
	switch decoder & 3 {
	case 0:
		x = a + i*0x9e3779b97f4a7c15
		x ^= rotateObf64Test(b^i, uint(i&63))
		x += c ^ (d + i*0xd1b54a32d192ed03)
	case 1:
		x = b + i*0xd1b54a32d192ed03
		x ^= rotateObf64Test(c+i, uint((i+17)&63))
		x += d ^ (a + i*0x9e3779b97f4a7c15)
	case 2:
		x = c + i*0x94d049bb133111eb
		x ^= rotateObf64Test(d^i, uint((i+31)&63))
		x += a ^ (b + i*0xbf58476d1ce4e5b9)
	default:
		x = d + i*0xbf58476d1ce4e5b9
		x ^= rotateObf64Test(a+i, uint((i+47)&63))
		x += b ^ (c + i*0x94d049bb133111eb)
	}
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return byte(x >> uint((i&7)*8))
}

func rotateObf64Test(x uint64, n uint) uint64 {
	if n == 0 {
		return x
	}
	return x<<n | x>>(64-n)
}
