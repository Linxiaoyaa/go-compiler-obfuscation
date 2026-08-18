// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package staticdata

import (
	"hash/fnv"

	"cmd/internal/obj"
	"cmd/internal/src"
)

// ObfuscatedStringSym emits an encrypted backing symbol for a string literal
// and returns the key used by runtime.obfStringData to decode it. The function
// name and compiler seed are part of the key so identical literals in marked
// functions do not share plaintext or ciphertext across protection domains.
func ObfuscatedStringSym(pos src.XPos, functionName, seed, text string) (*obj.LSym, uint64) {
	key := obfuscatedStringKey(functionName, seed, text)
	ciphertext := make([]byte, len(text))
	for i := range ciphertext {
		ciphertext[i] = text[i] ^ obfuscatedStringMask(key, i)
	}
	return StringSym(pos, string(ciphertext)), key
}

func obfuscatedStringKey(functionName, seed, text string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("go-obf-string-v1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(seed))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(functionName))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(text))
	key := h.Sum64()
	if key == 0 {
		key = 0x6a09e667f3bcc909
	}
	return key
}

func obfuscatedStringMask(key uint64, index int) byte {
	x := key + uint64(index)*0x9e3779b97f4a7c15
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return byte(x >> uint((index&7)*8))
}
