// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	obfEntryOffDisabled   uint32 = 0xa5a5a5a5
	obfPclnMagicUnpatched uint32 = 0xa5a5a5a5
)

// ObfRuntimeGuardV1Values returns the function-local tag and seal consumed by
// runtime.obfRuntimeGuardV1. The seal binds the function identity to the
// linker values derived from the same build seed without embedding that seed
// in the executable.
func ObfRuntimeGuardV1Values(seed, function string) (tag, seal uint64) {
	tagDigest := sha256.Sum256([]byte("go-obf-runtime-guard-v1/function\x00" + seed + "\x00" + function))
	tag = binary.LittleEndian.Uint64(tagDigest[:8])
	entryKey := obfRuntimeEntryKey(seed)
	magic := obfRuntimePclnMagic(seed)
	return tag, obfRuntimeGuardSealV1(tag, entryKey, magic)
}

func obfRuntimeEntryKey(seed string) uint32 {
	digest := sha256.Sum256([]byte(seed))
	key := binary.LittleEndian.Uint32(digest[:4]) | 1
	if key == 0 || key == obfEntryOffDisabled {
		return 0x6d2b79f5
	}
	return key
}

func obfRuntimePclnMagic(seed string) uint32 {
	digest := sha256.Sum256([]byte("pcln-magic/" + seed))
	magic := binary.LittleEndian.Uint32(digest[:4])
	switch magic {
	case 0, obfPclnMagicUnpatched, 0xfffffffb, 0xfffffffa, 0xfffffff0, 0xfffffff1:
		return 0x1234567d
	}
	return magic
}

func obfRuntimeGuardSealV1(tag uint64, entryKey, magic uint32) uint64 {
	x := tag ^ (uint64(entryKey) << 32) ^ uint64(magic)
	x ^= 0xd1b54a32d192ed03
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ (x >> 31)
}
