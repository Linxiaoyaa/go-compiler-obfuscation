// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "internal/abi"

// obfRuntimeGuardV1 checks the linker-populated metadata that protected
// functions rely on. The per-function seal is emitted by cmd/compile from the
// same build seed used for the linker keys, so a patched or mismatched runtime
// metadata record reaches a fatal path before protected work begins.
//
//go:noinline
func obfRuntimeGuardV1(tag, seal uint64) {
	hdr := firstmoduledata.pcHeader
	if hdr == nil || !obfRuntimeGuardValidV1(tag, seal, obfEntryOffKey, obfPclnMagic, hdr.magic) {
		throw("protected runtime integrity check failed")
	}
}

func obfRuntimeGuardValidV1(tag, seal uint64, entryKey uint32, magic, headerMagic abi.PCLnTabMagic) bool {
	if entryKey == obfEntryOffDisabled || magic == obfPclnMagicUnpatched || headerMagic != magic {
		return false
	}
	return obfRuntimeGuardSealV1(tag, entryKey, uint32(magic)) == seal
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
