// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
)

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

// obfRuntimeGuardV2Cache is populated after the first successful bootstrap
// verification. Every protected entry still compares the linker-patched seal,
// while the cache records that startup validation reached a consistent state.
var obfRuntimeGuardV2Cache atomic.Uint64

//go:noinline
func obfRuntimeGuardV2(tag, seal, expectedBootstrap uint64) {
	hdr := firstmoduledata.pcHeader
	if hdr == nil || !obfRuntimeGuardV2BootstrapReady(expectedBootstrap) ||
		!obfRuntimeGuardValidV2(tag, seal, expectedBootstrap, obfEntryOffKey, obfPclnMagic, hdr.magic, obfRuntimeGuardV2Seal) {
		throw("protected runtime integrity check failed")
	}
}

func obfRuntimeGuardV2BootstrapReady(expected uint64) bool {
	if expected == 0 || expected == obfRuntimeGuardV2Unpatched || obfRuntimeGuardV2Seal != expected {
		return false
	}
	stamp := obfRuntimeGuardV2CacheStamp(expected)
	if obfRuntimeGuardV2Cache.Load() != stamp {
		obfRuntimeGuardV2Cache.Store(stamp)
	}
	// Re-read the patched value after publishing the cache state. This keeps
	// the fast path tied to the actual image field rather than cache state alone.
	return obfRuntimeGuardV2Cache.Load() == stamp && obfRuntimeGuardV2Seal == expected
}

func obfRuntimeGuardV2CacheStamp(expected uint64) uint64 {
	stamp := expected ^ 0x6a09e667f3bcc909
	if stamp == 0 {
		return 0x510e527fade682d1
	}
	return stamp
}

func obfRuntimeGuardValidV2(tag, seal, expectedBootstrap uint64, entryKey uint32, magic, headerMagic abi.PCLnTabMagic, bootstrap uint64) bool {
	if expectedBootstrap == 0 || expectedBootstrap == obfRuntimeGuardV2Unpatched || bootstrap != expectedBootstrap {
		return false
	}
	if entryKey == obfEntryOffDisabled || magic == obfPclnMagicUnpatched || headerMagic != magic {
		return false
	}
	return obfRuntimeGuardSealV2(tag, entryKey, uint32(magic), bootstrap) == seal
}

func obfRuntimeGuardSealV2(tag uint64, entryKey, magic uint32, bootstrap uint64) uint64 {
	x := tag ^ (uint64(entryKey) << 32) ^ uint64(magic) ^ bootstrap
	x ^= 0x9e3779b97f4a7c15
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ (x >> 31)
}
