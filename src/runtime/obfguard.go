// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"math/bits"
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

// obfRuntimeGuardV3State records the first image binding that passed the v3
// gate. Unlike the v2 cache, the state is installed with CAS and every entry
// rechecks the patched image lanes, so a later metadata edit cannot turn the
// cache into an unconditional bypass.
var obfRuntimeGuardV3State atomic.Uint64

//go:noinline
func obfRuntimeGuardV3(tag, seal, bootstrap, imageLo, imageHi, platform uint64) {
	hdr := firstmoduledata.pcHeader
	if hdr == nil || !obfRuntimeGuardV3ModuleReady(hdr) ||
		!obfRuntimeGuardValidV3(tag, seal, bootstrap, imageLo, imageHi, platform,
			obfEntryOffKey, obfPclnMagic, hdr.magic,
			obfRuntimeGuardV3Seal[0], obfRuntimeGuardV3Seal[1],
			obfRuntimeGuardV3Bootstrap, obfRuntimeGuardV3Platform) {
		throw("protected runtime integrity check failed")
	}
	stamp := obfRuntimeGuardV3Stamp(bootstrap, imageLo, imageHi, platform)
	state := obfRuntimeGuardV3State.Load()
	if state == 0 {
		if !obfRuntimeGuardV3State.CompareAndSwap(0, stamp) && obfRuntimeGuardV3State.Load() != stamp {
			throw("protected runtime integrity check failed")
		}
	} else if state != stamp {
		throw("protected runtime integrity check failed")
	}
	// Re-read all image fields after publishing the state. This gives the fast
	// path the same fail-closed behavior as the cold path under concurrent edits.
	if obfRuntimeGuardV3State.Load() != stamp ||
		obfRuntimeGuardV3Seal[0] != imageLo || obfRuntimeGuardV3Seal[1] != imageHi ||
		obfRuntimeGuardV3Bootstrap != bootstrap || obfRuntimeGuardV3Platform != platform {
		throw("protected runtime integrity check failed")
	}
}

func obfRuntimeGuardV3ModuleReady(hdr *pcHeader) bool {
	return hdr.nfunc > 0 && firstmoduledata.text != 0 && firstmoduledata.etext > firstmoduledata.text &&
		firstmoduledata.maxpc > firstmoduledata.minpc && firstmoduledata.minpc >= firstmoduledata.text &&
		firstmoduledata.maxpc <= firstmoduledata.etext
}

func obfRuntimeGuardV3Stamp(bootstrap, imageLo, imageHi, platform uint64) uint64 {
	x := bootstrap ^ imageLo ^ bits.RotateLeft64(imageHi, 17) ^ bits.RotateLeft64(platform, 31)
	x ^= 0x13198a2e03707344
	x ^= x >> 29
	x *= 0x9e3779b97f4a7c15
	x ^= x >> 32
	if x == 0 {
		return 0x6a09e667f3bcc909
	}
	return x
}

func obfRuntimeGuardValidV3(tag, seal, bootstrap, imageLo, imageHi, platform uint64, entryKey uint32, magic, headerMagic abi.PCLnTabMagic, patchedLo, patchedHi, patchedBootstrap, patchedPlatform uint64) bool {
	if bootstrap == 0 || bootstrap == obfRuntimeGuardV3Unpatched ||
		imageLo == 0 || imageHi == 0 || platform == 0 ||
		patchedLo != imageLo || patchedHi != imageHi ||
		patchedBootstrap != bootstrap || patchedPlatform != platform {
		return false
	}
	if entryKey == obfEntryOffDisabled || magic == obfPclnMagicUnpatched || headerMagic != magic {
		return false
	}
	return obfRuntimeGuardSealV3(tag, entryKey, uint32(magic), bootstrap, imageLo, imageHi, platform) == seal
}

func obfRuntimeGuardSealV3(tag uint64, entryKey, magic uint32, bootstrap, imageLo, imageHi, platform uint64) uint64 {
	x := tag ^ (uint64(entryKey) << 32) ^ uint64(magic) ^ bootstrap ^ imageLo
	x ^= bits.RotateLeft64(imageHi, 17) ^ bits.RotateLeft64(platform, 31)
	x ^= 0x243f6a8885a308d3
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ (x >> 31)
}
