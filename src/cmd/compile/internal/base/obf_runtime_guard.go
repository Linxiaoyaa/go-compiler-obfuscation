// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base

import (
	"crypto/sha256"
	"encoding/binary"
	"internal/buildcfg"
	"math/bits"
)

const (
	obfEntryOffDisabled   uint32 = 0xa5a5a5a5
	obfPclnMagicUnpatched uint32 = 0xa5a5a5a5
	obfRuntimeGuardV2None uint64 = 0xa5a5a5a5a5a5a5a5
	obfRuntimeGuardV3None uint64 = 0xa5a5a5a5a5a5a5a5
	obfRuntimeGuardV4None uint64 = 0xa5a5a5a5a5a5a5a5
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

// ObfRuntimeGuardV2Values returns the per-function values and the independent
// bootstrap seal consumed by runtime.obfRuntimeGuardV2. The bootstrap seal is
// patched by cmd/link, while the function seal binds all linker-derived values
// together so a copied or mismatched entry record cannot satisfy the gate.
func ObfRuntimeGuardV2Values(seed, function string) (tag, seal, bootstrap uint64) {
	tagDigest := sha256.Sum256([]byte("go-obf-runtime-guard-v2/function\x00" + seed + "\x00" + function))
	tag = binary.LittleEndian.Uint64(tagDigest[:8])
	bootstrap = ObfRuntimeGuardV2BootstrapSeal(seed)
	return tag, obfRuntimeGuardSealV2(tag, obfRuntimeEntryKey(seed), obfRuntimePclnMagic(seed), bootstrap), bootstrap
}

// ObfRuntimeGuardV2BootstrapSeal derives the linker-patched process value.
// It intentionally has a distinct hash domain from every function seal.
func ObfRuntimeGuardV2BootstrapSeal(seed string) uint64 {
	digest := sha256.Sum256([]byte("go-obf-runtime-guard-v2/bootstrap\x00" + seed))
	seal := binary.LittleEndian.Uint64(digest[:8])
	if seal == 0 || seal == obfRuntimeGuardV2None {
		return 0x6a09e667f3bcc909
	}
	return seal
}

// ObfRuntimeGuardV3Values derives the v3 function and image bindings for the
// compiler's target tuple. The target is included in every independent domain
// so a cached object compiled for one platform cannot satisfy another image.
func ObfRuntimeGuardV3Values(seed, function string) (tag, seal, bootstrap, imageLo, imageHi, platform uint64) {
	return ObfRuntimeGuardV3ValuesForTarget(seed, function, buildcfg.GOOS+"/"+buildcfg.GOARCH)
}

// ObfRuntimeGuardV3ValuesForTarget is split out for deterministic unit tests
// and for tools that need to preview a cross-compiled guard record.
func ObfRuntimeGuardV3ValuesForTarget(seed, function, target string) (tag, seal, bootstrap, imageLo, imageHi, platform uint64) {
	tagDigest := obfRuntimeGuardV3Digest("go-obf-runtime-guard-v3/function", seed, target, function)
	tag = binary.LittleEndian.Uint64(tagDigest[:8])
	bootstrap = obfRuntimeGuardV3Word("go-obf-runtime-guard-v3/bootstrap", seed, target)
	imageLo = obfRuntimeGuardV3Word("go-obf-runtime-guard-v3/image-lo", seed, target)
	imageHi = obfRuntimeGuardV3Word("go-obf-runtime-guard-v3/image-hi", seed, target)
	platform = obfRuntimeGuardV3Word("go-obf-runtime-guard-v3/platform", "", target)
	seal = obfRuntimeGuardSealV3(tag, obfRuntimeEntryKey(seed), obfRuntimePclnMagic(seed), bootstrap, imageLo, imageHi, platform)
	return
}

// ObfRuntimeGuardV4Values derives v4's function, image, and metadata-key
// bindings for a target. The linker turns metadataKey into a final-image seal
// after pclntab generation; the compiler-only function seal binds that key to
// the entry record without embedding the build seed in the binary.
func ObfRuntimeGuardV4Values(seed, function string) (tag, seal, bootstrap, imageLo, imageHi, platform, metadataKey uint64) {
	return ObfRuntimeGuardV4ValuesForTarget(seed, function, buildcfg.GOOS+"/"+buildcfg.GOARCH)
}

// ObfRuntimeGuardV4ValuesForTarget is split out for deterministic tests and
// cross-compilation tooling.
func ObfRuntimeGuardV4ValuesForTarget(seed, function, target string) (tag, seal, bootstrap, imageLo, imageHi, platform, metadataKey uint64) {
	tagDigest := obfRuntimeGuardV3Digest("go-obf-runtime-guard-v4/function", seed, target, function)
	tag = binary.LittleEndian.Uint64(tagDigest[:8])
	bootstrap = obfRuntimeGuardV4Word("go-obf-runtime-guard-v4/bootstrap", seed, target)
	imageLo = obfRuntimeGuardV4Word("go-obf-runtime-guard-v4/image-lo", seed, target)
	imageHi = obfRuntimeGuardV4Word("go-obf-runtime-guard-v4/image-hi", seed, target)
	platform = obfRuntimeGuardV4Word("go-obf-runtime-guard-v4/platform", "", target)
	metadataKey = obfRuntimeGuardV4Word("go-obf-runtime-guard-v4/metadata-key", seed, target)
	seal = obfRuntimeGuardSealV4(tag, obfRuntimeEntryKey(seed), obfRuntimePclnMagic(seed), bootstrap, imageLo, imageHi, platform, metadataKey)
	return
}

func obfRuntimeGuardV3Digest(domain, seed, target, function string) [32]byte {
	return sha256.Sum256([]byte(domain + "\x00" + seed + "\x00" + target + "\x00" + function))
}

func obfRuntimeGuardV3Word(domain, seed, target string) uint64 {
	digest := sha256.Sum256([]byte(domain + "\x00" + seed + "\x00" + target))
	word := binary.LittleEndian.Uint64(digest[:8])
	if word == 0 || word == obfRuntimeGuardV3None {
		return 0x6a09e667f3bcc909
	}
	return word
}

func obfRuntimeGuardV4Word(domain, seed, target string) uint64 {
	digest := sha256.Sum256([]byte(domain + "\x00" + seed + "\x00" + target))
	word := binary.LittleEndian.Uint64(digest[:8])
	if word == 0 || word == obfRuntimeGuardV4None {
		return 0x6a09e667f3bcc909
	}
	return word
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

func obfRuntimeGuardSealV2(tag uint64, entryKey, magic uint32, bootstrap uint64) uint64 {
	x := tag ^ (uint64(entryKey) << 32) ^ uint64(magic) ^ bootstrap
	x ^= 0x9e3779b97f4a7c15
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ (x >> 31)
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

func obfRuntimeGuardSealV4(tag uint64, entryKey, magic uint32, bootstrap, imageLo, imageHi, platform, metadataKey uint64) uint64 {
	x := tag ^ (uint64(entryKey) << 32) ^ uint64(magic) ^ bootstrap ^ imageLo ^ metadataKey
	x ^= bits.RotateLeft64(imageHi, 17) ^ bits.RotateLeft64(platform, 31) ^ bits.RotateLeft64(metadataKey, 43)
	x ^= 0x452821e638d01377
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ (x >> 31)
}
