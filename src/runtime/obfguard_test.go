// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"runtime"
	"testing"
)

func TestObfRuntimeGuardV1(t *testing.T) {
	const (
		tag      = uint64(0x42d6f4c1a9b375e0)
		entryKey = uint32(0x13579bdf)
		magic    = uint32(0x2468ace1)
	)
	seal := runtime.ObfRuntimeGuardSealForTest(tag, entryKey, magic)
	if !runtime.ObfRuntimeGuardValidForTest(tag, seal, entryKey, magic, magic) {
		t.Fatal("valid runtime guard input was rejected")
	}
	if runtime.ObfRuntimeGuardValidForTest(tag, seal^1, entryKey, magic, magic) {
		t.Fatal("modified runtime guard seal was accepted")
	}
	if runtime.ObfRuntimeGuardValidForTest(tag, seal, entryKey^1, magic, magic) {
		t.Fatal("modified entry key was accepted")
	}
	if runtime.ObfRuntimeGuardValidForTest(tag, seal, entryKey, magic, magic^1) {
		t.Fatal("modified pclntab header magic was accepted")
	}
}

func TestObfRuntimeGuardV2(t *testing.T) {
	const (
		tag       = uint64(0x2d6f4c1a9b375e04)
		entryKey  = uint32(0x13579bdf)
		magic     = uint32(0x2468ace1)
		bootstrap = uint64(0x7f4a7c159e3779b9)
	)
	seal := runtime.ObfRuntimeGuardV2SealForTest(tag, entryKey, magic, bootstrap)
	if !runtime.ObfRuntimeGuardV2ValidForTest(tag, seal, bootstrap, entryKey, magic, magic, bootstrap) {
		t.Fatal("valid runtime guard v2 input was rejected")
	}
	if runtime.ObfRuntimeGuardV2ValidForTest(tag, seal^1, bootstrap, entryKey, magic, magic, bootstrap) {
		t.Fatal("modified runtime guard v2 seal was accepted")
	}
	if runtime.ObfRuntimeGuardV2ValidForTest(tag, seal, bootstrap^1, entryKey, magic, magic, bootstrap) {
		t.Fatal("modified expected bootstrap seal was accepted")
	}
	if runtime.ObfRuntimeGuardV2ValidForTest(tag, seal, bootstrap, entryKey, magic, magic, bootstrap^1) {
		t.Fatal("modified linker bootstrap seal was accepted")
	}
	if runtime.ObfRuntimeGuardV2ValidForTest(tag, seal, bootstrap, entryKey, magic, magic^1, bootstrap) {
		t.Fatal("modified pclntab header magic was accepted")
	}
}

func TestObfRuntimeGuardV3(t *testing.T) {
	const (
		tag       = uint64(0x2d6f4c1a9b375e04)
		bootstrap = uint64(0x7f4a7c159e3779b9)
		imageLo   = uint64(0x0123456789abcdef)
		imageHi   = uint64(0xfedcba9876543210)
		platform  = uint64(0x0f1e2d3c4b5a6978)
		entryKey  = uint32(0x13579bdf)
		magic     = uint32(0x2468ace1)
	)
	seal := runtime.ObfRuntimeGuardV3SealForTest(tag, entryKey, magic, bootstrap, imageLo, imageHi, platform)
	if !runtime.ObfRuntimeGuardV3ValidForTest(tag, seal, bootstrap, imageLo, imageHi, platform, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform) {
		t.Fatal("valid runtime guard v3 input was rejected")
	}
	if runtime.ObfRuntimeGuardV3ValidForTest(tag, seal^1, bootstrap, imageLo, imageHi, platform, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform) {
		t.Fatal("modified runtime guard v3 seal was accepted")
	}
	if runtime.ObfRuntimeGuardV3ValidForTest(tag, seal, bootstrap, imageLo^1, imageHi, platform, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform) {
		t.Fatal("modified image lane was accepted")
	}
	if runtime.ObfRuntimeGuardV3ValidForTest(tag, seal, bootstrap, imageLo, imageHi, platform^1, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform) {
		t.Fatal("modified platform binding was accepted")
	}
}

func TestObfRuntimeGuardV4(t *testing.T) {
	const (
		tag         = uint64(0x2d6f4c1a9b375e04)
		bootstrap   = uint64(0x7f4a7c159e3779b9)
		imageLo     = uint64(0x0123456789abcdef)
		imageHi     = uint64(0xfedcba9876543210)
		platform    = uint64(0x0f1e2d3c4b5a6978)
		metadataKey = uint64(0x243f6a8885a308d3)
		entryKey    = uint32(0x13579bdf)
		magic       = uint32(0x2468ace1)
		nfunc       = uint64(173)
		nfiles      = uint64(29)
		pclntable   = uint64(16384)
	)
	seal := runtime.ObfRuntimeGuardV4SealForTest(tag, entryKey, magic, bootstrap, imageLo, imageHi, platform, metadataKey)
	metadataSeal := runtime.ObfRuntimeGuardV4MetadataSealForTest(metadataKey, nfunc, nfiles, pclntable)
	if !runtime.ObfRuntimeGuardV4ValidForTest(tag, seal, bootstrap, imageLo, imageHi, platform, metadataKey, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform, metadataKey, metadataSeal, nfunc, nfiles, pclntable) {
		t.Fatal("valid runtime guard v4 input was rejected")
	}
	if runtime.ObfRuntimeGuardV4ValidForTest(tag, seal^1, bootstrap, imageLo, imageHi, platform, metadataKey, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform, metadataKey, metadataSeal, nfunc, nfiles, pclntable) {
		t.Fatal("modified runtime guard v4 seal was accepted")
	}
	if runtime.ObfRuntimeGuardV4ValidForTest(tag, seal, bootstrap, imageLo, imageHi, platform, metadataKey^1, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform, metadataKey, metadataSeal, nfunc, nfiles, pclntable) {
		t.Fatal("modified metadata key was accepted")
	}
	if runtime.ObfRuntimeGuardV4ValidForTest(tag, seal, bootstrap, imageLo, imageHi, platform, metadataKey, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform, metadataKey, metadataSeal^1, nfunc, nfiles, pclntable) {
		t.Fatal("modified metadata seal was accepted")
	}
	if runtime.ObfRuntimeGuardV4ValidForTest(tag, seal, bootstrap, imageLo, imageHi, platform, metadataKey, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform, metadataKey, metadataSeal, nfunc+1, nfiles, pclntable) {
		t.Fatal("modified function count was accepted")
	}
	if runtime.ObfRuntimeGuardV4ValidForTest(tag, seal, bootstrap, imageLo, imageHi, platform, metadataKey, entryKey, magic, magic, imageLo, imageHi, bootstrap, platform, metadataKey, metadataSeal, nfunc, nfiles, pclntable+8) {
		t.Fatal("modified pclntab length was accepted")
	}
}
