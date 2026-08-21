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
