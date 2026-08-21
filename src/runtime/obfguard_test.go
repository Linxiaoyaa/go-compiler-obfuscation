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
