// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ld

import (
	"encoding/binary"
	"testing"
)

func TestIsObfuscatedProtectedFuncName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"obf.fn.0123456789abcdef0123456789abcdef", true},
		{"obf.fn.abcdefabcdefabcdefabcdefabcdefab", true},
		{"obf.fn.0123456789abcdef0123456789abcdef-tramp0", true},
		{"obf.fn.0123456789abcdef0123456789abcdef-tramp17", true},
		{"obf.fn.0123456789abcdef0123456789abcdef+10-tramp2", true},
		{"obf.fn.0123456789abcdef0123456789abcdef-1f-tramp3", true},
		{"main.privateWorker", false},
		{"obf.fn.0123456789abcdef", false},
		{"obf.fn.0123456789abcdef0123456789abcdef00", false},
		{"obf.fn.0123456789ABCDEF0123456789ABCDEF", false},
		{"obf.fn.0123456789abcdef0123456789abcdeg", false},
		{"obf.fn.0123456789abcdef0123456789abcdef-tramp", false},
		{"obf.fn.0123456789abcdef0123456789abcdef-trampx", false},
		{"obf.fn.0123456789abcdef0123456789abcdef+10-tramp", false},
		{"obf.fn.0123456789abcdef0123456789abcdef+1G-tramp0", false},
		{"obf.fn.0123456789abcdef0123456789abcdef-tramp0-extra", false},
	}
	for _, test := range tests {
		if got := isObfuscatedProtectedFuncName(test.name); got != test.want {
			t.Errorf("isObfuscatedProtectedFuncName(%q) = %t; want %t", test.name, got, test.want)
		}
	}
}

func TestObfEntryOffDomain(t *testing.T) {
	base := obfEntryOffDomain(0, ^uint32(0), 42)
	if base == 0 {
		t.Fatal("entry offset domain is zero")
	}
	if got := obfEntryOffDomain(0, ^uint32(0), 42); got != base {
		t.Fatalf("entry offset domain is not deterministic: got %#x want %#x", got, base)
	}
	for _, input := range [][3]uint32{
		{1, ^uint32(0), 42},
		{0, 7, 42},
		{0, ^uint32(0), 43},
	} {
		if got := obfEntryOffDomain(input[0], input[1], input[2]); got == base {
			t.Fatalf("entry offset domain collision for %#v", input)
		}
	}
}

func TestObfPclnBuildModeSupported(t *testing.T) {
	tests := []struct {
		mode BuildMode
		want bool
	}{
		{BuildModeExe, true},
		{BuildModePIE, true},
		{BuildModeCShared, true},
		{BuildModeCArchive, false},
		{BuildModeShared, false},
		{BuildModePlugin, false},
	}
	for _, test := range tests {
		if got := obfPclnBuildModeSupported(test.mode); got != test.want {
			t.Errorf("obfPclnBuildModeSupported(%s) = %t; want %t", test.mode, got, test.want)
		}
	}
}

func TestObfPclnMagicValue(t *testing.T) {
	for _, magic := range []uint32{
		uint32(0xfffffffb), uint32(0xfffffffa), uint32(0xfffffff0), uint32(0xfffffff1), 0,
	} {
		if isObfuscatedPclnMagic(magic) {
			t.Fatalf("standard/zero magic %#x accepted", magic)
		}
	}
	if !isObfuscatedPclnMagic(0x1234567d) {
		t.Fatal("custom magic rejected")
	}
}

func TestObfRuntimeGuardV2SealWords(t *testing.T) {
	const seal = uint64(0x0123456789abcdef)
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		first, second := obfRuntimeGuardV2SealWords(order, seal)
		var encoded [8]byte
		order.PutUint32(encoded[:4], first)
		order.PutUint32(encoded[4:], second)
		if got := order.Uint64(encoded[:]); got != seal {
			t.Fatalf("%T seal serialization = %#x; want %#x", order, got, seal)
		}
	}
}

func TestObfRuntimeGuardV3SealWords(t *testing.T) {
	const seal = uint64(0xfedcba9876543210)
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		first, second := obfRuntimeGuardV3SealWords(order, seal)
		var encoded [8]byte
		order.PutUint32(encoded[:4], first)
		order.PutUint32(encoded[4:], second)
		if got := order.Uint64(encoded[:]); got != seal {
			t.Fatalf("%T v3 seal serialization = %#x; want %#x", order, got, seal)
		}
	}
}

func TestObfRuntimeGuardV4MetadataSeal(t *testing.T) {
	const (
		metadataKey = uint64(0x243f6a8885a308d3)
		nfunc       = uint64(173)
		nfiles      = uint64(29)
		pclntable   = uint64(16384)
	)
	base := obfRuntimeGuardV4MetadataSealFor(metadataKey, nfunc, nfiles, pclntable)
	if base == 0 || base == obfRuntimeGuardV4Unpatched {
		t.Fatalf("invalid v4 metadata seal %#x", base)
	}
	for _, candidate := range [][4]uint64{
		{metadataKey ^ 1, nfunc, nfiles, pclntable},
		{metadataKey, nfunc + 1, nfiles, pclntable},
		{metadataKey, nfunc, nfiles + 1, pclntable},
		{metadataKey, nfunc, nfiles, pclntable + 8},
	} {
		if got := obfRuntimeGuardV4MetadataSealFor(candidate[0], candidate[1], candidate[2], candidate[3]); got == base {
			t.Fatalf("v4 metadata seal did not bind %#v", candidate)
		}
	}
}

func TestObfuscatedPclnFileName(t *testing.T) {
	first := obfuscatedPclnFileName("C:/project/internal/auth/service.go", 0x123456789abcdef0)
	if len(first) != len("obf.src.")+32 || first[:len("obf.src.")] != "obf.src." {
		t.Fatalf("hashed filename = %q; want obf.src.<32 hex chars>", first)
	}
	if got := obfuscatedPclnFileName("C:/project/internal/auth/service.go", 0x123456789abcdef0); got != first {
		t.Fatalf("hashed filename is not deterministic: %q vs %q", got, first)
	}
	if got := obfuscatedPclnFileName("C:/project/internal/license/service.go", 0x123456789abcdef0); got == first {
		t.Fatal("different source paths produced the same hashed filename")
	}
	if got := obfuscatedPclnFileName("C:/project/internal/auth/service.go", 0xfedcba9876543210); got == first {
		t.Fatal("different keys produced the same hashed filename")
	}
}
