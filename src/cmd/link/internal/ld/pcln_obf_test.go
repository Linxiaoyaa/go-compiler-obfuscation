// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ld

import "testing"

func TestIsObfuscatedProtectedFuncName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"obf.fn.0123456789abcdef0123456789abcdef", true},
		{"obf.fn.abcdefabcdefabcdefabcdefabcdefab", true},
		{"main.privateWorker", false},
		{"obf.fn.0123456789abcdef", false},
		{"obf.fn.0123456789abcdef0123456789abcdef00", false},
		{"obf.fn.0123456789ABCDEF0123456789ABCDEF", false},
		{"obf.fn.0123456789abcdef0123456789abcdeg", false},
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
