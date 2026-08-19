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
