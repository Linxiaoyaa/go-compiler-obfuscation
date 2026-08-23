// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import "testing"

//go:vm
//go:encrypt
func protectedVMCalc(a, b uint64) uint64 {
	return (((a ^ 0x123456789abcdef0) + b) * 3) ^ (a << (b & 63))
}

//go:obf
//go:encrypt
func protectedNativeCalc(a, b uint64) uint64 {
	return (a + 0x0f1e2d3c4b5a6978) ^ (b * 5)
}

//go:noinline
func protectedNativeCall(v uint64) uint64 {
	return ((v ^ 0x7f4a7c159e3779b9) * 9) + 0x94d049bb133111eb
}

//go:noinline
//go:obf
//go:encrypt
func protectedNativeBranch(a, b uint64) uint64 {
	if a < b {
		return protectedNativeCall((a ^ 0x1020304050607080) + b)
	}
	if a&1 == 0 {
		return protectedNativeCall((a + 0x0badf00ddeadbeef) ^ b)
	}
	return protectedNativeCall((a - b) ^ 0x55aa55aa55aa55aa)
}

//go:noinline
//go:obf
//go:encrypt
func protectedNativeLoopCall(n, seed uint64) uint64 {
	state := seed
	for i := uint64(0); i < n; i++ {
		if i&1 == 0 {
			state = protectedNativeCall(state ^ i)
		} else {
			state = protectedNativeCall(state + i)
		}
	}
	return state
}

var protectedNativeDeferred uint64

//go:noinline
func protectedNativeRecordDeferred(v uint64) {
	protectedNativeDeferred ^= v
}

//go:noinline
//go:obf
//go:encrypt
func protectedNativeDefer(v uint64) uint64 {
	defer protectedNativeRecordDeferred(v)
	if v&1 == 0 {
		return v ^ 0x3141592653589793
	}
	return v + 0x2718281828459045
}

//go:noprotect
func unprotectedCalc(a, b uint64) uint64 {
	return a + b
}

//go:vm
//go:encrypt
//go:obf
func protectedVMBranch(a, b uint64) uint64 {
	if a == b {
		return (a ^ 0x1111222233334444) + 7
	}
	if a < b {
		return (b - a) ^ 0x5555666677778888
	}
	return (a - b) ^ 0x9999aaaabbbbcccc
}

//go:vm
//go:encrypt
func protectedVMLoop(n, seed uint64) uint64 {
	acc := seed
	for i := uint64(0); i < n; i++ {
		if i&1 == 0 {
			acc += i ^ 0x123456789abcdef0
		} else {
			acc ^= i + 0x0fedcba987654321
		}
	}
	return acc
}

//go:vm
//go:encrypt
func protectedVMBool(a, b uint64) bool {
	return a < b || a == 0x4242424242424242
}

//go:vm
func protectedVMPlain(a, b uint64) uint64 {
	return (a ^ 0x0a0b0c0d0e0f1011) + b
}

//go:encrypt
func protectedStringLiteral() string {
	return "obf-runtime-string-v1-secret"
}

//go:encrypt
func protectedStringCheck() bool {
	s := "obf-runtime-string-v1-secret"
	return len(s) == 28 && s[0] == 'o' && s[3] == '-' && s[12] == 's' && s[27] == 't'
}

//go:encrypt
//go:stream
func protectedStringStreamCheck(last int) bool {
	s := "obf-runtime-string-v4-stream"
	return len(s) == 28 && s[0] == 'o' && s[3] == '-' && s[last] == 'm'
}

//go:encrypt
//go:streamv5
func protectedStringLeaseStreamCheck(last int) bool {
	s := "obf-runtime-string-v5-lease"
	return len(s) == 27 && s[0] == 'o' && s[19] == 'v' && s[last] == 'e'
}

//go:encrypt
func protectedStringMap() string {
	m := map[string]string{"obf-runtime-map-key": "obf-runtime-map-value"}
	return m["obf-runtime-map-key"]
}

//go:noinline
func obfTestBranchSelect(v uint64, text string) string {
	if v&1 == 0 {
		return text
	}
	return text
}

//go:encrypt
func protectedStringBranch(flag bool) string {
	if flag {
		return obfTestBranchSelect(0x2468ace013579bdf, "obf-runtime-branch-even")
	}
	return obfTestBranchSelect(0xfdb97531eca86420, "obf-runtime-branch-odd")
}

//go:encrypt
func ProtectedExportedName() string {
	return "exported-name-stays-stable"
}

//go:noprotect
func stableUnprotectedName() string {
	return "unprotected-name-stays-stable"
}

func TestProtectionDirectives(t *testing.T) {
	tests := [][2]uint64{
		{0, 0},
		{1, 2},
		{0x1122334455667788, 17},
		{^uint64(0), 63},
	}
	for _, test := range tests {
		a, b := test[0], test[1]
		vmWant := (((a ^ 0x123456789abcdef0) + b) * 3) ^ (a << (b & 63))
		if got := protectedVMCalc(a, b); got != vmWant {
			t.Fatalf("protectedVMCalc(%#x, %#x) = %#x; want %#x", a, b, got, vmWant)
		}
		nativeWant := (a + 0x0f1e2d3c4b5a6978) ^ (b * 5)
		if got := protectedNativeCalc(a, b); got != nativeWant {
			t.Fatalf("protectedNativeCalc(%#x, %#x) = %#x; want %#x", a, b, got, nativeWant)
		}
		nativeCallWant := func(v uint64) uint64 {
			return ((v ^ 0x7f4a7c159e3779b9) * 9) + 0x94d049bb133111eb
		}
		nativeBranchWant := func() uint64 {
			if a < b {
				return nativeCallWant((a ^ 0x1020304050607080) + b)
			}
			if a&1 == 0 {
				return nativeCallWant((a + 0x0badf00ddeadbeef) ^ b)
			}
			return nativeCallWant((a - b) ^ 0x55aa55aa55aa55aa)
		}()
		if got := protectedNativeBranch(a, b); got != nativeBranchWant {
			t.Fatalf("protectedNativeBranch(%#x, %#x) = %#x; want %#x", a, b, got, nativeBranchWant)
		}
		for _, n := range []uint64{0, 1, 2, 7, 19} {
			loopWant := b
			for i := uint64(0); i < n; i++ {
				if i&1 == 0 {
					loopWant = nativeCallWant(loopWant ^ i)
				} else {
					loopWant = nativeCallWant(loopWant + i)
				}
			}
			if got := protectedNativeLoopCall(n, b); got != loopWant {
				t.Fatalf("protectedNativeLoopCall(%#x, %#x) = %#x; want %#x", n, b, got, loopWant)
			}
		}
		beforeDefer := protectedNativeDeferred
		deferWant := a + 0x2718281828459045
		if a&1 == 0 {
			deferWant = a ^ 0x3141592653589793
		}
		if got := protectedNativeDefer(a); got != deferWant {
			t.Fatalf("protectedNativeDefer(%#x) = %#x; want %#x", a, got, deferWant)
		}
		if got := protectedNativeDeferred; got != beforeDefer^a {
			t.Fatalf("protectedNativeDeferred = %#x; want %#x", got, beforeDefer^a)
		}
		if got := unprotectedCalc(a, b); got != a+b {
			t.Fatalf("unprotectedCalc(%#x, %#x) = %#x; want %#x", a, b, got, a+b)
		}
		branchWant := func() uint64 {
			if a == b {
				return (a ^ 0x1111222233334444) + 7
			}
			if a < b {
				return (b - a) ^ 0x5555666677778888
			}
			return (a - b) ^ 0x9999aaaabbbbcccc
		}()
		if got := protectedVMBranch(a, b); got != branchWant {
			t.Fatalf("protectedVMBranch(%#x, %#x) = %#x; want %#x", a, b, got, branchWant)
		}
		for _, n := range []uint64{0, 1, 2, 7, 19} {
			loopWant := b
			for i := uint64(0); i < n; i++ {
				if i&1 == 0 {
					loopWant += i ^ 0x123456789abcdef0
				} else {
					loopWant ^= i + 0x0fedcba987654321
				}
			}
			if got := protectedVMLoop(n, b); got != loopWant {
				t.Fatalf("protectedVMLoop(%#x, %#x) = %#x; want %#x", n, b, got, loopWant)
			}
		}
		boolWant := a < b || a == 0x4242424242424242
		if got := protectedVMBool(a, b); got != boolWant {
			t.Fatalf("protectedVMBool(%#x, %#x) = %t; want %t", a, b, got, boolWant)
		}
		plainWant := (a ^ 0x0a0b0c0d0e0f1011) + b
		if got := protectedVMPlain(a, b); got != plainWant {
			t.Fatalf("protectedVMPlain(%#x, %#x) = %#x; want %#x", a, b, got, plainWant)
		}
	}
	if got := protectedStringLiteral(); len(got) != 28 || got[0] != 'o' || got[27] != 't' {
		t.Fatalf("protectedStringLiteral() = %q", got)
	}
	if !protectedStringCheck() {
		t.Fatal("protectedStringCheck() = false")
	}
	if !protectedStringStreamCheck(27) {
		t.Fatal("protectedStringStreamCheck() = false")
	}
	if !protectedStringLeaseStreamCheck(26) {
		t.Fatal("protectedStringLeaseStreamCheck() = false")
	}
	if got := protectedStringMap(); got != "obf-runtime-map-value" {
		t.Fatalf("protectedStringMap() = %q", got)
	}
	for _, flag := range []bool{false, true} {
		got := protectedStringBranch(flag)
		want := "obf-runtime-branch-odd"
		if flag {
			want = "obf-runtime-branch-even"
		}
		if got != want {
			t.Fatalf("protectedStringBranch(%t) = %q; want %q", flag, got, want)
		}
	}
	if got := ProtectedExportedName(); got != "exported-name-stays-stable" {
		t.Fatalf("ProtectedExportedName() = %q", got)
	}
	if got := stableUnprotectedName(); got != "unprotected-name-stays-stable" {
		t.Fatalf("stableUnprotectedName() = %q", got)
	}
}
