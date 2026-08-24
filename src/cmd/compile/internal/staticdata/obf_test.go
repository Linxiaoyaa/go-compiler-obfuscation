// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package staticdata

import (
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
	"strconv"
	"strings"
	"testing"
)

var obfuscatedStringKeyV2Sink ObfuscatedStringKey

func TestObfuscatedStringKeyV2Domains(t *testing.T) {
	base := obfuscatedStringKeyV2("pkg.fn", "seed-a", "literal-a")
	if base.Decoder > 3 {
		t.Fatalf("decoder = %d; want 0..3", base.Decoder)
	}
	for i, lane := range base.Lanes {
		if lane == 0 {
			t.Fatalf("lane %d is zero", i)
		}
	}

	cases := []struct {
		name string
		fn   string
		seed string
		text string
	}{
		{"function", "pkg.other", "seed-a", "literal-a"},
		{"seed", "pkg.fn", "seed-b", "literal-a"},
		{"literal", "pkg.fn", "seed-a", "literal-b"},
	}
	for _, tc := range cases {
		got := obfuscatedStringKeyV2(tc.fn, tc.seed, tc.text)
		if got == base {
			t.Fatalf("%s domain produced identical key", tc.name)
		}
	}

	for decoder := uint8(0); decoder < 4; decoder++ {
		seen := make(map[byte]bool)
		for i := 0; i < 32; i++ {
			seen[obfuscatedStringMaskV2(base.Lanes, decoder, i)] = true
		}
		if len(seen) < 8 {
			t.Fatalf("decoder %d produced weak short stream: %d distinct bytes", decoder, len(seen))
		}
	}
}

func TestObfuscatedStringKeyV2Deterministic(t *testing.T) {
	want := obfuscatedStringKeyV2("pkg.fn", "seed-a", "literal-a")
	for i := 0; i < 32; i++ {
		if got := obfuscatedStringKeyV2("pkg.fn", "seed-a", "literal-a"); got != want {
			t.Fatalf("iteration %d changed key: got %#v want %#v", i, got, want)
		}
	}
}

func TestObfuscatedStringKeyV2DecoderCoverage(t *testing.T) {
	var seen [4]bool
	for i := 0; i < 128; i++ {
		key := obfuscatedStringKeyV2("pkg.fn", "seed-"+strconv.Itoa(i), "literal")
		seen[key.Decoder] = true
	}
	for decoder, ok := range seen {
		if !ok {
			t.Fatalf("decoder %d was not selected", decoder)
		}
	}
}

func TestObfuscatedStringKeyV3SeparateDomain(t *testing.T) {
	v2 := obfuscatedStringKeyV2("pkg.fn", "seed-a", "literal-a")
	v3 := obfuscatedStringKeyV3("pkg.fn", "seed-a", "literal-a")
	if v2 == v3 {
		t.Fatal("String v3 reused the String v2 key domain")
	}
	if again := obfuscatedStringKeyV3("pkg.fn", "seed-a", "literal-a"); again != v3 {
		t.Fatalf("String v3 is not deterministic: %#v != %#v", again, v3)
	}
}

func TestObfuscatedStringKeyV4SeparateDomain(t *testing.T) {
	v2 := obfuscatedStringKeyV2("pkg.fn", "seed-a", "literal-a")
	v3 := obfuscatedStringKeyV3("pkg.fn", "seed-a", "literal-a")
	v4 := obfuscatedStringKeyV4("pkg.fn", "seed-a", "literal-a")
	if v4 == v2 || v4 == v3 {
		t.Fatal("String v4 reused an earlier string key domain")
	}
	if again := obfuscatedStringKeyV4("pkg.fn", "seed-a", "literal-a"); again != v4 {
		t.Fatalf("String v4 is not deterministic: %#v != %#v", again, v4)
	}
}

func TestObfuscatedStringKeyV5SeparateDomain(t *testing.T) {
	v2 := obfuscatedStringKeyV2("pkg.fn", "seed-a", "literal-a")
	v3 := obfuscatedStringKeyV3("pkg.fn", "seed-a", "literal-a")
	v4 := obfuscatedStringKeyV4("pkg.fn", "seed-a", "literal-a")
	v5 := obfuscatedStringKeyV5("pkg.fn", "seed-a", "literal-a")
	if v5 == v2 || v5 == v3 || v5 == v4 {
		t.Fatal("String v5 reused an earlier string key domain")
	}
	if v5.Lease == 0 {
		t.Fatal("String v5 lease is zero")
	}
	if again := obfuscatedStringKeyV5("pkg.fn", "seed-a", "literal-a"); again != v5 {
		t.Fatalf("String v5 is not deterministic: %#v != %#v", again, v5)
	}
	if other := obfuscatedStringKeyV5("pkg.fn", "seed-a", "literal-b"); other.Lease == v5.Lease {
		t.Fatal("String v5 literal did not change the lease")
	}
}

func TestObfuscatedStringKeyV6SeparateDomain(t *testing.T) {
	v2 := obfuscatedStringKeyV2("pkg.fn", "seed-a", "literal-a")
	v3 := obfuscatedStringKeyV3("pkg.fn", "seed-a", "literal-a")
	v4 := obfuscatedStringKeyV4("pkg.fn", "seed-a", "literal-a")
	v5 := obfuscatedStringKeyV5("pkg.fn", "seed-a", "literal-a")
	v6 := obfuscatedStringKeyV6("pkg.fn", "seed-a", "literal-a")
	if v6 == v2 || v6 == v3 || v6 == v4 || v6 == v5 {
		t.Fatal("String v6 reused an earlier string key domain")
	}
	if v6.Lease == 0 || v6.Ticket == 0 {
		t.Fatalf("String v6 capability fields are invalid: lease=%#x ticket=%#x", v6.Lease, v6.Ticket)
	}
	if again := obfuscatedStringKeyV6("pkg.fn", "seed-a", "literal-a"); again != v6 {
		t.Fatalf("String v6 is not deterministic: %#v != %#v", again, v6)
	}
	other := obfuscatedStringKeyV6("pkg.fn", "seed-a", "literal-b")
	if other.Lease == v6.Lease || other.Ticket == v6.Ticket {
		t.Fatal("String v6 literal did not rotate both capability fields")
	}
	for decoder := uint8(0); decoder < 4; decoder++ {
		seen := make(map[byte]bool)
		for i := 0; i < 32; i++ {
			seen[obfuscatedStringMaskV6(v6.Lanes, v6.Lease, v6.Ticket, decoder, i)] = true
		}
		if len(seen) < 8 {
			t.Fatalf("String v6 decoder %d produced weak short stream: %d distinct bytes", decoder, len(seen))
		}
	}
}

func BenchmarkObfuscatedStringKeyV2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		obfuscatedStringKeyV2Sink = obfuscatedStringKeyV2(
			"example.com/project/internal/service.processRequest",
			"0123456789abcdef0123456789abcdef",
			"a representative protected string literal",
		)
	}
}

func TestObfuscateProtectedFuncLinkname(t *testing.T) {
	pkg := types.NewPkg("example.com/obf/sample", "sample")
	fn := ir.NewFunc(src.NoXPos, src.NoXPos, pkg.Lookup("privateWorker"), types.NewSignature(nil, nil, nil))
	fn.Protection = ir.ProtectObfuscate
	name, ok := ObfuscateProtectedFuncLinkname(fn, "seed-a")
	if !ok || name == "" {
		t.Fatalf("protected function was not renamed: %q, %t", name, ok)
	}
	if name != fn.Sym().Linkname || !strings.HasPrefix(name, "obf.fn.") {
		t.Fatalf("linkname = %q; want deterministic obf.fn prefix", name)
	}
	if got, ok := ObfuscateProtectedFuncLinkname(fn, "seed-b"); ok || got != "" {
		t.Fatalf("already renamed function changed again: %q, %t", got, ok)
	}
	seedA := fn.Sym().Linkname
	fn.Sym().Linkname = ""
	seedB, ok := ObfuscateProtectedFuncLinkname(fn, "seed-b")
	if !ok || seedA == seedB {
		t.Fatalf("seed did not change hashed name: %q vs %q", seedA, seedB)
	}
	linked := ir.NewFunc(src.NoXPos, src.NoXPos, pkg.Lookup("linkedWorker"), types.NewSignature(nil, nil, nil))
	linked.Protection = ir.ProtectObfuscate
	linked.Sym().Linkname = "external.linkedWorker"
	if got, ok := ObfuscateProtectedFuncLinkname(linked, "seed-a"); ok || got != "" {
		t.Fatalf("existing linkname was replaced with %q", got)
	}

	for _, name := range []string{"PublicWorker", "main", "init"} {
		candidate := ir.NewFunc(src.NoXPos, src.NoXPos, pkg.Lookup(name), types.NewSignature(nil, nil, nil))
		candidate.Protection = ir.ProtectEncrypt
		if got, ok := ObfuscateProtectedFuncLinkname(candidate, "seed-a"); ok || got != "" {
			t.Fatalf("special function %q was renamed to %q", name, got)
		}
	}

	abi0 := ir.NewFunc(src.NoXPos, src.NoXPos, pkg.Lookup("abi0Worker"), types.NewSignature(nil, nil, nil))
	abi0.Protection = ir.ProtectVirtualize
	abi0.ABI = obj.ABI0
	if got, ok := ObfuscateProtectedFuncLinkname(abi0, "seed-a"); ok || got != "" {
		t.Fatalf("ABI0 function was renamed to %q", got)
	}

	closure := ir.NewFunc(src.NoXPos, src.NoXPos, pkg.Lookup("privateWorker.deferwrap1"), types.NewSignature(nil, nil, nil))
	closure.ClosureParent = fn
	if got, ok := ObfuscateProtectedFuncLinkname(closure, "seed-a"); !ok || !strings.HasPrefix(got, "obf.fn.") {
		t.Fatalf("protected defer wrapper was not renamed: %q, %t", got, ok)
	}
}
