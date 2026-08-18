// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package staticdata

import (
	"strconv"
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

func BenchmarkObfuscatedStringKeyV2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		obfuscatedStringKeyV2Sink = obfuscatedStringKeyV2(
			"example.com/project/internal/service.processRequest",
			"0123456789abcdef0123456789abcdef",
			"a representative protected string literal",
		)
	}
}
