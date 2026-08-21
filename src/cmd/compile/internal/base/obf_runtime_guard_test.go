// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base

import "testing"

func TestObfRuntimeGuardV1Values(t *testing.T) {
	seed := "runtime-guard-test-seed"
	tag, seal := ObfRuntimeGuardV1Values(seed, "example.com/test.protected")
	if tag == 0 || seal == 0 {
		t.Fatalf("runtime guard values must be non-zero: tag=%#x seal=%#x", tag, seal)
	}
	tagAgain, sealAgain := ObfRuntimeGuardV1Values(seed, "example.com/test.protected")
	if tag != tagAgain || seal != sealAgain {
		t.Fatalf("runtime guard derivation is not deterministic")
	}
	otherTag, otherSeal := ObfRuntimeGuardV1Values(seed, "example.com/test.other")
	if tag == otherTag || seal == otherSeal {
		t.Fatalf("function identity did not change runtime guard values")
	}
	_, otherSeedSeal := ObfRuntimeGuardV1Values("runtime-guard-other-seed", "example.com/test.protected")
	if seal == otherSeedSeal {
		t.Fatalf("seed did not change runtime guard seal")
	}
}

func TestObfRuntimeGuardV2Values(t *testing.T) {
	seed := "runtime-guard-v2-test-seed"
	tag, seal, bootstrap := ObfRuntimeGuardV2Values(seed, "example.com/test.protected")
	if tag == 0 || seal == 0 || bootstrap == 0 {
		t.Fatalf("runtime guard v2 values must be non-zero: tag=%#x seal=%#x bootstrap=%#x", tag, seal, bootstrap)
	}
	if bootstrap != ObfRuntimeGuardV2BootstrapSeal(seed) {
		t.Fatal("runtime guard v2 bootstrap derivation changed")
	}
	_, otherSeal, otherBootstrap := ObfRuntimeGuardV2Values(seed, "example.com/test.other")
	if otherSeal == seal || otherBootstrap != bootstrap {
		t.Fatal("runtime guard v2 function binding is invalid")
	}
	_, seedSeal, seedBootstrap := ObfRuntimeGuardV2Values("runtime-guard-v2-other-seed", "example.com/test.protected")
	if seedSeal == seal || seedBootstrap == bootstrap {
		t.Fatal("runtime guard v2 seed did not alter all seals")
	}
}
