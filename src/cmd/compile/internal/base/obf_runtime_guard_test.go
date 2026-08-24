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

func TestObfRuntimeGuardV3Values(t *testing.T) {
	seed := "runtime-guard-v3-test-seed"
	values := func(target string) (uint64, uint64, uint64, uint64, uint64, uint64) {
		return ObfRuntimeGuardV3ValuesForTarget(seed, "example.com/test.protected", target)
	}
	tag, seal, bootstrap, imageLo, imageHi, platform := values("windows/amd64")
	if tag == 0 || seal == 0 || bootstrap == 0 || imageLo == 0 || imageHi == 0 || platform == 0 {
		t.Fatalf("runtime guard v3 values must be non-zero: tag=%#x seal=%#x bootstrap=%#x lo=%#x hi=%#x platform=%#x", tag, seal, bootstrap, imageLo, imageHi, platform)
	}
	tagAgain, sealAgain, bootstrapAgain, loAgain, hiAgain, platformAgain := values("windows/amd64")
	if tag != tagAgain || seal != sealAgain || bootstrap != bootstrapAgain || imageLo != loAgain || imageHi != hiAgain || platform != platformAgain {
		t.Fatal("runtime guard v3 derivation is not deterministic")
	}
	_, otherSeal, otherBootstrap, otherLo, otherHi, otherPlatform := values("linux/amd64")
	if seal == otherSeal || bootstrap == otherBootstrap || imageLo == otherLo || imageHi == otherHi || platform == otherPlatform {
		t.Fatal("runtime guard v3 target binding did not change all image values")
	}
	_, seedSeal, _, seedLo, seedHi, _ := ObfRuntimeGuardV3ValuesForTarget("runtime-guard-v3-other-seed", "example.com/test.protected", "windows/amd64")
	if seedSeal == seal || seedLo == imageLo || seedHi == imageHi {
		t.Fatal("runtime guard v3 seed did not alter image binding")
	}
}

func TestObfRuntimeGuardV4Values(t *testing.T) {
	seed := "runtime-guard-v4-test-seed"
	values := func(target string) (uint64, uint64, uint64, uint64, uint64, uint64, uint64) {
		return ObfRuntimeGuardV4ValuesForTarget(seed, "example.com/test.protected", target)
	}
	tag, seal, bootstrap, imageLo, imageHi, platform, metadataKey := values("windows/amd64")
	if tag == 0 || seal == 0 || bootstrap == 0 || imageLo == 0 || imageHi == 0 || platform == 0 || metadataKey == 0 {
		t.Fatalf("runtime guard v4 values must be non-zero: tag=%#x seal=%#x bootstrap=%#x lo=%#x hi=%#x platform=%#x metadata=%#x", tag, seal, bootstrap, imageLo, imageHi, platform, metadataKey)
	}
	tagAgain, sealAgain, bootstrapAgain, loAgain, hiAgain, platformAgain, metadataAgain := values("windows/amd64")
	if tag != tagAgain || seal != sealAgain || bootstrap != bootstrapAgain || imageLo != loAgain || imageHi != hiAgain || platform != platformAgain || metadataKey != metadataAgain {
		t.Fatal("runtime guard v4 derivation is not deterministic")
	}
	_, otherSeal, otherBootstrap, otherLo, otherHi, otherPlatform, otherMetadata := values("linux/amd64")
	if seal == otherSeal || bootstrap == otherBootstrap || imageLo == otherLo || imageHi == otherHi || platform == otherPlatform || metadataKey == otherMetadata {
		t.Fatal("runtime guard v4 target binding did not change all image values")
	}
	_, seedSeal, _, seedLo, seedHi, _, seedMetadata := ObfRuntimeGuardV4ValuesForTarget("runtime-guard-v4-other-seed", "example.com/test.protected", "windows/amd64")
	if seedSeal == seal || seedLo == imageLo || seedHi == imageHi || seedMetadata == metadataKey {
		t.Fatal("runtime guard v4 seed did not alter image binding")
	}
}
