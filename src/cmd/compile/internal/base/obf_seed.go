// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

func resolveObfSeed(debug *DebugFlags, getenv func(string) string) error {
	if debug == nil || debug.ObfSeedEnv == "" {
		return nil
	}
	if debug.ObfSeed != "" {
		return fmt.Errorf("-d=obfseed and -d=obfseedenv are mutually exclusive")
	}
	seed := getenv(debug.ObfSeedEnv)
	if seed == "" {
		return fmt.Errorf("-d=obfseedenv=%s refers to an empty environment variable", debug.ObfSeedEnv)
	}
	if debug.ObfSeedID == "" {
		return fmt.Errorf("-d=obfseedenv requires -d=obfseedid to isolate compiler cache entries")
	}
	digest := sha256.Sum256([]byte("go-obf-seed-v1/" + seed))
	if expected := fmt.Sprintf("%x", digest[:]); !strings.EqualFold(debug.ObfSeedID, expected) {
		return fmt.Errorf("-d=obfseedid does not match the environment-sourced protection seed")
	}
	debug.ObfSeed = seed
	return nil
}
