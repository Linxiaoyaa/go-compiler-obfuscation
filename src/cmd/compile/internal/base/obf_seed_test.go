// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestResolveObfSeed(t *testing.T) {
	seed := "environment-seed"
	digest := sha256.Sum256([]byte("go-obf-seed-v1/" + seed))
	seedID := fmt.Sprintf("%x", digest[:])

	tests := []struct {
		name    string
		debug   DebugFlags
		env     string
		want    string
		wantErr string
	}{
		{name: "disabled", debug: DebugFlags{ObfSeed: "explicit"}, want: "explicit"},
		{name: "both", debug: DebugFlags{ObfSeed: "explicit", ObfSeedEnv: "GO_OBF_SEED", ObfSeedID: seedID}, env: seed, wantErr: "mutually exclusive"},
		{name: "empty environment", debug: DebugFlags{ObfSeedEnv: "GO_OBF_SEED", ObfSeedID: seedID}, wantErr: "empty environment variable"},
		{name: "missing identity", debug: DebugFlags{ObfSeedEnv: "GO_OBF_SEED"}, env: seed, wantErr: "requires -d=obfseedid"},
		{name: "mismatched identity", debug: DebugFlags{ObfSeedEnv: "GO_OBF_SEED", ObfSeedID: strings.Repeat("0", 64)}, env: seed, wantErr: "does not match"},
		{name: "valid", debug: DebugFlags{ObfSeedEnv: "GO_OBF_SEED", ObfSeedID: strings.ToUpper(seedID)}, env: seed, want: seed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			debug := test.debug
			err := resolveObfSeed(&debug, func(name string) string {
				if name != "GO_OBF_SEED" {
					t.Fatalf("unexpected environment lookup %q", name)
				}
				return test.env
			})
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("resolveObfSeed error = %v; want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveObfSeed: %v", err)
			}
			if debug.ObfSeed != test.want {
				t.Fatalf("ObfSeed = %q; want %q", debug.ObfSeed, test.want)
			}
		})
	}
}
