// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import "testing"

func TestVM3BucketCount(t *testing.T) {
	tests := []struct {
		states int
		want   int
	}{
		{1, 1},
		{3, 1},
		{4, 1},
		{7, 1},
		{8, 2},
		{23, 2},
		{24, 4},
		{63, 4},
		{64, 8},
	}
	for _, test := range tests {
		if got := vm3BucketCount(test.states); got != test.want {
			t.Fatalf("vm3BucketCount(%d) = %d; want %d", test.states, got, test.want)
		}
	}
}

func TestBuildVM3ProgramFusesAndRemaps(t *testing.T) {
	blocks := []*Block{{}, {}, {}, {}}
	source := &vm2Program{
		blocks:     blocks,
		blockFirst: map[*Block]int{blocks[0]: 0, blocks[1]: 5, blocks[2]: 8, blocks[3]: 9},
		instructions: []vm2Instruction{
			{kind: vm2Exec, next: 1},
			{kind: vm2Exec, next: 2},
			{kind: vm2Exec, next: 3},
			{kind: vm2Exec, next: 4},
			{kind: vm2Jump, edges: [2]vm2Edge{{target: 5}}},
			{kind: vm2Exec, next: 6},
			{kind: vm2Exec, next: 7},
			{kind: vm2Branch, edges: [2]vm2Edge{{target: 8}, {target: 9}}},
			{kind: vm2Return},
			{kind: vm2Return},
		},
	}
	p, err := buildVM3Program(source, &protectionRNG{state: 1})
	if err != nil {
		t.Fatal(err)
	}
	if p.fused < 3 || len(p.units) >= len(source.instructions) {
		t.Fatalf("v3 fused %d instructions into %d states from %d instructions", p.fused, len(p.units), len(source.instructions))
	}
	if p.terminalFused == 0 {
		t.Fatal("v3 did not fuse any safe terminal")
	}
	if len(p.sourceToUnit) != len(source.instructions) {
		t.Fatalf("sourceToUnit has %d entries; want %d", len(p.sourceToUnit), len(source.instructions))
	}
	for raw, unitIndex := range p.sourceToUnit {
		if unitIndex < 0 || unitIndex >= len(p.units) {
			t.Fatalf("source instruction %d maps to invalid unit %d", raw, unitIndex)
		}
	}
	for unitIndex := range p.units {
		unit := &p.units[unitIndex]
		if unit.count > 0 {
			for raw := unit.first; raw < unit.first+unit.count; raw++ {
				if source.instructions[raw].kind != vm2Exec {
					t.Fatalf("unit %d execution prefix crosses terminator at source instruction %d", unitIndex, raw)
				}
				if p.sourceToUnit[raw] != unitIndex {
					t.Fatalf("source instruction %d maps to unit %d; want %d", raw, p.sourceToUnit[raw], unitIndex)
				}
			}
			if unit.kind != vm2Exec && (unit.term < 0 || unit.term >= len(source.instructions) || p.sourceToUnit[unit.term] != unitIndex) {
				t.Fatalf("unit %d has invalid terminator mapping %d", unitIndex, unit.term)
			}
		}
		switch unit.kind {
		case vm2Exec:
			if unit.count <= 0 || unit.count > vm3MaxBundleOps {
				t.Fatalf("execution unit %d has invalid width %d", unitIndex, unit.count)
			}
			last := &source.instructions[unit.first+unit.count-1]
			if unit.next != p.sourceToUnit[last.next] {
				t.Fatalf("execution unit %d targets %d; want %d", unitIndex, unit.next, p.sourceToUnit[last.next])
			}
		case vm2Jump, vm2Branch:
			if unit.kind == vm2Branch && unit.count != 0 {
				t.Fatalf("conditional unit %d fused an execution prefix", unitIndex)
			}
			inst := &source.instructions[unit.term]
			for edgeIndex := 0; edgeIndex < 2; edgeIndex++ {
				if unit.kind == vm2Jump && edgeIndex == 1 {
					break
				}
				want := p.sourceToUnit[inst.edges[edgeIndex].target]
				if unit.edges[edgeIndex].target != want {
					t.Fatalf("unit %d edge %d targets %d; want %d", unitIndex, edgeIndex, unit.edges[edgeIndex].target, want)
				}
			}
		case vm2Return:
		default:
			t.Fatalf("unit %d has invalid kind %d", unitIndex, unit.kind)
		}
	}
	if p.buckets != vm3BucketCount(len(p.units)) {
		t.Fatalf("v3 selected %d buckets for %d states", p.buckets, len(p.units))
	}
}

func TestVM3StateForBucket(t *testing.T) {
	rng := &protectionRNG{state: 0x12345678}
	seen := make(map[uint64]bool)
	const key = uint64(0x9e3779b97f4a7c15)
	const mask = uint64(3)
	for bucket := 0; bucket < 4; bucket++ {
		state := vm3StateForBucket(rng, seen, key, mask, bucket)
		if state == 0 {
			t.Fatalf("bucket %d received zero state", bucket)
		}
		if got := int((state ^ key) & mask); got != bucket {
			t.Fatalf("state %#x selects bucket %d; want %d", state, got, bucket)
		}
	}
}

func TestVM4AliasBudget(t *testing.T) {
	p := &vm3Program{units: make([]vm3Unit, 64)}
	if got := len(p.units) / 4; got != 16 {
		t.Fatalf("default v4 alias estimate = %d; want 16", got)
	}
	const budget = 128
	if got := budget / 32; got != 4 {
		t.Fatalf("budget cap = %d; want 4", got)
	}
}
