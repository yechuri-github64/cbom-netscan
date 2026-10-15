// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"slices"
	"strconv"
	"testing"
	"time"
)

// TestMergeEvidenceDedupe pins how merging treats evidence: an occurrence
// already on the stored asset is not added again, new ones are appended in
// order, duplicates within one added asset collapse, and occurrences
// appended to the stored asset between merges are still recognised.
func TestMergeEvidenceDedupe(t *testing.T) {
	ev := func(line int) Evidence { return Evidence{Location: "fw.conf", Line: line, Symbol: "s"} }
	add := func(inv *Inventory, evs ...Evidence) *Asset {
		return inv.Add(&Asset{Type: AssetTypeAlgorithm, Name: "AES-256-GCM", Alg: &Algorithm{Primitive: "ae"}, Evidence: evs})
	}
	lines := func(a *Asset) []int {
		var out []int
		for _, e := range a.Evidence {
			out = append(out, e.Line)
		}
		return out
	}

	inv := NewInventory()
	stored := add(inv, ev(1), ev(2))
	add(inv, ev(2), ev(3), ev(3), ev(1), ev(4))
	if got := lines(stored); !slices.Equal(got, []int{1, 2, 3, 4}) {
		t.Errorf("after merge: lines %v, want [1 2 3 4]", got)
	}
	// An extractor may append to the asset Add returned; the next merge
	// must still treat that occurrence as present.
	stored.Evidence = append(stored.Evidence, ev(5))
	add(inv, ev(5), ev(6))
	if got := lines(stored); !slices.Equal(got, []int{1, 2, 3, 4, 5, 6}) {
		t.Errorf("after append and merge: lines %v, want [1 2 3 4 5 6]", got)
	}
	// Occurrences differing only in context are different.
	add(inv, Evidence{Location: "fw.conf", Line: 1, Symbol: "s", Context: "vdom root"})
	if got := len(stored.Evidence); got != 7 {
		t.Errorf("evidence count %d, want 7", got)
	}
	if len(inv.Assets) != 1 || len(inv.Warnings) != 0 {
		t.Errorf("assets %d warnings %v", len(inv.Assets), inv.Warnings)
	}
}

// addTunnels inventories n tunnels sharing one algorithm, each its own
// protocol component, and returns the inventory and how long it took.
func addTunnels(n int) (*Inventory, time.Duration) {
	inv := NewInventory()
	start := time.Now()
	for i := 0; i < n; i++ {
		name := "t" + strconv.Itoa(i)
		ev := []Evidence{{Location: "fw.conf", Line: i + 1, Symbol: "vpn ipsec phase1-interface/" + name + "/proposal"}}
		alg := inv.Add(&Asset{Type: AssetTypeAlgorithm, Name: "AES-256-GCM", Alg: &Algorithm{Primitive: "ae"}, Evidence: ev})
		inv.Add(&Asset{Type: AssetTypeProtocol, Name: name, Proto: &Protocol{Type: "ike", Refs: []string{alg.ID}}, Evidence: ev})
	}
	return inv, time.Since(start)
}

// TestAddScalesLinearly: inventorying 2n tunnels that share an algorithm
// must take about twice as long as n, not four times. With a linear scan
// for duplicate evidence it was quadratic (100,000 tunnels took 23 s), and a
// crafted backup with millions of tunnels would not finish. The sizes are
// run interleaved, three rounds, and the fastest time of each is compared,
// so other tests running at the same time do not decide the result. Linear
// code gives a ratio near 2 and the quadratic version near 4; the test fails
// above 3.
func TestAddScalesLinearly(t *testing.T) {
	n := 100_000
	if raceEnabled || testing.Short() {
		n = 20_000
	}
	best := map[int]time.Duration{}
	for round := 0; round < 3; round++ {
		for _, size := range []int{n, 2 * n} {
			inv, d := addTunnels(size)
			if len(inv.Assets) != size+1 || len(inv.Assets[0].Evidence) != size {
				t.Fatalf("%d tunnels: assets %d, shared evidence %d", size, len(inv.Assets), len(inv.Assets[0].Evidence))
			}
			if b, ok := best[size]; !ok || d < b {
				best[size] = d
			}
		}
	}
	ratio := float64(best[2*n]) / float64(best[n])
	t.Logf("%d tunnels in %v, %d in %v: ratio %.2f", n, best[n].Round(time.Millisecond), 2*n, best[2*n].Round(time.Millisecond), ratio)
	if ratio > 3 {
		t.Errorf("doubling the tunnels multiplied the time by %.2f, want about 2 (linear); above 3 suggests quadratic growth", ratio)
	}
}

// BenchmarkAdd1500kTunnels inventories 1.5 million tunnels sharing one
// algorithm (about 10 s on the development machine), for a sense of scale:
// go test -run '^$' -bench Add1500k ./pkg/model
func BenchmarkAdd1500kTunnels(b *testing.B) {
	for b.Loop() {
		addTunnels(1_500_000)
	}
}

// BenchmarkAddSharedAlgorithm measures one merge into an algorithm already
// shared by many tunnels.
func BenchmarkAddSharedAlgorithm(b *testing.B) {
	inv := NewInventory()
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		inv.Add(&Asset{Type: AssetTypeAlgorithm, Name: "AES-256-GCM", Alg: &Algorithm{Primitive: "ae"},
			Evidence: []Evidence{{Location: "fw.conf", Line: i + 1, Symbol: "vpn ipsec phase1-interface/t/proposal"}}})
	}
}
