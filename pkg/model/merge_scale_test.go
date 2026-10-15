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

// TestAddManyTunnels: 1.5 million tunnels sharing one algorithm, each its
// own protocol component, must be inventoried quickly. With a linear scan
// for duplicate evidence this was quadratic: 100,000 tunnels took 23 s, and
// a crafted backup with millions of tunnels would not finish. Under -race or
// -short it uses 200,000 tunnels, still far past where the quadratic version
// was too slow. The limit is generous (about 10 s alone, 30 s alongside the
// other packages' tests): it only has to tell linear from quadratic, which
// takes over an hour.
func TestAddManyTunnels(t *testing.T) {
	n, limit := 1_500_000, 120*time.Second
	if raceEnabled || testing.Short() {
		n, limit = 200_000, 120*time.Second
	}
	inv := NewInventory()
	start := time.Now()
	for i := 0; i < n; i++ {
		name := "t" + strconv.Itoa(i)
		ev := []Evidence{{Location: "fw.conf", Line: i + 1, Symbol: "vpn ipsec phase1-interface/" + name + "/proposal"}}
		alg := inv.Add(&Asset{Type: AssetTypeAlgorithm, Name: "AES-256-GCM", Alg: &Algorithm{Primitive: "ae"}, Evidence: ev})
		inv.Add(&Asset{Type: AssetTypeProtocol, Name: name, Proto: &Protocol{Type: "ike", Refs: []string{alg.ID}}, Evidence: ev})
	}
	elapsed := time.Since(start)
	t.Logf("%d tunnels in %v", n, elapsed.Round(time.Millisecond))
	if elapsed > limit {
		t.Errorf("%d tunnels took %v, want under %v", n, elapsed, limit)
	}
	if len(inv.Assets) != n+1 || len(inv.Assets[0].Evidence) != n {
		t.Errorf("assets %d, shared algorithm evidence %d; want %d and %d", len(inv.Assets), len(inv.Assets[0].Evidence), n+1, n)
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
