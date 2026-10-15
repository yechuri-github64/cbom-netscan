// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"strconv"
	"testing"
)

func tunnel(i int) *Asset {
	return &Asset{Type: AssetTypeProtocol, Name: "t" + strconv.Itoa(i), Proto: &Protocol{Type: "ike"},
		Evidence: []Evidence{{Location: "fw.conf", Line: i + 1}}}
}

// TestLimitsComponents: the component limit stops storing new assets, and
// Exceeded reports it.
func TestLimitsComponents(t *testing.T) {
	inv := NewInventory()
	inv.Limits = Limits{Components: 3}
	for i := 0; i < 3; i++ {
		inv.Add(tunnel(i))
	}
	if err := inv.Exceeded(); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	extra := inv.Add(tunnel(3))
	var le *LimitError
	if err := inv.Exceeded(); !errors.As(err, &le) || le.Kind != "components" || le.Limit != 3 {
		t.Fatalf("Exceeded() = %v, want a components LimitError", err)
	}
	if extra.ID == "" {
		t.Errorf("an asset past the limit has no bom-ref; callers still use it")
	}
	// Nothing more is stored: assets, evidence, warnings.
	inv.Add(tunnel(4))
	inv.Add(tunnel(0)) // a duplicate would add evidence
	inv.AddWarning(Warning{Code: "x"})
	if len(inv.Assets) != 3 || len(inv.Assets[0].Evidence) != 1 || len(inv.Warnings) != 0 {
		t.Errorf("after the limit: %d assets, %d occurrences on t0, %d warnings; want 3, 1, 0",
			len(inv.Assets), len(inv.Assets[0].Evidence), len(inv.Warnings))
	}
}

// TestLimitsEvidence: evidence occurrences from new assets and from merges,
// and warnings, all count toward the evidence limit. Repeating one name adds
// no components but is still bounded.
func TestLimitsEvidence(t *testing.T) {
	inv := NewInventory()
	inv.Limits = Limits{Components: 100, Evidence: 5}
	alg := func(line int) *Asset {
		return &Asset{Type: AssetTypeAlgorithm, Name: "AES-256-GCM", Alg: &Algorithm{Primitive: "ae"},
			Evidence: []Evidence{{Location: "fw.conf", Line: line}}}
	}
	inv.Add(alg(1))                    // 1
	inv.Add(alg(2))                    // 2 (merged)
	inv.Add(alg(2))                    // still 2: an identical occurrence is not stored
	inv.AddWarning(Warning{Code: "w"}) // 3
	inv.Add(alg(3))                    // 4
	inv.Add(alg(4))                    // 5
	if err := inv.Exceeded(); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	inv.Add(alg(5)) // 6
	var le *LimitError
	if err := inv.Exceeded(); !errors.As(err, &le) || le.Kind != "evidence" || le.Limit != 5 {
		t.Fatalf("Exceeded() = %v, want an evidence LimitError", err)
	}
	if len(inv.Assets) != 1 {
		t.Errorf("assets = %d, want 1 (one repeated name)", len(inv.Assets))
	}
	n := len(inv.Assets[0].Evidence)
	inv.Add(alg(6))
	inv.AddWarning(Warning{Code: "w"})
	if len(inv.Assets[0].Evidence) != n || len(inv.Warnings) != 1 {
		t.Errorf("evidence or warnings grew after the limit")
	}
}

// TestLimitsZeroMeansNone: an inventory without limits never reports one.
func TestLimitsZeroMeansNone(t *testing.T) {
	inv := NewInventory()
	for i := 0; i < 1000; i++ {
		inv.Add(tunnel(i))
		inv.AddWarning(Warning{Code: "w"})
	}
	if err := inv.Exceeded(); err != nil || len(inv.Assets) != 1000 {
		t.Errorf("Exceeded() = %v with %d assets, want nil and 1000", err, len(inv.Assets))
	}
}
