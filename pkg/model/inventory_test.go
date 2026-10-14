// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"fmt"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

func asset(props map[string]string, ev ...model.Evidence) *model.Asset {
	return &model.Asset{
		Type: model.AssetTypeAlgorithm, Name: "AES-256-GCM",
		Alg: &model.Algorithm{Primitive: "ae"}, Properties: props, Evidence: ev,
	}
}

var (
	evA = model.Evidence{Location: "fw.conf", Line: 5, Symbol: "vpn ipsec phase1-interface/t/proposal"}
	evB = model.Evidence{Location: "fw.conf", Line: 9, Symbol: "system ssh-config/ssh-enc-algo"}
)

func TestAdd_ReturnsStoredAsset(t *testing.T) {
	inv := model.NewInventory()
	first := inv.Add(asset(nil, evA))
	second := inv.Add(asset(nil, evB))
	if second != first || len(inv.Assets) != 1 {
		t.Fatalf("duplicate not merged: %d assets, same pointer %v", len(inv.Assets), second == first)
	}
	if first.ID == "" {
		t.Errorf("ID not set")
	}
}

func TestAdd_DedupesEvidence(t *testing.T) {
	inv := model.NewInventory()
	inv.Add(asset(nil, evA))
	inv.Add(asset(nil, evA)) // same proposal line naming the algorithm twice
	inv.Add(asset(nil, evB, evA))
	got := inv.Assets[0].Evidence
	if len(got) != 2 || got[0] != evA || got[1] != evB {
		t.Errorf("evidence = %+v, want [evA evB] with no duplicates", got)
	}
}

// TestAdd_MergeIsOrderIndependent adds the same two assets in both orders and
// expects the same properties: combined, and the smaller value on a conflict.
func TestAdd_MergeIsOrderIndependent(t *testing.T) {
	x := map[string]string{"cbom-netscan:a": "1", "cbom-netscan:conflict": "zeta"}
	y := map[string]string{"cbom-netscan:b": "2", "cbom-netscan:conflict": "alpha"}
	result := func(first, second map[string]string) string {
		inv := model.NewInventory()
		inv.Add(asset(clone(first)))
		inv.Add(asset(clone(second)))
		return fmt.Sprint(inv.Assets[0].Properties)
	}
	xy, yx := result(x, y), result(y, x)
	want := fmt.Sprint(map[string]string{"cbom-netscan:a": "1", "cbom-netscan:b": "2", "cbom-netscan:conflict": "alpha"})
	if xy != want || yx != want {
		t.Errorf("x then y = %s, y then x = %s, want %s for both", xy, yx, want)
	}

	inv := model.NewInventory()
	inv.Add(asset(nil))
	inv.Add(asset(map[string]string{"cbom-netscan:a": "1"}))
	if inv.Assets[0].Properties["cbom-netscan:a"] != "1" {
		t.Errorf("properties from a later duplicate were dropped when the first had none")
	}
}

func clone(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
