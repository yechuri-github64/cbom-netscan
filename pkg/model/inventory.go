// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package model

import "slices"

// NewInventory creates an empty Inventory with the dedupe map initialised.
// Always use this constructor; the zero value of Inventory has a nil map
// and will panic on Add().
func NewInventory() *Inventory {
	return &Inventory{byKey: make(map[string]*Asset)}
}

// Add inserts an asset into the inventory and returns the asset that is
// stored: a itself, or the existing asset it was merged into.
//
// Deduplication key: (Type, Name, OID).  If an asset with the same key
// already exists, the new asset's evidence is merged into the existing
// one instead of creating a duplicate component.  This is the expected
// behaviour when the same algorithm appears in multiple config blocks or
// in both a config file and a live TLS scan.  Callers that reference the
// asset from elsewhere must use the returned asset's ID, since the existing
// asset keeps its own ID.
//
// Add sets a.ID via BOMRef() using the first evidence location if ID is
// empty, so callers do not have to compute bom-refs themselves.
func (inv *Inventory) Add(a *Asset) *Asset {
	if a.ID == "" {
		loc := ""
		if len(a.Evidence) > 0 {
			loc = a.Evidence[0].Location
		}
		a.ID = BOMRef(a.Type, a.Name, loc)
	}

	key := string(a.Type) + "\x00" + a.Name + "\x00" + a.OID
	if existing, ok := inv.byKey[key]; ok {
		existing.merge(a)
		return existing
	}

	inv.byKey[key] = a
	inv.Assets = append(inv.Assets, a)
	return a
}

// merge folds a duplicate into the stored asset so that the result does not
// depend on which extractor added the asset first:
//   - evidence occurrences are added unless an identical one is already there
//     (the same proposal line naming one algorithm twice gives one occurrence);
//   - properties are combined; if both set a key to different values, the
//     smaller value is kept, so the outcome is the same in either order.
//
// The algorithm, protocol, certificate, or material details of the stored
// asset are kept. Extractors that share components must define them
// identically; extract/shared_test.go checks that.
func (existing *Asset) merge(a *Asset) {
	for _, ev := range a.Evidence {
		if !slices.Contains(existing.Evidence, ev) {
			existing.Evidence = append(existing.Evidence, ev)
		}
	}
	if len(a.Properties) > 0 && existing.Properties == nil {
		existing.Properties = map[string]string{}
	}
	for k, v := range a.Properties {
		if old, ok := existing.Properties[k]; !ok || v < old {
			existing.Properties[k] = v
		}
	}
}

// AddWarning appends a warning to the inventory.
func (inv *Inventory) AddWarning(w Warning) {
	inv.Warnings = append(inv.Warnings, w)
}

// AddSource records a source artefact.  The Reader is not consumed here.
func (inv *Inventory) AddSource(s Source) {
	inv.Sources = append(inv.Sources, s)
}
