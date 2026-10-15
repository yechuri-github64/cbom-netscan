// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"reflect"
	"slices"
)

// NewInventory creates an empty Inventory with the dedupe map initialised.
// Always use this constructor; the zero value of Inventory has a nil map
// and will panic on Add().
func NewInventory() *Inventory {
	return &Inventory{byKey: make(map[string]*Asset), seen: make(map[*Asset]*evidenceSet)}
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
// A new asset with an empty ID gets one from BOMRef(), using its first
// evidence location, so callers do not have to compute bom-refs. A duplicate
// is not given an ID: use the returned asset's.
//
// Add is O(1) per call, also for an asset that is a duplicate of one already
// stored many times (see merge).
func (inv *Inventory) Add(a *Asset) *Asset {
	key := string(a.Type) + "\x00" + a.Name + "\x00" + a.OID
	if existing, ok := inv.byKey[key]; ok {
		inv.merge(existing, a)
		return existing
	}

	// Only a new asset needs a bom-ref; a duplicate keeps the stored one.
	if a.ID == "" {
		loc := ""
		if len(a.Evidence) > 0 {
			loc = a.Evidence[0].Location
		}
		a.ID = BOMRef(a.Type, a.Name, loc)
	}

	inv.byKey[key] = a
	inv.Assets = append(inv.Assets, a)
	return a
}

// merge folds a duplicate into the stored asset so that the result does not
// depend on which extractor added the asset first:
//   - evidence occurrences are added unless an identical one is already there
//     (the same proposal line naming one algorithm twice gives one occurrence);
//   - properties are combined. If both set a key to different values, the
//     smaller value is kept, so the outcome is the same in either order, and
//     a merge-conflict warning names both values, because a real conflict
//     means two extractors disagree about the same component.
//
// The algorithm, protocol, certificate, or material details of the stored
// asset are kept; if the duplicate's details differ, that is also reported
// as a merge-conflict. extract/shared_test.go checks that the extractors
// define shared components identically.
func (inv *Inventory) merge(existing, a *Asset) {
	es := inv.seen[existing]
	if es == nil || es.n > len(existing.Evidence) {
		es = &evidenceSet{set: make(map[Evidence]struct{}, len(existing.Evidence)+len(a.Evidence))}
		inv.seen[existing] = es
	}
	for _, ev := range existing.Evidence[es.n:] {
		es.set[ev] = struct{}{}
	}
	for _, ev := range a.Evidence {
		if _, dup := es.set[ev]; !dup {
			es.set[ev] = struct{}{}
			existing.Evidence = append(existing.Evidence, ev)
		}
	}
	es.n = len(existing.Evidence)
	if len(a.Properties) > 0 && existing.Properties == nil {
		existing.Properties = map[string]string{}
	}
	keys := make([]string, 0, len(a.Properties))
	for k := range a.Properties {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		v := a.Properties[k]
		old, ok := existing.Properties[k]
		switch {
		case !ok:
			existing.Properties[k] = v
		case v != old:
			lo, hi := min(v, old), max(v, old)
			existing.Properties[k] = lo
			inv.conflict(existing, fmt.Sprintf("property %s was set to %q and to %q; kept %q", k, lo, hi, lo))
		}
	}
	if !reflect.DeepEqual(existing.Alg, a.Alg) || !reflect.DeepEqual(existing.Proto, a.Proto) ||
		!reflect.DeepEqual(existing.Cert, a.Cert) || !reflect.DeepEqual(existing.Mat, a.Mat) {
		inv.conflict(existing, "two copies have different algorithm, protocol, certificate, or material details; kept the first")
	}
}

func (inv *Inventory) conflict(a *Asset, detail string) {
	inv.AddWarning(Warning{
		Code:    "merge-conflict",
		Message: fmt.Sprintf("component %q: %s", a.Name, detail),
		Ev:      Evidence{Symbol: a.Name},
	})
}

// AddWarning appends a warning to the inventory.
func (inv *Inventory) AddWarning(w Warning) {
	inv.Warnings = append(inv.Warnings, w)
}

// AddSource records a source artefact.  The Reader is not consumed here.
func (inv *Inventory) AddSource(s Source) {
	inv.Sources = append(inv.Sources, s)
}
