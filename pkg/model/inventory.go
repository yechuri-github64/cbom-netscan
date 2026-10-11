// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package model

// NewInventory creates an empty Inventory with the dedupe map initialised.
// Always use this constructor; the zero value of Inventory has a nil map
// and will panic on Add().
func NewInventory() *Inventory {
	return &Inventory{byKey: make(map[string]*Asset)}
}

// Add inserts an asset into the inventory.
//
// Deduplication key: (Type, Name, OID).  If an asset with the same key
// already exists, the new asset's evidence is merged into the existing
// one instead of creating a duplicate component.  This is the expected
// behaviour when the same algorithm appears in multiple config blocks or
// in both a config file and a live TLS scan.
//
// Add sets a.ID via BOMRef() using the first evidence location if ID is
// empty, so callers do not have to compute bom-refs themselves.
func (inv *Inventory) Add(a *Asset) {
	if a.ID == "" {
		loc := ""
		if len(a.Evidence) > 0 {
			loc = a.Evidence[0].Location
		}
		a.ID = BOMRef(a.Type, a.Name, loc)
	}

	key := string(a.Type) + "\x00" + a.Name + "\x00" + a.OID
	if existing, ok := inv.byKey[key]; ok {
		existing.Evidence = append(existing.Evidence, a.Evidence...)
		return
	}

	inv.byKey[key] = a
	inv.Assets = append(inv.Assets, a)
}

// AddWarning appends a warning to the inventory.
func (inv *Inventory) AddWarning(w Warning) {
	inv.Warnings = append(inv.Warnings, w)
}

// AddSource records a source artefact.  The Reader is not consumed here.
func (inv *Inventory) AddSource(s Source) {
	inv.Sources = append(inv.Sources, s)
}
