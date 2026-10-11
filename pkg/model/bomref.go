// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// BOMRef returns a deterministic bom-ref for an asset.
//
// Format:
//
//	"crypto/" + first 16 hex characters of SHA-256(type NUL name NUL location)
//
// Using NUL (0x00) as field separator because it cannot appear in the
// field values, so there are no collisions between adjacent fields.
//
// Using only 16 hex chars (8 bytes, 64 bits) keeps bom-refs short while
// keeping the collision probability negligible for any realistic CBOM
// (< 1-in-a-trillion for up to ~10,000 assets).
//
// "location" is the evidence location (file path or "host:port") of the
// primary evidence occurrence.  Pass an empty string for hand-crafted or
// test assets where no specific location exists.
func BOMRef(t AssetType, name, location string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s", t, name, location)
	return "crypto/" + hex.EncodeToString(h.Sum(nil))[:16]
}
