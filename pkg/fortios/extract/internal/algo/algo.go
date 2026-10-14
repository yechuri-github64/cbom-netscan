// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package algo holds algorithm rules shared by the FortiOS extractors.
package algo

import "github.com/yechuri-github64/cbom-netscan/pkg/model"

// MarkQuantumVulnerable sets nistQuantumSecurityLevel to 0 on classical
// public-key algorithms (key agreement, signatures, and public-key
// encryption such as RSA certificate keys), which a quantum computer breaks.
// CycloneDX 1.6 defines 0 as "none of the categories are met", so
// post-quantum readiness does not depend on a consumer's heuristic.
//
// A level that is already set (ML-KEM) is kept. Symmetric algorithms,
// combiners, and PQC schemes that are not NIST standards are left unset,
// because their category is not a plain fact the tool can state.
func MarkQuantumVulnerable(a *model.Algorithm) {
	if a.NISTQuantumLevel != nil {
		return
	}
	switch a.Primitive {
	case "key-agree", "signature", "pke":
		zero := 0
		a.NISTQuantumLevel = &zero
	}
}
