// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package ipsec

import (
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/field"
)

// TestDefaultsUseKnownTokens fails if a defaults table, including its
// per-version overrides, holds an IPsec token the extractor does not know.
func TestDefaultsUseKnownTokens(t *testing.T) {
	phase1 := map[string]field.Spec{
		"ike-version": specIKEVersion, "dhgrp": specDHGroup,
		"authmethod": specAuth, "signature-hash-alg": specSigHash,
	}
	phase2 := map[string]field.Spec{"pfs": specPFS, "dhgrp": specDHGroup}
	for i := 1; i <= 7; i++ {
		k := "addke" + string(rune('0'+i))
		phase1[k], phase2[k] = specAddke, specAddke
	}

	for _, tb := range defaults.Tables() {
		for _, fam := range families {
			for section, specs := range map[string]map[string]field.Spec{fam.phase1: phase1, fam.phase2: phase2} {
				for name, sp := range specs {
					f, ok := tb.Field(section, name)
					if !ok {
						continue // addke is absent before 7.6.3
					}
					vals := [][]string{f.Value}
					for _, o := range f.ByVersion {
						vals = append(vals, o.Value)
					}
					for _, v := range vals {
						for _, tok := range v {
							if !sp.Known[tok] {
								t.Errorf("table %s: %s / %s default %q is not a known token", tb.Name, section, name, tok)
							}
						}
					}
				}
			}
		}
	}
}

// TestProposalsDecompose checks that every known proposal token maps to at
// least one algorithm, so a valid token never silently yields nothing.
func TestProposalsDecompose(t *testing.T) {
	for tok := range specP1Proposal.Known {
		cipher, hash, _ := splitProposal(tok)
		if _, ok := ciphers[cipher]; !ok {
			t.Errorf("phase1 %s: cipher %q has no algorithm", tok, cipher)
		}
		if _, ok := hashes[hash]; !ok {
			t.Errorf("phase1 %s: hash %q has no algorithm", tok, hash)
		}
	}
	for tok := range specP2Proposal.Known {
		cipher, hash, _ := splitProposal(tok)
		_, c := ciphers[cipher]
		_, h := hashes[hash]
		if !c && !h {
			t.Errorf("phase2 %s: neither %q nor %q has an algorithm", tok, cipher, hash)
		}
	}
}
