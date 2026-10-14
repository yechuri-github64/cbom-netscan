// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package algo

import (
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

func TestMarkQuantumVulnerable(t *testing.T) {
	three := 3
	cases := []struct {
		primitive string
		preset    *int
		want      *int // nil: left unset
	}{
		{"key-agree", nil, new(int)},
		{"signature", nil, new(int)},
		{"pke", nil, new(int)},  // RSA certificate keys
		{"kem", &three, &three}, // ML-KEM keeps its level
		{"kem", nil, nil},       // non-NIST PQC KEMs stay unset
		{"combiner", nil, nil},
		{"block-cipher", nil, nil},
		{"ae", nil, nil},
		{"mac", nil, nil},
		{"kdf", nil, nil},
		{"unknown", nil, nil},
	}
	for _, tc := range cases {
		a := model.Algorithm{Primitive: tc.primitive, NISTQuantumLevel: tc.preset}
		MarkQuantumVulnerable(&a)
		switch {
		case tc.want == nil && a.NISTQuantumLevel != nil:
			t.Errorf("%s: level = %d, want unset", tc.primitive, *a.NISTQuantumLevel)
		case tc.want != nil && (a.NISTQuantumLevel == nil || *a.NISTQuantumLevel != *tc.want):
			t.Errorf("%s: level = %v, want %d", tc.primitive, a.NISTQuantumLevel, *tc.want)
		}
	}
}
