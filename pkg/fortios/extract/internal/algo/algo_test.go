// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package algo

import (
	"slices"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

func ptr(n int) *int { return &n }

func TestComplete(t *testing.T) {
	cases := []struct {
		name      string
		in        model.Algorithm
		classical *int
		funcs     []string
		nist      *int
	}{
		{"AES-256-GCM", model.Algorithm{Primitive: "ae", Mode: "gcm", ParameterSetIdentifier: "256"}, ptr(256), []string{"encrypt", "decrypt"}, nil},
		{"3DES-CBC", model.Algorithm{Primitive: "block-cipher", Mode: "cbc"}, ptr(112), []string{"encrypt", "decrypt"}, nil},
		// SP 800-57 Part 1 Rev. 5 Table 3, HMAC column, not collision resistance.
		{"HMAC-SHA1", model.Algorithm{Primitive: "mac"}, ptr(128), []string{"tag"}, nil},
		{"HMAC-SHA256", model.Algorithm{Primitive: "mac"}, ptr(256), []string{"tag"}, nil},
		{"HMAC-SHA384", model.Algorithm{Primitive: "mac"}, ptr(256), []string{"tag"}, nil},
		{"PRF-HMAC-SHA256", model.Algorithm{Primitive: "kdf"}, ptr(256), []string{"keyderive"}, nil},
		// Not rated by Table 3, and RC4 is broken whatever its key size.
		{"HMAC-MD5", model.Algorithm{Primitive: "mac"}, nil, []string{"tag"}, nil},
		{"UMAC-128", model.Algorithm{Primitive: "mac"}, nil, []string{"tag"}, nil},
		{"RC4", model.Algorithm{Primitive: "stream-cipher"}, nil, []string{"encrypt", "decrypt"}, nil},
		{"NULL", model.Algorithm{Primitive: "other", ClassicalSecurityLevel: ptr(0)}, ptr(0), nil, nil},
		{"X25519", model.Algorithm{Primitive: "key-agree", Curve: "x25519"}, ptr(128), []string{"keyderive"}, ptr(0)},
		{"MODP-2048", model.Algorithm{Primitive: "key-agree", ParameterSetIdentifier: "2048"}, ptr(112), []string{"keyderive"}, ptr(0)},
		{"RSA-2048", model.Algorithm{Primitive: "pke", ParameterSetIdentifier: "2048"}, ptr(112), []string{"encrypt", "decrypt", "sign", "verify"}, ptr(0)},
		{"Ed25519", model.Algorithm{Primitive: "signature", Curve: "ed25519"}, ptr(128), []string{"sign", "verify"}, ptr(0)},
		{"ML-KEM-768", model.Algorithm{Primitive: "kem", ParameterSetIdentifier: "768", NISTQuantumLevel: ptr(3)}, nil, []string{"encapsulate", "decapsulate"}, ptr(3)},
		{"X25519MLKEM768", model.Algorithm{Primitive: "combiner"}, nil, nil, nil},
	}
	for _, tc := range cases {
		a := tc.in
		Complete(tc.name, &a)
		Complete(tc.name, &a) // idempotent
		switch {
		case tc.classical == nil && a.ClassicalSecurityLevel != nil:
			t.Errorf("%s: classical = %d, want unset", tc.name, *a.ClassicalSecurityLevel)
		case tc.classical != nil && (a.ClassicalSecurityLevel == nil || *a.ClassicalSecurityLevel != *tc.classical):
			t.Errorf("%s: classical = %v, want %d", tc.name, a.ClassicalSecurityLevel, *tc.classical)
		}
		if !slices.Equal(a.CryptoFunctions, tc.funcs) {
			t.Errorf("%s: cryptoFunctions = %v, want %v", tc.name, a.CryptoFunctions, tc.funcs)
		}
		switch {
		case tc.nist == nil && a.NISTQuantumLevel != nil:
			t.Errorf("%s: nist = %d, want unset", tc.name, *a.NISTQuantumLevel)
		case tc.nist != nil && (a.NISTQuantumLevel == nil || *a.NISTQuantumLevel != *tc.nist):
			t.Errorf("%s: nist = %v, want %d", tc.name, a.NISTQuantumLevel, *tc.nist)
		}
	}
}

func TestOID(t *testing.T) {
	if got, want := OID("AES-256-GCM"), "2.16.840.1.101.3.4.1.46"; got != want {
		t.Errorf("AES-256-GCM OID = %q, want %q", got, want)
	}
	if got, want := OID("ML-KEM-768"), "2.16.840.1.101.3.4.4.2"; got != want {
		t.Errorf("ML-KEM-768 OID = %q, want %q", got, want)
	}
	if got, want := OID("RSA-2048"), "1.2.840.113549.1.1.1"; got != want {
		t.Errorf("RSA-2048 OID = %q, want %q", got, want)
	}
	// NIST's aes arcs 9, 29, and 49 are AES-GMAC (RFC 9044); CTR has none.
	for _, name := range []string{"AES-128-CTR", "AES-192-CTR", "AES-256-CTR"} {
		if got := OID(name); got != "" {
			t.Errorf("%s OID = %q, want empty", name, got)
		}
	}
	if got := OID("MODP-2048"); got != "" {
		t.Errorf("MODP-2048 OID = %q, want empty", got)
	}
	if got := OID("KYBER-768"); got != "" {
		t.Errorf("KYBER-768 OID = %q, want empty", got)
	}
}

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
