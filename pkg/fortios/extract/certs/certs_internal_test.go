// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/x509"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCABFMaxDays checks each step of Baseline Requirements §6.3.2 at the
// last second before it and the first second of it.
func TestCABFMaxDays(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		issued string
		want   int
	}{
		{"2020-09-01T00:00:00Z", 398},
		{"2026-03-14T23:59:59Z", 398},
		{"2026-03-15T00:00:00Z", 200},
		{"2027-03-14T23:59:59Z", 200},
		{"2027-03-15T00:00:00Z", 100},
		{"2029-03-14T23:59:59Z", 100},
		{"2029-03-15T00:00:00Z", 47},
		{"2035-01-01T00:00:00Z", 47},
		// A notBefore in another zone is compared as an instant.
		{"2027-03-15T01:00:00+02:00", 200},
	} {
		if got, _ := cabfMaxDays(at(tc.issued)); got != tc.want {
			t.Errorf("cabfMaxDays(%s) = %d, want %d", tc.issued, got, tc.want)
		}
	}
}

// TestValidityDays: the period is inclusive and any part of a day counts, so
// a certificate whose notAfter is exactly N days after notBefore is valid
// for N+1 days, and one second less is N days.
func TestValidityDays(t *testing.T) {
	nb := time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		after time.Duration
		want  int
	}{
		{0, 1},
		{time.Second, 1},
		{24*time.Hour - time.Second, 1},
		{24 * time.Hour, 2},
		{100*24*time.Hour - time.Second, 100}, // the longest certificate allowed from 2027-03-15
		{100 * 24 * time.Hour, 101},           // one second too long
	} {
		c := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(tc.after)}
		if got := validityDays(c); got != tc.want {
			t.Errorf("validityDays(notAfter = notBefore + %v) = %d, want %d", tc.after, got, tc.want)
		}
	}
}

// TestSignatureNamesDoNotShadowKeyNames: key and signature algorithm
// components share one namespace of bom-refs, so a signature algorithm may
// share a key algorithm's name only if it is the same algorithm with the
// same definition (pure Ed25519). Covers every signature algorithm
// crypto/x509 knows.
func TestSignatureNamesDoNotShadowKeyNames(t *testing.T) {
	for sa := x509.SignatureAlgorithm(1); sa < 64; sa++ {
		name := sa.String()
		if _, err := strconv.Atoi(name); err == nil {
			continue // not a known algorithm
		}
		got := signatureAlgorithm(&parsed{cert: &x509.Certificate{SignatureAlgorithm: sa}, sigOID: "oid"})
		switch {
		case got.name == "Ed25519":
			if want := ed25519Alg("oid"); !reflect.DeepEqual(got, want) {
				t.Errorf("Ed25519 signature = %+v, key = %+v; want one definition", got, want)
			}
		case strings.HasPrefix(got.name, "RSA-"), strings.HasPrefix(got.name, "ECDSA-P"), strings.HasPrefix(got.name, "OID "):
			t.Errorf("signature algorithm %v is named %q, like a key algorithm", sa, got.name)
		}
	}
}
