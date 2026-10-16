// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/x509"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
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
// same definition (pure Ed25519 and Ed448). Covers every signature algorithm
// crypto/x509 knows, and Ed448, which it does not.
func TestSignatureNamesDoNotShadowKeyNames(t *testing.T) {
	dsaKeyName := regexp.MustCompile(`^DSA-[0-9]+$`) // DSA-SHA256 is a signature name
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
		case strings.HasPrefix(got.name, "RSA-"), strings.HasPrefix(got.name, "ECDSA-P"), strings.HasPrefix(got.name, "OID "),
			dsaKeyName.MatchString(got.name):
			t.Errorf("signature algorithm %v is named %q, like a key algorithm", sa, got.name)
		}
	}
	ed448 := &parsed{cert: &x509.Certificate{}, sigOID: oidEd448, keyOID: oidEd448}
	if sig, key := signatureAlgorithm(ed448), keyAlgorithm(ed448); sig.name != "Ed448" || !reflect.DeepEqual(sig, key) {
		t.Errorf("Ed448 signature = %+v, key = %+v; want one Ed448 definition", sig, key)
	}
}

// FuzzScanCertField: the block scanner must end on any text, and the
// certificate text it returns must be one complete CERTIFICATE block with
// no other BEGIN line inside.
func FuzzScanCertField(f *testing.F) {
	f.Add("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
	f.Add("-----BEGIN PRIVATE KEY-----\nx\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
	f.Add("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----")
	f.Add("-----BEGIN -----\n-----END -----")
	f.Fuzz(func(t *testing.T, text string) {
		c := scanCertField(text)
		if c.cert == "" {
			return
		}
		lines := strings.Split(c.cert, "\n")
		if pemLabel(lines[0]) != "CERTIFICATE" || !isEndLine(lines[len(lines)-1], "CERTIFICATE") {
			t.Fatalf("certificate text is not one complete CERTIFICATE block")
		}
		for _, l := range lines[1:] {
			if pemLabel(l) != "" {
				t.Fatalf("certificate text contains another BEGIN line, so it could decode an inner block")
			}
		}
	})
}

// TestDocumentedCountingExamples pins the examples in the package
// documentation: a certificate whose notAfter is exactly 365 days after its
// notBefore counts as 366 days, one second less as 365; and the limit is
// chosen by notBefore alone, however late notAfter is.
func TestDocumentedCountingExamples(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	year := 365 * 24 * time.Hour
	if got := validityDays(&x509.Certificate{NotBefore: nb, NotAfter: nb.Add(year)}); got != 366 {
		t.Errorf("notAfter = notBefore + 365 days: %d days, want 366", got)
	}
	if got := validityDays(&x509.Certificate{NotBefore: nb, NotAfter: nb.Add(year - time.Second)}); got != 365 {
		t.Errorf("notAfter = notBefore + 365 days - 1s: %d days, want 365", got)
	}
	// Started a second before 2026-03-15 and ending years later: still the
	// 398-day rule, because only notBefore is used.
	start := time.Date(2026, 3, 14, 23, 59, 59, 0, time.UTC)
	if max, rule := cabfMaxDays(start); max != 398 || rule != "notBefore before 2026-03-15" {
		t.Errorf("cabfMaxDays(%s) = %d %q", start, max, rule)
	}
}

// TestPEMLabel: the label is read from a BEGIN line even with text after the
// closing dashes; anything else is not a BEGIN line.
func TestPEMLabel(t *testing.T) {
	for line, want := range map[string]string{
		"-----BEGIN PRIVATE KEY-----":            "PRIVATE KEY",
		"  -----BEGIN CERTIFICATE-----\r":        "CERTIFICATE",
		"-----BEGIN PRIVATE KEY----- trailing":   "PRIVATE KEY",
		"-----BEGIN RSA PRIVATE KEY-----x":       "RSA PRIVATE KEY",
		"-----BEGIN PRIVATE KEY":                 "",
		"x -----BEGIN PRIVATE KEY-----":          "",
		"-----BEGIN -----":                       "",
		"-----END PRIVATE KEY-----":              "",
		"c3ludGhldGlj":                           "",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----z": "ENCRYPTED PRIVATE KEY",
		"\uFEFF-----BEGIN PRIVATE KEY-----":      "PRIVATE KEY",
	} {
		if got := pemLabel(line); got != want {
			t.Errorf("pemLabel(%q) = %q, want %q", line, got, want)
		}
	}
	if !isEndLine("-----END PRIVATE KEY----- trailing", "PRIVATE KEY") || isEndLine("-----END RSA PRIVATE KEY-----", "PRIVATE KEY") {
		t.Errorf("isEndLine does not match the END line with trailing text, or matches another label")
	}
	// A byte order mark before the END line is skipped, as before BEGIN.
	if !isEndLine("\uFEFF-----END PRIVATE KEY-----", "PRIVATE KEY") || !isEndLine(" \uFEFF\uFEFF-----END CERTIFICATE-----\r", "CERTIFICATE") {
		t.Errorf("isEndLine does not skip a leading byte order mark")
	}
}

// TestNestedCertificateNotDecoded: a CERTIFICATE block with a BEGIN line
// inside is never handed to pem.Decode, so the inner block's body is never
// decoded; parsePEM says why.
func TestNestedCertificateNotDecoded(t *testing.T) {
	text := "-----BEGIN CERTIFICATE-----\nMIIB\n-----BEGIN EC PRIVATE KEY-----\nc3ludGhldGlj\n-----END EC PRIVATE KEY-----\nMIIB\n-----END CERTIFICATE-----"
	f := scanCertField(text)
	if f.cert != "" || f.nestedCerts != 1 || f.keyBlocks != 1 {
		t.Errorf("scanCertField = %+v, want no certificate text, 1 nested certificate, 1 key", f)
	}
	_, err := parsePEM(&tree.Attr{Values: []string{text}})
	if err == nil || !strings.Contains(err.Error(), "not decoded") {
		t.Errorf("parsePEM error = %v", err)
	}
}
