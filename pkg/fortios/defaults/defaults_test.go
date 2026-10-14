// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package defaults_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
)

// requiredFields are the fields every table must define, so an extractor
// never silently falls back to "unknown" because a table forgot one.
var requiredFields = map[string][]string{
	"system global": {
		"admin-https-ssl-versions", "admin-https-ssl-ciphersuites", "admin-https-ssl-banned-ciphers",
		"admin-server-cert", "strong-crypto", "ssl-static-key-ciphers",
	},
	"system ssh-config":          {"ssh-enc-algo", "ssh-kex-algo", "ssh-mac-algo", "ssh-hsk-algo"},
	"vpn ipsec phase1-interface": {"ike-version", "proposal", "dhgrp", "authmethod", "signature-hash-alg"},
	"vpn ipsec phase1":           {"ike-version", "proposal", "dhgrp", "authmethod", "signature-hash-alg"},
	"vpn ipsec phase2-interface": {"proposal", "pfs", "dhgrp"},
	"vpn ipsec phase2":           {"proposal", "pfs", "dhgrp"},
	"vpn ssl settings":           {"algorithm", "banned-cipher", "ciphersuite", "ssl-min-proto-ver", "ssl-max-proto-ver", "tls-groups", "servercert"},
}

func TestTables_WellFormed(t *testing.T) {
	versionRE := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	ts := defaults.Tables()
	if len(ts) == 0 {
		t.Fatal("no embedded tables")
	}
	for _, tb := range ts {
		if tb.Name == "" || len(tb.Versions) == 0 {
			t.Errorf("table %q: missing name or versions", tb.Name)
		}
		for _, v := range tb.Versions {
			if !versionRE.MatchString(v) {
				t.Errorf("table %s: version %q is not maj.min.patch", tb.Name, v)
			}
		}
		for section, fields := range requiredFields {
			for _, f := range fields {
				got, ok := tb.Field(section, f)
				if !ok {
					t.Errorf("table %s: missing %s / %s", tb.Name, section, f)
					continue
				}
				checkField(t, tb.Name+": "+section+" / "+f, got)
				for v, o := range got.ByVersion {
					checkField(t, tb.Name+": "+section+" / "+f+" @"+v, o)
				}
			}
		}
	}
}

// checkField: a default has a source, and either a value list or is marked
// undocumented (never both).
func checkField(t *testing.T, where string, f defaults.Field) {
	t.Helper()
	switch {
	case f.Source == "":
		t.Errorf("%s: no source", where)
	case f.Undocumented && f.Value != nil:
		t.Errorf("%s: undocumented but has a value", where)
	case !f.Undocumented && f.Value == nil:
		t.Errorf("%s: no value list (use [] for an empty default, or undocumented)", where)
	}
}

// TestIPsecDefaultsByVersion pins the per-version IPsec defaults from the
// research notes (§3.3, §3.4, §9).
func TestIPsecDefaultsByVersion(t *testing.T) {
	cases := []struct {
		version, section, field, want string // want "undocumented" for no default
		noteHas                       string
	}{
		{"7.4.12", "vpn ipsec phase1-interface", "dhgrp", "14", "20 and 21"},
		{"7.6.4", "vpn ipsec phase1-interface", "dhgrp", "14", "20 and 21"},
		{"7.6.5", "vpn ipsec phase1-interface", "dhgrp", "20", "Model-dependent"},
		{"7.6.6", "vpn ipsec phase1", "dhgrp", "20", "Model-dependent"},
		{"7.6.7", "vpn ipsec phase1-interface", "dhgrp", "20", "20 and 21"},
		{"7.6.7", "vpn ipsec phase2-interface", "dhgrp", "20", ""},
		{"8.0.1", "vpn ipsec phase2", "dhgrp", "20", ""},
		{"7.6.7", "vpn ipsec phase1-interface", "ike-version", "1", ""},
		{"8.0.1", "vpn ipsec phase1-interface", "ike-version", "2", "upgrading does not change"},
		{"7.6.7", "vpn ipsec phase1-interface", "signature-hash-alg", "sha2-512", ""},
		{"8.0.1", "vpn ipsec phase1-interface", "signature-hash-alg", "identity", ""},
		{"7.6.7", "vpn ipsec phase2-interface", "pfs", "enable", ""},
		{"7.6.7", "vpn ipsec phase1-interface", "addke1", "", ""},
		{"7.6.7", "vpn ipsec phase1-interface", "proposal", "undocumented", ""},
		{"8.0.1", "vpn ipsec phase2", "proposal", "undocumented", ""},
		{"7.4.12", "vpn ssl settings", "tls-groups", "undocumented", ""},
		{"7.6.4", "vpn ssl settings", "tls-groups", "undocumented", ""},
		{"7.6.5", "vpn ssl settings", "tls-groups", "P-521 P-384 ML-KEM768 ML-KEM1024 P-384-MLKEM1024 P-256-MLKEM768 X25519-MLKEM768 X448 FFDHE4096 FFDHE6144 FFDHE8192", ""},
		{"8.0.1", "vpn ssl settings", "tls-groups", "P-521 P-384 ML-KEM768 ML-KEM1024 P-384-MLKEM1024 P-256-MLKEM768 X25519-MLKEM768 X448 FFDHE4096 FFDHE6144 FFDHE8192", ""},
		{"7.6.7", "vpn ssl settings", "ssl-min-proto-ver", "tls1-2", ""},
		{"7.6.7", "vpn ssl settings", "banned-cipher", "SHA1 SHA256 SHA384", ""},
		{"7.4.12", "vpn ssl settings", "dtls-tunnel", "enable", ""},
	}
	for _, tc := range cases {
		d := defaults.ForVersion(tc.version)
		f, ok := d.Field(tc.section, tc.field)
		if !ok {
			t.Errorf("%s %s / %s: missing", tc.version, tc.section, tc.field)
			continue
		}
		got := strings.Join(f.Value, " ")
		if f.Undocumented {
			got = "undocumented"
		}
		if got != tc.want {
			t.Errorf("%s %s / %s = %q, want %q", tc.version, tc.section, tc.field, got, tc.want)
		}
		if tc.noteHas != "" && !strings.Contains(f.Note, tc.noteHas) {
			t.Errorf("%s %s / %s note %q lacks %q", tc.version, tc.section, tc.field, f.Note, tc.noteHas)
		}
		if f.ByVersion != nil {
			t.Errorf("%s %s / %s: resolved field still carries ByVersion", tc.version, tc.section, tc.field)
		}
	}
	if _, ok := defaults.ForVersion("7.6.7").Field("vpn ssl settings", "dtls-tunnel"); ok {
		t.Errorf("7.6.7 has a dtls-tunnel default, but DTLS settings are 7.4.12-only")
	}
	if _, ok := defaults.ForVersion("7.4.12").Field("vpn ipsec phase1-interface", "addke1"); ok {
		t.Errorf("7.4.12 has an addke1 default, but addke is absent before 7.6.3")
	}
}

func TestForVersion(t *testing.T) {
	cases := []struct {
		version, want string // want "" means no table
	}{
		{"7.4.12", "7.4"},
		{"7.4.8", ""},
		{"7.6.2", ""},
		{"7.6.3", "7.6"},
		{"7.6.7", "7.6"},
		{"8.0.0", ""},
		{"8.0.1", "8.0"},
		{"7.0.8", ""},
	}
	for _, tc := range cases {
		got := defaults.ForVersion(tc.version)
		switch {
		case tc.want == "" && got != nil:
			t.Errorf("ForVersion(%s) = table %s, want none", tc.version, got.Name)
		case tc.want != "" && (got == nil || got.Name != tc.want):
			t.Errorf("ForVersion(%s) = %v, want table %s", tc.version, got, tc.want)
		}
	}
}

// TestKexDefaults pins the one value that differs between release lines.
func TestKexDefaults(t *testing.T) {
	const pq = "mlkem768x25519-sha256"
	for version, wantPQ := range map[string]bool{"7.4.12": false, "7.6.7": false, "8.0.1": true} {
		f, ok := defaults.ForVersion(version).Field("system ssh-config", "ssh-kex-algo")
		if !ok {
			t.Fatalf("%s: no ssh-kex-algo default", version)
		}
		if got := slices.Contains(f.Value, pq); got != wantPQ {
			t.Errorf("%s: ssh-kex-algo default contains %s = %v, want %v", version, pq, got, wantPQ)
		}
	}
}
