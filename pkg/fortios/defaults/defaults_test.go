// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package defaults_test

import (
	"regexp"
	"slices"
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
	"system ssh-config": {"ssh-enc-algo", "ssh-kex-algo", "ssh-mac-algo", "ssh-hsk-algo"},
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
				if got.Value == nil || got.Source == "" {
					t.Errorf("table %s: %s / %s needs a value list and a source", tb.Name, section, f)
				}
			}
		}
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
