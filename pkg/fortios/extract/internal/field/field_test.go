// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package field

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const ssl = "vpn ssl settings"

var anyToken = Spec{Known: map[string]bool{"tls1-2": true, "tls1-3": true}, Pattern: regexp.MustCompile(`^[a-z0-9-]+$`)}

func resolver(version string) *Resolver {
	return &Resolver{Loc: "fw.conf", Inv: model.NewInventory(), Defaults: defaults.ForVersion(version)}
}

// TestResolveSources covers each way a field gets its value: configured, a
// documented default (also after unset, and per build), and unknown (no
// table, not documented for this build, or not in the table).
func TestResolveSources(t *testing.T) {
	for _, tc := range []struct {
		name, version, field string
		attr                 *tree.Attr
		source               string
		tokens               []string
		line                 int
		undocumented         bool
	}{
		{"configured", "7.6.7", "ssl-min-proto-ver", &tree.Attr{Values: []string{"tls1-3"}, Line: 5}, Configured, []string{"tls1-3"}, 5, false},
		{"configured_without_table", "7.2.4", "ssl-min-proto-ver", &tree.Attr{Values: []string{"tls1-3"}, Line: 5}, Configured, []string{"tls1-3"}, 5, false},
		{"configured_empty", "7.6.7", "servercert", &tree.Attr{Values: []string{}, Line: 7}, Configured, nil, 7, false},
		{"absent_default", "7.6.7", "ssl-min-proto-ver", nil, Default, []string{"tls1-2"}, 0, false},
		{"unset_is_default", "7.6.7", "ssl-min-proto-ver", &tree.Attr{Unset: true, Line: 9}, Default, []string{"tls1-2"}, 0, false},
		{"default_by_build", "7.6.5", "tls-groups", nil, Default, []string{"P-521", "P-384", "ML-KEM768", "ML-KEM1024", "P-384-MLKEM1024", "P-256-MLKEM768", "X25519-MLKEM768", "X448", "FFDHE4096", "FFDHE6144", "FFDHE8192"}, 0, false},
		{"undocumented_for_build", "7.6.4", "tls-groups", nil, Unknown, nil, 0, true},
		{"no_table", "7.2.4", "ssl-min-proto-ver", nil, Unknown, nil, 0, false},
		{"not_in_table", "7.6.7", "no-such-field", nil, Unknown, nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := resolver(tc.version)
			v := r.Resolve(tc.attr, ssl, tc.field, ssl+"/"+tc.field, "vdom root", Spec{Pattern: regexp.MustCompile(`.`), Freeform: true})
			if v.Source != tc.source || !slices.Equal(v.Tokens, tc.tokens) || v.Line != tc.line || v.Default.Undocumented != tc.undocumented {
				t.Errorf("Resolve = source %s tokens %q line %d undocumented %v; want %s %q %d %v",
					v.Source, v.Tokens, v.Line, v.Default.Undocumented, tc.source, tc.tokens, tc.line, tc.undocumented)
			}
			if v.Field != tc.field || v.Symbol != ssl+"/"+tc.field || v.Context != "vdom root" {
				t.Errorf("Resolve identity = %q %q %q", v.Field, v.Symbol, v.Context)
			}
			if tc.source == Default && v.Default.Source == "" {
				t.Errorf("default without its source document")
			}
		})
	}
}

// TestCleanTokens: known tokens are kept; unknown ones matching the pattern
// are kept and warned about (silently when freeform); anything else is
// dropped and the warning does not show it; duplicates and empty tokens go.
func TestCleanTokens(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sp       Spec
		in       []string
		want     []string
		warnings []string // message fragments, in order
	}{
		{"known", anyToken, []string{"tls1-2", "tls1-3"}, []string{"tls1-2", "tls1-3"}, nil},
		{"duplicates_and_empty", anyToken, []string{"tls1-2", "", "tls1-2"}, []string{"tls1-2"}, nil},
		{"unknown_option_kept", anyToken, []string{"tls1-4"}, []string{"tls1-4"}, []string{`unknown option "tls1-4"; kept as unknown`}},
		{"invalid_dropped_unshown", anyToken, []string{"tls1-2", "ENC c3ludGhldGlj"}, []string{"tls1-2"}, []string{"not a valid option; it was dropped and is not shown"}},
		{"no_pattern_drops_unknown", Spec{Known: map[string]bool{"a": true}}, []string{"a", "b"}, []string{"a"}, []string{"dropped"}},
		{"freeform_silent", Spec{Pattern: regexp.MustCompile(`^[A-Za-z_]+$`), Freeform: true}, []string{"Fortinet_Factory"}, []string{"Fortinet_Factory"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := resolver("7.6.7")
			v := r.Resolve(&tree.Attr{Values: tc.in, Line: 3}, ssl, "x", ssl+"/x", "", tc.sp)
			if !slices.Equal(v.Tokens, tc.want) {
				t.Errorf("tokens = %q, want %q", v.Tokens, tc.want)
			}
			if len(r.Inv.Warnings) != len(tc.warnings) {
				t.Fatalf("warnings = %+v, want %d", r.Inv.Warnings, len(tc.warnings))
			}
			for i, w := range r.Inv.Warnings {
				if w.Code != "unknown-token" || !strings.Contains(w.Message, tc.warnings[i]) || w.Ev.Line != 3 || w.Ev.Symbol != ssl+"/x" {
					t.Errorf("warning %d = %+v, want unknown-token at line 3 containing %q", i, w, tc.warnings[i])
				}
				if strings.Contains(w.Message, "c3ludGhldGlj") {
					t.Errorf("warning shows the dropped token: %s", w.Message)
				}
			}
		})
	}
}

// TestRecord: the provenance properties written for each source.
func TestRecord(t *testing.T) {
	r := resolver("7.6.7")
	configured := r.Resolve(&tree.Attr{Values: []string{"tls1-3"}, Line: 5}, ssl, "ssl-min-proto-ver", ssl+"/ssl-min-proto-ver", "vdom root", anyToken)
	def := r.Resolve(nil, ssl, "ssl-max-proto-ver", ssl+"/ssl-max-proto-ver", "", anyToken)
	noted := r.Resolve(nil, "vpn ipsec phase1-interface", "dhgrp", "vpn ipsec phase1-interface/t/dhgrp", "", Spec{Pattern: regexp.MustCompile(`.`)})
	undocumented := resolver("7.6.4").Resolve(nil, ssl, "tls-groups", ssl+"/tls-groups", "", anyToken)
	plainUnknown := resolver("7.2.4").Resolve(nil, ssl, "algorithm", ssl+"/algorithm", "", anyToken)
	if noted.Default.Note == "" {
		t.Fatalf("fixture: the 7.6 dhgrp default should carry a note")
	}

	a := &model.Asset{Properties: map[string]string{}}
	r.Record(a, configured, true)
	r.Record(a, def, true)
	r.Record(a, noted, false)
	r.Record(a, undocumented, true)
	r.Record(a, plainUnknown, true)

	want := map[string]string{
		Prefix + "ssl-min-proto-ver:source": "configured",
		Prefix + "ssl-min-proto-ver:line":   "5",
		Prefix + "ssl-min-proto-ver:value":  "tls1-3",
		Prefix + "ssl-max-proto-ver:source": "default",
		Prefix + "ssl-max-proto-ver:value":  "tls1-3",
		Prefix + "defaults-table":           "7.6",
		Prefix + "dhgrp:source":             "default",
		Prefix + "tls-groups:source":        "unknown",
		Prefix + "algorithm:source":         "unknown",
	}
	for k, v := range want {
		if a.Properties[k] != v {
			t.Errorf("%s = %q, want %q", k, a.Properties[k], v)
		}
	}
	for k, wantSet := range map[string]bool{
		Prefix + "ssl-max-proto-ver:default-source": true,  // default: where it came from
		Prefix + "dhgrp:default-note":               true,  // default with a caveat
		Prefix + "dhgrp:value":                      false, // recorded without its value
		Prefix + "tls-groups:unknown-reason":        true,  // undocumented for this build
		Prefix + "tls-groups:value":                 false, // unknown: no value
		Prefix + "algorithm:unknown-reason":         false, // unknown, but no table to explain
		Prefix + "ssl-min-proto-ver:default-source": false, // configured: no default info
	} {
		if _, ok := a.Properties[k]; ok != wantSet {
			t.Errorf("%s present = %v, want %v (%q)", k, ok, wantSet, a.Properties[k])
		}
	}
	if !strings.Contains(a.Properties[Prefix+"tls-groups:unknown-reason"], "7.6.5") {
		t.Errorf("unknown-reason = %q", a.Properties[Prefix+"tls-groups:unknown-reason"])
	}
	// Only the configured value adds an evidence occurrence.
	wantEv := []model.Evidence{{Location: "fw.conf", Line: 5, Symbol: ssl + "/ssl-min-proto-ver", Context: "vdom root"}}
	if !slices.Equal(a.Evidence, wantEv) {
		t.Errorf("evidence = %+v, want %+v", a.Evidence, wantEv)
	}
}

func TestMarkConfiguredView(t *testing.T) {
	a := &model.Asset{Properties: map[string]string{}}
	MarkConfiguredView(a)
	if a.Properties[Prefix+"view"] != "configured" {
		t.Errorf("properties = %v", a.Properties)
	}
}

// TestNoDefaultsWarning: every extractor builds the same warning, so the CLI
// can print it once.
func TestNoDefaultsWarning(t *testing.T) {
	a, b := NoDefaultsWarning("7.2.4", "fw.conf"), NoDefaultsWarning("7.2.4", "fw.conf")
	if a != b {
		t.Errorf("two calls differ: %+v %+v", a, b)
	}
	if a.Code != "no-default-table" || !strings.Contains(a.Message, "FortiOS 7.2.4") || a.Ev != (model.Evidence{Location: "fw.conf", Line: 1, Symbol: "#config-version"}) {
		t.Errorf("warning = %+v", a)
	}
}
