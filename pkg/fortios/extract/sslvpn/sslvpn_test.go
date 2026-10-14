// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package sslvpn_test

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/certs"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/sslvpn"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const (
	hdr767  = "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin\n"
	hdr764  = "#config-version=FGVMH6-7.6.4-FW-build3400-251001:opmode=0:vdom=0:user=admin\n"
	hdr7412 = "#config-version=FGVMH6-7.4.12-FW-build2900-260301:opmode=0:vdom=0:user=admin\n"
	hdr801  = "#config-version=FGVMH6-8.0.1-FW-build1500-260801:opmode=0:vdom=0:user=admin\n"
	hdr724  = "#config-version=FGVMH6-7.2.4-FW-build1396-230131:opmode=0:vdom=0:user=admin\n"

	tls = "FortiOS SSL VPN TLS "
)

var secretFragments = []string{"c3ludGhldGlj", "PRIVATE KEY", "BEGIN CERTIFICATE", "ENC "}

func pemFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../certs/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// localCert is a vpn certificate local block with one certificate.
func localCert(t *testing.T, name, pem string) string {
	return `config vpn certificate local
    edit "` + name + `"
        set private-key ENC c3ludGhldGljLWtleQ==
        set certificate "` + pemFile(t, pem) + `"
    next
end
`
}

// extract runs the certificate and SSL VPN extractors, as the CLI does.
func extract(t *testing.T, cfg string) *model.Inventory {
	t.Helper()
	tr, err := tree.Parse(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	inv := model.NewInventory()
	certs.Extract(tr, "fw.conf", inv, time.Time{})
	sslvpn.Extract(tr, "fw.conf", inv)
	return inv
}

func find(t *testing.T, inv *model.Inventory, name string) *model.Asset {
	t.Helper()
	for _, a := range inv.Assets {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("no component %q; have %q", name, protocols(inv))
	return nil
}

// protocols lists the protocol component names.
func protocols(inv *model.Inventory) []string {
	out := []string{}
	for _, a := range inv.Assets {
		if a.Type == model.AssetTypeProtocol {
			out = append(out, a.Name)
		}
	}
	return out
}

func names(inv *model.Inventory, ids []string) []string {
	byID := map[string]string{}
	for _, a := range inv.Assets {
		byID[a.ID] = a.Name
	}
	out := []string{}
	for _, id := range ids {
		out = append(out, byID[id])
	}
	return out
}

func eq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

func prop(t *testing.T, a *model.Asset, key, want string) {
	t.Helper()
	if got, ok := a.Properties["cbom-netscan:fortios:"+key]; !ok || got != want {
		t.Errorf("%s: %s = %q (present %v), want %q", a.Name, key, got, ok, want)
	}
}

func warnCodes(inv *model.Inventory) []string {
	out := []string{}
	for _, w := range inv.Warnings {
		out = append(out, w.Code)
	}
	return out
}

func suites(a *model.Asset) []string {
	out := []string{}
	for _, s := range a.Proto.CipherSuites {
		out = append(out, s.Name)
	}
	return out
}

func level(a *model.Asset) string {
	if a.Alg.NISTQuantumLevel == nil {
		return "unset"
	}
	return string(rune('0' + *a.Alg.NISTQuantumLevel))
}

func TestExtract(t *testing.T) {
	cases := []struct {
		name  string
		cfg   string
		check func(t *testing.T, inv *model.Inventory)
	}{
		{
			name: "configured_pqc_groups",
			cfg: hdr767 + localCert(t, "gw-ecdsa", "gw-ecdsa.pem") + `config vpn ssl settings
    set servercert "gw-ecdsa"
    set ssl-min-proto-ver tls1-2
    set ssl-max-proto-ver tls1-3
    set algorithm high
    set banned-cipher SHA1 RSA
    set ciphersuite TLS-AES-256-GCM-SHA384 TLS-CHACHA20-POLY1305-SHA256
    set tls-groups X25519-MLKEM768 P-256-MLKEM768 ML-KEM768 X25519 P-384 FFDHE4096
end
`,
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "protocols", protocols(inv), []string{tls + "1.2", tls + "1.3"})
				t13, t12 := find(t, inv, tls+"1.3"), find(t, inv, tls+"1.2")
				if t13.Proto.Type != "tls" || t13.Proto.Version != "1.3" || t12.Proto.Version != "1.2" {
					t.Errorf("protocol types/versions = %+v, %+v", *t13.Proto, *t12.Proto)
				}
				eq(t, "1.3 suites", suites(t13), []string{"TLS-AES-256-GCM-SHA384", "TLS-CHACHA20-POLY1305-SHA256"})
				eq(t, "1.2 suites", suites(t12), []string{})
				prop(t, t12, "cipher-suites", "unknown")
				prop(t, t12, "banned-cipher:value", "SHA1 RSA")
				prop(t, t13, "tls-groups:source", "configured")
				prop(t, t13, "view", "configured")
				prop(t, t13, "servercert:value", "gw-ecdsa")

				// Groups in configured order; each hybrid is followed by its parts.
				wantRefs := []string{
					"X25519MLKEM768", "ML-KEM-768", "X25519",
					"SecP256r1MLKEM768", "ECP-256",
					"ECP-384", "FFDHE-4096",
					"FortiOS certificate local gw-ecdsa",
				}
				eq(t, "1.3 refs", names(inv, t13.Proto.Refs), wantRefs)
				// TLS 1.2 gets the classical groups only: ML-KEM and hybrid
				// groups are defined for TLS 1.3. ECP-256 is configured only as
				// a hybrid part, so it is not a TLS 1.2 group either.
				eq(t, "1.2 refs", names(inv, t12.Proto.Refs), []string{"X25519", "ECP-384", "FFDHE-4096", "FortiOS certificate local gw-ecdsa"})
				prop(t, t12, "tls-groups:tls13-only", "X25519-MLKEM768 P-256-MLKEM768 ML-KEM768")
				if _, ok := t13.Properties["cbom-netscan:fortios:tls-groups:tls13-only"]; ok {
					t.Errorf("TLS 1.3 component has a tls13-only property")
				}
				eq(t, "dependsOn", names(inv, t13.DependsOn), []string{"FortiOS certificate local gw-ecdsa"})

				eq(t, "X25519MLKEM768 parts", names(inv, find(t, inv, "X25519MLKEM768").DependsOn), []string{"ML-KEM-768", "X25519"})
				eq(t, "SecP256r1MLKEM768 parts", names(inv, find(t, inv, "SecP256r1MLKEM768").DependsOn), []string{"ML-KEM-768", "ECP-256"})

				for name, want := range map[string]struct{ prim, level string }{
					"X25519MLKEM768": {"combiner", "unset"},
					"ML-KEM-768":     {"kem", "3"},
					"X25519":         {"key-agree", "0"},
					"ECP-256":        {"key-agree", "0"},
					"ECP-384":        {"key-agree", "0"},
					"FFDHE-4096":     {"key-agree", "0"},
				} {
					a := find(t, inv, name)
					if a.Alg.Primitive != want.prim || level(a) != want.level {
						t.Errorf("%s: primitive %s level %s, want %s %s", name, a.Alg.Primitive, level(a), want.prim, want.level)
					}
				}
				if p := find(t, inv, "FFDHE-4096").Alg.ParameterSetIdentifier; p != "4096" {
					t.Errorf("FFDHE-4096 parameterSetIdentifier = %q", p)
				}
				if len(inv.Warnings) != 0 {
					t.Errorf("warnings = %+v", inv.Warnings)
				}
			},
		},
		{
			// An empty section on 7.6.7: every value is the documented default.
			name: "defaults_767",
			cfg:  hdr767 + "config vpn ssl settings\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "protocols", protocols(inv), []string{tls + "1.2", tls + "1.3"})
				t13 := find(t, inv, tls+"1.3")
				prop(t, t13, "ssl-min-proto-ver:source", "default")
				prop(t, t13, "defaults-table", "7.6")
				prop(t, t13, "tls-groups:value", "P-521 P-384 ML-KEM768 ML-KEM1024 P-384-MLKEM1024 P-256-MLKEM768 X25519-MLKEM768 X448 FFDHE4096 FFDHE6144 FFDHE8192")
				eq(t, "1.3 suites", suites(t13), []string{"TLS-AES-128-GCM-SHA256", "TLS-AES-256-GCM-SHA384", "TLS-CHACHA20-POLY1305-SHA256"})
				prop(t, find(t, inv, tls+"1.2"), "banned-cipher:value", "SHA1 SHA256 SHA384")
				eq(t, "1.3 refs", names(inv, t13.Proto.Refs), []string{
					"ECP-521", "ECP-384", "ML-KEM-768", "ML-KEM-1024",
					"SecP384r1MLKEM1024", "SecP256r1MLKEM768", "ECP-256", "X25519MLKEM768", "X25519",
					"X448", "FFDHE-4096", "FFDHE-6144", "FFDHE-8192",
				})
				if len(t13.DependsOn) != 0 || len(inv.Warnings) != 0 {
					t.Errorf("dependsOn %v warnings %v; want none without a servercert", t13.DependsOn, inv.Warnings)
				}
				// A default adds no evidence occurrence.
				if ev := find(t, inv, "ML-KEM-1024").Evidence; len(ev) != 0 {
					t.Errorf("default group has evidence %+v", ev)
				}
			},
		},
		{
			name: "defaults_801",
			cfg:  hdr801 + "config vpn ssl settings\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				t13 := find(t, inv, tls+"1.3")
				prop(t, t13, "defaults-table", "8.0")
				prop(t, t13, "tls-groups:source", "default")
			},
		},
		{
			// tls-groups arrived in 7.6.5: on 7.6.4 it is unknown, with no group
			// components, and the rest still resolves.
			name: "tls_groups_unknown_764",
			cfg:  hdr764 + "config vpn ssl settings\n    set ssl-min-proto-ver tls1-3\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "protocols", protocols(inv), []string{tls + "1.3"})
				t13 := find(t, inv, tls+"1.3")
				prop(t, t13, "tls-groups:source", "unknown")
				if r := t13.Properties["cbom-netscan:fortios:tls-groups:unknown-reason"]; !strings.Contains(r, "7.6.5") {
					t.Errorf("unknown-reason = %q", r)
				}
				if len(t13.Proto.Refs) != 0 || len(inv.Warnings) != 0 {
					t.Errorf("refs %v warnings %v", t13.Proto.Refs, inv.Warnings)
				}
			},
		},
		{
			// 7.4.12 has DTLS; dtls-tunnel is enabled by default.
			name: "dtls_7412",
			cfg:  hdr7412 + "config vpn ssl settings\n    set ssl-max-proto-ver tls1-2\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "protocols", protocols(inv), []string{tls + "1.2", "FortiOS SSL VPN DTLS 1.0", "FortiOS SSL VPN DTLS 1.2"})
				d := find(t, inv, "FortiOS SSL VPN DTLS 1.0")
				prop(t, d, "transport", "dtls")
				prop(t, d, "dtls-tunnel:source", "default")
				prop(t, d, "defaults-table", "7.4")
				if d.Proto.Type != "tls" || d.Proto.Version != "1.0" {
					t.Errorf("DTLS protocol = %+v", *d.Proto)
				}
				prop(t, find(t, inv, tls+"1.2"), "tls-groups:source", "unknown")
			},
		},
		{
			name: "dtls_disabled_7412",
			cfg:  hdr7412 + "config vpn ssl settings\n    set dtls-tunnel disable\n    set dtls-min-proto-ver dtls1-2\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "protocols", protocols(inv), []string{tls + "1.2", tls + "1.3"})
			},
		},
		{
			// Most backups have no SSL VPN section, and that is not an error.
			name: "section_absent",
			cfg:  hdr767 + "config system global\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				if len(inv.Assets) != 0 || len(inv.Warnings) != 0 {
					t.Errorf("assets %d warnings %v, want none", len(inv.Assets), inv.Warnings)
				}
			},
		},
		{
			// No defaults table and no section: nothing, not even the
			// no-defaults warning.
			name: "section_absent_no_table",
			cfg:  hdr724 + "config system global\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				if len(inv.Assets) != 0 || len(inv.Warnings) != 0 {
					t.Errorf("assets %d warnings %v, want none", len(inv.Assets), inv.Warnings)
				}
			},
		},
		{
			// No defaults table: the versions are unknown, so one component
			// without a version stands for the section.
			name: "versions_unknown_no_table",
			cfg:  hdr724 + "config vpn ssl settings\n    set tls-groups X25519-MLKEM768 X25519 ML-KEM768\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "protocols", protocols(inv), []string{"FortiOS SSL VPN TLS"})
				a := find(t, inv, "FortiOS SSL VPN TLS")
				prop(t, a, "tls-version", "unknown")
				prop(t, a, "ssl-min-proto-ver:source", "unknown")
				prop(t, a, "cipher-suites", "unknown")
				if a.Proto.Version != "" {
					t.Errorf("version = %q, want empty", a.Proto.Version)
				}
				// It may be TLS 1.2, so it references only the classical group,
				// and lists the TLS 1.3-only ones.
				eq(t, "refs", names(inv, a.Proto.Refs), []string{"X25519"})
				prop(t, a, "tls-groups:tls13-only", "X25519-MLKEM768 ML-KEM768")
				eq(t, "warnings", warnCodes(inv), []string{"no-default-table"})
			},
		},
		{
			name: "min_above_max",
			cfg:  hdr767 + "config vpn ssl settings\n    set ssl-min-proto-ver tls1-3\n    set ssl-max-proto-ver tls1-2\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "protocols", protocols(inv), []string{})
				eq(t, "warnings", warnCodes(inv), []string{"ssl-version-range-empty"})
				if inv.Warnings[0].Ev.Line != 3 {
					t.Errorf("warning line = %d, want 3", inv.Warnings[0].Ev.Line)
				}
			},
		},
		{
			// Only max is configured, below the default min: the warning points
			// at max.
			name: "max_below_default_min",
			cfg:  hdr767 + "config vpn ssl settings\n    set ssl-max-proto-ver tls1-1\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "warnings", warnCodes(inv), []string{"ssl-version-range-empty"})
				if inv.Warnings[0].Ev.Line != 3 {
					t.Errorf("warning line = %d, want 3 (ssl-max-proto-ver)", inv.Warnings[0].Ev.Line)
				}
			},
		},
		{
			name: "unknown_servercert",
			cfg:  hdr767 + "config vpn ssl settings\n    set servercert \"Fortinet_Factory\"\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "warnings", warnCodes(inv), []string{"unknown-certificate"})
				w := inv.Warnings[0]
				if !strings.Contains(w.Message, `"Fortinet_Factory"`) || w.Ev.Line != 3 {
					t.Errorf("warning = %+v", w)
				}
				if a := find(t, inv, tls+"1.3"); len(a.DependsOn) != 0 {
					t.Errorf("dependsOn = %v, want none", a.DependsOn)
				}
			},
		},
		{
			// A new group name is kept as a value and warned about, but makes
			// no component; something that is not a group name is dropped
			// without being shown.
			name: "unknown_tokens",
			cfg:  hdr767 + "config vpn ssl settings\n    set tls-groups X25519 MLKEM-NEW \"ENC c3ludGhldGlj\"\n    set ciphersuite TLS-AES-256-GCM-SHA384 \"ENC c3ludGhldGlj\"\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "warnings", warnCodes(inv), []string{"unknown-token", "unknown-token", "unknown-token"})
				t13 := find(t, inv, tls+"1.3")
				prop(t, t13, "tls-groups:value", "X25519 MLKEM-NEW")
				prop(t, t13, "ciphersuite:value", "TLS-AES-256-GCM-SHA384")
				eq(t, "refs", names(inv, t13.Proto.Refs), []string{"X25519"})
			},
		},
		{
			name: "multi_vdom",
			cfg: strings.Replace(hdr767, "vdom=0", "vdom=1", 1) + `config vdom
edit root
next
edit branch
next
end
config global
` + localCert(t, "shared-gw", "gw-ecdsa.pem") + `end
config vdom
edit root
config vpn ssl settings
    set servercert "shared-gw"
    set ssl-min-proto-ver tls1-3
    set tls-groups X25519-MLKEM768
end
next
edit branch
config vpn ssl settings
    set servercert "shared-gw"
    set tls-groups X25519
end
end
`,
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "protocols", protocols(inv), []string{tls + "1.3 (vdom root)", tls + "1.2 (vdom branch)", tls + "1.3 (vdom branch)"})
				root := find(t, inv, tls+"1.3 (vdom root)")
				prop(t, root, "scope", "vdom root")
				eq(t, "root dependsOn", names(inv, root.DependsOn), []string{"FortiOS certificate local shared-gw (global)"})
				branch := find(t, inv, tls+"1.3 (vdom branch)")
				eq(t, "branch refs", names(inv, branch.Proto.Refs), []string{"X25519", "FortiOS certificate local shared-gw (global)"})
				// The branch's X25519 and root's hybrid part are one component
				// with evidence from both VDOMs.
				var ctx []string
				for _, ev := range find(t, inv, "X25519").Evidence {
					ctx = append(ctx, ev.Context)
				}
				slices.Sort(ctx)
				eq(t, "X25519 evidence contexts", ctx, []string{"vdom branch", "vdom root"})
				if len(inv.Warnings) != 0 {
					t.Errorf("warnings = %+v", inv.Warnings)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := extract(t, tc.cfg)
			tc.check(t, inv)
			dump, err := json.Marshal(struct {
				A []*model.Asset
				W []model.Warning
			}{inv.Assets, inv.Warnings})
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range secretFragments {
				if strings.Contains(string(dump), s) {
					t.Errorf("inventory contains secret fragment %q", s)
				}
			}
		})
	}
}
