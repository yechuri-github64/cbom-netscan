// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package global_test

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/global"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const (
	hdr76  = "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin\n"
	hdr748 = "#config-version=FGVMH6-7.4.8-FW-build2795-250523:opmode=0:vdom=0:user=admin\n"
	hdr801 = "#config-version=FGVMH6-8.0.1-FW-build1500-260801:opmode=0:vdom=0:user=admin\n"
	hdrMul = "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=1:user=admin\n"
)

func extract(t *testing.T, cfg string) *model.Inventory {
	t.Helper()
	tr, err := tree.Parse(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	inv := model.NewInventory()
	global.Extract(tr, "fw.conf", inv)
	return inv
}

func find(inv *model.Inventory, name string) *model.Asset {
	for _, a := range inv.Assets {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func names(inv *model.Inventory) []string {
	var out []string
	for _, a := range inv.Assets {
		out = append(out, a.Name)
	}
	slices.Sort(out)
	return out
}

func warnCodes(inv *model.Inventory) []string {
	var out []string
	for _, w := range inv.Warnings {
		out = append(out, w.Code)
	}
	return out
}

// prop fails the test unless asset name has property key = want.
func prop(t *testing.T, inv *model.Inventory, name, key, want string) {
	t.Helper()
	a := find(inv, name)
	if a == nil {
		t.Errorf("no component %q; have %v", name, names(inv))
		return
	}
	if got, ok := a.Properties["cbom-netscan:fortios:"+key]; !ok || got != want {
		t.Errorf("%s: property %s = %q (present %v), want %q", name, key, got, ok, want)
	}
}

func TestExtract(t *testing.T) {
	const tls12, tls13, tlsAny, ssh = "FortiOS admin HTTPS TLS 1.2", "FortiOS admin HTTPS TLS 1.3", "FortiOS admin HTTPS TLS", "FortiOS admin SSH"

	cases := []struct {
		name  string
		cfg   string
		check func(t *testing.T, inv *model.Inventory)
	}{
		{
			name: "defaults_only_7.6",
			cfg:  hdr76,
			check: func(t *testing.T, inv *model.Inventory) {
				if len(inv.Assets) != 23 {
					t.Errorf("components = %d, want 23 (2 TLS + SSH + 20 SSH algorithms): %v", len(inv.Assets), names(inv))
				}
				prop(t, inv, tls13, "admin-https-ssl-versions:source", "default")
				prop(t, inv, tls13, "admin-https-ssl-ciphersuites:source", "default")
				prop(t, inv, tls13, "defaults-table", "7.6")
				prop(t, inv, tls13, "strong-crypto:value", "enable")
				prop(t, inv, tls12, "ssl-static-key-ciphers:value", "enable")
				prop(t, inv, tls12, "cipher-suites", "unknown")
				prop(t, inv, ssh, "ssh-kex-algo:source", "default")
				var suites []string
				for _, s := range find(inv, tls13).Proto.CipherSuites {
					suites = append(suites, s.Name)
				}
				if got := strings.Join(suites, " "); got != "TLS-AES-128-GCM-SHA256 TLS-AES-256-GCM-SHA384 TLS-CHACHA20-POLY1305-SHA256" {
					t.Errorf("TLS 1.3 suites = %s", got)
				}
				if n := len(find(inv, ssh).Proto.Refs); n != 20 {
					t.Errorf("SSH refs = %d, want 20", n)
				}
				if ev := find(inv, "aes256-ctr").Evidence; len(ev) != 0 {
					t.Errorf("default-sourced component has evidence %v", ev)
				}
				if len(inv.Warnings) != 0 {
					t.Errorf("warnings = %v, want none", warnCodes(inv))
				}
			},
		},
		{
			name: "configured_records_line",
			cfg:  hdr76 + "config system global\n    set admin-https-ssl-versions tlsv1-3\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				if find(inv, tls12) != nil {
					t.Errorf("TLS 1.2 emitted although only tlsv1-3 is configured")
				}
				prop(t, inv, tls13, "admin-https-ssl-versions:source", "configured")
				prop(t, inv, tls13, "admin-https-ssl-versions:line", "3")
				prop(t, inv, tls13, "admin-https-ssl-ciphersuites:source", "default")
				ev := find(inv, tls13).Evidence
				if len(ev) != 1 || ev[0].Line != 3 || ev[0].Symbol != "system global/admin-https-ssl-versions" || ev[0].Location != "fw.conf" {
					t.Errorf("evidence = %+v", ev)
				}
			},
		},
		{
			name: "unset_uses_default",
			cfg:  hdr76 + "config system global\n    unset admin-https-ssl-versions\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				prop(t, inv, tls12, "admin-https-ssl-versions:source", "default")
				prop(t, inv, tls13, "admin-https-ssl-versions:source", "default")
			},
		},
		{
			name: "no_table_reports_unknown",
			cfg:  hdr748 + "config system ssh-config\n    set ssh-enc-algo aes256-ctr\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				if got := warnCodes(inv); !slices.Equal(got, []string{"no-default-table"}) {
					t.Errorf("warnings = %v, want [no-default-table]", got)
				}
				prop(t, inv, tlsAny, "admin-https-ssl-versions:source", "unknown")
				prop(t, inv, tlsAny, "admin-https-ssl-ciphersuites:source", "unknown")
				prop(t, inv, ssh, "ssh-kex-algo:source", "unknown")
				prop(t, inv, ssh, "ssh-enc-algo:source", "configured")
				prop(t, inv, "aes256-ctr", "ssh-enc-algo:line", "3")
				if n := len(find(inv, ssh).Proto.Refs); n != 1 {
					t.Errorf("SSH refs = %d, want 1 (only the configured cipher)", n)
				}
				if a := find(inv, tlsAny); a != nil {
					if _, ok := a.Properties["cbom-netscan:fortios:strong-crypto:value"]; ok {
						t.Errorf("unknown strong-crypto has a value property")
					}
				}
			},
		},
		{
			name: "8.0.1_default_hybrid_kex",
			cfg:  hdr801,
			check: func(t *testing.T, inv *model.Inventory) {
				a := find(inv, "mlkem768x25519-sha256")
				if a == nil {
					t.Fatalf("hybrid kex missing; have %v", names(inv))
				}
				if a.Alg.Primitive != "kem" || a.Alg.NISTQuantumLevel == nil || *a.Alg.NISTQuantumLevel != 3 {
					t.Errorf("hybrid kex alg = %+v", a.Alg)
				}
				prop(t, inv, "mlkem768x25519-sha256", "hybrid", "ML-KEM-768 + X25519")
				prop(t, inv, "mlkem768x25519-sha256", "defaults-table", "8.0")
			},
		},
		{
			name: "multi_vdom_reads_global_scope",
			cfg: hdrMul + `config vdom
edit root
next
end
config global
config system global
    set admin-https-ssl-versions tlsv1-3
end
end
config vdom
edit root
config system global
    set admin-https-ssl-versions tlsv1-1
end
next
end
`,
			check: func(t *testing.T, inv *model.Inventory) {
				prop(t, inv, tls13, "admin-https-ssl-versions:line", "8")
				if a := find(inv, "FortiOS admin HTTPS TLS 1.1"); a != nil {
					t.Errorf("read system global from a VDOM scope instead of config global")
				}
			},
		},
		{
			name: "unknown_and_unsafe_tokens",
			cfg:  hdr76 + "config system ssh-config\n    set ssh-enc-algo aes256-ctr new-cipher@example.com \"ENC c3ludGhldGljLWJsb2I=\"\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				if a := find(inv, "new-cipher@example.com"); a == nil || a.Alg.Primitive != "unknown" {
					t.Errorf("unknown but plain token not kept as primitive unknown: %+v", a)
				}
				var enc []string
				for _, a := range inv.Assets {
					if _, ok := a.Properties["cbom-netscan:fortios:ssh-enc-algo:source"]; ok && a.Type == model.AssetTypeAlgorithm {
						enc = append(enc, a.Name)
					}
				}
				slices.Sort(enc)
				if !slices.Equal(enc, []string{"aes256-ctr", "new-cipher@example.com"}) {
					t.Errorf("cipher components = %v, want [aes256-ctr new-cipher@example.com] (unsafe token dropped)", enc)
				}
				if got := warnCodes(inv); !slices.Equal(got, []string{"unknown-token", "unknown-token"}) {
					t.Errorf("warnings = %v, want two unknown-token", got)
				}
			},
		},
		{
			name: "secrets_never_output",
			cfg: hdr76 + `config system global
    set admin-server-cert "ENC c3ludGhldGljLWNlcnQ="
end
config system admin
    edit "admin"
        set password ENC c3ludGhldGljLWFkbWlu
    next
end
config system ssh-config
    set ssh-hsk-password ENC c3ludGhldGljLWhzaw==
    set ssh-hsk "-----BEGIN OPENSSH PRIVATE KEY-----
c3ludGhldGljLWtleQ==
-----END OPENSSH PRIVATE KEY-----"
end
`,
			check: func(t *testing.T, inv *model.Inventory) {
				prop(t, inv, tls13, "admin-server-cert:source", "configured")
				prop(t, inv, tls13, "admin-server-cert:value", "")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := extract(t, tc.cfg)
			tc.check(t, inv)

			// Every case: nothing secret-looking anywhere in assets or warnings.
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
