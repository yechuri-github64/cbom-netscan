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
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/ipsec"
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

// TestSharedAlgorithmsWithIPsec: a cipher used by both SSH and IPsec is one
// component referenced by both protocols, and MAC -etm variants share their
// MAC's component.
func TestSharedAlgorithmsWithIPsec(t *testing.T) {
	tr, err := tree.Parse(strings.NewReader(hdr76 + `config system ssh-config
    set ssh-enc-algo aes256-gcm@openssh.com
    set ssh-mac-algo hmac-sha2-256 hmac-sha2-256-etm@openssh.com
end
config vpn ipsec phase1-interface
    edit "t"
        set ike-version 2
        set proposal aes256gcm-prfsha384 aes256-sha256
    next
end
`))
	if err != nil {
		t.Fatal(err)
	}
	inv := model.NewInventory()
	global.Extract(tr, "fw.conf", inv)
	ipsec.Extract(tr, "fw.conf", inv)

	count := map[string]int{}
	ids := map[string]string{}
	for _, a := range inv.Assets {
		count[a.Name]++
		ids[a.Name] = a.ID
	}
	for _, n := range []string{"AES-256-GCM", "HMAC-SHA256"} {
		if count[n] != 1 {
			t.Errorf("%s components = %d, want 1", n, count[n])
		}
	}
	ssh, tunnel := find(inv, "FortiOS admin SSH"), find(inv, "FortiOS IPsec phase1-interface t")
	if !slices.Contains(ssh.Proto.Refs, ids["AES-256-GCM"]) || !slices.Contains(tunnel.Proto.IKEEncr, ids["AES-256-GCM"]) {
		t.Errorf("AES-256-GCM not referenced by both SSH and IPsec")
	}
	if !slices.Contains(ssh.Proto.Refs, ids["HMAC-SHA256"]) || !slices.Contains(tunnel.Proto.IKEInteg, ids["HMAC-SHA256"]) {
		t.Errorf("HMAC-SHA256 not referenced by both SSH and IPsec")
	}
	n := 0
	for _, id := range ssh.Proto.Refs {
		if id == ids["HMAC-SHA256"] {
			n++
		}
	}
	if n != 1 {
		t.Errorf("SSH references HMAC-SHA256 %d times, want once", n)
	}
	if got := len(find(inv, "AES-256-GCM").Evidence); got != 2 {
		t.Errorf("AES-256-GCM occurrences = %d, want 2 (SSH and IPsec lines)", got)
	}
}

// TestHybridSharesMLKEMWithIPsec: ML-KEM-768 inside the SSH hybrid and in an
// IPsec addke is one component, referenced by both protocols.
func TestHybridSharesMLKEMWithIPsec(t *testing.T) {
	tr, err := tree.Parse(strings.NewReader(hdr801 + "config vpn ipsec phase1-interface\n    edit \"t\"\n        set ike-version 2\n        set proposal aes256gcm-prfsha384\n        set addke1 ml-kem-768\n    next\nend\n"))
	if err != nil {
		t.Fatal(err)
	}
	inv := model.NewInventory()
	global.Extract(tr, "fw.conf", inv)
	ipsec.Extract(tr, "fw.conf", inv)

	var id string
	n := 0
	for _, a := range inv.Assets {
		if a.Name == "ML-KEM-768" {
			id, n = a.ID, n+1
		}
	}
	if n != 1 {
		t.Fatalf("ML-KEM-768 components = %d, want 1", n)
	}
	ssh, tunnel := find(inv, "FortiOS admin SSH"), find(inv, "FortiOS IPsec phase1-interface t")
	if !slices.Contains(ssh.Proto.Refs, id) || !slices.Contains(tunnel.Proto.IKEKE, id) {
		t.Errorf("ML-KEM-768 %s not referenced by both: ssh %v, ipsec ke %v", id, ssh.Proto.Refs, tunnel.Proto.IKEKE)
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
				// 8 kex + 2 ciphers + 2 MACs (the -etm variants share the MAC) + 6 host-key algorithms
				if len(inv.Assets) != 21 {
					t.Errorf("components = %d, want 21 (2 TLS + SSH + 18 SSH algorithms): %v", len(inv.Assets), names(inv))
				}
				prop(t, inv, tls13, "admin-https-ssl-versions:source", "default")
				prop(t, inv, tls13, "admin-https-ssl-ciphersuites:source", "default")
				prop(t, inv, tls13, "defaults-table", "7.6")
				prop(t, inv, tls13, "strong-crypto:value", "enable")
				prop(t, inv, tls12, "ssl-static-key-ciphers:value", "enable")
				prop(t, inv, tls12, "cipher-suites", "unknown")
				prop(t, inv, ssh, "ssh-kex-algo:source", "default")
				for _, name := range []string{tls12, tls13, ssh} {
					prop(t, inv, name, "view", "configured")
				}
				var suites []string
				for _, s := range find(inv, tls13).Proto.CipherSuites {
					suites = append(suites, s.Name)
				}
				if got := strings.Join(suites, " "); got != "TLS-AES-128-GCM-SHA256 TLS-AES-256-GCM-SHA384 TLS-CHACHA20-POLY1305-SHA256" {
					t.Errorf("TLS 1.3 suites = %s", got)
				}
				if n := len(find(inv, ssh).Proto.Refs); n != 18 {
					t.Errorf("SSH refs = %d, want 18", n)
				}
				for name, want := range map[string]int{"ecdh-sha2-nistp384": 0, "curve25519-sha256@libssh.org": 0, "ssh-ed25519": 0, "rsa-sha2-512": 0} {
					if l := find(inv, name).Alg.NISTQuantumLevel; l == nil || *l != want {
						t.Errorf("%s: nistQuantumSecurityLevel = %v, want %d (classical public-key)", name, l, want)
					}
				}
				prop(t, inv, ssh, "ssh-mac-algo:value", "hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com")
				for _, name := range []string{"AES-256-CTR", "HMAC-SHA256"} {
					if l := find(inv, name).Alg.NISTQuantumLevel; l != nil {
						t.Errorf("%s: nistQuantumSecurityLevel = %d, want unset (symmetric)", name, *l)
					}
				}
				if ev := find(inv, "AES-256-CTR").Evidence; len(ev) != 0 {
					t.Errorf("default-sourced component has evidence %v", ev)
				}
				if len(inv.Warnings) != 0 {
					t.Errorf("warnings = %v, want none", warnCodes(inv))
				}
			},
		},
		{
			// strong-crypto defaults to enable: what it disables is marked,
			// but still reported as configured.
			name: "strong_crypto_markers",
			cfg: hdr76 + `config system global
    set admin-https-ssl-versions tlsv1-1 tlsv1-2 tlsv1-3
    set admin-https-ssl-ciphersuites TLS-AES-128-CCM-SHA256 TLS-AES-256-GCM-SHA384
end
config system ssh-config
    set ssh-enc-algo aes128-cbc aes256-ctr
    set ssh-hsk-algo ssh-rsa ssh-ed25519
end
`,
			check: func(t *testing.T, inv *model.Inventory) {
				for name, want := range map[string]bool{"FortiOS admin HTTPS TLS 1.1": true, tls12: false, tls13: false} {
					_, got := find(inv, name).Properties["cbom-netscan:fortios:strong-crypto-may-restrict"]
					if got != want {
						t.Errorf("%s: strong-crypto-may-restrict present = %v, want %v", name, got, want)
					}
				}
				// SSH markers name the tokens on the protocol, not on the
				// algorithm components, which other protocols may share.
				prop(t, inv, ssh, "ssh-enc-algo:strong-crypto-may-restrict", "aes128-cbc")
				prop(t, inv, ssh, "ssh-hsk-algo:strong-crypto-may-restrict", "ssh-rsa")
				if _, ok := find(inv, ssh).Properties["cbom-netscan:fortios:ssh-mac-algo:strong-crypto-may-restrict"]; ok {
					t.Errorf("default MACs are all allowed under strong-crypto")
				}
				for _, a := range inv.Assets {
					if a.Type != model.AssetTypeAlgorithm {
						continue
					}
					for k := range a.Properties {
						if strings.Contains(k, "strong-crypto") {
							t.Errorf("algorithm %s carries %s", a.Name, k)
						}
					}
				}
				prop(t, inv, tls13, "strong-crypto-may-restrict:cipher-suites", "TLS-AES-128-CCM-SHA256")
				prop(t, inv, "FortiOS admin HTTPS TLS 1.1", "admin-https-ssl-versions:source", "configured")
			},
		},
		{
			name: "strong_crypto_disabled_no_markers",
			cfg: hdr76 + `config system global
    set strong-crypto disable
    set admin-https-ssl-versions tlsv1-1 tlsv1-2
end
config system ssh-config
    set ssh-enc-algo aes128-cbc
end
`,
			check: func(t *testing.T, inv *model.Inventory) {
				for _, a := range inv.Assets {
					for k := range a.Properties {
						if strings.HasPrefix(k, "cbom-netscan:fortios:strong-crypto-may-restrict") {
							t.Errorf("%s has %s although strong-crypto is disable", a.Name, k)
						}
					}
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
				prop(t, inv, ssh, "ssh-enc-algo:line", "3")
				if ev := find(inv, "AES-256-CTR").Evidence; len(ev) != 1 || ev[0].Line != 3 {
					t.Errorf("AES-256-CTR evidence = %+v, want line 3", ev)
				}
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
				if a.Alg.Primitive != "combiner" || a.Alg.NISTQuantumLevel != nil {
					t.Errorf("hybrid kex alg = %+v, want a combiner with no level of its own", a.Alg)
				}
				prop(t, inv, "mlkem768x25519-sha256", "hybrid", "ML-KEM-768 + X25519")
				prop(t, inv, "FortiOS admin SSH", "defaults-table", "8.0")
				prop(t, inv, "FortiOS admin SSH", "ssh-kex-algo:source", "default")

				byID := map[string]*model.Asset{}
				for _, x := range inv.Assets {
					byID[x.ID] = x
				}
				var parts []string
				for _, id := range a.DependsOn {
					parts = append(parts, byID[id].Name)
				}
				if !slices.Equal(parts, []string{"ML-KEM-768", "X25519"}) {
					t.Errorf("hybrid dependsOn = %v, want [ML-KEM-768 X25519]", parts)
				}
				if k := find(inv, "ML-KEM-768"); k == nil || k.Alg.Primitive != "kem" || k.Alg.NISTQuantumLevel == nil || *k.Alg.NISTQuantumLevel != 3 {
					t.Errorf("ML-KEM-768 part = %+v", k)
				}
				if x := find(inv, "X25519"); x == nil || x.Alg.Primitive != "key-agree" || x.Alg.Curve != "x25519" {
					t.Errorf("X25519 part = %+v", x)
				}
				refs := map[string]bool{}
				for _, id := range find(inv, "FortiOS admin SSH").Proto.Refs {
					refs[byID[id].Name] = true
				}
				for _, want := range []string{"mlkem768x25519-sha256", "ML-KEM-768", "X25519"} {
					if !refs[want] {
						t.Errorf("SSH protocol does not reference %s", want)
					}
				}
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
				prop(t, inv, ssh, "ssh-enc-algo:value", "aes256-ctr new-cipher@example.com")
				if find(inv, "AES-256-CTR") == nil {
					t.Errorf("aes256-ctr not emitted as AES-256-CTR")
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
