// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package ipsec_test

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/ipsec"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const (
	hdr767 = "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin\n"
	hdr765 = "#config-version=FGVMH6-7.6.5-FW-build3500-260101:opmode=0:vdom=0:user=admin\n"
	hdr764 = "#config-version=FGVMH6-7.6.4-FW-build3400-251001:opmode=0:vdom=0:user=admin\n"
	hdr748 = "#config-version=FGVMH6-7.4.8-FW-build2795-250523:opmode=0:vdom=0:user=admin\n"

	p1 = "FortiOS IPsec phase1-interface "
	p2 = "FortiOS IPsec phase2-interface "
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func extract(t *testing.T, cfg string) *model.Inventory {
	t.Helper()
	tr, err := tree.Parse(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	inv := model.NewInventory()
	ipsec.Extract(tr, "fw.conf", inv)
	return inv
}

func find(t *testing.T, inv *model.Inventory, name string) *model.Asset {
	t.Helper()
	for _, a := range inv.Assets {
		if a.Name == name {
			return a
		}
	}
	var have []string
	for _, a := range inv.Assets {
		have = append(have, a.Name)
	}
	t.Fatalf("no component %q; have %q", name, have)
	return nil
}

// names maps bom-refs to component names, for readable comparisons.
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

func propHas(t *testing.T, a *model.Asset, key, sub string) {
	t.Helper()
	if got := a.Properties["cbom-netscan:fortios:"+key]; !strings.Contains(got, sub) {
		t.Errorf("%s: %s = %q, want it to contain %q", a.Name, key, got, sub)
	}
}

func warnCodes(inv *model.Inventory) []string {
	out := []string{}
	for _, w := range inv.Warnings {
		out = append(out, w.Code)
	}
	return out
}

func occurrences(a *model.Asset) []string {
	var out []string
	for _, ev := range a.Evidence {
		out = append(out, fmt.Sprintf("%d %s", ev.Line, ev.Context))
	}
	return out
}

func TestExtract(t *testing.T) {
	cases := []struct {
		name  string
		cfg   string
		check func(t *testing.T, inv *model.Inventory)
	}{
		{
			name: "fixture_tunnels",
			cfg:  fixture(t, "ipsec-7.6.conf"),
			check: func(t *testing.T, inv *model.Inventory) {
				hq := find(t, inv, p1+"hq-ikev2")
				if hq.Proto.Version != "2" || len(hq.Proto.Refs) != 0 {
					t.Errorf("hq-ikev2: version %q, refs %v; want IKEv2 transform slots only", hq.Proto.Version, hq.Proto.Refs)
				}
				eq(t, "hq encr", names(inv, hq.Proto.IKEEncr), []string{"AES-256-GCM", "AES-256-CBC"})
				eq(t, "hq prf", names(inv, hq.Proto.IKEPRF), []string{"PRF-HMAC-SHA384", "PRF-HMAC-SHA256"})
				eq(t, "hq integ", names(inv, hq.Proto.IKEInteg), []string{"HMAC-SHA256"})
				eq(t, "hq ke", names(inv, hq.Proto.IKEKE), []string{"DH group 20 (ECP-384)", "DH group 21 (ECP-521)"})
				eq(t, "hq auth", names(inv, hq.Proto.IKEAuth), []string{p1 + "hq-ikev2 pre-shared key"})
				prop(t, hq, "dhgrp:source", "configured")
				prop(t, hq, "dhgrp:line", "22")
				prop(t, find(t, inv, p1+"hq-ikev2 pre-shared key"), "psksecret:form", "ENC")

				br := find(t, inv, p1+"branch-ikev1")
				if br.Proto.Version != "1" || len(br.Proto.IKEEncr) != 0 {
					t.Errorf("branch-ikev1: version %q, encr %v; want IKEv1 using cryptoRefArray", br.Proto.Version, br.Proto.IKEEncr)
				}
				prop(t, br, "ike-version:source", "default")
				prop(t, br, "dhgrp:source", "default")
				prop(t, br, "dhgrp:value", "20")
				prop(t, br, "defaults-table", "7.6")
				propHas(t, br, "dhgrp:default-note", "20 and 21")
				propHas(t, br, "dhgrp:default-source", "7.6.7")
				eq(t, "branch refs", names(inv, br.Proto.Refs), []string{
					"AES-128-CBC", "3DES-CBC", "HMAC-SHA1", "PRF-HMAC-SHA1", "DH group 20 (ECP-384)", p1 + "branch-ikev1 pre-shared key",
				})
				prop(t, find(t, inv, p1+"branch-ikev1 pre-shared key"), "psksecret:form", "plaintext")

				pq := find(t, inv, p1+"pqc-ikev2")
				eq(t, "pqc ke", names(inv, pq.Proto.IKEKE), []string{"DH group 21 (ECP-521)", "ML-KEM-768", "KYBER-768", "HQC-192"})
				prop(t, pq, "addke1:value", "ml-kem-768")
				prop(t, pq, "addke2:value", "kyber768 hqc192")
				prop(t, pq, "signature-hash-alg:source", "default")
				prop(t, pq, "signature-hash-alg:value", "sha2-512")
				prop(t, pq, "certificate:value", "lab-vpn-cert")
				if len(pq.Proto.IKEAuth) != 0 {
					t.Errorf("signature tunnel has auth refs %v; certificates are referenced by name only", pq.Proto.IKEAuth)
				}

				mlkem := find(t, inv, "ML-KEM-768")
				if mlkem.Alg.Primitive != "kem" || mlkem.Alg.NISTQuantumLevel == nil || *mlkem.Alg.NISTQuantumLevel != 3 {
					t.Errorf("ML-KEM-768 alg = %+v", mlkem.Alg)
				}
				eq(t, "ML-KEM-768 occurrences", occurrences(mlkem), []string{"37 ", "58 "})

				n := 0
				for _, a := range inv.Assets {
					if a.Name == "AES-256-GCM" {
						n++
					}
				}
				if n != 1 {
					t.Errorf("AES-256-GCM components = %d, want 1 shared component", n)
				}
				eq(t, "AES-256-GCM occurrences", occurrences(find(t, inv, "AES-256-GCM")), []string{"21 ", "35 ", "47 ", "57 "})

				hqp2 := find(t, inv, p2+"hq-p2")
				eq(t, "hq-p2 dependsOn", names(inv, hqp2.DependsOn), []string{p1 + "hq-ikev2"})
				eq(t, "hq-p2 encr", names(inv, hqp2.Proto.IKEEncr), []string{"AES-256-GCM", "ChaCha20-Poly1305"})
				eq(t, "hq-p2 ke", names(inv, hqp2.Proto.IKEKE), []string{"DH group 20 (ECP-384)"})
				prop(t, hqp2, "pfs:source", "default")

				brp2 := find(t, inv, p2+"branch-p2")
				eq(t, "branch-p2 dependsOn", names(inv, brp2.DependsOn), []string{p1 + "branch-ikev1"})
				eq(t, "branch-p2 refs (IKEv1 parent, no PFS)", names(inv, brp2.Proto.Refs), []string{"AES-128-CBC", "HMAC-SHA1"})
				prop(t, brp2, "pfs:value", "disable")

				pqp2 := find(t, inv, p2+"pqc-p2")
				eq(t, "pqc-p2 ke", names(inv, pqp2.Proto.IKEKE), []string{"DH group 20 (ECP-384)", "ML-KEM-768"})
				prop(t, pqp2, "dhgrp:source", "default")

				eq(t, "warnings", warnCodes(inv), []string{})
			},
		},
		{
			name: "numeric_addke_and_765_default",
			cfg:  hdr765 + "config vpn ipsec phase1-interface\n    edit \"t\"\n        set ike-version 2\n        set proposal aes256gcm-prfsha384\n        set addke1 36\n    next\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				tn := find(t, inv, p1+"t")
				eq(t, "ke", names(inv, tn.Proto.IKEKE), []string{"DH group 20 (ECP-384)", "ML-KEM-768"})
				prop(t, tn, "addke1:value", "36")
				propHas(t, tn, "dhgrp:default-note", "Model-dependent")
			},
		},
		{
			// RFC 9370 additional key exchanges are IKEv2-only: on an IKEv1
			// tunnel (and its phase2) they are recorded but not counted.
			name: "addke_ignored_on_ikev1",
			cfg: hdr767 + `config vpn ipsec phase1-interface
    edit "v1"
        set ike-version 1
        set proposal aes256-sha256
        set addke1 36
    next
end
config vpn ipsec phase2-interface
    edit "v1-p2"
        set phase1name "v1"
        set proposal aes256-sha256
        set addke1 ml-kem-768
    next
end
`,
			check: func(t *testing.T, inv *model.Inventory) {
				tn := find(t, inv, p1+"v1")
				eq(t, "v1 refs", names(inv, tn.Proto.Refs), []string{"AES-256-CBC", "HMAC-SHA256", "PRF-HMAC-SHA256", "DH group 20 (ECP-384)"})
				prop(t, tn, "addke1:value", "36")
				prop(t, tn, "addke:applies", "no")
				p := find(t, inv, p2+"v1-p2")
				eq(t, "v1-p2 refs", names(inv, p.Proto.Refs), []string{"AES-256-CBC", "HMAC-SHA256", "DH group 20 (ECP-384)"})
				prop(t, p, "addke:applies", "no")
				for _, a := range inv.Assets {
					if a.Name == "ML-KEM-768" {
						t.Errorf("ML-KEM-768 component emitted although no IKEv2 tunnel uses it")
					}
				}
				eq(t, "warnings", warnCodes(inv), []string{"addke-not-ikev2", "addke-not-ikev2"})
			},
		},
		{
			name: "addke_not_counted_when_version_unknown",
			cfg:  hdr748 + "config vpn ipsec phase1-interface\n    edit \"u\"\n        set proposal aes256-sha256\n        set addke1 36\n    next\nend\nconfig vpn ipsec phase2-interface\n    edit \"orphan\"\n        set phase1name \"none\"\n        set addke1 36\n        set pfs enable\n    next\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				tn := find(t, inv, p1+"u")
				prop(t, tn, "addke:applies", "unknown")
				prop(t, tn, "addke1:value", "36")
				for _, n := range names(inv, tn.Proto.Refs) {
					if n == "ML-KEM-768" {
						t.Errorf("ML-KEM-768 counted although the IKE version is unknown")
					}
				}
				prop(t, find(t, inv, p2+"orphan"), "addke:applies", "unknown")
				eq(t, "warnings", warnCodes(inv), []string{"unknown-phase1", "no-default-table"})
			},
		},
		{
			name: "764_default_dhgrp_14",
			cfg:  hdr764 + "config vpn ipsec phase1-interface\n    edit \"t\"\n        set proposal aes256-sha256\n    next\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				tn := find(t, inv, p1+"t")
				prop(t, tn, "dhgrp:value", "14")
				eq(t, "refs", names(inv, tn.Proto.Refs), []string{"AES-256-CBC", "HMAC-SHA256", "PRF-HMAC-SHA256", "DH group 14 (MODP-2048)"})
			},
		},
		{
			name: "no_table_reports_unknown",
			cfg:  hdr748 + "config vpn ipsec phase1-interface\n    edit \"t\"\n        set proposal aes256-sha256\n    next\nend\nconfig vpn ipsec phase2-interface\n    edit \"t2\"\n        set phase1name \"t\"\n    next\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "warnings", warnCodes(inv), []string{"no-default-table"})
				tn := find(t, inv, p1+"t")
				if tn.Proto.Version != "" || len(tn.Proto.Refs) == 0 {
					t.Errorf("unknown IKE version: version %q refs %v; want no version and cryptoRefArray", tn.Proto.Version, tn.Proto.Refs)
				}
				prop(t, tn, "ike-version:source", "unknown")
				prop(t, tn, "dhgrp:source", "unknown")
				prop(t, tn, "addke:source", "unknown")
				prop(t, find(t, inv, p2+"t2"), "pfs:source", "unknown")
			},
		},
		{
			name: "proposal_default_is_undocumented",
			cfg:  hdr767 + "config vpn ipsec phase1-interface\n    edit \"t\"\n    next\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				tn := find(t, inv, p1+"t")
				prop(t, tn, "proposal:source", "unknown")
				propHas(t, tn, "proposal:unknown-reason", "no documented default")
				if len(tn.Proto.IKEEncr)+len(tn.Proto.Refs) == 0 {
					t.Fatalf("expected the DH default and PSK-less tunnel to still reference the DH group")
				}
				for _, n := range names(inv, tn.Proto.Refs) {
					if strings.Contains(n, "AES") || strings.Contains(n, "HMAC") {
						t.Errorf("cipher %q reported although the proposal is unknown", n)
					}
				}
			},
		},
		{
			name: "unknown_phase1_reference",
			cfg:  hdr767 + "config vpn ipsec phase2-interface\n    edit \"lost\"\n        set phase1name \"missing\"\n        set proposal aes256gcm\n    next\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				eq(t, "warnings", warnCodes(inv), []string{"unknown-phase1"})
				p := find(t, inv, p2+"lost")
				if len(p.DependsOn) != 0 || len(p.Proto.IKEEncr) != 0 {
					t.Errorf("orphan phase2: dependsOn %v, encr %v; want neither", p.DependsOn, p.Proto.IKEEncr)
				}
				eq(t, "refs", names(inv, p.Proto.Refs), []string{"AES-256-GCM", "DH group 20 (ECP-384)"})
			},
		},
		{
			name: "policy_based_tables",
			cfg:  hdr767 + "config vpn ipsec phase1\n    edit \"pb\"\n        set ike-version 2\n        set proposal aes128gcm-prfsha256\n    next\nend\nconfig vpn ipsec phase2\n    edit \"pb2\"\n        set phase1name \"pb\"\n        set proposal aes128gcm\n    next\nend\n",
			check: func(t *testing.T, inv *model.Inventory) {
				p := find(t, inv, "FortiOS IPsec phase2 pb2")
				eq(t, "dependsOn", names(inv, p.DependsOn), []string{"FortiOS IPsec phase1 pb"})
				eq(t, "encr", names(inv, p.Proto.IKEEncr), []string{"AES-128-GCM"})
			},
		},
		{
			name: "multi_vdom",
			cfg:  fixture(t, "ipsec-multivdom-7.6.conf"),
			check: func(t *testing.T, inv *model.Inventory) {
				root := find(t, inv, p1+"to-dc (vdom root)")
				branch := find(t, inv, p1+"to-dc (vdom branch)")
				prop(t, root, "scope", "vdom root")
				prop(t, root, "dhgrp:source", "default")
				prop(t, branch, "dhgrp:value", "14")
				eq(t, "AES-256-CBC occurrences", occurrences(find(t, inv, "AES-256-CBC")), []string{"21 vdom root", "28 vdom root", "37 vdom branch"})
				eq(t, "root phase2 dependsOn", names(inv, find(t, inv, p2+"to-dc-p2 (vdom root)").DependsOn), []string{p1 + "to-dc (vdom root)"})
				eq(t, "warnings", warnCodes(inv), []string{})
			},
		},
		{
			name: "secrets_never_output",
			cfg: hdr767 + `config vpn ipsec phase1-interface
    edit "m"
        set proposal aes256-sha256 "ENC c3ludGhldGljLWJsb2I="
        set psksecret FortinetPasswordMask
        set certificate "c3ludGhldGljLWNlcnQ="
        set ppk-secret ENC c3ludGhldGljLXBwaw==
    next
end
`,
			check: func(t *testing.T, inv *model.Inventory) {
				prop(t, find(t, inv, p1+"m pre-shared key"), "psksecret:form", "masked")
				eq(t, "warnings", warnCodes(inv), []string{"unknown-token", "unknown-token"})
				prop(t, find(t, inv, p1+"m"), "proposal:value", "aes256-sha256")
				prop(t, find(t, inv, p1+"m"), "certificate:value", "")
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
