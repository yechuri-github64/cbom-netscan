// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package certs_test

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).
// The certificates come from testdata/gencerts.go; their keys were discarded.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/certs"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const hdr = "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin\n"

// secretFragments occur only inside secret values (private keys, passwords)
// and the PEM armour, none of which may reach the inventory.
var secretFragments = []string{"c3ludGhldGlj", "PRIVATE KEY", "BEGIN CERTIFICATE", "ENC ", "FortinetPasswordMask"}

// now is 2026-10-11T00:00:00Z, the CLI tests' SOURCE_DATE_EPOCH.
var now = time.Unix(1791676800, 0).UTC()

func pemFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// config is one backup with every kind of certificate entry: RSA and ECDSA
// local certificates with private keys in the encrypted-PEM and ENC forms,
// an expired one, a CA, a long-lived remote certificate under the 7.6
// "certificate remote" path, and a PEM that does not parse.
func config(t *testing.T) string {
	return hdr + `config vpn certificate local
    edit "vpn-rsa"
        set password ENC c3ludGhldGljLWNlcnQtcGFzcw==
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
c3ludGhldGljLXJzYS1rZXk=
-----END ENCRYPTED PRIVATE KEY-----"
        set certificate "` + pemFile(t, "vpn-rsa.pem") + `"
        set source user
    next
    edit "gw-ecdsa"
        set private-key ENC c3ludGhldGljLWVjZHNhLWtleQ==
        set certificate "` + pemFile(t, "gw-ecdsa.pem") + `"
    next
    edit "old-expired"
        set private-key FortinetPasswordMask
        set certificate "` + pemFile(t, "old-expired.pem") + `"
        set range global
    next
    edit "broken"
        set private-key ENC c3ludGhldGljLWJyb2tlbg==
        set certificate "-----BEGIN CERTIFICATE-----
c3ludGhldGljLW5vdC1hLWNlcnQ=
-----END CERTIFICATE-----"
    next
end
config vpn certificate ca
    edit "lab-root-ca"
        set ca "` + pemFile(t, "lab-root-ca.pem") + `"
        set source factory-c3ludGhldGlj
    next
end
config certificate remote
    edit "long-lived"
        set remote "` + pemFile(t, "long-lived.pem") + `"
        set private-key ENC c3ludGhldGljLW5vdC1hLWZpZWxk
    next
end
`
}

func extract(t *testing.T, cfg string, at time.Time) (*tree.Tree, *model.Inventory) {
	t.Helper()
	tr, err := tree.Parse(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	inv := model.NewInventory()
	certs.Extract(tr, "fw.conf", inv, at)
	return tr, inv
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

func byID(t *testing.T, inv *model.Inventory, id string) *model.Asset {
	t.Helper()
	for _, a := range inv.Assets {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no component with bom-ref %q", id)
	return nil
}

func prop(t *testing.T, a *model.Asset, key, want string) {
	t.Helper()
	if got, ok := a.Properties[key]; !ok || got != want {
		t.Errorf("%s: %s = %q (present %v), want %q", a.Name, key, got, ok, want)
	}
}

func noProp(t *testing.T, a *model.Asset, key string) {
	t.Helper()
	if got, ok := a.Properties[key]; ok {
		t.Errorf("%s: %s = %q, want it absent", a.Name, key, got)
	}
}

const local = "FortiOS certificate local "

func TestExtractCertificates(t *testing.T) {
	_, inv := extract(t, config(t), now)

	type want struct {
		name, subject, keyAlg, keyOID, keyPrim, curve, psi string
		keySize                                            int
		sigAlg, sigOID, padding                            string
		days                                               string
		cabf, exceeds, expired, isCA                       string
	}
	for _, w := range []want{
		{
			name: local + "vpn-rsa", subject: "CN=vpn.example.com,O=Example Lab",
			keyAlg: "RSA-2048", keyOID: "1.2.840.113549.1.1.1", keyPrim: "pke", psi: "2048", keySize: 2048,
			sigAlg: "ECDSA-SHA384", sigOID: "1.2.840.10045.4.3.3",
			days: "121", cabf: "200 (notBefore on or after 2026-03-15; Baseline Requirements §6.3.2)", exceeds: "false", expired: "false", isCA: "false",
		},
		{
			name: local + "gw-ecdsa", subject: "CN=gw.example.net,O=Example Lab",
			keyAlg: "ECDSA-P256", keyOID: "1.2.840.10045.2.1", keyPrim: "signature", curve: "secp256r1", keySize: 256,
			sigAlg: "ECDSA-SHA384", sigOID: "1.2.840.10045.4.3.3",
			days: "181", cabf: "200 (notBefore on or after 2026-03-15; Baseline Requirements §6.3.2)", exceeds: "false", expired: "false", isCA: "false",
		},
		{
			// 2024 is a leap year: 1 January to 31 December inclusive is 366 days.
			name: local + "old-expired", subject: "CN=old.example.org,O=Example Lab",
			keyAlg: "RSA-2048", keyOID: "1.2.840.113549.1.1.1", keyPrim: "pke", psi: "2048", keySize: 2048,
			sigAlg: "SHA256-RSA", sigOID: "1.2.840.113549.1.1.11", padding: "pkcs1v15",
			days: "366", cabf: "398 (notBefore before 2026-03-15; Baseline Requirements §6.3.2)", exceeds: "false", expired: "true", isCA: "false",
		},
		{
			// 2028 and 2032 are leap years: 3652 days apart, 3653 inclusive.
			name: "FortiOS certificate ca lab-root-ca", subject: "CN=Example Lab Root CA,O=Example Lab",
			keyAlg: "ECDSA-P384", keyOID: "1.2.840.10045.2.1", keyPrim: "signature", curve: "secp384r1", keySize: 384,
			sigAlg: "ECDSA-SHA384", sigOID: "1.2.840.10045.4.3.3",
			days: "3653", cabf: "not applicable: CA certificate", expired: "false", isCA: "true",
		},
		{
			// 731 days apart, 732 inclusive, issued after 2026-03-15: over 200.
			name: "FortiOS certificate remote long-lived", subject: "CN=long.example.com,O=Example Lab",
			keyAlg: "ECDSA-P256", keyOID: "1.2.840.10045.2.1", keyPrim: "signature", curve: "secp256r1", keySize: 256,
			sigAlg: "ECDSA-SHA384", sigOID: "1.2.840.10045.4.3.3",
			days: "732", cabf: "200 (notBefore on or after 2026-03-15; Baseline Requirements §6.3.2)", exceeds: "true", expired: "false", isCA: "false",
		},
	} {
		t.Run(w.name, func(t *testing.T) {
			c := find(t, inv, w.name)
			if c.Type != model.AssetTypeCertificate || c.Cert.Format != "X.509" {
				t.Errorf("type %s format %q", c.Type, c.Cert.Format)
			}
			if c.Cert.SubjectName != w.subject {
				t.Errorf("subject = %q, want %q", c.Cert.SubjectName, w.subject)
			}
			if c.Cert.IssuerName == "" || c.Cert.NotValidBefore == nil || c.Cert.NotValidAfter == nil || len(c.Cert.SHA256) != 64 {
				t.Errorf("cert details incomplete: %+v", c.Cert)
			}

			sig := byID(t, inv, c.Cert.SignatureAlgorithmRef)
			if sig.Name != w.sigAlg || sig.OID != w.sigOID || sig.Alg.Primitive != "signature" || sig.Alg.Padding != w.padding {
				t.Errorf("signature algorithm = %s %s %+v, want %s %s padding %q", sig.Name, sig.OID, *sig.Alg, w.sigAlg, w.sigOID, w.padding)
			}
			pub := byID(t, inv, c.Cert.SubjectPublicKeyRef)
			if pub.Mat.Type != "public-key" || !strings.HasPrefix(pub.Mat.ID, "spki-sha256:") || pub.Mat.Size == nil || *pub.Mat.Size != w.keySize {
				t.Errorf("public key = %+v", *pub.Mat)
			}
			key := byID(t, inv, pub.Mat.AlgorithmRef)
			if key.Name != w.keyAlg || key.OID != w.keyOID || key.Alg.Primitive != w.keyPrim || key.Alg.Curve != w.curve || key.Alg.ParameterSetIdentifier != w.psi {
				t.Errorf("key algorithm = %s %s %+v", key.Name, key.OID, *key.Alg)
			}
			// RSA and ECDSA are broken by a quantum computer: level 0.
			for _, a := range []*model.Asset{sig, key} {
				if a.Alg.NISTQuantumLevel == nil || *a.Alg.NISTQuantumLevel != 0 {
					t.Errorf("%s: nistQuantumSecurityLevel = %v, want 0", a.Name, a.Alg.NISTQuantumLevel)
				}
			}

			prop(t, c, "cbom-netscan:cert:validity-days", w.days)
			prop(t, c, "cbom-netscan:cert:cabf-max-days", w.cabf)
			prop(t, c, "cbom-netscan:cert:expired", w.expired)
			prop(t, c, "cbom-netscan:cert:expiry-checked-at", "2026-10-11T00:00:00Z")
			prop(t, c, "cbom-netscan:cert:is-ca", w.isCA)
			if w.exceeds == "" {
				noProp(t, c, "cbom-netscan:cert:exceeds-cabf-max")
			} else {
				prop(t, c, "cbom-netscan:cert:exceeds-cabf-max", w.exceeds)
			}
		})
	}

	// Configured source and range are recorded; an unknown value is dropped.
	prop(t, find(t, inv, local+"vpn-rsa"), "cbom-netscan:fortios:source:value", "user")
	prop(t, find(t, inv, local+"old-expired"), "cbom-netscan:fortios:range:value", "global")
	noProp(t, find(t, inv, "FortiOS certificate ca lab-root-ca"), "cbom-netscan:fortios:source:value")

	// RSA-2048 and ECDSA-SHA384 are each one component shared by the
	// certificates that use them.
	n := map[string]int{}
	for _, a := range inv.Assets {
		n[a.Name]++
	}
	if n["RSA-2048"] != 1 || n["ECDSA-SHA384"] != 1 || n["ECDSA-P256"] != 1 {
		t.Errorf("shared algorithms not merged: %v", n)
	}
}

// TestPrivateKeysPresenceOnly: a private key in any form (encrypted PEM, ENC,
// masked) is one related-crypto-material component without an id, linked to
// the certificate key's algorithm and size.
func TestPrivateKeysPresenceOnly(t *testing.T) {
	_, inv := extract(t, config(t), now)
	for _, tc := range []struct {
		cert, alg string
		size      int
	}{
		{"vpn-rsa", "RSA-2048", 2048},
		{"gw-ecdsa", "ECDSA-P256", 256},
		{"old-expired", "RSA-2048", 2048},
		{"broken", "", 0}, // the PEM does not parse, so the key's algorithm is unknown
	} {
		k := find(t, inv, local+tc.cert+" private key")
		// model.Material has no value field at all, so only the id can leak.
		if k.Mat.Type != "private-key" || k.Mat.ID != "" {
			t.Errorf("%s: material = %+v; want a private-key with no id", k.Name, *k.Mat)
		}
		prop(t, k, "cbom-netscan:fortios:private-key", "present")
		if tc.alg == "" {
			if k.Mat.AlgorithmRef != "" || k.Mat.Size != nil {
				t.Errorf("%s: algorithm %q size %v, want none", k.Name, k.Mat.AlgorithmRef, k.Mat.Size)
			}
			continue
		}
		if byID(t, inv, k.Mat.AlgorithmRef).Name != tc.alg || k.Mat.Size == nil || *k.Mat.Size != tc.size {
			t.Errorf("%s: algorithm %q size %v, want %s %d", k.Name, k.Mat.AlgorithmRef, k.Mat.Size, tc.alg, tc.size)
		}
	}
	// CA and remote tables have no private-key field; one set there anyway
	// (long-lived) is not read.
	for _, a := range inv.Assets {
		if strings.HasSuffix(a.Name, " private key") && !strings.HasPrefix(a.Name, local) {
			t.Errorf("unexpected private key component %s", a.Name)
		}
	}
}

func TestWarnings(t *testing.T) {
	_, inv := extract(t, config(t), now)
	var codes []string
	for _, w := range inv.Warnings {
		codes = append(codes, w.Code)
		if w.Ev.Line == 0 || w.Ev.Location != "fw.conf" {
			t.Errorf("warning %s has no location: %+v", w.Code, w.Ev)
		}
	}
	if strings.Join(codes, " ") != "cert-expired cert-unparseable" {
		t.Errorf("warnings = %v, want [cert-expired cert-unparseable]", codes)
	}
	broken := find(t, inv, local+"broken")
	prop(t, broken, "cbom-netscan:cert:parse", "failed")
	if broken.Cert.SubjectName != "" || broken.Cert.SignatureAlgorithmRef != "" {
		t.Errorf("unparseable certificate has details: %+v", broken.Cert)
	}
}

// TestExpiryNotEvaluated: with no reference time, expiry is not judged and
// there is no expired warning, so output does not depend on the clock.
func TestExpiryNotEvaluated(t *testing.T) {
	_, inv := extract(t, config(t), time.Time{})
	c := find(t, inv, local+"old-expired")
	prop(t, c, "cbom-netscan:cert:expired", "not evaluated")
	noProp(t, c, "cbom-netscan:cert:expiry-checked-at")
	for _, w := range inv.Warnings {
		if w.Code == "cert-expired" {
			t.Errorf("cert-expired warning without a reference time: %+v", w)
		}
	}
	// The CA/B Forum check does not need a reference time.
	prop(t, find(t, inv, "FortiOS certificate remote long-lived"), "cbom-netscan:cert:exceeds-cabf-max", "true")
}

// TestExpiryBoundary: a certificate is expired only after its notAfter.
func TestExpiryBoundary(t *testing.T) {
	notAfter := time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		at   time.Time
		want string
	}{
		{notAfter.Add(-time.Second), "false"},
		{notAfter, "false"},
		{notAfter.Add(time.Second), "true"},
	} {
		_, inv := extract(t, config(t), tc.at)
		prop(t, find(t, inv, local+"old-expired"), "cbom-netscan:cert:expired", tc.want)
	}
}

func TestSecretsNeverInInventory(t *testing.T) {
	for _, at := range []time.Time{now, {}} {
		_, inv := extract(t, config(t), at)
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
	}
}

func TestRef(t *testing.T) {
	tr, inv := extract(t, config(t), now)
	r := certs.Ref(tr, "fw.conf", tree.ScopeSingle, "gw-ecdsa")
	if r.Missing || byID(t, inv, r.Cert).Name != local+"gw-ecdsa" || byID(t, inv, r.KeyAlg).Name != "ECDSA-P256" {
		t.Errorf("Ref(gw-ecdsa) = %+v", r)
	}
	if r := certs.Ref(tr, "fw.conf", tree.ScopeSingle, "broken"); r.Missing || r.Cert == "" || r.KeyAlg != "" {
		t.Errorf("Ref(broken) = %+v; want the certificate without a key algorithm", r)
	}
	// Only local certificates can identify this device; CA and remote names
	// and unknown names are missing.
	for _, name := range []string{"lab-root-ca", "long-lived", "Fortinet_Factory"} {
		if r := certs.Ref(tr, "fw.conf", tree.ScopeSingle, name); !r.Missing || r.Cert != "" {
			t.Errorf("Ref(%s) = %+v, want missing", name, r)
		}
	}
}

// TestMultiVDOM: certificates in global and in a VDOM get scoped names, and
// Ref from a VDOM falls back to global but not to another VDOM.
func TestMultiVDOM(t *testing.T) {
	cfg := strings.Replace(hdr, "vdom=0", "vdom=1", 1) + `config vdom
edit root
next
edit branch
next
end
config global
config vpn certificate local
    edit "shared"
        set certificate "` + pemFile(t, "gw-ecdsa.pem") + `"
    next
end
end
config vdom
edit root
config vpn certificate local
    edit "root-only"
        set certificate "` + pemFile(t, "vpn-rsa.pem") + `"
    next
end
next
edit branch
end
`
	tr, inv := extract(t, cfg, now)
	shared := find(t, inv, local+"shared (global)")
	rootOnly := find(t, inv, local+"root-only (vdom root)")
	if shared.Evidence[0].Context != "global" || rootOnly.Evidence[0].Context != "vdom root" {
		t.Errorf("evidence contexts = %q, %q", shared.Evidence[0].Context, rootOnly.Evidence[0].Context)
	}
	if r := certs.Ref(tr, "fw.conf", tree.VDOM("root"), "shared"); r.Cert != shared.ID {
		t.Errorf("root → shared = %+v, want the global certificate", r)
	}
	if r := certs.Ref(tr, "fw.conf", tree.VDOM("root"), "root-only"); r.Cert != rootOnly.ID {
		t.Errorf("root → root-only = %+v", r)
	}
	if r := certs.Ref(tr, "fw.conf", tree.VDOM("branch"), "root-only"); !r.Missing {
		t.Errorf("branch → root-only = %+v, want missing (another VDOM's certificate)", r)
	}
}

// TestNoCertificates: a backup without certificate tables adds nothing.
func TestNoCertificates(t *testing.T) {
	_, inv := extract(t, hdr+"config system global\nend\n", now)
	if len(inv.Assets) != 0 || len(inv.Warnings) != 0 {
		t.Errorf("assets %d warnings %v, want none", len(inv.Assets), inv.Warnings)
	}
}

// TestCABFBoundary: a leaf valid for exactly the maximum is within it; one
// second more is a day over. The certificates are generated here; their
// keys exist only in memory.
func TestCABFBoundary(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) // 200-day rule
	for _, tc := range []struct {
		after         time.Duration
		days, exceeds string
	}{
		{200*24*time.Hour - time.Second, "200", "false"},
		{200 * 24 * time.Hour, "201", "true"},
	} {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge.example.com"}, NotBefore: nb, NotAfter: nb.Add(tc.after)}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cfg := hdr + "config vpn certificate local\n    edit \"edge\"\n        set certificate \"" +
			strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))) + "\"\n    next\nend\n"
		_, inv := extract(t, cfg, now)
		c := find(t, inv, local+"edge")
		prop(t, c, "cbom-netscan:cert:validity-days", tc.days)
		prop(t, c, "cbom-netscan:cert:exceeds-cabf-max", tc.exceeds)
	}
}

// TestVDOMGlobalReferences: in a multi-VDOM backup each VDOM lists the global
// factory certificates with range global and no PEM. Those entries link to
// the global certificate instead of becoming components of their own, and
// produce no warnings.
func TestVDOMGlobalReferences(t *testing.T) {
	data, err := os.ReadFile("testdata/vdom-global-refs-7.6.conf")
	if err != nil {
		t.Fatal(err)
	}
	tr, inv := extract(t, string(data), now)
	if len(inv.Warnings) != 0 {
		t.Errorf("warnings = %+v, want none", inv.Warnings)
	}
	var certNames []string
	for _, a := range inv.Assets {
		if a.Type == model.AssetTypeCertificate {
			certNames = append(certNames, a.Name)
		}
	}
	want := []string{
		"FortiOS certificate ca Fortinet_CA (global)",
		"FortiOS certificate local Fortinet_Factory (global)",
		"FortiOS certificate local Fortinet_SSL_ECDSA256 (global)",
		"FortiOS certificate local Fortinet_SSL_ED25519 (global)",
	}
	slices.Sort(certNames)
	if !slices.Equal(certNames, want) {
		t.Errorf("certificates = %q, want %q (no per-VDOM copies)", certNames, want)
	}
	for _, name := range want {
		c := find(t, inv, name)
		prop(t, c, "cbom-netscan:fortios:referenced-from", "vdom branch, vdom root")
		var ctx []string
		for _, ev := range c.Evidence {
			ctx = append(ctx, ev.Context)
		}
		slices.Sort(ctx)
		if !slices.Equal(ctx, []string{"global", "vdom branch", "vdom root"}) {
			t.Errorf("%s: evidence contexts = %q", name, ctx)
		}
	}
	global := find(t, inv, "FortiOS certificate local Fortinet_Factory (global)")
	for _, vdom := range []string{"root", "branch"} {
		r := certs.Ref(tr, "fw.conf", tree.VDOM(vdom), "Fortinet_Factory")
		if r.Missing || r.Cert != global.ID || byID(t, inv, r.KeyAlg).Name != "RSA-2048" {
			t.Errorf("Ref from vdom %s = %+v, want the global certificate", vdom, r)
		}
	}
}

// TestNoPEMEntries: only a VDOM entry with range global and no PEM is a
// reference. A VDOM entry without range global, or a global entry, with no
// PEM still warns; a reference whose global certificate is missing gets its
// own warning; a VDOM entry with range global and a PEM is a certificate.
func TestNoPEMEntries(t *testing.T) {
	cfg := strings.Replace(hdr, "vdom=0", "vdom=1", 1) + `config vdom
edit root
next
end
config global
config vpn certificate local
    edit "global-empty"
        set range global
    next
end
end
config vdom
edit root
config vpn certificate local
    edit "vdom-empty"
        set source user
    next
    edit "dangling"
        set range global
        set source factory
    next
    edit "own-global"
        set range global
        set certificate "` + pemFile(t, "gw-ecdsa.pem") + `"
    next
end
end
`
	tr, inv := extract(t, cfg, now)
	var got []string
	for _, w := range inv.Warnings {
		got = append(got, w.Code+" "+w.Ev.Context)
	}
	slices.Sort(got)
	if want := []string{"cert-reference-missing vdom root", "cert-unparseable global", "cert-unparseable vdom root"}; !slices.Equal(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	find(t, inv, local+"own-global (vdom root)")
	for _, a := range inv.Assets {
		if strings.Contains(a.Name, "dangling") {
			t.Errorf("dangling reference became component %s", a.Name)
		}
	}
	if r := certs.Ref(tr, "fw.conf", tree.VDOM("root"), "dangling"); !r.Missing {
		t.Errorf("Ref(dangling) = %+v, want missing", r)
	}
}

// TestEd25519OneComponent: a pure Ed25519 certificate's key algorithm and
// signature algorithm are the same algorithm (id-Ed25519, 1.3.101.112), and
// Go names both "Ed25519". They must be one component with one definition;
// two definitions under one bom-ref caused a merge-conflict warning.
func TestEd25519OneComponent(t *testing.T) {
	cfg := hdr + `config vpn certificate local
    edit "Fortinet_SSL_ED25519"
        set private-key ENC c3ludGhldGljLWVkMjU1MTkta2V5
        set certificate "` + pemFile(t, "ed25519-self.pem") + `"
        set source factory
    next
end
`
	_, inv := extract(t, cfg, now)
	if len(inv.Warnings) != 0 {
		t.Errorf("warnings = %+v, want none", inv.Warnings)
	}
	c := find(t, inv, local+"Fortinet_SSL_ED25519")
	pub := byID(t, inv, c.Cert.SubjectPublicKeyRef)
	if c.Cert.SignatureAlgorithmRef != pub.Mat.AlgorithmRef {
		t.Errorf("signature algorithm %s and key algorithm %s differ; want the one Ed25519 component", c.Cert.SignatureAlgorithmRef, pub.Mat.AlgorithmRef)
	}
	ed := byID(t, inv, pub.Mat.AlgorithmRef)
	if ed.Name != "Ed25519" || ed.OID != "1.3.101.112" || ed.Alg.Primitive != "signature" || ed.Alg.Curve != "ed25519" || level(ed) != "0" {
		t.Errorf("Ed25519 = %s %s %+v", ed.Name, ed.OID, *ed.Alg)
	}
	if pub.Mat.Size == nil || *pub.Mat.Size != 256 {
		t.Errorf("public key size = %v, want 256", pub.Mat.Size)
	}
	prop(t, c, "cbom-netscan:cert:validity-days", "366")
}

func level(a *model.Asset) string {
	if a.Alg.NISTQuantumLevel == nil {
		return "unset"
	}
	return strconv.Itoa(*a.Alg.NISTQuantumLevel)
}

// TestPrivateKeyForms: the form comes from the first token or the BEGIN line
// alone. An unencrypted PKCS #8 key warns; a traditional or OpenSSH key, whose
// encryption the BEGIN line does not show, warns that it may be unencrypted.
// The key bodies here are not valid base64, so the test would fail if the
// code tried to decode them, and their marker text must not reach output.
func TestPrivateKeyForms(t *testing.T) {
	const body = "\nc3ludGhldGlj!!not-base64!!\n"
	for _, tc := range []struct {
		value, form string
		warn        string // "" none, else a message fragment
	}{
		{`ENC c3ludGhldGljLWtleQ==`, "ENC", ""},
		{`FortinetPasswordMask`, "masked", ""},
		{`"-----BEGIN ENCRYPTED PRIVATE KEY-----` + body + `-----END ENCRYPTED PRIVATE KEY-----"`, "encrypted-pem", ""},
		{`"-----BEGIN PRIVATE KEY-----` + body + `-----END PRIVATE KEY-----"`, "plaintext-pem", "is an unencrypted PEM key"},
		{`"-----BEGIN RSA PRIVATE KEY-----` + body + `-----END RSA PRIVATE KEY-----"`, "pem-encryption-unknown", "may be unencrypted"},
		{`"-----BEGIN EC PRIVATE KEY-----` + body + `-----END EC PRIVATE KEY-----"`, "pem-encryption-unknown", "may be unencrypted"},
		{`"-----BEGIN OPENSSH PRIVATE KEY-----` + body + `-----END OPENSSH PRIVATE KEY-----"`, "pem-encryption-unknown", "may be unencrypted"},
		// Text after the BEGIN line's closing dashes does not hide the key.
		{`"-----BEGIN PRIVATE KEY----- trailing` + body + `-----END PRIVATE KEY-----"`, "plaintext-pem", "is an unencrypted PEM key"},
		// Leading blank lines and spaces are skipped before the BEGIN line.
		{`"` + "\n\n  \t" + `-----BEGIN PRIVATE KEY-----` + body + `-----END PRIVATE KEY-----"`, "plaintext-pem", "is an unencrypted PEM key"},
		{`"` + "\r\n" + `-----BEGIN ENCRYPTED PRIVATE KEY-----` + body + `-----END ENCRYPTED PRIVATE KEY-----"`, "encrypted-pem", ""},
		// A BEGIN line after other text does not count: only the first
		// non-blank line is read.
		{`"c3ludGhldGlj` + "\n" + `-----BEGIN PRIVATE KEY-----` + body + `-----END PRIVATE KEY-----"`, "other", ""},
		{`c3ludGhldGljLXBsYWlu`, "other", ""},
	} {
		cfg := hdr + "config vpn certificate local\n    edit \"k\"\n        set private-key " + tc.value +
			"\n        set certificate \"" + pemFile(t, "gw-ecdsa.pem") + "\"\n    next\nend\n"
		_, inv := extract(t, cfg, now)
		k := find(t, inv, local+"k private key")
		prop(t, k, "cbom-netscan:fortios:private-key:form", tc.form)
		var msgs []string
		for _, w := range inv.Warnings {
			msgs = append(msgs, w.Code+": "+w.Message)
			if w.Code == "plaintext-private-key" && (w.Ev.Line != 4 || w.Ev.Symbol != "vpn certificate local/k/private-key") {
				t.Errorf("%s: warning evidence = %+v", tc.form, w.Ev)
			}
		}
		switch {
		case tc.warn == "" && len(msgs) != 0:
			t.Errorf("%s: warnings %q, want none", tc.form, msgs)
		case tc.warn != "" && (len(msgs) != 1 || !strings.HasPrefix(msgs[0], "plaintext-private-key: ") || !strings.Contains(msgs[0], tc.warn)):
			t.Errorf("%s: warnings %q, want one plaintext-private-key containing %q", tc.form, msgs, tc.warn)
		}
		dump, _ := json.Marshal(struct {
			A []*model.Asset
			W []model.Warning
		}{inv.Assets, inv.Warnings})
		for _, s := range []string{"c3ludGhldGlj", "not-base64", "PRIVATE KEY-----"} {
			if strings.Contains(string(dump), s) {
				t.Errorf("%s: output contains %q", tc.form, s)
			}
		}
	}
}

// TestCertificateFieldBlocks: a certificate field with several PEM blocks.
// Only the first CERTIFICATE block is decoded and parsed. A private key
// block before or after it is counted from its BEGIN line and warned about;
// its body (not valid base64 here) is never decoded or shown.
func TestCertificateFieldBlocks(t *testing.T) {
	key := "-----BEGIN PRIVATE KEY-----\nc3ludGhldGlj!!not-base64!!\n-----END PRIVATE KEY-----"
	rsaKey := strings.ReplaceAll(key, "PRIVATE KEY", "RSA PRIVATE KEY")
	gw, vpn := pemFile(t, "gw-ecdsa.pem"), pemFile(t, "vpn-rsa.pem")
	csr := "-----BEGIN CERTIFICATE REQUEST-----\nc3ludGhldGlj\n-----END CERTIFICATE REQUEST-----"
	for _, tc := range []struct {
		name, field string
		subject     string // "" if no certificate parses
		keys, extra string // property values, "" if absent
		other       string
	}{
		{"key_before_cert", key + "\n" + gw, "CN=gw.example.net,O=Example Lab", "1", "", ""},
		{"key_after_cert", gw + "\n" + rsaKey, "CN=gw.example.net,O=Example Lab", "1", "", ""},
		{"key_only", key, "", "1", "", ""},
		{"two_keys_around_cert", rsaKey + "\n" + gw + "\n" + key, "CN=gw.example.net,O=Example Lab", "2", "", ""},
		{"chain_first_cert_parsed", vpn + "\n" + gw, "CN=vpn.example.com,O=Example Lab", "", "1", ""},
		{"csr_then_cert", csr + "\n" + gw, "CN=gw.example.net,O=Example Lab", "", "", "1"},
		// BEGIN and END lines with trailing text are still recognised: the
		// key is counted and the certificate after it is parsed.
		{"trailing_text_on_key_lines", "-----BEGIN PRIVATE KEY-----junk\nc3ludGhldGlj\n-----END PRIVATE KEY----- junk\n" + gw, "CN=gw.example.net,O=Example Lab", "1", "", ""},
		// A key pasted inside the CERTIFICATE block: the key is counted, the
		// block is not decoded, and a later certificate is still parsed.
		{"key_inside_cert_block", certWithKeyInside(gw, key), "", "1", "", ""},
		{"key_inside_cert_then_cert", certWithKeyInside(gw, rsaKey) + "\n" + vpn, "CN=vpn.example.com,O=Example Lab", "1", "", ""},
		{"key_inside_unterminated_cert", "-----BEGIN CERTIFICATE-----\nMIIB\n" + key, "", "1", "", ""},
		// An unterminated key block swallows the rest of the field.
		{"unterminated_key", "-----BEGIN PRIVATE KEY-----\nc3ludGhldGlj\n" + gw, "", "1", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hdr + "config vpn certificate local\n    edit \"f\"\n        set certificate \"" + tc.field + "\"\n    next\nend\n"
			_, inv := extract(t, cfg, now)
			c := find(t, inv, local+"f")
			if c.Cert.SubjectName != tc.subject {
				t.Errorf("subject = %q, want %q", c.Cert.SubjectName, tc.subject)
			}
			for key, want := range map[string]string{
				"cbom-netscan:cert:key-blocks-in-certificate-field": tc.keys,
				"cbom-netscan:cert:additional-certificate-blocks":   tc.extra,
				"cbom-netscan:cert:other-pem-blocks":                tc.other,
			} {
				if got := c.Properties[key]; got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			var codes []string
			for _, w := range inv.Warnings {
				codes = append(codes, w.Code)
			}
			want := []string{}
			if tc.keys != "" {
				want = append(want, "private-key-in-certificate-field")
			}
			if tc.subject == "" {
				want = append(want, "cert-unparseable")
			}
			if strings.Join(codes, " ") != strings.Join(want, " ") {
				t.Errorf("warnings = %v, want %v", codes, want)
			}
			dump, _ := json.Marshal(struct {
				A []*model.Asset
				W []model.Warning
			}{inv.Assets, inv.Warnings})
			for _, s := range []string{"c3ludGhldGlj", "not-base64", "-----"} {
				if strings.Contains(string(dump), s) {
					t.Errorf("output contains %q", s)
				}
			}
		})
	}
}

// TestCABFInformational: exceeding the CA/B Forum limit is a property that
// says it is informational, never a warning, since internal VPN certificates
// are not bound by it. A CA certificate has neither property.
func TestCABFInformational(t *testing.T) {
	_, inv := extract(t, config(t), now)
	long := find(t, inv, "FortiOS certificate remote long-lived")
	prop(t, long, "cbom-netscan:cert:exceeds-cabf-max", "true")
	if got := long.Properties["cbom-netscan:cert:cabf-applicability"]; !strings.HasPrefix(got, "informational:") || !strings.Contains(got, "internal VPN certificates are not bound") {
		t.Errorf("cabf-applicability = %q", got)
	}
	prop(t, find(t, inv, local+"vpn-rsa"), "cbom-netscan:cert:cabf-applicability", long.Properties["cbom-netscan:cert:cabf-applicability"])
	noProp(t, find(t, inv, "FortiOS certificate ca lab-root-ca"), "cbom-netscan:cert:cabf-applicability")
	for _, w := range inv.Warnings {
		if strings.Contains(w.Code, "cabf") || strings.Contains(w.Message, "long-lived") {
			t.Errorf("CA/B limit produced a warning: %+v", w)
		}
	}
}

// certWithKeyInside puts key between the first and second lines of a
// certificate's base64 body.
func certWithKeyInside(cert, key string) string {
	lines := strings.Split(cert, "\n")
	return strings.Join(append(append(append([]string{}, lines[:2]...), key), lines[2:]...), "\n")
}
