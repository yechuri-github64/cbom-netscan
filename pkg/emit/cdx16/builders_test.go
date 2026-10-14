// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cdx16_test

// Synthetic test data below is dedicated to the public domain (CC0-1.0).

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/yechuri-github64/cbom-netscan/pkg/emit/cdx16"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

// builderInventory exercises every builder: a certificate, public and secret
// key material, a TLS protocol with cipher-suite identifiers and algorithm
// refs, an IKEv2 protocol with all five transform slots and a known ESN, an
// ESN-only protocol, properties, and dependencies.
func builderInventory() *model.Inventory {
	inv := model.NewInventory()
	add := func(a *model.Asset) string { return inv.Add(a).ID }
	at := func(s string) *time.Time { t, _ := time.Parse(time.RFC3339, s); return &t }
	size := 2048
	esnOn := true

	rsa := add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: "RSA-2048", Alg: &model.Algorithm{Primitive: "signature", ParameterSetIdentifier: "2048"}})
	sig := add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: "SHA256withRSA", Alg: &model.Algorithm{Primitive: "signature"}})
	aes := add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: "AES-256-GCM", Alg: &model.Algorithm{Primitive: "ae", Mode: "gcm"}})
	prf := add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: "PRF-HMAC-SHA384", Alg: &model.Algorithm{Primitive: "kdf"}})
	mac := add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: "HMAC-SHA256", Alg: &model.Algorithm{Primitive: "mac"}})
	dh := add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: "DH group 20 (ECP-384)", Alg: &model.Algorithm{Primitive: "key-agree", Curve: "secp384r1"}})

	pub := add(&model.Asset{
		Type: model.AssetTypeRelatedMaterial,
		Name: "lab cert public key",
		Mat: &model.Material{
			Type: "public-key", ID: "spki-sha256:00112233", State: "active", AlgorithmRef: rsa,
			Size: &size, Format: "DER",
			ActivationDate: at("2026-01-01T00:00:00Z"), ExpirationDate: at("2027-01-01T00:00:00Z"),
		},
	})
	psk := add(&model.Asset{Type: model.AssetTypeRelatedMaterial, Name: "tunnel PSK", Mat: &model.Material{Type: "secret-key"}})
	cert := add(&model.Asset{
		Type: model.AssetTypeCertificate,
		Name: "lab-vpn-cert",
		Cert: &model.Cert{
			SubjectName: "CN=vpn.example.com", IssuerName: "CN=Example Lab CA",
			NotValidBefore: at("2026-01-01T00:00:00Z"), NotValidAfter: at("2027-01-01T00:00:00Z"),
			SignatureAlgorithmRef: sig, SubjectPublicKeyRef: pub,
			Format: "X.509", Extension: "pem",
			SHA256: "aabbccdd", Serial: "01",
		},
		Properties: map[string]string{"cbom-netscan:test:z": "last", "cbom-netscan:test:a": "first"},
	})
	add(&model.Asset{
		Type: model.AssetTypeProtocol,
		Name: "TLS 1.3",
		Proto: &model.Protocol{
			Type: "tls", Version: "1.3",
			CipherSuites: []model.CipherSuite{{Name: "TLS_AES_256_GCM_SHA384", Identifiers: []string{"0x13", "0x02"}, AlgRefs: []string{aes}}},
			Refs:         []string{cert},
		},
		DependsOn: []string{cert},
	})
	add(&model.Asset{
		Type: model.AssetTypeProtocol,
		Name: "IKEv2 all slots",
		Proto: &model.Protocol{
			Type: "ike", Version: "2",
			IKEEncr: []string{aes}, IKEPRF: []string{prf}, IKEInteg: []string{mac}, IKEKE: []string{dh}, IKEAuth: []string{psk},
			ESN: &esnOn,
		},
	})
	add(&model.Asset{Type: model.AssetTypeProtocol, Name: "ESN only", Proto: &model.Protocol{Type: "ipsec", ESN: &esnOn}})
	return inv
}

func emitBuilders(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	meta := model.Meta{
		ToolVersion:  "test",
		Lifecycle:    "discovery",
		Created:      time.Unix(1791676800, 0),
		SerialNumber: "urn:uuid:00000000-0000-5000-8000-000000000001",
	}
	if err := (cdx16.Emitter{}).Emit(context.Background(), &buf, builderInventory(), meta); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	return buf.Bytes()
}

// TestEmit_Builders checks the CycloneDX fields each builder writes.
func TestEmit_Builders(t *testing.T) {
	var bom struct {
		Components []struct {
			Name       string            `json:"name"`
			Crypto     map[string]any    `json:"cryptoProperties"`
			Properties []json.RawMessage `json:"properties"`
		} `json:"components"`
		Dependencies []map[string]any `json:"dependencies"`
	}
	if err := json.Unmarshal(emitBuilders(t), &bom); err != nil {
		t.Fatal(err)
	}
	get := func(name string, path ...string) any {
		t.Helper()
		for _, c := range bom.Components {
			if c.Name != name {
				continue
			}
			var v any = c.Crypto
			for _, k := range path {
				m, ok := v.(map[string]any)
				if !ok {
					return nil
				}
				v = m[k]
			}
			return v
		}
		t.Fatalf("no component %q", name)
		return nil
	}

	cases := []struct {
		name, component string
		path            []string
		want            any
	}{
		{"cert subject", "lab-vpn-cert", []string{"certificateProperties", "subjectName"}, "CN=vpn.example.com"},
		{"cert issuer", "lab-vpn-cert", []string{"certificateProperties", "issuerName"}, "CN=Example Lab CA"},
		{"cert notValidBefore", "lab-vpn-cert", []string{"certificateProperties", "notValidBefore"}, "2026-01-01T00:00:00Z"},
		{"cert notValidAfter", "lab-vpn-cert", []string{"certificateProperties", "notValidAfter"}, "2027-01-01T00:00:00Z"},
		{"cert format", "lab-vpn-cert", []string{"certificateProperties", "certificateFormat"}, "X.509"},
		{"cert extension", "lab-vpn-cert", []string{"certificateProperties", "certificateExtension"}, "pem"},
		{"pubkey type", "lab cert public key", []string{"relatedCryptoMaterialProperties", "type"}, "public-key"},
		{"pubkey id", "lab cert public key", []string{"relatedCryptoMaterialProperties", "id"}, "spki-sha256:00112233"},
		{"pubkey state", "lab cert public key", []string{"relatedCryptoMaterialProperties", "state"}, "active"},
		{"pubkey size", "lab cert public key", []string{"relatedCryptoMaterialProperties", "size"}, float64(2048)},
		{"pubkey format", "lab cert public key", []string{"relatedCryptoMaterialProperties", "format"}, "DER"},
		{"pubkey activation", "lab cert public key", []string{"relatedCryptoMaterialProperties", "activationDate"}, "2026-01-01T00:00:00Z"},
		{"pubkey expiration", "lab cert public key", []string{"relatedCryptoMaterialProperties", "expirationDate"}, "2027-01-01T00:00:00Z"},
		{"secret key has no size", "tunnel PSK", []string{"relatedCryptoMaterialProperties", "size"}, nil},
		{"secret key has no state", "tunnel PSK", []string{"relatedCryptoMaterialProperties", "state"}, nil},
		{"secret key has no algorithmRef", "tunnel PSK", []string{"relatedCryptoMaterialProperties", "algorithmRef"}, nil},
		{"tls version", "TLS 1.3", []string{"protocolProperties", "version"}, "1.3"},
		{"esn-only protocol", "ESN only", []string{"protocolProperties", "ikev2TransformTypes", "esn"}, true},
		{"ikev2 esn", "IKEv2 all slots", []string{"protocolProperties", "ikev2TransformTypes", "esn"}, true},
	}
	for _, tc := range cases {
		if got := get(tc.component, tc.path...); got != tc.want {
			t.Errorf("%s: got %v (%T), want %v", tc.name, got, got, tc.want)
		}
	}

	suites, _ := get("TLS 1.3", "protocolProperties", "cipherSuites").([]any)
	if len(suites) != 1 {
		t.Fatalf("cipherSuites = %v", suites)
	}
	suite := suites[0].(map[string]any)
	if ids, _ := json.Marshal(suite["identifiers"]); string(ids) != `["0x13","0x02"]` {
		t.Errorf("cipherSuite identifiers = %s", ids)
	}
	if algs, _ := suite["algorithms"].([]any); len(algs) != 1 {
		t.Errorf("cipherSuite algorithms = %v", suite["algorithms"])
	}

	slots, _ := get("IKEv2 all slots", "protocolProperties", "ikev2TransformTypes").(map[string]any)
	for _, k := range []string{"encr", "prf", "integ", "ke", "auth"} {
		if list, _ := slots[k].([]any); len(list) != 1 {
			t.Errorf("ikev2TransformTypes.%s = %v, want one ref", k, slots[k])
		}
	}

	for _, c := range bom.Components {
		if c.Name != "lab-vpn-cert" {
			continue
		}
		var names []string
		for _, raw := range c.Properties {
			var p struct{ Name, Value string }
			_ = json.Unmarshal(raw, &p)
			names = append(names, p.Name+"="+p.Value)
		}
		want := `[cbom-netscan:cert:serial=01 cbom-netscan:cert:sha256=aabbccdd cbom-netscan:test:a=first cbom-netscan:test:z=last]`
		if got := fmt.Sprint(names); got != want {
			t.Errorf("certificate properties = %s, want %s (sorted, with cert fields)", got, want)
		}
	}

	if len(bom.Dependencies) != 1 {
		t.Errorf("dependencies = %v, want the TLS → certificate edge", bom.Dependencies)
	}
}

// TestEmit_DependencyOrder: dependencies are sorted by ref, whatever order
// the assets were added in.
func TestEmit_DependencyOrder(t *testing.T) {
	inv := model.NewInventory()
	target := inv.Add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: "AES-256-GCM", Alg: &model.Algorithm{Primitive: "ae"}}).ID
	for _, n := range []string{"zz", "mm", "aa", "qq"} {
		inv.Add(&model.Asset{Type: model.AssetTypeProtocol, Name: n, Proto: &model.Protocol{Type: "ipsec"}, DependsOn: []string{target}})
	}
	var buf bytes.Buffer
	if err := (cdx16.Emitter{}).Emit(context.Background(), &buf, inv, model.Meta{}); err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Dependencies []struct{ Ref string } `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, d := range bom.Dependencies {
		refs = append(refs, d.Ref)
	}
	if len(refs) != 4 || !slices.IsSorted(refs) {
		t.Errorf("dependency refs = %v, want 4 sorted refs", refs)
	}
}

// TestEmit_BuildersGolden keeps a golden file of the builder output in
// pkg/testdata/golden, so CI validates it against the CycloneDX 1.6 schema
// with cyclonedx-cli.
func TestEmit_BuildersGolden(t *testing.T) {
	got := emitBuilders(t)
	path := filepath.Join("..", "..", "testdata", "golden", "emitter-builders.cdx.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s; run go test -update and review the diff", path)
	}
}
