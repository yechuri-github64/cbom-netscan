// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cdx16_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/yechuri-github64/cbom-netscan/pkg/emit/cdx16"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// intPtr is a test helper that returns a pointer to an int literal.
func intPtr(v int) *int { return &v }

// TestEmit_AES256GCM builds a single AES-256-GCM algorithm asset, emits it
// as CycloneDX 1.6 JSON, and checks the key fields.
//
// AES-256-GCM values from plan §5.1 and V20:
//   - primitive: "ae"   (authenticated encryption; GCM/ChaCha20-Poly1305 → ae)
//   - mode:      "gcm"
//   - classical security level: 256 bits
//   - OID:       2.16.840.1.101.3.4.1.46
func TestEmit_AES256GCM(t *testing.T) {
	// ── 1. Build the inventory ───────────────────────────────────────────────
	inv := model.NewInventory()

	asset := &model.Asset{
		Type: model.AssetTypeAlgorithm,
		Name: "AES-256-GCM",
		OID:  "2.16.840.1.101.3.4.1.46",
		Alg: &model.Algorithm{
			Primitive:              "ae",
			Mode:                   "gcm",
			ClassicalSecurityLevel: intPtr(256),
			CryptoFunctions:        []string{"encrypt", "decrypt"},
		},
	}
	inv.Add(asset)

	// ── 2. Emit ──────────────────────────────────────────────────────────────
	// Fixed timestamp and serial so the golden file is stable; the emitter
	// defaults (now, random UUIDv4) are covered by TestEmit_DefaultSerialAndTimestamp.
	meta := model.Meta{
		ToolVersion:  "test",
		Lifecycle:    "discovery",
		Created:      time.Unix(1791676800, 0), // 2026-10-11 00:00:00 UTC
		SerialNumber: "urn:uuid:60f4096c-3a98-4d2c-8e90-e1d86f3843b0",
	}

	var buf bytes.Buffer
	emitter := cdx16.Emitter{}
	if err := emitter.Emit(context.Background(), &buf, inv, meta); err != nil {
		t.Fatalf("Emit() error: %v", err)
	}

	raw := buf.Bytes()
	t.Logf("emitted JSON:\n%s", raw)

	// ── 3. Parse and assert ──────────────────────────────────────────────────
	var bom map[string]any
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Top-level envelope.
	assertEqual(t, "bomFormat", "CycloneDX", bom["bomFormat"])
	assertEqual(t, "specVersion", "1.6", bom["specVersion"])

	// Serial number must be a urn:uuid:.
	serial, _ := bom["serialNumber"].(string)
	if len(serial) == 0 || serial[:9] != "urn:uuid:" {
		t.Errorf("serialNumber = %q, want urn:uuid:… prefix", serial)
	}

	// Timestamp must be RFC 3339 and match the fixed epoch.
	md, _ := bom["metadata"].(map[string]any)
	ts, _ := md["timestamp"].(string)
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("metadata.timestamp %q is not RFC 3339: %v", ts, err)
	}
	assertEqual(t, "metadata.timestamp", "2026-10-11T00:00:00Z", ts)

	// Lifecycle must be "discovery".
	lcs, _ := md["lifecycles"].([]any)
	if len(lcs) != 1 {
		t.Fatalf("metadata.lifecycles len = %d, want 1", len(lcs))
	}
	lc, _ := lcs[0].(map[string]any)
	assertEqual(t, "lifecycle.phase", "discovery", lc["phase"])

	// Exactly one component.
	comps, _ := bom["components"].([]any)
	if len(comps) != 1 {
		t.Fatalf("components len = %d, want 1", len(comps))
	}
	comp, _ := comps[0].(map[string]any)

	assertEqual(t, "component.type", "cryptographic-asset", comp["type"])
	assertEqual(t, "component.name", "AES-256-GCM", comp["name"])

	// bom-ref must start with "crypto/".
	bomRef, _ := comp["bom-ref"].(string)
	if len(bomRef) < 7 || bomRef[:7] != "crypto/" {
		t.Errorf("bom-ref = %q, want crypto/… prefix", bomRef)
	}

	// cryptoProperties.
	cp, _ := comp["cryptoProperties"].(map[string]any)
	assertEqual(t, "cryptoProperties.assetType", "algorithm", cp["assetType"])
	assertEqual(t, "cryptoProperties.oid", "2.16.840.1.101.3.4.1.46", cp["oid"])

	ap, _ := cp["algorithmProperties"].(map[string]any)
	assertEqual(t, "algorithmProperties.primitive", "ae", ap["primitive"])
	assertEqual(t, "algorithmProperties.mode", "gcm", ap["mode"])

	// classicalSecurityLevel must be the number 256.
	csl, _ := ap["classicalSecurityLevel"].(float64) // JSON numbers decode as float64
	if int(csl) != 256 {
		t.Errorf("classicalSecurityLevel = %v, want 256", ap["classicalSecurityLevel"])
	}

	// cryptoFunctions must contain encrypt and decrypt.
	funcs, _ := ap["cryptoFunctions"].([]any)
	funcSet := make(map[string]bool, len(funcs))
	for _, f := range funcs {
		if s, ok := f.(string); ok {
			funcSet[s] = true
		}
	}
	for _, want := range []string{"encrypt", "decrypt"} {
		if !funcSet[want] {
			t.Errorf("cryptoFunctions missing %q; got %v", want, funcs)
		}
	}

	// ── 4. Write golden file ─────────────────────────────────────────────────
	// The golden file is used by the CI cyclonedx-cli schema validation step
	// (added in a later commit).  Writing it here keeps the test self-contained.
	goldenDir := filepath.Join("..", "..", "testdata", "golden")
	if err := os.MkdirAll(goldenDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", goldenDir, err)
	}
	goldenPath := filepath.Join(goldenDir, "aes256gcm.cdx.json")
	if err := os.WriteFile(goldenPath, raw, 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", goldenPath, err)
	}
	t.Logf("golden file written to %s", goldenPath)
}

// TestGoldenCryptoAssetType guards against the cyclonedx-go bug where
// EncodeVersion silently downgrades "cryptographic-asset" to "application"
// (https://github.com/CycloneDX/cyclonedx-go/issues/298).
// It reads every *.cdx.json in pkg/testdata/golden/ and asserts that any
// component carrying a cryptoProperties object has type "cryptographic-asset".
func TestGoldenCryptoAssetType(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "testdata", "golden")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", goldenDir, err)
	}

	var checked int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}

		path := filepath.Join(goldenDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", path, err)
		}

		var bom struct {
			Components []map[string]any `json:"components"`
		}
		if err := json.Unmarshal(data, &bom); err != nil {
			t.Fatalf("%s: invalid JSON: %v", e.Name(), err)
		}

		for i, comp := range bom.Components {
			if _, hasCrypto := comp["cryptoProperties"]; !hasCrypto {
				continue
			}
			got, _ := comp["type"].(string)
			if got != "cryptographic-asset" {
				t.Errorf("%s: components[%d].type = %q, want \"cryptographic-asset\" (EncodeVersion downgrade bug?)", e.Name(), i, got)
			}
			checked++
		}
	}

	if checked == 0 {
		t.Error("no components with cryptoProperties found in any golden file — golden files missing or empty?")
	}
}

// TestEmit_EvidenceOccurrence checks that evidence line and symbol reach
// evidence.occurrences, and that line is omitted when unknown (0).
func TestEmit_EvidenceOccurrence(t *testing.T) {
	inv := model.NewInventory()
	inv.Add(&model.Asset{
		Type: model.AssetTypeAlgorithm,
		Name: "aes256-ctr",
		Alg:  &model.Algorithm{Primitive: "block-cipher", Mode: "ctr"},
		Evidence: []model.Evidence{
			{Location: "fw.conf", Line: 12, Symbol: "system ssh-config/ssh-enc-algo"},
			{Location: "other.conf"},
		},
	})
	var buf bytes.Buffer
	if err := (cdx16.Emitter{}).Emit(context.Background(), &buf, inv, model.Meta{ToolVersion: "test"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var bom struct {
		Components []struct {
			Evidence struct {
				Occurrences []map[string]any `json:"occurrences"`
			} `json:"evidence"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	occs := bom.Components[0].Evidence.Occurrences
	if len(occs) != 2 {
		t.Fatalf("occurrences = %v, want 2", occs)
	}
	assertEqual(t, "occ[0].location", "fw.conf", occs[0]["location"])
	assertEqual(t, "occ[0].line", float64(12), occs[0]["line"])
	assertEqual(t, "occ[0].symbol", "system ssh-config/ssh-enc-algo", occs[0]["symbol"])
	if _, ok := occs[1]["line"]; ok {
		t.Errorf("occ[1] has a line although Evidence.Line is 0: %v", occs[1])
	}
}

// TestEmit_ComponentOrder checks the output order: protocols, algorithms,
// certificates, related material, then by name within each type.
func TestEmit_ComponentOrder(t *testing.T) {
	inv := model.NewInventory()
	add := func(typ model.AssetType, name string) {
		a := &model.Asset{Type: typ, Name: name}
		switch typ {
		case model.AssetTypeProtocol:
			a.Proto = &model.Protocol{Type: "ssh"}
		case model.AssetTypeAlgorithm:
			a.Alg = &model.Algorithm{Primitive: "mac"}
		case model.AssetTypeCertificate:
			a.Cert = &model.Cert{}
		case model.AssetTypeRelatedMaterial:
			a.Mat = &model.Material{Type: "private-key"}
		}
		inv.Add(a)
	}
	add(model.AssetTypeRelatedMaterial, "a-key")
	add(model.AssetTypeAlgorithm, "zz-alg")
	add(model.AssetTypeCertificate, "a-cert")
	add(model.AssetTypeProtocol, "z-proto")
	add(model.AssetTypeAlgorithm, "aa-alg")
	add(model.AssetTypeProtocol, "a-proto")

	var buf bytes.Buffer
	if err := (cdx16.Emitter{}).Emit(context.Background(), &buf, inv, model.Meta{}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var bom struct {
		Components []struct{ Name string } `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range bom.Components {
		got = append(got, c.Name)
	}
	want := []string{"a-proto", "z-proto", "aa-alg", "zz-alg", "a-cert", "a-key"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// emitMeta emits a one-component inventory with meta and returns the BOM.
func emitMeta(t *testing.T, meta model.Meta) map[string]any {
	t.Helper()
	inv := model.NewInventory()
	inv.Add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: "aes256-ctr", Alg: &model.Algorithm{Primitive: "block-cipher"}})
	var buf bytes.Buffer
	if err := (cdx16.Emitter{}).Emit(context.Background(), &buf, inv, meta); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var bom map[string]any
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	return bom
}

var uuidV4RE = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestEmit_DefaultSerialAndTimestamp: with an empty Meta every BOM gets a new
// random UUIDv4 serial and the current time, even with SOURCE_DATE_EPOCH set,
// because the emitter reads no environment variables.
func TestEmit_DefaultSerialAndTimestamp(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1791676800")
	before := time.Now().UTC().Add(-time.Second)
	a, b := emitMeta(t, model.Meta{}), emitMeta(t, model.Meta{})

	sa, sb := a["serialNumber"].(string), b["serialNumber"].(string)
	if !uuidV4RE.MatchString(sa) || !uuidV4RE.MatchString(sb) {
		t.Errorf("serials %q, %q are not UUIDv4 URNs", sa, sb)
	}
	if sa == sb {
		t.Errorf("two default BOMs share serial %s", sa)
	}
	ts, _ := a["metadata"].(map[string]any)["timestamp"].(string)
	got, err := time.Parse(time.RFC3339, ts)
	if err != nil || got.Before(before) {
		t.Errorf("timestamp %q is not the current time (SOURCE_DATE_EPOCH must be ignored)", ts)
	}
}

func TestEmit_OmitTimestamp(t *testing.T) {
	bom := emitMeta(t, model.Meta{OmitTimestamp: true, SerialNumber: "urn:uuid:00000000-0000-5000-8000-000000000000"})
	if _, ok := bom["metadata"].(map[string]any)["timestamp"]; ok {
		t.Errorf("timestamp present although OmitTimestamp is set")
	}
	if bom["serialNumber"] != "urn:uuid:00000000-0000-5000-8000-000000000000" {
		t.Errorf("serialNumber = %v, want the one from Meta", bom["serialNumber"])
	}
}

// TestReproducibleSerial checks the UUIDv5 against Python's uuid.uuid5 for
// the same namespace and name, an independent implementation.
func TestReproducibleSerial(t *testing.T) {
	sum := sha256.Sum256([]byte("cbom-netscan reproducible-serial test vector\n"))
	const want = "urn:uuid:050dac56-225b-5fd1-ad24-521a83f9fdb6"
	if got := cdx16.ReproducibleSerial(sum, "v1.2.3"); got != want {
		t.Errorf("ReproducibleSerial = %s, want %s", got, want)
	}
	if cdx16.ReproducibleSerial(sum, "v1.2.4") == want {
		t.Errorf("serial does not change with the tool version")
	}
	other := sha256.Sum256([]byte("different input"))
	if cdx16.ReproducibleSerial(other, "v1.2.3") == want {
		t.Errorf("serial does not change with the input")
	}
}

// TestEmit_ESN checks that ikev2TransformTypes.esn is omitted when the model
// does not know it and kept as written when it does. The ESN edit works by
// position, so each scenario mixes known and unknown in a different order.
func TestEmit_ESN(t *testing.T) {
	no, yes := false, true
	scenarios := []struct {
		name   string
		protos map[string]*bool // component name → model ESN; output is sorted by name
	}{
		{"unknown_then_known", map[string]*bool{"a-unknown": nil, "b-off": &no, "c-on": &yes}},
		{"known_then_unknown", map[string]*bool{"a-on": &yes, "b-unknown": nil}},
		{"only_second_known", map[string]*bool{"a-unknown": nil, "b-on": &yes}},
		{"all_unknown", map[string]*bool{"a-unknown": nil, "b-unknown": nil}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			inv := model.NewInventory()
			alg := inv.Add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: "AES-256-GCM", Alg: &model.Algorithm{Primitive: "ae"}})
			for name, esn := range sc.protos {
				inv.Add(&model.Asset{
					Type:  model.AssetTypeProtocol,
					Name:  name,
					Proto: &model.Protocol{Type: "ipsec", IKEEncr: []string{alg.ID}, ESN: esn},
				})
			}
			var buf bytes.Buffer
			if err := (cdx16.Emitter{}).Emit(context.Background(), &buf, inv, model.Meta{}); err != nil {
				t.Fatalf("Emit: %v", err)
			}
			var bom struct {
				Components []struct {
					Name             string
					CryptoProperties struct {
						ProtocolProperties struct {
							IKEv2TransformTypes map[string]any `json:"ikev2TransformTypes"`
						} `json:"protocolProperties"`
					} `json:"cryptoProperties"`
				} `json:"components"`
			}
			if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
			checked := 0
			for _, c := range bom.Components {
				esn, ok := sc.protos[c.Name]
				if !ok {
					continue
				}
				checked++
				got, present := c.CryptoProperties.ProtocolProperties.IKEv2TransformTypes["esn"]
				switch {
				case esn == nil && present:
					t.Errorf("%s: esn = %v, want omitted", c.Name, got)
				case esn != nil && got != *esn:
					t.Errorf("%s: esn = %v, want %v", c.Name, got, *esn)
				}
				if _, ok := c.CryptoProperties.ProtocolProperties.IKEv2TransformTypes["encr"]; !ok {
					t.Errorf("%s: encr lost while editing esn", c.Name)
				}
			}
			if checked != len(sc.protos) {
				t.Errorf("checked %d protocol components, want %d", checked, len(sc.protos))
			}
		})
	}
}

// assertEqual is a tiny assertion helper that avoids importing testify for now.
func assertEqual(t *testing.T, field string, want, got any) {
	t.Helper()
	if want != got {
		t.Errorf("%s = %v (%T), want %v (%T)", field, got, got, want, want)
	}
}
