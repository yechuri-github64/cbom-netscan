// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cdx16

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// benchInventory has n tunnels sharing four algorithms. With ikev2 set they
// fill ikev2TransformTypes with an unknown ESN, so Emit runs omitESN; without
// it they use cryptoRefArray and the ESN pass is skipped.
func benchInventory(n int, ikev2 bool) *model.Inventory {
	inv := model.NewInventory()
	alg := func(name, prim string) string {
		return inv.Add(&model.Asset{Type: model.AssetTypeAlgorithm, Name: name, Alg: &model.Algorithm{Primitive: prim}}).ID
	}
	encr, prf, integ, ke := alg("AES-256-GCM", "ae"), alg("PRF-HMAC-SHA384", "kdf"), alg("HMAC-SHA256", "mac"), alg("ECP-384", "key-agree")
	for i := 0; i < n; i++ {
		p := &model.Protocol{Type: "ike", Version: "2"}
		if ikev2 {
			p.IKEEncr, p.IKEPRF, p.IKEInteg, p.IKEKE = []string{encr}, []string{prf}, []string{integ}, []string{ke}
		} else {
			p.Refs = []string{encr, prf, integ, ke}
		}
		inv.Add(&model.Asset{
			Type:       model.AssetTypeProtocol,
			Name:       fmt.Sprintf("tunnel-%06d", i),
			Proto:      p,
			Properties: map[string]string{"cbom-netscan:fortios:dhgrp:source": "configured"},
			Evidence:   []model.Evidence{{Location: "fw.conf", Line: i + 1, Symbol: "vpn ipsec phase1-interface"}},
		})
	}
	return inv
}

var benchMeta = model.Meta{SerialNumber: "urn:uuid:00000000-0000-5000-8000-000000000000", OmitTimestamp: true}

// BenchmarkEmit compares a full emit that needs the ESN pass with one that
// skips it, at the same component count; the difference is what omitESN
// adds end to end.
func BenchmarkEmit(b *testing.B) {
	for _, tc := range []struct {
		name  string
		ikev2 bool
	}{{"ikev2-esn-pass", true}, {"ikev1-no-esn-pass", false}} {
		b.Run(tc.name, func(b *testing.B) {
			inv := benchInventory(5000, tc.ikev2)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := (Emitter{}).Emit(context.Background(), io.Discard, inv, benchMeta); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOmitESN measures the scan alone on the compact JSON of the IKEv2
// inventory, reported in MB/s.
func BenchmarkOmitESN(b *testing.B) {
	inv := benchInventory(5000, true)
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	components, deps := buildComponents(inv.Assets)
	bom.Components = &components
	if len(deps) > 0 {
		bom.Dependencies = &deps
	}
	compact, err := json.Marshal(bom)
	if err != nil {
		b.Fatal(err)
	}
	unknown := unknownESN(components, inv.Assets)
	b.SetBytes(int64(len(compact)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := omitESN(compact, unknown); err != nil {
			b.Fatal(err)
		}
	}
}
