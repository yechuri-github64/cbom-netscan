// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package certs_test

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/certs"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// FuzzExtract feeds arbitrary DER, wrapped in a PEM certificate block, to the
// certificate extractor next to a private key. Extract must not panic, and
// the private-key text must never reach the inventory.
func FuzzExtract(f *testing.F) {
	pems, _ := filepath.Glob("testdata/*.pem")
	for _, p := range pems {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		if b, _ := pem.Decode(data); b != nil {
			f.Add(b.Bytes)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})

	const secret = "c3ludGhldGljLWZ1enota2V5"
	f.Fuzz(func(t *testing.T, der []byte) {
		block := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
		cfg := hdr + "config vpn certificate local\n    edit \"f\"\n        set private-key ENC " + secret +
			"\n        set certificate \"" + block + "\"\n    next\nend\n"
		tr, err := tree.Parse(strings.NewReader(cfg))
		if err != nil {
			return
		}
		inv := model.NewInventory()
		certs.Extract(tr, "fw.conf", inv, now)
		certs.Ref(tr, "fw.conf", tree.ScopeSingle, "f")
		dump, err := json.Marshal(struct {
			A []*model.Asset
			W []model.Warning
		}{inv.Assets, inv.Warnings})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(dump), secret) {
			t.Fatalf("private key text reached the inventory")
		}
	})
}
