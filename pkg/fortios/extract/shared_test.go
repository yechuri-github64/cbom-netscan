// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package extract_test checks properties that span the FortiOS extractors.
package extract_test

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/emit/cdx16"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/global"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/ipsec"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// shared uses, in one backup, every SSH cipher and MAC with a canonical name,
// the hybrid SSH key exchange, and IPsec proposals, DH groups, and addke that
// produce the same algorithms.
const shared = `#config-version=FGVMH6-8.0.1-FW-build1500-260801:opmode=0:vdom=0:user=admin
config system ssh-config
    set ssh-enc-algo aes128-ctr aes192-ctr aes256-ctr aes128-cbc aes192-cbc aes256-cbc rijndael-cbc@lysator.liu.se aes128-gcm@openssh.com aes256-gcm@openssh.com 3des-cbc
    set ssh-mac-algo hmac-md5 hmac-sha1 hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512
    set ssh-kex-algo mlkem768x25519-sha256 curve25519-sha256@libssh.org
end
config vpn ipsec phase1-interface
    edit "t"
        set ike-version 2
        set proposal aes128-md5 aes256-sha1 3des-sha256 aes192-sha512 aes128gcm-prfsha256 aes256gcm-prfsha384
        set dhgrp 31 20
        set addke1 ml-kem-768
    next
end
`

func parse(t *testing.T) *tree.Tree {
	t.Helper()
	tr, err := tree.Parse(strings.NewReader(shared))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// TestSharedDefinitionsAgree: an algorithm both extractors emit must be
// defined identically by both, because only the first copy is kept when the
// inventory merges them.
func TestSharedDefinitionsAgree(t *testing.T) {
	tr := parse(t)
	g, i := model.NewInventory(), model.NewInventory()
	global.Extract(tr, "fw.conf", g)
	ipsec.Extract(tr, "fw.conf", i)

	byName := map[string]*model.Asset{}
	for _, a := range g.Assets {
		if a.Type == model.AssetTypeAlgorithm {
			byName[a.Name] = a
		}
	}
	shared := 0
	for _, b := range i.Assets {
		a, ok := byName[b.Name]
		if !ok || b.Type != model.AssetTypeAlgorithm {
			continue
		}
		shared++
		if !reflect.DeepEqual(a.Alg, b.Alg) {
			t.Errorf("%s: SSH defines %+v, IPsec defines %+v", b.Name, *a.Alg, *b.Alg)
		}
		if a.ID != b.ID {
			t.Errorf("%s: bom-ref %s from SSH, %s from IPsec", b.Name, a.ID, b.ID)
		}
	}
	if shared < 8 {
		t.Errorf("only %d algorithms shared; the fixture should share at least 8", shared)
	}
}

// TestX25519CountedOnce: the SSH hybrid key exchange's X25519 part and IKE DH
// group 31 are the same algorithm, so they are one component referenced by
// both protocols. The SSH method curve25519-sha256@libssh.org (a curve plus a
// hash) stays its own component.
func TestX25519CountedOnce(t *testing.T) {
	tr := parse(t)
	inv := model.NewInventory()
	global.Extract(tr, "fw.conf", inv)
	ipsec.Extract(tr, "fw.conf", inv)

	var x25519 []string
	var id string
	for _, a := range inv.Assets {
		if a.Alg != nil && a.Alg.Curve == "x25519" {
			x25519 = append(x25519, a.Name)
		}
		if a.Name == "X25519" {
			id = a.ID
		}
	}
	slices.Sort(x25519)
	if !slices.Equal(x25519, []string{"X25519", "curve25519-sha256@libssh.org"}) {
		t.Errorf("x25519 components = %v, want [X25519 curve25519-sha256@libssh.org]", x25519)
	}
	var ssh, tunnel *model.Asset
	for _, a := range inv.Assets {
		switch a.Name {
		case "FortiOS admin SSH":
			ssh = a
		case "FortiOS IPsec phase1-interface t":
			tunnel = a
		}
	}
	if !slices.Contains(ssh.Proto.Refs, id) || !slices.Contains(tunnel.Proto.IKEKE, id) {
		t.Errorf("X25519 not referenced by both the SSH hybrid and IKE group 31")
	}
}

// TestExtractorOrderIndependent: running the extractors in either order gives
// byte-identical CBOMs, including components both add evidence to.
func TestExtractorOrderIndependent(t *testing.T) {
	emit := func(globalFirst bool) []byte {
		tr := parse(t)
		inv := model.NewInventory()
		if globalFirst {
			global.Extract(tr, "fw.conf", inv)
			ipsec.Extract(tr, "fw.conf", inv)
		} else {
			ipsec.Extract(tr, "fw.conf", inv)
			global.Extract(tr, "fw.conf", inv)
		}
		var buf bytes.Buffer
		meta := model.Meta{SerialNumber: "urn:uuid:00000000-0000-5000-8000-000000000000", OmitTimestamp: true}
		if err := (cdx16.Emitter{}).Emit(context.Background(), &buf, inv, meta); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	a, b := emit(true), emit(false)
	if !bytes.Equal(a, b) {
		t.Errorf("CBOM depends on extractor order")
	}
	if !bytes.Contains(a, []byte(`"symbol": "system ssh-config/ssh-enc-algo"`)) || !bytes.Contains(a, []byte(`"symbol": "vpn ipsec phase1-interface/t/proposal"`)) {
		t.Errorf("fixture does not give a shared component evidence from both extractors")
	}
}
