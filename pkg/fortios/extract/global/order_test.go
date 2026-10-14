// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package global

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).

import (
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// TestSSHDoesNotNeedAdminHTTPSFirst runs the SSH part on its own and in both
// orders: its strong-crypto markers must not depend on adminHTTPS having run.
func TestSSHDoesNotNeedAdminHTTPSFirst(t *testing.T) {
	const hdr = "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin\n"
	run := func(cfg, order string) (*model.Inventory, string) {
		tr, err := tree.Parse(strings.NewReader(cfg))
		if err != nil {
			t.Fatal(err)
		}
		inv := model.NewInventory()
		x := newExtractor(tr, "fw.conf", inv)
		switch order {
		case "ssh-only":
			x.ssh()
		case "ssh-first":
			x.ssh()
			x.adminHTTPS()
		default:
			x.adminHTTPS()
			x.ssh()
		}
		for _, a := range inv.Assets {
			if a.Name == "FortiOS admin SSH" {
				return inv, a.Properties["cbom-netscan:fortios:ssh-enc-algo:strong-crypto-may-restrict"]
			}
		}
		t.Fatalf("%s: no SSH component", order)
		return nil, ""
	}

	// strong-crypto is not set, so the 7.6 default (enable) applies whichever
	// part runs first, and aes128-cbc is marked.
	cfg := hdr + "config system ssh-config\n    set ssh-enc-algo aes128-cbc\nend\n"
	for _, order := range []string{"ssh-only", "ssh-first", "https-first"} {
		if _, got := run(cfg, order); got != "aes128-cbc" {
			t.Errorf("%s: ssh-enc-algo:strong-crypto-may-restrict = %q, want aes128-cbc", order, got)
		}
	}

	// A malformed strong-crypto value is resolved, and warned about, once.
	bad := cfg + "config system global\n    set strong-crypto bogus!value\nend\n"
	if inv, _ := run(bad, "https-first"); len(inv.Warnings) != 1 {
		t.Errorf("warnings = %d, want 1 (strong-crypto resolved once)", len(inv.Warnings))
	}
}
