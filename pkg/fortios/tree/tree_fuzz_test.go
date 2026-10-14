// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package tree_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
)

// FuzzParse checks that Parse never panics or hangs on any input, and that a
// successful parse can be walked through every lookup method.
func FuzzParse(f *testing.F) {
	seeds := []string{
		hdrSingle + "config system global\n    set hostname \"fw01\"\nend\n",
		hdrSingle + "config vpn ipsec phase1-interface\n    edit \"vpn1\"\n        set proposal aes256-sha256 aes128-sha256\n        unset keylife\n        config ipv4-exclude-range\n            edit 1\n            next\n        end\n    next\nend\n",
		hdrSingle + "config router bgp\n    set as 65001\n    config neighbor\n        edit \"192.0.2.1\"\n        next\n    end\nend\n",
		hdrSingle + "config firewall policy\n    edit 1\n        set action next\n    next\nend\n",
		hdrSingle + "config vpn certificate local\n    edit \"c1\"\n        set certificate \"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\"\n    next\nend",
		hdrMulti + multiBody,
		hdrUnknown + multiBody,
		hdrSingle + "config a\nedit x\nend\n",
		hdrSingle + "next\n",
		hdrSingle + "config a\nedit x\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	if data, err := os.ReadFile("testdata/multi-vdom-7.6.conf"); err == nil {
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tr, err := tree.Parse(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, s := range tr.Scopes() {
			for _, b := range tr.Roots(s) {
				for _, e := range tr.Get(s, b.Path) {
					e.Attr("proposal")
				}
				b.Attr("hostname")
			}
		}
	})
}
