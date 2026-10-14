// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package coverage_test

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/coverage"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
)

const (
	hdr  = "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin\n"
	hdrM = "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=1:user=admin\n"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name                         string
		cfg                          string
		inventoried, uncov, settings []string
	}{
		{
			name:        "covered_only",
			cfg:         hdr + "config system global\nend\nconfig vpn ipsec phase1-interface\nend\nconfig firewall address\nend\n",
			inventoried: []string{"system global", "vpn ipsec phase1-interface"},
		},
		{
			name:        "uncovered_sections_sorted",
			cfg:         hdr + "config vpn qkd\nend\nconfig vpn certificate crl\nend\nconfig vpn ssl settings\nend\nconfig system global\nend\n",
			inventoried: []string{"system global"},
			uncov:       []string{"vpn certificate crl", "vpn qkd", "vpn ssl settings"},
		},
		{
			// Settings-only sections are recorded but not warned about.
			name:        "settings_are_metadata_only",
			cfg:         hdr + "config system global\nend\nconfig system admin\nend\nconfig system ntp\nend\n",
			inventoried: []string{"system global"},
			settings:    []string{"system admin", "system ntp"},
		},
		{
			name: "vip_without_ssl_is_not_relevant",
			cfg:  hdr + "config firewall vip\n    edit \"v\"\n        set extip 192.0.2.5\n    next\nend\n",
		},
		{
			name:  "vip_with_ssl_offload",
			cfg:   hdr + "config firewall vip\n    edit \"v\"\n        set ssl-mode full\n    next\nend\n",
			uncov: []string{"firewall vip"},
		},
		{
			name:        "multi_vdom_scopes",
			cfg:         hdrM + "config vdom\nedit root\nnext\nend\nconfig global\nconfig system global\nend\nend\nconfig vdom\nedit root\nconfig vpn certificate local\nend\nconfig vpn certificate ocsp-server\nend\nend\n",
			inventoried: []string{"system global", "vpn certificate local"},
			uncov:       []string{"vpn certificate ocsp-server"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := tree.Parse(strings.NewReader(tc.cfg))
			if err != nil {
				t.Fatal(err)
			}
			r := coverage.Check(tr)
			if !slices.Equal(r.Inventoried, tc.inventoried) || !slices.Equal(r.NotInventoried, tc.uncov) || !slices.Equal(r.NotInventoriedSettings, tc.settings) {
				t.Errorf("Check = %+v, want inventoried %v, not inventoried %v, settings %v", r, tc.inventoried, tc.uncov, tc.settings)
			}
			w := r.Warning("fw.conf")
			switch {
			case tc.uncov == nil && w != nil:
				t.Errorf("warning %+v, want none", w)
			case tc.uncov != nil && (w == nil || w.Code != "section-not-inventoried" || !strings.HasSuffix(w.Message, strings.Join(tc.uncov, ", "))):
				t.Errorf("warning = %+v, want section-not-inventoried naming %v", w, tc.uncov)
			}
			props := r.Properties()
			if got := props["cbom-netscan:fortios:sections-not-inventoried"]; got != strings.Join(tc.uncov, ", ") {
				t.Errorf("sections-not-inventoried = %q", got)
			}
			if got := props["cbom-netscan:fortios:sections-inventoried"]; got != strings.Join(tc.inventoried, ", ") {
				t.Errorf("sections-inventoried = %q", got)
			}
			if got := props["cbom-netscan:fortios:settings-not-inventoried"]; got != strings.Join(tc.settings, ", ") {
				t.Errorf("settings-not-inventoried = %q", got)
			}
		})
	}
}

// TestListsDisjoint guards against a section being in two lists, or twice in one.
func TestListsDisjoint(t *testing.T) {
	all := append(append(slices.Clone(coverage.Inventoried), coverage.NotInventoried...), coverage.NotInventoriedSettings...)
	if len(all) != len(slicesCompactSorted(all)) {
		t.Errorf("a section is listed more than once across Inventoried, NotInventoried, NotInventoriedSettings: %s", fmt.Sprint(all))
	}
}

func slicesCompactSorted(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return slices.Compact(c)
}
