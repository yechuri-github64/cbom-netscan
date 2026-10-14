// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package coverage reports which crypto-relevant config sections of a backup
// the CBOM covers, so a reader can tell when it is incomplete.
package coverage

import (
	"slices"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// Inventoried are the config sections an extractor reads. Keep this in step
// with pkg/fortios/extract/*.
var Inventoried = []string{
	"system global",
	"system ssh-config",
	"vpn ipsec phase1",
	"vpn ipsec phase1-interface",
	"vpn ipsec phase2",
	"vpn ipsec phase2-interface",
	"vpn ssl settings",
	"vpn certificate local", "vpn certificate ca", "vpn certificate remote",
	"certificate local", "certificate ca", "certificate remote",
}

// NotInventoried are sections that hold crypto assets or protocols with
// algorithm choices (research notes §3.5-3.12) that no extractor reads yet.
// Their presence means the CBOM is missing certificates, keys, or protocols,
// so it is warned about.
var NotInventoried = []string{
	// §3.5 manual keys, §3.6 QKD
	"vpn ipsec manualkey", "vpn ipsec manualkey-interface",
	"vpn qkd",
	// §3.8 certificates and SSH keys not yet read
	"vpn certificate crl", "vpn certificate ocsp-server", "vpn certificate hsm-local", "vpn certificate setting",
	"certificate crl",
	"firewall ssh local-key", "firewall ssh local-ca",
	// §3.9 SSL inspection, §3.10 SSL offload (only when a VIP uses ssl-*), §3.11 ZTNA
	"firewall ssl-ssh-profile",
	"firewall vip",
	"firewall access-proxy", "firewall access-proxy-virtual-host", "ztna web-proxy", "ztna service-connector",
	// §3.12 protocols with their own algorithm choices
	"system snmp user", "wireless-controller vap",
}

// NotInventoriedSettings are crypto-related service settings from research
// notes §3.12 (TLS options of management and logging connections, admin and
// API credentials). Nearly every backup has them and they are not missing
// algorithm inventory, so they are recorded in metadata only, not warned.
var NotInventoriedSettings = []string{
	"system admin", "system api-user", "log fortianalyzer setting", "log syslogd setting",
	"system central-management", "system ha", "system fortiguard", "system fortisandbox",
	"user ldap", "user radius", "user setting", "system dns", "system ntp", "system csf",
}

// relevant narrows sections that also hold non-crypto configuration.
var relevant = map[string]func([]*tree.Block) bool{
	// A VIP is crypto-relevant only with SSL offload (ssl-* settings).
	"firewall vip": func(bs []*tree.Block) bool {
		for _, b := range bs {
			for _, e := range b.Entries {
				for _, a := range e.Attrs {
					if strings.HasPrefix(a.Key, "ssl-") {
						return true
					}
				}
			}
		}
		return false
	},
}

// Report lists the crypto-relevant sections present in a backup, split by
// whether the CBOM covers them. Both lists are sorted.
type Report struct {
	Inventoried            []string
	NotInventoried         []string // crypto assets missing from the CBOM; warned
	NotInventoriedSettings []string // crypto-related settings; metadata only
}

// Check looks for every known section in every scope of t.
func Check(t *tree.Tree) Report {
	present := func(path string) bool {
		var bs []*tree.Block
		for _, s := range t.Scopes() {
			bs = append(bs, t.Blocks(s, path)...)
		}
		if len(bs) == 0 {
			return false
		}
		if f, ok := relevant[path]; ok {
			return f(bs)
		}
		return true
	}
	var r Report
	for _, p := range Inventoried {
		if present(p) {
			r.Inventoried = append(r.Inventoried, p)
		}
	}
	for _, p := range NotInventoried {
		if present(p) {
			r.NotInventoried = append(r.NotInventoried, p)
		}
	}
	for _, p := range NotInventoriedSettings {
		if present(p) {
			r.NotInventoriedSettings = append(r.NotInventoriedSettings, p)
		}
	}
	slices.Sort(r.Inventoried)
	slices.Sort(r.NotInventoried)
	slices.Sort(r.NotInventoriedSettings)
	return r
}

// Properties are the metadata.properties recording the coverage.
func (r Report) Properties() map[string]string {
	m := map[string]string{}
	if len(r.Inventoried) > 0 {
		m["cbom-netscan:fortios:sections-inventoried"] = strings.Join(r.Inventoried, ", ")
	}
	if len(r.NotInventoried) > 0 {
		m["cbom-netscan:fortios:sections-not-inventoried"] = strings.Join(r.NotInventoried, ", ")
	}
	if len(r.NotInventoriedSettings) > 0 {
		m["cbom-netscan:fortios:settings-not-inventoried"] = strings.Join(r.NotInventoriedSettings, ", ")
	}
	return m
}

// Warning is one warning naming every section with crypto assets the CBOM
// does not cover, or nil if there are none. Settings-only sections are not
// warned about; they are in Properties.
func (r Report) Warning(location string) *model.Warning {
	if len(r.NotInventoried) == 0 {
		return nil
	}
	return &model.Warning{
		Code:    "section-not-inventoried",
		Message: "the CBOM does not cover the certificates, keys, or protocols in these sections yet: " + strings.Join(r.NotInventoried, ", "),
		Ev:      model.Evidence{Location: location},
	}
}
