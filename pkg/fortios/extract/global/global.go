// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package global extracts admin HTTPS and SSH crypto from "config system
// global" and "config system ssh-config" (research notes §3.1-3.2).
//
// Every field is resolved to one of three sources, recorded on the component
// as cbom-netscan:fortios:<field>:source:
//
//	configured  set in the backup; :line and an evidence occurrence give the line
//	default     not set; taken from the defaults table for the header's version
//	unknown     not set and no defaults table covers this version
//
// Only an allow-list of fields is read. Secret fields in these sections
// (ssh-hsk, ssh-hsk-password) are never touched.
//
// The components describe the configured set. strong-crypto is recorded as a
// property but its effect on what is actually negotiated (§3.1a) is not
// applied here; that "effective" view is separate work (§8.12).
package global

import (
	"slices"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/algo"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/field"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/lexer"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const (
	sectionGlobal = "system global"
	sectionSSH    = "system ssh-config"
)

// Extract adds admin HTTPS and SSH components from the global scope of t to
// inv. location is recorded in evidence occurrences, e.g. the backup's path.
func Extract(t *tree.Tree, location string, inv *model.Inventory) {
	x := &extractor{
		t:     t,
		inv:   inv,
		r:     &field.Resolver{Loc: location, Inv: inv, Defaults: defaults.ForVersion(t.Header.Version)},
		scope: tree.ScopeSingle,
	}
	if t.VDOMMode == lexer.VDOMMulti {
		x.scope = tree.ScopeGlobal
	}
	if x.r.Defaults == nil {
		inv.AddWarning(field.NoDefaultsWarning(t.Header.Version, location))
	}
	x.adminHTTPS()
	x.ssh()
}

type extractor struct {
	t      *tree.Tree
	inv    *model.Inventory
	r      *field.Resolver
	scope  tree.Scope
	strong bool // strong-crypto resolves to enable (configured or default)
}

// mayRestrict marks a as something strong-crypto may disable.
func mayRestrict(a *model.Asset) {
	a.Properties[field.Prefix+"strong-crypto-may-restrict"] = "true"
	a.Properties[field.Prefix+"strong-crypto-may-restrict:reason"] = strongCryptoReason
}

// resolve finds field in section of the global scope (the last set line
// wins across repeated blocks) and resolves it.
func (x *extractor) resolve(section, name string, sp field.Spec) field.Value {
	var attr *tree.Attr
	for _, b := range x.t.Blocks(x.scope, section) {
		if a := b.Attr(name); a != nil {
			attr = a
		}
	}
	return x.r.Resolve(attr, section, name, section+"/"+name, "", sp)
}

// adminHTTPS emits one TLS protocol component per enabled admin HTTPS
// version. TLS 1.3 carries admin-https-ssl-ciphersuites. TLS 1.2 and 1.1
// carry the banned-cipher and static-key settings; their suite list is the
// AG table referenced in §3.1a, which is not in the research notes yet, so
// it is marked unknown rather than guessed.
func (x *extractor) adminHTTPS() {
	versions := x.resolve(sectionGlobal, "admin-https-ssl-versions", specTLSVersions)
	suites := x.resolve(sectionGlobal, "admin-https-ssl-ciphersuites", specTLS13Suites)
	banned := x.resolve(sectionGlobal, "admin-https-ssl-banned-ciphers", specBanned)
	strong := x.resolve(sectionGlobal, "strong-crypto", specEnableDis)
	static := x.resolve(sectionGlobal, "ssl-static-key-ciphers", specEnableDis)
	cert := x.resolve(sectionGlobal, "admin-server-cert", specCertName)
	x.strong = strings.Join(strong.Tokens, " ") == "enable"

	newTLS := func(name, version string) *model.Asset {
		a := &model.Asset{
			Type:       model.AssetTypeProtocol,
			Name:       name,
			Proto:      &model.Protocol{Type: "tls", Version: version},
			Properties: map[string]string{},
		}
		field.MarkConfiguredView(a)
		x.r.Record(a, versions, false)
		x.r.Record(a, strong, true)
		x.r.Record(a, cert, true)
		return a
	}

	if versions.Source == field.Unknown {
		a := newTLS("FortiOS admin HTTPS TLS", "")
		x.r.Record(a, suites, false)
		x.r.Record(a, banned, true)
		x.r.Record(a, static, true)
		x.inv.Add(a)
		return
	}

	for _, tok := range versions.Tokens {
		ver := tlsVersions[tok]
		a := newTLS("FortiOS admin HTTPS TLS "+ver, ver)
		if ver == "1.3" {
			x.r.Record(a, suites, false)
			var restricted []string
			for _, s := range suites.Tokens {
				a.Proto.CipherSuites = append(a.Proto.CipherSuites, model.CipherSuite{Name: s})
				if x.strong && slices.Contains(strongCryptoDisabledTLS13, s) {
					restricted = append(restricted, s)
				}
			}
			if len(restricted) > 0 {
				a.Properties[field.Prefix+"strong-crypto-may-restrict:cipher-suites"] = strings.Join(restricted, " ")
				a.Properties[field.Prefix+"strong-crypto-may-restrict:reason"] = strongCryptoReason
			}
		} else {
			// "When strong encryption is enabled, only TLS 1.2 and TLS 1.3
			// are allowed" (research notes §3.1a).
			if ver == "1.1" && x.strong {
				mayRestrict(a)
			}
			x.r.Record(a, banned, true)
			x.r.Record(a, static, true)
			a.Properties[field.Prefix+"cipher-suites"] = field.Unknown
		}
		x.inv.Add(a)
	}
}

// ssh emits one SSH protocol component whose cryptoRefArray points at one
// algorithm component per key exchange, cipher, MAC, and host key token.
func (x *extractor) ssh() {
	p := &model.Asset{
		Type:       model.AssetTypeProtocol,
		Name:       "FortiOS admin SSH",
		Proto:      &model.Protocol{Type: "ssh"},
		Properties: map[string]string{},
	}
	field.MarkConfiguredView(p)

	fields := []struct {
		name string
		algs map[string]model.Algorithm
	}{
		{"ssh-kex-algo", sshKex},
		{"ssh-enc-algo", sshEnc},
		{"ssh-mac-algo", sshMac},
		{"ssh-hsk-algo", sshHsk},
	}
	for _, f := range fields {
		v := x.resolve(sectionSSH, f.name, field.Spec{Known: keys(f.algs), Pattern: sshTokenRE})
		x.r.Record(p, v, false)
		for _, tok := range v.Tokens {
			alg, ok := f.algs[tok]
			if !ok {
				alg = model.Algorithm{Primitive: "unknown"}
			}
			algo.MarkQuantumVulnerable(&alg)
			a := &model.Asset{
				Type:       model.AssetTypeAlgorithm,
				Name:       tok,
				Alg:        &alg,
				Properties: map[string]string{},
			}
			x.r.Record(a, v, false)
			if x.strong && !strongCryptoAllowed[f.name][tok] {
				mayRestrict(a)
			}
			if h, ok := hybridProp[tok]; ok {
				a.Properties[field.Prefix+"hybrid"] = h
			}
			var parts []string
			for _, hp := range hybridParts[tok] {
				pa := hp.alg
				algo.MarkQuantumVulnerable(&pa)
				c := &model.Asset{
					ID:         model.BOMRef(model.AssetTypeAlgorithm, hp.name, x.r.Loc),
					Type:       model.AssetTypeAlgorithm,
					Name:       hp.name,
					Alg:        &pa,
					Properties: map[string]string{},
				}
				x.r.Record(c, v, false)
				parts = append(parts, x.inv.Add(c).ID)
			}
			a.DependsOn = parts
			p.Proto.Refs = append(p.Proto.Refs, x.inv.Add(a).ID)
			p.Proto.Refs = append(p.Proto.Refs, parts...)
		}
	}
	x.inv.Add(p)
}
