// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package global extracts admin HTTPS and SSH crypto from "config system
// global" and "config system ssh-config" (research notes §3.1-3.2).
//
// Every field is resolved to one of three sources, recorded on the protocol
// component as cbom-netscan:fortios:<field>:source:
//
//	configured  set in the backup; :line and an evidence occurrence give the line
//	default     not set; taken from the defaults table for the header's version
//	unknown     not set and no defaults table covers this version
//
// Only an allow-list of fields is read. Secret fields in these sections
// (ssh-hsk, ssh-hsk-password) are never touched.
//
// Algorithm components are shared with other extractors (AES-256-GCM is one
// component whether SSH or IPsec uses it), so they carry only the algorithm
// and evidence occurrences; SSH tokens and provenance stay on the protocol.
//
// The components describe the configured set. strong-crypto is recorded as a
// property, and what it may disable is marked (§3.1a), but its effect on what
// is actually negotiated is not applied; that "effective" view is separate
// work (§8.12).
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
	x := newExtractor(t, location, inv)
	x.adminHTTPS()
	x.ssh()
}

// newExtractor resolves the settings both parts depend on (scope and
// strong-crypto) up front, so adminHTTPS and ssh can run in either order.
func newExtractor(t *tree.Tree, location string, inv *model.Inventory) *extractor {
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
	x.strongV = x.resolve(sectionGlobal, "strong-crypto", specEnableDis)
	x.strong = strings.Join(x.strongV.Tokens, " ") == "enable"
	return x
}

type extractor struct {
	t       *tree.Tree
	inv     *model.Inventory
	r       *field.Resolver
	scope   tree.Scope
	strongV field.Value // strong-crypto, resolved once in newExtractor
	strong  bool        // strongV is enable (configured or default)
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
	strong := x.strongV
	static := x.resolve(sectionGlobal, "ssl-static-key-ciphers", specEnableDis)
	cert := x.resolve(sectionGlobal, "admin-server-cert", specCertName)

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
	addRef := func(ids ...string) {
		for _, id := range ids {
			if !slices.Contains(p.Proto.Refs, id) {
				p.Proto.Refs = append(p.Proto.Refs, id)
			}
		}
	}
	for _, f := range fields {
		v := x.resolve(sectionSSH, f.name, field.Spec{Known: keys(f.algs), Pattern: sshTokenRE})
		x.r.Record(p, v, true) // the SSH tokens live here; algorithm components are shared
		var restricted []string
		for _, tok := range v.Tokens {
			if x.strong && !strongCryptoAllowed[f.name][tok] {
				restricted = append(restricted, tok)
			}
			alg, ok := f.algs[tok]
			if !ok {
				alg = model.Algorithm{Primitive: "unknown"}
			}
			name := tok
			if c, ok := sshCanonical[tok]; ok {
				name = c
			}
			a := x.algorithm(name, alg, v)
			if h, ok := hybridProp[tok]; ok {
				a.Properties[field.Prefix+"hybrid"] = h
			}
			var parts []string
			for _, hp := range hybridParts[tok] {
				parts = append(parts, x.inv.Add(x.algorithm(hp.name, hp.alg, v)).ID)
			}
			a.DependsOn = parts
			addRef(x.inv.Add(a).ID)
			addRef(parts...)
		}
		if len(restricted) > 0 {
			p.Properties[field.Prefix+f.name+":strong-crypto-may-restrict"] = strings.Join(restricted, " ")
			p.Properties[field.Prefix+"strong-crypto-may-restrict:reason"] = strongCryptoReason
		}
	}
	x.inv.Add(p)
}

// algorithm builds an algorithm component. The bom-ref is fixed from the
// name and location, as in the IPsec extractor, so an algorithm both use is
// one component with one ref. Field provenance lives on the protocol
// component, because a shared algorithm can be configured in one place and a
// default in another; a configured value adds an evidence occurrence here.
func (x *extractor) algorithm(name string, alg model.Algorithm, v field.Value) *model.Asset {
	algo.MarkQuantumVulnerable(&alg)
	a := &model.Asset{
		ID:         model.BOMRef(model.AssetTypeAlgorithm, name, x.r.Loc),
		Type:       model.AssetTypeAlgorithm,
		Name:       name,
		Alg:        &alg,
		Properties: map[string]string{},
	}
	if v.Source == field.Configured {
		a.Evidence = []model.Evidence{x.r.Evidence(v)}
	}
	return a
}
