// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package ipsec extracts IKE and IPsec crypto from "config vpn ipsec
// phase1-interface", "phase1", "phase2-interface", and "phase2" (research
// notes §3.3-3.4), in every scope of the tree.
//
// Each phase1 entry becomes one protocol component of type ike, version 1 or
// 2. Each phase2 entry becomes one protocol component of type ipsec that
// depends on its phase1. Both reference shared algorithm components: a
// cipher, MAC, PRF, DH group, or PQC KEM used by several tunnels is one
// component whose evidence lists every place it is configured.
//
// IKEv2 tunnels fill ikev2TransformTypes (encr, integ, prf, ke, auth); IKEv1
// tunnels, and tunnels whose version is unknown, use cryptoRefArray (§3.3).
// Additional key exchanges (addke1-7, RFC 9370) are added to ke and recorded
// per round as properties, since CycloneDX 1.6 has no per-round slot.
//
// Field provenance is recorded as in the global extractor (package field).
// Only allow-listed fields are read. psksecret is looked at only to report
// whether it is present and in which form (ENC, masked, or plaintext); its
// value is never stored. Certificates are referenced by name only.
package ipsec

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/algo"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/field"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// families pairs each phase1 table with the phase2 table that refers to it.
var families = []struct{ phase1, phase2 string }{
	{"vpn ipsec phase1-interface", "vpn ipsec phase2-interface"},
	{"vpn ipsec phase1", "vpn ipsec phase2"},
}

// Extract adds IKE and IPsec components for every tunnel in t to inv.
// location is recorded in evidence occurrences, e.g. the backup's file name.
func Extract(t *tree.Tree, location string, inv *model.Inventory) {
	x := &extractor{
		inv: inv,
		r:   &field.Resolver{Loc: location, Inv: inv, Defaults: defaults.ForVersion(t.Header.Version)},
	}
	found := false
	for _, scope := range t.Scopes() {
		for _, fam := range families {
			tunnels := map[string]*model.Asset{}
			for _, e := range t.Get(scope, fam.phase1) {
				tunnels[e.Name] = x.phase1(scope, fam.phase1, e)
				found = true
			}
			for _, e := range t.Get(scope, fam.phase2) {
				x.phase2(scope, fam.phase2, e, tunnels)
				found = true
			}
		}
	}
	if found && x.r.Defaults == nil {
		inv.AddWarning(field.NoDefaultsWarning(t.Header.Version, location))
	}
}

type extractor struct {
	inv *model.Inventory
	r   *field.Resolver
}

// entry is one phase1 or phase2 edit being processed.
type entry struct {
	section string // "vpn ipsec phase1-interface"
	e       *tree.Entry
	ctx     string // evidence context: "", "vdom root", or "global"
	label   string // component name
}

func newEntry(scope tree.Scope, section string, e *tree.Entry) entry {
	table := strings.TrimPrefix(section, "vpn ipsec ")
	en := entry{section: section, e: e, label: fmt.Sprintf("FortiOS IPsec %s %s", table, e.Name)}
	switch scope.Kind {
	case tree.KindVDOM:
		en.ctx = "vdom " + scope.Name
	case tree.KindGlobal:
		en.ctx = "global"
	}
	if en.ctx != "" {
		en.label += " (" + en.ctx + ")"
	}
	return en
}

func (x *extractor) resolve(en entry, name string, sp field.Spec) field.Value {
	sym := en.section + "/" + en.e.Name + "/" + name
	return x.r.Resolve(en.e.Attr(name), en.section, name, sym, en.ctx, sp)
}

// refs collects algorithm references for one protocol component, in order
// and without duplicates.
type refs struct {
	encr, integ, prf, ke, auth []string
}

func (r *refs) add(slot *[]string, id string) {
	if !slices.Contains(*slot, id) {
		*slot = append(*slot, id)
	}
}

// apply writes the references to p: IKEv2 transform slots when ikev2 is set,
// otherwise one cryptoRefArray.
func (r *refs) apply(p *model.Protocol, ikev2 bool) {
	if ikev2 {
		p.IKEEncr, p.IKEInteg, p.IKEPRF, p.IKEKE, p.IKEAuth = r.encr, r.integ, r.prf, r.ke, r.auth
		return
	}
	seen := map[string]bool{}
	for _, slot := range [][]string{r.encr, r.integ, r.prf, r.ke, r.auth} {
		for _, id := range slot {
			if !seen[id] {
				seen[id] = true
				p.Refs = append(p.Refs, id)
			}
		}
	}
}

// algorithm adds (or reuses) the component for a and returns its bom-ref.
// The bom-ref is fixed from the type, name, and location, not from the first
// evidence, so every tunnel gets the same ref for the same algorithm. A
// configured value adds an evidence occurrence; a default adds none.
func (x *extractor) algorithm(a alg, v field.Value) string {
	alg := a.a
	algo.MarkQuantumVulnerable(&alg)
	asset := &model.Asset{
		ID:         model.BOMRef(model.AssetTypeAlgorithm, a.name, x.r.Loc),
		Type:       model.AssetTypeAlgorithm,
		Name:       a.name,
		Alg:        &alg,
		Properties: map[string]string{},
	}
	if v.Source == field.Configured {
		asset.Evidence = []model.Evidence{x.r.Evidence(v)}
	}
	return x.inv.Add(asset).ID
}

// splitProposal returns the cipher and hash of a proposal token.
// Phase1 non-AEAD tokens are <cipher>-<hash>, where hash gives integrity and
// PRF. Phase1 AEAD tokens are <aead>-prf<hash>: hash is the PRF only and prf
// is true. Phase2 tokens are <cipher>-<hash> (either may be null) or a bare
// AEAD name. sm4-sm3 is SM4 with SM3.
func splitProposal(tok string) (cipher, hash string, prf bool) {
	cipher, hash, _ = strings.Cut(tok, "-")
	if strings.HasPrefix(hash, "prf") {
		return cipher, strings.TrimPrefix(hash, "prf"), true
	}
	return cipher, hash, false
}

// proposals adds the algorithms of each proposal token to rs.
func (x *extractor) proposals(v field.Value, phase1 bool, rs *refs) {
	for _, tok := range v.Tokens {
		cipher, hash, prfOnly := splitProposal(tok)
		if c, ok := ciphers[cipher]; ok {
			rs.add(&rs.encr, x.algorithm(c, v))
		}
		h, ok := hashes[hash]
		if !ok {
			continue
		}
		if !prfOnly {
			rs.add(&rs.integ, x.algorithm(macAlg(h.integ), v))
		}
		if phase1 {
			rs.add(&rs.prf, x.algorithm(prfAlg(h.prf), v))
		}
	}
}

func (x *extractor) dhGroups(v field.Value, rs *refs) {
	for _, tok := range v.Tokens {
		if g, ok := dhGroups[tok]; ok {
			rs.add(&rs.ke, x.algorithm(g, v))
		}
	}
}

// addkeApplies says whether RFC 9370 additional key exchanges take effect
// for a tunnel with this IKE version: they exist only in IKEv2.
func addkeApplies(ikeVersion string) string {
	switch ikeVersion {
	case "2":
		return "yes"
	case "1":
		return "no"
	}
	return field.Unknown
}

// addke records addke1-7 on a. Their KEMs are added to rs only when applies
// is "yes", so an IKEv1 tunnel, or one whose IKE version is unknown, is never
// reported as using ML-KEM. Rounds that are not set are summarised in one
// addke:source property instead of seven.
func (x *extractor) addke(en entry, a *model.Asset, rs *refs, applies string) {
	configured := false
	line := 0
	for i := 1; i <= 7; i++ {
		name := "addke" + strconv.Itoa(i)
		v := x.resolve(en, name, specAddke)
		if v.Source != field.Configured {
			continue
		}
		if !configured {
			line = v.Line
		}
		configured = true
		x.r.Record(a, v, true)
		if applies != "yes" {
			continue
		}
		for _, tok := range v.Tokens {
			if k, ok := addkeAlgs[tok]; ok {
				rs.add(&rs.ke, x.algorithm(k, v))
			}
		}
	}
	if configured {
		switch applies {
		case "no":
			a.Properties[field.Prefix+"addke:applies"] = "no"
			a.Properties[field.Prefix+"addke:applies-reason"] = "RFC 9370 additional key exchanges apply only to IKEv2; this tunnel uses IKEv1"
			x.inv.AddWarning(model.Warning{
				Code:    "addke-not-ikev2",
				Message: en.label + " sets addke on an IKEv1 tunnel; additional key exchanges are IKEv2-only, so they are not counted",
				Ev:      model.Evidence{Location: x.r.Loc, Line: line, Symbol: en.section + "/" + en.e.Name + "/addke", Context: en.ctx},
			})
		case field.Unknown:
			a.Properties[field.Prefix+"addke:applies"] = field.Unknown
			a.Properties[field.Prefix+"addke:applies-reason"] = "the IKE version is unknown, and additional key exchanges apply only to IKEv2; they are not counted"
		}
		return
	}
	switch {
	case x.r.Defaults == nil:
		a.Properties[field.Prefix+"addke:source"] = field.Unknown
	default:
		if _, ok := x.r.Defaults.Field(en.section, "addke1"); ok {
			a.Properties[field.Prefix+"addke:source"] = field.Default
		}
	}
}

func (x *extractor) phase1(scope tree.Scope, section string, e *tree.Entry) *model.Asset {
	en := newEntry(scope, section, e)
	a := &model.Asset{
		Type:       model.AssetTypeProtocol,
		Name:       en.label,
		Proto:      &model.Protocol{Type: "ike"},
		Properties: map[string]string{},
	}
	field.MarkConfiguredView(a)
	if en.ctx != "" {
		a.Properties[field.Prefix+"scope"] = en.ctx
	}

	ver := x.resolve(en, "ike-version", specIKEVersion)
	prop := x.resolve(en, "proposal", specP1Proposal)
	dh := x.resolve(en, "dhgrp", specDHGroup)
	auth := x.resolve(en, "authmethod", specAuth)
	for _, v := range []field.Value{ver, prop, dh, auth} {
		x.r.Record(a, v, true)
	}
	if len(ver.Tokens) == 1 {
		a.Proto.Version = ver.Tokens[0]
	}

	var rs refs
	x.proposals(prop, true, &rs)
	x.dhGroups(dh, &rs)
	x.addke(en, a, &rs, addkeApplies(a.Proto.Version))

	method := strings.Join(auth.Tokens, " ")
	if method == "signature" {
		x.r.Record(a, x.resolve(en, "signature-hash-alg", specSigHash), true)
	}
	if cert := x.resolve(en, "certificate", specCertName); cert.Source == field.Configured {
		x.r.Record(a, cert, true)
	}
	// A PSK is reported whenever one is set, even if the tunnel authenticates
	// with signatures; it is part of the auth transform only for psk.
	if id := x.psk(en, a, method); id != "" && method == "psk" {
		rs.add(&rs.auth, id)
	}

	rs.apply(a.Proto, a.Proto.Version == "2")
	return x.inv.Add(a)
}

// psk records whether a pre-shared key is set and in which form, and returns
// the bom-ref of a presence-only secret-key component, or "" if none is set.
// The key value is never stored: only its first token is inspected, to tell
// an ENC blob or the FortinetPasswordMask placeholder from plaintext.
//
// A plaintext key is a finding in itself (the backup was taken without
// encrypting secrets), so it also produces a plaintext-psk warning, still
// without the value. A key on a tunnel whose authmethod is not psk is marked
// unused, since it is left over rather than in effect.
func (x *extractor) psk(en entry, tunnel *model.Asset, method string) string {
	attr := en.e.Attr("psksecret")
	if attr == nil || attr.Unset || len(attr.Values) == 0 {
		if method == "psk" {
			tunnel.Properties[field.Prefix+"psksecret"] = "absent"
		}
		return ""
	}
	form := "plaintext"
	switch attr.Values[0] {
	case "ENC":
		form = "ENC"
	case "FortinetPasswordMask":
		form = "masked"
	}
	tunnel.Properties[field.Prefix+"psksecret"] = "present"
	if method != "psk" {
		tunnel.Properties[field.Prefix+"psksecret:unused"] = "authmethod is " + method
	}
	if form == "plaintext" {
		x.inv.AddWarning(model.Warning{
			Code:    "plaintext-psk",
			Message: en.label + " has a plaintext pre-shared key in the backup (value not shown); take backups with secrets encrypted",
			Ev:      model.Evidence{Location: x.r.Loc, Line: attr.Line, Symbol: en.section + "/" + en.e.Name + "/psksecret", Context: en.ctx},
		})
	}

	v := field.Value{Field: "psksecret", Symbol: en.section + "/" + en.e.Name + "/psksecret", Context: en.ctx, Line: attr.Line}
	m := &model.Asset{
		Type: model.AssetTypeRelatedMaterial,
		Name: en.label + " pre-shared key",
		Mat:  &model.Material{Type: "secret-key"},
		Properties: map[string]string{
			field.Prefix + "psksecret:form": form,
			field.Prefix + "psksecret:line": strconv.Itoa(attr.Line),
		},
		Evidence: []model.Evidence{x.r.Evidence(v)},
	}
	return x.inv.Add(m).ID
}

func (x *extractor) phase2(scope tree.Scope, section string, e *tree.Entry, tunnels map[string]*model.Asset) {
	en := newEntry(scope, section, e)
	a := &model.Asset{
		Type:       model.AssetTypeProtocol,
		Name:       en.label,
		Proto:      &model.Protocol{Type: "ipsec"},
		Properties: map[string]string{},
	}
	field.MarkConfiguredView(a)
	if en.ctx != "" {
		a.Properties[field.Prefix+"scope"] = en.ctx
	}

	ikev2, parentVersion := false, ""
	if p1 := e.Attr("phase1name"); p1 != nil && len(p1.Values) == 1 {
		a.Properties[field.Prefix+"phase1name"] = p1.Values[0]
		if parent, ok := tunnels[p1.Values[0]]; ok {
			a.DependsOn = append(a.DependsOn, parent.ID)
			parentVersion = parent.Proto.Version
			ikev2 = parentVersion == "2"
		} else {
			x.inv.AddWarning(model.Warning{
				Code:    "unknown-phase1",
				Message: fmt.Sprintf("%s refers to phase1 %q, which is not defined in the same scope", en.label, p1.Values[0]),
				Ev:      model.Evidence{Location: x.r.Loc, Line: p1.Line, Symbol: en.section + "/" + e.Name + "/phase1name", Context: en.ctx},
			})
		}
	}

	prop := x.resolve(en, "proposal", specP2Proposal)
	pfs := x.resolve(en, "pfs", specPFS)
	dh := x.resolve(en, "dhgrp", specDHGroup)
	for _, v := range []field.Value{prop, pfs, dh} {
		x.r.Record(a, v, true)
	}

	var rs refs
	x.proposals(prop, false, &rs)
	// PFS groups apply only when pfs is known to be enabled.
	if strings.Join(pfs.Tokens, " ") == "enable" {
		x.dhGroups(dh, &rs)
		x.addke(en, a, &rs, addkeApplies(parentVersion))
	}
	rs.apply(a.Proto, ikev2)
	x.inv.Add(a)
}
