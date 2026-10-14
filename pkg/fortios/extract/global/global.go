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
	"fmt"
	"strconv"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/lexer"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const (
	sectionGlobal = "system global"
	sectionSSH    = "system ssh-config"

	srcConfigured = "configured"
	srcDefault    = "default"
	srcUnknown    = "unknown"

	propPrefix = "cbom-netscan:fortios:"
)

// Extract adds admin HTTPS and SSH components from the global scope of t to
// inv. location is recorded in evidence occurrences, e.g. the backup's path.
func Extract(t *tree.Tree, location string, inv *model.Inventory) {
	x := &extractor{
		t:     t,
		loc:   location,
		inv:   inv,
		tbl:   defaults.ForVersion(t.Header.Version),
		scope: tree.ScopeSingle,
	}
	if t.VDOMMode == lexer.VDOMMulti {
		x.scope = tree.ScopeGlobal
	}
	if x.tbl == nil {
		inv.AddWarning(model.Warning{
			Code:    "no-default-table",
			Message: fmt.Sprintf("no defaults table for FortiOS %s; fields not set in the config are reported as unknown", t.Header.Version),
			Ev:      model.Evidence{Location: location, Line: 1, Symbol: "#config-version"},
		})
	}
	x.adminHTTPS()
	x.ssh()
}

type extractor struct {
	t     *tree.Tree
	loc   string
	inv   *model.Inventory
	tbl   *defaults.Table
	scope tree.Scope
}

// value is one resolved field.
type value struct {
	field  string
	symbol string // "system global/admin-https-ssl-versions"
	tokens []string
	src    string
	line   int // set when src is configured
}

// resolve finds field in section: the last set line wins across repeated
// blocks, unset means the default, and with no table the value is unknown.
// Configured tokens are filtered through sp before they are returned.
func (x *extractor) resolve(section, field string, sp spec) value {
	v := value{field: field, symbol: section + "/" + field, src: srcUnknown}
	var attr *tree.Attr
	for _, b := range x.t.Blocks(x.scope, section) {
		if a := b.Attr(field); a != nil {
			attr = a
		}
	}
	if attr != nil && !attr.Unset {
		v.src, v.line = srcConfigured, attr.Line
		v.tokens = x.clean(v, attr.Values, sp)
		return v
	}
	if x.tbl != nil {
		if f, ok := x.tbl.Field(section, field); ok {
			v.src, v.tokens = srcDefault, f.Value
		}
	}
	return v
}

// clean applies sp to configured tokens and removes empty and repeated ones.
func (x *extractor) clean(v value, toks []string, sp spec) []string {
	var out []string
	seen := map[string]bool{}
	for _, tok := range toks {
		if tok == "" || seen[tok] {
			continue
		}
		switch {
		case sp.known[tok]:
		case sp.pattern != nil && sp.pattern.MatchString(tok):
			if !sp.freeform {
				x.warn(v, fmt.Sprintf("%s has unknown option %q; kept with primitive unknown", v.symbol, tok))
			}
		default:
			x.warn(v, v.symbol+" has a token that is not a valid option; it was dropped and is not shown")
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return out
}

func (x *extractor) warn(v value, msg string) {
	x.inv.AddWarning(model.Warning{
		Code:    "unknown-token",
		Message: msg,
		Ev:      model.Evidence{Location: x.loc, Line: v.line, Symbol: v.symbol},
	})
}

// record writes v's provenance onto a, and its value when withValue is set.
func (x *extractor) record(a *model.Asset, v value, withValue bool) {
	p := propPrefix + v.field
	a.Properties[p+":source"] = v.src
	switch v.src {
	case srcConfigured:
		a.Properties[p+":line"] = strconv.Itoa(v.line)
		a.Evidence = append(a.Evidence, model.Evidence{Location: x.loc, Line: v.line, Symbol: v.symbol})
	case srcDefault:
		a.Properties[propPrefix+"defaults-table"] = x.tbl.Name
	}
	if withValue && v.src != srcUnknown {
		a.Properties[p+":value"] = strings.Join(v.tokens, " ")
	}
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

	newTLS := func(name, version string) *model.Asset {
		a := &model.Asset{
			Type:       model.AssetTypeProtocol,
			Name:       name,
			Proto:      &model.Protocol{Type: "tls", Version: version},
			Properties: map[string]string{},
		}
		x.record(a, versions, false)
		x.record(a, strong, true)
		x.record(a, cert, true)
		return a
	}

	if versions.src == srcUnknown {
		a := newTLS("FortiOS admin HTTPS TLS", "")
		x.record(a, suites, false)
		x.record(a, banned, true)
		x.record(a, static, true)
		x.inv.Add(a)
		return
	}

	for _, tok := range versions.tokens {
		ver := tlsVersions[tok]
		a := newTLS("FortiOS admin HTTPS TLS "+ver, ver)
		if ver == "1.3" {
			x.record(a, suites, false)
			for _, s := range suites.tokens {
				a.Proto.CipherSuites = append(a.Proto.CipherSuites, model.CipherSuite{Name: s})
			}
		} else {
			x.record(a, banned, true)
			x.record(a, static, true)
			a.Properties[propPrefix+"cipher-suites"] = srcUnknown
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
		v := x.resolve(sectionSSH, f.name, spec{known: keys(f.algs), pattern: sshTokenRE})
		x.record(p, v, false)
		for _, tok := range v.tokens {
			alg, ok := f.algs[tok]
			if !ok {
				alg = model.Algorithm{Primitive: "unknown"}
			}
			a := &model.Asset{
				Type:       model.AssetTypeAlgorithm,
				Name:       tok,
				Alg:        &alg,
				Properties: map[string]string{},
			}
			x.record(a, v, false)
			if h, ok := hybridProp[tok]; ok {
				a.Properties[propPrefix+"hybrid"] = h
			}
			x.inv.Add(a)
			p.Proto.Refs = append(p.Proto.Refs, a.ID)
		}
	}
	x.inv.Add(p)
}
