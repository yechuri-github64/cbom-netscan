// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package sslvpn extracts the SSL VPN (Agentless VPN from 7.6) TLS settings
// from "config vpn ssl settings" (research notes §3.7), in every scope.
//
// The section exists in 7.4.12, 7.6.x, and 8.0.1; a backup without it simply
// produces no components. For each TLS version between ssl-min-proto-ver and
// ssl-max-proto-ver it emits one protocol component:
//   - TLS 1.3 lists the ciphersuite values as cipher suites;
//   - TLS 1.2 and below carry banned-cipher and algorithm, with the suite list
//     marked unknown, since the research notes do not list it;
//   - the versions reference the tls-groups as algorithm components, named
//     and defined as in the IPsec extractor so shared groups are one component.
//     Hybrid groups are combiners that depend on their ML-KEM and classical
//     parts. ML-KEM and hybrid groups are defined for TLS 1.3 only, so TLS 1.2
//     and below reference just the classical groups and list the others in a
//     tls-groups:tls13-only property. tls-groups exists from 7.6.5; earlier
//     versions report it unknown.
//   - when a version is unknown (no defaults table), one component without a
//     version stands for the section. It references only the classical
//     groups, like TLS 1.2, since it cannot claim TLS 1.3.
//   - servercert links the component to that local certificate.
//
// 7.4.12 also has DTLS (dtls-tunnel, dtls-min/max-proto-ver), emitted as
// separate protocol components when DTLS is enabled.
package sslvpn

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/certs"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/algo"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/field"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const section = "vpn ssl settings"

// Option tokens, verified against the CLI HTML (research notes §3.7 note).
var (
	tlsVersions  = []string{"tls1-0", "tls1-1", "tls1-2", "tls1-3"}
	dtlsVersions = []string{"dtls1-0", "dtls1-2"}
	versionName  = map[string]string{"tls1-0": "1.0", "tls1-1": "1.1", "tls1-2": "1.2", "tls1-3": "1.3", "dtls1-0": "1.0", "dtls1-2": "1.2"}

	specTLSVersion  = field.Spec{Known: set(tlsVersions...)}
	specDTLSVersion = field.Spec{Known: set(dtlsVersions...)}
	specAlgorithm   = field.Spec{Known: set("high", "medium", "default", "low")}
	specBanned      = field.Spec{Known: set("RSA", "DHE", "ECDHE", "DSS", "ECDSA", "AES", "AESGCM", "CAMELLIA", "3DES", "SHA1", "SHA256", "SHA384", "STATIC", "CHACHA20", "ARIA", "AESCCM"), Pattern: regexp.MustCompile(`^[A-Z0-9]{1,16}$`)}
	specSuites      = field.Spec{Known: set("TLS-AES-128-GCM-SHA256", "TLS-AES-256-GCM-SHA384", "TLS-CHACHA20-POLY1305-SHA256", "TLS-AES-128-CCM-SHA256", "TLS-AES-128-CCM-8-SHA256"), Pattern: regexp.MustCompile(`^TLS-[A-Z0-9-]{1,60}$`)}
	specGroups      = field.Spec{Known: keys(groups), Pattern: regexp.MustCompile(`^[A-Za-z0-9-]{1,32}$`)}
	specEnableDis   = field.Spec{Known: set("enable", "disable")}
	specCertName    = field.Spec{Pattern: regexp.MustCompile(`^[A-Za-z0-9 _.@-]{1,35}$`), Freeform: true}
)

type alg struct {
	name  string
	a     model.Algorithm
	parts []alg // for hybrid (combiner) groups
}

var nist1, nist3, nist5 = 1, 3, 5

func ecp(name, curve string) alg {
	return alg{name: name, a: model.Algorithm{Primitive: "key-agree", Curve: curve}}
}
func ffdhe(bits string) alg {
	return alg{name: "FFDHE-" + bits, a: model.Algorithm{Primitive: "key-agree", ParameterSetIdentifier: bits}}
}
func mlkem(psi string, level *int) alg {
	return alg{name: "ML-KEM-" + psi, a: model.Algorithm{Primitive: "kem", ParameterSetIdentifier: psi, NISTQuantumLevel: level}}
}

// groups maps tls-groups tokens to algorithms. ECP-*, X25519, X448, and
// ML-KEM-* match the IPsec extractor's names and definitions. FFDHE groups
// (RFC 7919) are different groups from IKE's MODP groups (RFC 3526), so they
// are named separately. Hybrid names are the IANA TLS group names listed in
// research notes §4.
var groups = map[string]alg{
	"P-521":           ecp("ECP-521", "secp521r1"),
	"P-384":           ecp("ECP-384", "secp384r1"),
	"P-256":           ecp("ECP-256", "secp256r1"),
	"X25519":          ecp("X25519", "x25519"),
	"X448":            ecp("X448", "x448"),
	"FFDHE2048":       ffdhe("2048"),
	"FFDHE3072":       ffdhe("3072"),
	"FFDHE4096":       ffdhe("4096"),
	"FFDHE6144":       ffdhe("6144"),
	"FFDHE8192":       ffdhe("8192"),
	"ML-KEM512":       mlkem("512", &nist1),
	"ML-KEM768":       mlkem("768", &nist3),
	"ML-KEM1024":      mlkem("1024", &nist5),
	"X25519-MLKEM768": {name: "X25519MLKEM768", a: model.Algorithm{Primitive: "combiner"}, parts: []alg{mlkem("768", &nist3), ecp("X25519", "x25519")}},
	"P-256-MLKEM768":  {name: "SecP256r1MLKEM768", a: model.Algorithm{Primitive: "combiner"}, parts: []alg{mlkem("768", &nist3), ecp("ECP-256", "secp256r1")}},
	"P-384-MLKEM1024": {name: "SecP384r1MLKEM1024", a: model.Algorithm{Primitive: "combiner"}, parts: []alg{mlkem("1024", &nist5), ecp("ECP-384", "secp384r1")}},
}

// Extract adds SSL VPN TLS components for every scope that has the section.
func Extract(t *tree.Tree, location string, inv *model.Inventory) {
	x := &extractor{t: t, inv: inv, r: &field.Resolver{Loc: location, Inv: inv, Defaults: defaults.ForVersion(t.Header.Version)}}
	found := false
	for _, scope := range t.Scopes() {
		if blocks := t.Blocks(scope, section); len(blocks) > 0 {
			found = true
			x.scope(scope, blocks)
		}
	}
	if found && x.r.Defaults == nil {
		inv.AddWarning(field.NoDefaultsWarning(t.Header.Version, location))
	}
}

type extractor struct {
	t   *tree.Tree
	inv *model.Inventory
	r   *field.Resolver
}

func (x *extractor) scope(scope tree.Scope, blocks []*tree.Block) {
	ctx, suffix := "", ""
	switch scope.Kind {
	case tree.KindVDOM:
		ctx = "vdom " + scope.Name
	case tree.KindGlobal:
		ctx = "global"
	}
	if ctx != "" {
		suffix = " (" + ctx + ")"
	}
	resolve := func(name string, sp field.Spec) field.Value {
		var attr *tree.Attr
		for _, b := range blocks {
			if a := b.Attr(name); a != nil {
				attr = a
			}
		}
		return x.r.Resolve(attr, section, name, section+"/"+name, ctx, sp)
	}

	min, max := resolve("ssl-min-proto-ver", specTLSVersion), resolve("ssl-max-proto-ver", specTLSVersion)
	algorithm, banned := resolve("algorithm", specAlgorithm), resolve("banned-cipher", specBanned)
	suites, grps := resolve("ciphersuite", specSuites), resolve("tls-groups", specGroups)
	server := resolve("servercert", specCertName)

	groupRefs, classicalRefs, pqNames := x.groups(grps)
	var certRefs []string
	for _, name := range server.Tokens {
		r := certs.Ref(x.t, x.r.Loc, scope, name)
		if r.Missing && r.Reported {
			continue // the certificate extractor already warned
		}
		if r.Missing {
			x.inv.AddWarning(model.Warning{
				Code:    "unknown-certificate",
				Message: fmt.Sprintf("SSL VPN servercert %q is not among the local certificates it can use (it may be built in)", name),
				Ev:      x.r.Evidence(server),
			})
			continue
		}
		certRefs = append(certRefs, r.Cert)
	}

	newTLS := func(name, version string) *model.Asset {
		a := &model.Asset{
			Type:       model.AssetTypeProtocol,
			Name:       name + suffix,
			Proto:      &model.Protocol{Type: "tls", Version: version},
			Properties: map[string]string{},
			DependsOn:  certRefs,
		}
		field.MarkConfiguredView(a)
		if ctx != "" {
			a.Properties[field.Prefix+"scope"] = ctx
		}
		return a
	}

	versions := versionRange(min, max, tlsVersions)
	if versions == nil && (len(min.Tokens) != 1 || len(max.Tokens) != 1) {
		// A version is unknown (no defaults table, or an unknown option), so
		// one component without a version stands for the section.
		versions = []string{""}
	}
	for _, ver := range versions {
		name := "FortiOS SSL VPN TLS"
		if ver != "" {
			name += " " + versionName[ver]
		}
		a := newTLS(name, versionName[ver])
		if ver == "" {
			a.Properties[field.Prefix+"tls-version"] = field.Unknown
		}
		for _, v := range []field.Value{min, max, algorithm, grps, server} {
			x.r.Record(a, v, true)
		}
		switch ver {
		case "tls1-3":
			x.r.Record(a, suites, true)
			for _, s := range suites.Tokens {
				a.Proto.CipherSuites = append(a.Proto.CipherSuites, model.CipherSuite{Name: s})
			}
		case "":
			x.r.Record(a, suites, true)
			x.r.Record(a, banned, true)
			a.Properties[field.Prefix+"cipher-suites"] = field.Unknown
		default:
			x.r.Record(a, banned, true)
			a.Properties[field.Prefix+"cipher-suites"] = field.Unknown
		}
		refs := groupRefs
		if ver != "tls1-3" {
			// ML-KEM and hybrid groups are defined for TLS 1.3 only. With the
			// version unknown, the component may stand for TLS 1.2 or below,
			// so it does not claim them either.
			refs = classicalRefs
			if len(pqNames) > 0 {
				a.Properties[field.Prefix+"tls-groups:tls13-only"] = strings.Join(pqNames, " ")
			}
		}
		a.Proto.Refs = append(append([]string(nil), refs...), certRefs...)
		x.inv.Add(a)
	}
	if len(min.Tokens) == 1 && len(max.Tokens) == 1 && slices.Index(tlsVersions, min.Tokens[0]) > slices.Index(tlsVersions, max.Tokens[0]) {
		at := min // point at whichever end is configured
		if at.Source != field.Configured {
			at = max
		}
		x.inv.AddWarning(model.Warning{
			Code:    "ssl-version-range-empty",
			Message: fmt.Sprintf("SSL VPN ssl-min-proto-ver %s is above ssl-max-proto-ver %s%s; no TLS version is enabled", min.Tokens[0], max.Tokens[0], suffix),
			Ev:      x.r.Evidence(at),
		})
	}

	// DTLS settings exist only in 7.4.12; on other versions they resolve to
	// unknown and nothing is emitted.
	dtls := resolve("dtls-tunnel", specEnableDis)
	if strings.Join(dtls.Tokens, " ") != "enable" {
		return
	}
	dmin, dmax := resolve("dtls-min-proto-ver", specDTLSVersion), resolve("dtls-max-proto-ver", specDTLSVersion)
	for _, ver := range versionRange(dmin, dmax, dtlsVersions) {
		a := newTLS("FortiOS SSL VPN DTLS "+versionName[ver], versionName[ver])
		a.Properties[field.Prefix+"transport"] = "dtls"
		a.Properties[field.Prefix+"cipher-suites"] = field.Unknown
		for _, v := range []field.Value{dtls, dmin, dmax, server} {
			x.r.Record(a, v, true)
		}
		a.Proto.Refs = append([]string(nil), certRefs...)
		x.inv.Add(a)
	}
}

// versionRange returns the versions from min to max inclusive, or nil when
// either is unknown or not a known option, or min is above max.
func versionRange(min, max field.Value, order []string) []string {
	if len(min.Tokens) != 1 || len(max.Tokens) != 1 {
		return nil
	}
	i, j := slices.Index(order, min.Tokens[0]), slices.Index(order, max.Tokens[0])
	if i < 0 || j < 0 || i > j {
		return nil
	}
	return order[i : j+1]
}

// groups adds the algorithm components for the configured TLS groups. It
// returns the bom-refs of all of them, hybrid parts included; the bom-refs
// of the classical groups alone, for TLS 1.2 and below; and the tokens of the
// ML-KEM and hybrid groups, which are defined for TLS 1.3 only
// (draft-ietf-tls-mlkem, RFC 10024; research notes §3.7 note).
func (x *extractor) groups(v field.Value) (all, classical, pq []string) {
	add := func(refs *[]string, id string) {
		if !slices.Contains(*refs, id) {
			*refs = append(*refs, id)
		}
	}
	for _, tok := range v.Tokens {
		g, ok := groups[tok]
		if !ok {
			continue
		}
		var parts []string
		for _, p := range g.parts {
			parts = append(parts, x.algorithm(p, v, nil))
		}
		id := x.algorithm(g, v, parts)
		add(&all, id)
		for _, p := range parts {
			add(&all, p)
		}
		if g.a.Primitive == "kem" || g.a.Primitive == "combiner" {
			pq = append(pq, tok)
		} else {
			add(&classical, id)
		}
	}
	return all, classical, pq
}

// algorithm adds (or reuses) an algorithm component with the bom-ref the
// other extractors compute for the same name.
func (x *extractor) algorithm(g alg, v field.Value, dependsOn []string) string {
	def := g.a
	algo.MarkQuantumVulnerable(&def)
	a := &model.Asset{
		ID:        model.BOMRef(model.AssetTypeAlgorithm, g.name, x.r.Loc),
		Type:      model.AssetTypeAlgorithm,
		Name:      g.name,
		Alg:       &def,
		DependsOn: dependsOn,
	}
	if v.Source == field.Configured {
		a.Evidence = []model.Evidence{x.r.Evidence(v)}
	}
	return x.inv.Add(a).ID
}

func set(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

func keys[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
