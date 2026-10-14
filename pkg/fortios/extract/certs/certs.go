// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package certs extracts certificates from "config vpn certificate local",
// "ca", and "remote" (and the same tables under "config certificate", which
// 7.6.7 and 8.0.1 also have), per research notes §3.8.
//
// Only the public certificate PEM is parsed, with crypto/x509. A field may
// hold several PEM blocks; they are told apart by their BEGIN lines, only the
// first CERTIFICATE block is decoded and parsed, further certificates are
// counted, and a private key block there is warned about without being read.
// For each certificate it emits:
//
//	certificate component   subject, issuer, validity, format, fingerprint, serial
//	  → public key          related-crypto-material, key size, SPKI fingerprint as id
//	      → key algorithm   e.g. RSA-2048 (pke), ECDSA-P256 (signature)
//	  → signature algorithm e.g. ECDSA-SHA384, SHA256-RSA
//	private key             related-crypto-material, presence only
//
// The private-key value is never parsed, decoded, or emitted: the code only
// checks whether the field is set and, to tell its form, its first token or
// a PEM key's BEGIN line (plus, for traditional RSA/EC/DSA keys, the RFC 1421
// Proc-Type header). An unencrypted PEM key is warned about. The password
// field is never read.
//
// Certificates are flagged when expired at the reference time (a warning).
// A leaf certificate whose validity exceeds the CA/Browser Forum maximum for
// its issue date (Baseline Requirements §6.3.2; research notes §3.7 note) gets
// exceeds-cabf-max=true, for information only: the limit binds publicly
// trusted TLS server certificates, and certificates for internal VPNs (IPsec,
// SSL VPN with a private CA) are not bound by it. It never gives a warning;
// cabf-applicability says so on each component that carries the flag.
//
// Two details of that check. The limit is chosen by the certificate's start
// date, notBefore: the Baseline Requirements key the limits to the issue
// date, and notBefore is the date the certificate itself carries (CAs set it
// to the issue time; a backdated notBefore selects an earlier, longer limit).
// The validity period is counted as the Baseline Requirements define it,
// from notBefore through notAfter inclusive with any part of a day counting
// as a whole day, so a certificate whose notAfter is exactly 365 days after
// its notBefore has a validity of 366 days (validity-days), and one that is
// valid for at most 365 days ends one second earlier.
//
// In a multi-VDOM backup each VDOM's tables also list the global (factory)
// certificates by name, with range global and no PEM. Such an entry is a
// reference to the global certificate of the same name: it adds no component
// of its own, and the global certificate gets an evidence occurrence and a
// referenced-from property for each VDOM that lists it.
//
// Ref lets other extractors (IPsec, SSL VPN) reference a local certificate by
// name. It computes the same bom-refs Extract uses, so extractor order does
// not matter.
package certs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/algo"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/field"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// table is one certificate table and the field holding its PEM.
type table struct {
	path     string // config path
	pemField string
	kind     string // local | ca | remote
}

// tables lists the certificate tables (research notes §3.8). The
// "certificate ..." paths hold the same fields as "vpn certificate ...".
var tables = []table{
	{"vpn certificate local", "certificate", "local"},
	{"vpn certificate ca", "ca", "ca"},
	{"vpn certificate remote", "remote", "remote"},
	{"certificate local", "certificate", "local"},
	{"certificate ca", "ca", "ca"},
	{"certificate remote", "remote", "remote"},
}

// Values recorded as properties when configured; anything else is ignored.
var (
	knownSource = map[string]bool{"factory": true, "user": true, "bundle": true}
	knownRange  = map[string]bool{"global": true, "vdom": true}
)

// Extract adds certificate components for every certificate in every scope
// of t. now is the reference time for the expiry check; if it is zero, expiry
// is recorded as not evaluated.
func Extract(t *tree.Tree, location string, inv *model.Inventory, now time.Time) {
	// First pass: VDOM entries that point at a global certificate. Their
	// occurrences go on the global component, keyed by table kind and name.
	refs := map[string][]model.Evidence{}
	for _, scope := range t.Scopes() {
		for _, tb := range tables {
			for _, e := range t.Get(scope, tb.path) {
				if !globalRef(scope, tb, e) {
					continue
				}
				ev := model.Evidence{Location: location, Line: e.Attr("range").Line, Symbol: tb.path + "/" + e.Name + "/range", Context: scopeContext(scope)}
				if findGlobal(t, tb.kind, e.Name) == nil {
					inv.AddWarning(model.Warning{
						Code:    "cert-reference-missing",
						Message: fmt.Sprintf("vpn certificate %s %q in %s has range global, but the backup has no global certificate of that name", tb.kind, e.Name, ev.Context),
						Ev:      ev,
					})
					continue
				}
				k := tb.kind + "\x00" + e.Name
				refs[k] = append(refs[k], ev)
			}
		}
	}
	for _, scope := range t.Scopes() {
		for _, tb := range tables {
			for _, e := range t.Get(scope, tb.path) {
				if globalRef(scope, tb, e) {
					continue
				}
				var from []model.Evidence
				if scope.Kind == tree.KindGlobal {
					from = refs[tb.kind+"\x00"+e.Name]
				}
				addCert(inv, location, scope, tb, e, now, from)
			}
		}
	}
}

// globalRef reports whether e, in a VDOM, only refers to the global
// certificate of the same name: range global and no PEM.
func globalRef(scope tree.Scope, tb table, e *tree.Entry) bool {
	if scope.Kind != tree.KindVDOM {
		return false
	}
	if a := e.Attr(tb.pemField); a != nil && !a.Unset && len(a.Values) > 0 {
		return false
	}
	r := e.Attr("range")
	return r != nil && !r.Unset && len(r.Values) == 1 && r.Values[0] == "global"
}

// findGlobal returns the global entry of the given kind and name, or nil.
func findGlobal(t *tree.Tree, kind, name string) *tree.Entry {
	for _, tb := range tables {
		if tb.kind != kind {
			continue
		}
		for _, e := range t.Get(tree.ScopeGlobal, tb.path) {
			if e.Name == name {
				return e
			}
		}
	}
	return nil
}

// Refs are the bom-refs another component needs to point at a certificate.
type Refs struct {
	Cert    string // certificate component
	KeyAlg  string // the certificate key's algorithm component; empty if the PEM does not parse
	Missing bool   // no local certificate with that name in the backup
	// Reported is set with Missing when the name is a VDOM reference to a
	// global certificate that is not in the backup. Extract already warns
	// about that (cert-reference-missing), so callers should not warn again.
	Reported bool
}

// Ref finds the local certificate name for a component in scope, looking in
// scope first and then in the global scope (multi-VDOM backups keep shared
// certificates there). A VDOM entry that only refers to the global
// certificate (range global, no PEM) resolves to the global one. It returns the bom-refs Extract gives that
// certificate, without adding anything to an inventory.
func Ref(t *tree.Tree, location string, scope tree.Scope, name string) Refs {
	scopes := []tree.Scope{scope}
	if scope.Kind == tree.KindVDOM {
		scopes = append(scopes, tree.ScopeGlobal)
	}
	reference := false // a VDOM entry names a global certificate
	for _, s := range scopes {
		for _, tb := range tables {
			if tb.kind != "local" {
				continue
			}
			for _, e := range t.Get(s, tb.path) {
				if e.Name != name {
					continue
				}
				if globalRef(s, tb, e) {
					reference = true
					continue
				}
				r := Refs{Cert: model.BOMRef(model.AssetTypeCertificate, certName(s, tb, e), location)}
				if p, err := parsePEM(e.Attr(tb.pemField)); err == nil {
					r.KeyAlg = model.BOMRef(model.AssetTypeAlgorithm, keyAlgorithm(p).name, location)
				}
				return r
			}
		}
	}
	return Refs{Missing: true, Reported: reference}
}

// certName is the component name: table kind, entry name, and scope.
func certName(scope tree.Scope, tb table, e *tree.Entry) string {
	n := "FortiOS certificate " + tb.kind + " " + e.Name
	switch scope.Kind {
	case tree.KindVDOM:
		n += " (vdom " + scope.Name + ")"
	case tree.KindGlobal:
		n += " (global)"
	}
	return n
}

func scopeContext(scope tree.Scope) string {
	switch scope.Kind {
	case tree.KindVDOM:
		return "vdom " + scope.Name
	case tree.KindGlobal:
		return "global"
	}
	return ""
}

// parsed is a certificate plus the algorithm OIDs read from its ASN.1, so
// algorithms crypto/x509 does not know still get an OID.
type parsed struct {
	cert   *x509.Certificate
	sigOID string
	keyOID string
}

// pemText is the certificate field's value, or "" if it is not set.
func pemText(attr *tree.Attr) string {
	if attr == nil || attr.Unset || len(attr.Values) == 0 {
		return ""
	}
	return strings.Join(attr.Values, " ")
}

// parsePEM parses the first CERTIFICATE block of a certificate field. Blocks
// are told apart by their BEGIN lines first (scanCertField), so only
// certificate text is ever base64-decoded, wherever a key block sits.
func parsePEM(attr *tree.Attr) (*parsed, error) {
	text := pemText(attr)
	if text == "" {
		return nil, fmt.Errorf("no certificate PEM")
	}
	f := scanCertField(text)
	if f.cert == "" && f.nestedCerts > 0 {
		return nil, fmt.Errorf("the CERTIFICATE block contains another PEM block, so it was not decoded")
	}
	if f.cert == "" {
		return nil, fmt.Errorf("no PEM CERTIFICATE block")
	}
	block, _ := pem.Decode([]byte(f.cert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM CERTIFICATE block does not decode")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("X.509 parse failed")
	}
	p := &parsed{cert: c}
	var outer struct {
		TBS    asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.Raw, &outer); err == nil {
		p.sigOID = outer.SigAlg.Algorithm.String()
	}
	var spki struct {
		Alg pkix.AlgorithmIdentifier
		Key asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err == nil {
		p.keyOID = spki.Alg.Algorithm.String()
	}
	return p, nil
}

// alg is an algorithm component definition.
type alg struct {
	name string
	oid  string
	a    model.Algorithm
	bits int // key size, for the public and private key components
}

// ed25519Alg is Ed25519 as both a key algorithm and a signature algorithm:
// pure Ed25519 uses one OID (id-Ed25519, 1.3.101.112, RFC 8410) for the key
// and the signature, and crypto/x509 names both "Ed25519". Both uses must
// give the same definition, or the inventory would hold two different
// copies under one bom-ref.
func ed25519Alg(oid string) alg {
	return alg{name: "Ed25519", oid: oid, bits: 256, a: model.Algorithm{Primitive: "signature", Curve: "ed25519"}}
}

var curveNames = map[string]string{"P-224": "secp224r1", "P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1"}

// keyAlgorithm names the certificate key's algorithm. RSA keys are pke (they
// can encrypt as well as sign); EC and Ed25519 keys are signature keys.
func keyAlgorithm(p *parsed) alg {
	switch k := p.cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		return alg{name: "RSA-" + strconv.Itoa(bits), oid: p.keyOID, bits: bits,
			a: model.Algorithm{Primitive: "pke", ParameterSetIdentifier: strconv.Itoa(bits)}}
	case *ecdsa.PublicKey:
		params := k.Curve.Params()
		return alg{name: "ECDSA-" + strings.ReplaceAll(params.Name, "-", ""), oid: p.keyOID, bits: params.BitSize,
			a: model.Algorithm{Primitive: "signature", Curve: curveNames[params.Name]}}
	case ed25519.PublicKey:
		return ed25519Alg(p.keyOID)
	}
	return alg{name: "OID " + p.keyOID, oid: p.keyOID, a: model.Algorithm{Primitive: "unknown"}}
}

func signatureAlgorithm(p *parsed) alg {
	sa := p.cert.SignatureAlgorithm
	if sa == x509.UnknownSignatureAlgorithm {
		return alg{name: "OID " + p.sigOID, oid: p.sigOID, a: model.Algorithm{Primitive: "unknown"}}
	}
	if sa == x509.PureEd25519 {
		return ed25519Alg(p.sigOID)
	}
	a := model.Algorithm{Primitive: "signature"}
	switch sa {
	case x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.MD5WithRSA:
		a.Padding = "pkcs1v15"
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		a.Padding = "other" // CycloneDX 1.6 has no PSS value
	}
	return alg{name: sa.String(), oid: p.sigOID, a: a}
}

// cabfApplicability qualifies exceeds-cabf-max on every component that has it.
const cabfApplicability = "informational: the CA/Browser Forum limit binds only publicly trusted TLS server certificates; internal VPN certificates are not bound by it"

// cabfMaxDays is the CA/Browser Forum maximum validity for a Subscriber
// Certificate (Baseline Requirements §6.3.2). The rules are keyed to the issue
// date; the certificate's notBefore stands in for it, since that is the date
// the certificate carries.
func cabfMaxDays(notBefore time.Time) (int, string) {
	d := func(y int, m time.Month, day int) time.Time { return time.Date(y, m, day, 0, 0, 0, 0, time.UTC) }
	switch {
	case !notBefore.Before(d(2029, 3, 15)):
		return 47, "notBefore on or after 2029-03-15"
	case !notBefore.Before(d(2027, 3, 15)):
		return 100, "notBefore on or after 2027-03-15"
	case !notBefore.Before(d(2026, 3, 15)):
		return 200, "notBefore on or after 2026-03-15"
	}
	return 398, "notBefore before 2026-03-15"
}

// validityDays counts the validity period the way the Baseline Requirements
// do: notBefore through notAfter inclusive (§1.6.1, "Validity Period"), any
// part of a day as a day (§6.3.2). The +1 second makes notAfter itself part of the
// period, so notAfter = notBefore + 365 days is 366 days, and notAfter =
// notBefore + 365 days - 1 second is 365.
func validityDays(c *x509.Certificate) int {
	secs := c.NotAfter.Sub(c.NotBefore).Seconds() + 1
	return int(math.Ceil(secs / 86400))
}

// addCert adds the components for one certificate entry. from holds the
// occurrences of VDOM entries that refer to this (global) certificate.
func addCert(inv *model.Inventory, location string, scope tree.Scope, tb table, e *tree.Entry, now time.Time, from []model.Evidence) {
	name := certName(scope, tb, e)
	ctx := scopeContext(scope)
	pemAttr := e.Attr(tb.pemField)
	sym := tb.path + "/" + e.Name + "/" + tb.pemField

	c := &model.Asset{
		ID:         model.BOMRef(model.AssetTypeCertificate, name, location),
		Type:       model.AssetTypeCertificate,
		Name:       name,
		Cert:       &model.Cert{Format: "X.509", Extension: "pem"},
		Properties: map[string]string{field.Prefix + "certificate-kind": tb.kind},
	}
	var ev []model.Evidence
	if pemAttr != nil {
		ev = []model.Evidence{{Location: location, Line: pemAttr.Line, Symbol: sym, Context: ctx}}
	}
	c.Evidence = append(slices.Clone(ev), from...)
	if len(from) > 0 {
		var ctx []string
		for _, f := range from {
			ctx = append(ctx, f.Context)
		}
		slices.Sort(ctx)
		c.Properties[field.Prefix+"referenced-from"] = strings.Join(slices.Compact(ctx), ", ")
	}
	for _, f := range []struct {
		key   string
		known map[string]bool
	}{{"source", knownSource}, {"range", knownRange}} {
		if a := e.Attr(f.key); a != nil && !a.Unset && len(a.Values) == 1 && f.known[a.Values[0]] {
			c.Properties[field.Prefix+f.key+":value"] = a.Values[0]
			c.Properties[field.Prefix+f.key+":line"] = strconv.Itoa(a.Line)
		}
	}

	// Look at what else the field holds before parsing. A private key block
	// is counted by its BEGIN line only and warned about, never read.
	if text := pemText(pemAttr); text != "" {
		f := scanCertField(text)
		if f.keyBlocks > 0 {
			c.Properties["cbom-netscan:cert:key-blocks-in-certificate-field"] = strconv.Itoa(f.keyBlocks)
			inv.AddWarning(model.Warning{
				Code:    "private-key-in-certificate-field",
				Message: fmt.Sprintf("%s: the certificate field also holds a private key block (not read or shown); keys belong in private-key, and this one may be unencrypted in the backup", name),
				Ev:      model.Evidence{Location: location, Line: pemAttr.Line, Symbol: sym, Context: ctx},
			})
		}
		if f.extraCerts > 0 {
			c.Properties["cbom-netscan:cert:additional-certificate-blocks"] = strconv.Itoa(f.extraCerts)
		}
		if f.other > 0 {
			c.Properties["cbom-netscan:cert:other-pem-blocks"] = strconv.Itoa(f.other)
		}
	}

	p, err := parsePEM(pemAttr)
	if err != nil {
		c.Properties["cbom-netscan:cert:parse"] = "failed"
		line := 0
		if pemAttr != nil {
			line = pemAttr.Line
		}
		inv.AddWarning(model.Warning{
			Code:    "cert-unparseable",
			Message: fmt.Sprintf("%s: %v; reported without certificate details", name, err),
			Ev:      model.Evidence{Location: location, Line: line, Symbol: sym, Context: ctx},
		})
		inv.Add(c)
		addPrivateKey(inv, location, ctx, tb, e, name, nil, "")
		return
	}
	cert := p.cert

	key, sig := keyAlgorithm(p), signatureAlgorithm(p)
	keyID := addAlgorithm(inv, location, key, ev)
	sigID := addAlgorithm(inv, location, sig, ev)

	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	pub := &model.Asset{
		ID:   model.BOMRef(model.AssetTypeRelatedMaterial, name+" public key", location),
		Type: model.AssetTypeRelatedMaterial,
		Name: name + " public key",
		Mat: &model.Material{
			Type: "public-key", ID: "spki-sha256:" + hex.EncodeToString(spki[:]), AlgorithmRef: keyID,
			Size: sizePtr(key.bits),
		},
		Evidence: ev,
	}
	inv.Add(pub)

	nb, na := cert.NotBefore.UTC(), cert.NotAfter.UTC()
	fp := sha256.Sum256(cert.Raw)
	c.Cert.SubjectName = cert.Subject.String()
	c.Cert.IssuerName = cert.Issuer.String()
	c.Cert.NotValidBefore, c.Cert.NotValidAfter = &nb, &na
	c.Cert.SignatureAlgorithmRef = sigID
	c.Cert.SubjectPublicKeyRef = pub.ID
	c.Cert.SHA256 = hex.EncodeToString(fp[:])
	c.Cert.Serial = cert.SerialNumber.Text(16)

	days := validityDays(cert)
	c.Properties["cbom-netscan:cert:is-ca"] = strconv.FormatBool(cert.IsCA)
	c.Properties["cbom-netscan:cert:validity-days"] = strconv.Itoa(days)
	if cert.IsCA {
		c.Properties["cbom-netscan:cert:cabf-max-days"] = "not applicable: CA certificate"
	} else {
		max, rule := cabfMaxDays(nb)
		c.Properties["cbom-netscan:cert:cabf-max-days"] = fmt.Sprintf("%d (%s; Baseline Requirements §6.3.2)", max, rule)
		c.Properties["cbom-netscan:cert:exceeds-cabf-max"] = strconv.FormatBool(days > max)
		c.Properties["cbom-netscan:cert:cabf-applicability"] = cabfApplicability
	}
	if now.IsZero() {
		c.Properties["cbom-netscan:cert:expired"] = "not evaluated"
	} else {
		expired := now.After(na)
		c.Properties["cbom-netscan:cert:expired"] = strconv.FormatBool(expired)
		c.Properties["cbom-netscan:cert:expiry-checked-at"] = now.UTC().Format(time.RFC3339)
		if expired {
			inv.AddWarning(model.Warning{
				Code:    "cert-expired",
				Message: fmt.Sprintf("%s expired on %s", name, na.Format("2006-01-02")),
				Ev:      model.Evidence{Location: location, Line: pemAttr.Line, Symbol: sym, Context: ctx},
			})
		}
	}
	inv.Add(c)
	addPrivateKey(inv, location, ctx, tb, e, name, &key, keyID)
}

// addPrivateKey records a private key's presence and form. The key is never
// read: only the first token, or a PEM key's BEGIN line and Proc-Type
// header, is looked at (see privateKeyForm). A key that is, or may be, unencrypted in the backup gives
// a plaintext-private-key warning, without the value.
func addPrivateKey(inv *model.Inventory, location, ctx string, tb table, e *tree.Entry, certName string, key *alg, keyID string) {
	if tb.kind != "local" {
		return
	}
	a := e.Attr("private-key")
	if a == nil || a.Unset || len(a.Values) == 0 {
		return
	}
	m := &model.Material{Type: "private-key"}
	if key != nil {
		m.AlgorithmRef, m.Size = keyID, sizePtr(key.bits)
	}
	ev := model.Evidence{Location: location, Line: a.Line, Symbol: tb.path + "/" + e.Name + "/private-key", Context: ctx}
	form, warn := privateKeyForm(a.Values)
	if warn {
		msg := "is an unencrypted PEM key"
		if form == formPEMUnknown {
			msg = "is an OpenSSH-format (or other) PEM key that records its encryption inside the key, which is not read, so it may be unencrypted"
		}
		inv.AddWarning(model.Warning{
			Code:    "plaintext-private-key",
			Message: fmt.Sprintf("%s: the private key %s in the backup (value not shown); take backups with secrets encrypted", certName, msg),
			Ev:      ev,
		})
	}
	inv.Add(&model.Asset{
		ID:   model.BOMRef(model.AssetTypeRelatedMaterial, certName+" private key", location),
		Type: model.AssetTypeRelatedMaterial,
		Name: certName + " private key",
		Mat:  m,
		Properties: map[string]string{
			field.Prefix + "private-key":      "present",
			field.Prefix + "private-key:form": form,
		},
		Evidence: []model.Evidence{ev},
	})
}

func addAlgorithm(inv *model.Inventory, location string, a alg, ev []model.Evidence) string {
	def := a.a
	algo.MarkQuantumVulnerable(&def)
	return inv.Add(&model.Asset{
		ID:       model.BOMRef(model.AssetTypeAlgorithm, a.name, location),
		Type:     model.AssetTypeAlgorithm,
		Name:     a.name,
		OID:      a.oid,
		Alg:      &def,
		Evidence: ev,
	}).ID
}

func sizePtr(bits int) *int {
	if bits == 0 {
		return nil
	}
	return &bits
}
