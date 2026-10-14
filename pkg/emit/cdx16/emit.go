// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package cdx16 emits a model.Inventory as a CycloneDX 1.6 JSON CBOM
// using the official cyclonedx-go library.
//
// Design decisions:
//
//   - The serial number is a random UUIDv4 unless meta.SerialNumber is set;
//     the timestamp is meta.Created, omitted with meta.OmitTimestamp, or now.
//     The emitter reads no environment variables; reproducible output is the
//     caller's choice (see ReproducibleSerial).
//   - Components are sorted protocols first, then algorithms, certificates,
//     and related crypto material, then by name (bom-ref breaks ties), so
//     the output reads top-down and diffs are stable.
//   - Properties within each component are sorted by name for the same reason.
//   - We set bom.SpecVersion = SpecVersion1_6 directly and call Encode (not
//     EncodeVersion) to avoid the copyAndConvert path in cyclonedx-go v0.12.0.
//     That path's supportsComponentType() has no case for CryptographicAsset,
//     so EncodeVersion silently downgrades it to "application" (library bug).
//     See https://github.com/CycloneDX/cyclonedx-go/issues/298 — once fixed
//     upstream, switch back to EncodeVersion.
package cdx16

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// Emitter implements model.Emitter for CycloneDX 1.6 JSON.
type Emitter struct{}

// Format returns the format identifier used in logs and CLI output.
func (Emitter) Format() string { return "cyclonedx-1.6-json" }

// Emit serialises inv to w as a pretty-printed CycloneDX 1.6 JSON BOM.
//
// See bomSerial and bomTimestamp for how meta controls the serial number and
// timestamp.
func (Emitter) Emit(_ context.Context, w io.Writer, inv *model.Inventory, meta model.Meta) error {
	bom := cdx.NewBOM()
	// Pin to 1.6 before Encode so the $schema field is correct and the
	// encoder writes the right specVersion without going through
	// copyAndConvert (which would silently downgrade cryptographic-asset).
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.JSONSchema = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	bom.SerialNumber = bomSerial(meta)
	bom.Metadata = buildMetadata(meta)

	components, deps := buildComponents(inv.Assets)
	bom.Components = &components
	if len(deps) > 0 {
		bom.Dependencies = &deps
	}

	// Encode compactly, fix what the library cannot express, then indent.
	// json.Encoder with SetIndent does the same marshal-then-indent, so
	// untouched output is byte-identical to encoding with indentation.
	compact, err := json.Marshal(bom)
	if err != nil {
		return err
	}
	compact, err = dropUnknownESN(compact, unknownESN(components, inv.Assets))
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return err
	}
	out.WriteByte('\n')
	_, err = w.Write(out.Bytes())
	return err
}

// unknownESN lists, for each component that has ikev2TransformTypes, in
// output order, whether its ESN is unknown (model ESN nil).
func unknownESN(components []cdx.Component, assets []*model.Asset) []bool {
	known := map[string]bool{}
	for _, a := range assets {
		if a.Proto != nil && a.Proto.ESN != nil {
			known[a.ID] = true
		}
	}
	var out []bool
	for _, c := range components {
		cp := c.CryptoProperties
		if cp != nil && cp.ProtocolProperties != nil && cp.ProtocolProperties.IKEv2TransformTypes != nil {
			out = append(out, !known[c.BOMRef])
		}
	}
	return out
}

// dropUnknownESN removes "esn":false from the i-th ikev2TransformTypes object
// when drop[i] is set. cyclonedx-go v0.12.0 declares ESN as a bool without
// omitempty, so it always writes "esn":false, which would claim ESN is off
// when the config does not say. CycloneDX 1.6 can only express "unknown" by
// omitting the field.
//
// Matching on raw bytes is safe here: quotes inside JSON strings are escaped,
// so `"ikev2TransformTypes":{` and `"esn":false` only occur as real keys.
func dropUnknownESN(b []byte, drop []bool) ([]byte, error) {
	key, esn := []byte(`"ikev2TransformTypes":{`), []byte(`"esn":false`)
	var out []byte
	rest := b
	for i := 0; ; i++ {
		j := bytes.Index(rest, key)
		if j < 0 {
			if i != len(drop) {
				return nil, fmt.Errorf("cdx16: found %d ikev2TransformTypes objects, expected %d", i, len(drop))
			}
			return append(out, rest...), nil
		}
		if i >= len(drop) {
			return nil, fmt.Errorf("cdx16: more ikev2TransformTypes objects than expected (%d)", len(drop))
		}
		start := j + len(key)
		out = append(out, rest[:start]...)
		rest = rest[start:]
		if !drop[i] {
			continue
		}
		k := bytes.Index(rest, esn)
		if k < 0 {
			return nil, fmt.Errorf("cdx16: ikev2TransformTypes object %d has no esn field", i)
		}
		before, after := rest[:k], rest[k+len(esn):]
		switch {
		case len(before) > 0 && before[len(before)-1] == ',':
			before = before[:len(before)-1]
		case len(after) > 0 && after[0] == ',':
			after = after[1:]
		}
		out = append(out, before...)
		rest = after
	}
}

// ── metadata ────────────────────────────────────────────────────────────────

func buildMetadata(meta model.Meta) *cdx.Metadata {
	md := &cdx.Metadata{
		Timestamp: bomTimestamp(meta),
	}

	// Lifecycle: map our two values to the CycloneDX enum.
	switch meta.Lifecycle {
	case "operations":
		md.Lifecycles = &[]cdx.Lifecycle{{Phase: cdx.LifecyclePhaseOperations}}
	case "discovery":
		md.Lifecycles = &[]cdx.Lifecycle{{Phase: cdx.LifecyclePhaseDiscovery}}
	}

	// Tool is represented as a component (the preferred form in 1.5+).
	// ToolsChoice uses custom JSON marshaling; setting Components is correct.
	if meta.ToolVersion != "" {
		md.Tools = &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "cbom-netscan",
				Version: meta.ToolVersion,
			}},
		}
	}

	md.Properties = buildProperties(meta.Properties)
	return md
}

// ── components + dependencies ────────────────────────────────────────────────

func buildComponents(assets []*model.Asset) ([]cdx.Component, []cdx.Dependency) {
	components := make([]cdx.Component, 0, len(assets))
	var deps []cdx.Dependency

	for _, a := range assets {
		c := cdx.Component{
			BOMRef: a.ID,
			Type:   cdx.ComponentTypeCryptographicAsset,
			Name:   a.Name,
		}

		c.CryptoProperties = buildCryptoProps(a)
		c.Evidence = buildEvidence(a.Evidence)
		c.Properties = buildProperties(withCertProps(a))

		components = append(components, c)

		// Usage edges become CycloneDX dependencies[].
		// Dependency.Ref and Dependencies are plain strings (not BOMReference).
		if len(a.DependsOn) > 0 {
			refs := make([]string, len(a.DependsOn))
			for i, ref := range a.DependsOn {
				refs[i] = ref
			}
			deps = append(deps, cdx.Dependency{
				Ref:          a.ID,
				Dependencies: &refs,
			})
		}
	}

	sort.SliceStable(components, func(i, j int) bool {
		a, b := components[i], components[j]
		if ra, rb := assetTypeRank(a), assetTypeRank(b); ra != rb {
			return ra < rb
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.BOMRef < b.BOMRef
	})

	return components, deps
}

// assetTypeRank orders components by asset type for output.
func assetTypeRank(c cdx.Component) int {
	if c.CryptoProperties == nil {
		return 4
	}
	switch c.CryptoProperties.AssetType {
	case cdx.CryptoAssetTypeProtocol:
		return 0
	case cdx.CryptoAssetTypeAlgorithm:
		return 1
	case cdx.CryptoAssetTypeCertificate:
		return 2
	case cdx.CryptoAssetTypeRelatedCryptoMaterial:
		return 3
	}
	return 4
}

// buildCryptoProps maps a model.Asset to CycloneDX CryptoProperties.
func buildCryptoProps(a *model.Asset) *cdx.CryptoProperties {
	cp := &cdx.CryptoProperties{
		OID: a.OID,
	}

	switch a.Type {
	case model.AssetTypeAlgorithm:
		cp.AssetType = cdx.CryptoAssetTypeAlgorithm
		if a.Alg != nil {
			cp.AlgorithmProperties = buildAlgProps(a.Alg)
		}

	case model.AssetTypeCertificate:
		cp.AssetType = cdx.CryptoAssetTypeCertificate
		if a.Cert != nil {
			cp.CertificateProperties = buildCertProps(a.Cert)
		}

	case model.AssetTypeProtocol:
		cp.AssetType = cdx.CryptoAssetTypeProtocol
		if a.Proto != nil {
			cp.ProtocolProperties = buildProtoProps(a.Proto)
		}

	case model.AssetTypeRelatedMaterial:
		cp.AssetType = cdx.CryptoAssetTypeRelatedCryptoMaterial
		if a.Mat != nil {
			cp.RelatedCryptoMaterialProperties = buildMatProps(a.Mat)
		}
	}

	return cp
}

// buildAlgProps maps model.Algorithm → cdx.CryptoAlgorithmProperties.
func buildAlgProps(alg *model.Algorithm) *cdx.CryptoAlgorithmProperties {
	p := &cdx.CryptoAlgorithmProperties{
		Primitive:                cdx.CryptoPrimitive(alg.Primitive),
		ParameterSetIdentifier:   alg.ParameterSetIdentifier,
		Curve:                    alg.Curve,
		Mode:                     cdx.CryptoAlgorithmMode(alg.Mode),
		Padding:                  cdx.CryptoPadding(alg.Padding),
		ExecutionEnvironment:     cdx.CryptoExecutionEnvironment(alg.ExecutionEnvironment),
		ImplementationPlatform:   cdx.ImplementationPlatform(alg.ImplementationPlatform),
		ClassicalSecurityLevel:   alg.ClassicalSecurityLevel,
		NistQuantumSecurityLevel: alg.NISTQuantumLevel,
	}

	if len(alg.CryptoFunctions) > 0 {
		funcs := make([]cdx.CryptoFunction, len(alg.CryptoFunctions))
		for i, f := range alg.CryptoFunctions {
			funcs[i] = cdx.CryptoFunction(f)
		}
		p.CryptoFunctions = &funcs
	}

	return p
}

// buildCertProps maps model.Cert → cdx.CertificateProperties.
// In 1.6, fingerprint and serialNumber are not direct fields; they are
// emitted as properties on the component (see buildProperties).
func buildCertProps(cert *model.Cert) *cdx.CertificateProperties {
	p := &cdx.CertificateProperties{
		SubjectName:          cert.SubjectName,
		IssuerName:           cert.IssuerName,
		CertificateFormat:    cert.Format,
		CertificateExtension: cert.Extension,
	}

	if cert.NotValidBefore != nil {
		s := cert.NotValidBefore.UTC().Format(time.RFC3339)
		p.NotValidBefore = s
	}
	if cert.NotValidAfter != nil {
		s := cert.NotValidAfter.UTC().Format(time.RFC3339)
		p.NotValidAfter = s
	}
	if cert.SignatureAlgorithmRef != "" {
		p.SignatureAlgorithmRef = cdx.BOMReference(cert.SignatureAlgorithmRef)
	}
	if cert.SubjectPublicKeyRef != "" {
		p.SubjectPublicKeyRef = cdx.BOMReference(cert.SubjectPublicKeyRef)
	}

	return p
}

// withCertProps returns a's properties plus the certificate fields CycloneDX
// 1.6 has no slot for: the fingerprint and serial number go out as
// cbom-netscan:cert:sha256 and cbom-netscan:cert:serial (see model.Cert).
func withCertProps(a *model.Asset) map[string]string {
	if a.Cert == nil || (a.Cert.SHA256 == "" && a.Cert.Serial == "") {
		return a.Properties
	}
	m := make(map[string]string, len(a.Properties)+2)
	for k, v := range a.Properties {
		m[k] = v
	}
	if a.Cert.SHA256 != "" {
		m["cbom-netscan:cert:sha256"] = a.Cert.SHA256
	}
	if a.Cert.Serial != "" {
		m["cbom-netscan:cert:serial"] = a.Cert.Serial
	}
	return m
}

// buildProtoProps maps model.Protocol → cdx.CryptoProtocolProperties.
func buildProtoProps(proto *model.Protocol) *cdx.CryptoProtocolProperties {
	p := &cdx.CryptoProtocolProperties{
		Type:    cdx.CryptoProtocolType(proto.Type),
		Version: proto.Version,
	}

	if len(proto.CipherSuites) > 0 {
		suites := make([]cdx.CipherSuite, len(proto.CipherSuites))
		for i, cs := range proto.CipherSuites {
			suites[i] = buildCipherSuite(cs)
		}
		p.CipherSuites = &suites
	}

	// IKEv2 transform types are bom-ref arrays.
	if len(proto.IKEEncr)+len(proto.IKEPRF)+len(proto.IKEInteg)+len(proto.IKEKE)+len(proto.IKEAuth) > 0 {
		p.IKEv2TransformTypes = buildIKEv2(proto)
	}

	// ESN: only emit when explicitly known (not nil).
	// IKEv2TransformTypes.ESN is bool (not *bool); a property
	// "cbom-netscan:ike:esn-unknown=true" should be added by the collector
	// when ESN is truly unknown so it isn't confused with false.
	if proto.ESN != nil {
		p.IKEv2TransformTypes = ensureIKEv2(p.IKEv2TransformTypes)
		p.IKEv2TransformTypes.ESN = *proto.ESN
	}

	// TLS groups and IKEv1 algorithms go in cryptoRefArray in 1.6.
	if len(proto.Refs) > 0 {
		refs := make([]cdx.BOMReference, len(proto.Refs))
		for i, r := range proto.Refs {
			refs[i] = cdx.BOMReference(r)
		}
		p.CryptoRefArray = &refs
	}

	return p
}

func buildCipherSuite(cs model.CipherSuite) cdx.CipherSuite {
	s := cdx.CipherSuite{Name: cs.Name}
	if len(cs.Identifiers) > 0 {
		s.Identifiers = &cs.Identifiers
	}
	if len(cs.AlgRefs) > 0 {
		refs := make([]cdx.BOMReference, len(cs.AlgRefs))
		for i, r := range cs.AlgRefs {
			refs[i] = cdx.BOMReference(r)
		}
		s.Algorithms = &refs
	}
	return s
}

func buildIKEv2(proto *model.Protocol) *cdx.IKEv2TransformTypes {
	t := &cdx.IKEv2TransformTypes{}
	if len(proto.IKEEncr) > 0 {
		refs := make([]cdx.IKEv2Enc, len(proto.IKEEncr))
		for i, id := range proto.IKEEncr {
			refs[i] = cdx.IKEv2Enc{BOMRef: cdx.BOMReference(id)}
		}
		t.Encr = &refs
	}
	if len(proto.IKEPRF) > 0 {
		refs := make([]cdx.IKEv2Prf, len(proto.IKEPRF))
		for i, id := range proto.IKEPRF {
			refs[i] = cdx.IKEv2Prf{BOMRef: cdx.BOMReference(id)}
		}
		t.PRF = &refs
	}
	if len(proto.IKEInteg) > 0 {
		refs := make([]cdx.IKEv2Integ, len(proto.IKEInteg))
		for i, id := range proto.IKEInteg {
			refs[i] = cdx.IKEv2Integ{BOMRef: cdx.BOMReference(id)}
		}
		t.Integ = &refs
	}
	if len(proto.IKEKE) > 0 {
		refs := make([]cdx.IKEv2Ke, len(proto.IKEKE))
		for i, id := range proto.IKEKE {
			refs[i] = cdx.IKEv2Ke{BOMRef: cdx.BOMReference(id)}
		}
		t.KE = &refs
	}
	if len(proto.IKEAuth) > 0 {
		refs := make([]cdx.IKEv2Auth, len(proto.IKEAuth))
		for i, id := range proto.IKEAuth {
			refs[i] = cdx.IKEv2Auth{BOMRef: cdx.BOMReference(id)}
		}
		t.Auth = &refs
	}
	return t
}

func ensureIKEv2(t *cdx.IKEv2TransformTypes) *cdx.IKEv2TransformTypes {
	if t == nil {
		return &cdx.IKEv2TransformTypes{}
	}
	return t
}

// buildMatProps maps model.Material → cdx.RelatedCryptoMaterialProperties.
func buildMatProps(mat *model.Material) *cdx.RelatedCryptoMaterialProperties {
	p := &cdx.RelatedCryptoMaterialProperties{
		Type:         cdx.RelatedCryptoMaterialType(mat.Type),
		ID:           mat.ID,
		State:        cdx.CryptoKeyState(mat.State),
		AlgorithmRef: cdx.BOMReference(mat.AlgorithmRef),
		Format:       mat.Format,
		Size:         mat.Size,
	}
	if mat.ActivationDate != nil {
		s := mat.ActivationDate.UTC().Format(time.RFC3339)
		p.ActivationDate = s
	}
	if mat.ExpirationDate != nil {
		s := mat.ExpirationDate.UTC().Format(time.RFC3339)
		p.ExpirationDate = s
	}
	// CreationDate deliberately omitted: often unavailable offline and must
	// not be confused with cert.NotBefore (see §5.2 notes).
	return p
}

// ── evidence ─────────────────────────────────────────────────────────────────

func buildEvidence(evs []model.Evidence) *cdx.Evidence {
	if len(evs) == 0 {
		return nil
	}
	occs := make([]cdx.EvidenceOccurrence, 0, len(evs))
	for _, ev := range evs {
		if ev.Location == "" {
			continue
		}
		occ := cdx.EvidenceOccurrence{
			Location:          ev.Location,
			Symbol:            ev.Symbol,
			AdditionalContext: ev.Context,
		}
		if ev.Line > 0 {
			line := ev.Line
			occ.Line = &line
		}
		occs = append(occs, occ)
	}
	if len(occs) == 0 {
		return nil
	}
	return &cdx.Evidence{Occurrences: &occs}
}

// ── properties ───────────────────────────────────────────────────────────────

// buildProperties converts the asset's property map to a sorted cdx.Property
// slice.  Sorting by name makes diffs stable.
func buildProperties(m map[string]string) *[]cdx.Property {
	if len(m) == 0 {
		return nil
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	props := make([]cdx.Property, len(keys))
	for i, k := range keys {
		props[i] = cdx.Property{Name: k, Value: m[k]}
	}
	return &props
}

// ── timestamp & serial ───────────────────────────────────────────────────────

// bomTimestamp returns meta.Created, nothing when OmitTimestamp is set, or
// the current time.
func bomTimestamp(meta model.Meta) string {
	switch {
	case !meta.Created.IsZero():
		return meta.Created.UTC().Format(time.RFC3339)
	case meta.OmitTimestamp:
		return ""
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// bomSerial returns meta.SerialNumber, or a random UUIDv4 URN, which is what
// CycloneDX expects: every BOM, even of the same input, gets a new serial.
func bomSerial(meta model.Meta) string {
	if meta.SerialNumber != "" {
		return meta.SerialNumber
	}
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic(fmt.Sprintf("cbom-netscan: crypto/rand failed: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 9562 variant
	return uuidURN(b)
}

// serialNamespace is the UUIDv5 namespace for reproducible serial numbers.
// It was generated once at random for this project and must never change,
// or every reproducible serial would change with it.
var serialNamespace = [16]byte{
	0x96, 0x03, 0x81, 0xc8, 0xef, 0xa9, 0x46, 0x27,
	0xaf, 0x02, 0x76, 0x5c, 0x8f, 0x7e, 0xe1, 0xe7,
} // 960381c8-efa9-4627-af02-765c8f7ee1e7

// ReproducibleSerial returns a UUIDv5 URN (RFC 9562 §5.5) derived from the
// SHA-256 of the input and the tool version, so the same input processed by
// the same release always gets the same serial, and any change to either
// gives a new one.
func ReproducibleSerial(inputSHA256 [32]byte, toolVersion string) string {
	h := sha1.New() // UUIDv5 is defined over SHA-1; this is an identifier, not a security use.
	h.Write(serialNamespace[:])
	fmt.Fprintf(h, "sha256=%s;tool-version=%s", hex.EncodeToString(inputSHA256[:]), toolVersion)
	var b [16]byte
	copy(b[:], h.Sum(nil))
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 9562 variant
	return uuidURN(b)
}

func uuidURN(b [16]byte) string {
	s := hex.EncodeToString(b[:])
	return "urn:uuid:" + s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
