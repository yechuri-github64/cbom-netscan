// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package cdx16 emits a model.Inventory as a CycloneDX 1.6 JSON CBOM
// using the official cyclonedx-go library.
//
// Design decisions:
//
//   - Output is deterministic when SOURCE_DATE_EPOCH is set: the BOM serial
//     number and timestamp are both derived from that value, so two runs on
//     the same inventory produce byte-identical output.
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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
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
// If meta.Created is zero, the timestamp comes from the SOURCE_DATE_EPOCH
// environment variable (if set) or time.Now().  The same epoch also drives
// the BOM serial number so that builds are reproducible.
func (Emitter) Emit(_ context.Context, w io.Writer, inv *model.Inventory, meta model.Meta) error {
	bom := cdx.NewBOM()
	// Pin to 1.6 before Encode so the $schema field is correct and the
	// encoder writes the right specVersion without going through
	// copyAndConvert (which would silently downgrade cryptographic-asset).
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.JSONSchema = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	bom.SerialNumber = bomSerial()
	bom.Metadata = buildMetadata(meta)

	components, deps := buildComponents(inv.Assets)
	bom.Components = &components
	if len(deps) > 0 {
		bom.Dependencies = &deps
	}

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

// ── metadata ────────────────────────────────────────────────────────────────

func buildMetadata(meta model.Meta) *cdx.Metadata {
	md := &cdx.Metadata{
		Timestamp: bomTimestamp(meta.Created),
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
		c.Properties = buildProperties(a.Properties)

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

// bomTimestamp returns an RFC 3339 timestamp.  Priority:
//  1. meta.Created (if non-zero)
//  2. SOURCE_DATE_EPOCH env var (for reproducible builds)
//  3. time.Now()
func bomTimestamp(created time.Time) string {
	if !created.IsZero() {
		return created.UTC().Format(time.RFC3339)
	}
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if epoch, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(epoch, 0).UTC().Format(time.RFC3339)
		}
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// bomSerial returns a "urn:uuid:…" serial number.
// When SOURCE_DATE_EPOCH is set, the UUID is deterministic (derived from the
// epoch via SHA-256) so two runs produce the same serial.
// Otherwise a random UUID v4 is used.
func bomSerial() string {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if epoch, err := strconv.ParseInt(v, 10, 64); err == nil {
			h := sha256.Sum256([]byte(fmt.Sprintf("cbom-netscan:serial:%d", epoch)))
			return uuidFromBytes(h[:16])
		}
	}

	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic(fmt.Sprintf("cbom-netscan: crypto/rand failed: %v", err))
	}
	return uuidFromBytes(b[:])
}

// uuidFromBytes formats 16 bytes as a RFC 4122 UUID v4 string.
func uuidFromBytes(b []byte) string {
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	s := hex.EncodeToString(b[:16])
	return "urn:uuid:" + s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
