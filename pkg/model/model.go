// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package model defines the vendor-neutral crypto inventory that all
// collectors populate and all emitters consume.  Field names mirror
// CycloneDX 1.6 so the emitter is a near-1:1 mapping, and the types are
// forward-compatible with 1.7 (e.g. Cert.SHA256 → property in 1.6,
// certificateProperties.fingerprint in 1.7).
package model

import "time"

// AssetType values equal the CycloneDX cryptoProperties.assetType enum.
type AssetType string

const (
	AssetTypeAlgorithm       AssetType = "algorithm"
	AssetTypeCertificate     AssetType = "certificate"
	AssetTypeProtocol        AssetType = "protocol"
	AssetTypeRelatedMaterial AssetType = "related-crypto-material"
)

// Evidence records where in a source file or live scan a crypto asset was
// found.  Context must never hold a secret value.
type Evidence struct {
	Location string // file path (absolute or repo-relative) or "host:port"
	Line     int    // 0 if unknown or not applicable
	Symbol   string // e.g. "vpn ipsec phase1-interface/to-dr/proposal"
	Context  string // surrounding text — NEVER a secret
}

// Algorithm carries the algorithm-specific fields that feed
// cryptoProperties.algorithmProperties in CycloneDX.
type Algorithm struct {
	// Primitive values: drbg|mac|block-cipher|stream-cipher|signature|hash|
	// pke|xof|kdf|key-agree|kem|ae|combiner|key-wrap|other|unknown
	Primitive string

	ParameterSetIdentifier string // "128", "768", "1024"
	Curve                  string // "secp256r1", "x25519"

	// Mode values: cbc|ecb|ccm|gcm|cfb|ofb|ctr|other|unknown.
	// Omit for non-block primitives; don't set "unknown" where it doesn't apply.
	Mode string

	Padding string // pkcs5|pkcs7|oaep|pss|other|unknown

	// CryptoFunctions values: generate|keygen|encrypt|decrypt|digest|tag|
	// keyderive|sign|verify|encapsulate|decapsulate|other|unknown
	CryptoFunctions []string

	ClassicalSecurityLevel *int // bits; nil if unknown
	NISTQuantumLevel       *int // 0..6; nil if not applicable

	ExecutionEnvironment   string // "software-plain-ram"; empty if unknown
	ImplementationPlatform string
}

// CipherSuite corresponds to protocolProperties.cipherSuites[].
type CipherSuite struct {
	Name        string   // IANA name, e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	AlgRefs     []string // bom-refs of algorithm assets
	Identifiers []string // IANA byte pair representation, e.g. ["0xC0","0x2F"]
	// Groups holds bom-refs of key-exchange group assets.
	// In 1.6 these go into cryptoRefArray + properties.
	// In 1.7 they become cipherSuite.tlsGroups.
	Groups []string
}

// Protocol carries the fields for protocolProperties in CycloneDX.
type Protocol struct {
	// Type values: tls|ssh|ipsec|ike|sstp|wpa|other|unknown
	Type    string
	Version string // "1.2", "1.3", "2"

	CipherSuites []CipherSuite

	// IKEv2 transform type asset IDs (bom-refs).
	IKEEncr []string
	IKEPRF  []string
	IKEInteg []string
	IKEKE   []string
	IKEAuth []string

	// ESN is nil when unknown (emitter omits the field rather than defaulting to false).
	ESN *bool

	// Refs holds bom-refs for cryptoRefArray: IKEv1 algorithms and TLS
	// key-exchange groups (the 1.6 representation of groups).
	Refs []string
}

// Cert carries the fields for certificateProperties in CycloneDX 1.6.
// In 1.7, SHA256 moves to fingerprint and Serial to serialNumber.
type Cert struct {
	SubjectName string
	IssuerName  string

	NotValidBefore *time.Time
	NotValidAfter  *time.Time

	// Refs to algorithm assets (emitter resolves to bom-refs).
	SignatureAlgorithmRef string
	SubjectPublicKeyRef   string

	Format    string // "X.509"
	Extension string // schema title: "Certificate File Extension" — "pem", "crt"

	SHA256 string // hex; → property cbom-netscan:cert:sha256 in 1.6
	Serial string // → property cbom-netscan:cert:serial in 1.6
}

// Material carries the fields for relatedCryptoMaterialProperties.
// There is deliberately NO Value field: cbom-netscan never stores key or
// secret material, even though CycloneDX 1.6 defines the field.
type Material struct {
	// Type values: public-key|private-key|secret-key|password|shared-secret|
	// blinded-secret-key|private-key-signing-key|other|unknown
	Type string

	// ID is a non-secret identifier (e.g. SHA-256 of SubjectPublicKeyInfo).
	// Never hash a PSK or password.
	ID string

	// State values: pre-activation|active|suspended|deactivated|compromised|destroyed.
	// Note: CycloneDX 1.6 has no "revoked" or "expired" state.  Expired keys
	// stay "active" and get a property cbom-netscan:key:expired=true.
	State string

	AlgorithmRef string // bom-ref of the algorithm asset
	Size         *int   // bits; nil for secret keys (size would require reading the value)
	Format       string

	CreationDate   *time.Time // often unavailable offline
	ActivationDate *time.Time // for keys in a cert: notBefore
	ExpirationDate *time.Time // for keys in a cert: notAfter
}

// Asset is one entry in the CBOM.  ID becomes the CycloneDX bom-ref and is
// computed deterministically with BOMRef().
type Asset struct {
	ID   string    // deterministic bom-ref; set by BOMRef()
	Type AssetType
	Name string
	OID  string // dotted OID string; empty if none assigned

	// Exactly one of Alg/Proto/Cert/Mat is non-nil, matching Type.
	Alg   *Algorithm
	Proto *Protocol
	Cert  *Cert
	Mat   *Material

	Evidence []Evidence

	// Properties keys follow the pattern "cbom-netscan:<area>:<key>".
	Properties map[string]string

	// DependsOn holds bom-refs of assets this one depends on (usage edges).
	// Maps to CycloneDX dependencies[].
	DependsOn []string
}

// Inventory is the in-memory CBOM being built.  Use NewInventory() to
// create one; the zero value has a nil dedupe map and panics on Add().
type Inventory struct {
	Assets   []*Asset
	Warnings []Warning
	Sources  []Source

	// byKey deduplicates on (Type, Name, OID).  Unexported so callers
	// must go through Add(); the emitter reads only Assets.
	byKey map[string]*Asset
}

// Meta holds BOM-level metadata passed to every Emitter.
type Meta struct {
	ToolVersion string
	// Lifecycle is the CycloneDX metadata.lifecycles phase.
	// Use "operations" for production configs, "discovery" for scan results.
	Lifecycle string
	// Created is used as the BOM timestamp.  If zero, the emitter falls back
	// to SOURCE_DATE_EPOCH (for reproducible builds) or time.Now().
	Created time.Time
}
