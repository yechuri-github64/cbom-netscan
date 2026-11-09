// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package algo holds algorithm rules shared by the FortiOS extractors.
package algo

import (
	"strconv"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// Complete fills the algorithm fields every extractor must set the same way,
// so a shared component (AES-256-GCM in SSH and IPsec) merges without a
// conflict: nistQuantumSecurityLevel, classicalSecurityLevel, and
// cryptoFunctions. A value already set is kept (ML-KEM's NIST level, NULL's
// classical 0).
func Complete(name string, a *model.Algorithm) {
	if a == nil {
		return
	}
	MarkQuantumVulnerable(a)
	if a.ClassicalSecurityLevel == nil {
		if n, ok := classicalLevel(name, a); ok {
			v := n
			a.ClassicalSecurityLevel = &v
		}
	}
	if len(a.CryptoFunctions) == 0 {
		a.CryptoFunctions = functions(a.Primitive)
	}
}

// MarkQuantumVulnerable sets nistQuantumSecurityLevel to 0 on classical
// public-key algorithms (key agreement, signatures, and public-key
// encryption such as RSA certificate keys), which a quantum computer breaks.
// CycloneDX 1.6 defines 0 as "none of the categories are met", so
// post-quantum readiness does not depend on a consumer's heuristic.
//
// A level that is already set (ML-KEM) is kept. Symmetric algorithms,
// combiners, and PQC schemes that are not NIST standards are left unset,
// because their category is not a plain fact the tool can state.
func MarkQuantumVulnerable(a *model.Algorithm) {
	if a.NISTQuantumLevel != nil {
		return
	}
	switch a.Primitive {
	case "key-agree", "signature", "pke":
		zero := 0
		a.NISTQuantumLevel = &zero
	}
}

// functions is the CycloneDX cryptoFunctions list for a primitive, by the
// algorithm's role (MAPPING.md §8.5). Combiners, "other", and "unknown"
// have none: a combiner's parts carry the functions.
func functions(primitive string) []string {
	switch primitive {
	case "block-cipher", "ae", "stream-cipher":
		return []string{"encrypt", "decrypt"}
	case "mac":
		return []string{"tag"}
	case "kdf":
		return []string{"keyderive"}
	case "hash":
		return []string{"digest"}
	case "signature":
		return []string{"sign", "verify"}
	case "pke":
		return []string{"encrypt", "decrypt", "sign", "verify"}
	case "key-agree":
		return []string{"keyderive"}
	case "kem":
		return []string{"encapsulate", "decapsulate"}
	}
	return nil
}

// classicalLevel is bits of classical security, from NIST SP 800-57 Part 1
// Rev. 5 Table 2 where that table has a row, and from the algorithm's
// well-known strength otherwise. Combiners and NIST KEMs are left unset:
// a combiner's level is not a single Table 2 number (MAPPING.md §8.5).
func classicalLevel(name string, a *model.Algorithm) (int, bool) {
	if n, ok := classicalByName[name]; ok {
		return n, true
	}
	if a.ParameterSetIdentifier != "" {
		if bits, err := strconv.Atoi(a.ParameterSetIdentifier); err == nil && bits > 0 {
			switch a.Primitive {
			case "ae", "block-cipher", "stream-cipher":
				return bits, true
			case "pke", "signature", "key-agree":
				return finiteFieldLevel(bits), true
			}
		}
	}
	if n, ok := curveLevel[a.Curve]; ok {
		return n, true
	}
	return 0, false
}

// classicalByName covers algorithms whose strength is not in ParameterSetIdentifier
// or Curve (3DES, HMAC, ChaCha20, NULL).
var classicalByName = map[string]int{
	"NULL": 0, "NULL-MAC": 0,
	"DES-CBC": 56, "3DES-CBC": 112,
	"SM4": 128, "SEED": 128, "Blowfish-CBC": 128, "CAST-128-CBC": 128,
	"HMAC-MD5": 64, "HMAC-MD5-96": 64,
	"HMAC-SHA1": 80, "PRF-HMAC-SHA1": 80, "PRF-HMAC-MD5": 64,
	"HMAC-SHA256": 128, "PRF-HMAC-SHA256": 128, "HMAC-SM3": 128, "PRF-HMAC-SM3": 128,
	"HMAC-SHA384": 192, "PRF-HMAC-SHA384": 192,
	"HMAC-SHA512": 256, "PRF-HMAC-SHA512": 256,
	"HMAC-RIPEMD160": 80,
	"UMAC-64":        64, "UMAC-128": 128,
	"ChaCha20-Poly1305": 256, "ChaCha20-Poly1305 (OpenSSH)": 256,
	"RC4": 128, "RC4-128-drop1536": 128, "RC4-256-drop1536": 256,
	"ARIA-128": 128, "ARIA-192": 192, "ARIA-256": 256,
}

// finiteFieldLevel maps an RSA/DSA/MODP/FFDHE modulus size onto Table 2.
// Sizes between rows use the weaker row (4096-bit RSA is 128, not 192).
func finiteFieldLevel(bits int) int {
	switch {
	case bits >= 15360:
		return 256
	case bits >= 7680:
		return 192
	case bits >= 3072:
		return 128
	case bits >= 2048:
		return 112
	case bits >= 1024:
		return 80
	default:
		return 0
	}
}

// curveLevel is Table 2 ECC rows, plus X25519/Ed25519 (128) and
// X448/Ed448 (224, RFC 7748 / RFC 8032; not a Table 2 row).
var curveLevel = map[string]int{
	"secp224r1": 112, "brainpoolP224r1": 112,
	"secp256r1": 128, "x25519": 128, "ed25519": 128, "brainpoolP256r1": 128,
	"secp384r1": 192, "brainpoolP384r1": 192,
	"secp521r1": 256, "brainpoolP512r1": 256,
	"x448": 224, "ed448": 224,
}

// OID returns a dotted OID for a named algorithm when one is assigned
// (NIST CSOR, PKCS #1, RFC 8410). Empty if none: MODP groups and
// Fortinet-private KEMs have no OID to give.
func OID(name string) string {
	if oid, ok := oids[name]; ok {
		return oid
	}
	if strings.HasPrefix(name, "RSA-") {
		return oidRSAEncryption
	}
	return ""
}

const oidRSAEncryption = "1.2.840.113549.1.1.1"

// oids are well-known algorithm OIDs. Certificate extractors prefer the OID
// from the certificate's ASN.1; this table fills IPsec, SSH, and TLS groups.
var oids = map[string]string{
	"AES-128-CBC": "2.16.840.1.101.3.4.1.2",
	"AES-192-CBC": "2.16.840.1.101.3.4.1.22",
	"AES-256-CBC": "2.16.840.1.101.3.4.1.42",
	"AES-128-GCM": "2.16.840.1.101.3.4.1.6",
	"AES-192-GCM": "2.16.840.1.101.3.4.1.26",
	"AES-256-GCM": "2.16.840.1.101.3.4.1.46",
	"AES-128-CTR": "2.16.840.1.101.3.4.1.9",
	"AES-192-CTR": "2.16.840.1.101.3.4.1.29",
	"AES-256-CTR": "2.16.840.1.101.3.4.1.49",
	"3DES-CBC":    "1.2.840.113549.3.7",
	"HMAC-SHA1":   "1.2.840.113549.2.7",
	"HMAC-SHA256": "1.2.840.113549.2.9",
	"HMAC-SHA384": "1.2.840.113549.2.10",
	"HMAC-SHA512": "1.2.840.113549.2.11",
	"HMAC-MD5":    "1.2.840.113549.2.6",
	"ML-KEM-512":  "2.16.840.1.101.3.4.4.1",
	"ML-KEM-768":  "2.16.840.1.101.3.4.4.2",
	"ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
	"X25519":      "1.3.101.110",
	"X448":        "1.3.101.111",
	"Ed25519":     "1.3.101.112",
	"Ed448":       "1.3.101.113",
	"ECP-256":     "1.2.840.10045.3.1.7",
	"ECP-384":     "1.3.132.0.34",
	"ECP-521":     "1.3.132.0.35",
	"SHA1-RSA":    "1.2.840.113549.1.1.5",
	"SHA256-RSA":  "1.2.840.113549.1.1.11",
	"SHA384-RSA":  "1.2.840.113549.1.1.12",
	"SHA512-RSA":  "1.2.840.113549.1.1.13",
}
