// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package ipsec

import (
	"regexp"
	"strconv"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/field"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// Option sets come from research notes §3.3-3.4 and the CLI HTML pages
// recorded there. The phase1 proposal list is the research notes' set
// notation expanded; the phase2 list is the verified 7.6.7 list plus the
// 8.0.1-only sm4-sm3.

var (
	p1Ciphers = []string{"des", "3des", "aes128", "aes192", "aes256", "aria128", "aria192", "aria256", "seed"}
	p1Hashes  = []string{"md5", "sha1", "sha256", "sha384", "sha512"}
	aeads     = []string{"aes128gcm", "aes256gcm", "chacha20poly1305"}
	prfs      = []string{"prfsha1", "prfsha256", "prfsha384", "prfsha512"}

	p2Ciphers = []string{"des", "3des", "aes128", "aes192", "aes256", "aria128", "aria192", "aria256", "seed"}
	p2Hashes  = []string{"null", "md5", "sha1", "sha256", "sha384", "sha512"}
)

func phase1Proposals() map[string]bool {
	m := map[string]bool{"sm4-sm3": true}
	for _, c := range p1Ciphers {
		for _, h := range p1Hashes {
			m[c+"-"+h] = true
		}
	}
	for _, a := range aeads {
		for _, p := range prfs {
			m[a+"-"+p] = true
		}
	}
	return m
}

func phase2Proposals() map[string]bool {
	m := map[string]bool{"sm4-sm3": true}
	for _, h := range p2Hashes {
		if h != "null" {
			m["null-"+h] = true // there is no null-null
		}
	}
	for _, c := range p2Ciphers {
		for _, h := range p2Hashes {
			m[c+"-"+h] = true
		}
	}
	for _, a := range aeads {
		m[a] = true
	}
	return m
}

var (
	proposalRE = regexp.MustCompile(`^[a-z0-9]{2,24}(-[a-z0-9]{2,12})?$`)

	specIKEVersion = field.Spec{Known: set("1", "2")}
	specP1Proposal = field.Spec{Known: phase1Proposals(), Pattern: proposalRE}
	specP2Proposal = field.Spec{Known: phase2Proposals(), Pattern: proposalRE}
	specDHGroup    = field.Spec{Known: keys(dhGroups), Pattern: regexp.MustCompile(`^[0-9]{1,4}$`)}
	specAuth       = field.Spec{Known: set("psk", "signature")}
	specSigHash    = field.Spec{Known: set("sha1", "sha2-256", "sha2-384", "sha2-512", "identity")}
	specPFS        = field.Spec{Known: set("enable", "disable")}
	specAddke      = field.Spec{Known: addkeKnown(), Pattern: regexp.MustCompile(`^[a-z0-9-]{1,20}$`)}
	specCertName   = field.Spec{Pattern: regexp.MustCompile(`^[A-Za-z0-9 _.@-]{1,79}$`), Freeform: true}
)

// alg is a named algorithm component.
type alg struct {
	name string
	a    model.Algorithm
}

var ciphers = map[string]alg{
	"des":              {"DES-CBC", model.Algorithm{Primitive: "block-cipher", Mode: "cbc"}},
	"3des":             {"3DES-CBC", model.Algorithm{Primitive: "block-cipher", Mode: "cbc"}},
	"aes128":           {"AES-128-CBC", model.Algorithm{Primitive: "block-cipher", Mode: "cbc", ParameterSetIdentifier: "128"}},
	"aes192":           {"AES-192-CBC", model.Algorithm{Primitive: "block-cipher", Mode: "cbc", ParameterSetIdentifier: "192"}},
	"aes256":           {"AES-256-CBC", model.Algorithm{Primitive: "block-cipher", Mode: "cbc", ParameterSetIdentifier: "256"}},
	"aria128":          {"ARIA-128", model.Algorithm{Primitive: "block-cipher", ParameterSetIdentifier: "128"}},
	"aria192":          {"ARIA-192", model.Algorithm{Primitive: "block-cipher", ParameterSetIdentifier: "192"}},
	"aria256":          {"ARIA-256", model.Algorithm{Primitive: "block-cipher", ParameterSetIdentifier: "256"}},
	"seed":             {"SEED", model.Algorithm{Primitive: "block-cipher"}},
	"sm4":              {"SM4", model.Algorithm{Primitive: "block-cipher"}},
	"aes128gcm":        {"AES-128-GCM", model.Algorithm{Primitive: "ae", Mode: "gcm", ParameterSetIdentifier: "128"}},
	"aes256gcm":        {"AES-256-GCM", model.Algorithm{Primitive: "ae", Mode: "gcm", ParameterSetIdentifier: "256"}},
	"chacha20poly1305": {"ChaCha20-Poly1305", model.Algorithm{Primitive: "ae"}},
}

// hashes maps a proposal hash to its integrity (HMAC) and PRF algorithms.
// Research notes §7: integrity → mac; PRF → kdf (a mapping choice).
var hashes = map[string]struct{ integ, prf string }{
	"md5":    {"HMAC-MD5", "PRF-HMAC-MD5"},
	"sha1":   {"HMAC-SHA1", "PRF-HMAC-SHA1"},
	"sha256": {"HMAC-SHA256", "PRF-HMAC-SHA256"},
	"sha384": {"HMAC-SHA384", "PRF-HMAC-SHA384"},
	"sha512": {"HMAC-SHA512", "PRF-HMAC-SHA512"},
	"sm3":    {"HMAC-SM3", "PRF-HMAC-SM3"},
}

func macAlg(name string) alg { return alg{name, model.Algorithm{Primitive: "mac"}} }
func prfAlg(name string) alg { return alg{name, model.Algorithm{Primitive: "kdf"}} }

var nist1, nist3, nist5 = 1, 3, 5

func modp(n, bits string) alg {
	return alg{"DH group " + n + " (MODP-" + bits + ")", model.Algorithm{Primitive: "key-agree", ParameterSetIdentifier: bits}}
}

func ecdh(n, label, curve string) alg {
	return alg{"DH group " + n + " (" + label + ")", model.Algorithm{Primitive: "key-agree", Curve: curve}}
}

// dhGroups follows the IANA IKEv2 group registry as listed in research notes
// §3.3 (Fortinet's docs only say "DH Group N").
var dhGroups = map[string]alg{
	"1":  modp("1", "768"),
	"2":  modp("2", "1024"),
	"5":  modp("5", "1536"),
	"14": modp("14", "2048"),
	"15": modp("15", "3072"),
	"16": modp("16", "4096"),
	"17": modp("17", "6144"),
	"18": modp("18", "8192"),
	"19": ecdh("19", "ECP-256", "secp256r1"),
	"20": ecdh("20", "ECP-384", "secp384r1"),
	"21": ecdh("21", "ECP-521", "secp521r1"),
	"27": ecdh("27", "brainpoolP224r1", "brainpoolP224r1"),
	"28": ecdh("28", "brainpoolP256r1", "brainpoolP256r1"),
	"29": ecdh("29", "brainpoolP384r1", "brainpoolP384r1"),
	"30": ecdh("30", "brainpoolP512r1", "brainpoolP512r1"),
	"31": ecdh("31", "Curve25519", "x25519"),
	"32": ecdh("32", "Curve448", "x448"),
}

func kem(name, psi string, level *int) alg {
	return alg{name, model.Algorithm{Primitive: "kem", ParameterSetIdentifier: psi, NISTQuantumLevel: level}}
}

// privateUseFrom is the first IKEv2 transform ID reserved for private use:
// RFC 7296 §3.3.2 reserves 1024-65535 "for private use among mutually
// consenting parties". FortiOS uses 1080-1094 for the Kyber, FrodoKEM, BIKE,
// and HQC key exchanges (research notes §3.3), so those IDs are FortiOS's own,
// not IANA assignments, and their components say so.
const privateUseFrom = 1024

// addkeAlgs maps both addke spellings (numeric up to 7.6.6, named from 7.6.7,
// research notes §3.3 and §8.2) to one algorithm. NIST levels are set only
// for ML-KEM (FIPS 203); the other schemes are not NIST standards.
// Built by a variable initializer, not init(), because specAddke depends
// on it and package variables are initialized before init functions run.
// addkeProps holds per-algorithm properties, keyed by component name.
var addkeAlgs, addkeProps = buildAddke()

func buildAddke() (map[string]alg, map[string]map[string]string) {
	m := map[string]alg{}
	props := map[string]map[string]string{}
	for _, e := range []struct {
		num, named string
		a          alg
	}{
		{"35", "ml-kem-512", kem("ML-KEM-512", "512", &nist1)},
		{"36", "ml-kem-768", kem("ML-KEM-768", "768", &nist3)},
		{"37", "ml-kem-1024", kem("ML-KEM-1024", "1024", &nist5)},
		{"1080", "kyber512", kem("KYBER-512", "512", nil)},
		{"1081", "kyber768", kem("KYBER-768", "768", nil)},
		{"1082", "kyber1024", kem("KYBER-1024", "1024", nil)},
		{"1083", "frodo-l1", kem("FRODO-L1", "L1", nil)},
		{"1084", "frodo-l3", kem("FRODO-L3", "L3", nil)},
		{"1085", "frodo-l5", kem("FRODO-L5", "L5", nil)},
		{"1089", "bike-l1", kem("BIKE-L1", "L1", nil)},
		{"1090", "bike-l3", kem("BIKE-L3", "L3", nil)},
		{"1091", "bike-l5", kem("BIKE-L5", "L5", nil)},
		{"1092", "hqc128", kem("HQC-128", "128", nil)},
		{"1093", "hqc192", kem("HQC-192", "192", nil)},
		{"1094", "hqc256", kem("HQC-256", "256", nil)},
	} {
		if n, _ := strconv.Atoi(e.num); n >= privateUseFrom {
			props[e.a.name] = map[string]string{
				field.Prefix + "ike-transform-id":             e.num,
				field.Prefix + "ike-transform-id:private-use": "true",
			}
		}
		m[e.num] = e.a
		m[e.named] = e.a
	}
	return m, props
}

// addkeNone are the tokens that mean "no additional key exchange".
var addkeNone = set("0", "none")

func addkeKnown() map[string]bool {
	m := keys(addkeAlgs)
	for k := range addkeNone {
		m[k] = true
	}
	return m
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
