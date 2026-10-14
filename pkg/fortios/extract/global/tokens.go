// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package global

import (
	"regexp"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/field"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// Option tokens below are the exact CLI spellings, verified against the
// FortiOS 7.4.12, 7.6.7, and 8.0.0 CLI reference (research notes §3.1-3.2).

var tlsVersions = map[string]string{
	"tlsv1-1": "1.1",
	"tlsv1-2": "1.2",
	"tlsv1-3": "1.3",
}

var tls13Suites = set(
	"TLS-AES-128-GCM-SHA256", "TLS-AES-256-GCM-SHA384", "TLS-CHACHA20-POLY1305-SHA256",
	"TLS-AES-128-CCM-SHA256", "TLS-AES-128-CCM-8-SHA256",
)

var bannedCiphers = set(
	"RSA", "DHE", "ECDHE", "DSS", "ECDSA", "AES", "AESGCM", "CAMELLIA", "3DES",
	"SHA1", "SHA256", "SHA384", "STATIC", "CHACHA20", "ARIA", "AESCCM",
)

var enableDisable = set("enable", "disable")

// SSH algorithm classification. Primitive and mode follow the research notes
// §3.2/§7 mapping. MODP group sizes are from RFC 4253 §8 (group1 = 1024-bit
// Oakley Group 2, group14 = 2048) and RFC 8268 (group16 = 4096, group18 = 8192).
var sshEnc = map[string]model.Algorithm{
	"chacha20-poly1305@openssh.com": {Primitive: "ae"},
	"aes128-ctr":                    {Primitive: "block-cipher", Mode: "ctr", ParameterSetIdentifier: "128"},
	"aes192-ctr":                    {Primitive: "block-cipher", Mode: "ctr", ParameterSetIdentifier: "192"},
	"aes256-ctr":                    {Primitive: "block-cipher", Mode: "ctr", ParameterSetIdentifier: "256"},
	"arcfour256":                    {Primitive: "stream-cipher", ParameterSetIdentifier: "256"},
	"arcfour128":                    {Primitive: "stream-cipher", ParameterSetIdentifier: "128"},
	"arcfour":                       {Primitive: "stream-cipher"},
	"aes128-cbc":                    {Primitive: "block-cipher", Mode: "cbc", ParameterSetIdentifier: "128"},
	"aes192-cbc":                    {Primitive: "block-cipher", Mode: "cbc", ParameterSetIdentifier: "192"},
	"aes256-cbc":                    {Primitive: "block-cipher", Mode: "cbc", ParameterSetIdentifier: "256"},
	"3des-cbc":                      {Primitive: "block-cipher", Mode: "cbc"},
	"blowfish-cbc":                  {Primitive: "block-cipher", Mode: "cbc"},
	"cast128-cbc":                   {Primitive: "block-cipher", Mode: "cbc"},
	"rijndael-cbc@lysator.liu.se":   {Primitive: "block-cipher", Mode: "cbc", ParameterSetIdentifier: "256"},
	"aes128-gcm@openssh.com":        {Primitive: "ae", Mode: "gcm", ParameterSetIdentifier: "128"},
	"aes256-gcm@openssh.com":        {Primitive: "ae", Mode: "gcm", ParameterSetIdentifier: "256"},
}

var nistLevel3 = 3

var sshKex = map[string]model.Algorithm{
	"diffie-hellman-group1-sha1":           {Primitive: "key-agree", ParameterSetIdentifier: "1024"},
	"diffie-hellman-group14-sha1":          {Primitive: "key-agree", ParameterSetIdentifier: "2048"},
	"diffie-hellman-group14-sha256":        {Primitive: "key-agree", ParameterSetIdentifier: "2048"},
	"diffie-hellman-group16-sha512":        {Primitive: "key-agree", ParameterSetIdentifier: "4096"},
	"diffie-hellman-group18-sha512":        {Primitive: "key-agree", ParameterSetIdentifier: "8192"},
	"diffie-hellman-group-exchange-sha1":   {Primitive: "key-agree"},
	"diffie-hellman-group-exchange-sha256": {Primitive: "key-agree"},
	"curve25519-sha256@libssh.org":         {Primitive: "key-agree", Curve: "x25519"},
	"ecdh-sha2-nistp256":                   {Primitive: "key-agree", Curve: "secp256r1"},
	"ecdh-sha2-nistp384":                   {Primitive: "key-agree", Curve: "secp384r1"},
	"ecdh-sha2-nistp521":                   {Primitive: "key-agree", Curve: "secp521r1"},
	// Hybrid ML-KEM-768 + X25519: a combiner whose parts are separate
	// components (research notes §7), see hybridParts.
	"mlkem768x25519-sha256": {Primitive: "combiner"},
}

var hybridProp = map[string]string{
	"mlkem768x25519-sha256": "ML-KEM-768 + X25519",
}

// hybridPart is one algorithm inside a hybrid key exchange.
type hybridPart struct {
	name string
	alg  model.Algorithm
}

// hybridParts lists the algorithms a hybrid key exchange combines. Each part
// is its own component, depended on by the combiner and referenced by the SSH
// protocol, so a policy looking for a post-quantum KEM finds ML-KEM-768 and
// one rejecting classical-only key exchange sees it is not classical-only.
// The ML-KEM-768 name and properties match the IPsec extractor's, so a backup
// using ML-KEM-768 in both SSH and IPsec yields one component.
// ML-KEM-768 is NIST level 3 (FIPS 203).
var hybridParts = map[string][]hybridPart{
	"mlkem768x25519-sha256": {
		{"ML-KEM-768", model.Algorithm{Primitive: "kem", ParameterSetIdentifier: "768", NISTQuantumLevel: &nistLevel3}},
		{"X25519", model.Algorithm{Primitive: "key-agree", Curve: "x25519"}},
	},
}

var sshMac = map[string]model.Algorithm{
	"hmac-md5":                       {Primitive: "mac"},
	"hmac-md5-etm@openssh.com":       {Primitive: "mac"},
	"hmac-md5-96":                    {Primitive: "mac"},
	"hmac-md5-96-etm@openssh.com":    {Primitive: "mac"},
	"hmac-sha1":                      {Primitive: "mac"},
	"hmac-sha1-etm@openssh.com":      {Primitive: "mac"},
	"hmac-sha2-256":                  {Primitive: "mac"},
	"hmac-sha2-256-etm@openssh.com":  {Primitive: "mac"},
	"hmac-sha2-512":                  {Primitive: "mac"},
	"hmac-sha2-512-etm@openssh.com":  {Primitive: "mac"},
	"hmac-ripemd160":                 {Primitive: "mac"},
	"hmac-ripemd160@openssh.com":     {Primitive: "mac"},
	"hmac-ripemd160-etm@openssh.com": {Primitive: "mac"},
	"umac-64@openssh.com":            {Primitive: "mac"},
	"umac-128@openssh.com":           {Primitive: "mac"},
	"umac-64-etm@openssh.com":        {Primitive: "mac"},
	"umac-128-etm@openssh.com":       {Primitive: "mac"},
}

var sshHsk = map[string]model.Algorithm{
	"ssh-rsa":             {Primitive: "signature"},
	"ecdsa-sha2-nistp521": {Primitive: "signature", Curve: "secp521r1"},
	"ecdsa-sha2-nistp384": {Primitive: "signature", Curve: "secp384r1"},
	"ecdsa-sha2-nistp256": {Primitive: "signature", Curve: "secp256r1"},
	"rsa-sha2-256":        {Primitive: "signature"},
	"rsa-sha2-512":        {Primitive: "signature"},
	"ssh-ed25519":         {Primitive: "signature", Curve: "ed25519"},
}

var (
	specTLSVersions = field.Spec{Known: keys(tlsVersions)}
	specTLS13Suites = field.Spec{Known: tls13Suites, Pattern: regexp.MustCompile(`^TLS-[A-Z0-9-]{1,60}$`)}
	specBanned      = field.Spec{Known: bannedCiphers, Pattern: regexp.MustCompile(`^[A-Z0-9]{1,16}$`)}
	specEnableDis   = field.Spec{Known: enableDisable}
	specCertName    = field.Spec{Pattern: regexp.MustCompile(`^[A-Za-z0-9 _.@-]{1,35}$`), Freeform: true}
	sshTokenRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9@._-]{0,63}$`)
)

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

// strongCryptoAllowed lists, per field, what stays enabled when strong-crypto
// is enable (research notes §3.1a, AG "FortiGate encryption algorithm cipher
// suites"). Anything else configured gets a strong-crypto-may-restrict marker.
// mlkem768x25519-sha256 is kept: the 8.0.1 CLI default includes it although
// the AG table omits it (research notes §9).
var strongCryptoAllowed = map[string]map[string]bool{
	"ssh-enc-algo": set("aes256-gcm@openssh.com", "aes256-ctr"),
	"ssh-kex-algo": set("diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512",
		"diffie-hellman-group-exchange-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "mlkem768x25519-sha256"),
	"ssh-mac-algo": set("hmac-sha2-256", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-512-etm@openssh.com"),
	"ssh-hsk-algo": set("ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512", "ssh-ed25519"),
}

// strongCryptoDisabledTLS13 are the admin HTTPS TLS 1.3 suites the AG marks
// "Disabled if strong-crypto enabled" (research notes §3.1a).
var strongCryptoDisabledTLS13 = []string{"TLS-AES-128-CCM-SHA256", "TLS-AES-128-CCM-8-SHA256"}

const strongCryptoReason = "strong-crypto is enable, which disables this per the FortiOS Administration Guide; the CBOM shows the configured set, not the effective one (research notes §3.1a, §8.12)"

// sshCanonical gives SSH cipher and MAC tokens the algorithm name the IPsec
// extractor uses for the same algorithm, so a backup using AES-256-GCM in
// both SSH and IPsec yields one component. The SSH token itself is kept on
// the SSH protocol component (<field>:value).
//
// Key-exchange methods and host-key algorithms keep their SSH names: a method
// such as ecdh-sha2-nistp256 is a curve plus a hash, not the same thing as an
// IKE DH group. chacha20-poly1305@openssh.com is OpenSSH's own construction,
// not the RFC 8439 AEAD that IPsec uses, so it gets a distinct name.
// rijndael-cbc@lysator.liu.se is OpenSSH's alias for aes256-cbc. arcfour128
// and arcfour256 discard the first 1536 bytes of keystream (RFC 4345). The
// -etm variants change how the MAC is applied, not the MAC algorithm.
var sshCanonical = map[string]string{
	"aes128-ctr":                     "AES-128-CTR",
	"aes192-ctr":                     "AES-192-CTR",
	"aes256-ctr":                     "AES-256-CTR",
	"aes128-cbc":                     "AES-128-CBC",
	"aes192-cbc":                     "AES-192-CBC",
	"aes256-cbc":                     "AES-256-CBC",
	"rijndael-cbc@lysator.liu.se":    "AES-256-CBC",
	"aes128-gcm@openssh.com":         "AES-128-GCM",
	"aes256-gcm@openssh.com":         "AES-256-GCM",
	"3des-cbc":                       "3DES-CBC",
	"blowfish-cbc":                   "Blowfish-CBC",
	"cast128-cbc":                    "CAST-128-CBC",
	"arcfour":                        "RC4",
	"arcfour128":                     "RC4-128-drop1536",
	"arcfour256":                     "RC4-256-drop1536",
	"chacha20-poly1305@openssh.com":  "ChaCha20-Poly1305 (OpenSSH)",
	"hmac-md5":                       "HMAC-MD5",
	"hmac-md5-etm@openssh.com":       "HMAC-MD5",
	"hmac-md5-96":                    "HMAC-MD5-96",
	"hmac-md5-96-etm@openssh.com":    "HMAC-MD5-96",
	"hmac-sha1":                      "HMAC-SHA1",
	"hmac-sha1-etm@openssh.com":      "HMAC-SHA1",
	"hmac-sha2-256":                  "HMAC-SHA256",
	"hmac-sha2-256-etm@openssh.com":  "HMAC-SHA256",
	"hmac-sha2-512":                  "HMAC-SHA512",
	"hmac-sha2-512-etm@openssh.com":  "HMAC-SHA512",
	"hmac-ripemd160":                 "HMAC-RIPEMD160",
	"hmac-ripemd160@openssh.com":     "HMAC-RIPEMD160",
	"hmac-ripemd160-etm@openssh.com": "HMAC-RIPEMD160",
	"umac-64@openssh.com":            "UMAC-64",
	"umac-64-etm@openssh.com":        "UMAC-64",
	"umac-128@openssh.com":           "UMAC-128",
	"umac-128-etm@openssh.com":       "UMAC-128",
}
