// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package global

import (
	"regexp"

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
	"rijndael-cbc@lysator.liu.se":   {Primitive: "block-cipher", Mode: "cbc"},
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
	// Hybrid ML-KEM-768 + X25519. Research notes §7 allow "kem" + props for
	// hybrids; ML-KEM-768 is NIST level 3 (FIPS 203). See hybridProp.
	"mlkem768x25519-sha256": {Primitive: "kem", ParameterSetIdentifier: "768", NISTQuantumLevel: &nistLevel3},
}

var hybridProp = map[string]string{
	"mlkem768x25519-sha256": "ML-KEM-768 + X25519",
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
	"ssh-ed25519":         {Primitive: "signature"},
}

// spec says which configured tokens may reach the CBOM.
//
// Known tokens are kept. An unknown token that matches pattern is kept and
// flagged (new firmware may add options); with freeform set it is kept
// silently, for names such as certificates. Anything else is dropped without
// being echoed in the warning, so stray secret text never reaches output.
type spec struct {
	known    map[string]bool
	pattern  *regexp.Regexp // nil: unknown tokens are always dropped
	freeform bool
}

var (
	specTLSVersions = spec{known: keys(tlsVersions)}
	specTLS13Suites = spec{known: tls13Suites, pattern: regexp.MustCompile(`^TLS-[A-Z0-9-]{1,60}$`)}
	specBanned      = spec{known: bannedCiphers, pattern: regexp.MustCompile(`^[A-Z0-9]{1,16}$`)}
	specEnableDis   = spec{known: enableDisable}
	specCertName    = spec{pattern: regexp.MustCompile(`^[A-Za-z0-9 _.@-]{1,35}$`), freeform: true}
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
