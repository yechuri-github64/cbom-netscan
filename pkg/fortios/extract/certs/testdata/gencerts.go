// SPDX-FileCopyrightText: 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: CC0-1.0

//go:build ignore

// gencerts writes the synthetic test certificates in this directory:
//
//	lab-root-ca.pem  ECDSA P-384 CA, 2025-01-01 to 2035-01-01
//	vpn-rsa.pem      RSA-2048 leaf signed by the CA (ECDSA-SHA384), 121 days
//	gw-ecdsa.pem     ECDSA P-256 leaf signed by the CA, 181 days
//	old-expired.pem  RSA-2048 self-signed (SHA256-RSA), expired 2024-12-31
//	long-lived.pem   ECDSA P-256 leaf signed by the CA, 732 days (over 200)
//	ed25519-self.pem Ed25519 self-signed (pure Ed25519 signature), 366 days,
//	                 like FortiOS's factory Ed25519 certificate
//	dsa1024-self.pem DSA self-signed, 1024-bit p and 160-bit q (DSA-SHA1),
//	dsa2048-self.pem and 2048-bit p and 256-bit q (DSA-SHA256), 366 days,
//	                 like FortiOS's factory DSA certificates
//	ed448-self.pem   Ed448 self-signed, 366 days, like FortiOS's factory
//	                 Ed448 certificate (see below)
//	fgvm-factory.pem RSA-2048 self-signed, 2026-01-01 to 2036-01-01, with
//	                 the made-up serial number FGVMEV0000000000 as common
//	                 name, like a FortiGate's factory certificate
//	fgvm-rsa1024.pem RSA-1024 with the same subject and dates. The
//	                 multi-VDOM VM fixture stores it as Fortinet_SSL_RSA2048:
//	                 the name says 2048 bits, the key has 1024
//
// Day counts are inclusive, as the CA/Browser Forum counts them. The private
// keys are generated in memory and discarded; only certificates are written,
// so rerunning it gives new keys and the goldens must be regenerated. Name
// certificates to write only those, leaving the others as they are:
//
//	go run gencerts.go                # all
//	go run gencerts.go ed25519-self   # one
//
// crypto/x509 cannot put a DSA or Ed448 key in a certificate, so swapKey
// builds those from a certificate x509 makes for a stand-in key. Go has no
// Ed448 at all: ed448-self.pem holds the public key of RFC 8032's first Ed448
// test vector and a signature of 114 zero bytes. It parses, but its signature
// does not verify; the extractor reads the algorithms and never checks
// signatures. ed448-self.pem is the same on every run.
package main

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"hash"
	"math/big"
	"os"
	"slices"
	"time"
)

var (
	oidDSA           = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}         // RFC 3279
	oidDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}         // RFC 3279
	oidDSAWithSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2} // RFC 5758
	oidEd448         = asn1.ObjectIdentifier{1, 3, 101, 113}                 // RFC 8410
)

// ed448TestKey is the public key of the first Ed448 test vector in RFC 8032
// §7.4 ("-----Blank"). It is published test data, not a secret, so the
// comment on its line tells gitleaks to allow it.
const ed448TestKey = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180" // gitleaks:allow

func day(s string) time.Time { t, _ := time.Parse("2006-01-02", s); return t }

func template(serial int64, cn string, from, to time.Time, isCA bool) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, Organization: []string{"Example Lab"}},
		NotBefore: from, NotAfter: to, BasicConstraintsValid: true, IsCA: isCA,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tpl.KeyUsage |= x509.KeyUsageCertSign
	} else {
		tpl.DNSNames = []string{cn}
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	return tpl
}

func mk(name string, serial int64, cn string, from, to time.Time, pub crypto.PublicKey, isCA bool, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	tpl := template(serial, cn, from, to, isCA)
	if parent == nil {
		parent = tpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	return save(name, der)
}

// save writes der to name.pem, unless certificate names were given and name
// is not one of them, and returns the parsed certificate.
func save(name string, der []byte) *x509.Certificate {
	if len(os.Args) == 1 || slices.Contains(os.Args[1:], name) {
		if err := os.WriteFile(name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			panic(err)
		}
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

// standIn is a self-signed leaf certificate for a throwaway ECDSA key, for
// swapKey to replace the key in.
func standIn(serial int64, cn string, from, to time.Time) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := template(serial, cn, from, to, false)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return der
}

// subjectPublicKeyInfo encodes an RFC 5280 SubjectPublicKeyInfo. params nil
// leaves the algorithm parameters absent, as RFC 8410 requires for Ed448.
func subjectPublicKeyInfo(alg asn1.ObjectIdentifier, params, key []byte) []byte {
	ai := pkix.AlgorithmIdentifier{Algorithm: alg}
	if params != nil {
		ai.Parameters = asn1.RawValue{FullBytes: params}
	}
	der, err := asn1.Marshal(struct {
		Alg pkix.AlgorithmIdentifier
		Key asn1.BitString
	}{ai, asn1.BitString{Bytes: key, BitLength: 8 * len(key)}})
	if err != nil {
		panic(err)
	}
	return der
}

// swapKey returns the self-signed certificate der with its public key
// replaced by spki and its signature algorithm by sigAlg (absent
// parameters), signed again by sign.
func swapKey(der, spki []byte, sigAlg asn1.ObjectIdentifier, sign func(tbs []byte) []byte) []byte {
	var cert struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		panic(err)
	}
	// The TBSCertificate fields (RFC 5280 §4.1): version, serialNumber,
	// signature, issuer, validity, subject, subjectPublicKeyInfo, extensions.
	var fields [][]byte
	for rest := cert.TBS.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			panic(err)
		}
		fields = append(fields, f.FullBytes)
	}
	alg := pkix.AlgorithmIdentifier{Algorithm: sigAlg}
	algDER, err := asn1.Marshal(alg)
	if err != nil {
		panic(err)
	}
	fields[2], fields[6] = algDER, spki
	tbs, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(fields, nil)})
	if err != nil {
		panic(err)
	}
	sig := sign(tbs)
	out, err := asn1.Marshal(struct {
		TBS    asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, alg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		panic(err)
	}
	return out
}

// dsaSelf writes a self-signed certificate for a new DSA key with the given
// parameter sizes, signed with the hash newHash under the OID sigAlg.
func dsaSelf(name string, serial int64, cn string, from, to time.Time, sizes dsa.ParameterSizes, newHash func() hash.Hash, sigAlg asn1.ObjectIdentifier) {
	k := new(dsa.PrivateKey)
	if err := dsa.GenerateParameters(&k.Parameters, rand.Reader, sizes); err != nil {
		panic(err)
	}
	if err := dsa.GenerateKey(k, rand.Reader); err != nil {
		panic(err)
	}
	params, err := asn1.Marshal(struct{ P, Q, G *big.Int }{k.P, k.Q, k.G}) // Dss-Parms, RFC 3279 §2.3.2
	if err != nil {
		panic(err)
	}
	y, err := asn1.Marshal(k.Y)
	if err != nil {
		panic(err)
	}
	sign := func(tbs []byte) []byte {
		h := newHash()
		h.Write(tbs)
		digest := h.Sum(nil)
		// FIPS 186-4 §4.6: the leftmost N bits of the hash, N being the
		// size of q. dsa.Sign leaves the truncation to the caller.
		if n := k.Q.BitLen() / 8; len(digest) > n {
			digest = digest[:n]
		}
		r, s, err := dsa.Sign(rand.Reader, k, digest)
		if err != nil {
			panic(err)
		}
		if !dsa.Verify(&k.PublicKey, digest, r, s) {
			panic("DSA signature does not verify")
		}
		sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s}) // Dss-Sig-Value
		if err != nil {
			panic(err)
		}
		return sig
	}
	save(name, swapKey(standIn(serial, cn, from, to), subjectPublicKeyInfo(oidDSA, params, y), sigAlg, sign))
}

func main() {
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ca := mk("lab-root-ca", 1, "Example Lab Root CA", day("2025-01-01"), day("2035-01-01"), &caKey.PublicKey, true, nil, caKey)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mk("vpn-rsa", 2, "vpn.example.com", day("2026-10-01"), day("2027-01-29"), &rsaKey.PublicKey, false, ca, caKey)

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk("gw-ecdsa", 3, "gw.example.net", day("2026-09-15"), day("2027-03-14"), &ecKey.PublicKey, false, ca, caKey)

	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mk("old-expired", 4, "old.example.org", day("2024-01-01"), day("2024-12-31"), &oldKey.PublicKey, false, nil, oldKey)

	longKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk("long-lived", 5, "long.example.com", day("2026-05-01"), day("2028-05-01"), &longKey.PublicKey, false, ca, caKey)

	edPub, edKey, _ := ed25519.GenerateKey(rand.Reader)
	mk("ed25519-self", 6, "ed.example.org", day("2026-01-01"), day("2027-01-01"), edPub, false, nil, edKey)

	dsaSelf("dsa1024-self", 7, "dsa1024.example.org", day("2026-01-01"), day("2027-01-01"), dsa.L1024N160, sha1.New, oidDSAWithSHA1)
	dsaSelf("dsa2048-self", 8, "dsa2048.example.org", day("2026-01-01"), day("2027-01-01"), dsa.L2048N256, sha256.New, oidDSAWithSHA256)

	ed448Pub, _ := hex.DecodeString(ed448TestKey)
	save("ed448-self", swapKey(standIn(9, "ed448.example.org", day("2026-01-01"), day("2027-01-01")),
		subjectPublicKeyInfo(oidEd448, nil, ed448Pub), oidEd448, func([]byte) []byte { return make([]byte, 114) }))

	const fakeSerial = "FGVMEV0000000000" // made up, not a real device's serial
	factoryKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mk("fgvm-factory", 10, fakeSerial, day("2026-01-01"), day("2036-01-01"), &factoryKey.PublicKey, false, nil, factoryKey)

	shortKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	mk("fgvm-rsa1024", 11, fakeSerial, day("2026-01-01"), day("2036-01-01"), &shortKey.PublicKey, false, nil, shortKey)
}
