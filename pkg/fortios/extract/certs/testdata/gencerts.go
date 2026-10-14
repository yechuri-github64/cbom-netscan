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
//
// Day counts are inclusive, as the CA/Browser Forum counts them. The private
// keys are generated in memory and discarded; only certificates are written,
// so rerunning it gives new keys and the goldens must be regenerated.
//
//	go run gencerts.go
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func day(s string) time.Time { t, _ := time.Parse("2006-01-02", s); return t }

func mk(name string, serial int64, cn string, from, to time.Time, pub crypto.PublicKey, isCA bool, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
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
	if parent == nil {
		parent = tpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
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
}
