// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package certs

import "strings"

// pemLabel returns the label of a PEM BEGIN line, "X" in "-----BEGIN X-----",
// or "" if line is not a BEGIN line. Only that one line is looked at; the
// base64 body that follows is never read here.
func pemLabel(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "-----BEGIN ") || !strings.HasSuffix(line, "-----") || len(line) < len("-----BEGIN -----") {
		return ""
	}
	return line[len("-----BEGIN ") : len(line)-len("-----")]
}

// firstLine is text up to its first newline.
func firstLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return text[:i]
	}
	return text
}

// isKeyLabel reports whether a PEM label is a private key of any format.
func isKeyLabel(label string) bool {
	return strings.HasSuffix(label, "PRIVATE KEY")
}

// Private-key forms, recorded as private-key:form. Only the first token, or
// for a PEM key only its BEGIN line, decides the form.
const (
	formENC        = "ENC"                    // FortiOS-encrypted (ENC <blob>)
	formMasked     = "masked"                 // FortinetPasswordMask
	formEncrypted  = "encrypted-pem"          // -----BEGIN ENCRYPTED PRIVATE KEY----- (PKCS #8, encrypted)
	formPlaintext  = "plaintext-pem"          // -----BEGIN PRIVATE KEY----- (PKCS #8, unencrypted)
	formPEMUnknown = "pem-encryption-unknown" // RSA/EC/DSA/OPENSSH PRIVATE KEY: encryption is not shown in the BEGIN line
	formOther      = "other"
)

// privateKeyForm classifies a private-key value without reading the key: it
// looks at the first token (ENC, FortinetPasswordMask) or, for a PEM key, at
// the BEGIN line alone. warn is set when the key is, or may be, stored
// unencrypted in the backup.
func privateKeyForm(values []string) (form string, warn bool) {
	switch values[0] {
	case "ENC":
		return formENC, false
	case "FortinetPasswordMask":
		return formMasked, false
	}
	label := pemLabel(firstLine(values[0]))
	switch {
	case label == "ENCRYPTED PRIVATE KEY":
		return formEncrypted, false
	case label == "PRIVATE KEY":
		return formPlaintext, true
	case isKeyLabel(label):
		// Traditional OpenSSL keys mark encryption in headers after the
		// BEGIN line, and OpenSSH keys inside the body; neither is read.
		return formPEMUnknown, true
	}
	return formOther, false
}
