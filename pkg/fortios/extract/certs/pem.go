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
	// Leading blank lines or spaces do not hide a PEM key.
	label := pemLabel(firstLine(strings.TrimLeft(values[0], " \t\r\n")))
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

// certField is what a certificate field holds, found from BEGIN and END
// lines alone: the text of its first CERTIFICATE block, and counts of the
// other blocks. Only certificate text is kept; other blocks are counted by
// label and their bodies are never decoded or stored.
type certField struct {
	cert       string // first complete CERTIFICATE block, BEGIN to END line; "" if none
	extraCerts int    // further CERTIFICATE blocks (a chain), not inventoried
	keyBlocks  int    // private-key blocks of any format
	other      int    // any other PEM blocks
}

// scanCertField splits text into PEM blocks by their BEGIN and END lines.
func scanCertField(text string) certField {
	var f certField
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		label := pemLabel(lines[i])
		if label == "" {
			continue
		}
		end := -1
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "-----END "+label+"-----" {
				end = j
				break
			}
		}
		switch {
		case isKeyLabel(label):
			f.keyBlocks++
		case label != "CERTIFICATE":
			f.other++
		case end < 0:
			// An unterminated certificate block is not a certificate.
		case f.cert == "":
			f.cert = strings.Join(lines[i:end+1], "\n")
		default:
			f.extraCerts++
		}
		if end < 0 {
			break // no END line: the rest of the field belongs to this block
		}
		i = end
	}
	return f
}
