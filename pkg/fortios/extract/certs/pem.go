// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package certs

import "strings"

// pemLabel returns the label of a PEM BEGIN line, "X" in "-----BEGIN X-----",
// or "" if line is not a BEGIN line. Text after the closing dashes is
// ignored, so trailing characters do not hide a key. Only that one line is
// looked at; the base64 body that follows is never read here.
func pemLabel(line string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), "-----BEGIN ")
	if !ok {
		return ""
	}
	label, _, ok := strings.Cut(rest, "-----")
	if !ok {
		return ""
	}
	return label
}

// isEndLine reports whether line ends a block with this label; like
// pemLabel, it ignores text after the closing dashes.
func isEndLine(line, label string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "-----END "+label+"-----")
}

// isKeyLabel reports whether a PEM label is a private key of any format.
func isKeyLabel(label string) bool {
	return strings.HasSuffix(label, "PRIVATE KEY")
}

// Private-key forms, recorded as private-key:form. Only the first token, or
// for a PEM key its BEGIN line and, for traditional keys, the Proc-Type
// header after it, decides the form.
const (
	formENC        = "ENC"                    // FortiOS-encrypted (ENC <blob>)
	formMasked     = "masked"                 // FortinetPasswordMask
	formEncrypted  = "encrypted-pem"          // ENCRYPTED PRIVATE KEY (PKCS #8), or RSA/EC/DSA PRIVATE KEY with Proc-Type: 4,ENCRYPTED
	formPlaintext  = "plaintext-pem"          // PRIVATE KEY (PKCS #8), or RSA/EC/DSA PRIVATE KEY without that header
	formPEMUnknown = "pem-encryption-unknown" // OPENSSH (or other) PRIVATE KEY: encryption is recorded inside the key body, which is not read
	formOther      = "other"
)

// traditionalKeyLabels are OpenSSL's traditional key formats, which mark
// encryption with RFC 1421 headers (Proc-Type, DEK-Info) after the BEGIN line.
var traditionalKeyLabels = map[string]bool{"RSA PRIVATE KEY": true, "EC PRIVATE KEY": true, "DSA PRIVATE KEY": true}

// privateKeyForm classifies a private-key value without reading the key: it
// looks at the first token (ENC, FortinetPasswordMask) or, for a PEM key, at
// the BEGIN line and, for a traditional key, the line after it. warn is set
// when the key is, or may be, stored unencrypted in the backup.
func privateKeyForm(values []string) (form string, warn bool) {
	switch values[0] {
	case "ENC":
		return formENC, false
	case "FortinetPasswordMask":
		return formMasked, false
	}
	// Leading blank lines or spaces do not hide a PEM key.
	lines := strings.SplitN(strings.TrimLeft(values[0], " \t\r\n"), "\n", 3)
	label := pemLabel(lines[0])
	switch {
	case label == "ENCRYPTED PRIVATE KEY":
		return formEncrypted, false
	case label == "PRIVATE KEY":
		return formPlaintext, true
	case traditionalKeyLabels[label]:
		if len(lines) > 1 && procTypeEncrypted(lines[1]) {
			return formEncrypted, false
		}
		return formPlaintext, true
	case isKeyLabel(label):
		// OpenSSH keys record their cipher inside the base64 body, which is
		// never decoded, so whether they are encrypted is unknown.
		return formPEMUnknown, true
	}
	return formOther, false
}

// procTypeEncrypted reports whether line is the RFC 1421 header
// "Proc-Type: 4,ENCRYPTED". RFC 1421 puts Proc-Type first, directly after
// the BEGIN line, so only that line is checked. The header is metadata, not
// key material; if the line is instead the first line of the key body, it
// is only compared with the header's prefix and nothing from it is kept.
func procTypeEncrypted(line string) bool {
	value, ok := strings.CutPrefix(strings.TrimSpace(line), "Proc-Type:")
	return ok && strings.ReplaceAll(strings.TrimSpace(value), " ", "") == "4,ENCRYPTED"
}

// certField is what a certificate field holds, found from BEGIN and END
// lines alone: the text of its first CERTIFICATE block, and counts of the
// other blocks. Only certificate text is kept; other blocks are counted by
// label and their bodies are never decoded or stored.
type certField struct {
	cert        string // first complete CERTIFICATE block, BEGIN to END line; "" if none
	extraCerts  int    // further CERTIFICATE blocks (a chain), not inventoried
	keyBlocks   int    // private-key blocks of any format, including inside a CERTIFICATE block
	other       int    // any other PEM blocks
	nestedCerts int    // CERTIFICATE blocks with another BEGIN line inside; never decoded
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
			if isEndLine(lines[j], label) {
				end = j
				break
			}
		}
		// A BEGIN line inside a CERTIFICATE block (a key pasted into it)
		// makes the block unsafe to decode: pem.Decode would skip the bad
		// base64 and decode the inner block. Such a block is counted, its
		// inner BEGIN lines are classified, and it is never decoded.
		nested := false
		if label == "CERTIFICATE" {
			bodyEnd := end
			if end < 0 {
				bodyEnd = len(lines)
			}
			for _, l := range lines[i+1 : bodyEnd] {
				switch inner := pemLabel(l); {
				case inner == "":
				case isKeyLabel(inner):
					f.keyBlocks++
					nested = true
				default:
					f.other++
					nested = true
				}
			}
		}
		switch {
		case isKeyLabel(label):
			f.keyBlocks++
		case label != "CERTIFICATE":
			f.other++
		case nested:
			f.nestedCerts++
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
