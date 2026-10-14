// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package global

import (
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
)

// TestDefaultsUseKnownTokens fails if a defaults table contains a token the
// classifier does not know, which would mean a typo in the JSON or a missing
// classification entry.
func TestDefaultsUseKnownTokens(t *testing.T) {
	specs := map[string]map[string]spec{
		sectionGlobal: {
			"admin-https-ssl-versions":       specTLSVersions,
			"admin-https-ssl-ciphersuites":   specTLS13Suites,
			"admin-https-ssl-banned-ciphers": specBanned,
			"strong-crypto":                  specEnableDis,
			"ssl-static-key-ciphers":         specEnableDis,
			"admin-server-cert":              specCertName,
		},
		sectionSSH: {
			"ssh-enc-algo": {known: keys(sshEnc)},
			"ssh-kex-algo": {known: keys(sshKex)},
			"ssh-mac-algo": {known: keys(sshMac)},
			"ssh-hsk-algo": {known: keys(sshHsk)},
		},
	}
	for _, tb := range defaults.Tables() {
		for section, fields := range specs {
			for field, sp := range fields {
				f, ok := tb.Field(section, field)
				if !ok {
					t.Errorf("table %s: no %s / %s", tb.Name, section, field)
					continue
				}
				for _, tok := range f.Value {
					known := sp.known[tok] || (sp.freeform && sp.pattern.MatchString(tok))
					if !known {
						t.Errorf("table %s: %s / %s default token %q is not known", tb.Name, section, field, tok)
					}
				}
			}
		}
	}
}
