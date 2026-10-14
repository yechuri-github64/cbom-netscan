// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package global

import (
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/internal/field"
)

// TestDefaultsUseKnownTokens fails if a defaults table contains a token the
// classifier does not know, which would mean a typo in the JSON or a missing
// classification entry.
func TestDefaultsUseKnownTokens(t *testing.T) {
	specs := map[string]map[string]field.Spec{
		sectionGlobal: {
			"admin-https-ssl-versions":       specTLSVersions,
			"admin-https-ssl-ciphersuites":   specTLS13Suites,
			"admin-https-ssl-banned-ciphers": specBanned,
			"strong-crypto":                  specEnableDis,
			"ssl-static-key-ciphers":         specEnableDis,
			"admin-server-cert":              specCertName,
		},
		sectionSSH: {
			"ssh-enc-algo": {Known: keys(sshEnc)},
			"ssh-kex-algo": {Known: keys(sshKex)},
			"ssh-mac-algo": {Known: keys(sshMac)},
			"ssh-hsk-algo": {Known: keys(sshHsk)},
		},
	}
	for _, tb := range defaults.Tables() {
		for section, fields := range specs {
			for name, sp := range fields {
				f, ok := tb.Field(section, name)
				if !ok {
					t.Errorf("table %s: no %s / %s", tb.Name, section, name)
					continue
				}
				for _, tok := range f.Value {
					known := sp.Known[tok] || (sp.Freeform && sp.Pattern.MatchString(tok))
					if !known {
						t.Errorf("table %s: %s / %s default token %q is not known", tb.Name, section, name, tok)
					}
				}
			}
		}
	}
}
