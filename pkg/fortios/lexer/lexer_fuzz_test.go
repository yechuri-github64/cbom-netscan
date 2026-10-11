// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package lexer_test

import (
	"bytes"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/lexer"
)

// FuzzLexer feeds arbitrary bytes to the lexer and drains every token.
// The only property checked is that the lexer terminates without panicking:
// errors from New or Next are expected for malformed input and are ignored.
// Each Next call must either consume input or return EOF/error, so the token
// count is bounded by the input length; exceeding it means the lexer looped.
func FuzzLexer(f *testing.F) {
	seeds := []string{
		hdr,
		hdr + "config test\nend\n",
		hdr + "config vpn ipsec phase1-interface\n    edit \"vpn-a\"\n        set proposal aes256-sha256\n        unset ike-version\n    next\nend\n",
		hdr + "config vpn ipsec phase1-interface\n    edit \"outer\"\n        config system replacemsg mail \"partial\"\n        end\n    next\nend\n",
		hdr + "config vpn ipsec phase1-interface\n    edit 1\n        set proposal aes128-sha256 aes256-sha256\n        set dhgrp 21 20\n    next\nend\n",
		hdr + "config test\n    set a \"she said \\\"hi\\\"\"\n    set b \"it\\'s fine\"\n    set c \"back\\\\slash\"\n    set d \"space\\ here\"\nend\n",
		hdr + "config test\n    set val 'back\\slash and \\\"quote'\nend\n",
		hdr + "config vpn certificate local\n    edit \"test-cert\"\n        set certificate \"-----BEGIN CERTIFICATE-----\nMIIBIQIDAQAB\n-----END CERTIFICATE-----\"\n    next\nend\n",
		hdr + "# secondary header comment\nconfig test\nend\n",
		hdr + "    # indented comment\nend\n",
		hdr + "config test\n    set tag v1.0#rc1\nend\n",
		hdr + "config test\r\n    set x 1\r\nend\r\n",
		hdr + "set x \"no closing quote",
		hdr + "set x 'no closing quote",
		"\xEF\xBB\xBF" + hdr + "config test\nend\n",
		"#FGBK|4|FGT80F|7|4|0318|\x00\x01\x02",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := lexer.New(bytes.NewReader(data))
		if err != nil {
			return
		}
		for n := 0; n <= len(data)+1; n++ {
			tok, err := l.Next()
			if err != nil || tok.Kind == lexer.TokEOF {
				return
			}
		}
		t.Fatalf("lexer emitted more tokens than input bytes (%d): possible infinite loop", len(data))
	})
}
