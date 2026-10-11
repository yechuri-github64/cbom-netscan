// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package lexer_test

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).
// They are minimal hand-crafted strings that resemble FortiOS backup syntax
// but contain no real device configuration or credentials.

import (
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/lexer"
)

// hdr is a valid #config-version= header used as a common prefix in tests
// that focus on token behaviour rather than header parsing.
const hdr = "#config-version=FGT80F-7.4.12-FW-build0318-220920:opmode=0:vdom=0:user=admin\n"

// tokenize runs the lexer on input and returns all tokens (excluding TokEOF).
// It fails the test immediately on any lexer error.
func tokenize(t *testing.T, input string) ([]lexer.Token, *lexer.ConfigHeader) {
	t.Helper()
	l, err := lexer.New(strings.NewReader(input))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var toks []lexer.Token
	for {
		tok, err := l.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if tok.Kind == lexer.TokEOF {
			break
		}
		toks = append(toks, tok)
	}
	return toks, l.Header
}

// TestLexer_Header checks that the #config-version= header is parsed into the
// correct Model, Version, and Build fields across representative firmware strings.
func TestLexer_Header(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantModel   string
		wantVersion string
		wantBuild   string
	}{
		{
			name:        "FGT80F_7.4.12",
			input:       "#config-version=FGT80F-7.4.12-FW-build0318-220920:opmode=0:vdom=0:user=admin\n",
			wantModel:   "FGT80F",
			wantVersion: "7.4.12",
			wantBuild:   "0318",
		},
		{
			name:        "FGVMK6_7.0.8",
			input:       "#config-version=FGVMK6-7.0.8-FW-build0418-220920:opmode=0:vdom=0:user=admin\n",
			wantModel:   "FGVMK6",
			wantVersion: "7.0.8",
			wantBuild:   "0418",
		},
		{
			name:        "FGT200F_8.0.1",
			input:       "#config-version=FGT200F-8.0.1-FW-build1500-260101:opmode=1:vdom=1:user=sysadmin\n",
			wantModel:   "FGT200F",
			wantVersion: "8.0.1",
			wantBuild:   "1500",
		},
		{
			// No trailing fields after the date — minimal valid header.
			name:        "minimal_header",
			input:       "#config-version=FGT60F-7.6.7-FW-build0999-260601\n",
			wantModel:   "FGT60F",
			wantVersion: "7.6.7",
			wantBuild:   "0999",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, hd := tokenize(t, tc.input)
			if hd.Model != tc.wantModel {
				t.Errorf("Model = %q, want %q", hd.Model, tc.wantModel)
			}
			if hd.Version != tc.wantVersion {
				t.Errorf("Version = %q, want %q", hd.Version, tc.wantVersion)
			}
			if hd.Build != tc.wantBuild {
				t.Errorf("Build = %q, want %q", hd.Build, tc.wantBuild)
			}
		})
	}
}

// TestLexer_Reject verifies that New returns an error for inputs that are not
// FortiOS standard backups: encrypted blobs, YAML exports, and empty files.
func TestLexer_Reject(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantMsg string // substring expected in the error message
	}{
		{
			name:    "encrypted_blob_FGBK",
			input:   "#FGBK|4|FGT80F|7|4|0318|\x00\x01\x02",
			wantMsg: "not a FortiOS config backup",
		},
		{
			name:    "yaml_export",
			input:   "---\nfortigate:\n  hostname: fw01\n",
			wantMsg: "not a FortiOS config backup",
		},
		{
			name:    "empty_file",
			input:   "",
			wantMsg: "not a FortiOS config backup",
		},
		{
			name:    "plain_text",
			input:   "config system global\n    set hostname fw01\nend\n",
			wantMsg: "not a FortiOS config backup",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lexer.New(strings.NewReader(tc.input))
			if err == nil {
				t.Fatal("New: expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

// TestLexer_Tokens is the main table-driven suite.  Each case supplies the
// body that follows the standard header, and the expected token stream.
func TestLexer_Tokens(t *testing.T) {
	tok := func(k lexer.TokenKind, v string, line int) lexer.Token {
		return lexer.Token{Kind: k, Value: v, Line: line}
	}

	cases := []struct {
		name string
		body string // appended to hdr; line 2 is the first body line
		want []lexer.Token
	}{
		// ── keywords ────────────────────────────────────────────────────────
		{
			name: "all_keywords",
			body: "config vpn ipsec phase1-interface\n" +
				"    edit \"vpn-a\"\n" +
				"        set proposal aes256-sha256\n" +
				"        unset ike-version\n" +
				"    next\n" +
				"end\n",
			want: []lexer.Token{
				tok(lexer.TokConfig, "config", 2),
				tok(lexer.TokWord, "vpn", 2),
				tok(lexer.TokWord, "ipsec", 2),
				tok(lexer.TokWord, "phase1-interface", 2),
				tok(lexer.TokEdit, "edit", 3),
				tok(lexer.TokString, "vpn-a", 3),
				tok(lexer.TokSet, "set", 4),
				tok(lexer.TokWord, "proposal", 4),
				tok(lexer.TokWord, "aes256-sha256", 4),
				tok(lexer.TokUnset, "unset", 5),
				tok(lexer.TokWord, "ike-version", 5),
				tok(lexer.TokNext, "next", 6),
				tok(lexer.TokEnd, "end", 7),
			},
		},
		// ── nested config ───────────────────────────────────────────────────
		{
			name: "nested_config",
			body: "config vpn ipsec phase1-interface\n" +
				"    edit \"outer\"\n" +
				"        config system replacemsg mail \"partial\"\n" +
				"        end\n" +
				"    next\n" +
				"end\n",
			want: []lexer.Token{
				tok(lexer.TokConfig, "config", 2),
				tok(lexer.TokWord, "vpn", 2),
				tok(lexer.TokWord, "ipsec", 2),
				tok(lexer.TokWord, "phase1-interface", 2),
				tok(lexer.TokEdit, "edit", 3),
				tok(lexer.TokString, "outer", 3),
				tok(lexer.TokConfig, "config", 4),
				tok(lexer.TokWord, "system", 4),
				tok(lexer.TokWord, "replacemsg", 4),
				tok(lexer.TokWord, "mail", 4),
				tok(lexer.TokString, "partial", 4),
				tok(lexer.TokEnd, "end", 5),
				tok(lexer.TokNext, "next", 6),
				tok(lexer.TokEnd, "end", 7),
			},
		},
		// ── multi-value set ─────────────────────────────────────────────────
		{
			name: "multi_value_set",
			body: "config vpn ipsec phase1-interface\n" +
				"    edit 1\n" +
				"        set proposal aes128-sha256 aes256-sha256\n" +
				"        set dhgrp 21 20\n" +
				"    next\n" +
				"end\n",
			want: []lexer.Token{
				tok(lexer.TokConfig, "config", 2),
				tok(lexer.TokWord, "vpn", 2),
				tok(lexer.TokWord, "ipsec", 2),
				tok(lexer.TokWord, "phase1-interface", 2),
				tok(lexer.TokEdit, "edit", 3),
				tok(lexer.TokWord, "1", 3),
				tok(lexer.TokSet, "set", 4),
				tok(lexer.TokWord, "proposal", 4),
				tok(lexer.TokWord, "aes128-sha256", 4),
				tok(lexer.TokWord, "aes256-sha256", 4),
				tok(lexer.TokSet, "set", 5),
				tok(lexer.TokWord, "dhgrp", 5),
				tok(lexer.TokWord, "21", 5),
				tok(lexer.TokWord, "20", 5),
				tok(lexer.TokNext, "next", 6),
				tok(lexer.TokEnd, "end", 7),
			},
		},
		// ── double-quote basic ──────────────────────────────────────────────
		{
			name: "double_quote_basic",
			body: "config test\n    set name \"hello world\"\nend\n",
			want: []lexer.Token{
				tok(lexer.TokConfig, "config", 2),
				tok(lexer.TokWord, "test", 2),
				tok(lexer.TokSet, "set", 3),
				tok(lexer.TokWord, "name", 3),
				tok(lexer.TokString, "hello world", 3),
				tok(lexer.TokEnd, "end", 4),
			},
		},
		// ── double-quote escapes ─────────────────────────────────────────────
		// AG-8.0.1 §"Special characters": \", \', \\, and backslash-space.
		{
			name: "double_quote_escapes",
			body: "config test\n" +
				"    set a \"she said \\\"hi\\\"\"\n" + // she said "hi"
				"    set b \"it\\'s fine\"\n" + // it's fine
				"    set c \"back\\\\slash\"\n" + // back\slash
				"    set d \"space\\ here\"\n" + // space here
				"end\n",
			want: []lexer.Token{
				tok(lexer.TokConfig, "config", 2),
				tok(lexer.TokWord, "test", 2),
				tok(lexer.TokSet, "set", 3), tok(lexer.TokWord, "a", 3), tok(lexer.TokString, `she said "hi"`, 3),
				tok(lexer.TokSet, "set", 4), tok(lexer.TokWord, "b", 4), tok(lexer.TokString, "it's fine", 4),
				tok(lexer.TokSet, "set", 5), tok(lexer.TokWord, "c", 5), tok(lexer.TokString, `back\slash`, 5),
				tok(lexer.TokSet, "set", 6), tok(lexer.TokWord, "d", 6), tok(lexer.TokString, "space here", 6),
				tok(lexer.TokEnd, "end", 7),
			},
		},
		// ── single-quote: no escape processing ──────────────────────────────
		// Batfish FortiosLexer.g4: single-quoted text has no escapes.
		// The backslash and quote characters are literal inside '…'.
		{
			name: "single_quote_no_escape",
			body: "config test\n" +
				"    set val 'back\\slash and \\\"quote'\n" +
				"end\n",
			want: []lexer.Token{
				tok(lexer.TokConfig, "config", 2),
				tok(lexer.TokWord, "test", 2),
				tok(lexer.TokSet, "set", 3),
				tok(lexer.TokWord, "val", 3),
				// Backslash and \" are NOT processed; the string ends at the first '.
				tok(lexer.TokString, `back\slash and \"quote`, 3),
				tok(lexer.TokEnd, "end", 4),
			},
		},
		// ── multi-line double-quoted (PEM certificate value) ─────────────────
		{
			name: "multiline_pem_value",
			body: "config vpn certificate local\n" +
				"    edit \"test-cert\"\n" +
				"        set certificate \"-----BEGIN CERTIFICATE-----\n" +
				"MIIBIQIDAQAB\n" +
				"-----END CERTIFICATE-----\"\n" +
				"    next\n" +
				"end\n",
			want: []lexer.Token{
				tok(lexer.TokConfig, "config", 2),
				tok(lexer.TokWord, "vpn", 2),
				tok(lexer.TokWord, "certificate", 2),
				tok(lexer.TokWord, "local", 2),
				tok(lexer.TokEdit, "edit", 3),
				tok(lexer.TokString, "test-cert", 3),
				tok(lexer.TokSet, "set", 4),
				tok(lexer.TokWord, "certificate", 4),
				tok(lexer.TokString,
					"-----BEGIN CERTIFICATE-----\nMIIBIQIDAQAB\n-----END CERTIFICATE-----",
					4),
				tok(lexer.TokNext, "next", 7),
				tok(lexer.TokEnd, "end", 8),
			},
		},
		// ── comment at line start ────────────────────────────────────────────
		{
			name: "comment_at_line_start",
			body: "# secondary header comment\n" +
				"config test\n" +
				"end\n",
			want: []lexer.Token{
				tok(lexer.TokComment, " secondary header comment", 2),
				tok(lexer.TokConfig, "config", 3),
				tok(lexer.TokWord, "test", 3),
				tok(lexer.TokEnd, "end", 4),
			},
		},
		// ── comment after leading whitespace ─────────────────────────────────
		// atLineStart remains true through horizontal whitespace, so an
		// indented # is still a comment (matches typical FortiOS comment style).
		{
			name: "comment_after_leading_whitespace",
			body: "    # indented comment\n" +
				"end\n",
			want: []lexer.Token{
				tok(lexer.TokComment, " indented comment", 2),
				tok(lexer.TokEnd, "end", 3),
			},
		},
		// ── inline # is NOT a comment ─────────────────────────────────────────
		// "#" mid-line (atLineStart == false) is included in the bare word.
		// In practice FortiOS values containing # would be quoted; this tests
		// that the lexer doesn't accidentally start a comment mid-line.
		{
			name: "inline_hash_is_word",
			body: "config test\n    set tag v1.0#rc1\nend\n",
			want: []lexer.Token{
				tok(lexer.TokConfig, "config", 2),
				tok(lexer.TokWord, "test", 2),
				tok(lexer.TokSet, "set", 3),
				tok(lexer.TokWord, "tag", 3),
				tok(lexer.TokWord, "v1.0#rc1", 3),
				tok(lexer.TokEnd, "end", 4),
			},
		},
		// ── CRLF line endings ─────────────────────────────────────────────────
		{
			name: "crlf_endings",
			body: "config test\r\n    set x 1\r\nend\r\n",
			want: []lexer.Token{
				tok(lexer.TokConfig, "config", 2),
				tok(lexer.TokWord, "test", 2),
				tok(lexer.TokSet, "set", 3),
				tok(lexer.TokWord, "x", 3),
				tok(lexer.TokWord, "1", 3),
				tok(lexer.TokEnd, "end", 4),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := tokenize(t, hdr+tc.body)
			if len(got) != len(tc.want) {
				t.Fatalf("token count: got %d, want %d\ngot:  %v\nwant: %v",
					len(got), len(tc.want), got, tc.want)
			}
			for i, w := range tc.want {
				if got[i] != w {
					t.Errorf("token[%d]: got  {%v %q line %d}\n"+
						"                 want {%v %q line %d}",
						i, got[i].Kind, got[i].Value, got[i].Line,
						w.Kind, w.Value, w.Line)
				}
			}
		})
	}
}

// TestLexer_UnterminatedQuote verifies that a quoted string that reaches EOF
// without a closing delimiter returns a clear error with the opening line
// number, and never hangs or panics.
func TestLexer_UnterminatedQuote(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string // required substring in error message
	}{
		{
			name:    "double_quote_at_eof",
			body:    "set x \"no closing quote",
			wantErr: "unterminated double-quoted string starting at line 2",
		},
		{
			name:    "single_quote_at_eof",
			body:    "set x 'no closing quote",
			wantErr: "unterminated single-quoted string starting at line 2",
		},
		{
			// Multi-line: opening " on line 2, spans to EOF with no closing ".
			name: "double_quote_multiline_at_eof",
			body: "set pem \"-----BEGIN CERTIFICATE-----\n" +
				"MIIBIQIDAQAB\n" +
				"(no end marker, no closing quote)",
			wantErr: "unterminated double-quoted string starting at line 2",
		},
		{
			// Opening quote is deeper in the file; error must report its line.
			name:    "double_quote_on_later_line",
			body:    "config test\n    set x \"missing\nend\n",
			wantErr: "unterminated double-quoted string starting at line 3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := lexer.New(strings.NewReader(hdr + tc.body))
			if err != nil {
				t.Fatalf("New: unexpected error: %v", err)
			}
			var lexErr error
			for {
				tok, err := l.Next()
				if err != nil {
					lexErr = err
					break
				}
				if tok.Kind == lexer.TokEOF {
					break
				}
			}
			if lexErr == nil {
				t.Fatal("expected an error for unterminated quote, got nil")
			}
			if !strings.Contains(lexErr.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", lexErr.Error(), tc.wantErr)
			}
		})
	}
}

// TestLexer_UTF8BOM verifies that a UTF-8 BOM (\xEF\xBB\xBF) at the start
// of the file is silently stripped before the #config-version= check, so
// configs saved by Windows text editors are accepted without manual cleaning.
func TestLexer_UTF8BOM(t *testing.T) {
	const bomPrefix = "\xEF\xBB\xBF"
	input := bomPrefix + hdr + "config test\nend\n"

	l, err := lexer.New(strings.NewReader(input))
	if err != nil {
		t.Fatalf("New with BOM: %v", err)
	}
	if l.Header.Model != "FGT80F" {
		t.Errorf("Header.Model = %q, want FGT80F", l.Header.Model)
	}
	if l.Header.Version != "7.4.12" {
		t.Errorf("Header.Version = %q, want 7.4.12", l.Header.Version)
	}

	// Confirm tokenization works normally after the BOM.
	var kinds []lexer.TokenKind
	for {
		tok, err := l.Next()
		if err != nil {
			t.Fatalf("Next after BOM: %v", err)
		}
		if tok.Kind == lexer.TokEOF {
			break
		}
		kinds = append(kinds, tok.Kind)
	}
	// Expect: config test end
	want := []lexer.TokenKind{lexer.TokConfig, lexer.TokWord, lexer.TokEnd}
	if len(kinds) != len(want) {
		t.Fatalf("token kinds: got %v, want %v", kinds, want)
	}
	for i, k := range want {
		if kinds[i] != k {
			t.Errorf("token[%d] kind: got %v, want %v", i, kinds[i], k)
		}
	}
}

// TestLexer_LineNumbers verifies that tokens in a multi-line input carry the
// correct 1-based source line numbers, including after a multi-line PEM value.
func TestLexer_LineNumbers(t *testing.T) {
	body := "config vpn certificate local\n" + // line 2
		"    edit \"cert1\"\n" + // line 3
		"        set certificate \"-----BEGIN CERTIFICATE-----\n" + // line 4
		"MIIBIQIDAQAB\n" + // line 5 (inside string)
		"-----END CERTIFICATE-----\"\n" + // line 6 (closes string)
		"    next\n" + // line 7
		"end\n" // line 8

	toks, _ := tokenize(t, hdr+body)

	// Find the "next" token and check it lands on line 7.
	for _, tok := range toks {
		if tok.Kind == lexer.TokNext {
			if tok.Line != 7 {
				t.Errorf("next token line = %d, want 7", tok.Line)
			}
			return
		}
	}
	t.Error("next token not found")
}
