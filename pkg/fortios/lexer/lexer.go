// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package lexer tokenizes a FortiOS backup configuration file.
//
// Usage:
//
//	l, err := lexer.New(r)   // validates the #config-version= header
//	if err != nil { … }
//	for {
//	    tok, err := l.Next()
//	    if err != nil { … }
//	    if tok.Kind == lexer.TokEOF { break }
//	    // use tok
//	}
//
// Token stream contract:
//   - New reads and validates the #config-version= header line and the
//     #conf_file_ver=, #buildno= and #global_vdom= lines after it. The parsed
//     fields are in Lexer.Header; those lines never appear as tokens.
//   - Next() returns tokens until TokEOF.
//   - Comments (# at line start, or after leading whitespace) are returned
//     as TokComment so callers can skip or inspect them uniformly.
//   - Quoted strings (single or double) are returned as TokString.
//     Double-quoted strings resolve the escapes \", \', \\, and "\ " (backslash-
//     space) per AG-8.0.1 §"Special characters".
//     Single-quoted strings have NO escape processing (Batfish grammar, §1.2).
//   - Bare words decode the same backslash escapes as double-quoted strings,
//     so a\ b\ c is one TokWord with value "a b c".
//   - Multi-line quoted strings (e.g. PEM certificate values) are handled
//     transparently; embedded newlines appear as \n in the TokString value.
//   - CRLF line endings are normalised to LF. No line-length limit.
package lexer

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// TokenKind identifies the type of a lexed token.
type TokenKind int

const (
	TokEOF     TokenKind = iota // end of input
	TokComment                  // # … at line start; Value = text after the #
	TokConfig                   // "config" keyword
	TokEdit                     // "edit" keyword
	TokSet                      // "set" keyword
	TokUnset                    // "unset" keyword
	TokNext                     // "next" keyword
	TokEnd                      // "end" keyword
	TokWord                     // bare unquoted token
	TokString                   // single- or double-quoted string (escapes resolved)
)

// Token is one lexed unit from the token stream.
type Token struct {
	Kind  TokenKind
	Value string // raw keyword text, unescaped string content, or comment body
	Line  int    // 1-based source line number
}

// ConfigHeader holds the parsed header block of a FortiOS standard backup:
// the #config-version= line plus the #conf_file_ver=, #buildno= and
// #global_vdom= lines that follow it.
//
// The user= field (the exporting admin) is deliberately never stored, and is
// redacted from error messages, so it cannot leak into a CBOM or a log.
//
// Only VDOM mode is interpreted; the other values are kept as raw strings
// because Fortinet does not document their semantics (research notes §10).
type ConfigHeader struct {
	Model     string   // FortiGate model identifier, e.g. "FGVMH6"
	Version   string   // firmware version, e.g. "7.6.7"
	Build     string   // build number, e.g. "3704"
	BuildDate string   // build date as YYMMDD, e.g. "260601"; empty if missing or not 6 digits
	OpMode    string   // opmode= value, e.g. "0"; empty if absent
	VDOMMode  VDOMMode // from vdom=; VDOMUnknown if absent or not 0/1

	ConfFileVer string // #conf_file_ver= value; empty if absent
	BuildNo     string // #buildno= value; empty if absent
	GlobalVDOM  string // #global_vdom= value; empty if absent

	// PrivateEncryptionKey is true when a #private-encryption-key= line was
	// seen. The key value itself is never stored, emitted, or logged.
	PrivateEncryptionKey bool
	// OpaqueSecrets is true when secret fields in this backup are encrypted
	// with a key the parser does not have, so they can only be reported as
	// present (research notes §5.3).
	OpaqueSecrets bool
}

// VDOMMode is the VDOM layout declared by the vdom= header field.
type VDOMMode int

const (
	// VDOMUnknown means vdom= was absent or not 0/1. The tree builder must
	// detect multi-VDOM itself from a top-level "config vdom" block.
	VDOMUnknown VDOMMode = iota
	VDOMSingle           // vdom=0
	VDOMMulti            // vdom=1
)

// headerRE matches the first colon-separated field after "#config-version=".
// Capture groups: (1) model, (2) version, (3) build number, (4) whatever
// follows the build number, which is the build date when it is 6 digits.
var headerRE = regexp.MustCompile(`^([^-]+)-(\d+\.\d+\.\d+)-FW-build(\d+)(?:-(.*))?$`)

var buildDateRE = regexp.MustCompile(`^\d{6}$`)

var userFieldRE = regexp.MustCompile(`(?i)(user=)[^:]*`)

// redactUser masks the user= value so error messages never expose it.
func redactUser(s string) string {
	return userFieldRE.ReplaceAllString(s, "${1}[REDACTED]")
}

// metaKeys are the header-block lines read after #config-version=, in the
// order a FortiOS backup writes them.
var metaKeys = []string{"conf_file_ver", "buildno", "global_vdom", privateKeyField}

const privateKeyField = "private-encryption-key"

var privateKeyRE = regexp.MustCompile(`(?i)(private-encryption-key=).*`)

// redactPrivateKey masks everything after private-encryption-key= so error
// messages never expose the key, whatever characters it contains.
func redactPrivateKey(s string) string {
	return privateKeyRE.ReplaceAllString(s, "${1}[REDACTED]")
}

// Lexer is a streaming FortiOS config tokenizer.
type Lexer struct {
	r           *bufio.Reader
	line        int  // current 1-based line number (1 = the header line)
	atLineStart bool // true at the beginning of each line and after leading whitespace
	pending     rune // one-rune pushback buffer used by back()
	hasPending  bool
	// Header is set by New() and holds the parsed #config-version= fields.
	Header *ConfigHeader
	// Warnings are non-fatal problems found while reading the header.
	// Messages never contain secret values.
	Warnings []model.Warning
}

// warn records a warning about the #config-version line.
func (l *Lexer) warn(code, msg string) {
	l.warnAt(1, "#config-version", code, msg)
}

func (l *Lexer) warnAt(line int, symbol, code, msg string) {
	l.Warnings = append(l.Warnings, model.Warning{
		Code:    code,
		Message: msg,
		Ev:      model.Evidence{Line: line, Symbol: symbol},
	})
}

// markPrivateKey records that a #private-encryption-key= line was found on
// line n. Only its presence is kept; callers must drop the value.
func (l *Lexer) markPrivateKey(n int) {
	if l.Header.PrivateEncryptionKey {
		return
	}
	l.Header.PrivateEncryptionKey = true
	l.Header.OpaqueSecrets = true
	l.warnAt(n, "#"+privateKeyField, "opaque-secrets",
		"backup has a #private-encryption-key= line; secret fields are encrypted and are reported as present only")
}

// New creates a Lexer from r and reads the mandatory #config-version= header.
// Returns an error if the file does not start with that prefix, so callers
// can reject encrypted backups (#FGBK|…), YAML exports, and plain-text files
// before attempting to parse them.
func New(r io.Reader) (*Lexer, error) {
	l := &Lexer{
		r:           bufio.NewReader(r),
		line:        1,
		atLineStart: true,
	}
	if err := l.readHeader(); err != nil {
		return nil, err
	}
	return l, nil
}

// readHeader reads and parses line 1, then the header-block lines after it.
// On return, l.line is the number of the first line Next() will read.
var yamlKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*:\s*$`)

// classify names what a rejected file looks like from its first line. The
// result is one of a fixed set of phrases and never contains input bytes.
func (l *Lexer) classify(first string) string {
	t := strings.TrimSpace(first)
	switch {
	case t == "" && l.restIsBlank():
		return "empty file"
	case strings.HasPrefix(t, "#FGBK"):
		return "encrypted FortiOS backup (#FGBK)"
	case t == "---" || strings.HasPrefix(t, "--- ") || strings.HasPrefix(t, "%YAML") || yamlKeyRE.MatchString(t):
		return "looks like YAML"
	case strings.HasPrefix(t, "-----BEGIN "),
		strings.HasPrefix(t, "ssh-rsa "), strings.HasPrefix(t, "ssh-ed25519 "),
		strings.HasPrefix(t, "ecdsa-sha2-"), strings.HasPrefix(t, "PuTTY-User-Key-File-"):
		return "looks like a PEM/key file"
	default:
		return "unrecognised format"
	}
}

// restIsBlank reports whether everything after the first line is whitespace.
// It is only called while rejecting a file, so consuming the reader is fine.
func (l *Lexer) restIsBlank() bool {
	for {
		b, err := l.r.ReadByte()
		if err != nil {
			return true
		}
		switch b {
		case ' ', '\t', '\r', '\n':
		default:
			return false
		}
	}
}

func (l *Lexer) readHeader() error {
	first, err := l.r.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("fortios lexer: reading header: %w", err)
	}
	first = strings.TrimRight(first, "\r\n")

	// Strip a UTF-8 BOM (\xEF\xBB\xBF) that Windows text editors sometimes
	// prepend when saving a file.  It must be removed before the prefix check
	// or files edited on Windows will be rejected.
	const bom = "\xEF\xBB\xBF"
	first = strings.TrimPrefix(first, bom)

	const prefix = "#config-version="
	if !strings.HasPrefix(first, prefix) {
		// Only a classification is reported, never input bytes: a file passed
		// by mistake may be a private key or a credentials file.
		return fmt.Errorf("fortios lexer: not a FortiOS config backup: %s", l.classify(first))
	}

	fields := strings.Split(first[len(prefix):], ":")
	m := headerRE.FindStringSubmatch(fields[0])
	if m == nil {
		return fmt.Errorf("fortios lexer: malformed #config-version line: %q", redactPrivateKey(redactUser(first)))
	}
	h := &ConfigHeader{Model: m[1], Version: m[2], Build: m[3]}
	if buildDateRE.MatchString(m[4]) {
		h.BuildDate = m[4]
	}

	vdomRaw, vdomSeen := "", false
	for _, f := range fields[1:] {
		k, v, _ := strings.Cut(f, "=")
		switch k {
		case "opmode":
			h.OpMode = v
		case "vdom":
			vdomRaw, vdomSeen = v, true
		}
		// user= and unknown fields are skipped; user= is never stored.
	}
	switch {
	case vdomSeen && vdomRaw == "0":
		h.VDOMMode = VDOMSingle
	case vdomSeen && vdomRaw == "1":
		h.VDOMMode = VDOMMulti
	case vdomSeen:
		// The raw value is not echoed: it is untrusted header text.
		l.warn("vdom-mode-unknown", "#config-version has a vdom= value other than 0 or 1; VDOM mode will be detected from the config tree")
	default:
		l.warn("vdom-mode-unknown", "#config-version has no vdom= field; VDOM mode will be detected from the config tree")
	}

	l.Header = h
	l.line = 2
	return l.readMetaLines()
}

// readMetaLines consumes the #conf_file_ver=, #buildno= and #global_vdom=
// lines that directly follow the header, so they are stored in Header instead
// of reaching the token stream as comments.  It stops at the first line that
// is not one of them; anything else is left for Next().
func (l *Lexer) readMetaLines() error {
	for {
		key := ""
		for _, k := range metaKeys {
			p := "#" + k + "="
			if b, _ := l.r.Peek(len(p)); string(b) == p {
				key = k
				break
			}
		}
		if key == "" {
			return nil
		}

		line, err := l.r.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("fortios lexer line %d: %w", l.line, err)
		}
		val := strings.TrimRight(line, "\r\n")[len(key)+2:]
		switch key {
		case "conf_file_ver":
			l.Header.ConfFileVer = val
		case "buildno":
			l.Header.BuildNo = val
		case "global_vdom":
			l.Header.GlobalVDOM = val
		case privateKeyField:
			l.markPrivateKey(l.line)
		}
		l.line++
	}
}

// next returns the next rune, discarding \r so CRLF behaves like LF.
// Returns io.EOF when the input is exhausted.
func (l *Lexer) next() (rune, error) {
	if l.hasPending {
		r := l.pending
		l.hasPending = false
		return r, nil
	}
	for {
		r, _, err := l.r.ReadRune()
		if err != nil {
			return 0, err
		}
		if r == '\r' {
			continue // discard CR; the following \n (if any) drives line counting
		}
		return r, nil
	}
}

// back pushes r back so the next call to next() returns it.
// Only one level of pushback is supported.
func (l *Lexer) back(r rune) {
	l.pending = r
	l.hasPending = true
}

// Next returns the next token from the stream.
// Returns (Token{Kind: TokEOF}, nil) at end of input.
func (l *Lexer) Next() (Token, error) {
	for {
		r, err := l.next()
		if err == io.EOF {
			return Token{Kind: TokEOF, Line: l.line}, nil
		}
		if err != nil {
			return Token{}, fmt.Errorf("fortios lexer line %d: %w", l.line, err)
		}

		if r == '\n' {
			l.line++
			l.atLineStart = true
			continue
		}

		// Horizontal whitespace: skip without clearing atLineStart so that
		// a # after leading spaces on a line is still treated as a comment.
		if r == ' ' || r == '\t' {
			continue
		}

		pos := l.line // record line before consuming more runes

		// A # at line start (or after leading whitespace) opens a comment.
		// Mid-line # is not special: it becomes part of a bare word.
		if r == '#' && l.atLineStart {
			body, err := l.readToEOL()
			if err != nil {
				return Token{}, err
			}
			// A key line outside the header block must not reach the token
			// stream either: record presence and drop the line.
			if strings.HasPrefix(strings.TrimLeft(body, " \t"), privateKeyField+"=") {
				l.markPrivateKey(pos)
				continue
			}
			return Token{Kind: TokComment, Value: body, Line: pos}, nil
		}

		l.atLineStart = false

		switch r {
		case '"':
			val, err := l.readDoubleQuoted(pos)
			if err != nil {
				return Token{}, err
			}
			return Token{Kind: TokString, Value: val, Line: pos}, nil
		case '\'':
			val, err := l.readSingleQuoted(pos)
			if err != nil {
				return Token{}, err
			}
			return Token{Kind: TokString, Value: val, Line: pos}, nil
		default:
			word, err := l.readWord(r)
			if err != nil {
				return Token{}, err
			}
			return wordToken(word, pos), nil
		}
	}
}

// readToEOL reads from the current position to the end of the line, consuming
// the newline itself and incrementing the line counter.
func (l *Lexer) readToEOL() (string, error) {
	var b strings.Builder
	for {
		r, err := l.next()
		if err == io.EOF {
			return b.String(), nil
		}
		if err != nil {
			return "", fmt.Errorf("fortios lexer line %d: %w", l.line, err)
		}
		if r == '\n' {
			l.line++
			l.atLineStart = true
			return b.String(), nil
		}
		b.WriteRune(r)
	}
}

// readWord reads a bare (unquoted) token beginning with first.
// It stops at whitespace, single or double quotes, or end of input.
// Newlines are pushed back so the caller's loop can handle them.
//
// Backslash escapes \ (space), \', \", and \\ are decoded so that input like
// a\ b\ c yields the single word "a b c" (verified on FortiOS 7.6.7). Any other
// backslash is kept literally and the following rune is processed normally,
// so a stray \ before a newline cannot swallow the line break.
func (l *Lexer) readWord(first rune) (string, error) {
	var b strings.Builder
	l.back(first)
	for {
		r, err := l.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("fortios lexer line %d: %w", l.line, err)
		}
		if r == '\\' {
			esc, err := l.next()
			if err == io.EOF {
				b.WriteRune('\\')
				break
			}
			if err != nil {
				return "", fmt.Errorf("fortios lexer line %d: %w", l.line, err)
			}
			switch esc {
			case ' ', '\'', '"', '\\':
				b.WriteRune(esc)
			default:
				b.WriteRune('\\')
				l.back(esc)
			}
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '"' || r == '\'' {
			l.back(r)
			break
		}
		b.WriteRune(r)
	}
	return b.String(), nil
}

// readDoubleQuoted reads a double-quoted string after the opening " has been consumed.
//
// Escape sequences (AG-8.0.1 §"Special characters"):
//
//	\"  → "      \'  → '      \\  → \      "\ " → space (backslash-space)
//
// Unknown escapes are preserved verbatim (backslash + char), matching the
// liberal-accept principle for offline parsing.
// Embedded newlines (multi-line PEM values etc.) are kept in the value as \n.
func (l *Lexer) readDoubleQuoted(startLine int) (string, error) {
	var b strings.Builder
	for {
		r, err := l.next()
		if err == io.EOF {
			return "", fmt.Errorf("fortios lexer: unterminated double-quoted string starting at line %d", startLine)
		}
		if err != nil {
			return "", fmt.Errorf("fortios lexer line %d: %w", l.line, err)
		}
		if r == '\n' {
			l.line++
			b.WriteRune('\n')
			continue
		}
		if r == '\\' {
			esc, err := l.next()
			if err == io.EOF {
				return "", fmt.Errorf("fortios lexer: truncated escape in double-quoted string at line %d", l.line)
			}
			if err != nil {
				return "", fmt.Errorf("fortios lexer line %d: %w", l.line, err)
			}
			switch esc {
			case '"', '\'', '\\', ' ':
				b.WriteRune(esc)
			default:
				// Unknown escape: pass through as-is.
				b.WriteRune('\\')
				b.WriteRune(esc)
			}
			continue
		}
		if r == '"' {
			return b.String(), nil
		}
		b.WriteRune(r)
	}
}

// readSingleQuoted reads a single-quoted string after the opening ' has been consumed.
//
// Single-quoted strings have NO escape processing: the string ends at the
// first unescaped ', and backslashes are literal (Batfish FortiosLexer.g4, §1.2).
// Embedded newlines are kept in the value.
func (l *Lexer) readSingleQuoted(startLine int) (string, error) {
	var b strings.Builder
	for {
		r, err := l.next()
		if err == io.EOF {
			return "", fmt.Errorf("fortios lexer: unterminated single-quoted string starting at line %d", startLine)
		}
		if err != nil {
			return "", fmt.Errorf("fortios lexer line %d: %w", l.line, err)
		}
		if r == '\n' {
			l.line++
			b.WriteRune('\n')
			continue
		}
		if r == '\'' {
			return b.String(), nil
		}
		b.WriteRune(r)
	}
}

// wordToken maps a bare-word string to its keyword token kind if applicable,
// or TokWord otherwise.
func wordToken(w string, line int) Token {
	var k TokenKind
	switch w {
	case "config":
		k = TokConfig
	case "edit":
		k = TokEdit
	case "set":
		k = TokSet
	case "unset":
		k = TokUnset
	case "next":
		k = TokNext
	case "end":
		k = TokEnd
	default:
		k = TokWord
	}
	return Token{Kind: k, Value: w, Line: line}
}
