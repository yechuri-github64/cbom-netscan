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
//   - New reads and validates the #config-version= header line. The parsed
//     model, version, and build fields are in Lexer.Header.
//   - Next() returns tokens until TokEOF.
//   - Comments (# at line start, or after leading whitespace) are returned
//     as TokComment so callers can skip or inspect them uniformly.
//   - Quoted strings (single or double) are returned as TokString.
//     Double-quoted strings resolve the escapes \", \', \\, and "\ " (backslash-
//     space) per AG-8.0.1 §"Special characters".
//     Single-quoted strings have NO escape processing (Batfish grammar, §1.2).
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

// ConfigHeader holds the parsed fields from the #config-version= header line.
// This is the first line of every FortiOS standard backup.
type ConfigHeader struct {
	Model   string // FortiGate model identifier, e.g. "FGT80F" or "FGVMK6"
	Version string // firmware version, e.g. "7.4.12"
	Build   string // build number, e.g. "0318"
	Raw     string // the full header line, for evidence and logging
}

// headerRE matches the content that follows "#config-version=".
// Capture groups: (1) model, (2) version (maj.min.patch), (3) build number.
var headerRE = regexp.MustCompile(`^([^-]+)-(\d+\.\d+\.\d+)-FW-build(\d+)`)

// Lexer is a streaming FortiOS config tokenizer.
type Lexer struct {
	r           *bufio.Reader
	line        int  // current 1-based line number (1 = the header line)
	atLineStart bool // true at the beginning of each line and after leading whitespace
	pending     rune // one-rune pushback buffer used by back()
	hasPending  bool
	// Header is set by New() and holds the parsed #config-version= fields.
	Header *ConfigHeader
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

// readHeader reads and parses line 1.  On return, l.line == 2 and the reader
// is positioned at the start of line 2.
func (l *Lexer) readHeader() error {
	first, err := l.r.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("fortios lexer: reading header: %w", err)
	}
	first = strings.TrimRight(first, "\r\n")

	const prefix = "#config-version="
	if !strings.HasPrefix(first, prefix) {
		snip := first
		if len(snip) > 40 {
			snip = snip[:40]
		}
		return fmt.Errorf("fortios lexer: not a FortiOS config backup (first line: %q)", snip)
	}

	m := headerRE.FindStringSubmatch(first[len(prefix):])
	if m == nil {
		return fmt.Errorf("fortios lexer: malformed #config-version line: %q", first)
	}
	l.Header = &ConfigHeader{
		Model:   m[1],
		Version: m[2],
		Build:   m[3],
		Raw:     first,
	}
	l.line = 2
	return nil
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
func (l *Lexer) readWord(first rune) (string, error) {
	var b strings.Builder
	b.WriteRune(first)
	for {
		r, err := l.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("fortios lexer line %d: %w", l.line, err)
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
