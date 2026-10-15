// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// terminalSafe returns s with every character a terminal could act on
// escaped: control characters (including ESC, so no ANSI escape sequence gets
// through), other non-printable runes such as bidirectional overrides, and
// invalid UTF-8. Printable text, including non-ASCII letters, is unchanged.
//
// Everything cbom-netscan writes to stderr goes through it. Warnings name
// tunnels, certificates, and files, which come from the backup or the command
// line; a crafted name must not be able to rewrite the terminal or hide text.
func terminalSafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString(`\x` + strconv.FormatUint(uint64(s[i]), 16))
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			// '\x1b', '\u202e', ... without the quotes.
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
		}
		i += size
	}
	return b.String()
}
