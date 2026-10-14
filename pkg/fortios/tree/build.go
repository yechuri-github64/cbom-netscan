// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package tree

import (
	"fmt"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/lexer"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

// frame is one open config block or edit entry on the parse stack.
// Exactly one of block and entry is set.
type frame struct {
	block *Block
	entry *Entry
}

func errAt(line int, format string, args ...any) error {
	return fmt.Errorf("fortios tree: line %d: %s", line, fmt.Sprintf(format, args...))
}

// nextToken returns the next token that is not a comment.
func nextToken(l *lexer.Lexer) (lexer.Token, error) {
	for {
		tok, err := l.Next()
		if err != nil || tok.Kind != lexer.TokComment {
			return tok, err
		}
	}
}

// build turns the token stream into top-level blocks.
//
// The lexer emits no newline tokens, so a statement is its keyword plus every
// following token that starts on the same line. That keeps "set action next"
// as a value instead of a next statement, and lets a multi-line PEM value,
// which starts on the set line, stay part of its set.
//
// An explicit stack is used instead of recursion so deeply nested input
// cannot exhaust the goroutine stack.
//
// Errors never quote attribute values or stray tokens, only keywords, config
// paths and edit names, so a malformed secret cannot end up in an error.
func build(l *lexer.Lexer) ([]*Block, []model.Warning, error) {
	var roots []*Block
	var stack []frame
	var warns []model.Warning

	tok, err := nextToken(l)
	for {
		if err != nil {
			return nil, nil, fmt.Errorf("fortios tree: %w", err)
		}
		if tok.Kind == lexer.TokEOF {
			break
		}

		kw, line := tok, tok.Line
		var args []string
		for {
			tok, err = nextToken(l)
			if err != nil || tok.Kind == lexer.TokEOF || tok.Line != line {
				break
			}
			args = append(args, tok.Value)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("fortios tree: %w", err)
		}

		var top *frame
		if len(stack) > 0 {
			top = &stack[len(stack)-1]
		}

		switch kw.Kind {
		case lexer.TokConfig:
			if len(args) == 0 {
				return nil, nil, errAt(line, "config without a path")
			}
			b := &Block{Path: strings.Join(args, " "), Line: line}
			switch {
			case top == nil:
				roots = append(roots, b)
			case top.entry != nil:
				top.entry.Blocks = append(top.entry.Blocks, b)
			default:
				top.block.Blocks = append(top.block.Blocks, b)
			}
			stack = append(stack, frame{block: b})

		case lexer.TokEdit:
			switch {
			case top == nil:
				return nil, nil, errAt(line, "edit outside a config block")
			case top.entry != nil:
				return nil, nil, errAt(line, "edit inside edit %q (line %d); missing next", top.entry.Name, top.entry.Line)
			case len(args) != 1:
				return nil, nil, errAt(line, "edit needs exactly one name, got %d", len(args))
			}
			e := &Entry{Name: args[0], Line: line}
			top.block.Entries = append(top.block.Entries, e)
			stack = append(stack, frame{entry: e})

		case lexer.TokSet, lexer.TokUnset:
			unset := kw.Kind == lexer.TokUnset
			switch {
			case top == nil:
				return nil, nil, errAt(line, "%s outside a config block", kw.Value)
			case len(args) == 0:
				return nil, nil, errAt(line, "%s without a field name", kw.Value)
			case unset && len(args) > 1:
				return nil, nil, errAt(line, "unset takes only a field name")
			}
			a := &Attr{Key: args[0], Line: line, Unset: unset}
			if !unset {
				a.Values = append([]string{}, args[1:]...)
			}
			if top.entry != nil {
				top.entry.Attrs = append(top.entry.Attrs, a)
			} else {
				top.block.Attrs = append(top.block.Attrs, a)
			}

		case lexer.TokNext:
			switch {
			case len(args) > 0:
				return nil, nil, errAt(line, "next takes no arguments")
			case top == nil:
				return nil, nil, errAt(line, "next without a matching edit")
			case top.block != nil:
				return nil, nil, errAt(line, "next without a matching edit (inside config %q from line %d)", top.block.Path, top.block.Line)
			}
			stack = stack[:len(stack)-1]

		case lexer.TokEnd:
			switch {
			case len(args) > 0:
				return nil, nil, errAt(line, "end takes no arguments")
			case top == nil:
				return nil, nil, errAt(line, "end without a matching config")
			}
			// Real backups always write next, but documentation examples and
			// hand-edited snippets often go straight to end. Treat it as an
			// implied next: close the edit, then the config block around it.
			if top.entry != nil {
				warns = append(warns, model.Warning{
					Code:    "implied-next",
					Message: fmt.Sprintf("end closes edit %q (line %d) without a next; treated as next then end", top.entry.Name, top.entry.Line),
					Ev:      model.Evidence{Line: line, Symbol: "edit " + top.entry.Name},
				})
				stack = stack[:len(stack)-1]
			}
			stack = stack[:len(stack)-1]

		case lexer.TokString:
			return nil, nil, errAt(line, "unexpected quoted string; expected config, edit, set, unset, next, or end")
		default:
			return nil, nil, errAt(line, "unexpected word; expected config, edit, set, unset, next, or end")
		}
	}

	if len(stack) > 0 {
		f := stack[len(stack)-1]
		if f.entry != nil {
			return nil, nil, fmt.Errorf("fortios tree: unexpected end of file: edit %q (line %d) has no next", f.entry.Name, f.entry.Line)
		}
		return nil, nil, fmt.Errorf("fortios tree: unexpected end of file: config %q (line %d) has no end", f.block.Path, f.block.Line)
	}
	return roots, warns, nil
}
