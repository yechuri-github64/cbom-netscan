// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package tree builds a nested configuration tree from FortiOS lexer tokens
// and splits it into VDOM scopes.
//
//	t, err := tree.Parse(r)
//	for _, e := range t.Get(tree.ScopeSingle, "vpn ipsec phase1-interface") {
//	    if a := e.Attr("proposal"); a != nil { … a.Values … }
//	}
//
// Single-VDOM backups have one scope, ScopeSingle. Multi-VDOM backups have
// ScopeGlobal for "config global" plus one scope per VDOM name.
package tree

import (
	"io"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/lexer"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const (
	ScopeSingle = ""       // the only scope of a single-VDOM backup
	ScopeGlobal = "global" // "config global" in a multi-VDOM backup
)

// Attr is one "set <key> <values...>" or "unset <key>" line.
type Attr struct {
	Key    string
	Values []string // nil for unset; empty (not nil) for a set with no values
	Unset  bool
	Line   int
}

// Entry is one "edit <name>" … "next" table entry.
type Entry struct {
	Name   string
	Line   int
	Attrs  []*Attr  // in file order
	Blocks []*Block // nested config blocks, in file order
}

// Block is one "config <path>" … "end" block.
type Block struct {
	Path    string // path tokens joined by single spaces, e.g. "vpn ipsec phase1-interface"
	Line    int
	Attrs   []*Attr  // set/unset lines directly in the block, in file order
	Entries []*Entry // edit entries, in file order
	Blocks  []*Block // nested config blocks, in file order
}

// Attr returns the last set/unset line for key in the entry, or nil.
func (e *Entry) Attr(key string) *Attr { return lastAttr(e.Attrs, key) }

// Attr returns the last set/unset line for key directly in the block, or nil.
func (b *Block) Attr(key string) *Attr { return lastAttr(b.Attrs, key) }

func lastAttr(attrs []*Attr, key string) *Attr {
	for i := len(attrs) - 1; i >= 0; i-- {
		if attrs[i].Key == key {
			return attrs[i]
		}
	}
	return nil
}

// Tree is a parsed backup split into VDOM scopes.
type Tree struct {
	Header *lexer.ConfigHeader
	// VDOMMode is the effective mode: the header's, or the detected one
	// when the header did not say (VDOMModeDetected is then true).
	VDOMMode         lexer.VDOMMode
	VDOMModeDetected bool
	Warnings         []model.Warning

	scopes map[string][]*Block
	order  []string
}

// Parse lexes r and builds the scoped tree. Errors carry line numbers.
func Parse(r io.Reader) (*Tree, error) {
	l, err := lexer.New(r)
	if err != nil {
		return nil, err
	}
	roots, buildWarns, err := build(l)
	if err != nil {
		return nil, err
	}
	t := &Tree{
		Header: l.Header,
		// Copied after build: the lexer can add warnings while tokenizing,
		// e.g. for a #private-encryption-key= line later in the file.
		Warnings: append(append([]model.Warning(nil), l.Warnings...), buildWarns...),
		scopes:   map[string][]*Block{},
	}
	if err := t.assignScopes(roots); err != nil {
		return nil, err
	}
	return t, nil
}

// Scopes returns the scope names in the order they first appear in the file.
func (t *Tree) Scopes() []string { return append([]string(nil), t.order...) }

// Roots returns the top-level config blocks of a scope, in file order.
func (t *Tree) Roots(scope string) []*Block { return t.scopes[scope] }

// Blocks returns the top-level blocks of scope whose path matches, in file
// order. Extra whitespace in path is ignored.
func (t *Tree) Blocks(scope, path string) []*Block {
	p := strings.Join(strings.Fields(path), " ")
	var out []*Block
	for _, b := range t.scopes[scope] {
		if b.Path == p {
			out = append(out, b)
		}
	}
	return out
}

// Get returns the edit entries of every top-level block in scope with the
// given path, in file order.
func (t *Tree) Get(scope, path string) []*Entry {
	var out []*Entry
	for _, b := range t.Blocks(scope, path) {
		out = append(out, b.Entries...)
	}
	return out
}

func (t *Tree) add(scope string, blocks ...*Block) {
	if _, ok := t.scopes[scope]; !ok {
		t.order = append(t.order, scope)
		t.scopes[scope] = []*Block{}
	}
	t.scopes[scope] = append(t.scopes[scope], blocks...)
}

func (t *Tree) warn(line int, symbol, code, msg string) {
	t.Warnings = append(t.Warnings, model.Warning{
		Code:    code,
		Message: msg,
		Ev:      model.Evidence{Line: line, Symbol: symbol},
	})
}
