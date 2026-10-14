// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package tree

import (
	"fmt"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/lexer"
)

// assignScopes places the top-level blocks into scopes according to the
// VDOM mode. When the header did not declare a mode, a top-level
// "config vdom" block means multi-VDOM; otherwise the file is single-VDOM.
// The lexer's vdom-mode-unknown warning is kept in that case.
//
// Multi-VDOM layout (research notes §1.3):
//
//	config vdom / edit root / next / end      VDOM declarations
//	config global / config system … / end      global scope
//	config vdom / edit root / config … / next  per-VDOM scope
func (t *Tree) assignScopes(roots []*Block) error {
	mode := t.Header.VDOMMode
	if mode == lexer.VDOMUnknown {
		t.VDOMModeDetected = true
		mode = lexer.VDOMSingle
		for _, b := range roots {
			if b.Path == "vdom" {
				mode = lexer.VDOMMulti
				break
			}
		}
	}
	t.VDOMMode = mode

	if mode == lexer.VDOMSingle {
		if !t.VDOMModeDetected {
			for _, b := range roots {
				if b.Path == "vdom" || b.Path == "global" {
					t.warn(b.Line, "config "+b.Path, "vdom-mode-conflict",
						"header declares single-VDOM (vdom=0) but the file has a top-level config "+b.Path+" block; it is kept as an ordinary block")
				}
			}
		}
		t.add(ScopeSingle, roots...)
		return nil
	}

	for _, b := range roots {
		switch b.Path {
		case "global":
			if len(b.Attrs) > 0 || len(b.Entries) > 0 {
				t.warn(b.Line, "config global", "unexpected-content",
					"config global has set or edit lines directly inside it; they are ignored")
			}
			t.add(ScopeGlobal, b.Blocks...)
		case "vdom":
			if len(b.Attrs) > 0 || len(b.Blocks) > 0 {
				t.warn(b.Line, "config vdom", "unexpected-content",
					"config vdom has set or config lines outside an edit; they are ignored")
			}
			for _, e := range b.Entries {
				if e.Name == ScopeSingle || e.Name == ScopeGlobal {
					return fmt.Errorf("fortios tree: line %d: vdom name %q is reserved", e.Line, e.Name)
				}
				if len(e.Attrs) > 0 {
					t.warn(e.Line, "config vdom", "unexpected-content",
						fmt.Sprintf("edit %q in config vdom has set lines directly inside it; they are ignored", e.Name))
				}
				t.add(e.Name, e.Blocks...)
			}
		default:
			t.warn(b.Line, "config "+b.Path, "unexpected-content",
				"top-level config block outside config global and config vdom in a multi-VDOM backup; placed in the global scope")
			t.add(ScopeGlobal, b)
		}
	}
	return nil
}
