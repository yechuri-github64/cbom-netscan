// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package tree_test

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).
// They resemble FortiOS backup syntax but contain no real device data.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/lexer"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
)

const (
	hdrSingle  = "#config-version=FGT80F-7.4.12-FW-build0318-220920:opmode=0:vdom=0:user=admin\n"
	hdrMulti   = "#config-version=FGT200F-8.0.1-FW-build1500-260101:opmode=0:vdom=1:user=admin\n"
	hdrUnknown = "#config-version=FGT60F-7.6.7-FW-build0999-260601\n"
)

// multiBody is a multi-VDOM layout: declarations, config global, then one
// config vdom block per VDOM. Line 2 is its first line.
const multiBody = `config vdom
edit root
next
edit dmz
next
end
config global
config system global
    set hostname "fw01"
end
end
config vdom
edit root
config vpn ipsec phase1-interface
    edit "root-vpn"
        set ike-version 2
    next
end
next
edit dmz
config vpn ipsec phase1-interface
    edit "dmz-vpn"
        set ike-version 1
    next
end
next
end
`

const multiDump = `scope "root"
config vpn ipsec phase1-interface @15
  edit "root-vpn" @16
    set ike-version ["2"] @17
scope "dmz"
config vpn ipsec phase1-interface @22
  edit "dmz-vpn" @23
    set ike-version ["1"] @24
scope "global"
config system global @9
  set hostname ["fw01"] @10
`

var modeName = map[lexer.VDOMMode]string{
	lexer.VDOMUnknown: "unknown",
	lexer.VDOMSingle:  "single",
	lexer.VDOMMulti:   "multi",
}

// dump renders a tree as indented text so table cases can state the whole
// expected structure, including line numbers, in one string.
func dump(t *tree.Tree) string {
	var b strings.Builder
	var codes []string
	for _, w := range t.Warnings {
		codes = append(codes, fmt.Sprintf("%s@%d", w.Code, w.Ev.Line))
	}
	fmt.Fprintf(&b, "mode=%s detected=%v warnings=%v\n", modeName[t.VDOMMode], t.VDOMModeDetected, codes)
	for _, s := range t.Scopes() {
		fmt.Fprintf(&b, "scope %q\n", s)
		for _, blk := range t.Roots(s) {
			dumpBlock(&b, blk, "")
		}
	}
	return b.String()
}

func dumpBlock(b *strings.Builder, blk *tree.Block, ind string) {
	fmt.Fprintf(b, "%sconfig %s @%d\n", ind, blk.Path, blk.Line)
	dumpAttrs(b, blk.Attrs, ind+"  ")
	for _, c := range blk.Blocks {
		dumpBlock(b, c, ind+"  ")
	}
	for _, e := range blk.Entries {
		fmt.Fprintf(b, "%s  edit %q @%d\n", ind, e.Name, e.Line)
		dumpAttrs(b, e.Attrs, ind+"    ")
		for _, c := range e.Blocks {
			dumpBlock(b, c, ind+"    ")
		}
	}
}

func dumpAttrs(b *strings.Builder, attrs []*tree.Attr, ind string) {
	for _, a := range attrs {
		if a.Unset {
			fmt.Fprintf(b, "%sunset %s @%d\n", ind, a.Key, a.Line)
		} else {
			fmt.Fprintf(b, "%sset %s %q @%d\n", ind, a.Key, a.Values, a.Line)
		}
	}
}

func parse(t *testing.T, input string) *tree.Tree {
	t.Helper()
	tr, err := tree.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return tr
}

func TestParse(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string // dump without the first (mode/warnings) line
		head  string // the first dump line
	}{
		{
			name: "single_scope_basic",
			input: hdrSingle + `config system global
    set hostname "fw01"
    set admin-https-ssl-versions tlsv1-2 tlsv1-3
end
config vpn ipsec phase1-interface
    edit "vpn1"
        set proposal aes256-sha256 aes128-sha256
        set dhgrp 21 20
        unset keylife
        set comments ""
    next
    edit "vpn2"
        set ike-version 2
    next
end
`,
			head: "mode=single detected=false warnings=[]",
			want: `scope ""
config system global @2
  set hostname ["fw01"] @3
  set admin-https-ssl-versions ["tlsv1-2" "tlsv1-3"] @4
config vpn ipsec phase1-interface @6
  edit "vpn1" @7
    set proposal ["aes256-sha256" "aes128-sha256"] @8
    set dhgrp ["21" "20"] @9
    unset keylife @10
    set comments [""] @11
  edit "vpn2" @13
    set ike-version ["2"] @14
`,
		},
		{
			name: "nested_config_in_edit",
			input: hdrSingle + `config vpn ipsec phase1-interface
    edit "vpn1"
        set proposal aes256gcm-prfsha384
        config ipv4-exclude-range
            edit 1
                set start-ip 192.0.2.1
                set end-ip 192.0.2.9
            next
        end
        set dhgrp 20
    next
end
`,
			head: "mode=single detected=false warnings=[]",
			want: `scope ""
config vpn ipsec phase1-interface @2
  edit "vpn1" @3
    set proposal ["aes256gcm-prfsha384"] @4
    set dhgrp ["20"] @11
    config ipv4-exclude-range @5
      edit "1" @6
        set start-ip ["192.0.2.1"] @7
        set end-ip ["192.0.2.9"] @8
`,
		},
		{
			name: "nested_config_in_block",
			input: hdrSingle + `config router bgp
    set as 65001
    config neighbor
        edit "192.0.2.1"
            set remote-as 65002
        next
    end
end
`,
			head: "mode=single detected=false warnings=[]",
			want: `scope ""
config router bgp @2
  set as ["65001"] @3
  config neighbor @4
    edit "192.0.2.1" @5
      set remote-as ["65002"] @6
`,
		},
		{
			// Keywords after set are values; comments are skipped; a
			// multi-line PEM stays one value; no trailing newline at EOF.
			name: "keyword_values_comments_pem",
			input: hdrSingle + `# a comment
config firewall policy
    edit 1
        set action next
        set name end
    next
end
config vpn certificate local
    edit "c1"
        set certificate "-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----"
    next
end`,
			head: "mode=single detected=false warnings=[]",
			want: `scope ""
config firewall policy @3
  edit "1" @4
    set action ["next"] @5
    set name ["end"] @6
config vpn certificate local @9
  edit "c1" @10
    set certificate ["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"] @11
`,
		},
		{
			name:  "multi_vdom_declared",
			input: hdrMulti + multiBody,
			head:  "mode=multi detected=false warnings=[]",
			want:  multiDump,
		},
		{
			name:  "unknown_detects_multi",
			input: hdrUnknown + multiBody,
			head:  "mode=multi detected=true warnings=[vdom-mode-unknown@1]",
			want:  multiDump,
		},
		{
			name:  "unknown_detects_single",
			input: hdrUnknown + "config system global\n    set hostname fw01\nend\n",
			head:  "mode=single detected=true warnings=[vdom-mode-unknown@1]",
			want: `scope ""
config system global @2
  set hostname ["fw01"] @3
`,
		},
		{
			name:  "single_header_with_config_vdom",
			input: hdrSingle + "config vdom\nedit root\nnext\nend\n",
			head:  "mode=single detected=false warnings=[vdom-mode-conflict@2]",
			want: `scope ""
config vdom @2
  edit "root" @3
`,
		},
		{
			name:  "multi_stray_top_level_block",
			input: hdrMulti + "config system global\n    set hostname fw01\nend\n",
			head:  "mode=multi detected=false warnings=[unexpected-content@2]",
			want: `scope "global"
config system global @2
  set hostname ["fw01"] @3
`,
		},
		{
			// Documentation-style snippet: end straight after edit.
			name: "end_without_next_is_implied",
			input: hdrSingle + `config a
    edit "x"
        set k v
end
config b
end
`,
			head: "mode=single detected=false warnings=[implied-next@5]",
			want: `scope ""
config a @2
  edit "x" @3
    set k ["v"] @4
config b @6
`,
		},
		{
			// The implied next closes only the inner edit and its config;
			// the outer edit stays open and later lines still attach to it.
			name: "implied_next_in_nested_config",
			input: hdrSingle + `config vpn ipsec phase1-interface
    edit "vpn1"
        config ipv4-exclude-range
            edit 1
        end
        set dhgrp 20
    next
end
`,
			head: "mode=single detected=false warnings=[implied-next@6]",
			want: `scope ""
config vpn ipsec phase1-interface @2
  edit "vpn1" @3
    set dhgrp ["20"] @7
    config ipv4-exclude-range @4
      edit "1" @5
`,
		},
		{
			// The key line is not right after the header, so the lexer
			// drops it while tokenizing; its warning must still reach Tree.
			name:  "private_key_warning_reaches_tree",
			input: hdrSingle + "# note\n#private-encryption-key=c3ludGhldGlj\nconfig a\nend\n",
			head:  "mode=single detected=false warnings=[opaque-secrets@3]",
			want: `scope ""
config a @4
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dump(parse(t, tc.input))
			want := tc.head + "\n" + tc.want
			if got != want {
				t.Errorf("tree mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
			}
		})
	}
}

func TestParse_Errors(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
		notWant string // must not appear in the error
	}{
		{"end_without_config", hdrSingle + "end\n", "line 2: end without a matching config", ""},
		{"next_at_top_level", hdrSingle + "next\n", "line 2: next without a matching edit", ""},
		{"next_in_config_without_edit", hdrSingle + "config a\nnext\n", `line 3: next without a matching edit (inside config "a" from line 2)`, ""},
		{"edit_outside_config", hdrSingle + "edit x\n", "line 2: edit outside a config block", ""},
		{"edit_inside_edit", hdrSingle + "config a\nedit x\nedit y\n", `line 4: edit inside edit "x" (line 3); missing next`, ""},
		{"edit_two_names", hdrSingle + "config a\nedit x y\n", "line 3: edit needs exactly one name, got 2", ""},
		{"set_outside_config", hdrSingle + "set a b\n", "line 2: set outside a config block", ""},
		{"set_without_key", hdrSingle + "config a\nset\nend\n", "line 3: set without a field name", ""},
		{"unset_with_value", hdrSingle + "config a\nunset k v\nend\n", "line 3: unset takes only a field name", ""},
		{"config_without_path", hdrSingle + "config\n", "line 2: config without a path", ""},
		{"next_with_args", hdrSingle + "config a\nedit x\nnext x\n", "line 4: next takes no arguments", ""},
		{"end_with_args", hdrSingle + "config a\nend now\n", "line 3: end takes no arguments", ""},
		{"stray_quoted_value", hdrSingle + "config a\n\"s3cr3t-value\" more\nend\n", "line 3: unexpected quoted string", "s3cr3t"},
		{"stray_word", hdrSingle + "config a\ns3cr3t-word\nend\n", "line 3: unexpected word", "s3cr3t"},
		{"eof_open_config", hdrSingle + "config a\n", `unexpected end of file: config "a" (line 2) has no end`, ""},
		{"eof_open_edit", hdrSingle + "config a\nedit x\n", `unexpected end of file: edit "x" (line 3) has no next`, ""},
		{"eof_open_nested", hdrSingle + "config a\nedit x\nconfig b\n", `unexpected end of file: config "b" (line 4) has no end`, ""},
		{"lexer_error_propagates", hdrSingle + "config a\nset k \"open\n", "unterminated double-quoted string starting at line 3", ""},
		{"bad_header_propagates", "not a backup\n", "not a FortiOS config backup", ""},
		{"reserved_vdom_name", hdrMulti + "config vdom\nedit global\nnext\nend\n", `line 3: vdom name "global" is reserved`, ""},
		{"empty_vdom_name", hdrMulti + "config vdom\nedit \"\"\nnext\nend\n", `line 3: vdom name "" is reserved`, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tree.Parse(strings.NewReader(tc.input))
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err, tc.wantErr)
			}
			if tc.notWant != "" && strings.Contains(err.Error(), tc.notWant) {
				t.Errorf("error %q leaks %q", err, tc.notWant)
			}
		})
	}
}

func TestGet(t *testing.T) {
	tr := parse(t, hdrSingle+`config system global
    set hostname old
    set hostname fw01
    unset timezone
end
config vpn ipsec phase1-interface
    edit "a"
    next
    edit "b"
    next
end
config firewall address
end
config vpn ipsec phase1-interface
    edit "c"
    next
end
`)

	var names []string
	for _, e := range tr.Get(tree.ScopeSingle, "  vpn   ipsec phase1-interface ") {
		names = append(names, e.Name)
	}
	if got := strings.Join(names, ","); got != "a,b,c" {
		t.Errorf("Get entries = %s, want a,b,c (file order across repeated blocks)", got)
	}

	if got := tr.Get(tree.ScopeSingle, "vpn ipsec phase2-interface"); got != nil {
		t.Errorf("Get unknown path = %v, want nil", got)
	}
	if got := tr.Get("no-such-scope", "vpn ipsec phase1-interface"); got != nil {
		t.Errorf("Get unknown scope = %v, want nil", got)
	}

	g := tr.Blocks(tree.ScopeSingle, "system global")
	if len(g) != 1 {
		t.Fatalf("Blocks(system global) = %d blocks, want 1", len(g))
	}
	if a := g[0].Attr("hostname"); a == nil || fmt.Sprint(a.Values) != "[fw01]" || a.Line != 4 {
		t.Errorf("Attr(hostname) = %+v, want last set: [fw01] on line 4", a)
	}
	if a := g[0].Attr("timezone"); a == nil || !a.Unset || a.Values != nil {
		t.Errorf("Attr(timezone) = %+v, want unset with nil Values", a)
	}
	if a := g[0].Attr("missing"); a != nil {
		t.Errorf("Attr(missing) = %+v, want nil", a)
	}
	if got := tr.Scopes(); len(got) != 1 || got[0] != tree.ScopeSingle {
		t.Errorf("Scopes = %q, want [\"\"]", got)
	}
}

func TestGet_MultiVDOMScopes(t *testing.T) {
	tr := parse(t, hdrMulti+multiBody)

	if got := fmt.Sprintf("%q", tr.Scopes()); got != `["root" "dmz" "global"]` {
		t.Errorf("Scopes = %s, want [root dmz global]", got)
	}
	for scope, want := range map[string]string{"root": "root-vpn", "dmz": "dmz-vpn"} {
		es := tr.Get(scope, "vpn ipsec phase1-interface")
		if len(es) != 1 || es[0].Name != want {
			t.Errorf("Get(%q) = %v, want one entry %q", scope, es, want)
		}
	}
	if es := tr.Get(tree.ScopeGlobal, "vpn ipsec phase1-interface"); es != nil {
		t.Errorf("phase1 leaked into global scope: %v", es)
	}
	if bs := tr.Blocks(tree.ScopeGlobal, "system global"); len(bs) != 1 {
		t.Errorf("Blocks(global, system global) = %d, want 1", len(bs))
	}
}
