// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

const repo = "yechuri-github64/cbom-netscan"

func changelog(section string) string {
	return "# Changelog\n\nIntro.\n\n## [9.9.9] - 2026-10-20\n" + section + "\n## [9.9.8] - 2026-10-01\n\nOlder.\n"
}

func TestNotesErrors(t *testing.T) {
	for name, tc := range map[string]struct{ changelog, want string }{
		"missing":    {changelog("\nText.\n"), "no section for 1.0.0"},
		"unreleased": {"## [1.0.0] - Unreleased\n\nText.\n", "still marks 1.0.0 as Unreleased"},
		"empty":      {"## [1.0.0] - 2026-10-20\n\n\n## [0.9.0] - 2026-01-01\n", "empty or only names the tag"},
		"tag only":   {"## [1.0.0] - 2026-10-20\n\nv1.0.0\n", "empty or only names the tag"},
	} {
		if _, err := notes(tc.changelog, "v1.0.0", repo); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// TestNotes: wrapped lines are joined, relative links become absolute
// outside code and <...> spans, and code blocks are kept as they are.
func TestNotes(t *testing.T) {
	in := changelog(`
A paragraph that is
wrapped over three
lines, with [MAPPING.md
section 7](MAPPING.md#7-limits).

### Fixed

- A list item that wraps
  onto a second line.
  - A nested item
    that wraps too.
- Inline code ` + "`[x](a.md)`" + ` and ` + "``[y](b.md)``" + ` stay; [docs](./docs/a.md "Docs") moves.
- Kept: [anchor](#here), [site](https://example.com/a.md), [abs](/root.md),
  [spaces](<docs/a b.md>), <https://example.org>, [ref][r].

` + "```sh" + `
cbom-netscan fortios fw.conf -o out.cdx.json
see [x](a.md)
` + "```" + `

    indented code
    [y](b.md)

[r]: docs/research.md
[abs-ref]: https://example.com/x
`)
	got, err := notes(in, "v9.9.9", repo)
	if err != nil {
		t.Fatal(err)
	}
	base := "https://github.com/" + repo + "/blob/v9.9.9/"
	want := "A paragraph that is wrapped over three lines, with [MAPPING.md section 7](" + base + "MAPPING.md#7-limits).\n" +
		"\n### Fixed\n\n" +
		"- A list item that wraps onto a second line.\n" +
		"  - A nested item that wraps too.\n" +
		"- Inline code `[x](a.md)` and ``[y](b.md)`` stay; [docs](" + base + "docs/a.md \"Docs\") moves.\n" +
		"- Kept: [anchor](#here), [site](https://example.com/a.md), [abs](/root.md), [spaces](<docs/a b.md>), <https://example.org>, [ref][r].\n" +
		"\n```sh\ncbom-netscan fortios fw.conf -o out.cdx.json\nsee [x](a.md)\n```\n" +
		"\n    indented code\n    [y](b.md)\n" +
		"\n[r]: " + base + "docs/research.md\n" +
		"[abs-ref]: https://example.com/x\n"
	if got != want {
		t.Errorf("notes =\n%s\nwant\n%s", got, want)
	}
}

// TestNotesCRLF: a changelog with Windows line endings gives the same notes.
func TestNotesCRLF(t *testing.T) {
	in := changelog("\nLine one\nline two.\n")
	a, err1 := notes(in, "v9.9.9", repo)
	b, err2 := notes(strings.ReplaceAll(in, "\n", "\r\n"), "v9.9.9", repo)
	if err1 != nil || err2 != nil || a != b || a != "Line one line two.\n" {
		t.Errorf("LF %q (%v), CRLF %q (%v)", a, err1, b, err2)
	}
}

// TestRealChangelog: every dated section of CHANGELOG.md gives notes with no
// relative link left and no wrapped list item.
func TestRealChangelog(t *testing.T) {
	data, err := os.ReadFile("../../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(l, "## [") || strings.Contains(l, "Unreleased") {
			continue
		}
		version := strings.TrimPrefix(strings.SplitN(l, "]", 2)[0], "## [")
		got, err := notes(string(data), "v"+version, repo)
		if err != nil {
			t.Errorf("%s: %v", version, err)
			continue
		}
		n++
		for _, link := range inlineLinkRE.FindAllString(got, -1) {
			t.Errorf("%s: relative link left: %s", version, link)
		}
		for _, line := range strings.Split(got, "\n") {
			if strings.HasPrefix(line, "  ") && !strings.HasPrefix(strings.TrimSpace(line), "-") {
				t.Errorf("%s: unjoined continuation line: %q", version, line)
			}
		}
	}
	if n == 0 {
		t.Fatal("no dated section in CHANGELOG.md")
	}
}
