// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Command releasenotes prints the GitHub release notes for a tag: the
// version's section of CHANGELOG.md, ready to be a release body.
//
//	go run ./internal/tools/releasenotes vX.Y.Z OWNER/REPO [CHANGELOG.md]
//
// It is used by .github/workflows/release.yml. Compared with the changelog
// text it:
//
//   - joins the wrapped lines of each paragraph and list item into one line,
//     because GitHub shows every newline in a release body as a line break;
//   - rewrites relative links to absolute
//     https://github.com/OWNER/REPO/blob/vX.Y.Z/... URLs, since the release
//     page is not in the repository tree, but not inside code (fenced blocks
//     or inline code spans) or <...> spans;
//   - fails if the section is missing, still marked Unreleased, or empty
//     apart from the tag name.
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintln(os.Stderr, "usage: releasenotes vX.Y.Z OWNER/REPO [CHANGELOG.md]")
		os.Exit(2)
	}
	path := "CHANGELOG.md"
	if len(os.Args) == 4 {
		path = os.Args[3]
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "::error::"+err.Error())
		os.Exit(1)
	}
	out, err := notes(string(data), os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "::error::"+err.Error())
		os.Exit(1)
	}
	fmt.Print(out)
}

// notes returns the release notes for tag from changelog (see the package
// documentation), ending in one newline.
func notes(changelog, tag, repo string) (string, error) {
	version := strings.TrimPrefix(tag, "v")
	section, heading, ok := extract(changelog, version)
	switch {
	case !ok:
		return "", fmt.Errorf("the changelog has no section for %s", version)
	case strings.Contains(heading, "Unreleased"):
		return "", fmt.Errorf("the changelog still marks %s as Unreleased; set the release date first", version)
	}
	base := "https://github.com/" + repo + "/blob/" + tag + "/"
	var out []string
	for _, l := range unwrap(section) {
		if !l.code {
			l.text = rewriteLinks(l.text, base)
		}
		out = append(out, l.text)
	}
	body := strings.Trim(strings.Join(out, "\n"), "\n")
	if t := strings.Join(strings.Fields(body), ""); t == "" || t == tag || t == version {
		return "", fmt.Errorf("the %s section of the changelog is empty or only names the tag", version)
	}
	return body + "\n", nil
}

// extract returns the lines after the "## [version]" heading, up to the next
// "## [" heading, and the heading itself.
func extract(changelog, version string) (lines []string, heading string, ok bool) {
	for _, l := range strings.Split(strings.ReplaceAll(changelog, "\r\n", "\n"), "\n") {
		switch {
		case !ok && strings.HasPrefix(l, "## ["+version+"]"):
			ok, heading = true, l
		case ok && strings.HasPrefix(l, "## ["):
			return lines, heading, true
		case ok:
			lines = append(lines, l)
		}
	}
	return lines, heading, ok
}

// line is one output line; code lines are copied as they are.
type line struct {
	text string
	code bool
}

var (
	fenceRE    = regexp.MustCompile("^ {0,3}(```+|~~~+)")
	listItemRE = regexp.MustCompile(`^\s*([-*+]|\d+[.)])\s+`)
	// Lines that start a block of their own and are never joined to the
	// line before or after: headings, quotes, tables, HTML, link reference
	// definitions, and thematic breaks.
	blockRE = regexp.MustCompile(`^ {0,3}(#{1,6}(\s|$)|>|\||<|\[[^\]]+\]:\s|([-*_])(\s*[-*_]){2,}\s*$)`)
)

// unwrap joins the wrapped lines of paragraphs and list items. Fenced code
// blocks, indented code after a blank line, and lines matching blockRE are
// kept as they are.
func unwrap(in []string) []line {
	var out []line
	fence := ""       // the open code fence, if any
	joinable := false // the last output line is paragraph or list item text
	for _, l := range in {
		trimmed := strings.TrimSpace(l)
		switch {
		case fence != "":
			out = append(out, line{l, true})
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
			}
			joinable = false
		case fenceRE.MatchString(l):
			fence = fenceRE.FindStringSubmatch(l)[1]
			out = append(out, line{l, true})
			joinable = false
		case trimmed == "":
			out = append(out, line{"", false})
			joinable = false
		case strings.HasPrefix(l, "    ") && !joinable:
			out = append(out, line{l, true}) // indented code block
		case listItemRE.MatchString(l):
			out = append(out, line{strings.TrimRight(l, " \t"), false})
			joinable = true
		case blockRE.MatchString(l):
			out = append(out, line{strings.TrimRight(l, " \t"), false})
			joinable = false
		case joinable:
			out[len(out)-1].text += " " + trimmed
		default:
			out = append(out, line{strings.TrimRight(l, " \t"), false})
			joinable = true
		}
	}
	return out
}

var (
	// An inline link to a relative target: ](path) or ](path "title").
	// Targets with a scheme (they contain ":"), anchors ("#..."), absolute
	// paths ("/..."), and <...> destinations are not relative.
	inlineLinkRE = regexp.MustCompile(`\]\((\./)?([^)\s#:/<][^)\s:]*)((?:\s+"[^"]*")?\))`)
	// A link reference definition with a relative target.
	// The target must end at whitespace or the end of the line, so a URL
	// with a scheme is not taken for a relative path ending at its ":".
	refDefRE = regexp.MustCompile(`^( {0,3}\[[^\]]+\]:\s+)(\./)?([^\s#:/<][^\s:]*)(\s|$)`)
)

// rewriteLinks makes relative link targets in s absolute under base, outside
// inline code and <...> spans.
func rewriteLinks(s, base string) string {
	if refDefRE.MatchString(s) {
		return refDefRE.ReplaceAllString(s, "${1}"+base+"${3}${4}")
	}
	repl := "](" + base + "$2$3"
	var b strings.Builder
	last := 0
	for _, sp := range protectedSpans(s) {
		b.WriteString(inlineLinkRE.ReplaceAllString(s[last:sp[0]], repl))
		b.WriteString(s[sp[0]:sp[1]])
		last = sp[1]
	}
	b.WriteString(inlineLinkRE.ReplaceAllString(s[last:], repl))
	return b.String()
}

// protectedSpans returns the byte ranges of s that links are not rewritten
// in: inline code spans (a run of backticks up to the next run of the same
// length, as in CommonMark) and <...> spans without spaces (autolinks,
// angle-bracket link destinations, HTML tags).
func protectedSpans(s string) [][2]int {
	var spans [][2]int
	for i := 0; i < len(s); {
		switch s[i] {
		case '`':
			n := run(s, i)
			end := -1
			for j := i + n; j < len(s); {
				if s[j] != '`' {
					j++
					continue
				}
				if m := run(s, j); m == n {
					end = j + m
					break
				} else {
					j += m
				}
			}
			if end < 0 { // no closing run: the backticks are literal
				i += n
				continue
			}
			spans = append(spans, [2]int{i, end})
			i = end
		case '<':
			j := i + 1
			for j < len(s) && s[j] != '>' && s[j] != '<' && s[j] != ' ' && s[j] != '\t' {
				j++
			}
			if j < len(s) && s[j] == '>' {
				spans = append(spans, [2]int{i, j + 1})
				i = j + 1
				continue
			}
			i++
		default:
			i++
		}
	}
	return spans
}

// run is the number of backticks starting at s[i].
func run(s string, i int) int {
	n := 0
	for i+n < len(s) && s[i+n] == '`' {
		n++
	}
	return n
}
