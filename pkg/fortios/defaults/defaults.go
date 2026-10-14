// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package defaults holds FortiOS firmware default values, one JSON table per
// release line, embedded at build time.
//
// A table lists the exact versions it covers. A version that is not listed,
// such as 7.4.8 when only 7.4.12 was checked against the docs, has no table;
// callers must report those fields as unknown rather than borrow a
// neighbouring version's defaults (research notes §8.1).
package defaults

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
)

//go:embed *.json
var files embed.FS

// Field is one default value and the document it was taken from.
type Field struct {
	Value  []string `json:"value"` // space-separated tokens as the CLI writes them
	Source string   `json:"source"`
}

// Table is the defaults for one FortiOS release line.
type Table struct {
	Name     string                      `json:"table"`    // e.g. "7.6"
	Versions []string                    `json:"versions"` // exact versions covered, e.g. "7.6.7"
	Sections map[string]map[string]Field `json:"sections"` // config path → field → default
}

// Field returns the default for field in the config section, e.g.
// ("system ssh-config", "ssh-kex-algo").
func (t *Table) Field(section, field string) (Field, bool) {
	f, ok := t.Sections[section][field]
	return f, ok
}

// The embedded files are part of the binary, so a malformed one is a build
// defect; defaults_test.go loads them so it fails in CI, not at run time.
var tables = mustLoad()

func mustLoad() []*Table {
	ts, err := load(files)
	if err != nil {
		panic(err)
	}
	return ts
}

func load(fsys fs.FS) ([]*Table, error) {
	names, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	seen := map[string]string{}
	var out []*Table
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var t Table
		if err := dec.Decode(&t); err != nil {
			return nil, fmt.Errorf("defaults %s: %w", name, err)
		}
		for _, v := range t.Versions {
			if prev, ok := seen[v]; ok {
				return nil, fmt.Errorf("defaults: version %s is in both %s and %s", v, prev, name)
			}
			seen[v] = name
		}
		out = append(out, &t)
	}
	return out, nil
}

// ForVersion returns the table that lists version exactly, or nil.
func ForVersion(version string) *Table {
	for _, t := range tables {
		for _, v := range t.Versions {
			if v == version {
				return t
			}
		}
	}
	return nil
}

// Tables returns every embedded table.
func Tables() []*Table { return append([]*Table(nil), tables...) }
