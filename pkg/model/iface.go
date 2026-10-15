// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"io"
)

// Source is one input artefact — a config backup file or a testssl.sh JSON.
// Path is used only for evidence.occurrences[].location; it is never read
// by the model package itself.
type Source struct {
	Path   string    // file path or "host:port"; used in Evidence.Location
	Kind   string    // "fortios-config" | "testssl-json"
	Reader io.Reader // consumed exactly once by the Parser
}

// Parser[T] turns a Source into a vendor-specific intermediate tree T.
// It must never return secret values — they must be replaced with
// the string "[REDACTED]" at parse time so later stages cannot leak them.
type Parser[T any] interface {
	Parse(ctx context.Context, src Source) (T, []Warning, error)
}

// Collector turns a Source into a vendor-neutral Inventory.
// Accepts() is a cheap sniff (header bytes, JSON shape) and must not
// consume src.Reader.
type Collector interface {
	Name() string            // "fortigate" | "testssl"
	Accepts(src Source) bool // cheap sniff, does not consume Reader
	Collect(ctx context.Context, src Source) (*Inventory, error)
}

// Assessor evaluates an Inventory against a policy profile.
// It must not mutate the Inventory (assessment is separate from scanning,
// per cbomkit-theia #149 discussion).
type Assessor interface {
	ID() string // "certin-t9" | "pqc" | "certlife"
	Assess(ctx context.Context, inv *Inventory) ([]Finding, error)
}

// Emitter serialises an Inventory to a writer.
type Emitter interface {
	Format() string // "cyclonedx-1.6-json"
	Emit(ctx context.Context, w io.Writer, inv *Inventory, meta Meta) error
}

// Warning is a non-fatal issue produced during parsing or collection.
type Warning struct {
	// Code is a machine-readable identifier, such as "unknown-token" or
	// "vdom-mode-conflict". MAPPING.md §5 lists every code with its meaning;
	// add a new code there when it is introduced.
	Code    string
	Message string
	Ev      Evidence
}

// Finding is one result from an Assessor.
type Finding struct {
	Rule    string // e.g. "certin-t9/certificates/not-valid-after"
	AssetID string // bom-ref of the assessed asset
	// Outcome values: present|missing|not-applicable|not-derivable-offline|pass|fail
	Outcome string
	// Severity values: info|low|medium|high
	Severity string
	Detail   string
	Source   string // URL of the normative rule source
}
