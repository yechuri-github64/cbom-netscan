// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package field resolves one FortiOS config field to a value and records
// where the value came from. It is shared by the FortiOS extractors so they
// all report provenance the same way:
//
//	cbom-netscan:fortios:<field>:source          configured | default | unknown
//	cbom-netscan:fortios:<field>:line            set when configured (plus an evidence occurrence)
//	cbom-netscan:fortios:defaults-table          table name when any value is a default, e.g. "7.6"
//	cbom-netscan:fortios:<field>:default-source  the document the default came from
//	cbom-netscan:fortios:<field>:default-note    a caveat on that default, if any
//	cbom-netscan:fortios:<field>:unknown-reason  set when the docs give no default
//	cbom-netscan:fortios:<field>:value           the tokens, for fields recorded with their value
package field

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/defaults"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

const (
	Configured = "configured"
	Default    = "default"
	Unknown    = "unknown"

	Prefix = "cbom-netscan:fortios:"
)

// Spec says which configured tokens may reach the CBOM.
//
// Known tokens are kept. An unknown token that matches Pattern is kept and
// flagged (new firmware may add options); with Freeform set it is kept
// silently, for names such as certificates. Anything else is dropped without
// being echoed in the warning, so stray secret text never reaches output.
type Spec struct {
	Known    map[string]bool
	Pattern  *regexp.Regexp // nil: unknown tokens are always dropped
	Freeform bool
}

// Value is one resolved field.
type Value struct {
	Field   string // property name, e.g. "dhgrp"
	Symbol  string // evidence symbol, e.g. "vpn ipsec phase1-interface/vpn1/dhgrp"
	Context string // evidence context, e.g. "vdom root"; never a secret
	Tokens  []string
	Source  string
	Line    int            // set when Source is Configured
	Default defaults.Field // set when Source is Default, or Unknown because undocumented
}

// MarkConfiguredView records that a protocol component shows the configured
// settings, not what is negotiated at run time: global options such as
// strong-crypto can narrow the effective set (research notes §8.12).
func MarkConfiguredView(a *model.Asset) {
	a.Properties[Prefix+"view"] = "configured"
}

// NoDefaultsWarning is the warning for a backup whose version has no
// defaults table. Every extractor uses it, so the text is identical and the
// CLI can print it once.
func NoDefaultsWarning(version, location string) model.Warning {
	return model.Warning{
		Code:    "no-default-table",
		Message: fmt.Sprintf("no defaults table for FortiOS %s; fields not set in the config are reported as unknown", version),
		Ev:      model.Evidence{Location: location, Line: 1, Symbol: "#config-version"},
	}
}

// Resolver resolves fields against one backup's defaults table.
type Resolver struct {
	Loc      string             // evidence location (the backup's file name)
	Inv      *model.Inventory   // receives warnings
	Defaults *defaults.Defaults // nil when no table covers the version
}

// Resolve turns attr, the last set/unset line for field (nil if absent), into
// a Value. unset means the default. Configured tokens are filtered through sp.
func (r *Resolver) Resolve(attr *tree.Attr, section, field, symbol, context string, sp Spec) Value {
	v := Value{Field: field, Symbol: symbol, Context: context, Source: Unknown}
	if attr != nil && !attr.Unset {
		v.Source, v.Line = Configured, attr.Line
		v.Tokens = r.clean(v, attr.Values, sp)
		return v
	}
	if r.Defaults == nil {
		return v
	}
	if f, ok := r.Defaults.Field(section, field); ok {
		v.Default = f
		if !f.Undocumented {
			v.Source, v.Tokens = Default, f.Value
		}
	}
	return v
}

func (r *Resolver) clean(v Value, toks []string, sp Spec) []string {
	var out []string
	seen := map[string]bool{}
	for _, tok := range toks {
		if tok == "" || seen[tok] {
			continue
		}
		switch {
		case sp.Known[tok]:
		case sp.Pattern != nil && sp.Pattern.MatchString(tok):
			if !sp.Freeform {
				r.Warn(v, fmt.Sprintf("%s has unknown option %q; kept as unknown", v.Symbol, tok))
			}
		default:
			r.Warn(v, v.Symbol+" has a token that is not a valid option; it was dropped and is not shown")
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return out
}

// Warn adds an unknown-token warning located at v.
func (r *Resolver) Warn(v Value, msg string) {
	r.Inv.AddWarning(model.Warning{
		Code:    "unknown-token",
		Message: msg,
		Ev:      r.Evidence(v),
	})
}

// Evidence is the occurrence for a configured value.
func (r *Resolver) Evidence(v Value) model.Evidence {
	return model.Evidence{Location: r.Loc, Line: v.Line, Symbol: v.Symbol, Context: v.Context}
}

// Record writes v's provenance onto a, and its tokens when withValue is set.
func (r *Resolver) Record(a *model.Asset, v Value, withValue bool) {
	p := Prefix + v.Field
	a.Properties[p+":source"] = v.Source
	switch v.Source {
	case Configured:
		a.Properties[p+":line"] = strconv.Itoa(v.Line)
		a.Evidence = append(a.Evidence, r.Evidence(v))
	case Default:
		a.Properties[Prefix+"defaults-table"] = r.Defaults.Name
		a.Properties[p+":default-source"] = v.Default.Source
		if v.Default.Note != "" {
			a.Properties[p+":default-note"] = v.Default.Note
		}
	case Unknown:
		if v.Default.Undocumented {
			a.Properties[p+":unknown-reason"] = "no documented default: " + v.Default.Source
		}
	}
	if withValue && v.Source != Unknown {
		a.Properties[p+":value"] = strings.Join(v.Tokens, " ")
	}
}
