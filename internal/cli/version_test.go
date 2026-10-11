// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionCmd_text(t *testing.T) {
	cmd := newVersionCmd("v0.0.1", "abc1234", "2026-10-12")
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()
	for _, want := range []string{"v0.0.1", "abc1234", "2026-10-12"} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q does not contain %q", got, want)
		}
	}
}

func TestVersionCmd_json(t *testing.T) {
	cmd := newVersionCmd("v0.0.1", "abc1234", "2026-10-12")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	// Simulate passing --json on the command line.
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got versionInfo
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if got.Version != "v0.0.1" {
		t.Errorf("version = %q, want %q", got.Version, "v0.0.1")
	}
	if got.Commit != "abc1234" {
		t.Errorf("commit = %q, want %q", got.Commit, "abc1234")
	}
	if got.Date != "2026-10-12" {
		t.Errorf("date = %q, want %q", got.Date, "2026-10-12")
	}
}
