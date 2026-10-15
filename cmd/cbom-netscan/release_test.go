// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"regexp"
	"testing"
)

// TestReleaseToolchainMatchesGoMod: .goreleaser.yaml pins GOTOOLCHAIN for
// release builds; it must name the toolchain go.mod does, so a release is
// built with the Go version CI tests with.
func TestReleaseToolchainMatchesGoMod(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	mod := regexp.MustCompile(`(?m)^toolchain (go\S+)$`).FindStringSubmatch(read("../../go.mod"))
	rel := regexp.MustCompile(`(?m)^\s*- GOTOOLCHAIN=(go\S+)$`).FindStringSubmatch(read("../../.goreleaser.yaml"))
	if mod == nil || rel == nil {
		t.Fatalf("toolchain not found: go.mod %v, .goreleaser.yaml %v", mod, rel)
	}
	if mod[1] != rel[1] {
		t.Errorf(".goreleaser.yaml builds with GOTOOLCHAIN=%s, go.mod names %s", rel[1], mod[1])
	}
}
