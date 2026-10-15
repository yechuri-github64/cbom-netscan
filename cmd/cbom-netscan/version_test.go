// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	vcs := func(rev, tm, modified string) []debug.BuildSetting {
		return []debug.BuildSetting{{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: rev}, {Key: "vcs.time", Value: tm}, {Key: "vcs.modified", Value: modified}}
	}
	for _, tc := range []struct {
		name                string
		in                  [3]string
		info                *debug.BuildInfo
		version, commit, dt string
	}{
		{"no build info", [3]string{"dev", "none", "unknown"}, nil, "dev", "none", "unknown"},
		{"go install module@version", [3]string{"dev", "none", "unknown"},
			&debug.BuildInfo{Main: debug.Module{Version: "v0.1.2"}}, "0.1.2", "none", "unknown"},
		{"go install pseudo-version", [3]string{"dev", "none", "unknown"},
			&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3-0.20261015060000-abcdef123456"}}, "0.1.3-0.20261015060000-abcdef123456", "none", "unknown"},
		{"go build in a checkout", [3]string{"dev", "none", "unknown"},
			&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs("0123abc", "2026-10-15T06:00:00Z", "false")}, "dev", "0123abc", "2026-10-15T06:00:00Z"},
		{"checkout with uncommitted changes", [3]string{"dev", "none", "unknown"},
			&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs("0123abc", "2026-10-15T06:00:00Z", "true")}, "dev", "0123abc-dirty", "2026-10-15T06:00:00Z"},
		{"release build keeps ldflags", [3]string{"0.1.2", "fedcba9", "2026-10-15T07:00:00Z"},
			&debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}, Settings: vcs("0123abc", "2026-10-15T06:00:00Z", "true")}, "0.1.2", "fedcba9", "2026-10-15T07:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, c, d := fromBuildInfo(tc.in[0], tc.in[1], tc.in[2], tc.info)
			if v != tc.version || c != tc.commit || d != tc.dt {
				t.Errorf("got %q %q %q, want %q %q %q", v, c, d, tc.version, tc.commit, tc.dt)
			}
		})
	}
}

// TestVersionFromRealBuild builds the binary without ldflags, as go install
// and go build do, and checks that "version --json" reports what Go recorded
// in it (go version -m): the module version, and the commit when the build
// was stamped from Git.
func TestVersionFromRealBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "cbom-netscan")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	meta, err := exec.Command("go", "version", "-m", bin).Output()
	if err != nil {
		t.Fatal(err)
	}
	var modVersion, revision string
	for _, line := range strings.Split(string(meta), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 3 && f[0] == "mod":
			modVersion = f[2]
		case len(f) >= 2 && f[0] == "build" && strings.HasPrefix(f[1], "vcs.revision="):
			revision = strings.TrimPrefix(f[1], "vcs.revision=")
		}
	}
	out, err := exec.Command(bin, "version", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var got struct{ Version, Commit string }
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	wantVersion := "dev"
	if modVersion != "" && modVersion != "(devel)" {
		wantVersion = strings.TrimPrefix(modVersion, "v")
	}
	if got.Version != wantVersion {
		t.Errorf("version %q, want %q (build info: %q)", got.Version, wantVersion, modVersion)
	}
	if revision == "" {
		t.Logf("no VCS stamp in this build (not a Git checkout?); commit not checked")
	} else if !strings.HasPrefix(got.Commit, revision) {
		t.Errorf("commit %q, want the build's vcs.revision %q", got.Commit, revision)
	}
}
