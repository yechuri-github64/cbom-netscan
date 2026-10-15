// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// cbom-netscan generates CycloneDX Cryptography Bills of Materials (CBOMs)
// from network-appliance configuration backups (FortiOS for now).
package main

import (
	"os"
	"runtime/debug"
	"strings"

	"github.com/yechuri-github64/cbom-netscan/internal/cli"
)

// These three variables are overwritten at build time by goreleaser via ldflags:
//
//	-X main.version={{.Version}}
//	-X main.commit={{.Commit}}
//	-X main.date={{.CommitDate}}
//
// Without them (go install, go build), fromBuildInfo fills in what Go
// records in the binary instead.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	info, _ := debug.ReadBuildInfo()
	v, c, d := fromBuildInfo(version, commit, date, info)
	if err := cli.Execute(v, c, d); err != nil {
		os.Exit(1)
	}
}

// fromBuildInfo replaces the defaults that ldflags did not set with what Go
// records in the binary: "go install .../cmd/cbom-netscan@v0.1.2" records
// the module version (reported without the "v", as release builds do), and
// a build in a Git checkout records the commit, its time, and whether the
// tree had uncommitted changes. Values set by ldflags are kept.
func fromBuildInfo(version, commit, date string, info *debug.BuildInfo) (string, string, string) {
	if info == nil {
		return version, commit, date
	}
	if v := info.Main.Version; version == "dev" && v != "" && v != "(devel)" {
		version = strings.TrimPrefix(v, "v")
	}
	vcs := map[string]string{}
	for _, s := range info.Settings {
		vcs[s.Key] = s.Value
	}
	if rev := vcs["vcs.revision"]; commit == "none" && rev != "" {
		commit = rev
		if vcs["vcs.modified"] == "true" {
			commit += "-dirty"
		}
	}
	if t := vcs["vcs.time"]; date == "unknown" && t != "" {
		date = t
	}
	return version, commit, date
}
