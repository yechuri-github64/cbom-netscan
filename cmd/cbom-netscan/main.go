// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// cbom-netscan generates CycloneDX Cryptography Bills of Materials (CBOMs)
// from network-appliance configuration backups and TLS scan output.
package main

import (
	"os"

	"github.com/yechuri-github64/cbom-netscan/internal/cli"
)

// These three variables are overwritten at build time by goreleaser via ldflags:
//
//	-X main.version={{.Version}}
//	-X main.commit={{.Commit}}
//	-X main.date={{.CommitDate}}
//
// When you build with plain "go build" they stay as "dev"/"none"/"unknown",
// which is fine for local development.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := cli.Execute(version, commit, date); err != nil {
		os.Exit(1)
	}
}
