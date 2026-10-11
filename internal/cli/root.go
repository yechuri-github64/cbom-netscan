// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package cli wires together all cbom-netscan cobra commands.
// main.go calls Execute(); every subcommand (collect, merge, assess, …)
// will be added here as the project grows.
package cli

import (
	"github.com/spf13/cobra"
)

// rootCmd is the top-level command.  It prints help when called with no
// subcommand.  Global flags (--log-level, --no-color, etc.) will be added
// here in later weeks so every subcommand inherits them automatically.
var rootCmd = &cobra.Command{
	Use:   "cbom-netscan",
	Short: "Generate CycloneDX CBOMs from network-appliance configs and TLS scans",
	Long: `cbom-netscan reads FortiOS configuration backups and testssl.sh JSON output
and produces a CycloneDX 1.6 Cryptography Bill of Materials (CBOM).

It never reads or emits secret values (PSKs, private keys, passwords).
All test fixtures use only synthetic, RFC 5737/3849/2606 data.`,
}

// Execute wires in the version string variables from main, registers
// subcommands, and runs the cobra argument parser.
// Returning the error (instead of calling os.Exit here) makes it easy to
// test the CLI in unit tests without killing the test process.
func Execute(version, commit, date string) error {
	rootCmd.AddCommand(newVersionCmd(version, commit, date))
	return rootCmd.Execute()
}
