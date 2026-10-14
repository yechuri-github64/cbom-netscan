// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

// Package cli wires together all cbom-netscan cobra commands.
// main.go calls Execute(); new subcommands are registered in newRootCmd.
package cli

import (
	"github.com/spf13/cobra"
)

// newRootCmd builds the top-level command. It is a constructor rather than a
// package-level var so tests can build a fresh command tree for every run.
func newRootCmd(version, commit, date string) *cobra.Command {
	root := &cobra.Command{
		Use:   "cbom-netscan",
		Short: "Generate CycloneDX 1.6 CBOMs from FortiOS configuration backups",
		Long: `cbom-netscan builds a CycloneDX 1.6 Cryptography Bill of Materials (CBOM)
from a FortiOS configuration backup:

  cbom-netscan fortios backup.conf -o backup.cdx.json

It currently reports:
  - admin HTTPS (TLS versions and cipher suites) and admin SSH (key exchange,
    ciphers, MACs, host key algorithms) from config system global and
    config system ssh-config;
  - IPsec VPN tunnels (IKE version, proposals, DH groups, authentication
    method, PQC additional key exchanges, phase2 proposals and PFS groups)
    from config vpn ipsec phase1/phase2 and their -interface variants.

Secret values (passwords, ENC values, private keys) are never written to the
CBOM or printed in warnings.`,
		// Usage is for argument mistakes; runtime errors such as a parse
		// failure print only the error.
		SilenceUsage: true,
	}
	root.AddCommand(newVersionCmd(version, commit, date))
	root.AddCommand(newFortiOSCmd(version))
	return root
}

// Execute builds the command tree and runs it with the process arguments.
// It returns the error instead of calling os.Exit so main decides the exit code.
func Execute(version, commit, date string) error {
	return newRootCmd(version, commit, date).Execute()
}
