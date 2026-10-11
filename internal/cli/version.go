// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// versionInfo is the struct we JSON-encode when --json is passed.
// The field tags control the exact JSON key names.
type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// newVersionCmd returns the "version" subcommand.
//
// Why a constructor instead of a package-level var?  Because version/commit/date
// come from main at startup and aren't known at package-init time.  Passing them
// as arguments keeps the package free of global state and easy to test.
//
// Usage:
//
//	cbom-netscan version          → cbom-netscan dev (commit none, built unknown)
//	cbom-netscan version --json   → {"version":"dev","commit":"none","date":"unknown"}
func newVersionCmd(version, commit, date string) *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version, commit hash, and build date",
		// RunE returns an error instead of calling os.Exit, so callers
		// (including tests) can inspect the result.
		RunE: func(cmd *cobra.Command, args []string) error {
			info := versionInfo{
				Version: version,
				Commit:  commit,
				Date:    date,
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"cbom-netscan %s (commit %s, built %s)\n",
				info.Version, info.Commit, info.Date,
			)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output version information as JSON")
	return cmd
}
