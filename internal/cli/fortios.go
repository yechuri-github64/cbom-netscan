// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/yechuri-github64/cbom-netscan/pkg/emit/cdx16"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/global"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

func newFortiOSCmd(version string) *cobra.Command {
	var out string
	var force, reproducible bool

	cmd := &cobra.Command{
		Use:   "fortios <backup.conf>",
		Short: "Build a CBOM from a FortiOS configuration backup",
		Long: `Reads a FortiOS standard configuration backup (the text file that starts with
#config-version=) and writes a CycloneDX 1.6 CBOM.

Encrypted backups, YAML exports, and other files are rejected. Warnings, for
example about fields reported as unknown, go to stderr; they never contain
secret values. The exit status is non-zero if the backup cannot be parsed or
the output cannot be written.

Evidence in the CBOM records the backup's file name, not its full path, so
the output does not depend on where the command is run.

By default every run gets a new random serialNumber and the current time, as
CycloneDX expects. With --reproducible the serialNumber is a UUIDv5 derived
from the SHA-256 of the backup and the tool version, and the timestamp comes
from SOURCE_DATE_EPOCH when set and is omitted otherwise, so two runs on the
same backup produce byte-identical output.`,
		Example: `  cbom-netscan fortios fw01.conf -o fw01.cdx.json
  cbom-netscan fortios fw01.conf > fw01.cdx.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFortiOS(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], out, force, reproducible, version)
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "write the CBOM to this file instead of stdout")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite the output file if it already exists")
	cmd.Flags().BoolVar(&reproducible, "reproducible", false, "derive serialNumber from the input and tool version; timestamp from SOURCE_DATE_EPOCH or omitted")
	return cmd
}

func runFortiOS(ctx context.Context, stdout, stderr io.Writer, in, out string, force, reproducible bool, version string) error {
	if out != "" {
		if err := checkOutput(in, out, force); err != nil {
			return err
		}
	}

	meta := model.Meta{ToolVersion: version, Lifecycle: "operations"}
	if reproducible {
		created, ok, err := sourceDateEpoch()
		if err != nil {
			return err
		}
		meta.Created, meta.OmitTimestamp = created, !ok
	}

	// The whole backup is read once so the bytes that are hashed for the
	// reproducible serial are exactly the bytes that are parsed.
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	if reproducible {
		meta.SerialNumber = cdx16.ReproducibleSerial(sha256.Sum256(data), version)
	}

	tr, err := tree.Parse(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}

	name := filepath.Base(in)
	inv := model.NewInventory()
	global.Extract(tr, name, inv)

	for _, w := range append(append([]model.Warning(nil), tr.Warnings...), inv.Warnings...) {
		printWarning(stderr, name, w)
	}

	var buf bytes.Buffer
	if err := (cdx16.Emitter{}).Emit(ctx, &buf, inv, meta); err != nil {
		return fmt.Errorf("writing CBOM: %w", err)
	}

	if out == "" {
		_, err := stdout.Write(buf.Bytes())
		return err
	}
	return writeOutput(out, buf.Bytes(), force)
}

// sourceDateEpoch reads SOURCE_DATE_EPOCH (reproducible-builds.org). ok is
// false when it is unset or empty; a malformed value is an error, as the
// spec asks.
func sourceDateEpoch() (t time.Time, ok bool, err error) {
	v := os.Getenv("SOURCE_DATE_EPOCH")
	if v == "" {
		return time.Time{}, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return time.Time{}, false, fmt.Errorf("SOURCE_DATE_EPOCH=%q is not a non-negative integer number of seconds", v)
	}
	return time.Unix(n, 0).UTC(), true, nil
}

// printWarning writes one warning line. Warning messages are built by the
// lexer, tree, and extractors without secret values, so they are safe to print.
func printWarning(w io.Writer, file string, wr model.Warning) {
	if wr.Ev.Line > 0 {
		fmt.Fprintf(w, "%s:%d: warning: %s [%s]\n", file, wr.Ev.Line, wr.Message, wr.Code)
		return
	}
	fmt.Fprintf(w, "%s: warning: %s [%s]\n", file, wr.Message, wr.Code)
}

// checkOutput fails early, before any parsing, when the output would replace
// the input backup or an existing file without --force.
func checkOutput(in, out string, force bool) error {
	outInfo, err := os.Stat(out)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if inInfo, err := os.Stat(in); err == nil && os.SameFile(inInfo, outInfo) {
		return fmt.Errorf("output file %s is the input backup; refusing to overwrite it", out)
	}
	if !force {
		return fmt.Errorf("output file %s already exists; use --force to overwrite it", out)
	}
	return nil
}

// writeOutput writes data to path. Without force the file is created with
// O_EXCL, so a file that appeared after checkOutput is still not replaced.
func writeOutput(path string, data []byte, force bool) error {
	if force {
		return os.WriteFile(path, data, 0o644)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("output file %s already exists; use --force to overwrite it", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
