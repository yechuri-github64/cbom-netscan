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
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/yechuri-github64/cbom-netscan/pkg/emit/cdx16"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/certs"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/coverage"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/global"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/ipsec"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/sslvpn"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

func newFortiOSCmd(version string) *cobra.Command {
	var o fortiosOpts
	o.version = version

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
same backup produce byte-identical output.

Certificates are checked for expiry against the current time, or under
--reproducible against SOURCE_DATE_EPOCH; with --reproducible and no
SOURCE_DATE_EPOCH, expiry is recorded as not evaluated.

The CBOM holds no secret values but is confidential infrastructure data: it
names tunnels and certificates and shows which weak or quantum-vulnerable
algorithms are enabled where. Files written with -o are created with mode
0600; output written to stdout is not protected that way, so a shell
redirection creates the file with your umask's permissions. The CBOM
inventories what the configuration says; it is not a compliance
certification.`,
		Example: `  cbom-netscan fortios fw01.conf -o fw01.cdx.json   # file readable by you only
  cbom-netscan fortios fw01.conf | jq .              # stdout, e.g. into another tool`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFortiOS(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], o)
		},
	}
	cmd.Flags().StringVarP(&o.out, "output", "o", "", "write the CBOM to this file instead of stdout")
	cmd.Flags().BoolVar(&o.force, "force", false, "overwrite the output file if it already exists")
	cmd.Flags().BoolVar(&o.reproducible, "reproducible", false, "derive serialNumber from the input and tool version; timestamp from SOURCE_DATE_EPOCH or omitted")
	cmd.Flags().Int64Var(&o.maxSizeMiB, "max-size", 256, "refuse backups larger than this many MiB")
	cmd.Flags().IntVar(&o.maxComponents, "max-components", defaultMaxComponents, "refuse backups that need more CBOM components than this (memory limit)")
	cmd.Flags().IntVar(&o.maxEvidence, "max-evidence", defaultMaxEvidence, "refuse backups that need more evidence occurrences and warnings than this (memory limit)")
	return cmd
}

type fortiosOpts struct {
	out                        string
	force, reproducible        bool
	maxSizeMiB                 int64
	maxComponents, maxEvidence int
	version                    string
}

// Default inventory limits. Measured peak memory is about 19.5 KB per
// component (a component with no evidence, the most per entry) and about
// 1.2 KB per further evidence occurrence or warning, so a backup at both
// limits peaks at about 2 GB. A real tunnel (phase1, phase2, pre-shared key)
// is 3 components and about 15 evidence occurrences, so both limits allow
// about 26,000 such tunnels. SECURITY.md has the measurements.
const (
	defaultMaxComponents = 100_000
	defaultMaxEvidence   = 500_000
)

func runFortiOS(ctx context.Context, stdout, stderr io.Writer, in string, o fortiosOpts) error {
	out, force, reproducible, version := o.out, o.force, o.reproducible, o.version
	if o.maxSizeMiB <= 0 {
		return fmt.Errorf("--max-size must be a positive number of MiB, got %d", o.maxSizeMiB)
	}
	if o.maxComponents <= 0 || o.maxEvidence <= 0 {
		return fmt.Errorf("--max-components and --max-evidence must be positive, got %d and %d", o.maxComponents, o.maxEvidence)
	}
	if out != "" {
		if err := checkOutput(in, out, force); err != nil {
			return err
		}
	}

	meta := model.Meta{ToolVersion: version, Lifecycle: "operations"}
	// now is the reference time for certificate expiry. Under --reproducible
	// it must not be the clock, or the output would change from day to day.
	now := time.Now()
	if reproducible {
		created, ok, err := sourceDateEpoch()
		if err != nil {
			return err
		}
		meta.Created, meta.OmitTimestamp = created, !ok
		now = created // zero when SOURCE_DATE_EPOCH is unset: not evaluated
	}

	// The whole backup is read once so the bytes that are hashed for the
	// reproducible serial are exactly the bytes that are parsed.
	data, err := readLimited(in, o.maxSizeMiB)
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
	// Parser warnings count toward the evidence limit too: a backup can
	// produce one per line. As many as the limit leave no room for any
	// evidence, so that is refused as well.
	if len(tr.Warnings) >= o.maxEvidence {
		return limitErr(in, &model.LimitError{Kind: "evidence", Limit: o.maxEvidence})
	}
	inv := model.NewInventory()
	inv.Limits = model.Limits{Components: o.maxComponents, Evidence: o.maxEvidence - len(tr.Warnings)}
	global.Extract(tr, name, inv)
	certs.Extract(tr, name, inv, now)
	ipsec.Extract(tr, name, inv)
	sslvpn.Extract(tr, name, inv)
	if err := inv.Exceeded(); err != nil {
		return limitErr(in, err)
	}
	cov := coverage.Check(tr)
	if w := cov.Warning(name); w != nil {
		inv.AddWarning(*w)
	}
	meta.Properties = cov.Properties()

	// Extractors share some warnings (e.g. no defaults table); print each once.
	printed := map[model.Warning]bool{}
	for _, w := range append(append([]model.Warning(nil), tr.Warnings...), inv.Warnings...) {
		if !printed[w] {
			printed[w] = true
			printWarning(stderr, name, w)
		}
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

// limitErr explains a reached inventory limit. No CBOM is written: the
// inventory stopped growing at the limit, so it would be incomplete.
func limitErr(in string, err error) error {
	return fmt.Errorf("%s: the backup needs %v; no CBOM was written. The limits keep peak memory near 2 GB "+
		"(about 20 KB per component); if the backup is genuine, raise --max-components or --max-evidence", in, err)
}

// readLimited reads the whole backup but refuses one larger than maxMiB, so a
// wrong file (a disk image or a pcap) fails fast instead of being lexed. A
// regular file is checked by size before reading; anything else (a pipe) is
// read through a limit. The error never includes file content.
func readLimited(path string, maxMiB int64) ([]byte, error) {
	// maxMiB << 20 overflows for values above about 8 EiB; such a limit is
	// larger than any file, so it means no limit. One byte of headroom keeps
	// the limit+1 below from overflowing too.
	limit := int64(math.MaxInt64 - 1)
	if maxMiB <= (math.MaxInt64-1)>>20 {
		limit = maxMiB << 20
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tooBig := fmt.Errorf("%s is larger than --max-size (%d MiB)", path, maxMiB)
	if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() && fi.Size() > limit {
		return nil, tooBig
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, tooBig
	}
	return data, nil
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
// lexer, tree, and extractors without secret values; the file name, message,
// and code are passed through terminalSafe, since names in a message come
// from the backup.
func printWarning(w io.Writer, file string, wr model.Warning) {
	file, msg, code := terminalSafe(file), terminalSafe(wr.Message), terminalSafe(wr.Code)
	if wr.Ev.Line > 0 {
		fmt.Fprintf(w, "%s:%d: warning: %s [%s]\n", file, wr.Ev.Line, msg, code)
		return
	}
	fmt.Fprintf(w, "%s: warning: %s [%s]\n", file, msg, code)
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

// outputMode is the permission for CBOM files: a CBOM describes a device's
// crypto, certificates, and VPN tunnels, so it is readable by its owner only.
const outputMode = 0o600

// writeOutput writes data to path with mode 0600. Without force the file is
// created with O_EXCL, so a file (or symlink) that appeared after
// checkOutput is still not replaced. With force, see replaceFile.
func writeOutput(path string, data []byte, force bool) error {
	if force {
		return replaceFile(path, data)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, outputMode)
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

// replaceFile writes data to a new temporary file (mode 0600) in path's
// directory, syncs it, and renames it over path. On Linux and macOS the
// rename is atomic (readers see the old file or the complete new one), and
// the directory is synced afterwards so the rename survives a crash. On
// Windows, where a rename over an existing file is not guaranteed atomic
// and a directory cannot be synced, it is best-effort. Either way a failed
// write leaves the old file as it was, and a symlink at path is replaced by
// the new file, not followed, so --force cannot be used to overwrite
// whatever it points to.
func replaceFile(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(outputMode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirAfterRename(filepath.Dir(path))
}

// syncDirAfterRename is syncDir; tests replace it to check that it runs, on
// the right directory, after the rename.
var syncDirAfterRename = syncDir

// syncDir flushes a directory's entries to disk, so a rename in it is
// durable. Windows cannot open a directory for syncing, so it is skipped
// there, as are file systems that do not support syncing a directory.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, errors.ErrUnsupported) || errors.Is(err, syscall.EINVAL) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("output written, but syncing its directory failed: %w", err)
	}
	return nil
}
