// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cli

// Synthetic test fixtures below are dedicated to the public domain (CC0-1.0).

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fixture = "../../pkg/fortios/extract/global/testdata/global-7.6.conf"
	golden  = "../../pkg/testdata/golden/fortios-global-7.6.cdx.json"
)

// run executes the full command tree with tool version "test" and returns
// stdout, stderr, and the error that main turns into a non-zero exit status.
func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return runVersion(t, "test", args...)
}

func runVersion(t *testing.T, version string, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd(version, "none", "unknown")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func readGolden(t *testing.T) []byte {
	t.Helper()
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	return want
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFortiOS_GoldenToFile runs lexer → tree → extractor → emitter through
// the CLI and compares the written file with the golden CBOM.
func TestFortiOS_GoldenToFile(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1791676800")
	out := filepath.Join(t.TempDir(), "out.cdx.json")
	stdout, stderr, err := run(t, "fortios", fixture, "-o", out, "--reproducible")
	if err != nil {
		t.Fatalf("fortios: %v\nstderr: %s", err, stderr)
	}
	// The fixture's config system admin block is a settings-only section:
	// recorded in metadata, not warned about.
	if stdout != "" || stderr != "" {
		t.Errorf("expected no stdout/stderr with -o; stdout=%q stderr=%q", stdout, stderr)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, readGolden(t)) {
		t.Errorf("%s differs from golden %s", out, golden)
	}
}

func TestFortiOS_GoldenToStdout(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1791676800")
	stdout, _, err := run(t, "fortios", fixture, "--reproducible")
	if err != nil {
		t.Fatalf("fortios: %v", err)
	}
	if stdout != string(readGolden(t)) {
		t.Errorf("stdout differs from golden %s", golden)
	}
}

func TestFortiOS_RefusesOverwriteWithoutForce(t *testing.T) {
	out := filepath.Join(t.TempDir(), "existing.cdx.json")
	writeFile(t, out, "keep me")

	_, _, err := run(t, "fortios", fixture, "-o", out)
	if err == nil || !strings.Contains(err.Error(), "already exists; use --force") {
		t.Fatalf("err = %v, want already-exists error", err)
	}
	if got, _ := os.ReadFile(out); string(got) != "keep me" {
		t.Errorf("existing file was modified: %q", got)
	}

	t.Setenv("SOURCE_DATE_EPOCH", "1791676800")
	if _, _, err := run(t, "fortios", fixture, "-o", out, "--force", "--reproducible"); err != nil {
		t.Fatalf("with --force: %v", err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, readGolden(t)) {
		t.Errorf("--force did not write the golden CBOM")
	}
}

func TestFortiOS_RefusesToOverwriteInput(t *testing.T) {
	in := filepath.Join(t.TempDir(), "fw.conf")
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, in, string(data))

	_, _, err = run(t, "fortios", in, "-o", in, "--force")
	if err == nil || !strings.Contains(err.Error(), "is the input backup") {
		t.Fatalf("err = %v, want input-backup refusal", err)
	}
	if got, _ := os.ReadFile(in); !bytes.Equal(got, data) {
		t.Errorf("input backup was modified")
	}
}

func TestFortiOS_FatalErrors(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, content, wantErr string
	}{
		{"not_a_backup", "config system global\nend\n", "not a FortiOS config backup"},
		{"unbalanced", "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin\nend\n", "line 2: end without a matching config"},
		{"unterminated_secret", "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin\nconfig system admin\nedit a\nset password \"c3ludGhldGlj-unterminated\n", "unterminated double-quoted string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := filepath.Join(dir, tc.name+".conf")
			out := filepath.Join(dir, tc.name+".cdx.json")
			writeFile(t, in, tc.content)

			stdout, stderr, err := run(t, "fortios", in, "-o", out)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error()+stdout+stderr, "c3ludGhldGlj") {
				t.Errorf("secret value printed: err=%v stderr=%q", err, stderr)
			}
			if _, statErr := os.Stat(out); statErr == nil {
				t.Errorf("output file created despite a fatal error")
			}
		})
	}

	if _, _, err := run(t, "fortios", filepath.Join(dir, "missing.conf")); err == nil {
		t.Errorf("missing input: expected an error")
	}
	if _, _, err := run(t, "fortios"); err == nil {
		t.Errorf("no argument: expected an error")
	}
}

// TestFortiOS_WarningsOnStderr checks that warnings reach stderr with file
// and line, while secret text dropped by the extractor is not echoed.
func TestFortiOS_WarningsOnStderr(t *testing.T) {
	in := filepath.Join(t.TempDir(), "fw.conf")
	writeFile(t, in, `#config-version=FGVMH6-7.4.8-FW-build2795-250523:opmode=0:vdom=0:user=admin
config firewall address
    edit "a"
end
config system ssh-config
    set ssh-enc-algo aes256-ctr "ENC c3ludGhldGljLWJsb2I="
end
`)
	stdout, stderr, err := run(t, "fortios", in)
	if err != nil {
		t.Fatalf("warnings must not be fatal: %v", err)
	}
	if !strings.Contains(stdout, `"bomFormat": "CycloneDX"`) {
		t.Errorf("no CBOM on stdout")
	}
	for _, want := range []string{
		"fw.conf:4: warning:",
		"[implied-next]",
		"fw.conf:1: warning: no defaults table for FortiOS 7.4.8",
		"[no-default-table]",
		"fw.conf:6: warning:",
		"[unknown-token]",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
	for _, secret := range []string{"c3ludGhldGlj", "ENC "} {
		if strings.Contains(stderr, secret) || strings.Contains(stdout, secret) {
			t.Errorf("secret fragment %q printed", secret)
		}
	}
}

// TestFortiOS_ReproducibleByteIdentical: two --reproducible runs on the same
// backup are byte-identical, with SOURCE_DATE_EPOCH set (fixed timestamp) and
// unset (no timestamp).
func TestFortiOS_ReproducibleByteIdentical(t *testing.T) {
	for _, epoch := range []string{"1791676800", ""} {
		t.Run("SOURCE_DATE_EPOCH="+epoch, func(t *testing.T) {
			t.Setenv("SOURCE_DATE_EPOCH", epoch)
			a, _, err := run(t, "fortios", fixture, "--reproducible")
			if err != nil {
				t.Fatal(err)
			}
			b, _, err := run(t, "fortios", fixture, "--reproducible")
			if err != nil {
				t.Fatal(err)
			}
			if a != b {
				t.Errorf("two --reproducible runs differ")
			}
			hasTS := strings.Contains(a, `"timestamp"`)
			if epoch == "" && hasTS {
				t.Errorf("timestamp present although SOURCE_DATE_EPOCH is unset")
			}
			if epoch != "" && !strings.Contains(a, `"timestamp": "2026-10-11T00:00:00Z"`) {
				t.Errorf("timestamp not taken from SOURCE_DATE_EPOCH")
			}
		})
	}
}

// TestFortiOS_ReproducibleSerialTracksInputAndVersion: the serial changes
// when any input byte or the tool version changes.
func TestFortiOS_ReproducibleSerialTracksInputAndVersion(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "")
	serialOf := func(version, in string) string {
		t.Helper()
		out, _, err := runVersion(t, version, "fortios", in, "--reproducible")
		if err != nil {
			t.Fatal(err)
		}
		_, rest, _ := strings.Cut(out, `"serialNumber": "`)
		serial, _, _ := strings.Cut(rest, `"`)
		return serial
	}

	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	edited := filepath.Join(t.TempDir(), "global-7.6.conf")
	writeFile(t, edited, string(data)+"# trailing comment\n")

	base := serialOf("test", fixture)
	if !strings.HasPrefix(base, "urn:uuid:") || base[23] != '5' {
		t.Errorf("serial %q is not a UUIDv5 URN", base)
	}
	if serialOf("test", edited) == base {
		t.Errorf("serial unchanged after the input changed")
	}
	if serialOf("test2", fixture) == base {
		t.Errorf("serial unchanged after the tool version changed")
	}
}

// TestFortiOS_DefaultNotReproducible: without --reproducible each run gets a
// new random serial and a timestamp, and SOURCE_DATE_EPOCH is not used.
func TestFortiOS_DefaultNotReproducible(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1791676800")
	a, _, err := run(t, "fortios", fixture)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := run(t, "fortios", fixture)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("two default runs are identical; serialNumber should be random")
	}
	if strings.Contains(a, "2026-10-11T00:00:00Z") || !strings.Contains(a, `"timestamp"`) {
		t.Errorf("default run should carry the current time, not SOURCE_DATE_EPOCH")
	}
}

func TestFortiOS_BadSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "yesterday")
	if _, _, err := run(t, "fortios", fixture, "--reproducible"); err == nil || !strings.Contains(err.Error(), "SOURCE_DATE_EPOCH") {
		t.Errorf("err = %v, want a SOURCE_DATE_EPOCH error", err)
	}
	if _, _, err := run(t, "fortios", fixture); err != nil {
		t.Errorf("without --reproducible SOURCE_DATE_EPOCH must be ignored: %v", err)
	}
}

// TestFortiOS_IPsecWired runs the CLI on the IPsec fixtures and checks that
// every component and dependency of the IPsec golden files is in the output
// unchanged. The CLI output also holds the other extractors' components, so
// it is a superset of the IPsec golden (IPsec plus certificates).
func TestFortiOS_IPsecWired(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1791676800")
	for fixtureName, goldenName := range map[string]string{
		"ipsec-7.6.conf":           "fortios-ipsec-7.6.cdx.json",
		"ipsec-multivdom-7.6.conf": "fortios-ipsec-multivdom-7.6.cdx.json",
	} {
		t.Run(fixtureName, func(t *testing.T) {
			out, stderr, err := run(t, "fortios", "../../pkg/fortios/extract/ipsec/testdata/"+fixtureName, "--reproducible")
			if err != nil {
				t.Fatalf("fortios: %v", err)
			}
			// ipsec-7.6.conf has one plaintext PSK on purpose (line 44).
			wantStderr := map[string]string{
				"ipsec-7.6.conf": "ipsec-7.6.conf:44: warning: FortiOS IPsec phase1-interface branch-ikev1 has a plaintext pre-shared key in the backup (value not shown); take backups with secrets encrypted [plaintext-psk]\n",
			}[fixtureName]
			if stderr != wantStderr {
				t.Errorf("stderr = %q, want %q", stderr, wantStderr)
			}
			want, err := os.ReadFile("../../pkg/testdata/golden/" + goldenName)
			if err != nil {
				t.Fatal(err)
			}

			type bom struct {
				SerialNumber string                       `json:"serialNumber"`
				Components   []map[string]json.RawMessage `json:"components"`
				Dependencies []json.RawMessage            `json:"dependencies"`
			}
			var g, c bom
			if err := json.Unmarshal(want, &g); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(out), &c); err != nil {
				t.Fatalf("CLI output is not JSON: %v", err)
			}
			if g.SerialNumber != c.SerialNumber {
				t.Errorf("serialNumber %s, golden %s", c.SerialNumber, g.SerialNumber)
			}
			have := map[string]string{}
			for _, comp := range c.Components {
				full, _ := json.Marshal(comp)
				have[string(comp["bom-ref"])] = string(full)
			}
			for _, comp := range g.Components {
				full, _ := json.Marshal(comp)
				if got, ok := have[string(comp["bom-ref"])]; !ok {
					t.Errorf("component %s missing from CLI output", comp["name"])
				} else if got != string(full) {
					t.Errorf("component %s differs from the golden file", comp["name"])
				}
			}
			deps := map[string]bool{}
			for _, d := range c.Dependencies {
				deps[string(d)] = true
			}
			for _, d := range g.Dependencies {
				if !deps[string(d)] {
					t.Errorf("dependency %s missing from CLI output", d)
				}
			}
		})
	}
}

// TestFortiOS_SharedWarningPrintedOnce: both extractors warn about a missing
// defaults table; the CLI prints it once.
func TestFortiOS_SharedWarningPrintedOnce(t *testing.T) {
	in := filepath.Join(t.TempDir(), "fw.conf")
	writeFile(t, in, "#config-version=FGVMH6-7.4.8-FW-build2795-250523:opmode=0:vdom=0:user=admin\n"+
		"config vpn ipsec phase1-interface\n    edit \"t\"\n        set proposal aes256-sha256\n    next\nend\n")
	_, stderr, err := run(t, "fortios", in)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(stderr, "[no-default-table]"); n != 1 {
		t.Errorf("no-default-table printed %d times, want 1:\n%s", n, stderr)
	}
}

func TestFortiOS_MaxSize(t *testing.T) {
	dir := t.TempDir()
	hdr := "#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin\n"
	big := filepath.Join(dir, "big.conf")
	writeFile(t, big, hdr+strings.Repeat("# c3ludGhldGlj padding line for the size test\n", (1<<20)/40))
	out := filepath.Join(dir, "big.cdx.json")

	_, stderr, err := run(t, "fortios", big, "--max-size", "1", "-o", out)
	if err == nil || !strings.Contains(err.Error(), "is larger than --max-size (1 MiB)") {
		t.Fatalf("err = %v, want a --max-size error", err)
	}
	if strings.Contains(err.Error()+stderr, "c3ludGhldGlj") {
		t.Errorf("error echoes file content: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Errorf("output written despite the size error")
	}

	small := filepath.Join(dir, "small.conf")
	writeFile(t, small, hdr+"config system global\nend\n")
	if _, _, err := run(t, "fortios", small, "--max-size", "1"); err != nil {
		t.Errorf("small backup under --max-size: %v", err)
	}
	// Values too large to convert to bytes must not overflow into a limit
	// that rejects everything.
	for _, huge := range []string{"9000000000000", "8796093022207", "8796093022208", "9223372036854775807"} {
		if _, _, err := run(t, "fortios", small, "--max-size", huge); err != nil {
			t.Errorf("--max-size %s rejected a tiny file: %v", huge, err)
		}
	}
	if _, _, err := run(t, "fortios", small, "--max-size", "0"); err == nil || !strings.Contains(err.Error(), "--max-size must be a positive") {
		t.Errorf("--max-size 0: err = %v, want a validation error", err)
	}
}

func TestRootHelp_OnlyExistingFeatures(t *testing.T) {
	stdout, _, err := run(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(stdout), "testssl") {
		t.Errorf("root help mentions testssl.sh, which is not implemented:\n%s", stdout)
	}
	// Every extractor the fortios command runs is described.
	for _, want := range []string{"fortios", "version", "config system ssh-config", "config vpn ipsec", "config vpn certificate", "config vpn ssl settings", "no live TLS scanning"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("root help missing %q", want)
		}
	}
}

var update = flag.Bool("update", false, "rewrite the golden files written by the CLI tests")

const sslvpnFixtures = "../../pkg/fortios/extract/sslvpn/testdata/"

// cliSecretFragments occur only in the fixtures' secret values (private keys,
// passwords) and PEM armour.
var cliSecretFragments = []string{"c3ludGhldGlj", "PRIVATE KEY", "BEGIN CERTIFICATE", "ENC ", "FortinetPasswordMask"}

// TestFortiOS_CertsSSLVPNGolden runs the whole pipeline (global, certificates,
// IPsec, SSL VPN) on the certificate fixtures and compares the CBOM with the
// golden files and the warnings with the expected list (none for the VDOM
// reference fixture). Neither may contain
// a secret.
func TestFortiOS_CertsSSLVPNGolden(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1791676800") // 2026-10-11T00:00:00Z
	for _, tc := range []struct {
		fixture, golden string
		stderr          []string
	}{
		{
			// Each VDOM lists the global factory certificates by name only
			// (range global, no PEM); they link to the global components.
			fixture: "../../certs/testdata/vdom-global-refs-7.6.conf",
			golden:  "fortios-certs-vdom-refs-7.6.cdx.json",
		},
		{
			fixture: "certs-sslvpn-7.6.conf",
			golden:  "fortios-certs-sslvpn-7.6.cdx.json",
			stderr: []string{
				"certs-sslvpn-7.6.conf:52: warning: FortiOS certificate local old-expired expired on 2024-12-31 [cert-expired]",
				"certs-sslvpn-7.6.conf:89: warning: FortiOS certificate local broken: X.509 parse failed; reported without certificate details [cert-unparseable]",
				`certs-sslvpn-7.6.conf:146: warning: FortiOS IPsec phase1-interface partner-sig: certificate "Fortinet_Factory" is not among the local certificates it can use (it may be built in) [unknown-certificate]`,
			},
		},
		{
			// branch-sig names root-rsa, which is in the root VDOM, not in
			// branch or global.
			fixture: "certs-sslvpn-multivdom-7.6.conf",
			golden:  "fortios-certs-sslvpn-multivdom-7.6.cdx.json",
			stderr: []string{
				`certs-sslvpn-multivdom-7.6.conf:99: warning: FortiOS IPsec phase1-interface branch-sig (vdom branch): certificate "root-rsa" is not among the local certificates it can use (it may be built in) [unknown-certificate]`,
			},
		},
	} {
		t.Run(filepath.Base(tc.fixture), func(t *testing.T) {
			out, stderr, err := run(t, "fortios", sslvpnFixtures+tc.fixture, "--reproducible")
			if err != nil {
				t.Fatalf("fortios: %v", err)
			}
			wantStderr := ""
			if len(tc.stderr) > 0 {
				wantStderr = strings.Join(tc.stderr, "\n") + "\n"
			}
			if stderr != wantStderr {
				t.Errorf("stderr =\n%s\nwant\n%s", stderr, wantStderr)
			}
			for _, s := range cliSecretFragments {
				if strings.Contains(out, s) || strings.Contains(stderr, s) {
					t.Errorf("output contains secret fragment %q", s)
				}
			}
			path := "../../pkg/testdata/golden/" + tc.golden
			if *update {
				writeFile(t, path, out)
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update to create it): %v", err)
			}
			if out != string(want) {
				t.Errorf("output differs from %s; run go test ./internal/cli -run CertsSSLVPN -update and review the diff", path)
			}
		})
	}
}

// TestFortiOS_ExpiryReferenceTime: without --reproducible, expiry is checked
// against the clock; with --reproducible and no SOURCE_DATE_EPOCH it is not
// evaluated, so the output stays the same from day to day.
func TestFortiOS_ExpiryReferenceTime(t *testing.T) {
	in := sslvpnFixtures + "certs-sslvpn-7.6.conf"

	t.Setenv("SOURCE_DATE_EPOCH", "")
	out, stderr, err := run(t, "fortios", in, "--reproducible")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr, "[cert-expired]") || !strings.Contains(out, `"value": "not evaluated"`) || strings.Contains(out, "expiry-checked-at") {
		t.Errorf("--reproducible without SOURCE_DATE_EPOCH evaluated expiry")
	}

	out, stderr, err = run(t, "fortios", in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "old-expired expired on 2024-12-31 [cert-expired]") || !strings.Contains(out, "cbom-netscan:cert:expiry-checked-at") {
		t.Errorf("default run did not check expiry against the clock:\n%s", stderr)
	}
}
