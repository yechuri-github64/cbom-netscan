// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// vmFixture is modelled on a FortiGate-VM 7.6.7 trial backup with two VDOMs
// (issue #4), with made-up data only: documentation addresses (192.0.2.0/24),
// synthetic secrets, a made-up serial number, and test certificates from
// certs/testdata/gencerts.go. Its tunnels are IKEv2 with AES-128/256, SHA-256,
// and DH groups 14 and 19 (root), and IKEv1 (the 7.6.7 default) with 3DES,
// SHA-1, and DH group 2 (testvdom); the phase2 relies on the default PFS with
// group 14; admin HTTPS allows TLS 1.1 and 1.2; and the factory certificate
// named Fortinet_SSL_RSA2048 holds a 1024-bit key.
const (
	vmFixture = "../../pkg/testdata/fortios/fgvm-multivdom-7.6.conf"
	vmGolden  = "../../pkg/testdata/golden/fortios-fgvm-multivdom-7.6.cdx.json"
)

// TestFortiOS_VMMultiVDOMGolden runs the whole pipeline on the VM fixture
// and compares the CBOM with its golden file. The fixture gives no warnings.
func TestFortiOS_VMMultiVDOMGolden(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1791676800") // 2026-10-11T00:00:00Z
	out, stderr, err := run(t, "fortios", vmFixture, "--reproducible")
	if err != nil {
		t.Fatalf("fortios: %v", err)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want no warnings", stderr)
	}
	if *update {
		writeFile(t, vmGolden, out)
	}
	want, err := os.ReadFile(vmGolden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if out != string(want) {
		t.Errorf("output differs from %s; run go test ./internal/cli -run VMMultiVDOM -update and review the diff", vmGolden)
	}
}

// TestFortiOS_VMFixtureNoPSK: no pre-shared key of the VM fixture reaches the
// CBOM or the warnings, neither as the ENC value in the backup nor decoded.
// The keys are read from the fixture, so a key added there is checked too.
// Each tunnel still gets its pre-shared key component, without a value.
func TestFortiOS_VMFixtureNoPSK(t *testing.T) {
	data, err := os.ReadFile(vmFixture)
	if err != nil {
		t.Fatal(err)
	}
	var psks []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 4 && f[0] == "set" && f[1] == "psksecret" && f[2] == "ENC" {
			psks = append(psks, f[3])
			if dec, err := base64.StdEncoding.DecodeString(f[3]); err == nil && len(dec) > 0 {
				psks = append(psks, string(dec))
			}
		}
	}
	if len(psks) != 4 { // two tunnels, each value as in the backup and decoded
		t.Fatalf("found %d pre-shared key values in the fixture, want 4: %q", len(psks), psks)
	}

	t.Setenv("SOURCE_DATE_EPOCH", "1791676800")
	out, stderr, err := run(t, "fortios", vmFixture, "--reproducible")
	if err != nil {
		t.Fatalf("fortios: %v", err)
	}
	for _, psk := range psks {
		if strings.Contains(out, psk) || strings.Contains(stderr, psk) {
			t.Errorf("output contains the pre-shared key value %q", psk)
		}
	}
	for _, tunnel := range []string{"test-vpn1 (vdom root)", "test-vpn2 (vdom testvdom)"} {
		if !strings.Contains(out, `"FortiOS IPsec phase1-interface `+tunnel+` pre-shared key"`) {
			t.Errorf("no pre-shared key component for %s", tunnel)
		}
	}
}
