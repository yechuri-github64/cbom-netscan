// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
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
