// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package global_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yechuri-github64/cbom-netscan/pkg/emit/cdx16"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/extract/global"
	"github.com/yechuri-github64/cbom-netscan/pkg/fortios/tree"
	"github.com/yechuri-github64/cbom-netscan/pkg/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

// secretFragments occur only inside secret values in the fixtures; none of
// them may appear in any output.
var secretFragments = []string{"c3ludGhldGlj", "PRIVATE KEY", "ENC "}

// The golden file lives in pkg/testdata/golden so CI validates it with
// cyclonedx-cli and TestGoldenCryptoAssetType checks its component types.
func TestGolden_Global76(t *testing.T) {
	const fixture = "testdata/global-7.6.conf"
	golden := filepath.Join("..", "..", "..", "testdata", "golden", "fortios-global-7.6.cdx.json")

	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := tree.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	inv := model.NewInventory()
	global.Extract(tr, filepath.Base(fixture), inv)
	if len(inv.Warnings) != 0 {
		t.Errorf("unexpected warnings: %+v", inv.Warnings)
	}

	// The same serial and timestamp that "cbom-netscan fortios --reproducible"
	// produces with tool version "test" and SOURCE_DATE_EPOCH=1791676800, so
	// the CLI end-to-end test can compare against this golden file.
	var buf bytes.Buffer
	meta := model.Meta{
		ToolVersion:  "test",
		Lifecycle:    "operations",
		Created:      time.Unix(1791676800, 0),
		SerialNumber: cdx16.ReproducibleSerial(sha256.Sum256(data), "test"),
	}
	if err := (cdx16.Emitter{}).Emit(context.Background(), &buf, inv, meta); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	got := buf.Bytes()

	for _, s := range secretFragments {
		if bytes.Contains(got, []byte(s)) {
			t.Errorf("output contains secret fragment %q", s)
		}
	}

	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s; run go test -update and review the diff\n%s", golden, firstDiff(string(want), string(got)))
	}
}

func firstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "line " + strconv.Itoa(i+1) + ":\n want: " + wl + "\n  got: " + gl
		}
	}
	return ""
}
