// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package global_test

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

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

	f, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr, err := tree.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	inv := model.NewInventory()
	global.Extract(tr, fixture, inv)
	if len(inv.Warnings) != 0 {
		t.Errorf("unexpected warnings: %+v", inv.Warnings)
	}

	t.Setenv("SOURCE_DATE_EPOCH", "1791676800")
	var buf bytes.Buffer
	meta := model.Meta{ToolVersion: "test", Lifecycle: "operations"}
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
