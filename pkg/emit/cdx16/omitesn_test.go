// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

package cdx16

import "testing"

func TestOmitESN(t *testing.T) {
	const pp = `"cryptoProperties":{"protocolProperties":{"ikev2TransformTypes":`
	comp := func(ref, tt string) string { return `{"bom-ref":` + ref + `,` + pp + tt + `}}}` }
	cases := []struct {
		name, in, want string
		unknown        map[string]bool
	}{
		{
			name:    "esn_last",
			in:      `{"components":[` + comp(`"a"`, `{"encr":[{"bom-ref":"x"}],"esn":false}`) + `]}`,
			want:    `{"components":[` + comp(`"a"`, `{"encr":[{"bom-ref":"x"}]}`) + `]}`,
			unknown: map[string]bool{"a": true},
		},
		{
			name:    "esn_first",
			in:      `{"components":[` + comp(`"a"`, `{"esn":false,"auth":[]}`) + `]}`,
			want:    `{"components":[` + comp(`"a"`, `{"auth":[]}`) + `]}`,
			unknown: map[string]bool{"a": true},
		},
		{
			name:    "esn_middle",
			in:      `{"components":[` + comp(`"a"`, `{"ke":[],"esn":false,"auth":[]}`) + `]}`,
			want:    `{"components":[` + comp(`"a"`, `{"ke":[],"auth":[]}`) + `]}`,
			unknown: map[string]bool{"a": true},
		},
		{
			name:    "esn_alone",
			in:      `{"components":[` + comp(`"a"`, `{"esn":false}`) + `]}`,
			want:    `{"components":[` + comp(`"a"`, `{}`) + `]}`,
			unknown: map[string]bool{"a": true},
		},
		{
			// Only the listed ref is edited, wherever it is and whatever its
			// key order; bom-ref after cryptoProperties still matches.
			name: "by_ref_not_position",
			in: `{"components":[` + comp(`"keep"`, `{"esn":false}`) + `,` +
				`{` + pp + `{"esn":false,"encr":[]}}},"bom-ref":"drop"}]}`,
			want: `{"components":[` + comp(`"keep"`, `{"esn":false}`) + `,` +
				`{` + pp + `{"encr":[]}}},"bom-ref":"drop"}]}`,
			unknown: map[string]bool{"drop": true},
		},
		{
			// Strings holding JSON-looking text are data, not structure.
			name: "strings_are_data",
			in: `{"components":[{"name":"x \"esn\":false {}[] \\","bom-ref":"a\u0026b",` +
				`"properties":[{"name":"esn","value":"esn"}],` + pp + `{"esn":false}}}}]}`,
			want: `{"components":[{"name":"x \"esn\":false {}[] \\","bom-ref":"a\u0026b",` +
				`"properties":[{"name":"esn","value":"esn"}],` + pp + `{}}}}]}`,
			unknown: map[string]bool{"a&b": true},
		},
		{
			// An esn key outside ikev2TransformTypes is never touched.
			name:    "esn_elsewhere_untouched",
			in:      `{"components":[{"bom-ref":"a","esn":false,"cryptoProperties":{"esn":false}}]}`,
			want:    `{"components":[{"bom-ref":"a","esn":false,"cryptoProperties":{"esn":false}}]}`,
			unknown: map[string]bool{"a": true},
		},
		{
			name:    "nothing_unknown",
			in:      `{"components":[` + comp(`"a"`, `{"esn":false}`) + `]}`,
			want:    `{"components":[` + comp(`"a"`, `{"esn":false}`) + `]}`,
			unknown: map[string]bool{"other": true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := omitESN([]byte(tc.in), tc.unknown)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}
