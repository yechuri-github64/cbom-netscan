# cbom-netscan

cbom-netscan turns a network appliance's configuration backup into a
[CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) Cryptography Bill of
Materials (CBOM): the protocols, algorithms, certificates, and keys the
device is configured to use, with the config line each one comes from.

> **Status: v0.1.0 supports FortiOS configuration backups only.** It reads the
> backup file offline. There is **no live TLS scanning yet**, and no other
> vendors. See [what it does not do](#limitations).

## What it reports

From a FortiOS standard configuration backup (the text file that starts with
`#config-version=`):

- **Admin HTTPS and SSH**: TLS versions and cipher suites, SSH key exchange,
  ciphers, MACs, and host-key algorithms (`config system global`,
  `config system ssh-config`).
- **IPsec VPN**: IKE version, proposals, DH groups, post-quantum additional
  key exchanges (ML-KEM and others), authentication by PSK or certificate,
  phase2 proposals (`config vpn ipsec phase1/phase2` and the `-interface`
  variants).
- **Certificates**: key and signature algorithms, validity, expiry, and the
  CA/Browser Forum validity limit as information (`config vpn certificate
  local/ca/remote`, `config certificate …`).
- **SSL VPN / Agentless VPN**: TLS versions, cipher suites, TLS groups
  including post-quantum hybrids such as X25519MLKEM768, and the server
  certificate (`config vpn ssl settings`).

Each algorithm is one component referenced by every protocol that uses it,
with `nistQuantumSecurityLevel` set (0 for RSA, ECDH, ECDSA, …), so
quantum-vulnerable crypto is easy to find. Every value says whether it was
configured, is the documented default for that firmware, or is unknown.
Multi-VDOM backups are supported.

**Secrets never reach the output.** Pre-shared keys, `ENC` values, passwords,
and private keys are reported as present (and in which form), never by
value, and warnings never quote them. Encrypted backups are refused, not
decrypted.

[MAPPING.md](MAPPING.md) maps every field to CERT-In's CBOM minimum elements
(Table 9) and CycloneDX 1.6: 19 of the 30 elements fully and 5 partially from
a backup alone.

## Install

Requires nothing at run time; one static binary.

**From a release** (Linux, macOS, Windows; amd64 and arm64). Download the
archive for your platform and `checksums.txt` from the
[releases page](https://github.com/yechuri-github64/cbom-netscan/releases),
then verify them:

```sh
# The checksums file is signed with Sigstore keyless signing (cosign v3).
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/yechuri-github64/cbom-netscan/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
tar -xzf cbom-netscan_0.1.0_linux_amd64.tar.gz cbom-netscan
```

Each archive has a CycloneDX SBOM next to it
(`cbom-netscan_0.1.0_linux_amd64.tar.gz.sbom.json`).

**With Go 1.26 or later:**

```sh
go install github.com/yechuri-github64/cbom-netscan/cmd/cbom-netscan@v0.1.0
```

(`cbom-netscan version` then prints `dev`; release binaries carry the version.)

**From source:**

```sh
git clone https://github.com/yechuri-github64/cbom-netscan.git
cd cbom-netscan && go build -o cbom-netscan ./cmd/cbom-netscan
```

## Try it

The repository has synthetic FortiOS backups (made-up configs and test
certificates, CC0) to try it on. With `cbom-netscan` and
[jq](https://jqlang.org) on your `PATH`:

```sh
git clone --depth 1 https://github.com/yechuri-github64/cbom-netscan.git && cd cbom-netscan
cbom-netscan fortios pkg/fortios/extract/sslvpn/testdata/certs-sslvpn-7.6.conf -o demo.cdx.json
jq -r '.components[] | select(.cryptoProperties.assetType == "protocol") | .name' demo.cdx.json
```

Output (the fixture has an expired certificate, a broken one, and a tunnel
naming a built-in certificate on purpose, so it warns on stderr):

```text
certs-sslvpn-7.6.conf:52: warning: FortiOS certificate local old-expired expired on 2024-12-31 [cert-expired]
certs-sslvpn-7.6.conf:89: warning: FortiOS certificate local broken: X.509 parse failed; reported without certificate details [cert-unparseable]
certs-sslvpn-7.6.conf:146: warning: FortiOS IPsec phase1-interface partner-sig: certificate "Fortinet_Factory" is not among the local certificates it can use (it may be built in) [unknown-certificate]
FortiOS IPsec phase1-interface dc-sig
FortiOS IPsec phase1-interface partner-sig
FortiOS SSL VPN TLS 1.2
FortiOS SSL VPN TLS 1.3
FortiOS admin HTTPS TLS 1.2
FortiOS admin HTTPS TLS 1.3
FortiOS admin SSH
```

`demo.cdx.json` holds 58 components (7 protocols, 34 algorithms,
7 certificates, 10 keys). A closer look at the SSL VPN's TLS 1.3, with its
references resolved to names:

```sh
jq '(.components | map({(.["bom-ref"]): .name}) | add) as $n
  | .components[] | select(.name == "FortiOS SSL VPN TLS 1.3")
  | {name, version: .cryptoProperties.protocolProperties.version,
     cipherSuites: [.cryptoProperties.protocolProperties.cipherSuites[].name],
     references: [.cryptoProperties.protocolProperties.cryptoRefArray[] | $n[.]]}' demo.cdx.json
```

```json
{
  "name": "FortiOS SSL VPN TLS 1.3",
  "version": "1.3",
  "cipherSuites": [
    "TLS-AES-256-GCM-SHA384",
    "TLS-CHACHA20-POLY1305-SHA256"
  ],
  "references": [
    "X25519MLKEM768",
    "ML-KEM-768",
    "X25519",
    "SecP384r1MLKEM1024",
    "ML-KEM-1024",
    "ECP-384",
    "FFDHE-4096",
    "FortiOS certificate local gw-ecdsa"
  ]
}
```

The hybrid groups appear as combiners together with their ML-KEM and
classical parts, and the TLS 1.2 component lists only the classical groups,
since the post-quantum groups are defined for TLS 1.3 only.

## Usage

```text
cbom-netscan fortios <backup.conf> [flags]

  -o, --output string   write the CBOM to this file instead of stdout
      --force           overwrite the output file if it already exists
      --reproducible    derive serialNumber from the input and tool version;
                        timestamp from SOURCE_DATE_EPOCH or omitted
      --max-size int    refuse backups larger than this many MiB (default 256)
```

Warnings go to stderr as `file:line: warning: message [code]`; the codes are
listed in [MAPPING.md §5](MAPPING.md#5-warnings). Warnings do not change the
exit status; it is non-zero when the backup cannot be read or parsed, the CBOM
cannot be written, or an option is invalid.

With `--reproducible`, two runs on the same backup give byte-identical output:
the serial number is derived from the backup and the tool version, and the
timestamp and certificate-expiry reference time come from
`SOURCE_DATE_EPOCH` (without it, expiry is recorded as "not evaluated").

Evidence records the backup's file name only, never its full path.

### Treat the CBOM as confidential

A CBOM holds no secret values, but it is still confidential infrastructure
data: it names the device's VPN tunnels and certificates, gives certificate
subjects and issuers, and shows exactly which weak or quantum-vulnerable
algorithms are enabled where, which is a map for an attacker. Store and
share it like the device's configuration, not like public documentation.
Files written with `-o` are created with mode `0600` (owner only). With
`--force`, the new CBOM is written to a temporary file in the same directory
and renamed over the old one, so the replacement is atomic, a failed write
leaves the old file intact, and a symlink at the output path is replaced
rather than followed.

## Limitations

- FortiOS configuration backups only. No live TLS scanning, no other vendors
  yet.
- TLS 1.2 cipher suites are not derivable from a backup and are reported as
  unknown; a live scan is needed for those.
- Firmware defaults are known for FortiOS 7.4.12, 7.6.3–7.6.7, and 8.0.1.
  For other versions, settings left at their default are reported as unknown.
- Some sections are not inventoried yet (for example SSL inspection
  profiles, SSH local keys, manual-key IPsec); the CBOM lists them and warns.
- Only the first certificate of a chain is inventoried.
- CycloneDX 1.6 output only.

The full list, with the reasons and accepted risks, is in
[MAPPING.md §7](MAPPING.md#7-known-limitations-and-accepted-risks); open
design questions are in [§8](MAPPING.md#8-open-decisions).

## Documentation

- [MAPPING.md](MAPPING.md): CERT-In Table 9 → CycloneDX 1.6 mapping, every
  output property and warning, design decisions, limitations.
- [docs/fortios-parser-research.md](docs/fortios-parser-research.md): the
  FortiOS fields, defaults, and versions the parser is built on, with
  sources.
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md),
  [SECURITY.md](SECURITY.md).

**Never post a real configuration backup** in an issue, even redacted. Use or
adapt the synthetic fixtures under `pkg/**/testdata/` instead.

## License

Apache-2.0 ([LICENSE](LICENSE)). Test fixtures are CC0-1.0. The repository is
[REUSE](https://reuse.software) compliant.

FortiOS, FortiGate, and Fortinet are trademarks of Fortinet, Inc.
cbom-netscan is not affiliated with or endorsed by Fortinet.
