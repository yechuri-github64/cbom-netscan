# Changelog

All notable changes to cbom-netscan are listed here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/); while the version is
0.x, a minor release may change the output.

## [0.1.1] - 2026-10-15

Release packaging fixes; the `cbom-netscan` program and its output are
unchanged.

### Fixed

- The GitHub release body is now the version's section of this changelog.
  v0.1.0 was published with an empty body (GitHub showed only "v0.1.0"):
  GoReleaser's `changelog.disable` setting also skipped reading the
  `--release-notes` file. Relative links in the notes are rewritten to
  absolute `blob/<tag>/` URLs, and the release workflow fails if the body
  would be empty or only the tag name, and checks the published body.
- Release SBOMs are CycloneDX 1.6, the version cbom-netscan itself emits
  (they were 1.7). Their subject is named `cbom-netscan` at the release
  version, and the binary is listed by its name in the archive, with its
  hashes, instead of syft's temporary unpacking path
  (`/tmp/syft-archive-contents-…`).
- Each release archive includes `REUSE.toml` and `LICENSES/Apache-2.0.txt`,
  and `REUSE.toml` covers the binary, so an extracted archive passes
  `reuse lint` on its own.

### Documentation

- README: `gh attestation verify` needs `gh auth login` (or `GH_TOKEN`)
  first.

## [0.1.0] - 2026-10-15

First release. cbom-netscan reads a FortiOS configuration backup offline and
writes a CycloneDX 1.6 CBOM. **FortiOS backups only; no live TLS scanning
yet.**

### Added

- `cbom-netscan fortios <backup.conf>` command, writing to stdout or
  `-o FILE` (`--force` to overwrite), with `--reproducible` (serial number
  derived from the backup and tool version, timestamp and expiry reference
  time from `SOURCE_DATE_EPOCH`) and `--max-size` (default 256 MiB).
  `cbom-netscan version [--json]`.
- FortiOS backup parser: streaming lexer for the standard text backup
  (header, quoting, escapes, multi-line values, byte order mark), and a
  scoped configuration tree for single- and multi-VDOM backups. Encrypted
  backups (`#FGBK`), YAML exports, PEM/key files, and other files are
  refused with a description of what they look like, never by quoting them.
- Extractors:
  - admin HTTPS (TLS versions, TLS 1.3 cipher suites) and admin SSH (key
    exchange including the hybrid `mlkem768x25519-sha256`, ciphers, MACs,
    host keys) from `system global` and `system ssh-config`;
  - IPsec phase1 and phase2, including the `-interface` tables: IKE version,
    proposals, DH groups, RFC 9370 additional key exchanges (ML-KEM, and
    Fortinet's Kyber, FrodoKEM, BIKE, and HQC IDs, marked private-use),
    PSK presence and form, and signature authentication linked to the
    certificate and its key algorithm;
  - certificates from `vpn certificate local/ca/remote` and
    `certificate local/ca/remote`: subject, issuer, validity, key and
    signature algorithms with OIDs, public-key fingerprint, private-key
    presence and form, expiry, and the CA/Browser Forum validity limit as
    information; VDOM entries that refer to global certificates are linked,
    not duplicated;
  - SSL VPN / Agentless VPN (`vpn ssl settings`): TLS versions, cipher
    suites, TLS groups including the ML-KEM and hybrid groups (TLS 1.3
    only), the server certificate, and DTLS on 7.4.12.
- Per-version FortiOS default tables (7.4.12, 7.6.3–7.6.7, 8.0.1) with the
  source of each default; every value is recorded as configured, default,
  or unknown.
- Shared algorithm components with evidence for every configured location,
  `nistQuantumSecurityLevel` on public-key algorithms and ML-KEM, and
  coverage metadata listing sections that were and were not inventoried.
- Warnings on stderr with file and line (plaintext PSKs and private keys,
  expired or unparseable certificates, unknown options, sections not yet
  covered, and more; see MAPPING.md §5).
- Documentation: README, MAPPING.md (CERT-In Table 9 → CycloneDX 1.6
  mapping: 19 of 30 elements covered and 5 partially; every property and
  warning; design decisions; limitations), FortiOS research notes,
  SECURITY.md, CONTRIBUTING.md.
- CI: `go mod verify`, gofmt, vet, staticcheck, govulncheck, race-enabled
  tests, fuzz smoke runs, REUSE lint, and CycloneDX schema validation of
  every golden file. Releases for Linux, macOS, and Windows on amd64 and
  arm64, with checksums, an SBOM per archive, Sigstore keyless signing, and
  build provenance attestations.

### Security

- Secret values (pre-shared keys, `ENC` values, passwords, private keys) are
  never written to the CBOM or printed; only their presence and form are
  reported. Private keys are classified by their PEM header lines and never
  decoded; only CERTIFICATE blocks are decoded.
- Evidence records the backup's file name only, not its path.
- CBOM files written with `-o` have mode 0600, since a CBOM is confidential
  infrastructure data. `--force` replaces the file through a temporary file
  and a rename (atomic on Linux and macOS, best-effort on Windows), without
  following a symlink at the output path.

### Known limitations

TLS 1.2 cipher suites are reported as unknown; defaults exist only for the
firmware versions above; some crypto sections are not inventoried yet; only
the first certificate of a chain is read. See
[MAPPING.md §7](MAPPING.md#7-known-limitations-and-accepted-risks).

### Note on the commit history

Commit `a6e40e8` is labelled `test(emit): cover the certificate, key,
cipher-suite, and IKEv2 builders`, but it also changes behaviour: the
certificate SHA-256 fingerprint and serial number, documented as the
`cbom-netscan:cert:sha256` and `cbom-netscan:cert:serial` properties, were
never emitted until that commit. It should have been labelled `fix(emit)`.
Tools that build release notes from commit types will file it under tests;
this changelog is the reference. Published history is not rewritten.

[0.1.1]: https://github.com/yechuri-github64/cbom-netscan/releases/tag/v0.1.1
[0.1.0]: https://github.com/yechuri-github64/cbom-netscan/releases/tag/v0.1.0
