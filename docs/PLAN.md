# cbom-netscan: 90-day technical execution plan

*Written 11 Oct 2026 (IST). The plan runs Mon 12 Oct 2026 to Sun 10 Jan 2027, 13 weeks. Context comes from `/workspace/oss-mission-report.md`. I checked every external fact on 11 Oct 2026 against a primary source, either by fetching the page/PDF or by cloning the repo and running the tool (method in §0). **(est.)** marks my estimates and judgement calls. **⚠ UNVERIFIED** marks things I could not confirm. Don't treat those as facts until you've checked them yourself.*

Fixed inputs (your decisions): Go, CycloneDX 1.6 CBOM, Phase 1 = FortiGate offline config parser plus a live TLS collector that ingests testssl.sh JSON. Testing uses only sanitised synthetic configs and FortiOS VM eval, never production. Upstream into cbomkit-theia if the maintainers agree, otherwise a standalone repo whose output CBOMkit can import. Time budget: about 10–12 h/week on nights and weekends **(est.)**, so roughly 130–150 h over 13 weeks **(est.)**.

---

## 0. Verification log: what I checked, and what changes the plan

### 0.1 Verified facts that drive design decisions

| # | Fact | How verified / source | Consequence for the plan |
|---|---|---|---|
| V1 | CycloneDX 1.6 `cryptoProperties` has exactly `assetType` (enum `algorithm`, `certificate`, `protocol`, `related-crypto-material`), `algorithmProperties`, `certificateProperties`, `relatedCryptoMaterialProperties`, `protocolProperties` and `oid`. Only `assetType` is required. | Parsed `bom-1.6.schema.json` at tags 1.6, 1.6.1, 1.6.2 ([schema](https://github.com/CycloneDX/specification/blob/1.6.2/schema/bom-1.6.schema.json)) | Field names in §2 and §5 come from the schema, not from memory |
| V2 | `protocolProperties` = `type` (enum `tls`, `ssh`, `ipsec`, `ike`, `sstp`, `wpa`, `other`, `unknown`), `version`, `cipherSuites[]` (`name`, `algorithms[]` refs, `identifiers[]`), `ikev2TransformTypes` (`encr`, `prf`, `integ`, `ke`, `auth` as bom-ref arrays, plus `esn` bool), `cryptoRefArray`. **There is no TLS-groups field in 1.6.** | Same schema | In 1.6, key-exchange groups go into `cryptoRefArray` as algorithm components plus namespaced `properties`. This matches what the theia maintainer proposed for #212 |
| V3 | CycloneDX 1.7 (released 21 Oct 2025; 1.7.2 on 17 Sep 2026) adds `cipherSuite.tlsGroups`, structured IKEv2 objects, `certificateProperties.serialNumber`/`fingerprint`/`certificateState`, and so on. | [Releases](https://github.com/CycloneDX/specification/releases), [bom-1.7 schema](https://github.com/CycloneDX/specification/blob/1.7/schema/bom-1.7.schema.json) | Keep 1.6 as the default; build the internal model so it's ready for 1.7; add a 1.7 emitter in a later release |
| V4 | `cyclonedx-go` v0.12.0 supports `SpecVersion1_6` and `SpecVersion1_7`. `EncodeVersion(bom, SpecVersion1_6)` strips 1.7-only fields (e.g. `TLSGroups` is nilled in `convert.go`). IKEv2 types serialise as a bare bom-ref string when `BOMRef` is set (the 1.6 form). | Cloned [cyclonedx-go@v0.12.0](https://github.com/CycloneDX/cyclonedx-go/tree/v0.12.0); read `cyclonedx_json.go`, `convert.go` | Use this library. It's also what theia uses (theia `go.mod`) |
| V5 | CERT-In Table 9 element names (verbatim). **Algorithms:** Name, Asset Type, Primitive, Mode, Crypto Functions, Classical security level, OID, List. **Keys:** Name, Asset Type, id, state, size, Creation Date, Activation Date. **Protocols:** Name, Asset Type, Version, Cipher Suites, OID. **Certificates:** Name, Asset Type, Subject Name, Issuer Name, Not Valid Before, Not Valid After, Signature Algorithm Reference, Subject Public Key Reference, Certificate Format, Certificate Extension. | `pdftotext -layout` on the [CERT-In v2.0 PDF](https://cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf), printed pp. 45–48 (dated 09.07.2025) | Basis for the §5 table and the `assess certin` profile (30 element checks) |
| V6 | FortiOS `config vpn ipsec phase1-interface` has `proposal`, `dhgrp`, `addke1` … `addke7`, `ike-version`, `authmethod`, `certificate`, `ppk`/`ppk-secret`, `qkd`/`qkd-hybrid`, `childless-ike`, `signature-hash-alg`, `rsa-signature-format`. `addke` option IDs: 0 NONE, **35 ML-KEM-512, 36 ML-KEM-768, 37 ML-KEM-1024**, 1080–1082 KYBER512/768/1024, 1083–1085 FRODO L1/L3/L5, 1089–1091 BIKE L1/L3/L5, 1092–1094 HQC128/192/256. `dhgrp` options: 1, 2, 5, 14–21, 27–32. | [FortiOS 7.6.3 CLI Reference PDF](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/e628f3e3-1a47-11f0-b13a-ca4255feedd9/FortiOS-7.6.3-CLI_Reference.pdf) pp. ~2179–2215; [FortiOS 8.0.1 PQC for IPsec](https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/229631/post-quantum-cryptography-for-ipsec-key-exchange) | The parser's lookup tables come from these. IDs 35–37 match the IANA IKEv2 Transform Type 4 registry ([IANA CSV](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters-8.csv)). 1080–1094 are Fortinet-specific |
| V7 | In 7.6.3, `config vpn ssl settings` is titled "**Configure Agentless VPN**". It has `ssl-min-proto-ver` (default tls1-2), `ssl-max-proto-ver` (default tls1-3), `algorithm` (high/medium/default/low, default high), `banned-cipher`, `ciphersuite` (TLS 1.3 list), `servercert`, `client-sigalgs`. It's **not available** on 40F/60F/61F/90G/91G and some other models. `set tls-groups` (P-256…, FFDHE…, ML-KEM512/768/1024, X25519-MLKEM768, P-256-MLKEM768, P-384-MLKEM1024) appears in **7.6.6** docs. | CLI Ref 7.6.3 pp. 2253–2261; [7.6.6 PQC for Agentless VPN](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/43632) | The parser has to be version-aware: `tls-groups` absent ≠ classical-only on builds older than 7.6.6 |
| V8 | `config system global`: `strong-crypto` (default enable), `admin-https-ssl-versions` (default tlsv1-2 tlsv1-3), `admin-https-ssl-ciphersuites`, `admin-https-ssl-banned-ciphers`, `ssl-min-proto-version` (default TLSv1-2), `ssl-static-key-ciphers` (default enable), `dh-params` (default 2048), `admin-server-cert`. SSH algorithms live in `config system ssh-config` (`ssh-kex-algo`, `ssh-enc-algo`, `ssh-mac-algo`, `ssh-hsk-algo`). In 7.6.3 the `ssh-kex-algo` options contain **no PQ KEX**. | CLI Ref 7.6.3 pp. ~1470–1530, `ssh-config` section | Admin-plane TLS/SSH become separate protocol components |
| V9 | `config vpn certificate local`: `certificate` (PEM), `private-key`, `password`, `source` (factory/user/bundle), `range`, **`enroll-protocol` (none/scep/cmpv2/acme2/est)**, `acme-*`, `auto-regenerate-days`. | CLI Ref 7.6.3 pp. 2129–2136 | `enroll-protocol` is the offline signal for "automation path exists" in the 47-day check |
| V10 | testssl.sh JSON. Flat `--jsonfile`/`-oj` is an array of `{id, ip, port, severity, cve, cwe, [hint], finding}`. Pretty `--jsonfile-pretty`/`-oJ` is `{Invocation, at, version, openssl, startTime, scanResult[], scanTime}`; each `scanResult[]` target has `targetHost, ip, port, rDNS, service` plus section arrays (`pretest, protocols, grease, ciphers, serverPreferences, fs, serverDefaults, vulnerabilities, cipherTests, browserSimulations, rating`). **`scanResult[]` can also contain bare finding objects** (e.g. `DNS_HTTPS_rrecord`). IDs seen in a real run: `TLS1_2`/`TLS1_3` ("offered"), `cipher-tls1_2_xc02f`, `supportedciphers_TLSv1_2`, `FS_KEMs` ("X25519MLKEM768"), `FS_ECDHE_curves`, `DH_groups`, `FS_TLS12_sig_algs`, `FS_TLS13_sig_algs`, `cert` (leaf PEM), `cert_notBefore`/`cert_notAfter` (`YYYY-MM-DD HH:MM`, UTC), `cert_signatureAlgorithm` ("SHA256 with RSA"), `cert_keySize` ("RSA 2048 bits (exponent is 65537)"), `cert_caIssuers`, `cert_serialNumber`, `cert_fingerprintSHA256`. When a server has more than one certificate, IDs get the suffix `" <hostCert#N>"`. | Cloned [testssl.sh](https://github.com/testssl/testssl.sh) 3.3dev @7ad4a6e (`fileout_json_*`, `run_fs`, `cipher_pref_check`), **and ran it** against OpenSSL 3.5.7 `s_server -groups X25519MLKEM768:X25519:P-256` with `-p -E -S -f --jsonfile-pretty` | The user brief said `cipher-*`; the exact pattern is `cipher-<proto>_x<hex>` and it only comes from `-E`/per-protocol runs. `-e` gives `cipher_x<hex>` with no protocol. `FS_KEMs` also exists on the 3.2 branch (latest release v3.2.4, 12 Jul 2026) |
| V11 | cbomkit-theia: Apache-2.0, Go (`go 1.26.8`), Cobra. Plugin interface: `GetName()`, `GetExplanation()`, `GetType() PluginType`, `UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error`. Plugins are registered in `scanner.GetAllPluginConstructors()`. A `--bom/-b` flag takes "BOM file to be verified and enriched". New files need the PQCA Apache header (`addlicense -c "PQCA" -l apache`). **DCO is enforced** (a "DCO" check runs on PRs, e.g. #230). No CLA file found. | Cloned [cbomkit-theia@445206c](https://github.com/cbomkit/cbomkit-theia) (30 Sep 2026); `CONTRIBUTING.md`, `AGENTS.md`, `scanner/plugins/plugin.go`; GitHub check-runs API | All commits use `git commit -s`. Licence = Apache-2.0 |
| V12 | theia **#212** is open. On 29 Sep a volunteer (SemyonAndreyev) claimed it. On 30 Sep maintainer n1ckl0sk0rtge set a plan: step 1, record `Groups` as a `theia:openssl:*` property in 1.6; step 2, structured `cipherSuite.tlsGroups` "once Theia's CycloneDX 1.7 support is ready end to end". No PR from the volunteer as of 11 Oct. | GitHub API | **Don't take #212.** Review or test the PR when it appears |
| V13 | theia **PR #149** (PQC readiness plugin) is open and stale. Maintainer san-zrl (10 Dec 2025, 4 May 2026): wants assessment "independent of the scanning". CBOMkit has an optional external compliance checker that is "an Open Policy Agent instance". | GitHub API | Assessment stays in your repo, or goes into cbomkit's OPA policies, never into a theia plugin |
| V14 | testssl.sh **#3116** is open. Volunteer AAH20 claimed it on 16 Aug. Collaborators asked for an example report for google.com "before code is written" (30 Aug). No PR by AAH20 as of 11 Oct. Licence is GPL-2.0. | GitHub API | Offer to test and give consumer-side input on JSON IDs; don't implement. Don't vendor any testssl.sh code or data files (GPL-2.0) into an Apache-2.0 repo |
| V15 | **Bug found:** `cbomkit/opa/quantum_safe.rego` line 14 lists primitive `"keyagree"`, but the CycloneDX 1.6 and 1.7 enum value is `"key-agree"` (and CBOMkit's built-in Java service uses `Primitive.KEY_AGREE`). Result: under the OPA path, an ECDH/X25519 key-agreement algorithm is classified `symmetric_na` instead of `quantum-vulnerable`. | Ran OPA 1.21.1 `opa eval` on a 2-component CBOM: ECDH came back `"result":"NA","rule":"symmetric_na"`. With `"key-agree"` it came back `quantum-vulnerable`. Wrote an `opa test` file that fails on main and passes with the fix | A ready-made, verifiable first PR for Week 1 (§3) |
| V16 | Go 1.26 `crypto/x509.ParseCertificate` parses an OpenSSL 3.5 ML-DSA-65 certificate **without error** but returns `SignatureAlgorithm=0` and `PublicKeyAlgorithm=0` (Unknown). | Generated a cert with `openssl req -x509 -newkey mldsa65` and parsed it with go1.26.9 | Collectors must read the signature/SPKI OIDs from the raw TBS when the enum is Unknown. Same class of bug as theia #227/#235 |
| V17 | FortiGate-VM permanent eval licence: one per FortiCloud account, **"low encryption operation only"** (except GUI management and FortiManager), max 1 CPU / 2 GB, max three interfaces, firewall policies and routes, no FortiCare/FortiGuard, at most 2 VDOMs. | [FortiOS 8.0.1 admin guide: Permanent trial mode](https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/441460/permanent-trial-mode-for-fortigate-vm) | Live strong-crypto IPsec/TLS testing on the eval VM is probably impossible. Use it only to check config syntax (see ⚠U2) |
| V18 | Fortinet EULA (Sept 2026 version) §2 forbids: (a) reverse engineering/**decrypting**/distributing the Software; (e) disclosing **benchmarking or performance measurements**; (g) use on a device you don't own and control; (h) sharing **non-public features or content** of the software with third parties; (i) accessing the Software "to build a competitive product … or to copy any ideas, features, functions". §1: internal business purposes only. §3: confidentiality. | [Fortinet EULA PDF](https://www.fortinet.com/content/dam/fortinet/assets/legal/EULA.pdf) | Fixture rules in §4.5 |
| V19 | Pinned tool versions as of 11 Oct 2026: goreleaser v2.18.3, cosign v3.1.3, cosign-installer v4.1.2, actions/attest-build-provenance v4.2.2 (has `subject-checksums`), anchore/sbom-action v0.24.3, syft v1.54.1, cyclonedx-cli v0.33.1, cobra v1.10.2, goreleaser-action v7.2.3, scorecard-action v2.4.4, govulncheck-action v1.1.0. goreleaser cosign recipe: `sign-blob --bundle=${signature} … --yes` over the checksum file; archives use `formats:` (plural, since v2.6). | GitHub releases API; [goreleaser sign docs](https://goreleaser.com/customization/sign/), [archive docs](https://goreleaser.com/customization/archive/) | §2.7 configs |
| V20 | TLS group codepoints: X25519MLKEM768 = 4588 (0x11EC), SecP256r1MLKEM768 = 4587, SecP384r1MLKEM1024 = 4589 (RFC 10024); MLKEM512/768/1024 = 512/513/514. OIDs (OpenSSL 3.5 object table): ML-KEM-512/768/1024 = 2.16.840.1.101.3.4.4.1/2/3; ML-DSA-44/65/87 = 2.16.840.1.101.3.4.3.17/18/19; AES-128-GCM 2.16.840.1.101.3.4.1.6 (matches the CERT-In example); SHA512withRSA 1.2.840.113549.1.1.13 (matches the CERT-In example). | [IANA TLS groups CSV](https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv); `openssl list` / `asn1parse` | `pkg/catalog` gets generated from the IANA CSVs |

### 0.2 Flags: unverified, or conflicting sources

| ID | Issue | What to do |
|---|---|---|
| ⚠U1 | **FortiOS defaults conflict.** The 7.6.3 CLI Reference lists default `ike-version` = 1 and `dhgrp` = 14. The 7.6.6 admin guide ([Phase 1 configuration](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/790613)) says "By default, FortiGate uses DH group 20 and 21 when configuring a VPN from the GUI or CLI". The CLI table doesn't show a default for `proposal`. Backups (`show`) **omit default values**. | Week 1 lab task: on the eval VM, `edit` a new phase1-interface with only `interface`/`remote-gw`, then compare `show` with `show full-configuration`. Encode per-version defaults in `defaults_<ver>.go` with a source comment. Emit a warning whenever a default is assumed |
| ⚠U2 | Whether the low-encryption eval VM's CLI **accepts** `set proposal aes256gcm-prfsha384`, `set addke1 36`, `set tls-groups X25519-MLKEM768`. | Week 1 lab task. If they're rejected, all strong-crypto fixtures are hand-authored from the CLI Reference and labelled "syntax per CLI Reference, not VM-validated" |
| ⚠U3 | Backup file header. I relied on `#config-version=<MODEL>-<ver>-FW-build<n>-<date>:opmode=…:vdom=…:user=…`, `#conf_file_ver=`, `#buildno=`, `#global_vdom=` from practice, not from a Fortinet document. I also didn't confirm the marker for **password-encrypted backups** or whether `config vpn certificate local` carries the PEM in backups. | Confirm on the eval VM in Week 1. The parser must **refuse** encrypted backups (no decryption, per EULA §2(a)) |
| ⚠U4 | The exact `tls-groups` tokens come from the 7.6.6 admin guide example, not a 7.6.6/8.0 CLI Reference table. | Fetch the 7.6.6 and 8.0.x CLI references in Week 10 |
| ⚠U5 | CERT-In Table 9 layout: the PDF's vertical labels put "**List**" under Algorithms. That's inferred from layout, and its description mentions "quantum device". | Treat as Algorithms/List and note the ambiguity in MAPPING.md |
| ⚠U6 | Table 9 "OID" for **Protocols**: I found no registry of OIDs identifying TLS/IPsec/SSH as protocols. | Mark `not-applicable` in the checker, not "missing" |
| ⚠U7 | CBOMkit viewer import of a cbom-netscan CBOM is untested. The theia `-b` enrich flow with an external CBOM is untested. | Week 2 and Week 7 tasks |
| ⚠U8 | PQCA TSC call time ("bi-weekly Tuesdays 4 PM CET") comes from a Dec 2025 comment in PR #149. That's 19:30 IST under CEST (until 25 Oct 2026) and 20:30 IST under CET. | Check [pqca.org/calendar](https://pqca.org/calendar) before joining |
| ⚠U9 | Whether `cosign verify-blob` with a bundle works fully offline (for air-gapped users). | Test in Week 12 and document the result |
| ⚠U10 | Holiday load (Diwali in early Nov, Christmas/New Year) reflected in lighter weeks is **(est.)**. | Adjust to your calendar |

### 0.3 Prototype already on the box (reference only)

`/workspace/cbom-netscan-proto/` is a throw-away spike I built to check the claims above. Treat it as reference, not as your repo's first commit; rewrite it in your own style so you understand it.
- `internal/fortios`: tokenizer/tree (quotes, escapes, multi-line PEM) plus an extractor for phase1-interface, certificate local and vpn ssl settings. Includes a fuzz target (45 s, no crashes) and a test that no secrets leak into the output.
- `internal/testssl`: loads both JSON forms.
- `internal/emit`: CycloneDX 1.6 through cyclonedx-go.
- `testdata/golden-example.cdx.json` **passes `cyclonedx validate --input-version v1_6 --fail-on-errors`** (cyclonedx-cli 0.33.1). A deliberately broken copy is rejected.
- `scripts/scrub_fortios.py` (§4.4) is tested on a fake VM export.
- `upstream/cbomkit-opa/quantum_safe_test.rego` is the V15 test.
- Known shortcuts in the spike:
  - HMAC used as both PRF and integrity is deduped into one asset. The real tool should keep separate role assets.
  - cyclonedx-go always emits `esn` (no omitempty), so "unknown" shows as `false`. Add a property to mark it unknown.
  - The V16 raw-OID fallback for unknown certificate algorithms isn't implemented yet.

---
## 1. Week-by-week plan (13 weeks)

Conventions: Conventional Commits, every commit signed off with `git commit -s` (DCO). `<you>` = your GitHub handle. Hours are **(est.)**. Each week ends with a tag or a written "no tag because …" in `CHANGELOG.md`.

### Week 1 · 12–18 Oct · Align upstream, bootstrap, lab feasibility · ~11 h
**Build**
- Create `github.com/<you>/cbom-netscan`. Add Apache-2.0 `LICENSE`, `NOTICE`, `REUSE.toml` (testdata = CC0-1.0), `go.mod` with `go 1.26` (theia uses `go 1.26.8`), DCO GitHub App. Branch protection moved to the v0.1.0 go-public checklist (Week 5): it is free once the repo is public.
- Write `docs/MAPPING.md` (copy of §5) and `docs/SCOPE.md`. Scope rules: offline config parsing, ingesting testssl.sh JSON you produced yourself, no live scanning without the `--authorized` flag, never reading secrets.
- Lab: FortiGate-VM eval on KVM/VirtualBox, host-only network, personal FortiCloud account. Run the ⚠U1/⚠U2/⚠U3 checks and keep raw notes **private** (`~/lab-notes/`, outside git).
- Generate the testssl.sh fixture matrix seed with OpenSSL 3.5 `s_server` (already proven to work, V10).

**Commits / PRs / tags**
- `chore: initialise module, Apache-2.0, REUSE, DCO`
- `docs: add CERT-In Table 9 → CycloneDX 1.6 mapping`
- `docs: scope, threat model, fixture policy`
- `ci: go vet, go test, cyclonedx-cli schema validation`
- **Upstream PR (cbomkit):** `fix(opa): match CycloneDX primitive "key-agree" in quantum_safe policy` plus `opa/quantum_safe_test.rego` (§3.4). **Done:** cbomkit #379, merged 2026-10-12.
- **Upstream issue (theia):** appliance-config scope question (§3.1). **Comments:** theia #235 (§3.2), testssl.sh #3116 (§3.3)
- No tag.

**Post:** LinkedIn plus the FOSS United forum ([forum.fossunited.org](https://forum.fossunited.org)). Draft topic: "CERT-In's CBOM Table 9 has 30 elements. Here's how each maps to CycloneDX 1.6, and which ones a firewall config can actually give you." Link `MAPPING.md`.

**Exit:** 4 upstream touchpoints posted; ⚠U1–U3 answered in private notes.

### Week 2 · 19–25 Oct · Model, emitter, catalog, golden harness · ~11 h
**Build**
- `pkg/model` (§2.3); `pkg/emit/cdx16` with `cyclonedx-go@v0.12.0` and `EncodeVersion(…, SpecVersion1_6)`.
- Deterministic output: bom-ref = `crypto/` + first 16 hex chars of SHA-256(type‖canonical-name‖location). Serial and timestamp come from `SOURCE_DATE_EPOCH` when set. Components and properties are sorted.
- `pkg/catalog`: `go generate` parses IANA `tls-parameters-4.csv` (cipher suites), `tls-parameters-8.csv` (groups) and `ikev2-parameters-5/-6/-7/-8.csv` (ENCR/PRF/INTEG/KE) into Go maps. Each CSV file's SHA-256 is recorded in the generated file header.
- `internal/golden`: `go test ./... -update` rewrites `testdata/golden/*.cdx.json`.
- Import a golden CBOM into the CBOMkit viewer (`docker compose up` from the cbomkit repo, then upload) and write down what renders (⚠U7).

**Commits:** `feat(model): vendor-neutral crypto inventory model` · `feat(emit): CycloneDX 1.6 JSON emitter with deterministic bom-refs` · `feat(catalog): generate TLS/IKEv2 registries from IANA CSVs` · `test: golden-file harness with -update`

**Post:** null community (your local chapter's mailing list/Telegram, or a [null.community](https://null.community) event idea). Draft topic: "How CycloneDX 1.6 represents an IKEv2 tunnel, and why TLS key-exchange groups need 1.7's `tlsGroups`."

### Week 3 · 26 Oct–1 Nov · testssl.sh collector → `v0.1.0-alpha.1` · ~12 h
**Build**
- `pkg/collect/testssl`: flat and pretty loaders. Group findings by `ip|port`. Skip bare objects in `scanResult`. Strip the `" <hostCert#N>"` suffix into a cert index. Detect version from the pretty `version` field. Parse IPv6 `[::1]`.
- Map protocol IDs (`SSLv2…TLS1_3` with finding prefix `offered`), `cipher-<proto>_x<hex>` (split hex into the `identifiers` byte pairs `0xC0`,`0x2F`, as in the CycloneDX example), `FS_KEMs`, `FS_ECDHE_curves`, `DH_groups`, and `cert` PEM → x509. Fall back to raw OIDs for unknown algorithms (V16).
- Fixture matrix (all on localhost, your own `s_server`): (a) X25519/P-256 only; (b) +X25519MLKEM768; (c) MLKEM1024 pure plus hybrid; (d) RSA-1024 SHA-1 cert; (e) dual RSA+ECDSA certs (exercises `<hostCert#2>`); (f) ML-DSA-65 cert; (g) 47-day cert; (h) 825-day cert. Each in both `-oj` and `-oJ` form. Scrub the `at` and `Invocation` fields, which contain your hostname and paths.
- `FuzzLoad` fuzz target.
- `cbom-netscan collect tls --testssl-json FILE… -o out.cdx.json`

**Commits:** `feat(testssl): ingest flat and pretty JSON` · `feat(testssl): map ciphers, KEMs, curves, certificates` · `test(testssl): fixture matrix from OpenSSL 3.5 s_server` · `feat(cli): collect tls`
**Tag:** `v0.1.0-alpha.1` (goreleaser `--snapshot` locally; no signed release yet)

**Post:** LinkedIn and FOSS United forum. Draft topic: "testssl.sh JSON → CycloneDX CBOM: what maps cleanly (protocols, suites, certs), what doesn't (groups in 1.6), and why `-E` not `-e`."

### Week 4 · 2–8 Nov · FortiOS tokenizer and tree · ~8 h (festival week, est.)
**Build**
- `pkg/parse/fortios`: tokenizer (double quotes, `\` escapes, multi-line quoted PEM), `config`/`edit`/`set`/`unset`/`next`/`end` tree, header parse, line numbers, `config global` / `config vdom` / `edit root` nesting. **Reject** password-encrypted backups with a clear error (⚠U3).
- Secret denylist (`psksecret`, `password`, `private-key`, `ppk-secret`, `*-password`, `*-secret`, …). The tree keeps those values as `[REDACTED]` at parse time, so later code can't leak them.
- `FuzzParse` plus a round-trip property test (`render(parse(x))` re-parses to an equal tree).
- `scripts/scrub_fortios.py` (§4.4) and the CI guard `--verify-only testdata/fortios/*.conf`.

**Commits:** `feat(fortios): tokenizer and block tree` · `feat(fortios): redact secret keys at parse time` · `test(fortios): fuzz target and seeds` · `chore(fixtures): fail-closed scrubber and CI guard`

**Post:** your OWASP India chapter (e.g. the chapter meetup page/Slack under [owasp.org/chapters](https://owasp.org/chapters/)) plus LinkedIn. Draft topic: "Publishing firewall-config test fixtures without leaking anything: a fail-closed scrubber (RFC 5737/3849/2606 mapping, ENC removal, verifier)."

### Week 5 · 9–15 Nov · FortiOS extraction → `v0.1.0` (first signed release) · ~12 h
**Build**
- Extractors:
  - `vpn ipsec phase1-interface`: `proposal` → ENCR/PRF/INTEG, `dhgrp` + `addke1..7` → KE, plus `ike-version`, `authmethod`, `certificate`, `ppk`, `qkd`, `signature-hash-alg`.
  - `vpn certificate local`: PEM, `source`, `enroll-protocol`, `acme-*`, `auto-regenerate-days`.
  - `vpn ssl settings`: `ssl-min/max-proto-ver`, `ciphersuite`, `banned-cipher`, `algorithm`, `tls-groups`, `servercert`.
  - `system global`: `strong-crypto`, `admin-https-ssl-versions`, `admin-https-ssl-ciphersuites`, `admin-https-ssl-banned-ciphers`, `ssl-min-proto-version`, `ssl-static-key-ciphers`, `dh-params`, `admin-server-cert`.
- `defaults_7_6.go` with a CLI-Reference page citation on every default. A warning in the CBOM `properties` (`cbom-netscan:warning:N`) whenever a default is assumed.
- Usage edges in `dependencies`: `vpn ssl settings` → its `servercert` certificate; phase1 → its `certificate`.
- `cbom-netscan collect fortigate --config FILE [--fortios-version auto|7.6.3]`
- Release pipeline (§2.7): goreleaser, syft SBOM per archive, cosign bundle on `checksums.txt`, `actions/attest-build-provenance`.

**Commits:** `feat(fortios): ipsec phase1 extraction incl. addke1-7` · `feat(fortios): local certificates, agentless VPN, admin TLS` · `feat(fortios): version-aware defaults with warnings` · `ci: goreleaser release with SBOM, cosign bundle, build provenance`
**Go-public checklist (before tagging `v0.1.0`):**
- Make the repository public.
- Turn on branch protection for `main`: require the CI checks and DCO sign-off (free once the repo is public; moved here from Week 1).

**Tag:** `v0.1.0`

**Post:** GitHub Release notes plus [r/fortinet](https://www.reddit.com/r/fortinet/) (read the sub's self-promotion rules first) plus LinkedIn. Draft topic: "v0.1.0: read a FortiGate config backup offline and list every IPsec proposal, DH/ML-KEM group and certificate as a CycloneDX CBOM. It never reads PSKs or keys."

### Week 6 · 16–22 Nov · Assessors · ~12 h
**Build**
- `pkg/assess/certin`: Table 9 completeness for each component by asset type, giving 30 element checks. Outcomes: `present`, `missing`, `not-applicable` (e.g. protocol OID, ⚠U6) or `not-derivable-offline` (e.g. the exact TLS 1.2 suite list from `algorithm high`).
- `pkg/assess/pqc` follows the testssl #3116 consensus that key exchange and authentication are separate questions:
  - `kex: classical-only | hybrid-pqc | pure-pqc | legacy-pqc-draft (KYBER 1080–1082) | non-nist-kem (FRODO/BIKE/HQC 1083–1094) | unknown`
  - `auth: classical | pqc | unknown`
  - HNDL exposure goes only on `classical-only` key exchange.
- `pkg/assess/certlife`: validity length checked against [CA/B Forum SC081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) steps (200 d from 15 Mar 2026, 100 d from 15 Mar 2027, 47 d from 15 Mar 2029). An automation path exists if `enroll-protocol ∈ {acme2, est, scep, cmpv2}`.
- Rules live as versioned YAML data (`policies/*.yaml`) with a source URL on every rule. Output in Markdown, JSON and SARIF 2.1.0 (optional).
- `cbom-netscan assess --cbom FILE --profile certin-t9,pqc,certlife --format md|json|sarif`

**Commits:** `feat(assess): CERT-In Table 9 completeness profile` · `feat(assess): PQC key-exchange/authentication classification` · `feat(assess): certificate lifetime and automation readiness` · `feat(cli): assess`
**Tag:** `v0.2.0-alpha.1`

**Post:** null chapter plus LinkedIn. Draft topic: "Ran a CERT-In Table 9 completeness check on a synthetic FortiGate: 7 of 30 elements are impossible to fill from config alone. Here's which ones and why."

### Week 7 · 23–29 Nov · Upstream decision point · ~12 h
**Branch on the theia answer to §3.1:**
- **Yes:** fork theia and open a **draft PR** `feat(plugins): add fortios plugin for FortiOS configuration backups`. Add `scanner/plugins/fortios/fortios.go` (`PluginTypeAppend`), `fortios_test.go` and `testdata/fortios/*.conf` (CC0, synthetic). Register `"fortios": fortios.NewFortiOSPlugin` in `GetAllPluginConstructors()`. Properties use `theia:fortios:*`. PQCA headers via `addlicense -c "PQCA" -l apache`. Follow theia `AGENTS.md`: testify, `t.Run`, CLI output example in the PR body.
- **No or silence after 21 days:**
  - Freeze `pkg/` APIs at v0 for importers.
  - Write `docs/cbomkit-import.md`: upload to the CBOMkit viewer, and the `cbomkit-theia dir ./dir -b netscan.cdx.json` enrich flow (test it; ⚠U7).
  - Put the theia adapter in a **separate module** `adapters/theia/go.mod`, so the core never pulls theia's Docker/gitleaks dependencies.
- Join one PQCA TSC call (⚠U8) with a 5-minute demo.

**Commits:** `feat(adapters/theia): Plugin implementation over Filesystem` · `docs: CBOMkit import and theia enrich flow`

**Post:** the theia PR/issue thread plus LinkedIn. Draft topic: "Upstreaming a network-appliance plugin to the Linux Foundation's CBOMkit-theia: the design trade-offs (1.6 properties now, 1.7 tlsGroups later)."

### Week 8 · 30 Nov–6 Dec · Phase 2, merge, authorised live run → `v0.2.0` · ~11 h
**Build**
- `vpn ipsec phase2-interface` (`proposal`, `pfs`, `dhgrp`, `addke1..7`, `phase1name`) becomes `ipsec` protocol components, linked to their phase1 via `dependencies`.
- `cbom-netscan merge a.cdx.json b.cdx.json -o merged.cdx.json`. Dedupe certificates by SHA-256 fingerprint and record config-vs-live discrepancies as properties, e.g. config says `tls-groups X25519-MLKEM768` but live `FS_KEMs` is empty.
- `collect tls --run host:port --authorized`. This calls testssl.sh as a separate process with `--quiet --warnings off -p -E -S -f -P --jsonfile-pretty`, runs no vulnerability tests by default, and refuses to run without `--authorized`.

**Commits:** `feat(fortios): phase2 selectors as ipsec protocol assets` · `feat(cli): merge with config/live discrepancy properties` · `feat(testssl): optional authorised runner`
**Tag:** `v0.2.0`

**Post:** Show HN plus the FOSS United forum. Draft topic: "Show HN: cbom-netscan, a CycloneDX CBOM from FortiGate configs plus testssl.sh, for India's 2027 PQC 'foundations' deadline."

### Week 9 · 7–13 Dec · User validation · ~10 h
- 5–8 practitioner sessions with utility/discom network engineers, SIs and CERT-In-empanelled auditors. They run the tool **locally** on their own lab configs. **Never accept their configs.** Collect feedback through an issue template. Ask them: "Which output field would you put in an audit report? What's missing?"
- Docs: 3-minute quickstart, air-gapped install (verify the release offline, ⚠U9), FAQ on what the tool never does.
- Submit a talk proposal: a null chapter meetup or IndiaFOSS CFP when it opens (check [fossunited.org](https://fossunited.org)).

**Commits:** `docs: quickstart, air-gapped install, FAQ` · `chore: issue templates (no-config-paste warning)`

**Post:** LinkedIn. Draft topic: "What 6 network engineers told me about inventorying VPN crypto on appliances." Give numbers, no names.

### Week 10 · 14–20 Dec · Version breadth and robustness → `v0.3.0-alpha.1` · ~11 h
- Default tables for FortiOS 7.4.x and 8.0.x from their CLI references (⚠U4). Fixtures for each version. Handle `show full-configuration` vs backup, and multi-VDOM.
- `config system ssh-config` → `ssh` protocol component (`ssh-kex-algo`, `ssh-enc-algo`, `ssh-mac-algo`, `ssh-hsk-algo`). 7.6.3 has no PQ KEX (V8).
- Nightly fuzz workflow (5 min per target) that uploads the corpus as an artefact.

**Commits:** `feat(fortios): 7.4 and 8.0 defaults` · `feat(fortios): admin SSH algorithms` · `ci: nightly fuzzing`
**Tag:** `v0.3.0-alpha.1`

**Post:** LinkedIn plus FOSS United forum. Draft topic: "FortiOS backups omit default values, so a naive config-based CBOM is wrong. How cbom-netscan handles defaults per version (and warns)."

### Week 11 · 21–27 Dec · Buffer, plus assessment upstream · ~8 h (holidays, est.)
- If cbomkit merged V15 and the maintainers agree in an issue first: propose `opa/certin_t9.rego`, a CERT-In completeness policy. This keeps assessment out of scanning, as asked in #149.
- Otherwise: catch-up and bug triage.

**Post:** a GitHub issue in cbomkit. Draft topic: "Proposal: a CERT-In CBOM minimum-elements policy (Rego) for the OPA compliance path."

### Week 12 · 28 Dec–3 Jan · Supply-chain hardening → `v0.3.0` · ~10 h
- `SECURITY.md` (private vulnerability reporting enabled), `docs/THREAT_MODEL.md`, OpenSSF Scorecard action, actions pinned by SHA (Dependabot for actions plus gomod), `govulncheck`.
- A reproducible-build check: two clean `goreleaser build --snapshot` runs give identical checksums (`-trimpath`, `mod_timestamp`).
- Document `cosign verify-blob` and `gh attestation verify`.

**Commits:** `ci: scorecard, pinned actions, govulncheck` · `docs: security policy and threat model` · `build: reproducible builds check`
**Tag:** `v0.3.0`

**Post:** OWASP India chapter plus LinkedIn. Draft topic: "Shipping a security CLI the way you'd want vendors to: SBOM, cosign bundle, SLSA build provenance and a reproducibility check, in about 60 lines of YAML."

### Week 13 · 4–10 Jan · 90-day review and next quarter · ~10 h
- `docs/reports/90-day.md` scores every §6 metric (actual vs target) and applies §7.
- Roadmap v0.4: Check Point Gaia/management export parser, or deeper FortiOS coverage, depending on the user feedback from Week 9.
- Funding prep: a FOSS United grant draft (a ₹1–4 L ask fits their listed range per the earlier report **(est.)**) and a GitHub Secure Open Source Fund readiness checklist (needs real users first **(est.)**).

**Post:** LinkedIn plus FOSS United forum. Draft topic: "90 days of cbom-netscan: numbers, what failed, what's next."

---
## 2. Go project structure

### 2.1 Folder tree
```
cbom-netscan/
├── cmd/cbom-netscan/main.go          # calls cli.Execute()
├── internal/cli/                     # cobra commands (root, collect, merge, assess, validate, scrub, version)
├── pkg/
│   ├── model/                        # vendor-neutral inventory (no cyclonedx import)
│   ├── catalog/                      # generated IANA TLS/IKEv2 tables + OID table (go generate)
│   │   └── gen/                      # generator reading testdata/iana/*.csv
│   ├── parse/fortios/                # tokenizer, tree, header, secret redaction
│   ├── collect/
│   │   ├── fortigate/                # tree -> model (extract_*.go, defaults_7_4.go, defaults_7_6.go, defaults_8_0.go)
│   │   └── testssl/                  # JSON -> model, optional runner
│   ├── x509util/                     # cert -> model incl. raw-OID fallback (V16)
│   ├── merge/
│   ├── assess/{certin,pqc,certlife}/
│   └── emit/{cdx16,cdx17}/           # cdx17 lands after v0.3
├── adapters/theia/                   # SEPARATE go.mod: implements theia plugins.Plugin
├── policies/                         # assessment rules as YAML, each with source URL
├── scripts/scrub_fortios.py
├── testdata/
│   ├── fortios/*.conf                # synthetic, CC0-1.0
│   ├── testssl/*.json                # self-generated against localhost
│   ├── iana/*.csv                    # IANA registries (public)
│   └── golden/*.cdx.json
├── docs/{MAPPING,SCOPE,FIXTURES,THREAT_MODEL,cbomkit-import}.md
├── .github/workflows/{ci,release,fuzz-nightly,scorecard}.yml
├── .goreleaser.yaml
├── LICENSE  NOTICE  REUSE.toml  SECURITY.md  CONTRIBUTING.md  CHANGELOG.md
```

### 2.2 Key interfaces
```go
// pkg/model/iface.go
package model

import (
	"context"
	"io"
)

// Source is one input artefact (a config backup, a testssl.sh JSON file).
type Source struct {
	Path   string // used only for evidence.occurrences[].location
	Kind   string // "fortios-config", "testssl-json"
	Reader io.Reader
}

// Parser turns raw vendor text into a vendor-specific tree. It must never
// return secret values (they are replaced by Redacted at parse time).
type Parser[T any] interface {
	Parse(ctx context.Context, src Source) (T, []Warning, error)
}

// Collector produces vendor-neutral crypto assets from one source.
type Collector interface {
	Name() string                     // "fortigate", "testssl"
	Accepts(src Source) bool          // sniffing (header / JSON shape)
	Collect(ctx context.Context, src Source) (*Inventory, error)
}

// Assessor evaluates an inventory against a policy profile. It must not
// mutate the inventory (assessment separate from scanning, theia #149).
type Assessor interface {
	ID() string                       // "certin-t9", "pqc", "certlife"
	Assess(ctx context.Context, inv *Inventory) ([]Finding, error)
}

// Emitter serialises the inventory.
type Emitter interface {
	Format() string                   // "cyclonedx-1.6-json"
	Emit(ctx context.Context, w io.Writer, inv *Inventory, meta Meta) error
}

type Warning struct {
	Code    string // "default-assumed", "unknown-token", "encrypted-backup"
	Message string
	Ev      Evidence
}

type Finding struct {
	Rule     string   // "certin-t9/certificates/not-valid-after"
	AssetID  string
	Outcome  string   // present|missing|not-applicable|not-derivable-offline|pass|fail
	Severity string   // info|low|medium|high
	Detail   string
	Source   string   // URL of the rule's normative source
}
```

### 2.3 Data model
Field names mirror CycloneDX 1.6, so the emitter is a 1:1 mapping, and they stay ready for 1.7.
```go
// pkg/model/model.go
package model

import "time"

type AssetType string // values equal CycloneDX cryptoProperties.assetType
const (
	Algorithm       AssetType = "algorithm"
	Certificate     AssetType = "certificate"
	Protocol        AssetType = "protocol"
	RelatedMaterial AssetType = "related-crypto-material"
)

type Evidence struct {
	Location string // file path or "host:port"
	Line     int
	Symbol   string // e.g. "vpn ipsec phase1-interface/to-dr/proposal"
	Context  string // NEVER a secret
}

type Algorithm struct {
	Primitive              string   // drbg|mac|block-cipher|stream-cipher|signature|hash|pke|xof|kdf|key-agree|kem|ae|combiner|other|unknown
	ParameterSetIdentifier string   // "128", "768"
	Curve                  string   // "secp256r1", "x25519"
	Mode                   string   // cbc|ecb|ccm|gcm|cfb|ofb|ctr|other|unknown
	Padding                string
	CryptoFunctions        []string // generate|keygen|encrypt|decrypt|digest|tag|keyderive|sign|verify|encapsulate|decapsulate|other|unknown
	ClassicalSecurityLevel *int
	NISTQuantumLevel       *int     // 0..6
	ExecutionEnvironment   string   // "software-plain-ram" etc. Leave empty if unknown
	ImplementationPlatform string
}

type CipherSuite struct {
	Name        string   // IANA name, e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	AlgRefs     []string // asset IDs
	Identifiers []string // ["0xC0","0x2F"]
	Groups      []string // asset IDs; 1.6: cryptoRefArray+properties; 1.7: tlsGroups
}

type Protocol struct {
	Type         string // tls|ssh|ipsec|ike|sstp|wpa|other|unknown
	Version      string // "1.2", "1.3", "2"
	CipherSuites []CipherSuite
	IKEEncr, IKEPRF, IKEInteg, IKEKE, IKEAuth []string // asset IDs, IKEv2 only
	ESN          *bool  // nil = unknown -> omit
	Refs         []string // cryptoRefArray (IKEv1 algorithms, TLS groups in 1.6)
}

type Cert struct {
	SubjectName, IssuerName       string
	NotValidBefore, NotValidAfter *time.Time
	SignatureAlgorithmRef         string
	SubjectPublicKeyRef           string
	Format                        string // "X.509"
	Extension                     string // "pem"/"crt" (schema title: "Certificate File Extension")
	SHA256                        string // -> property in 1.6, fingerprint in 1.7
	Serial                        string // -> property in 1.6, serialNumber in 1.7
}

type Material struct {
	Type           string // public-key|private-key|secret-key|password|shared-secret|...
	ID             string // non-secret identifier only
	State          string // pre-activation|active|suspended|deactivated|compromised|destroyed
	AlgorithmRef   string
	Size           *int   // bits
	Format         string
	CreationDate   *time.Time
	ActivationDate *time.Time
	ExpirationDate *time.Time
	// NO Value field. cbom-netscan never stores key or secret values.
}

type Asset struct {
	ID         string    // deterministic, becomes bom-ref
	Type       AssetType
	Name       string
	OID        string
	Alg        *Algorithm
	Proto      *Protocol
	Cert       *Cert
	Mat        *Material
	Evidence   []Evidence
	Properties map[string]string // keys "cbom-netscan:<area>:<key>"
	DependsOn  []string          // usage edges -> dependencies[]
}

type Inventory struct {
	Assets   []*Asset
	Warnings []Warning
	Sources  []Source
	byKey    map[string]*Asset // dedupe on (Type, Name, OID)
}

type Meta struct {
	ToolVersion string
	Lifecycle   string // CycloneDX metadata.lifecycles phase: "operations" or "discovery"
	Created     time.Time
}
```
Notes:
- `Material` has no `Value` field on purpose, even though CycloneDX 1.6 defines `relatedCryptoMaterialProperties.value`.
- CERT-In's key-state examples ("active, revoked, or expired") are **not** in the 1.6 `state` enum. Expired keys stay `active` plus a property `cbom-netscan:key:expired=true`.

### 2.4 Cobra CLI
| Command | Key flags | Output |
|---|---|---|
| `cbom-netscan collect tls` | `--testssl-json FILE…`, `--run HOST:PORT --authorized`, `--testssl-path`, `-o` | CBOM 1.6 |
| `cbom-netscan collect fortigate` | `--config FILE…`, `--fortios-version auto\|7.4\|7.6\|8.0`, `--vdom`, `--strict` (warnings → exit 3), `-o` | CBOM 1.6 |
| `cbom-netscan merge` | `FILE…`, `-o` | CBOM 1.6 |
| `cbom-netscan assess` | `--cbom FILE`, `--profile certin-t9,pqc,certlife`, `--format md\|json\|sarif`, `--fail-on high` | report, exit 0/4 |
| `cbom-netscan validate` | `--cbom FILE`, `--spec 1.6` (embedded schema, `santhosh-tekuri/jsonschema/v6`) | exit 0/1 |
| `cbom-netscan scrub fortigate` | `--in --out`, `--verify-only` (wraps the scrubber logic in Go after v0.2) | exit 0/2 |
| `cbom-netscan version` | `--json` | version, commit, date |

Global flags: `--spec-version 1.6` (1.7 later), `--log-level`, `--no-color`. Exit codes: 0 ok, 1 invalid input, 2 secrets detected, 3 strict warnings, 4 assess threshold hit.

### 2.5 Testing
- **Golden files:** each `testdata/fortios/*.conf` and `testdata/testssl/*.json` gets an expected `testdata/golden/*.cdx.json`. The test compares bytes after deterministic emission, and every golden is schema-validated in CI with `cyclonedx validate --input-version v1_6 --fail-on-errors`, plus in-process with the embedded 1.6 schema.
- **Fuzzing:** `FuzzParse` (FortiOS tokenizer/tree), `FuzzLoad` (testssl JSON) and `FuzzCert` (x509util raw-OID fallback). Seeded from testdata. 60 s per target in PR CI and 5 min nightly. Crashers go in `testdata/fuzz/` and become regression tests.
- **Secret-leak invariant tests:**
  - Every fixture is parsed and emitted, then the output is searched for `ENC `, `-----BEGIN ` followed by `PRIVATE KEY`, and any value that came from a denylisted key. Build those marker strings in test code, never as literals in fixtures (lesson from the spike: the scrub guard flags literals).
- **Table tests:** proposal tokens, addke IDs, dhgrp IDs, and testssl finding strings, all taken from V6/V10.
- **Upstream cross-check:** in Week 7, run `cbomkit-theia` over the same directory to make sure bom-refs don't collide when merging.

### 2.6 CI: `.github/workflows/ci.yml`
```yaml
name: ci
on: [push, pull_request]
permissions: { contents: read }
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7          # pin by SHA in Week 12
      - uses: actions/setup-go@v7
        with: { go-version-file: go.mod }
      - run: test -z "$(gofmt -l .)"
      - run: go vet ./...
      - run: go test -race ./...
      - run: go test ./pkg/parse/fortios -run=^$ -fuzz=^FuzzParse$ -fuzztime=60s
      - run: go test ./pkg/collect/testssl -run=^$ -fuzz=^FuzzLoad$ -fuzztime=60s
      - name: schema-validate goldens
        run: |
          curl -sSfL -o cdx https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.33.1/cyclonedx-linux-x64 && chmod +x cdx
          for f in testdata/golden/*.cdx.json; do ./cdx validate --input-file "$f" --input-version v1_6 --fail-on-errors; done
      - name: fixture secret guard
        run: python3 scripts/scrub_fortios.py --verify-only testdata/fortios/*.conf
      - uses: golang/govulncheck-action@v1.1.0
```
Note: `-fuzz` runs one target in one package per invocation, so there is one step per target.

### 2.7 Release: goreleaser, SBOM, cosign, SLSA provenance
`.goreleaser.yaml` (goreleaser v2.18.x):
```yaml
version: 2
project_name: cbom-netscan
before:
  hooks: [go mod tidy]
builds:
  - main: ./cmd/cbom-netscan
    env: [CGO_ENABLED=0]
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
    flags: [-trimpath]
    ldflags: [-s -w -X main.version={{.Version}} -X main.commit={{.Commit}} -X main.date={{.CommitDate}}]
    mod_timestamp: "{{ .CommitTimestamp }}"
archives:
  - formats: [tar.gz]
    format_overrides:
      - goos: windows
        formats: [zip]
checksum:
  name_template: checksums.txt
sboms:
  - artifacts: archive        # syft must be on PATH
signs:
  - cmd: cosign
    signature: "${artifact}.sigstore.json"
    args: ["sign-blob", "--bundle=${signature}", "${artifact}", "--yes"]
    artifacts: checksum
```
`.github/workflows/release.yml`:
```yaml
name: release
on: { push: { tags: ["v*"] } }
permissions:
  contents: write
  id-token: write        # keyless cosign + attestations
  attestations: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }
      - uses: actions/setup-go@v7
        with: { go-version-file: go.mod }
      - uses: sigstore/cosign-installer@v4.1.2
      - uses: anchore/sbom-action/download-syft@v0.24.3
      - uses: goreleaser/goreleaser-action@v7.2.3
        with: { version: "~> v2", args: release --clean }
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
      - uses: actions/attest-build-provenance@v4.2.2
        with: { subject-checksums: dist/checksums.txt }
```
User-side verification (goes in the README):
```
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/<you>/cbom-netscan/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify cbom-netscan_0.1.0_linux_amd64.tar.gz -R <you>/cbom-netscan
```
GitHub artifact attestations give SLSA v1 Build L2 provenance. If you need L3, swap in `slsa-framework/slsa-github-generator` v2.1.0's Go builder (more YAML). Decision: L2 is enough for v0.x **(est.)**.

### 2.8 Licence
**Apache-2.0** for code. It's the same as cbomkit-theia and cbomkit (both Apache-2.0, V11), so code moves upstream without relicensing. It also carries a patent grant.
- Add the standard Apache header plus SPDX to each file. When a file moves into theia, its header becomes `Copyright … PQCA` per `addlicense -c "PQCA" -l apache`.
- Fixtures and testdata: **CC0-1.0**, declared via `REUSE.toml`.
- **Never** copy testssl.sh code or `etc/cipher-mapping.txt` (GPL-2.0). Generate the catalog from IANA instead. Running testssl.sh as a separate process is fine.
- IANA registry CSVs are public data; cite them in NOTICE.

---
## 3. Week 1: exact GitHub engagement (state re-checked 11 Oct 2026)

| # | Target | State 11 Oct 2026 | Action |
|---|---|---|---|
| 3.1 | [cbomkit-theia: new issue](https://github.com/cbomkit/cbomkit-theia/issues/new) | Discussions are disabled on the repo, so use an issue | Ask the scope question |
| 3.2 | [cbomkit-theia #235](https://github.com/cbomkit/cbomkit-theia/issues/235) "Certificates with unknown algorithms are dropped from the CBOM" | open, 0 comments (8 Oct) | Comment with a concrete partial-entry shape plus a data point |
| 3.3 | [testssl.sh #3116](https://github.com/testssl/testssl.sh/issues/3116) "[Feature request] Add PQC-safe (Shor/Grover) reporting" | open, 12 comments, last 10 Sep. A volunteer claimed it, no PR yet | Consumer-side input, plus an offer to test |
| 3.4 | [cbomkit](https://github.com/cbomkit/cbomkit) `opa/quantum_safe.rego` | bug V15; no existing issue mentions `keyagree` (GitHub search = 0) | Open the issue, then the PR |
| 3.5 | [cbomkit-theia #212](https://github.com/cbomkit/cbomkit-theia/issues/212) | open, claimed 29 Sep, plan agreed by the maintainer, no PR | **Don't comment.** Watch it and review the PR when it opens |
| 3.6 | [cbomkit-theia PR #149](https://github.com/cbomkit/cbomkit-theia/pull/149) | open, stale since 4 May | **Don't comment.** Its lesson (assessment ≠ scanning) is applied in 3.4 and Week 11 |

Before posting anything, run `gh issue view <n> -R <repo>` to re-check the state. If someone has already posted the same point, add 👍 instead of commenting.

### 3.1 Paste into a new cbomkit-theia issue
**Title:** `Scope question: plugins for offline network-appliance configs (FortiGate first)?`
```markdown
Hi, before I write any code I'd like to check whether this fits Theia's scope.

**Context.** India's CERT-In SBOM/QBOM/CBOM guideline v2.0 (Table 9) lists minimum CBOM elements, and a lot of the crypto in Indian utilities and enterprises sits in network appliances: IPsec VPNs, SSL/agentless VPN portals and admin TLS. Theia already scans container images and directories for OpenSSL configs, java.security, certificates and secrets. Appliance configuration backups are a similar kind of "crypto configuration at rest" that nothing scans today.

**Proposal.** An `Append`-type plugin, `fortios`, that walks the `filesystem.Filesystem` for FortiOS configuration backups (`#config-version=` header) and adds:

- `protocol` components (`ipsec`/`ike` with `ikev2TransformTypes`, `tls` for agentless VPN and admin HTTPS) from `config vpn ipsec phase1-interface` (`proposal`, `dhgrp`, `addke1`..`addke7`: IDs 35/36/37 = ML-KEM per the IANA IKEv2 registry), `config vpn ssl settings` and `config system global`
- `certificate` components from `config vpn certificate local` PEM blocks, reusing the existing certificate handling
- key-exchange groups that 1.6 can't express in a cipher suite get the same `theia:<plugin>:*` property approach agreed in #212, and move to `tlsGroups` with 1.7

It would never read or emit secrets: `psksecret`, `password`, `private-key` and `ENC` values get dropped by the tokenizer. Test fixtures would be fully synthetic (RFC 5737/3849 addresses, RFC 2606 names, self-signed certs), never real configs.

**Questions**
1. Is vendor-specific appliance config in scope for Theia, or would you rather it lived in a separate tool whose CBOM users import into CBOMkit?
2. If it's in scope: one plugin per vendor (`fortios`, later maybe `checkpoint`), or a single `appliance` plugin with sub-parsers?
3. Any objection to a few hundred lines of synthetic `.conf` fixtures in `testdata/`?

I'm prototyping this as a standalone Go module (`cyclonedx-go` v0.12.0, emitting 1.6), so that either answer works. Happy to bring it to a TSC call.
```

### 3.2 Paste into theia #235
```markdown
A data point and a suggested shape, since I hit the same thing while prototyping a separate collector.

With Go 1.26, `x509.ParseCertificate` on an OpenSSL 3.5 `mldsa65` self-signed cert returns **no error**, but `SignatureAlgorithm` and `PublicKeyAlgorithm` are both `0` (Unknown). So "unknown algorithm" won't always show up as a parse error. Checking the enums is needed as well as `err`.

The OIDs are still there: `cert.RawTBSCertificate` contains the signature AlgorithmIdentifier, and `cert.RawSubjectPublicKeyInfo` contains the SPKI one. Both can be unmarshalled with `encoding/asn1` into `pkix.AlgorithmIdentifier`. Your proposed shape works in 1.6 without extensions:

- certificate component: `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `certificateFormat: "X.509"`, plus `evidence.occurrences[].location`
- `signatureAlgorithmRef` / `subjectPublicKeyRef` pointing to components with `assetType: "algorithm"`, `oid` set from the certificate, `algorithmProperties.primitive: "unknown"`, and `name` = the dotted OID (or a name if the OID is in a small known table)
- `relatedCryptoMaterialProperties.size` left out when it can't be derived
- a property such as `theia:certificates:unmapped-algorithm=true` so consumers can count these, and a non-zero entry in the scan log, so these certs don't silently disappear

For SLH-DSA, the OIDs are 2.16.840.1.101.3.4.3.20 onward (e.g. SLH-DSA-SHA2-128s = …3.20, per NIST CSOR / OpenSSL's object table), which would be a quick fixture for a test. I can open a PR with a test cert and the OID-fallback helper if that would help.
```

### 3.3 Paste into testssl.sh #3116
```markdown
A view from the consumer side. I'm writing a tool that turns testssl.sh JSON into CycloneDX CBOMs (it runs testssl.sh as a separate process and doesn't copy any code), so here's what would make the new output easy to parse, following @dcooper16's point about keeping key exchange and authentication separate:

1. **Offered vs. negotiated as separate IDs.** e.g. `PQC_KEX_offered` (list of group names, like the existing `FS_KEMs`) and `PQC_KEX_negotiated` (the group the default handshake actually used). Downstream tools need both: "server supports X25519MLKEM768" and "a default client actually gets it" are different statements.
2. **Put the verdict in its own ID** with a fixed vocabulary in `finding` (e.g. `hybrid`, `pqc-only`, `classical-only`, `unknown`), not mixed into the free text. That way parsers don't depend on wording changes.
3. **Stable IANA names** (`X25519MLKEM768`, `SecP256r1MLKEM768`, `MLKEM1024`) to match `FS_KEMs`, so they can be matched against the IANA TLS Supported Groups registry.
4. Keep certificate-side PQC (ML-DSA signatures) under the existing `cert_*` IDs rather than in the new KEX IDs.

If it helps, I can run the branch against a matrix of local OpenSSL 3.5 `s_server` setups (`-groups X25519MLKEM768:X25519`, `MLKEM1024` only, classical only, and ML-DSA-65 cert) and post the JSON diffs here. I'm not trying to take over the implementation from @AAH20.
```

### 3.4 cbomkit: issue, then PR
**Issue title:** `opa/quantum_safe.rego: "keyagree" never matches CycloneDX primitive "key-agree", so ECDH/X25519 are classified NA`
```markdown
`opa/quantum_safe.rego` (line 14) lists asymmetric primitives as

    ["signature", "keyagree", "kem", "pke", "unknown", "other"]

but the CycloneDX 1.6 and 1.7 schema enum value is `key-agree` (`cryptoProperties.algorithmProperties.primitive`), and the built-in Java service uses `Primitive.KEY_AGREE`. So under the OPA compliance path, key-agreement algorithms such as ECDH/X25519 are never treated as asymmetric.

**Repro** (OPA 1.21.1), input with one component:
`{"bom-ref":"alg-ecdh","type":"cryptographic-asset","name":"ECDH","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"key-agree","curve":"secp256r1"}}}`

`opa eval -d opa/ -i input.json 'data.policies.quantum_safe.findings'`
- current: `"rule": "symmetric_na", "result": "NA"`
- with `"key-agree"`: `"rule": "asymmetric_quantum_safe", "result": "quantum-vulnerable"`

Proposed fix: replace `"keyagree"` with `"key-agree"` and add `opa/quantum_safe_test.rego` (two tests; they fail on main and pass with the fix). PR to follow, signed off for DCO.
```
**PR:**
- Branch `fix/opa-key-agree`.
- Commit: `fix(opa): match CycloneDX primitive "key-agree" in quantum_safe policy` (`git commit -s`).
- Body: "Fixes #<issue>. One-token change plus `opa test opa/ -v` tests. Verified with OPA 1.21.1."
- Test file: `/workspace/cbom-netscan-proto/upstream/cbomkit-opa/quantum_safe_test.rego`.
- Before opening, check how cbomkit's CI handles `opa` files, and run `opa fmt`.

---
## 4. Safe, legal method for sanitised FortiGate fixtures

### 4.1 Principles (non-negotiable)
1. **Every fixture is synthetic.** It's either written by hand from the public CLI Reference, or exported from **your own** FortiGate-VM eval on **your own** machine, which you configured from scratch with made-up values.
2. **Never** a production, employer, customer or ex-employer config, not even "just the VPN section", and not even sanitised. Scrubbers don't catch everything, and structure, naming and topology are themselves confidential.
3. **Never decrypt** anything: no ENC passwords, no encrypted backups (EULA §2(a)). The parser rejects encrypted backups and drops `ENC` values without decoding them.
4. The scrubber is a **second line of defence**. The first is that no real values were ever entered.

### 4.2 Lab setup (FortiGate-VM permanent eval)
- Get the VM image and eval licence through your **personal** FortiCloud account (one eval per account, V17). Run it on a personal laptop or home lab, host-only network, no WAN.
  - Eval limits: 1 vCPU / 2 GB, 3 interfaces / policies / routes, low-encryption only.
- Build a config from scratch with these values:

| Value type | Use only | Source |
|---|---|---|
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) |
| IPv6 | `2001:db8::/32` | [RFC 3849](https://www.rfc-editor.org/rfc/rfc3849) |
| Names / FQDNs / e-mail | `example.com`, `example.net`, `example.org`, `*.test`, `*.example`, `*.invalid` | [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) |
| Hostname, tunnel and object names | `fgt-lab-01`, `to-dc-classic`, `to-dr-pqc`, `legacy-ikev1` | your choice |
| PSKs / passwords | a throwaway string like `lab-only-not-secret`. It gets SCRUBBED anyway | n/a |
| Certificates | self-signed, generated fresh (4.3) | n/a |

- Configure the blocks from V6–V9. Then, for each block, export the backup and capture both `show` and `show full-configuration`, to answer ⚠U1–U3.
- If the eval rejects strong algorithms (⚠U2), record the exact CLI error in your private notes. For those blocks, use hand-authored fixtures labelled `# syntax: FortiOS 7.6.3 CLI Reference, not VM-validated`.
- **Don't publish** factory certificates (`Fortinet_Factory`, `Fortinet_CA_SSL`, …), the VM serial, license files, or GUI screenshots of non-public features (EULA §2(h)).

### 4.3 Test certificates
`scripts/gen-test-certs.sh`, tested with OpenSSL 3.5.7 on the box:
```bash
#!/usr/bin/env bash
set -euo pipefail
out=testdata/certs; mkdir -p "$out"
s() { printf '/CN=%s.example.net/O=Example Org' "$1"; }
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null \
  -out "$out/vpn-ecdsa-p256.crt" -days 825  -subj "$(s vpn)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null \
  -out "$out/admin-rsa2048.crt"  -days 47   -subj "$(s admin)"
openssl req -x509 -newkey rsa:1024 -nodes -keyout /dev/null \
  -out "$out/legacy-rsa1024.crt" -days 3650 -subj "$(s legacy)"
openssl req -x509 -newkey mldsa65 -nodes -keyout /dev/null \
  -out "$out/pqc-mldsa65.crt"    -days 200  -subj "$(s pqc)"
```
- Private keys go to `/dev/null`, so fixtures only ever contain public certificates.
- The ML-DSA line needs OpenSSL 3.5 or later.
- Commit the generated `.crt` files under CC0 so tests are deterministic. They're self-signed test certificates, not secrets.

### 4.4 Scrubbing script (`scripts/scrub_fortios.py`, prototype on the box)
Usage:
```
scrub_fortios.py IN.conf OUT.conf [--map map.json] [--keep-names]
scrub_fortios.py --verify-only testdata/fortios/*.conf   # CI; exit 2 on residue
```
Processing order (fail-closed: if verification fails, OUT is **not written**):
1. Multi-line quoted values. `private-key` gets dropped. `certificate` / `ca` / `crl` / `csr` / `remote` PEMs become `@@CERT:<edit-name>@@` placeholders, filled from `testdata/certs/` by a fixture build step.
2. Secret keys are replaced with `SCRUBBED`. Matched by regex: `psksecret`, `psksecret-remote`, `ppk-secret`, `password`, `passwd`, `private-key`, `*-password`, `*-secret`, `*-psk`, `key`, `secret`, `authpasswd`, `acme-eab-key-hmac`, `scep-password`, `sso-password`, `login-password`. Any `ENC <blob>` token anywhere is also replaced with `SCRUBBED`.
3. IPv4 maps deterministically into the RFC 5737 ranges; `0.0.0.0` and `255.255.255.255` are kept. IPv6 (including `::`-compressed forms) maps into `2001:db8::/32`.
4. FQDNs become `hostN.example.net` and e-mails become `admin@example.com`. Free-text fields (`hostname`, `alias`, `comments`, `description`, banners, `contact-info`, `location`) become generic values.
5. Serial-like tokens (`FGVM…`, `FG…`) become `FGVM00SERIAL0000`. The `#config-version` stamp is normalised and other `#` lines are dropped.
6. `edit` object names are renamed consistently, except `port*`, `root`, `Fortinet_*` and other built-ins. Pass `--keep-names` only for hand-authored files.
7. The verifier re-scans the output and fails on any of: `ENC `, a PEM `PRIVATE KEY` header, a non-documentation IP, a non-RFC 2606 FQDN, a secret-key value other than `SCRUBBED`, or a serial pattern.

Workflow:
- `scrub` → **manual line-by-line review** → `--verify-only` → commit.
- CI runs `--verify-only` on every PR. A `pre-commit` hook runs it as well.
- The tokens `ENC` and `PRIVATE KEY` must never appear literally in fixtures, not even as fake data. Tests construct them at runtime.

### 4.5 Legal notes (not legal advice; check with a lawyer for anything beyond fixtures)
- **Fortinet EULA §2(a) (reverse engineering, decrypting, derivative works, distribution).**
  - Parsing a text config that you created is reading your own data, and the tool doesn't touch Fortinet binaries.
  - Never ship FortiOS images, license files or anything extracted from the VM disk.
  - Never implement ENC-password decryption.
- **§2(e) (no disclosure of benchmarking/performance measurements).** Publish **no** throughput or latency numbers from the VM. testssl.sh results against the VM are a grey area **(est.)**; avoid publishing them. Use OpenSSL `s_server` for all published TLS fixtures.
- **§2(h) (non-public features/content) and §3 (confidentiality).**
  - Fixtures should only use options documented in public docs.fortinet.com CLI References and admin guides. Keep the doc URL and page in a comment at the top of each fixture.
  - Don't publish full raw `show full-configuration` dumps; commit only reduced, hand-reviewed blocks.
- **§2(i) (accessing the Software "to build a competitive product … or to copy any ideas").** cbom-netscan isn't a firewall, and interoperating with public configuration syntax is a different thing. But to be safe, write fixtures from the public CLI Reference, and use the VM **only to validate syntax** and observe what defaults get emitted **(est.)**.
- **§1 (internal business purposes only)** applies to the eval licence. A personal lab used to check syntax is the lowest-risk reading **(est.)**.
- **Employer IP.**
  - Develop on personal hardware, on your own time, with a personal GitHub/FortiCloud account. No employer laptop, VPN, network or credentials.
  - Check your employment contract's IP-assignment and moonlighting clauses before the first public commit, and get written confirmation if the contract is ambiguous.
  - Don't base fixtures on anything you've seen at work.
- **Fixture licence:** CC0-1.0 via `REUSE.toml` (`path = "testdata/**"`). Keep them free of any third-party copyrighted material.

---
## 5. Mapping: CERT-In Table 9 → CycloneDX 1.6 → FortiGate → testssl.sh

How to read the table:
- Paths are relative to a `components[]` entry with `"type": "cryptographic-asset"`. `cp.` = `cryptoProperties.`
- Element names are verbatim from CERT-In v2.0 Table 9 (V5).
- FortiOS keys are from the 7.6.3 CLI Reference unless noted.
- testssl.sh IDs were seen in a real 3.3dev run (V10).
- "**n/d-offline**" = not derivable from that source. The assessor reports it as `not-derivable-offline`, not as `missing`.

### 5.1 Algorithms (one component per distinct algorithm)
| CERT-In element | CycloneDX 1.6 JSON path | FortiGate source | testssl.sh source | Notes |
|---|---|---|---|---|
| Name | `name` | Decomposed tokens: `proposal` (`aes256gcm-prfsha384` → `AES-256-GCM` + `HMAC-SHA384` PRF), `dhgrp` IDs (14 → `MODP-2048`, 19 → `ECDH-P256`, 31 → `X25519`), `addke1..7` IDs (36 → `ML-KEM-768`, 1083 → `FrodoKEM-L1`), `vpn ssl settings` `tls-groups` (7.6.6+), `ciphersuite` tokens | `cipher-<proto>_x<hex>` finding (last field = IANA suite name, decomposed); `FS_KEMs`, `FS_ECDHE_curves`, `DH_groups` tokens; `cert_signatureAlgorithm` | Names follow catalog conventions (tool choice). Keep the raw source token as property `cbom-netscan:source-token` |
| Asset Type | `cp.assetType` = `"algorithm"` | — | — | Required by the schema |
| Primitive | `cp.algorithmProperties.primitive` | Catalog: GCM/ChaCha20-Poly1305 → `ae`; CBC ciphers → `block-cipher`; `md5/sha*` integrity → `mac` (HMAC); PRF → `mac`; MODP/ECP/X25519 → `key-agree`; ML-KEM/FrodoKEM/BIKE/HQC/Kyber → `kem` | Same catalog on decomposed suite parts, groups and signature algorithm (`signature`) | Use `key-agree` with a hyphen. cbomkit's OPA policy had this wrong (V15) |
| Mode | `cp.algorithmProperties.mode` | From the proposal token: `aes128` → `cbc`, `aes128gcm` → `gcm`, `3des` → `cbc` | From the suite name (`_GCM_`, `_CBC_`, `_CCM`) | Omit for non-block primitives; don't emit `unknown` there |
| Crypto Functions | `cp.algorithmProperties.cryptoFunctions[]` | By role in IKE: ENCR → `encrypt`,`decrypt`; PRF → `keyderive`; INTEG → `tag`; KE (DH) → `keygen`,`keyderive`; KEM → `keygen`,`encapsulate`,`decapsulate`; cert signature → `sign`,`verify` | Same, by role in the TLS suite | **Convention (est.)**: role-to-function rules are the tool's, documented in MAPPING.md |
| Classical security level | `cp.algorithmProperties.classicalSecurityLevel` (integer bits) | Catalog: AES-128 → 128, AES-256 → 256, 3DES → 112, MODP-2048 → 112, P-256 → 128, RSA-2048 → 112 | Same; plus `cert_keySize` bits for the RSA/EC key | Values from [NIST SP 800-57 Pt 1 Rev 5 Table 2](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final). Also emit `nistQuantumSecurityLevel` (0 for classical, 3 for ML-KEM-768, …). It isn't in Table 9 but the PQC assessor needs it |
| OID | `cp.oid` | Catalog, e.g. AES-128-GCM `2.16.840.1.101.3.4.1.6`, AES-256-GCM `…1.46`, AES-256-CBC `…1.42`, ML-KEM-768 `2.16.840.1.101.3.4.4.2`, X25519 `1.3.101.110` | Catalog; for certificates, the OIDs from the raw cert (V16) | MODP DH groups and FrodoKEM/BIKE/HQC have no standard OID: omit the field and add property `cbom-netscan:oid=none-assigned` |
| List | no dedicated 1.6 field | — | — | ⚠U5. Table 9 layout puts "List" under Algorithms. It's interpreted as the CBOM's list of algorithm components, and the assessor treats it as satisfied when ≥1 algorithm component exists. Flag this in docs |

### 5.2 Keys (`related-crypto-material`)
| CERT-In element | CycloneDX 1.6 JSON path | FortiGate source | testssl.sh source | Notes |
|---|---|---|---|---|
| Name | `name` | `<cert-edit-name> public key`; `<phase1-name> PSK` when `authmethod psk` | `<CN> public key` | Never contains a value |
| Asset Type | `cp.assetType` = `"related-crypto-material"` and `cp.relatedCryptoMaterialProperties.type` (`public-key`, `private-key`, `shared-secret`) | public key from the cert PEM; `private-key` presence only (value redacted at parse); `psksecret` presence → `shared-secret` | public key from the `cert` PEM | **`value` is never emitted** |
| id | `cp.relatedCryptoMaterialProperties.id` | public key: SHA-256 of SubjectPublicKeyInfo (hex); PSK: config path `vpn ipsec phase1-interface/<name>/psksecret` | SHA-256 of SPKI from `cert` | Non-secret identifier only. Hashing a PSK would make it brute-forceable, so never hash secrets |
| state | `cp.relatedCryptoMaterialProperties.state` | `active` when referenced by an enabled object; otherwise no value | `active` (served live) | 1.6 enum: `pre-activation`, `active`, `suspended`, `deactivated`, `compromised`, `destroyed`. CERT-In's "revoked/expired" examples aren't in the enum → add property `cbom-netscan:key:expired=true` |
| size | `cp.relatedCryptoMaterialProperties.size` (bits) | from the PEM public key (RSA modulus bits, EC curve bits, ML-DSA parameter set); PSK → **omit** | `cert_keySize` (`"RSA 2048 bits (exponent is 65537)"` → 2048), cross-checked against the PEM | PSK length can't be found without reading the secret |
| Creation Date | `cp.relatedCryptoMaterialProperties.creationDate` | **n/d-offline** | **n/d-offline** | Don't use cert `notBefore` as the creation date. The key may be older |
| Activation Date | `cp.relatedCryptoMaterialProperties.activationDate` | cert `notBefore` (for keys bound in a cert) | `cert_notBefore` (UTC, `YYYY-MM-DD HH:MM` → RFC 3339 `…:00Z`) | **Convention (est.)**, documented. Also set `expirationDate` = `notAfter` |

### 5.3 Protocols
| CERT-In element | CycloneDX 1.6 JSON path | FortiGate source | testssl.sh source | Notes |
|---|---|---|---|---|
| Name | `name` | `IKEv2 <phase1-name>`, `IPsec <phase2-name>`, `TLS agentless-VPN`, `TLS admin-HTTPS`, `SSH admin` | `TLS <ip>:<port>` (per version) | — |
| Asset Type | `cp.assetType` = `"protocol"` and `cp.protocolProperties.type` | `ike` for phase1 (`ipsec` for phase2); `tls`; `ssh` | `tls` | 1.6 enum has both `ipsec` and `ike` |
| Version | `cp.protocolProperties.version` | phase1 `ike-version` (1\|2; default flagged ⚠U1); TLS: every version between `ssl-min-proto-ver` and `ssl-max-proto-ver` (`tls1-2` → `"1.2"`); admin `admin-https-ssl-versions` | IDs `SSLv2`, `SSLv3`, `TLS1`, `TLS1_1`, `TLS1_2`, `TLS1_3` where the finding starts with `offered` | One protocol component per version |
| Cipher Suites | `cp.protocolProperties.cipherSuites[]` → `name`, `algorithms[]` (bom-refs), `identifiers[]`; IKEv2: `cp.protocolProperties.ikev2TransformTypes.{encr,prf,integ,ke,auth}` (bom-ref arrays), `esn`; IKEv1 and 1.6 TLS groups: `cp.protocolProperties.cryptoRefArray` | TLS 1.3: `ciphersuite` (`TLS-AES-256-GCM-SHA384` …) and `admin-https-ssl-ciphersuites`; TLS ≤1.2 from `algorithm high\|medium\|low` → **n/d-offline** (exact list depends on build); IPsec: `proposal` + `dhgrp` + `addke1..7` → transform types; groups: `tls-groups` → `cryptoRefArray` + property `cbom-netscan:tls:groups` | `cipher-<proto>_x<hex>` → `name` = IANA name, `identifiers` = `["0xC0","0x2F"]`; `FS_KEMs` + `FS_ECDHE_curves` → algorithm components in `cryptoRefArray`, plus property `cbom-netscan:tls:groups` | Group tokens move to `cipherSuites[].tlsGroups` in 1.7 (V3). This follows the maintainer's plan for theia #212 (V12). `addke` rounds have no 1.6 slot: add them to `ke[]` with property `cbom-netscan:ike:addke<N>` |
| OID | `cp.oid` | — | — | ⚠U6: no protocol OIDs; `not-applicable` |

### 5.4 Certificates
| CERT-In element | CycloneDX 1.6 JSON path | FortiGate source | testssl.sh source | Notes |
|---|---|---|---|---|
| Name | `name` | `vpn certificate local` edit name | `cert_commonName` | — |
| Asset Type | `cp.assetType` = `"certificate"` | — | — | — |
| Subject Name | `cp.certificateProperties.subjectName` | parsed from the `certificate` PEM (RFC 4514 string) | parsed from `cert` PEM | `cert_commonName` alone is CN only; use the PEM |
| Issuer Name | `cp.certificateProperties.issuerName` | PEM | PEM (`cert_caIssuers` is `CN (O)` display text) | — |
| Not Valid Before | `cp.certificateProperties.notValidBefore` (date-time) | PEM | `cert_notBefore` → RFC 3339 UTC | testssl prints minutes, so PEM is more precise |
| Not Valid After | `cp.certificateProperties.notValidAfter` | PEM | `cert_notAfter` | Input to the CA/B SC081v3 checks |
| Signature Algorithm Reference | `cp.certificateProperties.signatureAlgorithmRef` (bom-ref) | PEM signature OID → algorithm component | `cert_signatureAlgorithm` (`"SHA256 with RSA"`) or PEM | Read the raw OID if Go reports Unknown (V16) |
| Subject Public Key Reference | `cp.certificateProperties.subjectPublicKeyRef` (bom-ref) | SPKI → `public-key` material (5.2) | `cert` PEM / `cert_keySize` | — |
| Certificate Format | `cp.certificateProperties.certificateFormat` = `"X.509"` | — | — | Schema example values: X.509, PEM, DER, CVC |
| Certificate Extension | `cp.certificateProperties.certificateExtension` = `"pem"` | inline PEM → `pem` | `cert` field is PEM → `pem` | The 1.6 schema titles this "Certificate File Extension" (file type, e.g. crt/pem). X.509v3 extensions (SAN, EKU) go in properties in 1.6, in 1.7 `certificateExtensions`. Flag in docs |

Extras recorded as properties in 1.6 and as native fields in 1.7: `cert_serialNumber` → `cbom-netscan:cert:serial`, `cert_fingerprintSHA256` → `cbom-netscan:cert:sha256`, FortiOS `source` (factory/user/bundle) and `enroll-protocol`.

Provenance for every row: `evidence.occurrences[]` with `location` (file or `host:port`), `line` (FortiOS), and `additionalContext` (the config path or testssl ID). Document-level: `metadata.lifecycles[].phase` = `operations`.

Table 8 also lists **Attestations** (a digital signature over the CBOM). In 1.6 this would be the top-level JSF `signature`. It's out of scope for v0.x; instead, sign the output file with `cosign sign-blob` and document it **(est.)**.

---
## 6. Metrics at day 30, 60 and 90 (all targets are estimates)

Measured on the Sunday that ends W4 (8 Nov), W9 (13 Dec) and W13 (10 Jan). Record them in `docs/reports/`.

| Metric | Day 30 | Day 60 | Day 90 | How measured |
|---|---|---|---|---|
| Tagged releases | ≥1 (`v0.1.0-alpha.1`) | ≥3 incl. signed `v0.2.0` | ≥5 incl. `v0.3.0` | `git tag` |
| Signed + attested releases | 0 | ≥2 | ≥3 | `cosign verify-blob` and `gh attestation verify` pass |
| Golden fixtures that validate against 1.6 | ≥8 (testssl) | ≥20 | ≥30 | CI count; **0 schema errors** at all times |
| FortiOS config blocks covered | 1 (tree only) | 5 (phase1, cert local, ssl settings, system global, phase2) | 6 (+ ssh-config) | MAPPING.md coverage |
| FortiOS versions with default tables | 0 | 1 (7.6) | 3 (7.4, 7.6, 8.0) | `defaults_*.go` |
| CERT-In Table 9 elements filled from combined FortiGate+testssl (synthetic lab) | n/a | ≥20 of 30 | ≥22 of 30 | `assess --profile certin-t9` |
| Fuzz time without new crash, per parser | ≥10 min | ≥2 h cumulative | ≥10 h cumulative (nightly) | fuzz workflow logs |
| Test coverage `pkg/` | ≥60 % | ≥75 % | ≥80 % | `go test -cover` |
| Upstream PRs opened / merged | ≥1 / 0 | ≥2 / ≥1 | ≥3 / ≥2 | GitHub |
| Upstream issue comments with substance | ≥3 | ≥5 | ≥8 | GitHub |
| Maintainer answer on theia scope | received | decision taken (plugin PR or standalone) | executed | §3.1 issue |
| Practitioner conversations | ≥5 | ≥10 | ≥15 | private log (no configs) |
| External users who ran it (issue, PR or message) | ≥1 | ≥3 | ≥8 from ≥5 distinct people | GitHub / messages |
| Orgs giving structured feedback | 0 | ≥1 | ≥2 | feedback issues |
| External code contributions merged | 0 | ≥1 | ≥2 | GitHub |
| GitHub stars | ≥15 | ≥50 | ≥120 | vanity; weak signal |
| Public posts published | 4 | 9 | 13 | §1 |
| Talk / CFP | — | ≥1 submitted | ≥1 accepted or delivered | — |
| OpenSSF Scorecard | — | — | ≥7.0 | scorecard action |
| Funding | — | — | FOSS United draft ready | doc |
| Fixture leaks (real data found) | **0** | **0** | **0** | any one triggers §7 S9 |
| Hours/week (rolling 4-week mean) | ≥9 | ≥9 | ≥9 | time log |

---

## 7. Stop / pivot signals and responses

| # | Signal (trigger) | Response |
|---|---|---|
| S1 | **theia says out-of-scope**, or there's no maintainer reply 21 days after the §3.1 issue | Go standalone, as already planned. Keep `adapters/theia` as an optional module. Document the CBOMkit viewer import and `cbomkit-theia -b` enrich flows. Keep sending small fixes upstream (V15, #235). Re-ask at a TSC call once |
| S2 | **theia welcomes it but asks for 1.7 output** (their #212 step 2 lands first) | Pull the `emit/cdx17` work into W8–W10. `tlsGroups` and structured IKEv2 come from the same model. Keep 1.6 as an option, because CERT-In references 1.6 |
| S3 | **Someone else ships FortiGate/appliance CBOM** (IBM, a theia plugin PR, a vendor tool) | Within 1 week: compare coverage. If theirs is better, contribute fixtures and testssl merge logic to theirs, and pivot to Check Point/F5 parsers, where you also have hands-on experience. Don't duplicate |
| S4 | **Eval VM can't produce strong-crypto configs** (⚠U2), or the eval programme changes | Hand-author fixtures from the CLI Reference (labelled). Ask on the theia/cbomkit issue whether anyone with a lab FortiGate will run `--verify-only`-checked **reduced** blocks. Don't buy or borrow a production unit |
| S5 | **EULA or legal concern raised** (Fortinet contact, a lawyer, a maintainer worry) | Pause fixture publication immediately and remove contested fixtures. Keep only CLI-Reference-derived hand-authored ones. Get advice (e.g. SFLC.in for Indian OSS legal help **(est.)**). Never argue it in public threads |
| S6 | **Employer objection or contract conflict** | Stop public commits until resolved in writing. If it can't be resolved, archive the repo and hand it over to a co-maintainer or PQCA. Don't work around the employer |
| S7 | **Demand signal weak**: <2 of 15 practitioners say they'd run it by day 60, and <3 external users by day 90 | Pivot from "tool" to "content". Publish MAPPING.md and the CERT-In Rego policy as the main artefacts, contribute the testssl→CBOM converter to cbomkit, and stop the FortiOS parser at v0.3 |
| S8 | **Time falls under 6 h/week for 3 weeks running** | Cut scope to testssl collector, phase1 + cert extraction and the CERT-In assessor. Drop W10 and W12 polish. Move metric targets 4 weeks later |
| S9 | **Real configuration data appears** (someone pastes a real config into an issue, or a fixture leak is found) | Within the hour: hide or delete the comment (GitHub "hide" plus ask the reporter), `git filter-repo` if it's in history and force-push only after telling collaborators, rotate nothing yourself (it isn't your data), tell the reporter which secrets to rotate. Add the pattern to the verifier. Post-mortem in `SECURITY.md` without the data |
| S10 | **testssl.sh changes JSON IDs** (#3116 lands new IDs, or 3.3 renames anything) | The collector is keyed by ID patterns with version sniffing (`version` field). Add a fixture for the new release within 1 week. Keep both old and new IDs |
| S11 | **CycloneDX/CERT-In guidance changes** (CERT-In v3.0, or it mandates 1.7) | Update MAPPING.md and the assessor rule data (`policies/*.yaml`). The model is already 1.7-ready |
| S12 | **Upstream PRs stale for >30 days** (V15 fix, theia plugin) | Ping once politely with a rebased branch. Raise at a TSC call (⚠U8). After 60 days, carry the fix in your own docs/adapters and stop waiting |
| S13 | **A false-negative bug in a PQC/HNDL verdict** (e.g. hybrid mis-classified as classical) | Treat as a security bug: fix, add a regression fixture, release a patch within 7 days, and add a CHANGELOG "Security" note |

---

## Appendix A: primary sources (accessed 11 Oct 2026)

CycloneDX:
- 1.6.2 schema: https://github.com/CycloneDX/specification/blob/1.6.2/schema/bom-1.6.schema.json
- Releases: https://github.com/CycloneDX/specification/releases
- 1.7 schema: https://github.com/CycloneDX/specification/blob/1.7/schema/bom-1.7.schema.json
- cyclonedx-go v0.12.0: https://github.com/CycloneDX/cyclonedx-go/tree/v0.12.0
- cyclonedx-cli: https://github.com/CycloneDX/cyclonedx-cli/releases

CERT-In:
- SBOM/QBOM/CBOM/AIBOM/HBOM guideline v2.0 (Table 9 on pp. 45–48): https://cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf

Fortinet:
- FortiOS 7.6.3 CLI Reference: https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/e628f3e3-1a47-11f0-b13a-ca4255feedd9/FortiOS-7.6.3-CLI_Reference.pdf
- FortiOS 8.0.1 PQC for IPsec: https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/229631/post-quantum-cryptography-for-ipsec-key-exchange
- FortiOS 7.6.6 PQC for Agentless VPN: https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/43632
- FortiOS 7.6.6 Phase 1 configuration: https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/790613
- FortiGate-VM permanent trial mode: https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/441460/permanent-trial-mode-for-fortigate-vm
- Fortinet EULA: https://www.fortinet.com/content/dam/fortinet/assets/legal/EULA.pdf

testssl.sh:
- Repo: https://github.com/testssl/testssl.sh (3.3dev @7ad4a6e; release v3.2.4)
- #3116: https://github.com/testssl/testssl.sh/issues/3116

CBOMkit:
- cbomkit-theia: https://github.com/cbomkit/cbomkit-theia (@445206c; `CONTRIBUTING.md`, `AGENTS.md`, `scanner/plugins/plugin.go`)
- Issues: https://github.com/cbomkit/cbomkit-theia/issues/212, https://github.com/cbomkit/cbomkit-theia/pull/149, https://github.com/cbomkit/cbomkit-theia/issues/235
- cbomkit OPA policy: https://github.com/cbomkit/cbomkit/blob/main/opa/quantum_safe.rego
- PQCA calendar: https://pqca.org/calendar

IANA registries:
- IKEv2 Transform Type 4: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters-8.csv
- TLS Supported Groups: https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
- TLS Cipher Suites: https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv

RFCs and standards:
- RFC 5737: https://www.rfc-editor.org/rfc/rfc5737
- RFC 3849: https://www.rfc-editor.org/rfc/rfc3849
- RFC 2606: https://www.rfc-editor.org/rfc/rfc2606
- NIST SP 800-57 Pt 1 Rev 5: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- CA/B Forum SC081v3: https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/

Release tooling:
- goreleaser: https://goreleaser.com/customization/sign/ and https://goreleaser.com/customization/archive/
- cosign: https://github.com/sigstore/cosign/releases
- attest-build-provenance: https://github.com/actions/attest-build-provenance
- slsa-github-generator: https://github.com/slsa-framework/slsa-github-generator
- Community and funding sources: see `/workspace/oss-mission-report.md`

## Appendix B: artefacts on the box
- `/workspace/cbom-netscan-proto/`: the spike (§0.3). `go test ./...` passes and the golden CBOM validates against 1.6.
- `/workspace/cbom-netscan-proto/scripts/scrub_fortios.py`: scrubber/verifier (§4.4).
- `/workspace/cbom-netscan-proto/testdata/fortios/synthetic-fgvm-7.6.conf`: hand-authored synthetic fixture (CC0), passes `--verify-only`.
- `/workspace/cbom-netscan-proto/upstream/cbomkit-opa/quantum_safe_test.rego`: the test for the §3.4 PR.
- `/workspace/research/lab/out.json`: the real testssl.sh pretty-JSON run used for V10. It contains the box hostname; use the scrubbed copy in `testdata/testssl/` instead.
