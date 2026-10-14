# cbom-netscan mapping: CERT-In Table 9 → CycloneDX 1.6 → FortiOS

This document says what cbom-netscan puts in a CBOM, where each value comes
from, and what it does not (yet) produce. It describes the code as of
2026-10-14 (FortiOS extractors: system global and SSH, IPsec, certificates,
SSL VPN). Where this document and the code disagree, the code is right and
this document has a bug.

Contents:

1. [How to read this](#1-how-to-read-this)
2. [CERT-In Table 9 → CycloneDX 1.6](#2-cert-in-table-9--cyclonedx-16)
3. [What each FortiOS section produces](#3-what-each-fortios-section-produces)
4. [Output properties](#4-output-properties)
5. [Warnings](#5-warnings)
6. [Design decisions](#6-design-decisions)
7. [Known limitations and accepted risks](#7-known-limitations-and-accepted-risks)
8. [Open decisions](#8-open-decisions)
9. [Sources](#9-sources)

---

## 1. How to read this

- Paths are relative to a `components[]` entry of type `cryptographic-asset`;
  `cp.` stands for `cryptoProperties.`. Field names are from the CycloneDX 1.6
  schema (`bom-1.6.schema.json`, identical in 1.6.1 and 1.6.2).
- Element names are verbatim from CERT-In's *Technical Guidelines on SBOM,
  QBOM & CBOM, AIBOM and HBOM*, version 2.0 dated 09.07.2025, Table 9
  "Minimum Elements pertaining to Cryptographic Asset" (printed pp. 45–48).
  Table 9 has **30** elements: 8 for algorithms, 7 for keys, 5 for protocols,
  10 for certificates. (docs/PLAN.md says 29 in several places; the PDF has
  30.)
- Coverage status, per element:
  - **covered**: filled for every component of that kind whenever the backup
    holds the information;
  - **partial**: filled for some components of that kind; the note says which
    and why not the others;
  - **not yet**: never filled. The note says whether it is planned, not
    derivable from a configuration backup, or has no defined value.
- "Fixtures" counts are measured on the six FortiOS golden files in
  `pkg/testdata/golden/fortios-*.cdx.json` (synthetic backups): 136 algorithm,
  28 key, 34 protocol, and 15 certificate components. They show what the code
  fills on realistic input, not a guarantee for every backup.

Every component also has `evidence.occurrences[]` (file name, line, config
path as `symbol`, and the scope, such as `vdom root`, as
`additionalContext`) for each place the value was configured. Only the
backup's file name is recorded, never its path. A value that comes from a
default has no occurrence, since no line sets it.

## 2. CERT-In Table 9 → CycloneDX 1.6

Summary: of the 30 elements, **19 covered, 5 partial, 6 not yet** (4 of those
planned, 1 not derivable from a backup, 1 with no defined value).

### 2.1 Algorithms

| Element | CycloneDX 1.6 field | Status | Source in cbom-netscan | Notes |
|---|---|---|---|---|
| Name | `name` | covered | Algorithm names chosen by cbom-netscan: `AES-256-GCM`, `HMAC-SHA256`, `MODP-2048`, `ECP-384`, `X25519`, `FFDHE-4096`, `ML-KEM-768`, `RSA-2048`, `ECDSA-P256`, `Ed25519`, `SHA256-RSA` | Named by algorithm, not by protocol token (§6.2). The configured tokens are kept on the protocol as `<field>:value`. Fixtures: 136/136 |
| Asset Type | `cp.assetType` = `algorithm` | covered | — | Fixtures: 136/136 |
| Primitive | `cp.algorithmProperties.primitive` | covered | Token tables in `extract/*/tokens.go`; certificate keys from the parsed key type | `key-agree` (hyphen, as in the schema), `kem`, `combiner`, `ae`, `block-cipher`, `mac`, `kdf`, `signature`, `pke` (RSA certificate keys, which can encrypt as well as sign). Fixtures: 136/136 |
| Mode | `cp.algorithmProperties.mode` | covered | Token tables (`aes256-ctr` → `ctr`, `aes256gcm` → `gcm`, `3des` → `cbc`) | Set on every block-cipher and AE algorithm that has a mode; omitted where none applies (ChaCha20-Poly1305, MACs, key agreement). Fixtures: 13/136, which is every component a mode applies to |
| Crypto Functions | `cp.algorithmProperties.cryptoFunctions[]` | not yet | — | Planned. Needs a documented convention for functions by role (ENCR → encrypt/decrypt, KE → keygen, …); the emitter already supports the field. Fixtures: 0/136 |
| Classical security level | `cp.algorithmProperties.classicalSecurityLevel` | not yet | — | Planned, from NIST SP 800-57 Part 1 Rev. 5 Table 2. The emitter already supports the field. Fixtures: 0/136 |
| OID | `cp.oid` | partial | Certificate algorithms only: read from the certificate's ASN.1, so algorithms Go does not know still get an OID | IPsec, SSH, and TLS-group algorithms have no OID yet (planned: generated catalog; MODP groups and the non-NIST PQC KEMs have none to give). Fixtures: 16/136 |
| List | no 1.6 field; the CBOM's set of algorithm components | covered (interpretation) | — | The PDF's layout puts "List" under Algorithms, but its description speaks of the algorithms "employed by the quantum device or system". Read here as the list of algorithm components, which every CBOM with crypto has. See §8.2 |

Not a Table 9 element but always set where it applies:
`cp.algorithmProperties.nistQuantumSecurityLevel` (§6.6). Fixtures: 93/136.

### 2.2 Keys

CERT-In says the asset type for keys "is typically 'key'". CycloneDX 1.6 has
no `key` asset type; keys are `related-crypto-material` with a
`relatedCryptoMaterialProperties.type`.

| Element | CycloneDX 1.6 field | Status | Source in cbom-netscan | Notes |
|---|---|---|---|---|
| Name | `name` | covered | `<certificate component name> public key` / `private key`; `<tunnel name> pre-shared key` | Never contains a value. Fixtures: 28/28 |
| Asset Type | `cp.assetType` = `related-crypto-material`, `cp.relatedCryptoMaterialProperties.type` | covered | `public-key` (from the certificate), `private-key` (presence only), `secret-key` (IPsec PSK, presence only) | Fixtures: 28/28 (14 public, 10 private, 4 secret) |
| id | `cp.relatedCryptoMaterialProperties.id` | partial | Public keys: `spki-sha256:<hex>`, the SHA-256 of the SubjectPublicKeyInfo | Private and secret keys get no id on purpose: any id derived from a secret could leak it, and a hashed PSK could be brute-forced. Fixtures: 14/28 |
| state | `cp.relatedCryptoMaterialProperties.state` | not yet | — | Planned, see §8.3. CERT-In's examples (active, revoked, expired) do not all exist in the 1.6 enum. Fixtures: 0/28 |
| size | `cp.relatedCryptoMaterialProperties.size` | partial | From the parsed certificate's public key (RSA modulus bits, EC curve bits, 256 for Ed25519), also set on that certificate's private key | Never for a PSK (its length could only come from reading it), nor for a private key whose certificate does not parse. Fixtures: 24/28 |
| Creation Date | `cp.relatedCryptoMaterialProperties.creationDate` | not yet (not derivable) | — | A backup does not say when a key was created, and a certificate's notBefore is not the key's creation date (keys are often reused). Fixtures: 0/28 |
| Activation Date | `cp.relatedCryptoMaterialProperties.activationDate` | not yet | — | Planned as a documented convention (notBefore of the certificate that binds the key), see §8.4. Fixtures: 0/28 |

### 2.3 Protocols

| Element | CycloneDX 1.6 field | Status | Source in cbom-netscan | Notes |
|---|---|---|---|---|
| Name | `name` | covered | `FortiOS admin HTTPS TLS 1.3`, `FortiOS admin SSH`, `FortiOS IPsec phase1-interface <name>`, `FortiOS IPsec phase2-interface <name>`, `FortiOS SSL VPN TLS 1.3`, `FortiOS SSL VPN DTLS 1.2`, each with ` (vdom <name>)` or ` (global)` in multi-VDOM backups | Fixtures: 34/34 |
| Asset Type | `cp.assetType` = `protocol`, `cp.protocolProperties.type` | covered | `tls`, `ssh`, `ike` (phase1), `ipsec` (phase2) | Fixtures: 34/34 |
| Version | `cp.protocolProperties.version` | partial | TLS: one component per enabled version (`1.2`, `1.3`); IKE: `ike-version` (`1`, `2`) | SSH has no version setting in FortiOS and ESP (phase2) has no version, so those have none; an SSL VPN whose versions cannot be resolved gets one component without a version. Fixtures: 26/34 |
| Cipher Suites | `cp.protocolProperties.cipherSuites[]`; IKEv2: `ikev2TransformTypes.{encr,prf,integ,ke,auth}`; IKEv1, SSH, TLS groups: `cryptoRefArray` | partial | TLS 1.3: `ciphersuite` / `admin-https-ssl-ciphersuites`; IKE/IPsec: `proposal`, `dhgrp`, `addke1`…`addke7`; SSH: `ssh-enc-algo`, `ssh-mac-algo`, `ssh-kex-algo`, `ssh-hsk-algo`; TLS groups: `tls-groups` | TLS 1.2 and below: the suite list is set only by `algorithm high/medium/low` and depends on the firmware build, so it is recorded as `cipher-suites: unknown` (§7.2). Fixtures: 30/34 have algorithm references (the 4 without are admin HTTPS TLS 1.2) |
| OID | `cp.oid` | not yet (no defined value) | — | No registry of OIDs that identify TLS, IPsec, or SSH as protocols was found (⚠U6 in docs/PLAN.md). Fixtures: 0/34 |

### 2.4 Certificates

All ten are filled from the certificate PEM parsed with Go's `crypto/x509`,
whenever the PEM parses. Fixtures: 14/15 (the fifteenth is a deliberately
broken PEM, which gets `cbom-netscan:cert:parse=failed` and a warning).

| Element | CycloneDX 1.6 field | Status | Notes |
|---|---|---|---|
| Name | `name` | covered | `FortiOS certificate <local\|ca\|remote> <entry name>`, plus the scope in multi-VDOM backups. The entry name, not the subject, because the entry name is what IPsec and SSL VPN settings refer to; the subject is in Subject Name |
| Asset Type | `cp.assetType` = `certificate` | covered | |
| Subject Name | `cp.certificateProperties.subjectName` | covered | RFC 4514 string from Go, e.g. `CN=vpn.example.com,O=Example Lab` |
| Issuer Name | `cp.certificateProperties.issuerName` | covered | |
| Not Valid Before | `cp.certificateProperties.notValidBefore` | covered | UTC, RFC 3339 |
| Not Valid After | `cp.certificateProperties.notValidAfter` | covered | UTC, RFC 3339 |
| Signature Algorithm Reference | `cp.certificateProperties.signatureAlgorithmRef` | covered | bom-ref of the signature algorithm component, e.g. `ECDSA-SHA384` with OID `1.2.840.10045.4.3.3` |
| Subject Public Key Reference | `cp.certificateProperties.subjectPublicKeyRef` | covered | bom-ref of the public-key component, which references the key algorithm |
| Certificate Format | `cp.certificateProperties.certificateFormat` = `X.509` | covered | |
| Certificate Extension | `cp.certificateProperties.certificateExtension` = `pem` | covered | The 1.6 schema means the file extension; the certificate is stored as PEM in the backup. X.509v3 extensions (SAN, EKU) are not recorded |

Also recorded as properties, since 1.6 has no field for them:
`cbom-netscan:cert:serial` (hex) and `cbom-netscan:cert:sha256` (fingerprint).

## 3. What each FortiOS section produces

| Section (every scope) | Components | Research notes |
|---|---|---|
| `system global` | Admin HTTPS: one `tls` protocol per version in `admin-https-ssl-versions`; TLS 1.3 suites from `admin-https-ssl-ciphersuites`; `strong-crypto`, `admin-server-cert` (by name) recorded as properties | §3.1 |
| `system ssh-config` | Admin SSH: one `ssh` protocol referencing cipher, MAC, key-exchange, and host-key algorithms | §3.2 |
| `vpn ipsec phase1-interface`, `vpn ipsec phase1` | One `ike` protocol per tunnel; IKEv2 in `ikev2TransformTypes`, IKEv1 and unknown versions in `cryptoRefArray`; a PSK as a `secret-key` (presence only); a signature tunnel depends on its certificates | §3.3 |
| `vpn ipsec phase2-interface`, `vpn ipsec phase2` | One `ipsec` protocol per phase2, depending on its phase1 | §3.4 |
| `vpn certificate local/ca/remote`, `certificate local/ca/remote` | One `certificate` per entry, its public key, key algorithm, and signature algorithm; a `private-key` (presence only) for local certificates | §3.8 |
| `vpn ssl settings` | One `tls` protocol per enabled version (DTLS separately on 7.4.12), referencing TLS groups and the server certificate | §3.7 |

Sections that hold crypto but are not read yet are listed in the CBOM's
metadata property `cbom-netscan:fortios:sections-not-inventoried` and give a
`section-not-inventoried` warning (§7.4). Crypto-related settings sections
(for example `system admin`, `system ha`) are listed in
`cbom-netscan:fortios:settings-not-inventoried`, without a warning. Sections
that were read are listed in `cbom-netscan:fortios:sections-inventoried`.

## 4. Output properties

All property names start with `cbom-netscan:`. `fortios:` properties describe
the configuration; `cert:` properties describe a parsed certificate.

### 4.1 Provenance: configured, default, unknown

Every configuration field an extractor uses is resolved to one of three
sources and recorded on the component that uses it:

| Property | Meaning |
|---|---|
| `fortios:<field>:source` | `configured` (a `set` line in the backup), `default` (no `set` line, or `unset`; the value is the documented default for this firmware), or `unknown` (no `set` line and no documented default) |
| `fortios:<field>:line` | the line of the `set`, when configured (plus an evidence occurrence) |
| `fortios:<field>:value` | the tokens used, for configured and default values. Tokens are filtered: an unknown token that looks like an option is kept and warned about (`unknown-token`); anything else is dropped without being shown, so stray secret text never reaches the output |
| `fortios:defaults-table` | the defaults table used (`7.4`, `7.6`, `8.0`), when any value on the component is a default |
| `fortios:<field>:default-source` | the document the default comes from (CLI reference page, verification date) |
| `fortios:<field>:default-note` | a caveat on that default, when the sources disagree (for example the IKE DH group default) |
| `fortios:<field>:unknown-reason` | why a value is unknown: the field is not documented for this firmware (for example `tls-groups` before 7.6.5) |

The seven `addke1`…`addke7` rounds are an exception: rounds that are set are
recorded as `fortios:addke<N>:source`/`:line`/`:value`, and when none is set
one `fortios:addke:source` (`default` or `unknown`) stands for all seven.

Rules: a default is used only when a defaults table covers the backup's
firmware and documents the field (§7.3). Nothing is guessed: with no table,
fields not set in the backup are `unknown`, and the CLI warns once
(`no-default-table`). Backups omit settings left at their default, so many
values are legitimately `default`.

Other configuration properties:

| Property | On | Meaning |
|---|---|---|
| `fortios:view` = `configured` | every protocol | The component shows the configured settings, not what is negotiated. Global options such as `strong-crypto` can narrow the effective set at run time (research notes §8.12); the CBOM records what is configured and marks what may be restricted, rather than computing the effective set |
| `fortios:strong-crypto-may-restrict`, `fortios:strong-crypto-may-restrict:reason`, `fortios:strong-crypto-may-restrict:cipher-suites`; `fortios:ssh-enc-algo:strong-crypto-may-restrict`, `fortios:ssh-mac-algo:strong-crypto-may-restrict` | admin HTTPS and SSH protocols | The configured option that `strong-crypto enable` may disable. `strong-crypto` does not apply to SSL VPN (§8.13), so SSL VPN components have no marker |
| `fortios:scope` | protocols in multi-VDOM backups | `vdom <name>` or `global` |
| `fortios:cipher-suites` = `unknown` | TLS 1.2 and below, DTLS | The suite list is not derivable from the backup (§7.2) |
| `fortios:tls-version` = `unknown` | SSL VPN | The versions could not be resolved, so one component stands for the section |
| `fortios:tls-groups:tls13-only` | SSL VPN TLS 1.2 and below, and the unknown-version component | The configured ML-KEM and hybrid groups, which are not referenced by this component because they are defined for TLS 1.3 only (§6.3) |
| `fortios:transport` = `dtls` | SSL VPN DTLS (7.4.12) | Distinguishes DTLS from TLS, since 1.6 has no DTLS protocol type |
| `fortios:ike-transform-id` | DH group and KEM algorithms used by IPsec | The IKEv2 Transform Type 4 ID (the DH group number, or the KEM ID such as 36 for ML-KEM-768), because the component is named by algorithm |
| `fortios:ike-transform-id:private-use` = `true` | Kyber, FrodoKEM, BIKE, HQC | IDs 1080–1094 are in RFC 7296's private-use range (1024 and above): Fortinet's numbers, not IANA assignments |
| `fortios:addke:applies`, `fortios:addke:applies-reason` | IKE tunnels with `addke` that is not counted | `no` on IKEv1 (RFC 9370 is IKEv2-only), `unknown` when the IKE version is unknown |
| `fortios:hybrid` | SSH hybrid key-exchange algorithm (the combiner) | Names its parts, e.g. `ML-KEM-768 + X25519` |
| `fortios:phase1name` | IPsec phase2 | The phase1 it belongs to |
| `fortios:psksecret` = `present`/`absent`, `fortios:psksecret:unused`; `fortios:psksecret:form`, `fortios:psksecret:line` | IPsec phase1; its pre-shared key component | Whether a PSK is set, and its form (`ENC`, `masked`, `plaintext`) and line, never its value; `psksecret:unused` names the authmethod when the tunnel does not use the PSK |
| `fortios:certificate-kind` | certificates | `local`, `ca`, or `remote` |
| `fortios:source:value`, `fortios:range:value` (with `:line`) | certificates | The entry's `source` (`factory`, `user`, `bundle`) and `range` (`global`, `vdom`), when set to a known value |
| `fortios:referenced-from` | global certificates | The VDOMs whose tables list this certificate by name (§6.4), e.g. `vdom branch, vdom root` |

### 4.2 Private keys

A certificate's private key, and an IPsec PSK, become a component that
records presence only. The value is never parsed, decoded, stored, or
printed; `model.Material` has no value field at all.

| Property | Meaning |
|---|---|
| `fortios:private-key` = `present` | The local certificate has a private-key value |
| `fortios:private-key:form` | How the key is stored in the backup, decided from the first token or the PEM BEGIN line (and, for traditional keys, the Proc-Type header) only: |

| Form | Value looks like | Warning |
|---|---|---|
| `ENC` | `ENC <blob>`: encrypted by FortiOS | none |
| `masked` | `FortinetPasswordMask` | none |
| `encrypted-pem` | `-----BEGIN ENCRYPTED PRIVATE KEY-----` (PKCS #8, encrypted), or `-----BEGIN RSA/EC/DSA PRIVATE KEY-----` directly followed by `Proc-Type: 4,ENCRYPTED` (RFC 1421) | none |
| `plaintext-pem` | `-----BEGIN PRIVATE KEY-----` (PKCS #8, unencrypted), or a traditional RSA/EC/DSA key without that header | `plaintext-private-key`: the key is unencrypted in the backup |
| `pem-encryption-unknown` | `-----BEGIN OPENSSH PRIVATE KEY-----` or another `… PRIVATE KEY` label | `plaintext-private-key`: the key *may* be unencrypted (§8.1) |
| `other` | anything else | none |

Leading whitespace and UTF-8 byte order marks are skipped before the BEGIN
line, and text after the BEGIN line's closing dashes is ignored, so neither
hides a key.

### 4.3 Certificates

| Property | Meaning |
|---|---|
| `cert:is-ca` | Basic constraints CA flag |
| `cert:validity-days` | The validity period in days, counted as the CA/Browser Forum Baseline Requirements define it: from notBefore **through** notAfter inclusive (BR §1.6.1, "Validity Period"), with any part of a day counting as a whole day (BR §6.3.2). So a certificate whose notAfter is exactly 365 days after its notBefore shows **366**: notAfter's own second is part of the period and starts a 366th day. A certificate valid for at most 365 days ends one second earlier |
| `cert:cabf-max-days` | The Baseline Requirements maximum for a Subscriber Certificate, with the rule used, e.g. `200 (notBefore on or after 2026-03-15; Baseline Requirements §6.3.2)`. The rules are keyed to the issue date, which a certificate does not carry, so its start date (notBefore) stands in for it: 398 days before 2026-03-15, 200 from 2026-03-15, 100 from 2027-03-15, 47 from 2029-03-15. A backdated notBefore selects an earlier, longer limit. `not applicable: CA certificate` for CA certificates |
| `cert:exceeds-cabf-max` | `true` when validity-days is above that maximum. **Informational only** (§6.7) |
| `cert:cabf-applicability` | Says so on every component that has exceeds-cabf-max: the limit binds only publicly trusted TLS server certificates, and internal VPN certificates are not bound by it |
| `cert:expired` | `true`/`false` at the reference time, or `not evaluated` when there is none; `true` also gives a `cert-expired` warning |
| `cert:expiry-checked-at` | The reference time: the current time, or under `--reproducible` the `SOURCE_DATE_EPOCH` time. With `--reproducible` and no `SOURCE_DATE_EPOCH`, expiry is not evaluated, so reproducible output does not change from day to day |
| `cert:serial`, `cert:sha256` | Serial number (hex) and SHA-256 fingerprint of the DER certificate |
| `cert:parse` = `failed` | The PEM did not parse; the component has no certificate details |
| `cert:additional-certificate-blocks` | Further CERTIFICATE blocks in the field (a chain); not inventoried (§7.1) |
| `cert:key-blocks-in-certificate-field` | Private key blocks found in the certificate field, from their BEGIN lines; never decoded |
| `cert:other-pem-blocks` | Other PEM blocks in the certificate field, for example a CSR |

### 4.4 Merging and merge conflicts

Each algorithm is one component per backup, shared by every protocol that
uses it, with an evidence occurrence for every place it is configured. Its
bom-ref is `crypto/` plus the first 16 hex digits of SHA-256 over asset type,
name, and the backup's file name, so every extractor computes the same
bom-ref for the same algorithm without coordinating.

When a second copy of a component (same type, name, and OID) is added, it is
merged into the first:

- evidence occurrences are added unless an identical one is already there;
- properties are combined; if both copies set a property to different
  values, the smaller value is kept, so the result does not depend on
  extractor order, and a `merge-conflict` warning names both values;
- the algorithm, protocol, certificate, or material details of the first
  copy are kept; if the second copy's details differ, that is a
  `merge-conflict` warning too.

A merge conflict means two extractors disagree about the same component,
which is a bug. Tests check that extractors define shared algorithms
identically (`extract/shared_test.go`), that the CBOM is byte-identical
whichever order the extractors run in, and that the fixtures produce no
merge conflict.

## 5. Warnings

Warnings go to stderr as `file:line: warning: message [code]`. They never
contain a secret value or the content of a key or certificate.

| Code | Meaning |
|---|---|
| `no-default-table` | No defaults table for this firmware; unset fields are `unknown` |
| `unknown-token` | A configured token is not a known option (kept if it looks like one, dropped and not shown otherwise) |
| `implied-next` | An `end` closed an `edit` without `next`; read as `next` then `end` |
| `section-not-inventoried` | The backup has crypto sections the CBOM does not cover yet |
| `plaintext-psk` | An IPsec PSK is stored in plaintext in the backup |
| `plaintext-private-key` | A private key is, or may be, stored unencrypted (§4.2) |
| `private-key-in-certificate-field` | A certificate field also holds a private key block |
| `cert-unparseable` | A certificate entry has no PEM that parses (and is not a VDOM reference) |
| `cert-expired` | A certificate expired before the reference time |
| `cert-reference-missing` | A VDOM entry refers to a global certificate that is not in the backup; reported once, not again by the protocols that use the name |
| `unknown-certificate` | A tunnel or SSL VPN names a certificate that is not among the local certificates it can use (for example a built-in one) |
| `unknown-phase1` | A phase2 names a phase1 that is not defined in the same scope |
| `addke-not-ikev2`, `addke-applies-unknown` | `addke` on an IKEv1 tunnel, or on one whose IKE version is unknown; not counted |
| `ssl-version-range-empty` | SSL VPN minimum version is above the maximum |
| `merge-conflict` | Two extractors disagree about one component (§4.4) |

## 6. Design decisions

### 6.1 One component per algorithm, many references

A CBOM of a firewall lists each algorithm once, with every place it is
configured as evidence, and protocols reference it. A policy asking "where is
3DES used?" gets one component with all its locations. CycloneDX 1.6 has the
references for this: `cryptoRefArray`, `ikev2TransformTypes`, and
`dependencies`.

### 6.2 Names by algorithm, not by protocol token

DH groups are named `MODP-2048`, `ECP-384`, `X25519` rather than "group 14":
IKE group 31, the X25519 part of an SSH hybrid, and the TLS group `X25519` are
the same algorithm and become one component. The IKE number is kept as
`ike-transform-id`. TLS FFDHE groups (RFC 7919) are named `FFDHE-2048` and
kept apart from IKE's MODP groups (RFC 3526): they are different groups of
the same size.

### 6.3 Hybrid key exchange and post-quantum TLS groups

- A hybrid key exchange is a `combiner` algorithm that depends on its parts,
  which are their own components; the protocol references the combiner and
  the parts. A policy looking for ML-KEM finds it, and one rejecting
  classical-only key exchange sees the exchange is not classical-only.
  - SSH `mlkem768x25519-sha256` → combiner, parts `ML-KEM-768` and `X25519`.
  - TLS groups use their IANA names (RFC 10024): `X25519-MLKEM768` →
    `X25519MLKEM768` (ML-KEM-768 + X25519), `P-256-MLKEM768` →
    `SecP256r1MLKEM768` (ML-KEM-768 + ECP-256), `P-384-MLKEM1024` →
    `SecP384r1MLKEM1024` (ML-KEM-1024 + ECP-384).
- IKEv2 additional key exchanges (`addke1`…`addke7`, RFC 9370) are not a
  combiner: each round is a separate key exchange. Each KEM is added to the
  tunnel's `ke` transforms next to the DH group, with the rounds kept as
  `addke<N>:value` properties, since 1.6 has no per-round slot.
- CycloneDX 1.6 has no TLS-groups field, so groups go into `cryptoRefArray`
  as algorithm components (1.7 adds `cipherSuite.tlsGroups`).
- ML-KEM and hybrid groups are defined for TLS 1.3 only
  (draft-ietf-tls-mlkem registers them "for use in TLS 1.3"; RFC 10024
  defines the hybrids "for TLS 1.3"), and TLS 1.2 has no KEM key exchange.
  So only the TLS 1.3 component references them. TLS 1.2 and below, and an
  SSL VPN component whose version is unknown (it may stand for TLS 1.2),
  reference only the classical groups and list the others in
  `tls-groups:tls13-only`.

### 6.4 VDOM references to global certificates

In a multi-VDOM backup each VDOM's certificate tables also list the global
(factory) certificates by name, with `range global` and no PEM. Such an
entry is a reference to the global certificate of the same name, not a
certificate:

- it adds no component (no duplicate) and no `cert-unparseable` warning;
- the global certificate gets an evidence occurrence for each VDOM entry and
  `referenced-from`;
- an IPsec tunnel or SSL VPN in the VDOM that names it links to the global
  component;
- if the global certificate is missing, one `cert-reference-missing` warning
  reports it, and the protocols that use the name do not warn again.

Name lookup goes from the protocol's scope to global, never to another VDOM;
a name found nowhere gives `unknown-certificate`. Entries that are neither
references nor contain a PEM keep `cert-unparseable`.

### 6.5 IPsec authentication (review item M2)

A tunnel with `authmethod signature` depends on each local certificate its
`certificate` field names, and its auth transform (IKEv2) or
`cryptoRefArray` (IKEv1) references the certificate key's algorithm, for
example `RSA-2048`. A PSK tunnel's auth references its `secret-key`
component; its `certificate` field is not linked.

### 6.6 Quantum security level

`nistQuantumSecurityLevel` is `0` on classical public-key algorithms
(`key-agree`, `signature`, `pke`), which Shor's algorithm breaks; CycloneDX
1.6 defines 0 as "none of the categories are met". ML-KEM-512/768/1024 are
1/3/5 (FIPS 203). It is left unset on symmetric algorithms, combiners (judge
them by their parts), and the non-NIST KEMs (Kyber, FrodoKEM, BIKE, HQC),
which have no NIST category.

### 6.7 The CA/Browser Forum check is informational

The Baseline Requirements limit the validity of publicly trusted TLS server
certificates. A firewall's IPsec and SSL VPN certificates are usually issued
by a private CA and are not bound by them, so `exceeds-cabf-max=true` is not
a finding by itself; it never gives a warning, and `cabf-applicability` says
why on each component. It is useful for the certificates that are publicly
trusted (for example an SSL VPN portal certificate from a public CA) and as
a lifetime indicator ahead of the shorter limits. Expiry, by contrast, is a
warning.

### 6.8 Certificate keys and signatures: one Ed25519, separate from ssh-ed25519

- Key algorithms are named by key: `RSA-<bits>` (`pke`), `ECDSA-P256/P384/
  P521` (`signature` with the curve), `Ed25519`. Signature algorithms use
  Go's names (`SHA256-RSA`, `ECDSA-SHA384`), with OIDs read from the
  certificate's ASN.1 so algorithms Go does not know (ML-DSA in Go 1.26) still
  get one.
- Pure Ed25519 uses one OID (`1.3.101.112`, RFC 8410) for the key and the
  signature, and Go names both `Ed25519`. They are the same algorithm, so they
  are one component with one definition (`signature`, curve `ed25519`).
  Defining it twice under one bom-ref caused a merge conflict, now guarded by
  a test that no signature algorithm can share a key algorithm's name unless
  the definitions match.
- The SSH host-key algorithm `ssh-ed25519` is a separate component (own name,
  own bom-ref), described identically (`signature`, curve `ed25519`, quantum
  level 0). The primitive is the same, but the identifiers and contexts
  differ: `ssh-ed25519` is SSH's name for the host-key signature scheme,
  negotiated in the SSH handshake (RFC 8709), while `Ed25519` is the X.509
  key and signature algorithm identified by OID. Keeping SSH's name lets a
  reader match the component to the `ssh-hsk-algo` setting and the SSH
  algorithm lists, and a policy can still find all Ed25519 use by primitive
  and curve.

### 6.9 Secrets

- Never output a secret: PSKs, `ENC` values, passwords, private keys. Report
  presence and form only.
- PEM values are told apart by their BEGIN and END lines before anything is
  decoded, and only CERTIFICATE blocks are ever decoded. A CERTIFICATE block
  with another BEGIN line inside (a pasted key) is not decoded either, since
  `pem.Decode` would skip the bad base64 and decode the inner block.
- Unknown tokens that do not look like options are dropped without being
  echoed, and warnings never quote values.
- Evidence records the backup's file name only, never its path (paths leak
  user names).
- Encrypted backups (`#FGBK`) are refused, not decrypted.

### 6.10 Reproducible output

Components are sorted (protocols, algorithms, certificates, material, then by
name), dependencies by ref, evidence occurrences by location. With
`--reproducible`, the serial number is a UUIDv5 derived from the backup's
SHA-256 and the tool version, and the timestamp and the expiry reference time
come from `SOURCE_DATE_EPOCH` (omitted, and expiry not evaluated, when it is
unset), so two runs give byte-identical output.

## 7. Known limitations and accepted risks

### 7.1 Only the first certificate of a chain

A certificate field may hold a chain. Only the first CERTIFICATE block is
parsed and inventoried; the others are counted in
`cert:additional-certificate-blocks`. Intermediate certificates in a local
certificate's field are therefore not in the CBOM.

### 7.2 TLS 1.2 cipher suites are unknown

For TLS 1.2 and below, FortiOS sets the suites with `algorithm
high/medium/low` and `banned-cipher` (SSL VPN), or the static-key and
banned-cipher options (admin HTTPS). The resulting list depends on the
firmware build and is not documented as a list, so the CBOM records the
settings and `cipher-suites: unknown` instead of guessing. A live scan
(testssl.sh) is the way to fill it.

### 7.3 Defaults only for specific firmware versions

Defaults tables cover FortiOS **7.4.12**, **7.6.3–7.6.7**, and **8.0.1**, for
`system global`, `system ssh-config`, the IPsec phase1/phase2 tables, and
`vpn ssl settings`. Other versions get no defaults: fields not set in the
backup are `unknown`, with one `no-default-table` warning. Some defaults
also differ within a table by build (`byVersion`, for example `tls-groups`
from 7.6.5).

### 7.4 Sections not inventoried yet

These hold crypto but are not read; when present they are listed in
`sections-not-inventoried` and warned about: `vpn ipsec manualkey`,
`vpn ipsec manualkey-interface`, `vpn qkd`, `vpn certificate crl`,
`vpn certificate ocsp-server`, `vpn certificate hsm-local`,
`vpn certificate setting`, `certificate crl`, `firewall ssh local-key`,
`firewall ssh local-ca`, `firewall ssl-ssh-profile`, `firewall vip` (only
with SSL offload), `firewall access-proxy`,
`firewall access-proxy-virtual-host`, `ztna web-proxy`,
`ztna service-connector`, `system snmp user`, `wireless-controller vap`.

### 7.5 Other limitations

- Table 9 elements not filled yet: Crypto Functions, Classical security
  level, key state, Activation Date (§2; §8.3–8.5), and algorithm OIDs
  outside certificates.
- `admin-server-cert` is recorded by name; admin HTTPS is not linked to a
  certificate component yet.
- The effective cipher set under `strong-crypto` is not computed; options it
  may disable are marked (§4.1).
- `ike-transform-id` is added by the IPsec extractor, so an X25519 or
  ML-KEM-768 component that only SSH uses has none. That is expected: the ID
  is an IKE number.
- Certificate validity is judged against today's Baseline Requirements text;
  the limits before 2020 are not modelled.
- DTLS exists only in 7.4.12, so DTLS components appear only for that version.
- `merge-conflict` warnings name the component but not a file line.
- CycloneDX 1.6 only; a 1.7 emitter (with `tlsGroups` and certificate
  extensions) is planned.
- Fixture syntax comes from Fortinet's CLI reference; checks on a FortiGate-VM
  (⚠U1–U3 in docs/PLAN.md) are still open.

### 7.6 Accepted risk: a forged Proc-Type header hides a plaintext key (R2)

A traditional RSA/EC/DSA key is classified `encrypted-pem` when
`Proc-Type: 4,ENCRYPTED` directly follows its BEGIN line. The body is never
read, so someone who hand-edits a plaintext key to add that header would
suppress the `plaintext-private-key` warning. This is accepted and not
fixed: the header is written only by tools that really encrypted the key,
so it cannot appear by accident, and anyone able to edit the backup can
also remove the key or the warning's cause in other ways. Checking further
would mean decoding the key body, which cbom-netscan does not do.

## 8. Open decisions

### 8.1 Detecting whether an OpenSSH-format key is encrypted

An `-----BEGIN OPENSSH PRIVATE KEY-----` value records its encryption inside
the base64 body: the key format (OpenSSH `PROTOCOL.key`) starts with the
magic `openssh-key-v1`, then `ciphername` and `kdfname`, which are `none`
for an unencrypted key, before the public keys and the encrypted private
section. Today such a key is `pem-encryption-unknown` with a warning that it
*may* be unencrypted. Options:

1. Keep it as is: never decode any of a key's body. Simple and consistent
   with §6.9, at the cost of a vague warning.
2. Decode only the start of the body, the first few dozen bytes, which hold
   the magic and the length-prefixed cipher name, and read nothing past it. The cipher name is metadata, not
   key material, but this is the only place cbom-netscan would decode part
   of a key.
3. Decide when `firewall ssh local-key` and `firewall ssh local-ca` are
   inventoried: those are where FortiOS stores OpenSSH-format keys (research
   notes §3.8). In a certificate's `private-key` field this format is unusual.

### 8.2 Table 9 "List"

Read as the list of algorithm components (§2.1). If CERT-In means a
per-system list of algorithms, as its "quantum device or system" wording
suggests (a QBOM idea), the CBOM's algorithm components already are that
list for a firewall; no extra field would be added either way.

### 8.3 Key state

CycloneDX 1.6's `state` enum is `pre-activation`, `active`, `suspended`,
`deactivated`, `compromised`, `destroyed`; CERT-In's examples include
`revoked` and `expired`, which it lacks. A backup does not show whether a key
is in use. One option: `active` for keys of certificates that a protocol
uses, nothing otherwise, and a property for expiry.

### 8.4 Activation Date

The certificate's notBefore is the earliest the key could have been used
through that certificate, not necessarily when the key became operational.
Using it would fill the element but needs to be documented as a convention.

### 8.5 Crypto Functions and Classical security level

Both need rules cbom-netscan would own: functions by the algorithm's role in
the protocol, and security levels from NIST SP 800-57 Part 1 Rev. 5 Table 2.
The open question is how to describe a combiner's level (the stronger or
weaker of its parts).

## 9. Sources

- CERT-In, *Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM*,
  version 2.0, dated 09.07.2025, Table 9, printed pp. 45–48:
  <https://cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf>
  (read 2026-10-14; SHA-256 of the file read:
  `28aa48f329114d665f8e4f8c4d2f33baf4981e29168a318e6e719c11a5ff5151`).
- CycloneDX 1.6 JSON schema: <https://cyclonedx.org/schema/bom-1.6.schema.json>
- FortiOS field names, defaults, and versions: `docs/fortios-parser-research.md`
  (§3.1–3.12 field tables, §7 CBOM mapping, §8 edge cases), which cites the
  FortiOS CLI references and administration guides it was taken from.
- CA/Browser Forum Baseline Requirements, §1.6.1 ("Validity Period") and
  §6.3.2: <https://github.com/cabforum/servercert/blob/main/docs/BR.md>
- RFC 10024 (ECDHE-MLKEM hybrid groups for TLS 1.3; draft-ietf-tls-ecdhe-mlkem-05)
  and draft-ietf-tls-mlkem-11 (ML-KEM groups for TLS 1.3).
- RFC 9370 (multiple key exchanges in IKEv2), RFC 7296 §3.3.2 (private-use
  transform IDs), IANA IKEv2 Transform Type 4 registry.
- RFC 7919 (FFDHE groups), RFC 3526 (MODP groups), FIPS 203 (ML-KEM).
- RFC 8410 (Ed25519 in X.509), RFC 8709 (Ed25519 in SSH), RFC 1421 (PEM
  Proc-Type header), RFC 7468 (PEM labels).
- OpenSSH `PROTOCOL.key`:
  <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key>
