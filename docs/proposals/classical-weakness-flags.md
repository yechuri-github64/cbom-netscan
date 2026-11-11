# Proposal: classical-weakness flags

Status: **proposal for review**, 2026-10-16. Nothing here is implemented yet;
the implementation follows only after the design is approved.

## What and why

cbom-netscan records which algorithms and protocols a device is configured
to use, and `nistQuantumSecurityLevel` says which of them a quantum computer
breaks. Nothing says yet which are already weak against classical attacks.
This proposal flags five such weaknesses, each through a rule that cites
its source:

- 3DES;
- SHA-1;
- MODP-1024 (IKE Diffie-Hellman group 2);
- RSA keys below 2048 bits;
- TLS 1.0 and 1.1.

The flags are informational, like the CA/Browser Forum check (MAPPING.md
§6.7): the CBOM stays an inventory, not a compliance verdict. A flag means
"this component matches a rule in cbom-netscan's list, which cites this
source". No flag means that no rule matched, not that the component is
strong.

## The property

A new, separate property on the algorithm and protocol components that
match a rule:

| Property | Value |
|---|---|
| `cbom-netscan:classical-weakness` | The IDs of the matching rules, space-separated and sorted, e.g. `tdea` |
| `cbom-netscan:classical-weakness:<rule ID>` | That rule's status and source, e.g. `disallowed; NIST SP 800-131A Rev. 2 §2 Table 1` |

The status is one of two words, taken from the cited source's terms:
`disallowed` (the source says it is no longer to be used to apply
protection) and `deprecated` (still allowed, with an announced end).

Why a new property and not an existing field:

- `nistQuantumSecurityLevel` answers a different question. CycloneDX 1.6
  defines it for quantum attacks, and RSA-1024 and RSA-4096 both have
  level 0. Reusing it would mix the two.
- `classicalSecurityLevel` (planned, MAPPING.md §8.5) is a number of bits
  from SP 800-57. It does not say whether a standard still allows the
  algorithm, and statuses change on dates while the bits stay the same
  (RSA-2048 stays 112 bits, but the SP 800-131A Rev. 3 draft deprecates
  112-bit signatures after 2030). The flag carries the verdict and its
  source; the two can be added independently.
- CycloneDX 1.6 has no field for this, so it is a cbom-netscan property,
  like the `cert:` ones. It has no `fortios:` part because it describes the
  algorithm, not the configuration.

Example, the 3DES algorithm from the multi-VDOM VM fixture (PR #6):

```json
{
  "type": "cryptographic-asset",
  "name": "3DES-CBC",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": { "primitive": "block-cipher", "mode": "cbc" }
  },
  "properties": [
    { "name": "cbom-netscan:classical-weakness", "value": "tdea" },
    { "name": "cbom-netscan:classical-weakness:tdea", "value": "disallowed; NIST SP 800-131A Rev. 2 §2 Table 1: three-key TDEA encryption is disallowed after 2023" }
  ]
}
```

## Rules

| ID | Status | Flags these components | Main source |
|---|---|---|---|
| `tdea` | disallowed | `3DES-CBC` (IKE and ESP `3des`, SSH `3des-cbc`) | SP 800-131A Rev. 2 §2, Table 1 |
| `sha1-signature` | disallowed | Certificate signature algorithms `SHA1-RSA`, `ECDSA-SHA1`, `DSA-SHA1`; SSH host key `ssh-rsa`; IKE tunnels whose `signature-hash-alg` includes `sha1` (the flag goes on the tunnel, since that hash is not a component) | SP 800-131A Rev. 2 §9, Table 8 |
| `sha1-mac` (decision 2) | deprecated | `HMAC-SHA1`, `PRF-HMAC-SHA1`, SSH `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1` | NIST's 2030 SHA-1 transition; RFC 8247, RFC 8221, RFC 9142 |
| `ffc-below-2048` | disallowed | `MODP-1024` (IKE group 2); with decision 3 also `MODP-768` (group 1), `MODP-1536` (group 5), and SSH `diffie-hellman-group1-sha1` | SP 800-131A Rev. 2 §5, Table 4 |
| `rsa-below-2048` | disallowed | Certificate key algorithms `RSA-<bits>` with fewer than 2048 bits | SP 800-131A Rev. 2 §3, Table 2 and §6, Table 5 |
| `tls-1.0`, `tls-1.1` | disallowed | TLS protocol components of version 1.0 or 1.1 (admin HTTPS, SSL VPN); with decision 4 also `dtls-1.0` | RFC 8996 §4, §5 |

The sources, quoted. All were read on 2026-10-16 from csrc.nist.gov,
nvlpubs.nist.gov, and rfc-editor.org.

### `tdea`: 3DES

- NIST SP 800-131A Rev. 2 (March 2019, final), §2, Table 1 "Approval Status
  of Symmetric Algorithms Used for Encryption and Decryption": two-key TDEA
  encryption "Disallowed"; three-key TDEA encryption "Deprecated through 2023
  / Disallowed after 2023"; decryption "Legacy use". Text: "After December
  31, 2023, three-key TDEA is disallowed for encryption unless specifically
  allowed by other NIST guidance."
- NIST withdrew SP 800-67 Rev. 2, the TDEA specification, on January 1,
  2024; its announcement (2023-06-29) says the withdrawal "will signify that
  TDEA is no longer an approved block cipher".
- IETF, for implementations: RFC 8221 §5 (ESP), ENCR_3DES "SHOULD NOT"; RFC
  8247 §2.1 (IKEv2), ENCR_3DES "MAY". Milder than NIST; the rule follows
  NIST.

### `sha1-signature`: SHA-1 in signatures

- SP 800-131A Rev. 2 §9, Table 8 "Approval Status of Hash Functions": SHA-1
  for digital signature generation "Disallowed, except where specifically
  allowed by NIST protocol-specific guidance"; for verification "Legacy
  use".
- `ssh-rsa` signs with SHA-1. RFC 4253 §6.6: "Signing and verifying using
  this key format is performed according to the RSASSA-PKCS1-v1_5 scheme in
  [RFC3447] using the SHA-1 hash."
- IKEv2: RFC 8247 §3.2, SHA1 as the hash of the Digital Signature
  authentication method "MUST NOT".
- A CA certificate signed with SHA-1 is flagged although the device only
  verifies it (legacy use): the flag says that the signature uses SHA-1.

### `sha1-mac`: SHA-1 in HMAC, PRF, and key exchange (decision 2)

Under the final SP 800-131A Rev. 2 these uses are acceptable: Table 8, SHA-1
for "Non-digital-signature applications: Acceptable"; §10, Table 9, HMAC
generation with keys of at least 112 bits "Acceptable" with any approved
hash; Table 7, HMAC-based key derivation acceptable. What points the other
way:

- NIST, "NIST Transitioning Away from SHA-1 for All Applications" (CSRC,
  2022-12-15): "NIST will transition away from the use of SHA-1 for applying
  cryptographic protection to all applications by December 31, 2030."
- SP 800-131A Rev. 3, initial public draft (2024-10-21, still a draft):
  "HMAC generation using SHA-1 ... is deprecated through December 31, 2030,
  and disallowed thereafter", and the same for SHA-1 in HMAC-based key
  derivation.
- RFC 8247 §2.2 and §2.3 (IKEv2): PRF_HMAC_SHA1 and AUTH_HMAC_SHA1_96
  "MUST-", "as cryptographic attacks against SHA1 are increasing"; RFC 8221
  §6 (ESP): AUTH_HMAC_SHA1_96 "MUST-".
- RFC 9142 (SSH key exchange, January 2022), Table 12:
  diffie-hellman-group14-sha1 "MAY" (was MUST), diffie-hellman-group1-sha1
  "SHOULD NOT" (was MUST), diffie-hellman-group-exchange-sha1 "SHOULD NOT".

Recommendation: flag these `deprecated`, not `disallowed`, so that a reader
can tell "allowed until 2030" from "not allowed".

### `ffc-below-2048`: MODP-1024 and other small finite-field groups

- SP 800-131A Rev. 2 §5, Table 4: SP 800-56A finite-field DH and MQV with
  "(len(p), len(q)) = (1024, 160)" "Disallowed"; non-compliant finite-field
  schemes with "len(p) < 2048 OR len(q) < 224" "Disallowed". Text: "The use
  of schemes that support a security strength less than 112 bits is
  disallowed, i.e., when using FIPS 186-type domain parameters where len(p)
  < 2048 or len(q) < 224."
- SP 800-56A Rev. 3, Appendix D, Table 25 "Approved IKE groups for FFC key
  agreement" lists only MODP-2048 (ID=14) through MODP-8192 (ID=18).
- RFC 8247 §2.4: group 2, the 1024-bit MODP group, "SHOULD NOT": "It is
  known to be weak against sufficiently funded attackers ... It is expected
  in the near future to be downgraded to MUST NOT." Group 1 "MUST NOT";
  group 5 "SHOULD NOT".
- NIST SP 800-77 Rev. 1 (June 2020), §3.9: "3DES, MD5, SHA-1, and DH Groups
  2 and 5 should not be used."
- SP 800-131A does not name IKE group numbers. Group 2 is the 1024-bit MODP
  group (IANA IKEv2 Transform Type 4), so it falls under len(p) < 2048.

### `rsa-below-2048`: RSA keys below 2048 bits

- SP 800-131A Rev. 2 §3, Table 2: digital signature generation with "RSA:
  len(n) < 2048" "Disallowed"; verification with 1024 ≤ len(n) < 2048 "Legacy
  use". Text: "RSA: The length of the modulus n shall be 2048 bits or more to
  meet the minimum security-strength requirement of 112 bits for Federal
  Government use."
- §6, Table 5: RSA key agreement and key transport with len(n) < 2048
  "Disallowed".
- SP 800-57 Part 1 Rev. 5, Table 2: k = 1024 is in the "≤ 80" bits row.
- RFC 8247 §3.1.1 (IKEv2 authentication): "RSA with key length smaller than
  2048" "SHOULD NOT".

### `tls-1.0`, `tls-1.1`: TLS 1.0 and 1.1

- RFC 8996 (March 2021, BCP 195), §4: "TLS 1.0 MUST NOT be used. Negotiation
  of TLS 1.0 from any version of TLS MUST NOT be permitted." §5: the same for
  TLS 1.1. §6, updating RFC 7525: "Implementations MUST NOT negotiate DTLS
  version 1.0".
- NIST SP 800-52 Rev. 2 (August 2019), §3.1: servers for government-only
  applications "should not be configured to use TLS 1.1 and shall not use
  TLS 1.0, SSL 3.0, or SSL 2.0"; for citizen- or business-facing servers
  "The use of TLS versions 1.1 and 1.0 is generally discouraged, but these
  versions may be configured when necessary".
- The status follows RFC 8996's MUST NOT.

## Where the rules live in the code

```
pkg/weakness/
  rules.go         the rule list: one table, the only place to edit when a
                   standard changes
  weakness.go      Apply(inv): runs every rule on every component and sets
                   the two properties
  weakness_test.go a matching and a non-matching component per rule; every
                   rule has a status and a source; MAPPING.md §6.11 lists
                   exactly the rule IDs in the table
```

A sketch of `rules.go`:

```go
// Rules is the list of classical weaknesses cbom-netscan flags. When a
// standard changes, edit this table, its tests, and MAPPING.md §6.11.
var Rules = []Rule{
	{
		ID:      "tdea",
		Status:  Disallowed,
		Source:  "NIST SP 800-131A Rev. 2 §2 Table 1: three-key TDEA encryption is disallowed after 2023",
		Checked: "2026-10-16", // when the source was last read
		Match:   algorithms("3DES-CBC"),
	},
	{
		ID:      "rsa-below-2048",
		Status:  Disallowed,
		Source:  "NIST SP 800-131A Rev. 2 §3 Table 2, §6 Table 5: RSA with a modulus under 2048 bits",
		Checked: "2026-10-16",
		Match:   keySizeBelow("RSA-", 2048),
	},
	// ...
}
```

The rules match the names and fields cbom-netscan already documents
(algorithm names in MAPPING.md §2.1, protocol type and version, the key
size), not FortiOS tokens, so the package does not depend on the vendor.
`Apply` runs once in `internal/cli/fortios.go`, after all extractors and
before the emitter, so the extractors do not change.

## How it appears in MAPPING.md

New §4.5 in "Output properties":

> ### 4.5 Classical weaknesses
>
> | Property | Meaning |
> |---|---|
> | `classical-weakness` | The rules of §6.11 that match this algorithm or protocol, space-separated, e.g. `tdea`. Informational; absent when no rule matches, which does not mean the component is strong |
> | `classical-weakness:<rule ID>` | The rule's status (`disallowed` or `deprecated`) and its source, e.g. `disallowed; NIST SP 800-131A Rev. 2 §2 Table 1: three-key TDEA encryption is disallowed after 2023` |

New §6.11 in "Design decisions":

> ### 6.11 Classical weaknesses are flagged by rule, with a source
>
> cbom-netscan flags algorithms and protocols that a cited standard
> disallows or deprecates, so that a reader can find them without knowing
> the standards. The rules are in `pkg/weakness/rules.go`; each has a status
> taken from its source and the date the source was last checked. The flag
> is separate from `nistQuantumSecurityLevel` (quantum attacks, §6.6) and
> from `classicalSecurityLevel` (bits, §8.5), and like the CA/Browser Forum
> check (§6.7) it never gives a warning: the CBOM is an inventory, not a
> compliance verdict.
>
> | Rule | Status | Flags | Source |
> |---|---|---|---|
> | `tdea` | disallowed | `3DES-CBC` | NIST SP 800-131A Rev. 2 §2 Table 1 |
> | `sha1-signature` | disallowed | `SHA1-RSA`, `ECDSA-SHA1`, `DSA-SHA1`, `ssh-rsa`; IKE tunnels with `signature-hash-alg sha1` | SP 800-131A Rev. 2 §9 Table 8; RFC 4253 §6.6; RFC 8247 §3.2 |
> | `sha1-mac` | deprecated | `HMAC-SHA1`, `PRF-HMAC-SHA1`, SSH `*-sha1` key exchanges | NIST SHA-1 transition (2022); SP 800-131A Rev. 3 draft; RFC 8247 §2.2–2.3; RFC 8221 §6; RFC 9142 |
> | `ffc-below-2048` | disallowed | `MODP-768`, `MODP-1024`, `MODP-1536`, SSH `diffie-hellman-group1-sha1` | SP 800-131A Rev. 2 §5 Table 4; SP 800-56A Rev. 3 Table 25; RFC 8247 §2.4 |
> | `rsa-below-2048` | disallowed | `RSA-<bits>` below 2048 | SP 800-131A Rev. 2 §3 Table 2, §6 Table 5 |
> | `tls-1.0`, `tls-1.1`, `dtls-1.0` | disallowed | TLS and DTLS components of those versions | RFC 8996 §4–6 |

§9 "Sources" gains SP 800-131A Rev. 2, SP 800-56A Rev. 3, SP 800-57 Part 1
Rev. 5, SP 800-52 Rev. 2, SP 800-77 Rev. 1, RFC 8996, RFC 8247, RFC 8221,
RFC 9142, and RFC 4253, with URLs.

## What the fixtures would show

With the VM fixture (PR #6): `3DES-CBC` gets `tdea`; `MODP-1024` gets
`ffc-below-2048`; `RSA-1024` (the certificate named Fortinet_SSL_RSA2048)
gets `rsa-below-2048`; `FortiOS admin HTTPS TLS 1.1` gets `tls-1.1`; and
with decision 2, `HMAC-SHA1` and `PRF-HMAC-SHA1` get `sha1-mac`. With PR #5,
`DSA-SHA1` gets `sha1-signature`, and with decision 5 `DSA-1024` gets a key
size flag.

## Decisions requested

1. **Property shape**: `cbom-netscan:classical-weakness` (rule IDs) plus
   `cbom-netscan:classical-weakness:<rule ID>` (status; source), with the
   statuses `disallowed` and `deprecated`.
2. **SHA-1 in HMAC, PRF, and SSH key exchange**: flag as `deprecated`
   (recommended), or not until SP 800-131A Rev. 3 is final?
3. **Small finite-field groups**: besides MODP-1024, also MODP-768 and
   MODP-1536 (IKE groups 1 and 5) and SSH `diffie-hellman-group1-sha1`, under
   the same threshold (recommended).
4. **DTLS 1.0** alongside TLS 1.0 and 1.1 (recommended; RFC 8996 §6).
5. **Other small keys**: DSA keys below 2048 bits (`DSA-1024`, from PR #5)
   are in the same disallowed row of SP 800-131A Table 2; flag them too as
   `dsa-below-2048` (recommended)?
6. **No warnings**: properties only, no stderr warnings, as for the CA/B
   check (recommended); or one warning per flagged component?
7. **Location**: `pkg/weakness`, applied once by the CLI.

Out of scope, possible follow-ups: IKEv1 itself (RFC 9395 deprecates it,
and it is still the default in FortiOS 7.6), DES and MD5 (weak as well; easy
to add), TLS 1.2 cipher suites (not derivable from the backup, MAPPING.md
§7.2), and `classicalSecurityLevel` (MAPPING.md §8.5).
