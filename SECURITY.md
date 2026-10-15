# Security policy

cbom-netscan reads configuration backups, which hold secrets. A bug that lets
a secret reach the CBOM or a warning is a security bug, as is anything that
makes the tool crash, hang, or misreport crypto on a crafted backup.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**, or go to
<https://github.com/yechuri-github64/cbom-netscan/security/advisories/new>.
Do not open a public issue, discussion, or pull request for a vulnerability.
If the button is missing, open an issue that only asks for a private contact,
without any details.

Include:

- the cbom-netscan version (`cbom-netscan version`) and platform;
- what happens and what you expected;
- a **synthetic** backup or snippet that reproduces it. Never send a real
  configuration backup, even redacted: adapt one of the fixtures under
  `pkg/**/testdata/` instead, with made-up names, documentation IP ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and fake secrets.

This is a volunteer project. The aim is to acknowledge a report within
7 days and to agree on a fix and disclosure date with you; fixes are released
as a new version with a GitHub security advisory crediting you, unless you
prefer otherwise.

## Scope

In scope:

- a secret value (pre-shared key, `ENC` value, password, private key) or any
  part of one appearing in the CBOM, in a warning, or in an error message;
- key material being decoded or parsed at all (only the PEM header lines of a
  key may be read; see MAPPING.md §6.9);
- a crash, hang, or excessive memory use on a crafted backup within the
  resource limits below;
- a crafted backup that makes the CBOM misreport crypto, for example hide a
  weak algorithm or claim a post-quantum one that is not configured;
- weaknesses in how releases are built, signed, or verified.

Out of scope:

- vulnerabilities in FortiOS or other Fortinet products: report those to
  [Fortinet PSIRT](https://www.fortiguard.com/psirt);
- findings that require a modified cbom-netscan binary or control of the
  machine it runs on;
- the documented accepted risks in
  [MAPPING.md §7.6](MAPPING.md#76-accepted-risk-a-forged-proc-type-header-hides-a-plaintext-key-r2).

## Resource limits

A backup is untrusted input, and a small one can describe a very large
inventory: about 1 MB of tunnels that set nothing produces 40,000 CBOM
components. cbom-netscan therefore refuses, with a clear error and without
writing a CBOM, a backup that would need more than:

| Limit | Flag | Default |
|---|---|---|
| Backup size | `--max-size` | 256 MiB |
| CBOM components | `--max-components` | 100,000 |
| Evidence occurrences plus warnings | `--max-evidence` | 500,000 |

Components and evidence are limited separately because repeating one name
in a backup adds evidence and warnings without adding components. Once a
limit is reached nothing more is stored, so memory stops growing, and the
run ends with an error.

The defaults keep peak memory at or below about 2 GB. Measured with
cbom-netscan 0.1.2 (Linux amd64) on synthetic backups at the limits:

| Backup | Components | Evidence + warnings | Peak memory |
|---|---|---|---|
| 33,000 tunnels (phase1, phase2, pre-shared key) | 99,026 | 495,000 | 1.76 GB |
| 99,970 tunnels with nothing set, plus one name repeated 33,000 times | 99,998 | 494,996 | 1.86 GB |
| 16,100 tunnels with many proposals, DH groups, and additional key exchanges | 48,335 | 499,100 | 1.27 GB |
| One component or occurrence over a limit | — | — | refused in about 1–2 s, 180–340 MB |

Most of the memory goes to emitting the CBOM (about 18–20 KB per component
at peak, mostly the JSON being built). For comparison, Fortinet's maximum
values table for FortiOS 7.6.7 allows up to 200 (FortiGate 60F), 2,000
(100F, 600F), 20,000 (1800F), or 40,000 (3000F and larger) policy-based IPsec
phase1 and phase2 entries, gives no fixed table size for phase1-interface,
and up to 3,000 local and 500 CA certificates per VDOM. A backup at the
1800F maximum (20,000 tunnels and a full certificate store) needs about
70,000 components and 310,000 evidence occurrences, within the defaults.
A backup at the 3000F-class maximum of 40,000 tunnels needs about 120,000
components and 600,000 evidence occurrences, and about 2.3 GB: raise both
limits for it on a machine with the memory. In every case the error names
the limit that was reached.

`--max-size` also bounds the parser, which measured about 5 times the
backup's size in memory, so lower it if large backups must stay under a
tighter memory budget.

## Supported versions

Only the latest release gets security fixes while the project is at 0.x.

## Verifying a release

Release checksums are signed with Sigstore keyless signing from the release
workflow; see [README.md](README.md#install) for the `cosign verify-blob`
command. A signature that does not verify against this repository's
`release.yml` workflow and a `v*` tag means the files did not come from this
project's release process.
