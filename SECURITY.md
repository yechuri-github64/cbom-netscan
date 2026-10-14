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
- a crash, hang, or excessive memory use on a crafted backup;
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

## Supported versions

Only the latest release gets security fixes while the project is at 0.x.

## Verifying a release

Release checksums are signed with Sigstore keyless signing from the release
workflow; see [README.md](README.md#install) for the `cosign verify-blob`
command. A signature that does not verify against this repository's
`release.yml` workflow and a `v*` tag means the files did not come from this
project's release process.
