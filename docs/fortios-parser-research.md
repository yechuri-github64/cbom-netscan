# FortiOS offline config → CycloneDX 1.6 CBOM: parser research (cbom-netscan)

Compiled 2026-10-11 (IST). Targets FortiOS 7.4, 7.6, 8.0. Every FortiOS claim cites an official Fortinet doc, with the version, page and URL. Items labelled **KB** come from community.fortinet.com Technical Tips. Items labelled **3rd-party** are not Fortinet sources. A default is only given where a doc states it. Anything a doc does not state is marked *unknown*.

## 0. Sources and citation key

Page numbers are printed page numbers in the PDF (CLI/AG/NF/RN).

| Key | Document | URL |
|---|---|---|
| CLI-7.4.12 | FortiOS 7.4.12 CLI Reference (latest 7.4 found) | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/f178ac04-47e1-11f1-b31d-02356ffb40d9/FortiOS-7.4.12-CLI_Reference.pdf |
| CLI-7.6.3 | 7.6.3 CLI Reference | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/e628f3e3-1a47-11f0-b13a-ca4255feedd9/FortiOS-7.6.3-CLI_Reference.pdf |
| CLI-7.6.4 | 7.6.4 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/0bec1c7c-7948-11f0-9bfd-6af4c3636dc7/FortiOS-7.6.4-CLI_Reference.pdf |
| CLI-7.6.5 | 7.6.5 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/7a17cdfc-d525-11f0-8b43-d2943efe5b2f/FortiOS-7.6.5-CLI_Reference.pdf |
| CLI-7.6.6 | 7.6.6 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/61a6a037-fafc-11f0-8b43-d2943efe5b2f/FortiOS-7.6.6-CLI_Reference.pdf |
| CLI-7.6.7 | 7.6.7 (latest 7.6 found) | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/7f08d735-5ac6-11f1-a33a-02356ffb40d9/FortiOS-7.6.7-CLI_Reference.pdf |
| CLI-8.0.1 | 8.0.1 (latest 8.0 found. The 8.0.0 HTML page links this PDF) | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/618862e1-3462-11f1-b31d-02356ffb40d9/FortiOS-8.0.1-CLI_Reference.pdf |
| AG-7.4.12 | Administration Guide 7.4.12 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/c673a09c-47e1-11f1-b31d-02356ffb40d9/FortiOS-7.4.12-Administration_Guide.pdf |
| AG-7.6.7 | Administration Guide 7.6.7 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/7f08ccb4-5ac6-11f1-a33a-02356ffb40d9/FortiOS-7.6.7-Administration_Guide.pdf |
| AG-8.0.1 | Administration Guide 8.0.1 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/4cd3f184-9fee-11f1-8c5a-8e4c95ff11ac/FortiOS-8.0.1-Administration_Guide.pdf |
| NF-7.6.0 | New Features Guide 7.6.0 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/688ca0ef-eaf8-11ee-8c42-fa163e15d75b/FortiOS-7.6.0-New_Features_Guide.pdf |
| NF-8.0.0 | New Features Guide 8.0.0 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/539e425c-69a8-11f0-a9d0-d2b0d2e22f7d/FortiOS-8.0.0-New_Features_Guide.pdf |
| RN-8.0.0 | Release Notes 8.0.0 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/d94b0a41-2dee-11f1-b31d-02356ffb40d9/fortios-v8.0.0-release-notes.pdf |
| RN-8.0.1 | Release Notes 8.0.1 | https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/592a453d-9fee-11f1-8c5a-8e4c95ff11ac/fortios-v8.0.1-release-notes.pdf |
| CDX-1.6 | CycloneDX bom-1.6.schema.json (local copy /workspace/research/bom-1.6.schema.json; 1.6.1/1.6.2 have identical cryptoProperties) | https://cyclonedx.org/schema/bom-1.6.schema.json |

CLI HTML pages use stable IDs across versions: `https://docs.fortinet.com/document/fortigate/{7.4.12|7.6.7|8.0.0}/cli-reference/<id>/<slug>`. The 8.0 HTML is labelled 8.0.0. Each section heading below gives `<id>/<slug>`.
Notation: `p` = page in the CLI-ref PDF for that version. "7.6" column = 7.6.3…7.6.7, with the patch named where a value changed. `**` in a default means the CLI ref footnote "Values may differ between models".

---

## 1. Backup text format

### 1.1 Header lines
| Item | Evidence | Source |
|---|---|---|
| Line 1: `#config-version=<MODEL>-<maj>.<min>.<patch>-FW-build<NNNN>-<YYMMDD>:opmode=<n>:vdom=<n>:user=<admin>` | Example `#config-version=FGVMK6-7.0.8-FW-build0418-220920:opmode=0:vdom=0:user=admin`, followed by `#conf_file_ver=2079893748141389`, `#buildno=0418`, `#global_vdom=1`, `#private-encryption-key=oY5GhQK3w0Ddn0EX+8hp6UYpjB4=`, then `config system global` | AG-8.0.1 "TPM support for FortiGate-VM" p5518–5526 (same in AG-7.6.7 p4733, AG-7.4.12 p4104); https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/80552/tpm-support-for-fortigate-vm |
| First line holds model, firmware and build. A VDOM-scope backup has a `vd_name` entry. `user=` = exporting admin | **KB** "Technical Tip: Understanding FortiGate configuration file format" (2025-02-01) https://community.fortinet.com/fortigate-3/technical-tip-understanding-fortigate-configuration-file-format-196541 |
| Field semantics of `opmode`, `vdom`, `conf_file_ver`, `global_vdom` | *Not documented officially* (see §10) | — |
| Standard backup holds "non-default settings and selected default settings" | **KB** (same as above) | — |
| `execute export config {standard\|full\|yaml} {encrypted\|obfuscated\|secrypt} {ftp\|scp\|sftp\|tftp\|usb} …` (8.0.1). `full` scope = full config (incl. defaults; *exact semantics unverified*) | AG-8.0.1 p4520; CLI-8.0.1 p4113+ | https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/702257/configuration-backup-and-restore |

### 1.2 Syntax
| Rule | Source |
|---|---|
| Tree commands: `config <path…>` … `end`. Table entries `edit <key>` … `next`. Attributes `set <field> <v1> [v2 …]`, `unset <field>`. Nested `config <sub>` inside `edit` | AG-8.0.1 "CLI basics"/"Subcommands" https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/896276/cli-basics, https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/627485/subcommands |
| Special chars `< > ( ) # ' "` cannot be used bare. A space or one of those chars inside a string needs quotes (`"…"` or `'…'`) or a backslash escape. Escapes: `\'`, `\"`, `\\`, `\ ` (space). `?`/tab entered via Ctrl+V | AG-8.0.1 p85–86 "Special characters" (in "Command syntax") https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/508024/command-syntax |
| Line continuation: line ending in `\` continues the command (interactive CLI) | AG-8.0.1 p84 |
| Input stored as UTF-8, not normalised | AG-8.0.1 p87 |
| Multi-value: space-separated tokens after field, each optionally quoted, e.g. `set member "a" "b"`, `set dhgrp 21 20`, `set proposal aes128-sha256 aes256-sha256` | AG-8.0.1 p3188, p574–577 NF-8.0.0 |
| Multi-line value: a quoted string may contain raw newlines, e.g. PEM: `set private-key "-----BEGIN OPENSSH PRIVATE KEY-----⏎…⏎-----END OPENSSH PRIVATE KEY-----"`; `set certificate "-----BEGIN CERTIFICATE-----⏎…⏎-----END CERTIFICATE-----"` | AG-8.0.1 p1972 (firewall ssh local-ca), p4905 |
| `config` header can carry extra quoted args, e.g. `config system replacemsg mail "partial"` | 3rd-party sample: Batfish testconfig `fortios_ignored` (Apache-2.0) https://github.com/batfish/batfish/blob/540a4644e0245adffc5d51ec911411a5cd09aa0d/projects/batfish/src/test/resources/org/batfish/grammar/fortios/testconfigs/fortios_ignored |
| Formal grammar from Fortinet | **None found** in CLI/AG 7.4.12/7.6.7/8.0.1. The closest de facto grammar is the Batfish ANTLR lexer/parser (below) |

Batfish lexer (Apache-2.0, commit 540a4644, 2026-10-10 UTC): `FortiosLexer.g4` defines double-quoted text with escapes `\" \' \\`, single-quoted text with no escapes, backslash-escape of any char in unquoted words, `\`+newline continuation, and `#` comments only at line start. The word charset excludes `# ( ) < > ? ' " \` and whitespace. Batfish parses only `config system|firewall|router` (no `vpn`, `certificate`, `vdom`, `global` top-level). Path: projects/batfish/src/main/antlr4/org/batfish/grammar/fortios/.

Verified on FortiOS 7.6.7: output values are always double-quoted (single-quoted input is normalized), and the escapes are `\'`, `\"`, and `\\`. Backslash-space (`\ `) is also verified on FortiOS 7.6.7 build 3704: input `set comment a\ b\ c` is stored and shown as `set comment "a b c"`.

### 1.3 VDOM mode
| Item | Source |
|---|---|
| `config system global` → `set vdom-mode {no-vdom\|multi-vdom}`, default `no-vdom` (all versions) | CLI-7.4.12 p1590, CLI-7.6.7 p1591, CLI-8.0.1 p1641; https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/339914554/config-system-global |
| Multi-VDOM CLI examples use `config vdom` / `edit <vdom>` / `config …` / `end` / `next` / `end`, and `config global` for global objects | AG-8.0.1 p142, p407, p446 |
| Multi-VDOM backup/restore (whole or per-VDOM) | AG-8.0.1 p4285–4288 https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/87472/backing-up-and-restoring-configurations-in-multi-vdom-mode |
| Exact multi-VDOM full-backup layout: (1) a declaration block `config vdom` / `edit root` / `next` / `edit <name>` / `next` / `end` listing VDOM names only; (2) `config global` … `end`, with the blocks inside it not indented; (3) one separate `config vdom` / `edit <name>` block per VDOM holding that VDOM's settings, closed by a single `end` with no `next` | Not documented officially. **Verified on FortiOS 7.6.7 build 3704** (multi-VDOM backup) |
| Some objects are scope-dependent: `vpn certificate local/ca/remote` have `range {global\|vdom}` (default `vdom` for local) | CLI-8.0.1 p2353 |

### 1.4 Non-plaintext and alternative formats (parser must detect and refuse/flag)
| Form | Marker | Source |
|---|---|---|
| Whole-file encrypted backup (password) | Official: restore needs the same model, firmware and password (**KB** 196541). Official format marker: *not documented*. 3rd-party: first line `#FGBK\|4\|<model>\|<maj>\|<min>\|<build>\|`, then gzip+AES-GCM blob (cyber.wtf 2024-06-13, **3rd-party, unverified**) | KB; https://cyber.wtf (3rd-party) |
| 8.0.1 `encrypted` / `secrypt` / `obfuscated` modes. Before 8.0.1, unpassworded backups encrypted secrets with a static key | NF-8.0.0 "Encrypted configuration export (8.0.1)" https://docs.fortinet.com/document/fortigate/8.0.0/new-features/241169/encrypted-configuration-export-8-0-1; AG-8.0.1 p4516–4520 |
| secrypt: "Passwords, certificates, etc. will be encrypted with the password of your choosing". On-disk token for secrypt values *undocumented* | AG-8.0.1 p4517 |
| obfuscated / masked: values replaced by `FortinetPasswordMask` (examples: `set password`, `old-password`, `private-key`, `psksecret`, `passphrase`). Cannot be restored | AG-8.0.1 p4519; AG-7.6.7 p4092–4093 |
| YAML export (`.yaml`) | AG-8.0.1 p4518 ("FortiOS or YAML format") |
| `private-data-encryption enable`: secrets encrypted with a random (TPM) or user master key, AES128-CBC. Backup can't be restored on another unit without the key. `#private-encryption-key=` header seen in example | AG-8.0.1 p4268–4270 https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/893277/trusted-platform-module-support; AG TPM-VM example above; **KB** "restore backup with private-data-encryption" (community.fortinet.com article id 97515; full URL not recorded; 32-hex key) |
| Per-secret `ENC <blob>` | AG-8.0.1 p426 `set password ENC XXXX…`, p3207/p3237/p3239 `set psksecret ENC <encrypted key>`; **KB** "Password Recovery when a backup file exists" (community.fortinet.com id 167411: `set password ENC SH2…` admin hash) |
| SCP encrypted backup (8.0.0): `scp -OT admin@<FGT>:encrypted-config:<password> <dst>` | RN-8.0.0 p17 (bug 1252864) |
| `execute backup config ftp/scp/sftp/tftp` "removed in version 8.0.1" (CLI ref). AG-8.0.1 multi-VDOM topic still shows it → **conflict** | CLI-8.0.1 p4071+; AG-8.0.1 p4285–4288 |

**Safe to read:** algorithm and option tokens, certificate *names*, and public PEM certificates (`vpn certificate ca/remote/local certificate`). **Never emit:** values of CLI type `password`, `password-2`, `password-3` (e.g. `psksecret`, `ppk-secret`, `password`, `passphrase`, `key`, `sae-password`, `api-key`), `private-key`, or `ENC` blobs. Emit only presence (and state=masked/encrypted).

### 1.5 OSS parsers (licenses verified from repo LICENSE files via GitHub API, 2026-10-11)
| Project | What | License (file) | Notes |
|---|---|---|---|
| batfish/batfish | FortiOS ANTLR4 grammar (FortiosLexer.g4, FortiosParser.g4, Fortios_*.g4) | Apache-2.0 (LICENSE) | No vpn/certificate/VDOM coverage. Best quoting reference |
| netdevops/hier_config | hierarchical config lib with `platforms/fortinet_fortios` driver | MIT (LICENSE) | Text-tree diffing |
| ariel-anieli/chexit | Go "FortiGate configuration parser" | Apache-2.0 (LICENSE.md) | Small, 0★ |
| deyixtan-archive/fortigate-config-parser | Python CLI parser | MIT (LICENSE) | Archived 2018 |
| zcook04/fortigate_config_parser | `show full-configuration` → dict | MIT (LICENSE) | |
| Cn33liz/FortiParse | Python parser | BSD-3-Clause (LICENSE) | 2016 |
| ornulfn/PSFortigateParser | PowerShell → CSV | BSD-3-Clause (LICENSE) | |
| jnmeurisse/fgtparser | Python parser | GPL-3.0 (LICENSE) | copyleft |
| acidjunk/fortigate-config-parser | Python | GPL-3.0 | copyleft |
| Fatal-Halt/FortiGate-Config-Parser | Python | GPL-2.0 (API metadata only; file not opened) | copyleft |
| mpenning/ciscoconfparse, ciscoconfparse2 | generic brace/indent parsers | GPL-3.0 (LICENSE) | copyleft. FortiOS syntax support *not verified* |
| fortinet-solutions-cse/fortiosapi | REST API client (not a text parser) | Apache-2.0 | |
| PyFortiAPI/PyFortiAPI (was jsimpso) | REST client | MIT (LICENSE.txt) | |
| vladimirs-git/fortigate-api | REST client | Apache-2.0 (LICENSE.txt) | |
| fortinet-ansible-dev/ansible-galaxy-fortios-collection | Ansible modules (per-version field schemas) | GPL-3.0 | copyleft. Useful as field reference only |
| fortinetdev/terraform-provider-fortios | Terraform provider (field schemas) | MPL-2.0 | file-level copyleft |
| napalm-automation-community/napalm-fortios | NAPALM driver | Apache-2.0 | |

---

## 2–3. Crypto fields, values, defaults, CBOM mapping

CBOM column uses CDX-1.6 field names only. "alg-ref" = bom-ref of a component with `type: cryptographic-asset`, `cryptoProperties.assetType: algorithm`. "props" = `component.properties[{name,value}]` (free-form. No 1.6 field exists).

### 3.1 `config system global` (339914554/config-system-global): CLI-7.4.12 p1552–1592, CLI-7.6.7 p1549–1592, CLI-8.0.1 p1599–1642
| Field | Values | Default 7.4.12 / 7.6 / 8.0.1 | CBOM 1.6 mapping |
|---|---|---|---|
| admin-https-ssl-versions | tlsv1-1 tlsv1-2 tlsv1-3 | `tlsv1-2 tlsv1-3` (all) | protocol component (admin HTTPS): protocolProperties.type=`tls`, version per enabled version (one component per version or comma list) |
| admin-https-ssl-ciphersuites (TLS1.3) | TLS-AES-128-GCM-SHA256, TLS-AES-256-GCM-SHA384, TLS-CHACHA20-POLY1305-SHA256, TLS-AES-128-CCM-SHA256, TLS-AES-128-CCM-8-SHA256 | first three (all) | protocolProperties.cipherSuites[].name / .algorithms (alg-refs) / .identifiers |
| admin-https-ssl-banned-ciphers (TLS≤1.2) | RSA DHE ECDHE DSS ECDSA AES AESGCM CAMELLIA 3DES SHA1 SHA256 SHA384 STATIC CHACHA20 ARIA AESCCM | empty (all) | subtract from TLS1.2 suite list (suite list itself = AG table, §3.1a) |
| strong-crypto | enable/disable | enable (all) | modifies effective suites/algos (see 3.1a). props |
| ssl-min-proto-version (FortiGate-wide default for many TLS clients/servers) | SSLv3 TLSv1 TLSv1-1 TLSv1-2 TLSv1-3 | TLSv1-2 (all) | used where a section says `ssl-min-proto-version default` |
| ssl-static-key-ciphers | enable/disable | enable (all, incl. 7.4.12 p1586) | if disable: remove TLS_RSA_*, TLS_DH_*, TLS_ECDH_* suites |
| dh-params | 1024 1536 2048 3072 4096 6144 8192 | 2048 (all) | alg (FFDH, key-agree) parameterSetIdentifier=bits |
| admin-server-cert | cert name | Fortinet_GUI_Server (all) | certificate component ref (cryptoRefArray of TLS protocol) |
| admin-ssh-v1 | enable/disable | disable | ssh protocol version "1" if enable |
| admin-ssh-password | enable/disable | enable | props |
| admin-telnet / admin-scp | enable/disable | enable / disable | props (cleartext admin) |
| auth-cert | cert name | Fortinet_Factory ** | certificate ref |
| private-data-encryption | enable/disable | disable | if enable: secrets unreadable. Flag |
| scim-server-cert | cert | — / Fortinet_Factory (7.6.3+) / Fortinet_Factory ** | certificate ref |
| tls-session-cache | enable/disable | — / enable (7.6.3+) / enable | props |
| ipsec-asic-offload, ipsec-hmac-offload, ipsec-qat-offload | enable/disable | enable (all) | algorithmProperties.executionEnvironment=`hardware` (*semantics inferred*, props safer) |
| vdom-mode | no-vdom multi-vdom | no-vdom | parser mode |

**3.1a strong-crypto effects** (AG "FortiGate encryption algorithm cipher suites", AG-7.4.12/7.6.7/8.0.1, https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/484445/fortigate-encryption-algorithm-cipher-suites):
- "When strong encryption is enabled, only TLS 1.2 and TLS 1.3 are allowed. If strong encryption is then disabled, TLS 1.1 has to be manually enabled."
- Admin HTTPS suites footnoted "Disabled if strong-crypto enabled": AES256-GCM-SHA384, AES128-GCM-SHA256 (static RSA, TLS1.2), all TLS1.1 suites, TLS-AES-128-CCM-SHA256, TLS-AES-128-CCM-8-SHA256.
- SSH with strong-crypto enabled: enc = aes256-gcm@openssh.com, aes256-ctr; hsk = ecdsa-sha2-nistp521/384/256, rsa-sha2-256/512, ssh-ed25519 (disabled adds ssh-rsa); kex = dh-group14-sha256, group16-sha512, group18-sha512, gex-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256/384/521 (disabled adds group14-sha1, gex-sha1); mac = hmac-sha2-256/512 (+etm).
- "strong-crypto … has no effect on the Agentless VPN [7.4: SSL VPN] encryption level or ciphers."
- `ssl-static-key-ciphers` topic (AG-7.6.7, AG-8.0.1. Absent from AG-7.4.12): applies to admin HTTPS, Agentless VPN, captive portal, FMG/FAZ comms, DoT/DoH. Not SSH, not SSL inspection, not FortiGate-as-client.
- SSL inspection: "Enabling strong-crypto in the global attributes sets the min-allowed-ssl-version to tls-1.1 by default." AG-8.0.1 p3045, AG-7.6.7 p2613, AG-7.4.12 p2167.

### 3.2 `config system ssh-config` (207795941/config-system-ssh-config): CLI-7.4.12 p2032–2033, CLI-7.6.7 p2051–2053, CLI-8.0.1 p2128–2131
| Field | Values | Default 7.4.12 / 7.6 / 8.0.1 | CBOM |
|---|---|---|---|
| ssh-enc-algo | chacha20-poly1305@openssh.com, aes128/192/256-ctr, arcfour256/128, aes128/192/256-cbc, 3des-cbc, blowfish-cbc, cast128-cbc, arcfour, rijndael-cbc@lysator.liu.se, aes128/256-gcm@openssh.com | `aes256-ctr aes256-gcm@openssh.com` (all) | protocol component type=`ssh`. cryptoRefArray → alg components (primitive block-cipher/ae, mode ctr/gcm/cbc) |
| ssh-kex-algo | dh-group1-sha1, group14-sha1, group14-sha256, group16-sha512, group18-sha512, gex-sha1, gex-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256/384/521, **mlkem768x25519-sha256 (8.0.1 only)** | group14-sha256 group16-sha512 group18-sha512 gex-sha256 curve25519-sha256@libssh.org ecdh-sha2-nistp256/384/521 (7.4.12, 7.6.x). **8.0.1 adds mlkem768x25519-sha256 to default** | cryptoRefArray → key-agree / kem alg components (hybrid: two refs or one "combiner") |
| ssh-mac-algo | hmac-md5, hmac-md5-96, hmac-sha1, hmac-sha2-256, hmac-sha2-512, hmac-ripemd160, umac-64/128 (+ -etm@openssh.com variants) | hmac-sha2-256(+etm), hmac-sha2-512(+etm) (all) | cryptoRefArray → mac alg |
| ssh-hsk-algo | ssh-rsa, ecdsa-sha2-nistp521/384/256, rsa-sha2-256, rsa-sha2-512, ssh-ed25519 | ecdsa-sha2-nistp521 nistp384 nistp256 rsa-sha2-256 rsa-sha2-512 ssh-ed25519 (all) | cryptoRefArray → signature alg |
| ssh-hsk-override | enable/disable | disable | — |
| ssh-hsk | PEM private host key (user) | empty | related-crypto-material type=`private-key` (presence only) |
| ssh-hsk-password | password | — | never emit |

Doc conflict: the AG strong-crypto SSH kex table omits mlkem768x25519-sha256, which CLI-8.0.1 lists in the default.

Exact tokens (the table above abbreviates them). Verified 2026-10-14 against the CLI HTML pages 207795941/config-system-ssh-config for 7.4.12, 7.6.7, and 8.0.0; all three agree except for mlkem768x25519-sha256:
- ssh-enc-algo options: `chacha20-poly1305@openssh.com aes128-ctr aes192-ctr aes256-ctr arcfour256 arcfour128 aes128-cbc 3des-cbc blowfish-cbc cast128-cbc aes192-cbc aes256-cbc arcfour rijndael-cbc@lysator.liu.se aes128-gcm@openssh.com aes256-gcm@openssh.com`. Default `aes256-ctr aes256-gcm@openssh.com`.
- ssh-kex-algo options: `diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group14-sha256 diffie-hellman-group16-sha512 diffie-hellman-group18-sha512 diffie-hellman-group-exchange-sha1 diffie-hellman-group-exchange-sha256 curve25519-sha256@libssh.org ecdh-sha2-nistp256 ecdh-sha2-nistp384 ecdh-sha2-nistp521`, plus `mlkem768x25519-sha256` on the 8.0 page. Default `diffie-hellman-group14-sha256 diffie-hellman-group16-sha512 diffie-hellman-group18-sha512 diffie-hellman-group-exchange-sha256 curve25519-sha256@libssh.org ecdh-sha2-nistp256 ecdh-sha2-nistp384 ecdh-sha2-nistp521`, with `mlkem768x25519-sha256` appended on the 8.0 page.
- ssh-mac-algo options: `hmac-md5 hmac-md5-etm@openssh.com hmac-md5-96 hmac-md5-96-etm@openssh.com hmac-sha1 hmac-sha1-etm@openssh.com hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com hmac-ripemd160 hmac-ripemd160@openssh.com hmac-ripemd160-etm@openssh.com umac-64@openssh.com umac-128@openssh.com umac-64-etm@openssh.com umac-128-etm@openssh.com`. Default `hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com`.
- ssh-hsk-algo options: `ssh-rsa ecdsa-sha2-nistp521 ecdsa-sha2-nistp384 ecdsa-sha2-nistp256 rsa-sha2-256 rsa-sha2-512 ssh-ed25519`. Default `ecdsa-sha2-nistp521 ecdsa-sha2-nistp384 ecdsa-sha2-nistp256 rsa-sha2-256 rsa-sha2-512 ssh-ed25519`.

The same check on 339914554/config-system-global confirmed the §3.1 tokens and defaults for admin-https-ssl-versions, admin-https-ssl-ciphersuites, admin-https-ssl-banned-ciphers (no default), and admin-server-cert in all three versions. strong-crypto and ssl-static-key-ciphers were not in the fetched part of that page; their defaults above come from the CLI PDF pages cited in §3.1.

### 3.3 `config vpn ipsec phase1-interface` (305883427) and `phase1` (574570212)
Pages: phase1-interface CLI-7.4.12 p2239–2265, CLI-7.6.3 p2187–2219, CLI-7.6.7 p2286–2318, CLI-8.0.1 p2411–2443. phase1 CLI-7.4.12 p2213+, CLI-7.6.7 p2253+, CLI-8.0.1 p2378+. The fields below are identical in both tables unless noted.
| Field | Values | Default 7.4.12 / 7.6 / 8.0.1 | CBOM |
|---|---|---|---|
| ike-version | 1, 2 | **1 / 1 / 2** | protocol component type=`ike`, version=`1`/`2`. RN-8.0.0 p23 (bug 1115026): new CLI VPNs default IKEv2. "Upgrading from previous version will not change the IKE version" |
| proposal | {des,3des,aes128,aes192,aes256,aria128,aria192,aria256,seed}-{md5,sha1,sha256,sha384,sha512}; {aes128gcm,aes256gcm,chacha20poly1305}-prf{sha1,sha256,sha384,sha512}; sm4-sm3 (8.0.1 only) | **CLI ref: empty/undocumented (unknown)**. RN-8.0.0 p24 (bug 1182788): "Remove xxx-SHA1 from default proposal" | IKEv2: ikev2TransformTypes.encr (cipher), .integ (hash→HMAC), .prf (prfshaX or hash for non-AEAD). IKEv1: cryptoRefArray |
| dhgrp | 1 2 5 14 15 16 17 18 19 20 21 27 28 29 30 31 32 | **14 / 14 (7.6.3, 7.6.4) → `20 **` (7.6.5, 7.6.6) → 20 (7.6.7) / 20** | ikev2TransformTypes.ke (alg-refs). Group→algorithm per IANA IKEv2 registry (not in Fortinet docs): 1 MODP768, 2 MODP1024, 5 MODP1536, 14 MODP2048, 15 MODP3072, 16 MODP4096, 17 MODP6144, 18 MODP8192, 19 ECP256, 20 ECP384, 21 ECP521, 27–30 brainpoolP224r1/256r1/384r1/512r1, 31 Curve25519, 32 Curve448 |
| addke1 … addke7 | **absent 7.4.12**. 7.6.3–7.6.6 numeric: 0, 35, 36, 37, 1080–1085, 1089–1094. 7.6.7 & 8.0.1 named: none, ml-kem-512, ml-kem-768, ml-kem-1024, kyber512/768/1024, frodo-l1/l3/l5, bike-l1/l3/l5, hqc128/192/256. Up to 3 per round, 7 rounds | empty | ikev2TransformTypes.ke has no per-round slot in 1.6 (title says "Transform Type 4 … per RFC 9370"). Emit alg components (primitive=`kem`, parameterSetIdentifier e.g. `768`, nistQuantumSecurityLevel 1/3/5 for ML-KEM-512/768/1024 per FIPS 203) referenced from ke, plus props `addkeN` |
| numeric↔name map (7.6.3–7.6.6 desc) | 35 ML-KEM-512, 36 ML-KEM-768, 37 ML-KEM-1024, 1080/1081/1082 KYBER512/768/1024, 1083/1084/1085 FRODO L1/L3/L5, 1089/1090/1091 BIKE L1/L3/L5, 1092/1093/1094 HQC128/192/256 | — | CLI-7.6.3 p2187; CLI-7.6.6 p2268 |
| childless-ike | enable/disable | disable | props (required for addke per AG) |
| authmethod / authmethod-remote | psk, signature | psk | ikev2TransformTypes.auth → alg (PSK = related-crypto-material; signature → signature alg) |
| psksecret, psksecret-remote | password-3 | — | related-crypto-material type=`secret-key` (presence/masked/ENC only) |
| certificate | local cert name(s) | — | certificate ref |
| digital-signature-auth | enable/disable | disable | RFC 7427 auth (props) |
| signature-hash-alg | sha1 sha2-256 sha2-384 sha2-512 (+identity 8.0.1) | **sha2-512 / sha2-512 / identity** | alg-ref (hash) in auth |
| rsa-signature-format | pkcs1, pss | pkcs1 | algorithmProperties.padding=`pkcs1v15` / `other`(PSS) |
| rsa-signature-hash-override | enable/disable | disable | props |
| keylife | 120–172800 s | 86400 | props |
| mode | main, aggressive | main | props (IKEv1) |
| peertype | any, one, dialup, peer, peergrp | peer | — |
| localid-type | auto, fqdn, user-fqdn, keyid, address, asn1dn | auto | — |
| cert-trust-store | local, ems | local | — |
| cert-id-validation | enable/disable | enable | props |
| send-cert-chain | enable/disable | enable | — |
| transport | udp, udp-fallback-tcp (7.4.12) / auto, tcp | **udp / auto / udp** | props |
| ppk | disable, allow, require | disable (all) | related-crypto-material type=`secret-key` for ppk-secret. props (RFC 8784) |
| ppk-identity / ppk-secret | string / password-3 | — | presence only |
| qkd | disable, allow, require | disable (all) | props. qkd-profile → `vpn qkd` |
| qkd-hybrid | enable/disable | — / disable (7.6.3+) / disable | props |
| eap, xauthtype, group-authentication-secret | … | — | secret presence only |

`config system settings` → `ike-proposal-visibility {recommended\|all}` default `recommended` (**8.0.1 only**, CLI-8.0.1 p2089; RN-8.0.0 bug 1233077). Under `recommended` the CLI shows only DH 15–21, 28–32 ("1,2,5,14,27 are hidden"), encryption AES128/192/256-CBC, AES128/256-GCM, CHACHA20POLY1305, and auth SHA256/384/512 (AG-8.0.1 p3126 in "Phase 1 configuration" https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/790613/phase-1-configuration). This is display-only. Hidden values can still appear in backups (*inferred*).

### 3.4 `config vpn ipsec phase2-interface` (252893715) / `phase2` (143662319): CLI-7.6.7 p2334–2344, CLI-8.0.1 p2458–2469
| Field | Values | Default 7.4.12 / 7.6 / 8.0.1 | CBOM |
|---|---|---|---|
| proposal | {null,des,3des,aes128,aes192,aes256,aria128,aria192,aria256,seed}-{null,md5,sha1,sha256,sha384,sha512}; aes128gcm, aes256gcm, chacha20poly1305; sm4-sm3 (8.0.1) | undocumented (unknown). RN-8.0.0: SHA1 removed from default | protocol type=`ipsec` (ESP): ikev2TransformTypes.encr/.integ/.esn |
| pfs | enable/disable | enable | if enable, dhgrp → ke |
| dhgrp | same as phase1 | 14 / 14→20 (as phase1) / 20 | ikev2TransformTypes.ke |
| addke1…7 | as phase1 (7.6.3+) | empty | as phase1 |
| keylife-type / keylifeseconds / keylifekbs | seconds/kbs/both; 120–172800; 5120–4294967295 | seconds / 43200 / 5120 | props |
| replay | enable/disable | enable | props |
| encapsulation | tunnel-mode, transport-mode | tunnel-mode | props |

### 3.5 `config vpn ipsec manualkey` (302168624) / `manualkey-interface` (263813893): CLI-8.0.1 p2370+
authentication `null md5 sha1 sha256 sha384 sha512` (default null). encryption `null des 3des aes128 aes192 aes256 aria128 aria192 aria256 seed` (default null). authkey/enckey (manualkey-interface: auth-alg, enc-alg, auth-key, enc-key) = secret keys → related-crypto-material `secret-key` (presence only). Protocol type=`ipsec`.

### 3.6 `config vpn qkd` (304582863): CLI-8.0.1 p2476
server, port, id, peer, certificate. → props + certificate ref. Present 7.4.12+ (CLI-7.4.12 TOC).

### 3.7 `config vpn ssl settings` (114404382; "Agentless VPN" in 7.6+): CLI-7.4.12 p2294–2305, CLI-7.6.7 p2354–2364, CLI-8.0.1 p2479–2489
| Field | Values | Default 7.4.12 / 7.6 / 8.0.1 | CBOM |
|---|---|---|---|
| algorithm | high, medium, default, low | high | AG: high = AES+ChaCha, medium adds 3DES/RC4, low adds DES |
| banned-cipher | RSA DHE ECDHE DSS ECDSA AES AESGCM CAMELLIA 3DES SHA1 SHA256 SHA384 STATIC CHACHA20 ARIA AESCCM | `SHA1 SHA256 SHA384` | filter cipherSuites |
| ciphersuite (TLS1.3) | the 5 TLS1.3 names | first three | cipherSuites[] |
| ssl-min-proto-ver / ssl-max-proto-ver | tls1-0 tls1-1 tls1-2 tls1-3 | tls1-2 / tls1-3 | protocol type=`tls`, version |
| tls-groups | P-521 P-384 P-256 ML-KEM512 ML-KEM768 ML-KEM1024 P-384-MLKEM1024 P-256-MLKEM768 X25519-MLKEM768 X448 X25519 FFDHE2048/3072/4096/6144/8192 | — / **7.6.5+**: `P-521 P-384 ML-KEM768 ML-KEM1024 P-384-MLKEM1024 P-256-MLKEM768 X25519-MLKEM768 X448 FFDHE4096 FFDHE6144 FFDHE8192` / same | no 1.6 field. cryptoRefArray → key-agree/kem alg components (1.7 adds cipherSuite.tlsGroups) |
| client-sigalgs | no-rsa-pss, all | all | props |
| servercert | cert name | empty | certificate ref |
| reqclientcert | enable/disable | disable | props |
| ssl-client-renegotiation | enable/disable | disable | props |
| remote-https-cert-check | no-check warn-on-error reject-on-error | — / warn-on-error (7.6.5+) / same | props |
| dtls-min-proto-ver / dtls-max-proto-ver / dtls-tunnel | dtls1-0 dtls1-2 / enable | dtls1-0 / dtls1-2 / enable — **7.4.12 only** | protocol `tls` (DTLS) version |
"No option" for PQC on FIPS-CC: PQC groups unavailable in FIPS-CC mode (NF-7.6.0 p611–612. AG-8.0.1 https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/43632/post-quantum-cryptography-for-agentless-vpn).

### 3.8 Certificates
`config vpn certificate local` (556354036): CLI-7.4.12 p2190–2194, CLI-8.0.1 p2353–2357. Same fields under `config certificate local` (254051044, CLI-7.6.7 p234+, CLI-8.0.1 p263).
| Field | Values | Default | CBOM |
|---|---|---|---|
| certificate | PEM (multi-line quoted) | — | assetType=`certificate`: parse X.509 → certificateProperties.subjectName, issuerName, notValidBefore, notValidAfter, signatureAlgorithmRef, subjectPublicKeyRef, certificateFormat=`X.509`. Key alg/size come only from parsed PEM: **no key-type/size config field** |
| private-key | PEM / ENC / FortinetPasswordMask | — | related-crypto-material type=`private-key`. Presence only. Size from cert SPKI |
| password | password | — | never emit |
| source | factory, user, bundle | user | props |
| range | global, vdom | vdom | props |
| enroll-protocol | none scep cmpv2 acme2 est | none | props |
| acme-rsa-key-size | 2048–4096 | 2048 | alg (RSA) parameterSetIdentifier if ACME |
| auto-regenerate-days, acme-renew-window | int | 0 / 30 | props |
| ike-localid-type | asn1dn, fqdn | asn1dn | — |
`vpn certificate ca` (144962638): ca (PEM), range, source, ssl-inspection-trusted (enable), auto-update-days, est-url, scep-url, obsolete → certificate components. `vpn certificate remote` (260190803): remote (PEM), range, source. `vpn certificate crl` (408996217): crl, http-url, ldap-*, scep-cert (Fortinet_CA_SSL), update-interval. `vpn certificate ocsp-server` (251248056): url, cert, secondary-*, unavail-action (revoke).
`vpn certificate hsm-local` (158463666, **7.6.3+**): vendor gch, gch-cryptokey-algorithm {rsa-sign-pkcs1-2048-sha256 (default), …-3072/4096-sha256, …-4096-sha512, rsa-sign-pss-…, ec-sign-p256-sha256, ec-sign-p384-sha384, ec-sign-secp256k1-sha256}, certificate (PEM) → algorithmProperties.executionEnvironment=`hardware`.
`vpn certificate setting` (211164210): certname-rsa1024/2048/4096, certname-dsa1024/2048, certname-ecdsa256/384/521, certname-ed25519/ed448, **certname-mldsa44/65/87 (8.0.1 only, defaults Fortinet_SSL_MLDSA44/65/87)**, ssl-min-proto-version (default `default`), cert-expire-warning 14, check-ca-cert, crl-verification.
`firewall ssh local-key` (739950788) / `local-ca` (228835467), CLI-8.0.1 p654: password, private-key, public-key, source {built-in, user}, default user → related-crypto-material private-key/public-key.

### 3.9 `config firewall ssl-ssh-profile` (116695140): CLI-7.4.12 p662–686, CLI-7.6.7 p662–686, CLI-8.0.1 p665–693
| Field | Values | Default 7.4.12 / 7.6 / 8.0.1 | CBOM |
|---|---|---|---|
| caname / untrusted-caname | cert | Fortinet_CA_SSL / Fortinet_CA_Untrusted | certificate refs (re-sign CA) |
| server-cert-mode | re-sign, replace | re-sign | props |
| supported-alpn | http1-1 http2 all none | all | props |
| {ssl,https,ftps,imaps,pop3s,smtps,dot}/min-allowed-ssl-version | ssl-3.0 tls-1.0 tls-1.1 tls-1.2 tls-1.3 | tls-1.1 (all). No max field | protocol type=`tls`, version floor |
| …/unsupported-ssl-version | allow, block | block | props |
| …/unsupported-ssl-cipher | allow, block | allow | props |
| …/encrypted-client-hello (https, ssl) | allow, block | block | props |
| https,ssl/cert-probe-failure | allow, block | **block / allow / allow** | props |
| https,dot/udp-not-quic | allow, block | — / allow (7.6.3+) / **block** | props |
| {ssl,https,ftps,dot}/tls-handshake-mode | sync, dual | — / — / sync (**8.0.1**) | props (PQC-classical translation) |
| ssh/ssh-algorithm | compatible, high-encryption | compatible | props |
No tls-groups/PQC field. Hybrid PQC inspection is automatic (§4).

### 3.10 `config firewall vip` (939799654) SSL offload: CLI-8.0.1 p703–734
ssl-algorithm {high medium low custom} default high. ssl-min-version default tls-1.1, ssl-max-version tls-1.3. ssl-pfs {require deny allow} default require. ssl-dh-bits 768–4096 default 2048. ssl-mode half/full. ssl-server-algorithm default client. ssl-server-min/max-version default client. ssl-certificate. `config ssl-cipher-suites` / cipher + versions: versions default **`ssl-3.0 tls-1.0 tls-1.1 tls-1.2 tls-1.3` (≤7.6.6) → `tls-1.1 tls-1.2 tls-1.3` (7.6.7, 8.0.1)**. ssl-accept-ffdhe-groups enable. ssl-client-renegotiation secure. → protocol `tls` + cipherSuites + certificate ref.

### 3.11 `config firewall access-proxy` (279706760) and `ztna web-proxy` (178817078)
access-proxy: CLI-7.4.12 p355–387, CLI-7.6.7 p379–410. **Absent from CLI-8.0.1 PDF and 8.0.0 HTML TOC**, but used in AG-8.0.1 p536, p1870 → doc conflict. api-gateway(/api-gateway6): ssl-algorithm high, ssl-dh-bits 2048, ssl-min-version tls-1.1, ssl-max-version tls-1.3, ssl-renegotiation enable, ssl-cipher-suites/versions default `tls-1.0 tls-1.1 tls-1.2 tls-1.3`. realservers/verify-cert **disable (7.4.12, 7.6.3) → enable (7.6.4+)**. 7.4.12 also client-cert enable, empty-cert-action block.
ztna web-proxy (7.6.3+, CLI-8.0.1 p2950–2976): same api-gateway SSL fields and defaults. verify-cert disable (7.6.3) → enable (7.6.4+).
access-proxy-virtual-host: ssl-certificate, client-cert enable, empty-cert-action block (7.6.3+).
ztna service-connector (**8.0.1**, p2930–2932): certificate, encryption (default disable. Change history: enable→disable), ssl-min-version tls-1.1, ssl-max-version tls-1.2.

### 3.12 Other TLS/crypto-bearing sections (CLI-8.0.1 pages. All present 7.4.12+ unless noted)
| Section (id) | Fields → defaults | CBOM |
|---|---|---|
| system admin (390485493) | password (password-2), ssh-public-key1/2/3, ssh-certificate, peer-auth disable | credential presence. public keys → public-key |
| system api-user (625450553) | api-key (password-2) | `token` presence |
| system snmp user (292257317) p2116–2123 | auth-proto md5 sha sha224 sha256 sha384 sha512 (default sha). priv-proto aes des aes256 aes256cisco (default aes). security-level default no-auth-no-priv | protocol type=`other` (SNMPv3) + mac/cipher alg refs |
| log fortianalyzer setting (269170403) p869–871 | enc-algorithm high-medium high low (default high). hmac-algorithm sha256. ssl-min-proto-version default. certificate-verification enable. preshared-key | tls |
| log syslogd setting (141516630) p962–964 | enc-algorithm high-medium high low disable (default **disable**). mode udp (default) / legacy-reliable / reliable. ssl-min-proto-version default | tls only if reliable+enc |
| system central-management (327901742) p1477 | enc-algorithm default high low (default high). ca-cert, local-cert | tls |
| system ha (857448677) p1650–1654 | authentication disable, encryption disable, key | props |
| system fortiguard (256936931) | protocol udp http https (default https) | tls |
| system fortisandbox (532438794) | enc-algorithm default, ssl-min-proto-version default. certificate-verification enable (7.6.3) → disable (7.6.4+) | tls |
| user ldap (590785459) | secure disable starttls ldaps (default disable). ssl-min-proto-version default. ca-cert, client-cert. pqc-policy (8.0.1, default enable) | tls |
| user radius (164332072) | transport-protocol udp tcp tls (default udp). tls-min-proto-version default. require-message-authenticator enable. pqc-policy (8.0.1) | tls/other |
| user setting (263822197) | auth-ssl-min/max-proto-version, auth-ssl-sigalgs. auth-secure-http disable→**enable (8.0.1)**. auth-type → **http (8.0.1)** (RN-8.0.0 bug 1230185: new deployments only) | tls |
| system dns (190194324) | protocol cleartext dot doh (default cleartext). ssl-certificate Fortinet_Factory. cert-verify (8.0.1) | tls |
| system ntp (105110478) | key-type MD5 SHA1 SHA256 (+AES128 8.0.1. 8.0.1 moves keys into `config keys`) | mac alg |
| system password-policy (127236326) | minimum-length 8→12 and min-* 0→1 at 7.6.5 | props |
| system csf (120351875) | 8.0.1: authorization-request-type serial→certificate, certificate ''→Fortinet_Factory | props |
| wireless-controller vap (304313044) CLI-7.4.12 p2553–2576, CLI-8.0.1 p2747–2771 | security {open wep64 wep128 wpa-personal wpa-enterprise wpa-only-personal wpa-only-enterprise wpa2-only-personal (default) wpa2-only-enterprise wpa3-enterprise wpa3-only-enterprise wpa3-enterprise-transition wpa3-sae wpa3-sae-transition owe osen}. encrypt TKIP AES TKIP-AES (default AES). pmf disable enable optional (default disable). sae-groups / owe-groups 19 20 21 (default empty). beacon-protection disable. passphrase, sae-password, key (secrets). keyindex 1 | protocol type=`wpa` |

---

## 4. PQC features: exact CLI
| Feature | Version | CLI | Source |
|---|---|---|---|
| IKEv2 multiple KE (RFC 9370, IKE_INTERMEDIATE RFC 9242, IKE_FOLLOWUP_KE) | 7.6.1+ (fields in CLI-7.6.3+. Absent 7.4.12) | phase1-interface/phase2-interface `set addke1..7 <≤3 tokens>`; `set childless-ike enable` | NF-7.6.0 p570–574; AG-8.0.1 p3184–3190 https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/229631/post-quantum-cryptography-for-ipsec-key-exchange |
| addke token form | numeric (7.6.3–7.6.6 CLI ref) → names (7.6.7, 8.0.1 CLI ref). **AG-8.0.1 p3188 still shows numeric** `set addke1 35 36 37`, `set addke2 1083`, phase2 `set addke1 1090` | — | conflict |
| Only ML-KEM-512/768/1024 are FIPS 203. Kyber/FRODO/BIKE/HQC also selectable | AG-8.0.1 p3184 | | |
| QKD (ETSI GS QKD 014) | 7.4.12+ | phase1 `set qkd {disable\|allow\|require}`, `set qkd-profile <vpn qkd>`; `config vpn qkd` server/port/id/peer/certificate | AG-7.6.7 https://docs.fortinet.com/document/fortigate/7.6.7/administration-guide/775314/ipsec-key-retrieval-with-a-qkd-system |
| QKD + PQC hybrid | 7.6.3+ | `set qkd-hybrid enable` | NF-7.6.0 p606; AG-7.6.7 https://docs.fortinet.com/document/fortigate/7.6.7/administration-guide/249519/applying-hybrid-qkd-and-pqc-in-ipsec-key-establishment |
| PPK (RFC 8784) | fields present 7.4.12+ | `set ppk {disable\|allow\|require}`, `set ppk-identity`, `set ppk-secret`. user local `ppk-secret` for dial-up | AG-8.0.1 p3202–3207 https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/527690/post-quantum-preshared-key-support |
| PQC signature auth (RFC 7427, ML-DSA FIPS 204, SLH-DSA FIPS 205) + RFC 8420 identity | 8.0.1 | `set authmethod signature`, `set digital-signature-auth enable`, `set signature-hash-alg identity` (8.0.1 default) | NF-8.0.0 p574–577; AG-8.0.1 https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/316673/signature-authentication-for-vpns-using-post-quantum-cryptography; RN-8.0.0 p55 |
| ML-DSA local certs | 8.0.1 | vpn certificate setting `certname-mldsa44/65/87` | CLI-8.0.1 |
| Agentless VPN TLS PQC (OpenSSL 3.5) | 7.6.5+ | `config vpn ssl settings` / `set tls-groups …` | NF-7.6.0 p611–612; AG-7.6.7 p3308–3310 |
| Admin HTTPS PQC | 7.6.5+ | **No CLI option**: "There is no option in CLI to specify TLS group(s) for admin GUI connection". Auto-negotiates X25519MLKEM768 and ML-DSA-65 server auth | NF-7.6.0 p886; AG-8.0.1 https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/980825/https-management-and-post-quantum-tls-algorithms |
| SSL deep inspection hybrid PQC | flow mode 7.6.5. Proxy mode 8.0.0 | No CLI field. Groups X25519MLKEM768 (0x11EC), SecP256r1MLKEM768 (0x11EB), SecP384r1MLKEM1024 (0x11ED). Pure MLKEM512/768/1024 listed as "0x1302" (**doc error**: IANA 0x0200/0x0201/0x0202) | NF-7.6.0 p546; NF-8.0.0 p424; AG-8.0.1 p3066 https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/771310/post-quantum-cryptography-support-in-ssl-deep-inspection |
| PQC↔classical translation | 8.0.1 | ssl-ssh-profile `{ssl,https,ftps,dot}` `set tls-handshake-mode {sync\|dual}` | NF-8.0.0 p458; AG-8.0.1 https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/338552/pqc-classical-tls-key-exchange-translation-support-in-proxy-mode-ssl-deep-inspection-new |
| ML-DSA-44/65/87 TLS auth in flow-mode deep inspection | 8.0.1 | none | NF-8.0.0 p468 |
| SSH PQ KEX | 8.0.1 | `ssh-kex-algo` token `mlkem768x25519-sha256` (in default) | CLI-8.0.1 p2129 |
| TLS pqc-policy for client connections | 8.0.1 | `set pqc-policy {enable\|disable}` (default enable) on user ldap, user radius, user pop3, user external-identity-provider | CLI-8.0.1 |
| ZTNA PQC | — | *no PQC-specific field found* in access-proxy / ztna web-proxy (7.4.12–8.0.1) | — |

Doc nit: AG-8.0.1 p3182 labels RFC 9242 "Hybrid Key Exchange". RFC 9242 is "Intermediate Exchange in IKEv2" and RFC 9370 is "Multiple Key Exchanges".

---

## 5. Encrypted and secret values: parser handling
1. Field types `password`, `password-2`, `password-3` in the CLI ref mark secrets. Values may be `ENC <base64>`, `FortinetPasswordMask`, or (on input) plaintext. Emit presence and `relatedCryptoMaterialProperties.type` only, never `value`.
2. `ENC` blob algorithm: official docs give none. KB TAC article (https://community.fortinet.com/fortigate-3/technical-tip-why-config-files-should-not-be-encrypted-when-requested-by-tac-187991, **KB**) says whole-file encryption is AES-GCM keyed to model+password. Do not decrypt (EULA/plan V18).
3. Detect and refuse: line 1 not starting `#config-version=` (e.g. `#FGBK|` per 3rd-party), YAML document, or `#private-encryption-key=` / private-data-encryption enable (secrets opaque). Report the scope as partial.
4. Secrypt-mode value token format is undocumented. Treat any unknown non-PEM value on secret fields as opaque.

## 6. License-clear sample configs
| Source | License (verified file) | Usefulness |
|---|---|---|
| batfish testconfigs (fortios/*) @540a4644 | Apache-2.0 | real-style syntax (replacemsg, accprofile, nested config). **No vpn/cert crypto** |
| fortinet/fortigate-terraform-deploy @aa319ee1 (e.g. `ibm/8.0/loadbalancer/config.conf`, `azure/8.0/single/fgtvm.conf`) | MIT (LICENSE, "Copyright 2019 Fortinet Inc.") | Fortinet-authored bootstrap snippets: no headers, no indentation, `${var}` placeholders, minimal crypto (`set psksecret ${preshare}`). Not backup format |
| fortinet/azure-templates @17334f5d, fortinet/aws-cloudformation-templates @ee1192b5 | MIT | IPsec/ZTNA snippets embedded in JSON/YAML/README |
| Fortinet docs examples | reference only (no license grant) | |
No permissively licensed *real* backup with crypto sections was found. Keep CC0 synthetic fixtures per version (7.4.12, 7.6.6-numeric-addke, 7.6.7-named-addke, 8.0.1).

## 7. FortiOS → CycloneDX 1.6 mapping (schema-verified field names)
CDX-1.6 cryptoProperties: assetType {algorithm, certificate, protocol, related-crypto-material}. algorithmProperties {primitive [drbg mac block-cipher stream-cipher signature hash pke xof kdf key-agree kem ae combiner other unknown], parameterSetIdentifier, curve, executionEnvironment, implementationPlatform, certificationLevel[], mode [cbc ecb ccm gcm cfb ofb ctr other unknown], padding [pkcs5 pkcs7 pkcs1v15 oaep raw other unknown], cryptoFunctions[], classicalSecurityLevel, nistQuantumSecurityLevel}. certificateProperties {subjectName, issuerName, notValidBefore, notValidAfter, signatureAlgorithmRef, subjectPublicKeyRef, certificateFormat, certificateExtension}. relatedCryptoMaterialProperties {type [private-key public-key secret-key key ciphertext signature digest initialization-vector nonce seed salt shared-secret tag additional-data password credential token other unknown], id, state, algorithmRef, creationDate, activationDate, updateDate, expirationDate, value, size, format, securedBy{mechanism, algorithmRef}}. protocolProperties {type [tls ssh ipsec ike sstp wpa other unknown], version, cipherSuites[{name, algorithms, identifiers}], ikev2TransformTypes{encr, prf, integ, ke, esn(boolean), auth}, cryptoRefArray}. oid. Component: type `cryptographic-asset`, `properties[{name,value}]`, `evidence.occurrences[{location, line, offset, symbol, additionalContext}]`.
| FortiOS | CDX 1.6 |
|---|---|
| phase1(-interface) edit | protocol: type `ike`, version `ike-version`; ikev2TransformTypes.encr/prf/integ from proposal; ke from dhgrp (+addke); auth from authmethod/signature-hash-alg |
| phase2(-interface) edit | protocol: type `ipsec`; ikev2TransformTypes.encr/integ (+ke when pfs) |
| aes128/192/256 (cbc) | algorithm primitive `block-cipher`, mode `cbc`, parameterSetIdentifier `128/192/256` |
| aes128gcm/aes256gcm | primitive `ae`, mode `gcm` |
| chacha20poly1305 | primitive `ae` |
| 3des/des | primitive `block-cipher`, mode `cbc` |
| md5/sha1/sha256… (integ) | primitive `mac` (HMAC); prfshaX → primitive `kdf` (*mapping choice*) |
| DH groups (MODP/ECP/brainpool/25519/448) | primitive `key-agree`, curve (ECP), parameterSetIdentifier (MODP bits) |
| ML-KEM-512/768/1024 | primitive `kem`, parameterSetIdentifier `512/768/1024`, nistQuantumSecurityLevel 1/3/5 (FIPS 203) |
| X25519-MLKEM768 etc. | primitive `combiner` with refs, or `kem` + props |
| ML-DSA-44/65/87 | primitive `signature`, nistQuantumSecurityLevel 2/3/5 (FIPS 204) |
| admin HTTPS / Agentless VPN / VIP / access-proxy / FAZ / LDAPS… | protocol type `tls`, version, cipherSuites[] (name = FortiOS token or IANA name; identifiers = IANA hex) |
| ssh-config | protocol type `ssh`, cryptoRefArray → enc/kex/mac/hsk algorithms |
| wireless vap | protocol type `wpa`, version from security token |
| SNMPv3, syslog-TLS, NTP keys | protocol type `other`/`tls` + props |
| vpn certificate local/ca/remote PEM | assetType `certificate` + certificateProperties (from PEM) |
| private-key, ssh-hsk, firewall ssh local-key | related-crypto-material `private-key` (no value) |
| psksecret, ppk-secret, manual keys | related-crypto-material `secret-key` (no value) |
| admin password, api-key | `password` / `token` (no value) |
| tls-groups (no 1.6 field) | cryptoRefArray + props. 1.7 adds cipherSuite.tlsGroups / tlsSignatureSchemes |
| addke rounds (no 1.6 field) | ke refs + props `fortios:addke<N>` |

## 8. Parser edge cases and gotchas
1. Omitted field = firmware default at the **config's** version (from `#config-version`), not the parser's. ike-version, dhgrp, signature-hash-alg, transport, vip cipher versions and udp-not-quic defaults all changed between 7.4.12, 7.6.x and 8.0.1. Upgrades keep old IKE version (RN-8.0.0). Standard backups omit most defaults (KB). `full` export includes them.
2. addke tokens: accept both numeric (7.6.3–7.6.6 docs, AG-8.0.1 examples) and named (7.6.7/8.0.1 CLI ref). The existing fixture uses numeric (valid for ≤7.6.6 docs only).
3. dhgrp default: 14 vs 20 vs "20 and 21" (see §9). Mark `default-source` in props.
4. Proposal default is undocumented. Don't infer; emit "unknown".
5. Quoted strings span lines (PEM, replacemsg buffers). Handle `\"`, `\'`, `\\`, `\ `. Single quotes have no escapes (Batfish). Bare `#` only begins a comment at line start.
6. `config` lines may carry multiple path tokens and quoted args (`config system replacemsg mail "partial"`, `config vpn ipsec phase1-interface`).
7. Same objects under two paths: `vpn certificate *` and `certificate *` (both in CLI ref 7.6.7/8.0.1).
8. VDOM: `config global` / `config vdom` / `edit <vdom>` wrappers. Phase1 and SSL settings are per-VDOM, ssh-config/system global are global. Track the VDOM in evidence.occurrences.additionalContext.
9. Hidden values under `ike-proposal-visibility recommended` (8.0.1) can still be stored. Do not validate against the "recommended" list.
10. 8.0.1 CLI ref drops `firewall access-proxy` although AG-8.0.1 uses it. Don't fail on unknown sections. Keep an allow-list of crypto paths and ignore the rest.
11. Model-dependent defaults (`**`), e.g. auth-cert, scim-server-cert. Mark them as model-dependent.
12. strong-crypto changes effective TLS/SSH sets without changing stored fields. Compute the "effective" set separately from the "configured" set.
13. Agentless VPN ignores strong-crypto. ssl-static-key-ciphers doesn't affect SSH/inspection.
14. Secrets: `ENC`, `FortinetPasswordMask`, secrypt (unknown token), private-data-encryption. Never output values.
15. Encrypted whole-file backup / YAML: refuse with a clear error.
16. Line endings may be CRLF (*inferred*, not documented). Strip `\r`. Input UTF-8 non-normalised (AG p87).
17. Very long lines (pac-file-data ≤256K, image-base64). Use a streaming tokenizer with no line-length cap.
18. `unset` lines and `set x ""` both mean empty. Distinguish empty from absent.
19. The FIPS-CC mode disables PQC TLS groups (Agentless VPN), so config may list groups that aren't effective.
20. Doc errors to not propagate: "0x1302" for pure ML-KEM, and RFC 9242 labelled "Hybrid".

## 9. Doc conflicts
| Topic | Conflict |
|---|---|
| phase1/phase2 dhgrp default | CLI-7.4.12/7.6.3/7.6.4: `14`. CLI-7.6.5/7.6.6: `20 **`. CLI-7.6.7/8.0.1: `20`. AG-7.6.7 p2676: "By default, FortiGate uses DH group 20 and 21". RN-8.0.0 p24 (bug 1182788): "Replace default DH groups 5 and 14 with 20 and 21 when configured from CLI" (implies old default 5 14, new 20 21, and change in 8.0.0, not 7.6.5) |
| proposal default | CLI ref: empty. RN-8.0.0: SHA1 removed from default (list not given) |
| addke tokens | numeric vs named (CLI-7.6.6 vs CLI-7.6.7). AG-8.0.1 examples numeric |
| SSH kex strong-crypto table | AG omits mlkem768x25519-sha256. CLI-8.0.1 default includes it |
| AG SSH enc table | "Enabled" lists only aes256-gcm/aes256-ctr. All others are listed under "Disabled", which looks like a formatting issue |
| firewall access-proxy | missing from CLI-8.0.1. Present in AG-8.0.1 |
| execute backup config | CLI-8.0.1: removed in 8.0.1. AG-8.0.1 multi-VDOM page still uses it |
| tls-groups default | omits P-256 and X25519 although both are options (CLI-7.6.5+): plausible but odd |
| Pure ML-KEM codepoints | NF-8.0.0/AG-8.0.1 "0x1302" vs IANA 0x0200–0x0202 |

## 10. Explicitly unverified / unknown
- Meaning of `opmode`, `vdom`, `#conf_file_ver`, `#global_vdom`, and whether `#private-encryption-key=` appears in every backup or only with private-data-encryption.
- CRLF vs LF. (The multi-VDOM full-backup layout is verified on 7.6.7 build 3704, §1.3.)
- Encrypted-backup magic `#FGBK|…` and AES-GCM details (3rd-party/KB only). The secrypt value token format. The `ENC` algorithm.
- Whether 7.6.7+/8.0.x firmware accepts or stores numeric addke values, or converts them to names (only docs checked, no device).
- IKE/ESP default proposal lists for every version.
- Whether `private-key` in backups is stored as encrypted PEM vs `ENC`.
- Precise definition of `standard` vs `full` export.
- 7.4.12 docs have no tls-groups/addke. Whether 7.4.x patches beyond 7.4.12 add them (none found. 7.4.13+ URLs redirect to 7.4.12).
- ciscoconfparse FortiOS support. Fatal-Halt license file (API metadata only).
- Mapping prfshaX → `kdf` and hybrid groups → `combiner` are design choices, not schema mandates.
- DH group → algorithm mapping is from the IANA IKEv2 registry (https://www.iana.org/assignments/ikev2-parameters), not from Fortinet docs (the CLI ref says only "DH Group N").
