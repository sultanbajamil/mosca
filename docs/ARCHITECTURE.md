# Architecture

MOSCA is a single Node.js package with no runtime dependencies. Every part of
the pipeline is a plain ES module with an explicit input and output, which is
what makes the tool auditable and the tests fast.

```
                     ┌──────────────────────────┐
  mosca.json ───────▶│ src/config.js            │
  .moscaignore ─────▶│ defaults, data classes   │
                     └────────────┬─────────────┘
                                  │ merged config
     ┌──────────────┬─────────────┼─────────────┬──────────────┐
     ▼              ▼             ▼             ▼              ▼
┌──────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────┐
│scan/     │ │scan/      │ │scan/      │ │scan/      │ │net/tls       │
│source    │ │config     │ │artifacts  │ │deps       │ │starttls      │
│148 rules │ │62 rules   │ │PEM/DER/JWK│ │8 lockfiles│ │quic / ikev2  │
│16 langs  │ │IaC/proxies│ │OpenSSH    │ │packages   │ │raw probes    │
└────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └──────┬───────┘
     │ findings    │ findings    │ findings    │ findings      │ endpoints
     └─────────────┴─────────────┼─────────────┴───────────────┘
                                 ▼
                     ┌──────────────────────────┐
                     │ analysis/risk.js         │
                     │ Mosca inequality, score, │
                     │ severity, QRI, effort,   │
                     │ roadmap                  │
                     └────────────┬─────────────┘
                                  │ analysis object
     ┌──────────────┬─────────────┼─────────────┬──────────────┐
     ▼              ▼             ▼             ▼              ▼
┌──────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────┐
│report/   │ │report/    │ │report/    │ │analysis/  │ │fix.js        │
│terminal  │ │cbom       │ │sarif      │ │compliance │ │patch +       │
│html      │ │CycloneDX  │ │SARIF      │ │4 standards│ │advisories    │
│mermaid   │ │1.6        │ │2.1.0      │ │           │ │              │
└──────────┘ └───────────┘ └───────────┘ └───────────┘ └──────────────┘
```

## Module map

| Path | Responsibility |
| --- | --- |
| `bin/mosca.js` | Executable shim; sets the process exit code |
| `src/cli.js` | Command grammar, output orchestration, exit codes |
| `src/index.js` | `scan()` pipeline and `exitCode()` |
| `src/config.js` | Defaults, scenarios, merge, data-class matching |
| `src/rules/algorithms.js` | 92-entry algorithm registry, aliases, replacements |
| `src/rules/source.js` | 148 source rules across 16 languages |
| `src/rules/config.js` | 62 rules for IaC, edge proxies, nginx, Apache, sshd, OpenSSL, Java, Kubernetes |
| `src/rules/crypto-packages.js` | Curated cryptographic package intelligence |
| `src/scan/source.js` | Walker integration, comment stripping, match → finding |
| `src/scan/constants.js` | Single-assignment constant propagation into crypto APIs |
| `src/scan/config.js` | Config-file detection and rule application |
| `src/scan/artifacts.js` | PEM, DER, JWK/JWKS, OpenSSH and `authorized_keys` metadata |
| `src/scan/deps.js` | Eight lockfile parsers and package → finding mapping |
| `src/net/clienthello.js` | Raw TLS ClientHello builder and ServerHello parser (TLS and QUIC) |
| `src/net/x509.js` | Dependency-free DER/X.509 parser |
| `src/net/x509-chain.js` | Chain classification, weakest link, long-lived roots, PQC projection |
| `src/net/tls.js` | Endpoint inspection, chain attachment and endpoint finding derivation |
| `src/net/ssh.js` | Raw RFC 4253 banner exchange, KEXINIT parser, SSH findings |
| `src/net/starttls.js` | SMTP, IMAP, POP3, PostgreSQL and LDAP STARTTLS upgrades |
| `src/net/quic.js` | RFC 9001 Initial packet protection and QUIC response parsing |
| `src/net/ikev2.js` | IKE_SA_INIT with RFC 9370 ADDKE transforms |
| `src/analysis/risk.js` | Mosca inequality, scoring, aggregates, unique-site effort, sensitivity, roadmap |
| `src/analysis/baseline.js` | Stable fingerprints, baseline build/load/apply, diff status |
| `src/analysis/compliance.js` | CNSA 2.0, NIST 2030, PCI DSS and HIPAA controls |
| `src/fix.js` | Fix planner, safe literal swaps, unified diff, advisories |
| `src/report/terminal.js` | ANSI terminal report |
| `src/report/html.js` | Self-contained interactive report, simulator and chain tree |
| `src/report/cbom.js` | CycloneDX 1.6 CBOM with library components |
| `src/report/sarif.js` | SARIF 2.1.0 with compliance properties |
| `src/report/mermaid.js` | Bounded risk, chain and dependency diagrams |
| `src/util/fs.js` | Walker, ignore rules, binary-safe reads, comment stripper |
| `src/util/log.js` | Colour, padding, score bars |

## Data flow

1. `cli.js` parses arguments and builds overrides.
2. `index.js` loads `mosca.json`, then runs the source scanner, the config
   scanner, the artefact scanner, the dependency scanner, and TLS, SSH,
   STARTTLS, QUIC and IKEv2 endpoint inspection. Network work is parallelised
   with `Promise.all`; one unreachable host never fails the scan.
3. Every scanner emits the same finding shape:

```js
{
  id, kind, title, algorithm, algorithmLabel, primitive,
  location: { file, line, column } | { host, port, target },
  snippet, matched, confidence, note, language?, evidence?
}
```

4. `analysis/risk.js` enriches each finding with the registry entry, shelf
   life, migration lead time, the inequality string, score, severity, priority
   and a primitive-aware replacement. It then aggregates.
5. Reporters consume the same `analysis` object. They do not recompute risk,
   so the terminal, HTML, CBOM, SARIF and Mermaid cannot disagree. The
   compliance engine runs over the enriched analysis before reporting; `fix.js`
   consumes the same items to build its plan.
6. `cli.js` writes artefacts and returns an exit code derived from
   `--fail-on` and, when requested, `--fail-on-compliance`.

## The raw TLS probe

This is the part that distinguishes MOSCA from a wrapper around OpenSSL.

### Why not use `tls.connect`?

The negotiated group is a property of the **server**, but the Node client only
reports what its own OpenSSL build supports. If the installed OpenSSL predates
ML-KEM, a hybrid-capable server looks classical. The probe therefore speaks the
protocol directly.

### ClientHello layout

```
TLS record header      type=0x16, version=0x0301, length
Handshake header       type=0x01 (ClientHello), 3-byte length
  legacy_version       0x0303 (TLS 1.2, per RFC 8446)
  random               32 bytes
  session_id           32 bytes (compatibility mode)
  cipher_suites        TLS 1.3 suites first, then ECDHE, then RSA for legacy probes
  compression          null only
  extensions
    server_name               (0x0000)
    supported_groups          (0x000a)  X25519MLKEM768 first
    signature_algorithms      (0x000d)  ML-DSA first, legacy SHA-1 last
    supported_versions        (0x002b)  0x0304, 0x0303
    key_share                 (0x0033)  one share per offered group
    ALPN                      (0x0010)  h2, http/1.1
    psk_key_exchange_modes    (0x002d)  psk_dhe_ke
    extended_master_secret    (0x0017)
```

Offered groups, in order:

| Codepoint | Group | Share size |
| --- | --- | --- |
| `0x11EC` | X25519MLKEM768 | 1216 bytes |
| `0x11EB` | X25519Kyber768Draft00 | 1216 bytes |
| `0x6399` | legacy Kyber draft codepoint | 1216 bytes |
| `0x001D` | X25519 | 32 bytes |
| `0x0017` | secp256r1 | 65 bytes |
| `0x0018` | secp384r1 | 97 bytes |
| `0x0100` | ffdhe2048 | 256 bytes |

### Getting a hybrid share accepted

Two details make the difference between a useful probe and a server alert:

1. **Order.** `draft-ietf-tls-ecdhe-mlkem` defines the share as the ML-KEM
   encapsulation key first, then the X25519 public key. Reversing the order
   produces `decode_error` (alert 50) on Cloudflare and `illegal_parameter`
   (alert 47) on Google.
2. **Canonical encoding.** ML-KEM-768's public key is 384 NTT coefficients
   packed as 12-bit values plus a 32-byte seed. Random bytes frequently encode
   coefficients ≥ q = 3329, which implementations reject. `canonicalMlKemEk()`
   reduces each 12-bit coefficient modulo q so the key parses. The probe never
   encapsulates, so the key does not need to correspond to a secret.

### Parsing the response

`parseServerFlight()` walks TLS records. It extracts:

- ServerHello: legacy version, 32-byte random, session id, cipher suite,
  extensions (`supported_versions`, `key_share`, ALPN).
- HelloRetryRequest: detected by comparing the random with
  `SHA-256("HelloRetryRequest")`.
- TLS 1.2 `Certificate`: first certificate DER from the message.
- TLS 1.2 `ServerKeyExchange`: the named curve.
- Alerts: level and description, surfaced as `probeAlert`.

The socket is destroyed as soon as the ServerHello is available. No
application data is sent or received.

## The raw SSH probe

`src/net/ssh.js` implements the smallest useful subset of RFC 4253:

```
TCP connect
  ◀  server identification   "SSH-2.0-OpenSSH_9.9p1 ..."
  ▶  client identification   "SSH-2.0-MOSCA_3.0"
  ▶  SSH_MSG_KEXINIT          type 20, random cookie, 10 name-lists
  ◀  SSH_MSG_KEXINIT          parse the server's 10 name-lists
  ■  close                    no authentication, no key exchange
```

The binary packet is `uint32 packet_length | uint8 padding_length | payload |
padding`. The probe aligns the packet to the 8-byte block that applies before
negotiation and emits at least four padding bytes. `parseKexInit()` reads the
ten name-lists in order:

1. key exchange
2. server host key
3. encryption client→server
4. encryption server→client
5. MAC client→server
6. MAC server→client
7. compression client→server
8. compression server→client
9. languages client→server
10. languages server→client

The advertised lists are classified through the same registry as every other
finding. `mlkem768x25519-sha256` and
`sntrup761x25519-sha512@openssh.com` are positive findings; `ssh-rsa`,
`ssh-dss`, SHA-1 group exchange, CBC ciphers and MD5/SHA-1 MACs are exposure.
SSH key-exchange findings participate in the same HNDL ratio as TLS, because a
recorded SSH session is just as readable after a CRQC as a recorded TLS one.

## Baseline model

`src/analysis/baseline.js` gives every actionable finding a stable identity:

```
sha256(id | kind | algorithm | primitive | file-or-host:port | normalised line)
```

Line and column are deliberately absent. Moving code, reformatting it or
renumbering a file must not create a "new" finding; changing the call must.
The baseline file stores fingerprints, not raw findings, so it contains no
source snippets and no secrets. `applyBaseline()` marks each item `new` or
`existing`, records resolved fingerprints, and adds a `summary.baseline`
block. `exitCode()` then evaluates only `new` items when a baseline was
supplied. The same fingerprint is written to SARIF as
`partialFingerprints.moscaFingerprint` and to `baselineState`.

## The X.509 parser

`src/net/x509.js` is a minimal DER reader: TLV framing, OID decoding, integers,
strings, UTCTime/GeneralizedTime, SPKI and the extensions MOSCA needs (SAN,
key usage, extended key usage, basic constraints). It classifies the signature
algorithm and public key through the same algorithm registry used everywhere
else, so a certificate for an RSA-2048 key and a source finding for RSA-2048
produce consistent labels.

It is tested against a real DER certificate captured from `example.com`, not a
hand-made fixture, because real encodings exercise long-form lengths,
multi-byte OIDs and extension nesting.

## X.509 chain analysis

`src/net/x509-chain.js` consumes the DER of every certificate in the peer
chain. It answers four questions that a leaf-only check cannot:

1. **Which certificate is the weakest link?** Each entry is classified as
   `broken`, `weakened` or `safe` from its key and signature algorithm, and the
   chain inherits the worst class. A modern ECDSA leaf signed by an RSA-2048
   intermediate is a chain problem.
2. **Does a classical root cross the CRQC window?** `longLivedClassical()`
   compares the root's expiry with the CRQC assumption and flags roots that
   must stay trusted for decades.
3. **What will the chain cost in bytes?** `PQC_SIZES` holds ML-DSA-44/65/87 and
   SLH-DSA parameter-set signature and public-key sizes. `estimatePqcHandshake()`
   projects the certificate flight for each option.
4. **Will it fragment?** The projection is compared with `INITIAL_CWND`
   (14 336 bytes). Exceeding the initial congestion window means an extra
   round-trip on every handshake.

Chain findings use `kind: 'chain'`, so risk scoring applies the chain surface
weight and the fix planner emits a trust-chain advisory rather than a literal
swap.

## STARTTLS, QUIC and IKEv2

The v3 probes share one rule: extract the protocol fingerprint, then close the
socket. Nothing authenticates and nothing completes a handshake.

- **STARTTLS** (`src/net/starttls.js`). The protocol descriptor carries the
  upgrade command (`STARTTLS`, `STLS`, the PostgreSQL `SSLRequest`, the LDAP
  `ExtendedRequest`). After the server accepts, the module reuses the raw
  ClientHello and ServerHello parser from `net/clienthello.js`, so a mail
  server is judged by exactly the same logic as a web server.
- **QUIC** (`src/net/quic.js`). An RFC 9001 v1 Initial packet is built from
  scratch: HKDF-SHA256 extracts and expands the initial secret, derives
  client key/IV/header-protection secrets, AES-128-ECB produces the header
  mask, and AES-128-GCM seals the payload. The implementation is pinned to the
  RFC 9001 Appendix A.1 vectors. The response parser handles Initial, Retry and
  Version Negotiation, and the ServerHello is handed to the same TLS parser.
- **IKEv2** (`src/net/ikev2.js`). The probe sends `IKE_SA_INIT` with a classic
  proposal and an RFC 9370 ADDKE proposal (transform type 6). The provisional
  ML-KEM transform IDs are `35, 36, 37, 41, 42, 43`; a gateway that answers
  anything other than `NO_PROPOSAL_CHOSEN` is treated as supporting hybrid
  key exchange, because the exact ID is still being assigned.

## Artefacts and supply chain

`src/scan/artifacts.js` recognises PEM blocks, DER files, JWK/JWKS documents,
OpenSSH private keys, `authorized_keys`, `known_hosts` and `*.pub` files. It
parses only the public metadata — algorithm, key size, curve, validity — and
never copies private key bodies into a finding. Findings use
`kind: 'artifact'`.

`src/scan/deps.js` parses eight lockfile formats into `{name, version,
ecosystem, file, line}` records and matches them against
`src/rules/crypto-packages.js`. The table records the primitive a package
fixes, the oldest secure version where one exists, and its quantum status.
Findings use `kind: 'dependency'`. Both scanners call
`createIgnore(..., { defaults: false })` so lockfiles and key files are not
excluded by the default walker ignores.

## Context, effort and compliance

`src/scan/constants.js` performs a deliberately small constant propagation:
a single-assignment string literal in the same file is substituted into a
known crypto call. Reassigned, concatenated or interpolated constants remain
unresolved, and the finding records the flow evidence so a reader can see why
the literal applies.

Risk analysis reports two effort numbers: raw occurrences and unique migration
sites. A site is keyed by `kind | algorithm | where | normalised match`;
duplicates add `1 + 0.15 * log2(1 + duplicates)` rather than a full unit, which
keeps a repeated call from inflating the estimate without pretending a
hundred edits are one.

`src/analysis/compliance.js` maps enriched findings onto named controls for
CNSA 2.0, NIST 2030, PCI DSS v4.0 and HIPAA. Each control reports pass,
partial or fail with a score, the offending fingerprints and a remediation
string. `--fail-on-compliance` turns the verdict into an exit code; SARIF and
HTML carry the same result.

## Fix planner

`src/fix.js` never writes to disk. It separates two kinds of change:

- **Automatic hunks** exist only for hash, MAC and AES key-size literal swaps.
  The replacement preserves the original spelling (`MD5`→`SHA256`,
  `SHA-1`→`SHA-256`, `aes-128-cbc`→`aes-256-cbc`).
- **Advisories** cover signatures, key agreement, certificates, protocol
  configuration, lockfiles and live listeners. Symmetric changes inside a
  protocol implementation or a test vector are demoted to advisories, because
  the literal is part of the wire format or the test oracle.

`buildPatch()` reads files through an injectable `readFile`, emits a unified
diff with CRLF preservation, and records skipped edits when a literal has
moved. The CLI writes `<out>/mosca-fix.patch`; the operator applies it.

## Rule model

Source rules are objects, not a DSL:

```js
{
  id: 'js-createHash',
  re: /createHash\(\s*['"`](md5|sha1|sha256|…)/gi,
  algo: (match) => normalise(match[1]),
  primitive: 'hash',
  confidence: 'high',
  note: 'Optional; the registry note is used when absent',
  bits: (match) => Number(match[2])   // optional key-size refinement
}
```

Design constraints:

- Rules are **linear regexes**, applied to comment-stripped content. No
  backtracking-heavy patterns; a 50k-file scan completes in tens of
  milliseconds.
- `algo` may be a function of the match, so `modulusLength: 2048` resolves to
  `rsa-2048`, not `rsa`.
- When two rules describe the same line and one algorithm id is a refinement of
  the other (`rsa` vs `rsa-2048`), the scanner keeps one finding and adopts the
  more specific id. This prevents double-counting a single key-generation call.
- Config rules carry an `appliesTo(path)` predicate, so `Ciphers` in
  `sshd_config` is not confused with `ssl_ciphers` in nginx.
- Inline suppressions (`mosca-ignore-line`, `mosca-ignore-next-line`,
  `mosca-ignore-file`) are read from the original text, because comments are
  stripped before rules run. `scanSourceContentDetailed` returns both the
  findings and the suppressed count, and `scanSourceDirectory` sums it into
  `stats.suppressed` for the terminal report.

## Report design

### HTML

The report is generated as one string with no external requests:

- No web fonts; a system font stack is used.
- No images; the gauge is inline SVG.
- No CDN; the ~250 lines of JavaScript that implement the CRQC slider, the
  findings filter and the crypto-agility simulator are inlined.
- All interpolated values pass through an HTML escaper, including project
  names, file paths and server errors.

The timeline is data-driven: each row carries `data-shelf` and `data-lead`, and
the slider recomputes exposure in the browser. The server-side score and the
client-side visual therefore use the same inequality. The v3 sections add:

- **Simulator** — client-side re-evaluation of every item against the selected
  CRQC year and migration-speed multiplier, with optional hybrid key exchange.
- **Chain tree** — one card per TLS endpoint, with role, subject, key,
  signature, days remaining and the PQC flight projection.
- **Compliance cards** — score, status and failed controls per standard.
- **Supply chain and artefacts** — lockfile packages and on-disk material.

### CBOM

Components are `cryptographic-asset` entries keyed by
`crypto/algorithm/<id>`. Repeated occurrences increment `evidence.occurrences`
instead of duplicating components. Each component carries:

- `cryptoProperties.algorithmProperties`: primitive, parameter set, mode,
  padding, crypto functions, classical security level, NIST quantum level.
- `properties`: quantum status, classical status, severity, primitive,
  replacement, standard, the Mosca inequality and the first location.

Certificates and negotiated protocols become first-class components, so the
CBOM describes the live estate as well as the source. v3 adds `library`
components for lockfile packages, with `mosca:cryptoPackageStatus`,
`mosca:algorithm` and `mosca:lockfile` properties, plus a top-level
`dependencies` entry connecting them to the application.

### SARIF

Rule ids are `mosca/<rule-id>`. Results include a `partialFingerprints` entry
built from rule id, URI and line, which is what lets GitHub code scanning
recognise the same issue after unrelated edits. Endpoint findings are excluded
because they have no file location; they appear in the CBOM and HTML instead.
With `--compliance`, each result carries `properties.compliance` (standard,
control, severity) and the run carries a `compliance` summary.

### Mermaid

`src/report/mermaid.js` builds bounded, deterministic diagrams:

- a risk graph linking algorithms to the files and endpoints that use them;
- a certificate-chain tree per inspected endpoint, including the PQC
  projection node;
- a dependency graph coloured by package status.

Node counts are capped (`MAX_ALGORITHMS`, `MAX_FILES`) so a large estate does
not produce an unreadable diagram. Labels are sanitised for Mermaid syntax.

## Testing strategy

`node --test` only, no framework:

| Area | What is asserted |
| --- | --- |
| `test/algorithms.test.js` | Shape of all 92 entries, replacement graph acyclic, alias resolution, TLS dialect mapping |
| `test/rules.test.js` | True and false positives for JS/Python/Go/Java plus nginx/sshd/OpenSSL |
| `test/clienthello.test.js` | Record framing, extension ordering, 1216-byte share, canonical coefficients, ServerHello and HRR parsing |
| `test/x509.test.js` | A real Cloudflare certificate, TLV boundaries, primitive decoders |
| `test/x509-chain.test.js` | Chain classification, weakest link, long-lived roots, PQC projection against 14 KB |
| `test/endpoint.test.js` | Target parsing, protocol normalisation, certificate summary, finding derivation |
| `test/starttls.test.js` | SMTP/PostgreSQL upgrades, refusal handling, classical-KEX findings |
| `test/quic.test.js` | RFC 9001 Appendix A.1 vectors, varints, Initial protect/unprotect, response parsing |
| `test/ikev2.test.js` | Packet framing, ADDKE proposals, notify parsing, finding derivation |
| `test/artifacts.test.js` | PEM, DER, JWK, OpenSSH and `authorized_keys` metadata; no private key leakage |
| `test/deps.test.js` | Eight lockfile parsers, package matching, version bounds |
| `test/context.test.js` | Constant propagation, reassignment refusal, indirect findings |
| `test/config-rules.test.js` | The 62-rule inventory and IaC/proxy true positives |
| `test/compliance.test.js` | Four standards, control evaluation, violation evidence |
| `test/fix.test.js` | Automatic vs advisory, patch generation, CRLF, protocol demotion |
| `test/mermaid.test.js` | Determinism, bounds, sanitisation, chain and dependency graphs |
| `test/reports-v3.test.js` | CBOM libraries, SARIF compliance properties, HTML v3 sections |
| `test/risk.test.js` | Every scoring direction, Mosca inequality, QRI, HNDL n/a semantics, unique-site effort, roadmap phases |
| `test/report.test.js` | CycloneDX shape, SARIF shape, HTML self-containment and escaping |
| `test/baseline.test.js` | Line-independent fingerprints, build/apply, new/existing/resolved, file validation |
| `test/ssh.test.js` | SSH packets, KEXINIT parsing, banner parsing, KEX/cipher/MAC classification |
| `test/v2.test.js` | Sensitivity, SSH-aware HNDL, registry aliases, SARIF baseline state, SSH CBOM assets |
| `test/fs.test.js` | Globs, ignore files, binary rejection, comment stripping |
| `test/config.test.js` | Merge semantics, scenarios, data classes |
| `test/scan.test.js` | End-to-end scan, determinism, exit codes |

The suite runs in well under a second and needs no network access; the only
network-derived artefact is the committed DER fixture.

## Performance

A cold `mosca demo` scan (10 source files, 3 config files, a lockfile and an
artefact) completes in roughly 80 ms on a laptop. The walker is synchronous and
single-pass; the expensive part of a real scan is endpoint latency, which is
parallelised. There is no AST, no type checker and no subprocess, which is why
the tool can be dropped into a pre-commit hook or a CI step without a build
stage.

## Extension points

- **A new source rule**: add an object to `RULES[language]` in
  `src/rules/source.js` and a test in `test/rules.test.js`.
- **A new configuration dialect**: add an `appliesTo` predicate and rules in
  `src/rules/config.js`; add the filename or extension to `CONFIG_FILENAMES` /
  `CONFIG_EXTENSIONS`.
- **A new algorithm**: add an entry to `ALGORITHMS` with `id`, `label`,
  `primitives`, `quantum`, `classical`, and optionally `replacement`,
  `standard`, `hybrid`. The registry test will catch broken references.
- **A new reporter**: consume the `analysis` object and add a format branch in
  `cli.js`. Reporters must not recompute risk.
- **A new live protocol**: add a module under `src/net/` that returns the
  endpoint shape (`reachable`, negotiated fields, `findings`) and wire it into
  `src/index.js` and `src/cli.js`. The socket must be closed without
  authentication.
- **A new lockfile format**: add a parser to `src/scan/deps.js` and a branch in
  `isDependencyFile` / `scanDependencyContent`.
- **A new compliance standard**: add a definition to `src/analysis/compliance.js`
  with controls that consume enriched findings; the CLI and SARIF pick it up
  from `COMPLIANCE_IDS`.
