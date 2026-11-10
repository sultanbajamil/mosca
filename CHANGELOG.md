# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.1.0] — 2026-11-10

The evidence edition: passive capture harvesting, a replayable global benchmark
and locally generated badges. The zero-dependency, pure-ESM contract is
unchanged.

### Added

- **Passive PCAP/PCAPNG harvesting** (`src/net/pcap.js`). Reads classic libpcap
  (big/little endian, microsecond and nanosecond magic) and PCAPNG Section
  Header, Interface Description, Enhanced Packet and Simple Packet blocks with
  per-interface timestamp resolution. Decodes Ethernet with stacked 802.1Q
  tags, Linux SLL/SLL2, BSD NULL and raw IP; parses IPv4/IPv6, TCP reassembly,
  TLS ClientHello/ServerHello and SSH banners plus `SSH_MSG_KEXINIT`, including
  first-match KEX agreement between both directions.
- **`mosca pcap <file...>` and `scan --pcap <file,...>`.** Captured sessions
  become `captured-session` findings in the unified schema. Exposure is
  anchored to the **capture year**, not the report date. The terminal, JSON,
  HTML, CBOM and SARIF surfaces all carry the capture date, negotiated KEX and
  the Mosca inequality.
- **HNDL Captured Ratio.** The share of recorded sessions that are
  classical-only, reported next to the live HNDL exposure. A capture can be
  audited on an air-gapped host with no reachable endpoint.
- **Global PQC benchmark** (`src/benchmark.js`, `scripts/benchmark-world.js`).
  Concurrency capped at 10, 5-second default timeout, TLS + optional SSH,
  deterministic aggregation by sector, per-sector data lifetime, HNDL
  exposure, hybrid adoption, key-exchange distribution and classical debt.
  `mosca benchmark` replays a snapshot or probes live.
- **State of PQC report** (`src/report/benchmark-html.js`,
  `docs/state-of-pqc.html`). Self-contained dark page with an A+–F leaderboard,
  sector filters, a 2027–2045 CRQC slider and shareable insight cards. The
  static social card is generated as `docs/state-of-pqc.svg`.
- **Benchmark target set and snapshot** (`benchmarks/targets.json`,
  `benchmarks/snapshot.json`, `benchmarks/report.json`). 69 named targets
  across 10 sectors; CI regenerates the published page from the raw handshake
  snapshot.
- **SVG badges** (`src/report/badge.js`, `--badge <dir>`). Writes
  `mosca-qri-badge.svg` and `mosca-hndl-badge.svg` from the scan summary with
  no network call or third-party badge service.
- **npm packaging.** `bin`, `exports` (`.`, `./pcap`, `./benchmark`,
  `./badge`, `./package.json`), `files`, keywords and engines are publication
  ready; `npx mosca-pqc <command>` is the canonical invocation.
- **Launch kit** (`docs/launch-kit/`): Show HN post, press release, English and
  Arabic social threads, and a CISO one-pager.
- **25 new tests** (231 total) for PCAP/PCAPNG fixtures, the benchmark engine,
  badge rendering and the self-contained benchmark page.

### Changed

- Version bumped to `3.1.0`.
- `mosca benchmark` is a first-class command; the GitHub Action gains `pcap`,
  `badge` and `benchmark-snapshot` inputs plus `badges` and `benchmark` outputs.
- The README is rebuilt around the executive pitch, the ten-second demos and
  the benchmark; `examples/vulnerable-app/README.md` uses the npm invocation.
- Captured sessions participate in compliance controls and the risk engine's
  surface weighting, but are counted separately from live-endpoint HNDL so a
  capture-only run cannot be mistaken for an empty estate.

## [3.0.0] — 2026-11-10

The enterprise and deep-protocol edition. Every new scanner and probe emits the
same unified finding schema, so risk scoring, baselines, CBOM, SARIF, the HTML
report and the fix planner all see the new surfaces without a second pipeline.

### Added

- **X.509 chain analysis** (`src/net/x509-chain.js`). Parses every certificate
  in the peer chain, classifies leaf, intermediate and root, finds the weakest
  link, flags long-lived classical roots that cross the CRQC window and SHA-1
  signatures, and projects an ML-DSA-65 / SLH-DSA chain size against the 14 KB
  initial congestion window. TLS and STARTTLS attach `chainAnalysis` and
  `pqcHandshake`; chain findings use `kind: 'chain'`.
- **STARTTLS probe** (`src/net/starttls.js`) for SMTP, IMAP, POP3, PostgreSQL
  and LDAP. Negotiates the upgrade with the native protocol command, sends the
  same raw ClientHello, extracts the negotiated group and chain, and closes the
  socket without authenticating. `mosca starttls` and `scan --starttls`.
- **QUIC / HTTP/3 probe** (`src/net/quic.js`). Builds an RFC 9001 Initial
  packet with HKDF-SHA256, AES-128-GCM and AES-128-ECB header protection by
  hand, pinned to the RFC 9001 Appendix A.1 test vectors, then parses the server
  Initial, Retry and Version Negotiation. `mosca quic` and `scan --quic`.
- **IKEv2 probe** (`src/net/ikev2.js`). Sends `IKE_SA_INIT` with RFC 9370
  ADDKE transforms and reports whether the gateway accepts hybrid key exchange.
  `mosca ikev2`, `scan --ikev2` and `--addke`.
- **On-disk artefact scanner** (`src/scan/artifacts.js`). Reads metadata from
  PEM, DER, JWK/JWKS, OpenSSH private keys, `authorized_keys`, `known_hosts`
  and `*.pub` files. Private key bodies are never emitted. Findings use
  `kind: 'artifact'`.
- **Cryptographic supply-chain scanner** (`src/scan/deps.js` and
  `src/rules/crypto-packages.js`). Eight lockfile parsers (package-lock,
  npm-shrinkwrap, yarn, pnpm, Cargo, Go, Poetry, requirements.txt, Maven) plus a
  curated package intelligence table. Findings use `kind: 'dependency'`.
- **Contextual static analysis** (`src/scan/constants.js`). Single-assignment
  string constants are propagated into crypto APIs; reassigned or interpolated
  constants stay unresolved. Indirect findings record `flow` evidence.
- **Unique-site migration effort.** Risk analysis now separates raw occurrences
  from unique migration sites, keyed by kind, algorithm, location and
  normalised match, and applies a damped duplication factor.
- **IaC and edge-proxy rules.** Configuration rules grow from 23 to **62**,
  covering Terraform, cert-manager, Istio, HAProxy, Envoy, Caddy, Traefik,
  Cloudflare and Dockerfile variants, plus `.tf`, `.hcl` and `.toml`.
- **Compliance engine** (`src/analysis/compliance.js`). `--compliance` and
  `--fail-on-compliance` for CNSA 2.0, NIST 2030, PCI DSS v4.0 and HIPAA, with
  per-control pass/partial/fail, scores, evidence and remediation. Compliance
  properties flow into SARIF and HTML.
- **`mosca fix`** (`src/fix.js`). Produces a reviewable unified patch for hash,
  MAC and AES key-size literal swaps and numbered advisories for signatures,
  key agreement, certificates, protocol, configuration, lockfile and endpoint
  changes. Symmetric edits inside protocol implementations and test vectors are
  demoted to advisories. Never applies a change.
- **Mermaid output** (`src/report/mermaid.js`). Bounded, deterministic risk,
  certificate-chain and supply-chain diagrams; `--format mermaid` writes
  `mosca.mmd` and `mosca-diagrams.md`.
- **HTML v3 sections**: crypto-agility simulator, X.509 chain tree, compliance
  cards, supply-chain table and artefact table.
- **CBOM** now includes lockfile packages as library components and a
  top-level dependency graph; **SARIF** carries per-result compliance controls
  and a run-level compliance summary.
- **94 new tests** (206 total) for chain analysis, STARTTLS, QUIC, IKEv2,
  artefacts, dependencies, constants, the 62 config rules, compliance, the fix
  planner, Mermaid and the v3 report surfaces.

### Changed

- Version bumped to `3.0.0`; Node ≥ 20 is still the only requirement.
- `mosca scan` now includes artefacts and dependencies by default, and accepts
  STARTTLS, QUIC and IKEv2 targets.
- The `rules` command reports the new protocols, artefact formats, lockfiles
  and compliance standards.
- The GitHub Action gains `starttls`, `quic`, `ikev2`, `compliance` and
  `fail-on-compliance` inputs; `mermaid` is in the default format list.

### Fixed

- Mermaid labels are sanitised for braces, brackets, pipes and backticks, so a
  malicious filename cannot break out of a node.
- `mosca fix` no longer proposes literal swaps inside protocol or test-vector
  paths.

## [2.0.0] — 2026-11-09

The release that turns MOSCA from a scanner into a CI-native platform.

### Added

- **Baseline and differential mode.** `--write-baseline` records a run;
  `--baseline` compares against it. Findings are matched with stable,
  line-independent fingerprints, marked `new` or `existing`, and `--fail-on`
  gates only on regressions when a baseline is supplied.
- **Raw SSH prober.** A minimal RFC 4253 exchange sends `SSH_MSG_KEXINIT` and
  parses the server's advertised KEX, host-key, cipher and MAC name-lists.
  Detects `mlkem768x25519-sha256` and
  `sntrup761x25519-sha512@openssh.com`, plus `ssh-rsa`, `ssh-dss`, SHA-1 KEX,
  CBC ciphers and MD5/SHA-1 MACs. New `mosca ssh` command and
  `scan --ssh`.
- **Composite GitHub Action** (`action.yml`) with inputs for TLS, SSH,
  baseline, formats and severity gate.
- **`mosca explain <algorithm>`** — registry-backed migration brief with an
  optional `--json` form.
- **CRQC sensitivity analysis** across 2029, 2033, 2038 and 2045 in the JSON,
  terminal and HTML report.
- **SSH findings in HNDL exposure** — TLS and SSH key exchange now share one
  internet-facing exposure ratio.
- **SSH protocol assets in the CBOM**, and SSH cards in the HTML report.
- **`new` badges and a "new since baseline" filter** in the HTML findings
  table; SARIF results carry `baselineState`.
- **34 new tests** (112 total) for baseline behaviour, SSH wire parsing and
  classification, sensitivity, SSH-aware HNDL, SARIF and CBOM.

### Changed

- SARIF `partialFingerprints.moscaFingerprint` is now line-independent, so
  moving code does not re-open an alert.
- The terminal summary splits inspected endpoints into TLS and SSH.
- `--fail-on` evaluates only new findings when a baseline is present.

## [1.0.0] — 2026-11-04

First release.

### Added

- **Raw TLS ClientHello prober** that offers `X25519MLKEM768` (0x11EC),
  `X25519Kyber768Draft00` (0x11EB and 0x6399), classical ECDHE and FFDHE
  groups, and reports the group selected by the server. Includes canonical
  ML-KEM-768 encapsulation keys and the correct ML-KEM-then-X25519 share order.
- **Dependency-free DER/X.509 parser** classifying signature algorithm, public
  key algorithm, curve, SAN, key usage and validity.
- **Endpoint inspection** combining a real Node handshake with the raw probe,
  plus a legacy TLS 1.0/1.1 acceptance check.
- **148 source rules** across JavaScript, TypeScript, Python, Java, Kotlin, Go,
  C, C++, C#, Rust, PHP, Ruby, Shell, PowerShell, Swift and Scala.
- **23 configuration rules** for nginx, Apache, OpenSSH, OpenSSL,
  `java.security` and Kubernetes ingress annotations.
- **91-entry algorithm registry** with quantum and classical classifications,
  NIST levels, aliases, standards and primitive-aware replacements.
- **Mosca-inequality risk engine**: shelf life, migration lead time, weighted
  score, severity bands, Quantum Readiness Index, HNDL exposure and a phased
  migration roadmap.
- **Interactive HTML report** — single file, no network requests, CRQC slider,
  findings filters, endpoint cards, algorithm inventory, roadmap.
- **CycloneDX 1.6 CBOM** with `cryptographic-asset` components, certificates
  and protocols.
- **SARIF 2.1.0** output with stable fingerprints for GitHub code scanning.
- **CLI** with `scan`, `tls`, `demo`, `init` and `rules`, plus `--fail-on` for
  CI gating.
- **Zero runtime and development dependencies**, enforced by
  `scripts/check-zero-deps.js` and CI.
- **Inline suppressions** (`mosca-ignore-line`, `mosca-ignore-next-line`,
  `mosca-ignore-file`) with mandatory-reason convention and an auditable
  suppressed count in the terminal report.
- **91 tests** covering the registry, rules, wire format, DER parsing, risk
  model, report schemas and end-to-end scans.
- Synthetic vulnerable estate in `examples/vulnerable-app/` for evaluation.

### Fixed

- TLS 1.2 `minVersion` no longer reported as a legacy floor.
- `!aNULL` in an nginx cipher list no longer reported as a NULL cipher.
- `MinProtocol = TLSv1.3` no longer reported as a legacy floor.
- Go and C TLS rules distinguish a minimum-version floor from a maximum-version
  cap.
- `HelloRetryRequest` detection now uses the actual
  `SHA-256("HelloRetryRequest")` value.
- Node's `TLSv1.3` protocol spelling is normalised before comparison, so a
  modern endpoint is not labelled legacy.
- RSA replacements are chosen by usage: ML-KEM-768 for encryption, ML-DSA-65
  for signatures.
- A key-generation call is reported once, with the more specific key size.
- The HTML report's CBOM download now embeds the real CycloneDX document
  instead of producing an empty object.

[Unreleased]: https://github.com/sultanbajamil/mosca/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/sultanbajamil/mosca/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/sultanbajamil/mosca/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/sultanbajamil/mosca/releases/tag/v1.0.0
