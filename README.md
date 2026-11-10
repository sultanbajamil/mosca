# MOSCA

**CI-native post-quantum exposure scanner for code, configuration, keys, dependencies and live TLS, SSH, STARTTLS, QUIC and IKEv2 endpoints.**

[![CI](https://github.com/sultanbajamil/mosca/actions/workflows/ci.yml/badge.svg)](https://github.com/sultanbajamil/mosca/actions/workflows/ci.yml)
[![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)](scripts/check-zero-deps.js)
[![tests: 206](https://img.shields.io/badge/tests-206-brightgreen)](test/)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![live report](https://img.shields.io/badge/live%20report-open-8b5cf6)](https://sultanbajamil.github.io/mosca/)

MOSCA answers one question that most security tools avoid:

> If an adversary records my traffic today, when does the data become readable?

It does that by applying **Mosca's inequality** to a real cryptographic inventory:
*the time your data must stay secret plus the time it takes to migrate must be
shorter than the time until a cryptographically relevant quantum computer
(CRQC) exists.* When the sum is larger, the data is **already exposed** —
harvest-now-decrypt-later is not a future risk, it is a disclosure in progress.

```console
$ npx github:sultanbajamil/mosca scan . --tls example.com --ssh bastion.example.com

   30.8 / 100   █████████░░░░░░░░░░░░░░░░░░░░░░░░

  Mosca window   7 years to a CRQC (2033)
  HNDL exposure  100% of internet-facing key exchange is classical-only
  Findings       60 total · 52 actionable · 52 inside the Mosca window
  Surface        10 source files · 3 config files · 1 TLS · 1 SSH
```

- **Zero runtime dependencies.** Node.js ≥ 20, ESM, no `node_modules`.
- **Finds crypto the way it is actually written** — 148 rules across 16
  languages, 62 configuration/IaC rules for nginx, Apache, OpenSSH, OpenSSL,
  Java, Kubernetes, Terraform, Istio, Envoy, HAProxy, Caddy, Traefik,
  Cloudflare and Dockerfiles, and 92 classified algorithms.
- **Follows constants.** `const HASH = 'md5'; crypto.createHash(HASH)` is a
  finding, not a blind spot; reassigned or interpolated constants stay
  unresolved.
- **Reads the artefacts and the supply chain.** PEM, DER, JWK/JWKS,
  `authorized_keys`, `known_hosts`, plus eight lockfile formats with a
  cryptographic package intelligence table.
- **Analyzes the whole X.509 chain**, not just the leaf: weakest link,
  long-lived classical roots, SHA-1 signatures, and a projected ML-DSA/SLH-DSA
  handshake against the 14 KB initial congestion window.
- **Probes TLS with a hand-built ClientHello** that offers
  `X25519MLKEM768` (0x11EC) and reports the group the *server* selected.
  Node's own TLS stack cannot do this, so neither can tools that inherit it.
- **Probes SSH with a hand-built `SSH_MSG_KEXINIT`**, reading the server's
  advertised KEX, host-key, cipher and MAC lists — including
  `mlkem768x25519-sha256` and `sntrup761x25519-sha512@openssh.com`.
- **Probes STARTTLS, QUIC and IKEv2.** SMTP, IMAP, POP3, PostgreSQL and LDAP
  upgrades; RFC 9001 Initial packet protection built by hand; and RFC 9370
  ADDKE transforms against IPsec gateways.
- **Gates on named standards.** CNSA 2.0, NIST IR 8547's 2030 transition,
  PCI DSS v4.0 and the HIPAA Security Rule, with per-control evidence.
- **Proposes fixes.** `mosca fix` emits a reviewable patch for hash, MAC and
  AES key-size swaps, and numbered advisories for everything that is a
  protocol or trust-chain migration. It never applies a change.
- **Diffs against a baseline.** Accept the debt you already have, then fail CI
  only when a change introduces a new exposure.
- **Emits artefacts**: an interactive self-contained HTML report with a
  crypto-agility simulator and certificate-chain tree, a CycloneDX 1.6
  **CBOM** with library dependencies, **SARIF 2.1.0** for GitHub code
  scanning, and **Mermaid** diagrams for review notes.

---

## Why this exists

NIST finalised ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) in
August 2024. CNSA 2.0 gives organisations a 2030–2033 migration window. Yet
most inventories still answer "which algorithms do we use?" and stop there.
That is the wrong question.

The right question is temporal. A patient attacker records TLS sessions today
and waits for the machine. If the recorded data must remain confidential for
ten years and a CRQC arrives in seven, the attacker already has the plaintext
— the only remaining step is computation. Mosca's theorem makes this precise:

```
exposed  ⇔  shelfLife + migrationLeadTime > yearsToCRQC
```

MOSCA turns that theorem into an operational score, a migration roadmap, and
a bill of materials you can hand to an auditor.

## What makes it different

| Capability | Typical crypto inventory | Typical TLS scanner | MOSCA |
| --- | --- | --- | --- |
| Source + config + live endpoints in one report | partial | no | **yes** |
| SSH hybrid KEX and host-key inventory | no | no | **yes, raw KEXINIT** |
| Baseline diff that gates only on regressions | no | rarely | **yes** |
| CycloneDX 1.6 CBOM | sometimes | no | **yes** |
| Server's chosen PQ hybrid group | no | only if linked OpenSSL supports it | **yes, raw ClientHello** |
| Mosca-inequality exposure per finding | no | no | **yes** |
| Zero runtime dependencies | rarely | rarely | **yes** |

### What v3 adds

v3 is the enterprise and deep-protocol edition. It keeps the zero-dependency
contract and extends the same unified finding schema to areas a source scan
cannot see:

| Area | What it does |
| --- | --- |
| X.509 chain analysis | Classifies every certificate in the peer chain, finds the weakest link, flags long-lived classical roots and SHA-1 signatures, and projects a post-quantum chain against the 14 KB initial congestion window. |
| STARTTLS | Negotiates SMTP, IMAP, POP3, PostgreSQL and LDAP upgrades, then sends the same raw ClientHello and closes the socket. |
| QUIC / HTTP/3 | Builds an RFC 9001 Initial packet with HKDF-SHA256, AES-128-GCM and AES-ECB header protection, then parses the server Initial, Retry and Version Negotiation. Pinned to RFC 9001 Appendix A.1 vectors. |
| IKEv2 | Sends `IKE_SA_INIT` with RFC 9370 ADDKE transforms and reports whether the gateway understands hybrid key exchange. |
| Artefacts | Reads metadata from PEM, DER, JWK/JWKS, `authorized_keys`, `known_hosts` and `*.pub` files; never emits private key material. |
| Supply chain | Parses npm, yarn, pnpm, Cargo, Go, Poetry, requirements.txt and Maven lockfiles against a curated cryptographic package table. |
| Context | Propagates single-assignment string constants into crypto APIs, and separates raw occurrences from unique migration sites. |
| IaC and edge proxies | 62 config rules covering Terraform, cert-manager, Istio, HAProxy, Envoy, Caddy, Traefik, Cloudflare and Dockerfiles. |
| Compliance | `--compliance` and `--fail-on-compliance` for CNSA 2.0, NIST 2030, PCI DSS v4.0 and HIPAA. |
| Fix and diagrams | `mosca fix` produces a patch plus advisories; `--format mermaid` produces review-ready graphs. |

The key-exchange probe is the part that cannot be copied from a library call.
MOSCA writes the TLS record by hand, generates a *canonical* ML-KEM-768
encapsulation key (coefficients reduced mod 3329, so servers accept it),
places the ML-KEM key **before** the X25519 share as
`draft-ietf-tls-ecdhe-mlkem` requires, and reads the selected group from the
ServerHello. It never completes a handshake or exchanges application data.

The SSH probe is the same idea at a different layer. MOSCA exchanges
identification strings, sends a minimal `SSH_MSG_KEXINIT`, and parses the
server's KEXINIT name-lists directly from the binary packet. It never
authenticates, never offers a credential and never completes key exchange.
That is how it can tell you a bastion already advertises
`mlkem768x25519-sha256` while still offering `ssh-rsa` host keys.

## Install and run

```bash
# run directly from GitHub — no clone, no npm publish required
npx github:sultanbajamil/mosca scan .

# or clone and run the source
git clone https://github.com/sultanbajamil/mosca.git
cd mosca
node bin/mosca.js scan /path/to/repo --tls example.com,github.com --out report
```

An npm release (`npx mosca-pqc`) is planned; until then the GitHub form above
is the canonical one-liner. A generated example report is published at
**https://sultanbajamil.github.io/mosca/**.

The scan writes `mosca-report/mosca-report.html` by default. Open it in any
browser: it is a single file with no external fonts, scripts or images, so it
can be attached to an email or published to GitHub Pages unchanged.

### Commands

```bash
mosca scan [path] [options]     # source + config + artefacts + deps + TLS/SSH/STARTTLS/QUIC/IKEv2
mosca tls <host...>             # probe live TLS endpoints only
mosca ssh <host...>             # probe SSH servers only
mosca starttls <target...>      # probe SMTP/IMAP/POP3/PostgreSQL/LDAP STARTTLS
mosca quic <host...>            # probe QUIC / HTTP/3
mosca ikev2 <host...>           # probe IPsec gateways for RFC 9370 hybrid KEX
mosca fix [path]                # propose a patch and print manual advisories
mosca explain <algorithm>       # why an algorithm is exposed, and what replaces it
mosca demo                      # scan the bundled vulnerable estate
mosca init                      # write a starter mosca.json
mosca rules                     # show the rule inventory
```

Common options:

| Flag | Meaning |
| --- | --- |
| `--tls <host,...>` | TLS endpoints to inspect (or set `endpoints` in `mosca.json`) |
| `--ssh <host,...>` | SSH targets to inspect (or set `ssh` in `mosca.json`) |
| `--starttls <target,...>` | STARTTLS targets (`smtp://`, `imap://`, `pop3://`, `postgres://`, `ldap://`) |
| `--quic <host,...>` | QUIC / HTTP/3 endpoints |
| `--ikev2 <host,...>` | IKEv2 gateways |
| `--compliance <id>` | `cnsa2`, `nist-2030`, `pci-dss`, `hipaa` or `all` |
| `--fail-on-compliance <id>` | Exit 1 when the selected standard fails |
| `--fix` | Write `<out>/mosca-fix.patch` and print the fix plan |
| `--baseline <file>` | Compare against a baseline; `--fail-on` considers only new findings |
| `--write-baseline <file>` | Write this run's findings as the new baseline |
| `--format <list>` | `html,json,cbom,sarif,term,mermaid` (default `html,term`) |
| `--out <dir>` | Output directory |
| `--fail-on <severity>` | Exit 1 at or above `low`, `medium`, `high`, `critical` |
| `--scenario <name>` | `aggressive` (2029), `moderate` (2033), `conservative` (2038) |
| `--crqc-year <year>` | Explicit CRQC assumption |
| `--shelf-life <years>` | Default confidentiality lifetime |
| `--quiet` | Suppress the terminal report |
| `--no-color` | Disable ANSI colour |

### CI gating and baseline mode

A gate that fails on every historical finding gets switched off. Record the
current estate once, commit the baseline, then fail only on regressions:

```bash
# once, on the current commit
npx github:sultanbajamil/mosca scan . --write-baseline .mosca-baseline.json

# in CI: existing debt is accepted, new exposure fails the build
npx github:sultanbajamil/mosca scan . \
  --baseline .mosca-baseline.json \
  --format sarif --out out --fail-on high
```

Fingerprints exclude line numbers, so moving a function does not manufacture
a "new" finding. Every result still carries a stable SARIF
`partialFingerprints.moscaFingerprint`, and the HTML report marks regressions
with a `new` badge and a one-click filter. A rendered example is at
[`docs/baseline-demo.html`](docs/baseline-demo.html).

A composite GitHub Action is included:

```yaml
- name: MOSCA
  uses: sultanbajamil/mosca@v3
  with:
    path: .
    tls: example.com,api.example.com
    ssh: bastion.example.com
    starttls: smtp://mail.example.com:587
    quic: example.com
    ikev2: vpn.example.com
    compliance: cnsa2
    fail-on-compliance: cnsa2
    baseline: .mosca-baseline.json
    fail-on: high
    format: html,sarif,json,cbom,mermaid

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mosca-report/mosca.sarif
```

### Compliance gates

A readiness score is useful for prioritisation but useless in an audit. The
compliance engine maps each enriched finding onto named controls and reports
pass, partial or fail per standard:

```bash
mosca scan . --compliance cnsa2
mosca scan . --compliance all --fail-on-compliance pci-dss
```

| Standard | Focus |
| --- | --- |
| `cnsa2` | ML-KEM key establishment, ML-DSA signatures, AES-256, SHA-384 |
| `nist-2030` | Deprecate RSA/ECC/DSA/EdDSA by 2030 and remove by 2035 |
| `pci-dss` | TLS 1.2+, no RC4/3DES/DES, RSA-2048+, no MD5/SHA-1, HNDL |
| `hipaa` | ePHI in transit and at rest, integrity, long-retention HNDL |

Each violation carries the finding fingerprint, algorithm and location, so the
SARIF result itself names the control it breaks.

### Fix plans

`mosca fix` is deliberately conservative. It only generates a textual hunk
when the change is a literal swap of a hash, MAC or AES key size — and never
inside a protocol implementation or a test vector, where the algorithm is part
of the wire format. Everything else becomes an advisory:

```bash
mosca fix .
# out/mosca-fix.patch — review with `git apply --check`, then apply deliberately
```

Signatures, key agreement, certificates, configuration, lockfiles and live
listeners are always manual: those are trust-chain or protocol migrations, not
find-and-replace. MOSCA never edits a file in the `fix` command.

### Mermaid diagrams

```bash
mosca scan . --format mermaid --out out
# out/mosca.mmd            risk graph
# out/mosca-diagrams.md    risk graph, certificate chains and supply chain
```

Diagrams are bounded and deterministic, so a committed diagram does not churn
on every scan. Labels are sanitised before they reach Mermaid syntax.

### Configuration

`mosca init` writes a starter file. Everything that shapes the model is
configurable:

```json
{
  "scenario": "moderate",
  "defaultShelfLife": 7,
  "endpoints": ["example.com", "api.example.com:8443"],
  "ssh": ["bastion.example.com", "git.example.com:2222"],
  "dataClasses": [
    { "pattern": "**/health/**", "years": 25, "label": "health records" },
    { "pattern": "**/billing/**", "years": 10, "label": "billing records" }
  ],
  "ignore": ["**/fixtures/**"]
}
```

Data classes are matched against file paths and directly change the exposure
calculation: the same MD5 in `health/` and in `util/` is not the same risk.

### Suppressing findings

A scanner is only trusted if it can be told "this one is intentional". MOSCA
supports the same inline directives in every language, with an optional reason
that is kept in the scan statistics:

```js
// mosca-ignore-line -- legacy detector, not a policy
minVersion: 'TLSv1',

// mosca-ignore-next-line -- third-party protocol requirement
crypto.createHash('md5');

// mosca-ignore-file -- generated compatibility shim
```

Suppressed findings never reach the report, and the terminal output shows how
many were suppressed, so a clean scan cannot hide a pile of exceptions. Use a
reason: the next reader needs to know why the line is safe, not just that
someone silenced it.

## Output

### Terminal

Ranked findings with severity, priority, location, replacement and the Mosca
inequality behind each one:

```text
  SEV         PRI  NEW  ALGORITHM             LOCATION                          REPLACE WITH
  ─────────────────────────────────────────────────────────────────────────────────────────
   CRITICAL   P0   NEW  SHA-1                 services/identity/main.go:30      SHA-256
   CRITICAL   P0        MD5                   src/api/auth.js:34                SHA-256
   CRITICAL   P0        RC4                   infra/nginx.conf:18               AES-256-GCM
   HIGH       P1        RSA                   services/identity/main.go:20      ML-KEM-768

  CRQC sensitivity  2029: 48  ·  2033: 48  ·  2038: 8  ·  2045: 0  exposed findings
```

`mosca explain <algorithm>` turns the registry into a one-screen migration
brief:

```console
$ mosca explain rsa
  RSA  (rsa)
  Primitives     pke, signature
  Quantum        broken
  Classical      acceptable
  Replace with   ML-KEM-768 (ml-kem-768)
  Standard       FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)
  Hybrid form    X25519MLKEM768
```

### Interactive HTML

The report renders Mosca's inequality as a timeline. Drag the CRQC line and
every bar is re-evaluated in the browser — no server, no JavaScript bundle,
no network access. It also contains:

- a **crypto-agility simulator** that re-scores the estate as you move the
  CRQC year, scale migration speed and assume a hybrid-key-exchange rollout;
- an **X.509 chain tree** for every inspected TLS endpoint, with the weakest
  link highlighted and the projected post-quantum flight size against the
  14 KB initial congestion window;
- **compliance cards** for CNSA 2.0, NIST 2030, PCI DSS and HIPAA, naming each
  failed control and its remediation;
- a **cryptographic supply-chain table** of lockfile packages and an
  **on-disk artefact table** (PEM, DER, JWK, OpenSSH);
- the findings table with severity and "new since baseline" filters, TLS,
  SSH, STARTTLS, QUIC and IKEv2 endpoint cards, a CRQC sensitivity strip, the
  algorithm inventory and the phased roadmap.

A generated example is committed at [`docs/index.html`](docs/index.html).

### CBOM (CycloneDX 1.6)

```bash
mosca scan . --format cbom --out out
# out/bom.cdx.json — cryptographic-asset components with
# cryptoProperties.algorithmProperties, NIST quantum level, and
# mosca:* properties (status, replacement, inequality, location).
# TLS and SSH servers appear as protocol assets with their KEX lists.
# Lockfile packages appear as library components, and the top-level
# `dependencies` graph connects them to the application.
```

### SARIF 2.1.0

Every actionable code finding becomes a SARIF result with a stable,
line-independent `partialFingerprints.moscaFingerprint`, so GitHub code
scanning tracks an issue across commits instead of re-opening it. Baseline
runs also set `baselineState` to `new` or `unchanged`. With `--compliance`,
each result gains a `properties.compliance` list naming the standards and
controls it violates, and the run carries an estate-wide compliance summary.

## How the score works

Each finding is scored 0–100 from five normalised factors:

| Factor | Weight | What it measures |
| --- | --- | --- |
| Quantum | 0.40 | Shor breaks it vs. Grover halves it vs. safe |
| Durability | 0.20 | Years the protected data must stay secret |
| Breadth | 0.15 | How widely the primitive is used (migration cost) |
| Classical | 0.15 | Whether it is broken *today* |
| Surface | 0.10 | Internet-facing endpoint vs. config vs. source |

Severity bands are deliberately asymmetric: anything classically broken is
**critical** regardless of the numeric score, because it is exploitable now,
not in 2033. The full model, including every constant and its justification,
is in [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## Demo

The repository ships an intentionally insecure estate — Node, Python, Go,
Java, nginx, sshd, OpenSSL and a shell deployment script — so the scanner can
be evaluated without pointing it at real code.

```bash
npm run demo
```

Expected result: **56 findings** (source, configuration, one on-disk RSA
artefact and two lockfile packages), QRI **23.9/100**, ~27 engineer-days of
estimated migration effort across **51 unique migration sites**, in under a
second. Add live endpoints for the full picture:

```bash
node bin/mosca.js demo --tls cloudflare.com,github.com,en.wikipedia.org,example.com \
  --ssh github.com --starttls smtp://gmail-smtp-in.l.google.com:25 --quic cloudflare.com
```

## Development

```bash
npm run check   # zero-dependency guard + 206 tests
npm test        # node:test only
npm run demo
```

No build step, no transpiler, no test framework to install. The test suite
covers the algorithm registry invariants, rule true/false positives, DER X.509
parsing against a real Cloudflare certificate, ClientHello construction and
ServerHello parsing, RFC 9001 QUIC Initial key derivation against the Appendix
A.1 vectors, the STARTTLS and IKEv2 wire formats, X.509 chain analysis,
lockfile parsing, artefact scanning, constant propagation, all four compliance
standards, the fix planner, the risk model, every report format and an
end-to-end scan.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module map and the
wire-format details, and [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to add a
rule.

## Honest limitations

- **Planning model, not prophecy.** The CRQC year is an assumption you choose,
  not a prediction. The report exposes the assumption rather than hiding it.
- **Static analysis has false positives.** Rules are regex-based for speed and
  zero dependencies. Confidence levels are reported and low-confidence findings
  are downgraded one severity band.
- **The probe measures the selected group, not full PQC readiness.** A hybrid
  key exchange does not fix a classical certificate signature; the report keeps
  those as separate findings.
- **SSH results describe advertised algorithms, not the negotiated ones.** The
  probe reads the server's KEXINIT and hangs up; it does not authenticate or
  complete key exchange, so the client's own preference order still decides
  what a real session uses.
- **Baseline fingerprints are content-based.** Two identical calls on two
  identical lines in the same file collapse into one baseline entry. That is
  intentional: the baseline records the defect, not the line count.
- **No authenticated scanning.** `mosca` does not log in, crawl authenticated
  pages, or test application logic.
- **TLS 1.0/1.1 acceptance is probed with a raw ClientHello.** Some CDNs answer
  legacy probes even when the property's policy claims otherwise; treat the
  finding as "this edge still negotiates legacy TLS" and verify at the origin.

## License

MIT. See [`LICENSE`](LICENSE).

## References

FIPS 203, FIPS 204, FIPS 205 · NIST IR 8547 (draft) · RFC 8446, RFC 8996 ·
`draft-ietf-tls-ecdhe-mlkem` · CycloneDX 1.6 · CNSA 2.0 · Mosca, *Cybersecurity,
an adversary's view* (2018).
