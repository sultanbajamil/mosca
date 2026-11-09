# MOSCA

**CI-native post-quantum exposure scanner for code, configuration, live TLS and SSH endpoints.**

[![CI](https://github.com/sultanbajamil/mosca/actions/workflows/ci.yml/badge.svg)](https://github.com/sultanbajamil/mosca/actions/workflows/ci.yml)
[![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)](scripts/check-zero-deps.js)
[![tests: 112](https://img.shields.io/badge/tests-112-brightgreen)](test/)
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
  languages, 23 configuration rules for nginx, Apache, OpenSSH, OpenSSL,
  Java and Kubernetes, and 91 classified algorithms.
- **Probes TLS with a hand-built ClientHello** that offers
  `X25519MLKEM768` (0x11EC) and reports the group the *server* selected.
  Node's own TLS stack cannot do this, so neither can tools that inherit it.
- **Probes SSH with a hand-built `SSH_MSG_KEXINIT`** and reads the server's
  advertised KEX, host-key, cipher and MAC lists — including
  `mlkem768x25519-sha256` and `sntrup761x25519-sha512@openssh.com`.
- **Diffs against a baseline.** Accept the debt you already have, then fail CI
  only when a change introduces a new exposure.
- **Emits artefacts**: an interactive self-contained HTML report, a
  CycloneDX 1.6 **CBOM**, and **SARIF 2.1.0** for GitHub code scanning.

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
mosca scan [path] [options]     # source + config + TLS + SSH
mosca tls <host...>             # probe live TLS endpoints only
mosca ssh <host...>             # probe SSH servers only
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
| `--baseline <file>` | Compare against a baseline; `--fail-on` considers only new findings |
| `--write-baseline <file>` | Write this run's findings as the new baseline |
| `--format <list>` | `html,json,cbom,sarif,term` (default `html,term`) |
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
  uses: sultanbajamil/mosca@v2
  with:
    path: .
    tls: example.com,api.example.com
    ssh: bastion.example.com
    baseline: .mosca-baseline.json
    fail-on: high
    format: html,sarif,json,cbom

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mosca-report/mosca.sarif
```

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
no network access. It also contains the findings table with severity and
"new since baseline" filters, TLS and SSH endpoint cards, a CRQC sensitivity
strip, the algorithm inventory and the phased roadmap.

A generated example is committed at [`docs/index.html`](docs/index.html).

### CBOM (CycloneDX 1.6)

```bash
mosca scan . --format cbom --out out
# out/bom.cdx.json — cryptographic-asset components with
# cryptoProperties.algorithmProperties, NIST quantum level, and
# mosca:* properties (status, replacement, inequality, location).
# TLS and SSH servers appear as protocol assets with their KEX lists.
```

### SARIF 2.1.0

Every actionable code finding becomes a SARIF result with a stable,
line-independent `partialFingerprints.moscaFingerprint`, so GitHub code
scanning tracks an issue across commits instead of re-opening it. Baseline
runs also set `baselineState` to `new` or `unchanged`.

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

Expected result: **53 findings** (16 critical, 21 high, 11 medium), QRI
**24.6/100**, ~25 engineer-days of estimated migration effort, in under a second.
Add live endpoints for the full picture:

```bash
node bin/mosca.js demo --tls cloudflare.com,github.com,en.wikipedia.org,example.com --ssh github.com
# 73 findings · QRI 29.6/100 · HNDL exposure 28.6% · 4 TLS + 1 SSH endpoint
```

## Development

```bash
npm run check   # zero-dependency guard + 112 tests
npm test        # node:test only
npm run demo
```

No build step, no transpiler, no test framework to install. The test suite
covers the algorithm registry invariants, 20+ rule true/false positives, DER
X.509 parsing against a real Cloudflare certificate, ClientHello construction
and ServerHello parsing, the risk model, all three report formats, the file
walker, configuration handling and an end-to-end scan.

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
