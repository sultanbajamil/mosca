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
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
┌───────────────┐        ┌────────────────┐        ┌──────────────────┐
│ scan/source   │        │ scan/config    │        │ net/tls          │
│ 148 rules     │        │ 23 rules       │        │ Node handshake + │
│ 16 languages  │        │ nginx/sshd/…   │        │ raw ClientHello  │
└───────┬───────┘        └───────┬────────┘        └────────┬─────────┘
        │ findings               │ findings                 │ endpoints
        └────────────────────────┼──────────────────────────┘
                                 ▼
                     ┌──────────────────────────┐
                     │ analysis/risk.js         │
                     │ Mosca inequality, score, │
                     │ severity, QRI, roadmap   │
                     └────────────┬─────────────┘
                                  │ analysis object
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
┌───────────────┐        ┌────────────────┐        ┌──────────────────┐
│ report/       │        │ report/cbom    │        │ report/sarif     │
│ terminal +    │        │ CycloneDX 1.6  │        │ SARIF 2.1.0      │
│ html          │        │                │        │                  │
└───────────────┘        └────────────────┘        └──────────────────┘
```

## Module map

| Path | Responsibility |
| --- | --- |
| `bin/mosca.js` | Executable shim; sets the process exit code |
| `src/cli.js` | Command grammar, output orchestration, exit codes |
| `src/index.js` | `scan()` pipeline and `exitCode()` |
| `src/config.js` | Defaults, scenarios, merge, data-class matching |
| `src/rules/algorithms.js` | 91-entry algorithm registry, aliases, replacements |
| `src/rules/source.js` | 148 source rules across 16 languages |
| `src/rules/config.js` | 23 rules for nginx, Apache, sshd, OpenSSL, Java, Kubernetes |
| `src/scan/source.js` | Walker integration, comment stripping, match → finding |
| `src/scan/config.js` | Config-file detection and rule application |
| `src/net/clienthello.js` | Raw TLS ClientHello builder and ServerHello parser |
| `src/net/x509.js` | Dependency-free DER/X.509 parser |
| `src/net/tls.js` | Endpoint inspection and endpoint finding derivation |
| `src/analysis/risk.js` | Mosca inequality, scoring, aggregates, roadmap |
| `src/report/terminal.js` | ANSI terminal report |
| `src/report/html.js` | Self-contained interactive report |
| `src/report/cbom.js` | CycloneDX 1.6 CBOM |
| `src/report/sarif.js` | SARIF 2.1.0 |
| `src/util/fs.js` | Walker, ignore rules, binary-safe reads, comment stripper |
| `src/util/log.js` | Colour, padding, score bars |

## Data flow

1. `cli.js` parses arguments and builds overrides.
2. `index.js` loads `mosca.json`, then runs the source scanner, the config
   scanner and endpoint inspection. Endpoint inspection is parallelised with
   `Promise.allSettled`; one unreachable host never fails the scan.
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
   so the terminal, HTML, CBOM and SARIF cannot disagree.
6. `cli.js` writes artefacts and returns an exit code derived from
   `--fail-on`.

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
- No CDN; the ~80 lines of JavaScript that implement the CRQC slider and the
  findings filter are inlined.
- All interpolated values pass through an HTML escaper, including project
  names, file paths and server errors.

The timeline is data-driven: each row carries `data-shelf` and `data-lead`, and
the slider recomputes exposure in the browser. The server-side score and the
client-side visual therefore use the same inequality.

### CBOM

Components are `cryptographic-asset` entries keyed by
`crypto/algorithm/<id>`. Repeated occurrences increment `evidence.occurrences`
instead of duplicating components. Each component carries:

- `cryptoProperties.algorithmProperties`: primitive, parameter set, mode,
  padding, crypto functions, classical security level, NIST quantum level.
- `properties`: quantum status, classical status, severity, primitive,
  replacement, standard, the Mosca inequality and the first location.

Certificates and negotiated protocols become first-class components, so the
CBOM describes the live estate as well as the source.

### SARIF

Rule ids are `mosca/<rule-id>`. Results include a `partialFingerprints` entry
built from rule id, URI and line, which is what lets GitHub code scanning
recognise the same issue after unrelated edits. Endpoint findings are excluded
because they have no file location; they appear in the CBOM and HTML instead.

## Testing strategy

`node --test` only, no framework:

| Area | What is asserted |
| --- | --- |
| `test/algorithms.test.js` | Shape of all 91 entries, replacement graph acyclic, alias resolution, TLS dialect mapping |
| `test/rules.test.js` | True and false positives for JS/Python/Go/Java plus nginx/sshd/OpenSSL |
| `test/clienthello.test.js` | Record framing, extension ordering, 1216-byte share, canonical coefficients, ServerHello and HRR parsing |
| `test/x509.test.js` | A real Cloudflare certificate, TLV boundaries, primitive decoders |
| `test/endpoint.test.js` | Target parsing, protocol normalisation, certificate summary, finding derivation |
| `test/risk.test.js` | Every scoring direction, Mosca inequality, QRI, HNDL n/a semantics, roadmap phases |
| `test/report.test.js` | CycloneDX shape, SARIF shape, HTML self-containment and escaping |
| `test/fs.test.js` | Globs, ignore files, binary rejection, comment stripping |
| `test/config.test.js` | Merge semantics, scenarios, data classes |
| `test/scan.test.js` | End-to-end scan, determinism, exit codes |

The suite runs in well under a second and needs no network access; the only
network-derived artefact is the committed DER fixture.

## Performance

A cold `mosca demo` scan (10 source files, 3 config files) completes in roughly
50 ms on a laptop. The walker is synchronous and single-pass; the expensive
part of a real scan is endpoint latency, which is parallelised. There is no
AST, no type checker and no subprocess, which is why the tool can be dropped
into a pre-commit hook or a CI step without a build stage.

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
