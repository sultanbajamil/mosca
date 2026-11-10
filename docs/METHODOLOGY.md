# Methodology

This document specifies every number MOSCA reports. It exists so a reviewer
can disagree with a weight and change it, rather than guess what the tool did.

## 1. The theorem

Mosca's inequality (Mosca, 2018) states that a system is quantum-safe only if

```
shelfLife + migrationLeadTime ≤ yearsToCRQC
```

where:

| Symbol | Meaning | Source in MOSCA |
| --- | --- | --- |
| `shelfLife` | Years the protected data must remain confidential | Path-based data class, default 7 years |
| `migrationLeadTime` | Years needed to replace the primitive everywhere | Derived from occurrence count (§3) |
| `yearsToCRQC` | Years until a cryptographically relevant quantum computer | Scenario or explicit year (§2) |

When the inequality is violated, the finding is marked `exposed`. This is the
harvest-now-decrypt-later condition: ciphertext recorded today contains the
plaintext of tomorrow. For signatures the same arithmetic matters differently
— a signature forged later does not retroactively invalidate a past decision —
so the report labels each finding `confidentiality` or `integrity` and the
roadmap prioritises confidentiality first.

### Why shelf life is a first-class input

A seven-year default is deliberately conservative and deliberately visible.
Healthcare records use 25 years, genomic data 50, backups 20, billing 10. The
same AES-128-CBC is medium severity in a utility module and high severity in
`services/billing/`. Hiding this behind one global number would make the score
look objective when it is not.

Matching is first-match-wins over the configured `dataClasses`, using a glob
with `**` support against the path with `/` separators. Windows backslashes are
normalised first. When nothing matches, the label is `general` and the value is
`defaultShelfLife`.

## 2. CRQC assumptions

| Scenario | Year | Intended use |
| --- | --- | --- |
| `aggressive` | 2029 | Adversary with a well-funded, focused programme |
| `moderate` | 2033 | Default; aligns with the CNSA 2.0 transition horizon |
| `conservative` | 2038 | Sceptical planning; still after most data-retention windows |

`yearsToCRQC = max(0, crqcYear - currentYear)`, using the scan year in UTC.
The number is an input, not a prediction. The interactive report exposes a
2029–2045 slider precisely so the reader can test their own belief.

## 3. Migration lead time

```
migrationLeadTime = 1 + min(4, log2(count + 1) / 2)
```

`count` is the number of occurrences of the algorithm in the scanned estate,
not the number of files. The curve is intentionally shallow: replacing a
primitive used once is a sprint; replacing one used a thousand times is a
programme, but even a thousand sites does not take a decade — it takes
coordination. The function is bounded to `[1, 5]` years.

Examples:

| Occurrences | Lead time |
| --- | --- |
| 1 | 1.5 years |
| 5 | 2.3 years |
| 50 | 3.8 years |
| 250+ | 5.0 years |

Since v3 the count used here is the number of **unique migration sites**, not
raw occurrences. A site is keyed by `kind | algorithm | where | normalised
match`, so the same call copied into ten files counts once per file but a
repeated identical anchor in one file counts once. The effort estimate adds a
damped spread for duplicates: `1 + 0.15 × log2(1 + duplicates)`. This keeps a
repeated helper from inflating a programme while still acknowledging the
coordination cost of many identical edits.

## 4. The finding score

Each finding receives a score in `[0, 100]`, rounded to one decimal:

```
score = 100 × (
    0.40 × quantum
  + 0.20 × durability
  + 0.15 × breadth
  + 0.15 × classical
  + 0.10 × surface
)
```

### Factor definitions

| Factor | Value |
| --- | --- |
| `quantum` | `broken` = 1.0, `weakened` = 0.5, `unknown` = 0.4, `safe` = 0 |
| `durability` | `min(1, shelfLife / 30)` |
| `breadth` | `min(1, log2(count + 1) / 6)` |
| `classical` | `broken` = 1.0, `weak` = 0.6, `acceptable` = 0.2, `strong` = 0 |
| `surface` | endpoint = 1.0, chain = 1.0, config = 0.6, dependency = 0.55, artifact = 0.5, source = 0.3 |

### Why these weights

- **Quantum 0.40.** It is the reason the tool exists. A primitive that falls to
  Shor is not a hygiene issue; it is a countdown.
- **Durability 0.20.** The second half of Mosca's inequality. Without it the
  score collapses into "is this algorithm old?".
- **Breadth 0.15.** Migration cost is the variable organisations control least.
  A finding that appears once is a ticket; one that appears 400 times is a
  budget line.
- **Classical 0.15.** MD5 and SHA-1 are broken now. They must not be diluted by
  a quantum-only model.
- **Surface 0.10.** Internet-facing code is exposed to recording today;
  internal code is not. The weight is small because internal code still becomes
  exposed the moment it is reached.

Weights live in `DEFAULT_CONFIG.weights` and are deep-merged from
`mosca.json`. They must sum to 1; the model does not renormalise silently.

### Positive findings

A finding is **positive** when the primitive is quantum-safe *and* at least
classically acceptable — for example SHA-256, AES-256-GCM, ML-KEM-768. Positive
findings score 0, are reported as `info`, are excluded from `actionable`, and
are hidden from the findings table by default. They remain in the CBOM so the
inventory is complete.

## 5. Severity

Severity is not a pure function of the score. The order of rules is:

1. Positive → `info`.
2. `classical === 'broken'` → `critical` (exploitable today).
3. `quantum === 'safe'` → `info`.
4. Score ≥ 70 → `critical`.
5. Score ≥ 45 → `high`.
6. Score ≥ 25 → `medium`.
7. Score ≥ 10 → `low`.
8. Otherwise → `info`.

Two adjustments follow:

- An **endpoint** finding that is inside the Mosca window is escalated one band
  unless already critical.
- A finding with **low confidence** is downgraded one band.

Bands map to priorities `P0`–`P3`. SARIF uses `critical/high → error`,
`medium → warning`, `low/info → note`, with `security-severity` 9.5/8.0/5.5/3.0.

## 6. Quantum Readiness Index (QRI)

QRI is a weighted share of the estate that is already quantum-safe:

```
weight_i        = endpoint ? 3 : captured-session ? 3 : chain ? 3 : config ? 2 : dependency ? 2 : artifact ? 2 : source ? 1
safety_i        = safe 1.0 | weakened 0.5 | unknown 0.3 | broken 0
QRI             = 100 × Σ(weight_i × safety_i) / Σ(weight_i)
```

An empty estate scores 100 by convention (nothing to migrate), and the report
says so. QRI is a communication device, not a compliance certification: it
mixes a live TLS finding with a source-code finding deliberately, because an
organisation's exposure does not respect those boundaries.

## 7. Harvest-now-decrypt-later exposure

```
HNDL = 100 × classical key-exchange findings / all key-exchange findings
```

Only endpoint findings with primitive `key-agreement` participate, from TLS
and SSH alike: a recorded SSH session is as readable after a CRQC as a
recorded TLS session. When no endpoint was inspected the value is reported as
**n/a**, not 0%, because "we did not look" and "we looked and found nothing"
are different statements. This distinction is enforced in the terminal report,
the HTML report and the CBOM
(`mosca:harvestNowDecryptLaterExposure = "n/a"`).

## 7a. CRQC sensitivity

The headline number uses one planning assumption. The sensitivity table
recomputes the exposed set for 2029, 2033, 2038 and 2045:

```
exposed(year) = findings where shelfLife + migrationLeadTime > (year - currentYear)
```

The purpose is to separate robust decisions from assumption-dependent ones. A
finding that is exposed under every date is a present-day migration problem; a
finding that only appears under the 2029 scenario is a bet on an aggressive
timeline. The table is emitted in JSON (`summary.sensitivity`), printed as a
compact strip in the terminal and rendered as cards in the HTML report.

## 7b. Certificate-chain projection

Chain findings use the transport surface and the endpoint shelf life. The
projection is a separate, deliberately transparent calculation:

```
flight(pqc) = Σ certificate public-key bytes + signature bytes + framing
exceeds     = flight(pqc) > INITIAL_CWND (14 336 bytes)
```

Signature and public-key sizes come from `PQC_SIZES` (ML-DSA-44/65/87,
SLH-DSA-128s/128f/192s/256s). The comparison is against the 14 KB initial
congestion window, not the path MTU: exceeding it adds a round-trip and makes
every handshake slower, which is an operational finding rather than a wire
error. A chain whose weakest entry is SHA-1 or a classical long-lived root is
reported independently of the projection.

## 7c. Compliance evaluation

Compliance is a mapping, not a second risk model. Each standard declares
controls with a predicate over enriched findings:

| Standard | Controls (summary) |
| --- | --- |
| `cnsa2` | ML-KEM key establishment, ML-DSA/ML-DSA-87 signatures, AES-256, SHA-384 |
| `nist-2030` | No RSA/ECC/DSA/EdDSA after 2030; removal by 2035 |
| `pci-dss` | TLS ≥ 1.2, no RC4/3DES/DES, RSA ≥ 2048, no MD5/SHA-1, HNDL exposure |
| `hipaa` | ePHI in transit and at rest, integrity, long-retention HNDL |

A control is `pass` when no finding violates it, `fail` when one or more do,
and `partial` when violations are limited to non-production surfaces. The
standard score is `100 × weighted passed controls / total`, rounded to one
decimal. Violations carry the finding fingerprint, so a gate can point at the
exact line or endpoint. `--fail-on-compliance` exits 1 when the selected
standard is `fail`.

## 7d. Fix policy

`mosca fix` is a suggestion engine with a narrow automatic boundary:

- **Automatic hunk**: hash, MAC or AES key-size literal swap where the target
  is unambiguous and the file is not a protocol implementation or test vector.
- **Advisory**: signatures, key agreement, certificates, protocol config,
  lockfiles and live listeners. Symmetric changes inside
  `net|protocol|tls|quic|ssh|ikev2|ipsec|test|spec|fixtures` paths are also
  advisory, because the literal is part of a wire format or an oracle.

The planner never edits a file. `buildPatch()` emits a unified diff with CRLF
preservation and records skipped hunks when the literal has moved, so a stale
finding produces a visible skip instead of a corrupt patch.

## 7e. Captured sessions and the HNDL Captured Ratio

A PCAP is a different observation from a live probe. The question is not what a
server supports today, but what a session negotiated when it was recorded:

```
captureYear     = UTC year of the first packet in the flow
yearsToCRQC     = max(0, crqcYear - captureYear)
exposed         = classicalKex && shelfLife > yearsToCRQC
capturedRatio   = 100 × classical sessions / all captured sessions
```

Anchoring to `captureYear` is the whole point. A ten-year secret recorded in
2010 is 23 years from a 2033 CRQC, not seven; a fresh scan of the same host
would report a different answer. Findings carry `captureYear`, `captureTime`
and `capturedProtocol`, and the risk engine uses the same shelf-life and
migration-lead inputs as a live endpoint.

Captured sessions do **not** enter the live HNDL exposure denominator. A host
with no reachable endpoint but a directory of captures is not an empty estate;
it is a capture audit, and the report says so. The CBOM exposes both metrics:

```
mosca:harvestNowDecryptLaterExposure = "n/a" | "<percent>%"
mosca:hndlCapturedRatio              = "n/a" | "<percent>%"
```

## 8. Effort estimate

A deliberately simple order-of-magnitude estimate:

```
effort = Σ  base(kind) × (quantum === 'broken' ? 1 : 0.5)
base   = endpoint 3 | captured-session 3 | chain 3 | config 1 | dependency 1 | artifact 1 | source 0.5
           (engineer-days per unique migration site)
```

It excludes the roadmap's fixed programme costs and coordination overhead, so
it is labelled "estimated effort", not a quote. Duplicate occurrences add the
damped spread described in §3. The roadmap recomputes effort per phase without
the quantum multiplier so the phases sum to a comparable number.

## 9. Roadmap ordering

Phases are ordered by dependency, not severity alone:

| Phase | Window | Selection |
| --- | --- | --- |
| 0. Stop the bleeding | 0–3 months | classically broken or critical |
| 1. Inventory and crypto-agility | 0–6 months | protocol and certificate findings |
| 2. Hybrid key exchange | 3–12 months | non-safe key agreement |
| 3. Post-quantum signatures | 6–18 months | non-safe signatures |
| 4. Symmetric and hashing hygiene | 12–24 months | weakened or classically weak |
| 5. Verify and decommission | ongoing | re-scan; no static items |

A finding can match more than one phase conceptually; it is assigned to the
first matching phase so the counts do not double. Key exchange precedes
signatures because HNDL damage cannot be repaired after the fact, while a
signature migration can be completed before the forgery window opens.

## 10. Confidence

| Level | Meaning | Effect |
| --- | --- | --- |
| `high` | A specific API or configuration directive was matched | none |
| `medium` | A generic pattern (for example a bare `RSA` token) | none |
| `low` | Context-dependent policy or a heuristic | severity −1 band |

Rules may carry a `note`; when they do not, the registry's note for the
algorithm is used. Notes are shown in the terminal and HTML reports and become
the SARIF rule description, so the reviewer sees the reasoning, not just the
verdict.

## 11. Known sources of error

1. **Regex rules cannot see dataflow.** A wrapper function named `safeHash`
   that calls MD5 internally will be flagged at the wrapper's call site only if
   the wrapper name matches a rule. Constant propagation covers only a
   single-assignment string in the same file; it is not a type system. Template
   languages and generated code can still defeat comment stripping.
2. **Counts are lexical, not linked.** Unique-site effort is a better proxy than
   raw occurrences, but a shared helper called from ten packages is still
   counted once per file. Dynamically dispatched algorithms can be missed.
3. **TLS, STARTTLS, QUIC and IKEv2 probes are unauthenticated and single-shot.**
   A transient network failure is reported as `unreachable`, not as a finding.
   Legacy-version acceptance is verified with one ClientHello; middleboxes can
   influence the answer. QUIC and IKEv2 are UDP and can be filtered even when
   the service exists.
4. **Artefact scanning reads metadata, not key strength.** A public key is
   classified by its declared algorithm and size. It cannot tell whether the
   private half is stored in an HSM, a vault or a laptop.
5. **The CRQC year dominates every conclusion.** That is the point. Change
   `--scenario` and watch the exposure count move. If a vendor tells you a
   single number without that assumption, ask what it is.
6. **A capture is not an estate.** `mosca pcap` sees only the flows in the
   file. Missing packets, TLS 1.3 application data, non-TCP transports and
   traffic that was never recorded are reported as unobserved, not inferred.
   The HNDL Captured Ratio is a property of the recording, not of the network.

## 12. Benchmark scoring

The benchmark deliberately uses a different score from the finding risk model.
A finding score answers "how exposed is this item?"; a benchmark score answers
"how ready is this endpoint?".

```
start  = 100
TLS    −40  no hybrid key exchange
       −20  negotiated TLS 1.0 or 1.1
       −15  weak cipher (RC4, 3DES, DES, NULL, EXPORT)
SSH    −15  no hybrid key exchange
debt    −5  per additional classical-debt signal, capped at −20
```

Classical-debt signals are: legacy TLS version, weak cipher, accepted legacy
version, legacy SSH host key (`ssh-rsa`, `ssh-dss`), weak KEX
(`diffie-hellman-group1-sha1`, SHA-1 variants), CBC ciphers and MD5/SHA-1 MACs.
A target with neither TLS nor SSH reachable is excluded from the average
(`observed = false`) rather than scored as zero.

Grade bands: A+ ≥ 90, A ≥ 80, B ≥ 70, C ≥ 60, D ≥ 50, E ≥ 40, F < 40.

Sector aggregation:

```
sectorQRI       = mean(observed target scores)
hybridAdoption  = 100 × observed targets with hybrid KEX / observed targets
hndlExposure    = 100 × classical targets where lifetime + 1 > yearsToCRQC
                  / observed targets
```

Each target uses its sector's data lifetime for the HNDL calculation, so a
sector with a high QRI and a 25-year retention obligation can still carry a
high exposure percentage. The benchmark is a floor over publicly reachable
endpoints, not a census: internal services, authenticated APIs and
configuration drift are out of scope. The raw handshake snapshot is committed
so the published page is reproducible.

## 13. References

- Mosca, M. (2018). *Cybersecurity in an era with quantum computers: will we
  be ready?* IEEE Security & Privacy.
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), August 2024.
- NIST IR 8547 (initial public draft), *Transition to Post-Quantum Cryptography
  Standards*.
- NSA CNSA 2.0, *Commercial National Security Algorithm Suite 2.0*.
- RFC 8446 (TLS 1.3), RFC 8996 (deprecating TLS 1.0/1.1).
- RFC 9001 (Using TLS to Secure QUIC), RFC 9370 (Multiple Key Exchanges in IKEv2).
- `draft-ietf-tls-ecdhe-mlkem`, *Hybrid ECDHE-MLKEM Key Agreement for TLS 1.3*.
- CycloneDX 1.6 specification, cryptography extension.
- SARIF 2.1.0, OASIS.
