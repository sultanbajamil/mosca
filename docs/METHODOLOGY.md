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
2027–2045 slider precisely so the reader can test their own belief.

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
| `surface` | endpoint = 1.0, config = 0.6, source = 0.3 |

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
weight_i        = endpoint ? 3 : config ? 2 : source ? 1
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

Only endpoint findings with primitive `key-agreement` participate. When no
endpoint was inspected the value is reported as **n/a**, not 0%, because "we
did not look" and "we looked and found nothing" are different statements. This
distinction is enforced in the terminal report, the HTML report and the CBOM
(`mosca:harvestNowDecryptLaterExposure = "n/a"`).

## 8. Effort estimate

A deliberately simple order-of-magnitude estimate:

```
effort = Σ  base(kind) × (quantum === 'broken' ? 1 : 0.5)
base   = endpoint 3 | config 1 | source 0.5   (engineer-days)
```

It excludes the roadmap's fixed programme costs and coordination overhead, so
it is labelled "estimated effort", not a quote. The roadmap recomputes effort
per phase without the quantum multiplier so the phases sum to a comparable
number.

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
   the wrapper name matches a rule. The reverse is also possible: a comment or
   string that looks like an API call is stripped where possible, but template
   languages and generated code can defeat comment stripping.
2. **Counts are lexical, not linked.** Migration lead time counts occurrences,
   not distinct call paths. A shared helper counted ten times overstates the
   work; a dynamically dispatched algorithm counted zero times understates it.
3. **TLS probes are unauthenticated and single-shot.** A transient network
   failure is reported as `unreachable`, not as a finding. Legacy-version
   acceptance is verified with one ClientHello offering TLS 1.0 and 1.1;
   middleboxes can influence the answer.
4. **The CRQC year dominates every conclusion.** That is the point. Change
   `--scenario` and watch the exposure count move. If a vendor tells you a
   single number without that assumption, ask what it is.

## 12. References

- Mosca, M. (2018). *Cybersecurity in an era with quantum computers: will we
  be ready?* IEEE Security & Privacy.
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), August 2024.
- NIST IR 8547 (initial public draft), *Transition to Post-Quantum Cryptography
  Standards*.
- NSA CNSA 2.0, *Commercial National Security Algorithm Suite 2.0*.
- RFC 8446 (TLS 1.3), RFC 8996 (deprecating TLS 1.0/1.1).
- `draft-ietf-tls-ecdhe-mlkem`, *Hybrid ECDHE-MLKEM Key Agreement for TLS 1.3*.
- CycloneDX 1.6 specification, cryptography extension.
- SARIF 2.1.0, OASIS.
