# CISO one-pager — Post-quantum exposure in 30 days

**Audience:** CISO, CIO, CTO, board risk committee
**Premise:** Harvest-now-decrypt-later turns recorded ciphertext into a future breach. The migration clock is not the certificate renewal cycle; it is the data retention obligation.

---

## 1. The decision

You do not need to choose a PQC vendor this quarter. You need to answer three questions with evidence:

1. **Where is quantum-vulnerable cryptography used today?** Source, config, artefacts, dependencies, live TLS/SSH, and recorded traffic.
2. **Which of those exposures already outlive the machine?** Apply `data shelf life + migration lead time > years to CRQC`.
3. **What will stop a regression next sprint?** A baseline gate in CI, not a spreadsheet.

MOSCA answers all three from one scan and produces the artefacts an auditor, a build pipeline and a board can each consume.

## 2. What the external benchmark says

*The State of Post-Quantum Readiness*, snapshot 2026-11-10, 68 observed endpoints across 10 sectors:

| Metric | Result | Implication |
| --- | --- | --- |
| Global QRI | **83.4/100 (A)** | Readiness is real but uneven. |
| Hybrid PQC adoption | **60.3%** | 4 in 10 observed endpoints still negotiate classical-only KEX. |
| HNDL exposure at 2033 | **41.2%** | Recordings of long-lived data are already dangerous. |
| Healthcare / government QRI | **77.1 (B)** | Respectable score, but **57.1%** HNDL exposure at a 25-year data lifetime. |
| Energy QRI | **66.7 (C)** | Lowest sector; 83.3% HNDL exposure at a 20-year lifetime. |
| Technology QRI | **94.4 (A+)** | Hybrid adoption is achievable at scale. |

**Board translation:** a B-grade TLS posture is not a B-grade data-risk posture. The difference is retention.

## 3. The 30-day plan

### Week 1 — Measure the estate

```bash
# source, config, artefacts, dependencies, live endpoints
mosca scan . \
  --tls api.example.com,www.example.com \
  --ssh bastion.example.com \
  --compliance all \
  --format html,cbom,sarif,json \
  --out pqc-baseline

# audit captures already on disk (read-only, no packets sent)
mosca pcap captures/edge.pcap --out pqc-captures
```

Deliverables: QRI, ranked findings, CBOM, SARIF, HNDL Captured Ratio.

### Week 2 — Classify data lifetimes

Set the confidentiality lifetime per business domain in `mosca.json`:

```json
{
  "dataClasses": [
    { "pattern": "**/health/**", "years": 25, "label": "patient records" },
    { "pattern": "**/finance/**", "years": 10, "label": "financial records" },
    { "pattern": "**/pii/**", "years": 15, "label": "personal data" }
  ]
}
```

The same weak primitive in a 25-year data path is a different risk from one in a 7-year path. The model should say so.

### Week 3 — Gate the regressions

```bash
mosca scan . --write-baseline .mosca-baseline.json
# CI:
mosca scan . --baseline .mosca-baseline.json --fail-on high --format sarif
```

Accept historical debt deliberately. Fail only on new exposure. Attach the CBOM to the release.

### Week 4 — Report to the board

Publish:
- QRI and trend vs. baseline;
- % of internet-facing key exchange that is classical-only;
- % of recorded sessions classical-only (HNDL Captured Ratio);
- top three migration sites with owner and effort estimate;
- compliance status against CNSA 2.0 / NIST 2030 / PCI DSS / HIPAA.

## 4. Metrics that belong in the risk register

| Metric | Source | Target |
| --- | --- | --- |
| Quantum Readiness Index (QRI) | `mosca scan` | Up and to the right, with a dated plan |
| Hybrid KEX adoption on internet-facing endpoints | `mosca tls` / benchmark | 100% of externally reachable TLS |
| HNDL exposure of long-lived data | `mosca scan` / `mosca pcap` | 0% for data with lifetime > years to CRQC |
| New findings per release | baseline diff | 0 at `high` or above |
| CBOM coverage | `bom.cdx.json` | Every production service has one |
| Classical debt (legacy TLS, weak ciphers, deprecated host keys) | benchmark / scan | Down each quarter |

## 5. Procurement questions

Ask any PQC vendor or migration partner:

1. Do you report **negotiated** key exchange, or only advertised support?
2. Does your model anchor exposure to the **recording date**, or to today?
3. Can you show the **raw evidence** behind a "hybrid enabled" claim?
4. Does the output feed a CBOM and a CI gate, or only a dashboard?
5. What is your false-positive rate on the languages and protocols we actually run?
6. Can the tool run with **zero runtime dependencies** inside a regulated pipeline?

## 6. What MOSCA is not

- Not a prediction of when a CRQC arrives. The year is an assumption you set and disclose.
- Not an authenticated scanner. It does not log in or test application logic.
- Not an estate census. Public benchmarks are a floor; internal services need their own scan.
- Not a magic fix. `mosca fix` proposes conservative literal swaps and advisories; protocol and trust-chain migrations stay manual.

## 7. One-sentence summary for the board

**We can now measure which of our cryptographic protections will fail after the quantum computer arrives, which recordings are already exposed, and whether each release makes the problem better or worse.**

---

**Links**
- Repository: https://github.com/sultanbajamil/mosca
- State of PQC report: https://sultanbajamil.github.io/mosca/state-of-pqc.html
- Methodology: https://github.com/sultanbajamil/mosca/blob/main/docs/METHODOLOGY.md
- Architecture: https://github.com/sultanbajamil/mosca/blob/main/docs/ARCHITECTURE.md
