# FOR IMMEDIATE RELEASE

## New benchmark finds 41% of publicly reachable endpoints carry data that a 2033 quantum computer could read — and most organisations cannot tell which recordings are already exposed

**MOSCA v3.1 launches with passive packet-capture auditing, a global sector benchmark, and a zero-dependency scanner that applies Mosca's inequality to code, TLS, SSH and recorded traffic.**

**LONDON — 10 November 2026** — MOSCA, the open-source post-quantum exposure scanner, today published *The State of Post-Quantum Readiness*, a benchmark of 68 publicly reachable endpoints across ten sectors. The headline finding: at a 2033 cryptographically relevant quantum computer (CRQC) assumption, **41.2% of observed endpoints carry data whose confidentiality lifetime outlives the machine** — even where the endpoint negotiates modern TLS.

The benchmark also found that only **60.3%** of observed endpoints negotiate a post-quantum hybrid key exchange. Technology (94.4/100, A+) and cloud infrastructure (94.3/100, A+) lead. Energy trails at **66.7/100 (C)**. Healthcare and government both score **77.1/100 (B)**, but because their data must remain confidential for 25 years, **57.1%** of their observed endpoints are inside the harvest-now-decrypt-later window.

"Most post-quantum programmes are inventories, not exposure calculations," said Sultan Bajamil, creator of MOSCA. "They can tell you that RSA is deprecated. They cannot tell you that a recording made in 2016 of a twenty-five-year secret is already a disclosure in progress. The difference is a date, and most tools throw the date away."

### The recording is the breach

Harvest-now-decrypt-later (HNDL) does not require a quantum computer today. An adversary records TLS or SSH sessions now and waits. MOSCA's model is built on **Mosca's inequality**:

```text
exposed  ⇔  data shelf life + migration lead time  >  years until a CRQC
```

The new `mosca pcap` command applies the inequality to packet captures already on disk. It reads classic PCAP and PCAPNG without a native packet library, decodes Ethernet, 802.1Q, Linux SLL and raw IP, reassembles TCP, and parses TLS ClientHello/ServerHello and SSH banners plus `SSH_MSG_KEXINIT`. Crucially, it anchors exposure to the **capture timestamp**: a session recorded in 2010 has had longer to fall inside the window than one recorded this morning.

The command sends no packets, performs no authentication, and reports a single board-level metric: the **HNDL Captured Ratio** — the share of recorded sessions that are classical-only.

### A benchmark you can replay

`mosca benchmark` probes the curated target set with a concurrency cap of 10 and a five-second timeout, then publishes an interactive page with an A+–F leaderboard, sector filters, a 2027–2045 CRQC slider and screenshot-ready insight cards.

Unlike a press-cycle dashboard, the benchmark is reproducible. The repository ships the raw handshake snapshot (`benchmarks/snapshot.json`), and CI regenerates the published report by replaying it. The numbers change when the evidence changes, not when a CDN rotates a key share.

### Built for regulated pipelines

MOSCA v3.1 remains **zero runtime dependencies**, pure ESM, Node.js 20 or newer. It emits CycloneDX 1.6 CBOM, SARIF 2.1.0, Mermaid diagrams, a self-contained HTML report and locally generated QRI/HNDL SVG badges. The GitHub Action now accepts PCAP captures, badge output and a benchmark snapshot as first-class inputs.

"Security teams are being asked to certify a migration they cannot measure," Bajamil added. "The useful artefact is not a slide that says 'quantum-ready by 2030'. It is a bill of materials with owners, a baseline that fails the build on a regression, and a recording audit that says which captures are already dangerous."

### Availability

MOSCA is available under the MIT licence at **https://github.com/sultanbajamil/mosca**. The interactive State of PQC report is published at **https://sultanbajamil.github.io/mosca/state-of-pqc.html**. The npm package is `mosca-pqc`; the CLI command is `mosca`.

### About

MOSCA is an independent open-source project focused on making post-quantum exposure measurable at the level where decisions are made: the finding, the recording, the sector and the build pipeline.

### Media contact

Sultan Bajamil
GitHub: https://github.com/sultanbajamil
Email: [add contact before distribution]

### Notes to editors

- The benchmark covers 69 targets; 68 answered within the probe timeout. One target is reported as unobserved rather than scored.
- Scores measure the negotiated handshake, not internal estate coverage, certificate policy or configuration drift.
- HNDL exposure uses each sector's data lifetime plus a one-year migration lead, compared with the years remaining to the stated CRQC year (2033 by default).
- Grades: A+ ≥ 90, A ≥ 80, B ≥ 70, C ≥ 60, D ≥ 50, E ≥ 40, F < 40.
- All figures are reproducible from `benchmarks/snapshot.json` in the public repository.
