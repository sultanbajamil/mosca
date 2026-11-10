# Show HN: MOSCA — a post-quantum exposure scanner with zero dependencies

## Title options

1. **Show HN: I scanned 68 public endpoints for post-quantum readiness. 41% are already exposed**
2. **Show HN: MOSCA – find crypto that a future quantum computer will break, including in old packet captures**
3. **Show HN: A zero-dependency PQC scanner that applies Mosca's inequality to code, TLS, SSH and PCAPs**

## Body

Hi HN,

I built MOSCA because every "post-quantum readiness" dashboard I saw answered the wrong question. They list algorithms. The question that decides whether you have a breach is temporal:

> If an adversary records this traffic today, when does it become readable?

That is **Mosca's inequality**: `data shelf life + migration lead time > years until a CRQC`. When the sum is larger, the recording is already a disclosure in progress. A perfect TLS 1.3 configuration does not help if the data must stay secret for 25 years and the machine arrives in 7.

MOSCA applies that model to a unified inventory:

- **Source and config** — 148 rules across 16 languages, 62 config/IaC rules, constant propagation so `const HASH = 'md5'` does not slip through.
- **Artefacts and supply chain** — PEM/DER/JWK/OpenSSH metadata and eight lockfile formats.
- **Live endpoints** — raw TLS ClientHello offering `X25519MLKEM768`, raw `SSH_MSG_KEXINIT`, STARTTLS, QUIC and IKEv2.
- **Recorded sessions** — new in v3.1: `mosca pcap` reads classic PCAP and PCAPNG, reassembles TCP, parses ClientHello/ServerHello and SSH banners/KEXINIT, and anchors exposure to the **capture date**. A session recorded in 2016 gets the 2016 clock, not today's.
- **A global benchmark** — `mosca benchmark` probes 69 named organisations across 10 sectors and publishes an interactive A+–F leaderboard with a 2027–2045 CRQC slider.

Two things I care about:

1. **Zero runtime dependencies.** Node ≥ 20, pure ESM, no native packet library, no OpenSSL bindings. A security scanner that drags a transitive tree into a regulated build pipeline is a supply-chain problem of its own.
2. **Every number is reproduceable.** The benchmark ships its raw handshake snapshot. CI replays it; the page does not move because a CDN rotated a key share. The self-scan runs in CI against the repository itself.

### What the benchmark found (snapshot 2026-11-10)

- **68 of 69** endpoints observed; global QRI **83.4/100 (A)**.
- **60.3%** negotiate a post-quantum hybrid key exchange.
- At a 2033 CRQC, **41.2%** carry data whose lifetime outlives the machine.
- Technology leads at **94.4 (A+)**; cloud **94.3 (A+)**; energy trails at **66.7 (C)**.
- Healthcare and government both score **77.1 (B)** — but their 25-year data lifetime means **57.1%** HNDL exposure, the highest legal-risk pairing in the set.

Interactive report: https://sultanbajamil.github.io/mosca/state-of-pqc.html

### Try it

```bash
npx mosca-pqc scan .
npx mosca-pqc tls cloudflare.com github.com
npx mosca-pqc ssh git.example.com:2222
npx mosca-pqc pcap capture.pcap
npx mosca-pqc benchmark --snapshot benchmarks/snapshot.json
```

Repo: https://github.com/sultanbajamil/mosca

No build step, no test framework, no `node_modules`. `npm run check` runs a zero-dependency guard and 231 tests. The PCAP tests generate real binary captures programmatically - TLS and SSH, Ethernet, VLAN, Linux SLL, PCAPNG - rather than mocking a packet object.

### Things I would like feedback on

- Which sectors or endpoints should be added to the benchmark? I deliberately kept it to publicly reachable, unauthenticated handshakes.
- Is the 1-year migration lead assumption in the HNDL calculation too generous, too conservative, or the wrong shape entirely?
- What is missing from the CBOM output for Dependency-Track or an actual auditor workflow?
- If you run it on a real estate and the score looks wrong, I would rather see the false positive than a nice demo.

I am happy to answer anything about the wire formats, the scoring model, or why the benchmark is a floor rather than a census.

## First comment (post immediately after submission)

A few implementation notes that did not fit in the post:

- The TLS probe does not use Node's TLS stack to decide the group. It writes the ClientHello by hand, generates a canonical ML-KEM-768 encapsulation key, places it before the X25519 share as `draft-ietf-tls-ecdhe-mlkem` requires, and reads the selected group from the ServerHello. That is the only way to test `X25519MLKEM768` when the local runtime cannot negotiate it.
- The SSH probe never authenticates. It exchanges identification strings, sends a minimal KEXINIT, parses the server's name-lists and hangs up. For captures, it performs first-match agreement between both KEXINIT directions, because that is what the recording actually used.
- The PCAP parser is about 900 lines of `node:fs` and `Buffer`. It handles both PCAP endiannesses, micro/nanosecond timestamps, PCAPNG SHB/IDB/EPB/SPB, stacked VLAN tags, Linux SLL/SLL2, IPv4/IPv6, and TLS records split across TCP segments.
- The score model is documented, including the weights and the severity asymmetry: classically broken primitives are critical even if the numeric score is not the highest.
- The HTML reports and benchmark pages are single files with inline CSS/JS and no external requests. The benchmark snapshot is committed so the page is stable.

## Notes for the submitter

- Post between 08:00 and 10:00 UTC on a weekday.
- Do not ask for upvotes. Reply to technical questions with links to the relevant module.
- If someone reports a false positive, ask for the file or capture shape and turn it into a fixture. That is the best possible thread.
- The strongest hook is the headline number, not the feature list. Lead with 41% and the capture-date argument.
