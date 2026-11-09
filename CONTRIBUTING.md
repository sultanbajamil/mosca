# Contributing to MOSCA

Thanks for taking the time. This project has an unusually strict constraint —
**zero runtime and development dependencies** — and a short set of conventions
that keep the scanner fast and auditable.

## Setup

```bash
git clone https://github.com/<owner>/mosca.git
cd mosca
node --version    # must be >= 20
npm run check     # zero-dependency guard + full test suite
npm run demo      # scan the bundled vulnerable estate
```

There is no build step. Edit a file, run the tests, run the demo.

## Ground rules

1. **No dependencies.** Not runtime, not dev. If you need a capability, write
   it in `src/util/` or `src/net/`. `scripts/check-zero-deps.js` enforces this
   in CI.
2. **Every behaviour gets a test.** Tests use `node:test` and `node:assert/strict`.
   No network access in tests; commit a fixture if you need real data.
3. **Findings are data, not prose.** A rule produces a normalised finding; the
   reporter decides how to present it. Do not format inside a scanner.
4. **Do not recompute risk in a reporter.** Reporters consume the `analysis`
   object from `src/analysis/risk.js`. If a number is wrong, fix it there and
   add a test.
5. **Keep the HTML self-contained.** No external fonts, scripts, images or
   stylesheets. No `innerHTML` with unescaped input.

## Adding a source rule

Rules live in `src/rules/source.js`, grouped by language:

```js
{
  id: 'js-createHash',                 // stable, kebab-case, prefixed by language
  re: /createHash\(\s*['"`](md5|sha1|sha256)['"`]/gi,
  algo: (m) => normaliseName(m[1]),    // string or function of the match
  primitive: 'hash',                   // pke | signature | key-agreement |
                                       // symmetric | mac | hash | kdf | protocol
  confidence: 'high',                  // high | medium | low
  note: 'Why this matters, in one sentence.',
  bits: (m) => Number(m[1]),           // optional, refines RSA/DSA key size
}
```

Then add a case to `test/rules.test.js` covering both a true positive and the
nearest false positive you can think of. False positives are treated as bugs:
a rule that fires on `minVersion: 'TLSv1.2'` is worse than a missing rule,
because it teaches users to ignore the report.

## Adding a configuration rule

Rules live in `src/rules/config.js`. Always provide an `appliesTo(path)`
predicate so a directive is not matched in the wrong dialect:

```js
{
  id: 'nginx-rc4',
  appliesTo: isNginx,
  re: /ssl_ciphers\s+([^;]*\bRC4[^;]*);/gi,
  algo: 'rc4',
  primitive: 'symmetric',
  confidence: 'high',
}
```

Negations matter. `!aNULL` is a *good* cipher policy, not a NULL cipher. Test
the negative case.

## When a finding is intentional

Do not weaken a rule to silence one occurrence. Use an inline suppression with
a reason instead, so the exception is visible and the rule keeps protecting
every other file:

```js
// mosca-ignore-line -- test fixture, not production code
const digest = crypto.createHash('md5');
```

`mosca-ignore-next-line` and `mosca-ignore-file` exist for the same purpose.
The terminal report counts suppressions, so an audit can see how many
exceptions a codebase carries.

## Adding an algorithm

Add an entry to `ALGORITHMS` in `src/rules/algorithms.js`:

```js
'ml-kem-1024': {
  id: 'ml-kem-1024',
  label: 'ML-KEM-1024',
  primitives: ['pke', 'key-agreement'],
  quantum: Q.SAFE,
  classical: C.STRONG,
  standard: 'FIPS 203',
  note: 'NIST level 5.',
}
```

`test/algorithms.test.js` checks that every id matches its key, every
replacement exists, and the replacement graph is acyclic.

## Adding a reporter

Consume `{ analysis, meta, endpoints }`. Add a format name in `src/cli.js` and
a test in `test/report.test.js`. If the format has a schema, validate the
shape in the test, not just the presence of a string.

## Style

- ESM only, explicit `.js` extensions in imports.
- 2-space indentation, single quotes, semicolons, trailing commas in
  multi-line literals.
- Prefer small pure functions. Side effects belong in `cli.js`.
- Comments explain **why**, not what. A comment that restates the code should
  be deleted.
- Error messages are lowercase, specific and actionable.

## Commit messages

```
area: short imperative summary

Why the change is needed, and what it changes. Reference an issue when one
exists. Mention tests added.
```

Examples: `rules: stop flagging TLS 1.2 as a legacy floor`,
`net: fix HRR random to the actual SHA-256 of "HelloRetryRequest"`.

## Pull requests

- One logical change per PR.
- `npm run check` must pass.
- Update `CHANGELOG.md` under `Unreleased` for user-visible changes.
- If you change the scoring model or a default, update `docs/METHODOLOGY.md`
  in the same PR. The documentation is part of the contract.

## Code of conduct

Be direct, be kind, assume good faith. Harassment or discrimination is not
welcome. Maintainers may close issues that are not actionable.
