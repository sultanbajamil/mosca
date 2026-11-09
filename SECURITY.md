# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this
repository. Include:

- the affected command and version,
- a minimal reproduction (a snippet, a `mosca.json`, or a host name),
- the impact you believe it has.

You can expect an acknowledgement within 72 hours. This is a volunteer
project; fixes are best-effort, but security reports are prioritised over
feature work.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | yes |
| < 1.0 | no |

## Threat model

MOSCA is a **read-only assessment tool**. It is designed to be safe to run
against production code and production endpoints.

### What it does on the network

- Opens a TCP connection to port 443 (or the port you specify).
- Sends one TLS ClientHello.
- Reads the first server flight (ServerHello, certificate, alert).
- Closes the socket.
- Optionally repeats that with a TLS 1.0/1.1-only ClientHello to test legacy
  acceptance.

It never completes a handshake, never sends application data, never
authenticates, never uploads results, and never writes outside the output
directory you choose.

### What it reads on disk

Files under the scan root that match a source-language extension or a
recognised configuration filename. It refuses files larger than 2 MiB
(512 KiB for configuration), skips files containing NUL bytes in the first
8 KiB, skips symlinks, and never follows a path outside the scan root through
a symlink. `.git`, `node_modules`, `vendor`, `dist`, `build` and similar
directories are skipped by default.

### What it does not do

- It does not exploit anything.
- It does not test authentication, authorisation, injection or application
  logic.
- It does not verify certificate chains or trust; certificate inspection is
  descriptive.
- It does not brute-force, fuzz, or send malformed traffic beyond the
  ClientHello variants described above.

## Handling of scan results

A report contains file paths, host names and cryptographic inventory. Treat it
as internal material: it maps exactly where an organisation is weakest. The
HTML report is self-contained and contains no telemetry, but it is still a
document you should review before publishing.

The project's own `docs/index.html` sample is generated from the synthetic
example estate plus public endpoints, and is intended for publication.

## Supply chain

MOSCA has **zero runtime and development dependencies**. `npm run check`
fails if a dependency is added, if a non-builtin bare import appears, or if a
lockfile is committed. The CI workflow runs the same check on every push.

## Safe defaults

- `rejectUnauthorized: false` is used only to retrieve certificates from
  endpoints you explicitly asked to inspect; it is never used to make a trust
  decision.
- Scan output defaults to `./mosca-report`, inside the scanned project.
- `--fail-on` is opt-in: a scan never fails a build unless you ask it to.
