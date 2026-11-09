# Nimbus Payments (demo target)

> **This project is intentionally insecure.** It exists so `mosca demo` has
> something to find. Do not deploy it, copy it, or point real traffic at it.

A small payments platform assembled the way real ones tend to accumulate
cryptography: an auth service written in Node, a ledger in Python, an
identity service in Go, a signing gateway in Java, plus the nginx and sshd
configuration that grew around them over six years.

Every primitive here is deliberately one of the ones that a post-quantum
migration has to find:

| Layer | What is there | Why it matters |
| --- | --- | --- |
| Auth | JWT signed with RS256, refresh tokens fingerprinted with MD5 | RSA falls to Shor; MD5 is already broken |
| Payments | AES-128-CBC, RSA-2048 key generation | 128-bit key, Shor |
| Legacy bridge | 3DES, MD5 | Broken today |
| Ledger | PyCryptodome RSA-2048, Fernet, ECB mode | Shor, 128-bit key, ECB |
| Identity | Go `rsa.GenerateKey`, SHA-1, TLS 1.0 | Shor, collision-broken, deprecated protocol |
| Gateway | Java `KeyPairGenerator("RSA")`, `SSLContext("TLSv1")` | Shor, deprecated protocol |
| Edge | nginx `ssl_protocols TLSv1 TLSv1.1`, RC4, 3DES | Protocol and cipher policy |
| Host | sshd `ssh-rsa`, `diffie-hellman-group1-sha1` | Broken signature and KEX |

Run the scan:

```bash
npx mosca-pqc scan . --tls example.com
```
