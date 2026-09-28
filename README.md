# xmip-core-library-ssh

SSH for Xmip, one copy: the wire types, the transport layer, user
authentication, a session channel, and the keys, signatures and fingerprints
every end of SSH in the estate reads. What a subsystem carries and what a
gate concludes from a key stay with the transport and the gate.

| Item | What it is |
| --- | --- |
| `SshRead` | Reads a `boolean`, a `string`, a `string` that is text, a positive `mpint` and a `name-list` off codec's `Cursor` (RFC 4251 section 5) |
| `SshWrite` | Writes a `boolean`, a `string`, an `mpint` and a `name-list` beside codec's `ByteWriter` |
| `packet::Conn` | The binary packet protocol over a TCP connection (RFC 4253 section 6): the identification exchange, read under `net::read`'s ceiling, and each message sealed and opened in turn |
| `cipher` | `aes256-ctr` with `hmac-sha2-256` (RFC 4253 section 6.3, RFC 6668), and the key derivation of section 7.2 |
| `kex` | The key exchange, both ends: `curve25519-sha256` (RFC 8731) with an `ssh-ed25519` host key (RFC 8709), one name offered on every axis |
| `userauth` | RFC 4252, both ends: a password or an Ed25519 key, `serve` admitting a key only where its signature verifies; `signed_data` writes what a public-key authentication signs (section 7) and `SignedData::read` takes it apart |
| `channel::Channel` | One session channel and a subsystem over it (RFC 4254 section 6.5) as a byte stream, a frame reassembled across channel messages, and the close from both ends |
| `key::PublicKey` | A key blob — `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa` — and the check of a signature blob made with it: Ed25519 strictly, RSA under `rsa-sha2-256` only, SHA-1 refused by name; `signature_blob` and `sign_ed25519` write one |
| `Fingerprint` | `SHA256:<base64>` as OpenSSH prints it, of a blob or read back from text, padded or not |

A `byte`, a `uint32` and a `uint64` are codec's own (`byte`, `u32_be`,
`u64_be`). A refusal is `net::NetError`: a connection's failure keeps its
kind, so a transport retries it as it would any connection's, and anything a
peer sent that is not SSH is the peer's and never retried.

`transport/sftp` runs its file protocol over `channel::Channel` and keeps its
client and its in-process far end; `authenticate/ssh-key` checks
`PublicKey` signatures over `SignedData` and keeps the `authorized_keys`
line; `identify/ssh-key` reads a `Fingerprint`. Until 2026-09-24 the wire
types were written twice. Until 2026-09-28 the transport layer sat in the
SFTP transport, and the key blob and the Ed25519 check (not strict in the
transport), the signature blob, the fingerprint and the signed data were
written two or three times across the transport, the gate and the identifier
(ADR-0050, amendments 2026-09-25 and 2026-09-28).

`architecture.toml` carries the maturity.

[RFC 4251]: https://www.rfc-editor.org/rfc/rfc4251
