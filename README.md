# xmip-core-library-ssh

The SSH wire types of [RFC 4251] section 5, read and written. What a message
means stays with the protocol or the gate that reads it.

| Item | What it is |
| --- | --- |
| `SshRead` | Reads a `boolean`, a `string`, a `string` that is text, a positive `mpint` and a `name-list` off codec's `Cursor` |
| `SshWrite` | Writes a `boolean`, a `string`, an `mpint` and a `name-list` beside codec's `ByteWriter` |

A `byte`, a `uint32` and a `uint64` are codec's own (`byte`, `u32_be`,
`u64_be`), and a refusal is codec's `CodecError`.

`transport/sftp` builds and reads its key exchange, user authentication,
channel and SFTP messages with this crate; `authenticate/ssh-key` reads the
key blobs, signature blobs and signed data it checks with it. The binary
packet framing of RFC 4253 section 6 is the transport's alone and stays
there. Until 2026-09-24 each of the two carried a reader of its own
(ADR-0050, amendment 2026-09-24).

`architecture.toml` carries the maturity.

[RFC 4251]: https://www.rfc-editor.org/rfc/rfc4251
