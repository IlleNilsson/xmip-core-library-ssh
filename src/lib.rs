#![forbid(unsafe_code)]

//! The SSH wire types (RFC 4251 section 5), read and written.
//!
//! ```text
//! boolean     one byte, zero is false
//! uint32      four bytes, big-endian            codec's u32_be
//! uint64      eight bytes, big-endian           codec's u64_be
//! string      a uint32 length and that many bytes
//! mpint       a string holding a two's-complement big-endian integer
//! name-list   a string of comma-separated names
//! ```
//!
//! [`SshRead`] reads them off codec's cursor and [`SshWrite`] lays them out
//! beside codec's byte writer, so a message is built and taken apart the
//! way every other binary protocol in the estate is.
//!
//! Until 2026-09-24 the encoding was written twice: the SFTP transport read
//! and wrote it for its key exchange, user authentication and channels, and
//! the ssh-key gate read it again for the key blobs, signature blobs and
//! signed data it checks. The packet framing (RFC 4253 section 6) is the
//! transport's alone and stays with it; what a message means stays with
//! the protocol or the gate that reads it.
//!
//! A refusal is codec's [`codec::CodecError`], which a capability already
//! turns into its own error.

mod read;
mod write;

pub use read::SshRead;
pub use write::SshWrite;
