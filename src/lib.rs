#![forbid(unsafe_code)]

//! SSH for Xmip: the wire types, the transport layer, user authentication,
//! a session channel, and the keys, signatures and fingerprints every end
//! of SSH in the estate reads.
//!
//! ```text
//! the wire types (RFC 4251 section 5)
//!   read.rs         SshRead: boolean, string, text, mpint, name-list off codec's cursor
//!   write.rs        SshWrite: the same laid out beside codec's byte writer
//! the transport layer (RFC 4253)
//!   packet.rs       Conn: the binary packet protocol over a TCP connection
//!   cipher.rs       aes256-ctr with hmac-sha2-256, and the key derivation
//!   kex.rs          curve25519-sha256 with an ssh-ed25519 host key
//! above it
//!   userauth.rs     RFC 4252: a password or a public key, and the signed data
//!   channel.rs      RFC 4254: one session channel and a subsystem over it
//! keys
//!   key.rs          PublicKey: ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa, and
//!                   their signatures checked, Ed25519 strictly
//!   fingerprint.rs  Fingerprint: SHA256:<base64>, as OpenSSH prints it
//! ```
//!
//! One algorithm is offered on each axis of the key exchange, so a peer
//! that speaks nothing else cannot connect. The SFTP transport runs its
//! file protocol over [`channel::Channel`]; the ssh-key gate checks
//! [`key::PublicKey`] signatures over [`userauth::SignedData`]; the ssh-key
//! identifier reads a [`Fingerprint`].
//!
//! Until 2026-09-24 the wire types were written twice, by the SFTP
//! transport and the ssh-key gate. Until 2026-09-28 the transport layer sat
//! in the SFTP transport, and the key blob, the Ed25519 check (not strict
//! there), the signature blob, the fingerprint and the signed data were
//! each written two or three times across it, the ssh-key gate and the
//! ssh-key identifier.
//!
//! A refusal is [`net::NetError`]: a connection's failure keeps its kind,
//! and anything a peer sent that is not SSH is the peer's, never retried.

pub mod channel;
pub mod cipher;
mod fingerprint;
pub mod kex;
pub mod key;
pub mod packet;
mod read;
pub mod userauth;
mod write;

pub use fingerprint::Fingerprint;
pub use read::SshRead;
pub use write::SshWrite;

/// What SSH answers, or why it did not.
pub type Result<T> = core::result::Result<T, net::NetError>;
