//! A private key as OpenSSH keeps it: the `openssh-key-v1` form
//! `ssh-keygen` writes, PEM-armored as `OPENSSH PRIVATE KEY` (OpenSSH's
//! PROTOCOL.key). What a Location's `key` secret holds for SSH (ADR-0019,
//! amendment 2026-10-29).
//!
//! Read here, once, for every end of SSH in the estate that signs as a
//! user. One key, Ed25519 (RFC 8709), unencrypted: an encrypted key's
//! passphrase would be a second secret, and is refused in words.

use codec::cursor::Cursor;
use net::NetError;

use crate::key::ED25519;
use crate::{SshRead, SshWrite};

/// What a key opens with, before its cipher.
const MAGIC: &[u8] = b"openssh-key-v1\0";
/// The armor's label.
const LABEL: &str = "OPENSSH PRIVATE KEY";

/// The Ed25519 key `pem` holds, OpenSSH's own form.
///
/// # Errors
///
/// In words that never repeat the key, where `pem` is not one unencrypted
/// Ed25519 key in that form, or its two check words differ — a key opened
/// under the wrong passphrase.
pub fn ed25519(pem: &str) -> Result<ed25519_dalek::SigningKey, NetError> {
    let refused = |why: &str| NetError::new(format!("the SSH private key is refused: {why}"));
    let body: String = pem
        .lines()
        .map(str::trim)
        .skip_while(|line| *line != format!("-----BEGIN {LABEL}-----"))
        .skip(1)
        .take_while(|line| *line != format!("-----END {LABEL}-----"))
        .collect();
    if body.is_empty() {
        return Err(refused(&format!(
            "it is no '{LABEL}' block, which ssh-keygen writes"
        )));
    }
    let bytes = codec::base64::decode(&body).map_err(|_| refused("its armor is not base64"))?;
    let rest = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(|| refused("it is not openssh-key-v1"))?;
    let mut outer = Cursor::new(rest);
    let malformed = |_| refused("it is malformed");
    let (cipher, kdf) = (
        outer.text().map_err(malformed)?,
        outer.text().map_err(malformed)?,
    );
    let _options = outer.string().map_err(malformed)?;
    if cipher != "none" || kdf != "none" {
        return Err(refused(
            "it is encrypted with a passphrase; a key secret is set unencrypted",
        ));
    }
    if outer.u32_be().map_err(malformed)? != 1 {
        return Err(refused("it holds more than one key"));
    }
    let _public = outer.string().map_err(malformed)?;
    let mut private = Cursor::new(outer.string().map_err(malformed)?);
    let (check, again) = (
        private.u32_be().map_err(malformed)?,
        private.u32_be().map_err(malformed)?,
    );
    if check != again {
        return Err(refused("its check words differ"));
    }
    let algorithm = private.text().map_err(malformed)?;
    if algorithm != ED25519 {
        return Err(refused(&format!(
            "it is {algorithm}; {ED25519} is read here"
        )));
    }
    let _public = private.string().map_err(malformed)?;
    let pair = private.string().map_err(malformed)?;
    let seed: [u8; 32] = pair
        .get(..32)
        .and_then(|seed| seed.try_into().ok())
        .ok_or_else(|| refused("its Ed25519 key is short"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// `key` as `ssh-keygen` writes it, unencrypted: what a `key` secret
/// holds, and what [`ed25519`] reads.
#[must_use]
pub fn written(key: &ed25519_dalek::SigningKey) -> String {
    written_as(key, "none", (0x05ec_07e7, 0x05ec_07e7))
}

/// `key` under `cipher`, with the two check words given.
fn written_as(key: &ed25519_dalek::SigningKey, cipher: &str, check: (u32, u32)) -> String {
    let public = key.verifying_key();
    let mut blob = Vec::new();
    blob.string(ED25519.as_bytes()).string(public.as_bytes());
    let mut pair = key.to_bytes().to_vec();
    pair.extend(public.as_bytes());
    let mut private = Vec::new();
    private.extend(check.0.to_be_bytes());
    private.extend(check.1.to_be_bytes());
    private
        .string(ED25519.as_bytes())
        .string(public.as_bytes())
        .string(&pair);
    private.string(b"");
    // Padded to the cipher's block, eight for none: 1, 2, 3 and on.
    let padding = (8 - private.len() % 8) % 8;
    private.extend((1..=padding).map(|n| u8::try_from(n).unwrap_or_default()));
    pair.fill(0);
    let mut whole = MAGIC.to_vec();
    whole.string(cipher.as_bytes()).string(b"none").string(b"");
    whole.extend(1u32.to_be_bytes());
    whole.string(&blob).string(&private);
    private.fill(0);
    let armored = codec::base64::encode(&whole);
    whole.fill(0);
    let lines: Vec<&str> = armored
        .as_bytes()
        .chunks(70)
        .map(|line| core::str::from_utf8(line).unwrap_or_default())
        .collect();
    format!(
        "-----BEGIN {LABEL}-----\n{}\n-----END {LABEL}-----\n",
        lines.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drawn() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&codec::random::array::<32>())
    }

    #[test]
    fn a_key_ssh_keygen_writes_is_read_and_one_it_cannot_be_is_refused() {
        let key = drawn();
        let read = ed25519(&written(&key)).expect("read");
        assert_eq!(read.to_bytes(), key.to_bytes());

        let encrypted = ed25519(&written_as(&key, "aes256-ctr", (7, 7))).expect_err("encrypted");
        assert!(encrypted.to_string().contains("passphrase"), "{encrypted}");
        let wrong = ed25519(&written_as(&key, "none", (7, 8))).expect_err("checks differ");
        assert!(wrong.to_string().contains("check words"), "{wrong}");
        let other = ed25519("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----");
        assert!(
            other
                .expect_err("no block")
                .to_string()
                .contains("OPENSSH PRIVATE KEY")
        );
    }
}
