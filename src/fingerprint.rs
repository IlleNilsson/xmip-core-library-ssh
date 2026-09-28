//! A public key's fingerprint as OpenSSH prints it: `SHA256:` and the
//! base64 of the SHA-256 digest of the key blob, without padding.

use core::fmt;

use net::NetError;
use sha2::{Digest, Sha256};

const PREFIX: &str = "SHA256:";

/// The SHA-256 digest of a key blob, which is what a key is known by from
/// the transport that saw it through the gates that check it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// The fingerprint of the key `blob`.
    #[must_use]
    pub fn of(blob: &[u8]) -> Self {
        Self(Sha256::digest(blob).into())
    }

    /// Read `SHA256:<base64>`, the base64 with or without its padding.
    ///
    /// # Errors
    /// Where the text is not `SHA256:` and the base64 of thirty-two bytes.
    pub fn parse(text: &str) -> Result<Self, NetError> {
        let Some(digest) = text.strip_prefix(PREFIX) else {
            return Err(NetError::new(format!(
                "the SSH key fingerprint is not SHA256: `{text}`"
            )));
        };
        codec::base64::decode(digest)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .map(Self)
            .ok_or_else(|| {
                NetError::new("the SSH key fingerprint is not the base64 of a SHA-256 digest")
            })
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}", codec::base64::encode_unpadded(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINTED: &str = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8";

    #[test]
    fn a_fingerprint_prints_as_openssh_does_and_reads_back_padded_or_not() {
        let print = Fingerprint::of(b"a key blob");
        let text = print.to_string();
        assert!(text.starts_with(PREFIX), "{text}");
        assert_eq!(text.len() - PREFIX.len(), 43, "{text}");
        assert_eq!(Fingerprint::parse(&text).expect("read"), print);
        assert_eq!(
            Fingerprint::parse(&format!("{text}=")).expect("padded"),
            print
        );
        assert_eq!(
            Fingerprint::parse(PRINTED).expect("read").to_string(),
            PRINTED
        );
    }

    #[test]
    fn what_is_not_a_sha256_fingerprint_is_refused_saying_why() {
        let md5 = "MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48";
        let refused = |text: &str| Fingerprint::parse(text).expect_err("refused").message;
        assert!(refused(md5).contains("not SHA256"));
        assert!(refused("SHA256:nThbg6").contains("SHA-256 digest"));
        assert!(refused("SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY*").contains("digest"));
    }
}
