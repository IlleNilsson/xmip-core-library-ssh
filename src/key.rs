//! A public key as SSH carries it, and the check of one signature made
//! with it.
//!
//! A key blob is RFC 4253 section 6.6 for `ssh-rsa` (`e` then `n`), RFC 5656
//! section 3.1 for `ecdsa-sha2-nistp256` (the curve name then the point) and
//! RFC 8709 section 4 for `ssh-ed25519` (the thirty-two bytes). A signature
//! is a blob too: the signature algorithm's name and the signature — raw for
//! Ed25519, `r` and `s` as integers for ECDSA, and for RSA the PKCS #1 v1.5
//! signature under `rsa-sha2-256` (RFC 8332). An `ssh-rsa` key is one key
//! type and three signature algorithms; only the SHA-256 one is verified.
//! An Ed25519 signature is verified strictly, so a signature with a small
//! order component or a non-canonical scalar does not pass.
//!
//! Every end of SSH in the estate reads a key here: the transport's host
//! key and user authentication, and the ssh-key gate's authorized keys.

use codec::CodecError;
use codec::cursor::Cursor;
use ed25519_dalek::Signer as _;
use net::NetError;
use rsa::sha2::Sha256;
use rsa::signature::Verifier as _;

use crate::{Fingerprint, SshRead, SshWrite};

/// The Ed25519 key type and signature algorithm (RFC 8709).
pub const ED25519: &str = "ssh-ed25519";
/// The ECDSA key type and signature algorithm on nistp256 (RFC 5656).
pub const ECDSA_P256: &str = "ecdsa-sha2-nistp256";
/// The RSA key type (RFC 4253), whose own signature algorithm is SHA-1.
pub const RSA: &str = "ssh-rsa";
/// The RSA signature algorithm verified: PKCS #1 v1.5 over SHA-256
/// (RFC 8332).
pub const RSA_SHA256: &str = "rsa-sha2-256";

#[derive(Clone, Debug)]
enum Material {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

/// A public key: its blob as it travels, and the key the blob holds.
#[derive(Clone, Debug)]
pub struct PublicKey {
    blob: Vec<u8>,
    algorithm: &'static str,
    material: Material,
}

impl PublicKey {
    /// Read a key blob.
    ///
    /// # Errors
    /// Where the blob names a key type not verified here, is not that
    /// type's key, or carries more than its key.
    pub fn parse(blob: &[u8]) -> Result<Self, NetError> {
        let mut reader = Cursor::new(blob);
        let named = reader.text().map_err(malformed(KEY_BLOB))?;
        let (algorithm, material) = match named {
            ED25519 => (ED25519, ed25519(&mut reader)?),
            ECDSA_P256 => (ECDSA_P256, p256_point(&mut reader)?),
            RSA => (RSA, rsa_key(&mut reader)?),
            other => {
                return Err(NetError::new(format!(
                    "the key type '{other}' is not one verified here: {ED25519}, \
                     {ECDSA_P256} and {RSA} are"
                )));
            }
        };
        if !reader.is_empty() {
            return Err(NetError::new("the key blob carries more than its key"));
        }
        Ok(Self {
            blob: blob.to_vec(),
            algorithm,
            material,
        })
    }

    /// The public half of an Ed25519 key, as its blob says it.
    #[must_use]
    pub fn ed25519(key: &ed25519_dalek::VerifyingKey) -> Self {
        let mut blob = Vec::new();
        blob.string(ED25519.as_bytes()).string(key.as_bytes());
        Self {
            blob,
            algorithm: ED25519,
            material: Material::Ed25519(*key),
        }
    }

    /// The key type the blob names.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// The key blob, as it travels on the wire.
    #[must_use]
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The key's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.blob)
    }

    /// Check a signature blob over `data`.
    ///
    /// # Errors
    /// Where the blob's algorithm is not one this key makes or not one
    /// verified here, the signature is malformed, or it does not verify.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), NetError> {
        let mut reader = Cursor::new(signature);
        let algorithm = reader.text().map_err(malformed("signature blob"))?;
        let raw = reader.string().map_err(malformed("signature blob"))?;

        let holds = match (&self.material, algorithm) {
            (Material::Ed25519(key), ED25519) => ed25519_dalek::Signature::from_slice(raw)
                .is_ok_and(|signature| key.verify_strict(data, &signature).is_ok()),
            (Material::P256(key), ECDSA_P256) => {
                let mut pair = Cursor::new(raw);
                let (r, s) = (
                    pair.mpint().map_err(malformed("ECDSA signature"))?,
                    pair.mpint().map_err(malformed("ECDSA signature"))?,
                );
                match (padded::<32>(r), padded::<32>(s)) {
                    (Some(r), Some(s)) => p256::ecdsa::Signature::from_scalars(r, s)
                        .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
                    _ => false,
                }
            }
            (Material::Rsa(key), RSA_SHA256) => {
                // RFC 8332 has the signature as wide as the modulus; some
                // clients drop its leading zeros, and the check wants them.
                let width = rsa::traits::PublicKeyParts::size(key);
                let mut whole = vec![0u8; width.saturating_sub(raw.len())];
                whole.extend_from_slice(raw);
                let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
                rsa::pkcs1v15::Signature::try_from(whole.as_slice())
                    .is_ok_and(|signature| key.verify(data, &signature).is_ok())
            }
            (Material::Rsa(_), RSA) => {
                return Err(NetError::new(
                    "the signature is ssh-rsa, which is SHA-1, and this node verifies \
                     rsa-sha2-256: the client must offer it (RFC 8332)",
                ));
            }
            _ => {
                return Err(NetError::new(format!(
                    "the signature algorithm '{algorithm}' is not one this node verifies \
                     with the key's type"
                )));
            }
        };

        if holds {
            Ok(())
        } else {
            Err(NetError::new(format!(
                "the {algorithm} signature does not verify with the key"
            )))
        }
    }
}

/// A signature blob: the algorithm's name and the signature.
#[must_use]
pub fn signature_blob(algorithm: &str, raw: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.string(algorithm.as_bytes()).string(raw);
    blob
}

/// The signature blob `key` makes over `data`.
#[must_use]
pub fn sign_ed25519(key: &ed25519_dalek::SigningKey, data: &[u8]) -> Vec<u8> {
    signature_blob(ED25519, &key.sign(data).to_bytes())
}

/// What a key blob is called in a refusal.
const KEY_BLOB: &str = "key blob";

/// A refusal of the SSH wire bytes called `what`, saying why.
fn malformed(what: &'static str) -> impl Fn(CodecError) -> NetError {
    move |error| NetError::new(format!("the {what} is malformed: {error}"))
}

/// Left-pad a big-endian integer to `WIDTH` bytes, as a scalar of that width
/// is read; `None` where it is wider.
fn padded<const WIDTH: usize>(integer: &[u8]) -> Option<[u8; WIDTH]> {
    let mut fixed = [0u8; WIDTH];
    let start = WIDTH.checked_sub(integer.len())?;
    fixed[start..].copy_from_slice(integer);
    Some(fixed)
}

fn ed25519(reader: &mut Cursor<'_>) -> Result<Material, NetError> {
    let bytes: &[u8; 32] = reader
        .string()
        .map_err(malformed(KEY_BLOB))?
        .try_into()
        .map_err(|_| NetError::new("an Ed25519 key is thirty-two bytes"))?;
    ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map(Material::Ed25519)
        .map_err(|_| NetError::new("the Ed25519 key is not a point on the curve"))
}

fn p256_point(reader: &mut Cursor<'_>) -> Result<Material, NetError> {
    let curve = reader.text().map_err(malformed(KEY_BLOB))?;
    if curve != "nistp256" {
        return Err(NetError::new(format!(
            "the ECDSA key's curve is '{curve}' and this node verifies nistp256"
        )));
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(reader.string().map_err(malformed(KEY_BLOB))?)
        .map(Material::P256)
        .map_err(|_| NetError::new("the ECDSA key is not a point on nistp256"))
}

fn rsa_key(reader: &mut Cursor<'_>) -> Result<Material, NetError> {
    let (exponent, modulus) = (
        reader.mpint().map_err(malformed(KEY_BLOB))?,
        reader.mpint().map_err(malformed(KEY_BLOB))?,
    );
    rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map(Material::Rsa)
    .map_err(|_| NetError::new("the RSA modulus and exponent are not a usable key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_pair(seed: u8) -> (ed25519_dalek::SigningKey, PublicKey) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let public = PublicKey::ed25519(&signing.verifying_key());
        (signing, public)
    }

    #[test]
    fn an_ed25519_key_reads_back_from_its_blob_and_verifies_what_its_private_half_signed() {
        let (signing, key) = ed25519_pair(7);
        let read = PublicKey::parse(key.blob()).expect("a key");
        let signature = sign_ed25519(&signing, b"session");

        assert_eq!(read.algorithm(), ED25519);
        assert_eq!(read.fingerprint(), key.fingerprint());
        assert!(read.verify(b"session", &signature).is_ok());
        let failure = read.verify(b"another", &signature).expect_err("refused");
        assert!(failure.message.contains("does not verify"));
    }

    #[test]
    fn an_ed25519_signature_is_checked_strictly() {
        // The identity point is a key of small order: verify_strict refuses
        // what the lenient check would let through for any message.
        let mut blob = Vec::new();
        let mut identity = [0u8; 32];
        identity[0] = 1;
        blob.string(ED25519.as_bytes()).string(&identity);
        let weak = PublicKey::parse(&blob).expect("a point");
        let mut signature = [0u8; 64];
        signature[0] = 1;
        assert!(
            weak.verify(b"anything", &signature_blob(ED25519, &signature))
                .is_err()
        );
    }

    #[test]
    fn an_ecdsa_nistp256_key_verifies_a_signature_of_two_integers() {
        use p256::ecdsa::signature::Signer as _;
        let signing = p256::ecdsa::SigningKey::from_slice(&[9; 32]).expect("a scalar");
        let mut blob = Vec::new();
        blob.string(ECDSA_P256.as_bytes());
        blob.string(b"nistp256");
        blob.string(signing.verifying_key().to_encoded_point(false).as_bytes());
        let key = PublicKey::parse(&blob).expect("a key");
        let signature: p256::ecdsa::Signature = signing.sign(b"session");
        let (r, s) = signature.split_bytes();
        let mut pair = Vec::new();
        pair.mpint(&r);
        pair.mpint(&s);

        assert!(
            key.verify(b"session", &signature_blob(ECDSA_P256, &pair))
                .is_ok()
        );
        assert!(
            key.verify(b"another", &signature_blob(ECDSA_P256, &pair))
                .is_err()
        );
    }

    #[test]
    fn an_rsa_key_verifies_rsa_sha2_256_and_refuses_sha_1_by_name() {
        use rsa::signature::{SignatureEncoding, Signer as _};
        use rsa::traits::PublicKeyParts;
        let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("a key");
        let mut blob = Vec::new();
        blob.string(RSA.as_bytes());
        blob.mpint(&private.e().to_bytes_be());
        blob.mpint(&private.n().to_bytes_be());
        let key = PublicKey::parse(&blob).expect("key");
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(private);
        let raw = signer.sign(b"session").to_vec();

        assert!(
            key.verify(b"session", &signature_blob(RSA_SHA256, &raw))
                .is_ok()
        );
        let failure = key
            .verify(b"session", &signature_blob(RSA, &raw))
            .expect_err("refused");
        assert!(failure.message.contains("SHA-1"));
    }

    #[test]
    fn a_blob_of_another_type_or_with_more_than_its_key_is_refused() {
        let mut dss = Vec::new();
        dss.string(b"ssh-dss");
        let other = PublicKey::parse(&dss).expect_err("refused");
        let (_, key) = ed25519_pair(7);
        let mut longer = key.blob().to_vec();
        longer.push(0);
        let more = PublicKey::parse(&longer).expect_err("refused");

        assert!(other.message.contains("'ssh-dss'"), "{other}");
        assert!(more.message.contains("more than its key"), "{more}");
    }

    #[test]
    fn a_signature_blob_that_promises_more_than_there_is_is_refused_by_name() {
        let (_, key) = ed25519_pair(7);
        let failure = key
            .verify(b"session", &[0, 0, 0, 9, b'x'])
            .expect_err("truncated");
        assert!(
            failure.message.contains("signature blob is malformed"),
            "{}",
            failure.message
        );
        let other = key
            .verify(b"session", &signature_blob(RSA_SHA256, &[0; 256]))
            .expect_err("refused");
        assert!(other.message.contains("'rsa-sha2-256'"));
    }
}
