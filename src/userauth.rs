//! User authentication over the exchanged keys (RFC 4252): the client asks
//! for the `ssh-connection` service by a password or by a public key, and
//! the server admits it and says who it was.
//!
//! A public-key authentication signs the session identifier and the request
//! — the signed data of section 7, which [`signed_data`] writes and
//! [`SignedData::read`] takes apart — so what the server keeps, the key's
//! fingerprint, the signature and the session identifier, is what an
//! identity gate reads back to present the peer. A password authentication
//! keeps only the name, and is admitted only where the check the server is
//! handed admits the user and the password offered (`net::login`); until
//! 2026-11-01 any password was.

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use ed25519_dalek::SigningKey;
use net::NetError;
use net::login::Offered;

use crate::kex::{SERVICE_ACCEPT, SERVICE_REQUEST};
use crate::key::{self, ED25519, PublicKey};
use crate::packet::Conn;
use crate::{Fingerprint, Result, SshRead, SshWrite};

/// The message that offers a credential.
const USERAUTH_REQUEST: u8 = 50;
/// The message that turns one down.
const USERAUTH_FAILURE: u8 = 51;
/// The message that admits one.
const USERAUTH_SUCCESS: u8 = 52;

/// The service a user authenticates for.
const CONNECTION: &str = "ssh-connection";
const USERAUTH: &str = "ssh-userauth";
const PUBLICKEY: &str = "publickey";
const PASSWORD: &str = "password";

/// The requests a client is answered before it is let go: `OpenSSH`'s
/// own `MaxAuthTries`, so a password cannot be guessed at on one
/// connection without end.
pub const MOST_ATTEMPTS: usize = 6;

/// Who authenticated, and by what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticated {
    /// The user name presented.
    pub user: String,
    /// The public key's fingerprint, where a key was presented rather than
    /// a password.
    pub fingerprint: Option<Fingerprint>,
    /// The signature blob the key made, where one was presented.
    pub signature: Option<Vec<u8>>,
    /// What that signature covers — the signed data of RFC 4252 section 7,
    /// which opens with the session identifier — where one was presented:
    /// what a gate checks the signature over, and reads the user and the
    /// key blob back out of.
    pub signed: Option<Vec<u8>>,
}

/// The bytes a public-key authentication signs (RFC 4252 section 7): the
/// session identifier, then the request up to and including the key blob.
#[must_use]
pub fn signed_data(session_id: &[u8], user: &str, algorithm: &str, blob: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.string(session_id)
        .byte(USERAUTH_REQUEST)
        .string(user.as_bytes())
        .string(CONNECTION.as_bytes())
        .string(PUBLICKEY.as_bytes())
        .boolean(true)
        .string(algorithm.as_bytes())
        .string(blob);
    data
}

/// Signed data taken apart: what a signature over it says about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedData<'a> {
    /// The session identifier the signature binds to.
    pub session_id: &'a [u8],
    /// The user the client asked to be.
    pub user: &'a str,
    /// The service it asked for.
    pub service: &'a str,
    /// The signature algorithm.
    pub algorithm: &'a str,
    /// The key blob it signed with.
    pub blob: &'a [u8],
}

impl<'a> SignedData<'a> {
    /// `data` read as RFC 4252 section 7 lays it out, or `None` where it is
    /// not of that shape.
    #[must_use]
    pub fn read(data: &'a [u8]) -> Option<Self> {
        let mut reader = Cursor::new(data);
        let session_id = reader.string().ok()?;
        if reader.byte().ok()? != USERAUTH_REQUEST {
            return None;
        }
        let user = reader.text().ok()?;
        let service = reader.text().ok()?;
        if reader.text().ok()? != PUBLICKEY || !reader.boolean().ok()? {
            return None;
        }
        let algorithm = reader.text().ok()?;
        let blob = reader.string().ok()?;
        reader.is_empty().then_some(Self {
            session_id,
            user,
            service,
            algorithm,
            blob,
        })
    }
}

/// Ask the server for the `ssh-userauth` service.
///
/// # Errors
/// Where the service was refused or a message was out of order.
pub fn request_service(conn: &mut Conn) -> Result<()> {
    let mut request = Vec::new();
    request.byte(SERVICE_REQUEST).string(USERAUTH.as_bytes());
    conn.send(&request)?;
    let accept = conn.expect(SERVICE_ACCEPT, "the userauth service")?;
    if Cursor::new(&accept[1..]).string()? == USERAUTH.as_bytes() {
        Ok(())
    } else {
        Err(NetError::new("the server accepted another service"))
    }
}

/// Ask to be `user` presenting nothing, the `none` method (RFC 4252
/// section 5.2): what a client with no secret asks, which a server that
/// checks who logs in turns down.
///
/// # Errors
/// Where the server turned it down, as Xmip's own server does.
pub fn none(conn: &mut Conn, user: &str) -> Result<()> {
    let mut request = Vec::new();
    request
        .byte(USERAUTH_REQUEST)
        .string(user.as_bytes())
        .string(CONNECTION.as_bytes())
        .string(b"none");
    conn.send(&request)?;
    admitted(conn)
}

/// Authenticate as `user` with `password`.
///
/// # Errors
/// Where the server turned the password down.
pub fn password(conn: &mut Conn, user: &str, secret: &str) -> Result<()> {
    let mut request = Vec::new();
    request
        .byte(USERAUTH_REQUEST)
        .string(user.as_bytes())
        .string(CONNECTION.as_bytes())
        .string(PASSWORD.as_bytes())
        .boolean(false)
        .string(secret.as_bytes());
    conn.send(&request)?;
    admitted(conn)
}

/// Authenticate as `user` with `key`, signing over `session_id`.
///
/// # Errors
/// Where the server turned the key down.
pub fn public_key(conn: &mut Conn, user: &str, key: &SigningKey, session_id: &[u8]) -> Result<()> {
    let public = PublicKey::ed25519(&key.verifying_key());
    let signed = signed_data(session_id, user, ED25519, public.blob());
    let signature = key::sign_ed25519(key, &signed);
    let mut request = Vec::new();
    request
        .byte(USERAUTH_REQUEST)
        .string(user.as_bytes())
        .string(CONNECTION.as_bytes())
        .string(PUBLICKEY.as_bytes())
        .boolean(true)
        .string(ED25519.as_bytes())
        .string(public.blob())
        .string(&signature);
    conn.send(&request)?;
    admitted(conn)
}

fn admitted(conn: &mut Conn) -> Result<()> {
    let reply = conn.recv()?;
    match reply.first() {
        Some(&USERAUTH_SUCCESS) => Ok(()),
        Some(&USERAUTH_FAILURE) => Err(NetError::new("the server turned the credential down")),
        _ => Err(NetError::new(
            "a message where the authentication answer was due",
        )),
    }
}

/// Serve one authentication over `conn`, `session_id` already settled, and
/// say who it was. A password is admitted only where `check` admits the
/// user and the password offered; a key only where its signature verifies
/// over the signed data, and what to make of the key is the gate's. A
/// client is answered at most [`MOST_ATTEMPTS`] requests.
///
/// # Errors
/// Where a message was out of order, a signature did not verify, or the
/// client was turned down [`MOST_ATTEMPTS`] times.
pub fn serve(
    conn: &mut Conn,
    session_id: &[u8],
    check: &dyn Fn(&Offered<'_>) -> bool,
) -> Result<Authenticated> {
    let request = conn.expect(SERVICE_REQUEST, "a service request")?;
    if Cursor::new(&request[1..]).string()? != USERAUTH.as_bytes() {
        return Err(NetError::new("a service request that was not for userauth"));
    }
    let mut accept = Vec::new();
    accept.byte(SERVICE_ACCEPT).string(USERAUTH.as_bytes());
    conn.send(&accept)?;

    for _ in 0..MOST_ATTEMPTS {
        let message = conn.expect(USERAUTH_REQUEST, "an authentication request")?;
        if let Some(who) = admit(&message, session_id, check)? {
            conn.send(&[USERAUTH_SUCCESS])?;
            return Ok(who);
        }
        let mut failure = Vec::new();
        failure
            .byte(USERAUTH_FAILURE)
            .string(b"publickey,password")
            .boolean(false);
        conn.send(&failure)?;
    }
    Err(NetError::new(format!(
        "a client turned down {MOST_ATTEMPTS} times"
    )))
}

/// Whether a request is a credential this end admits, and who it names;
/// `None` where it is turned down and the client may try again.
fn admit(
    message: &[u8],
    session_id: &[u8],
    check: &dyn Fn(&Offered<'_>) -> bool,
) -> Result<Option<Authenticated>> {
    let mut reader = Cursor::new(&message[1..]);
    let user = reader.text()?.to_string();
    let service = reader.text()?;
    let method = reader.text()?;
    match method {
        PASSWORD => {
            // A change of password (the flag set) is not offered here.
            if reader.boolean()? || service != CONNECTION {
                return Ok(None);
            }
            let secret = reader.text()?;
            if !check(&Offered {
                user: &user,
                secret,
            }) {
                return Ok(None);
            }
            Ok(Some(Authenticated {
                user,
                fingerprint: None,
                signature: None,
                signed: None,
            }))
        }
        PUBLICKEY => {
            if !reader.boolean()? {
                return Ok(None);
            }
            let algorithm = reader.text()?;
            let blob = reader.string()?;
            let signature = reader.string()?;
            let key = PublicKey::parse(blob)?;
            let signed = signed_data(session_id, &user, algorithm, blob);
            if service != CONNECTION {
                return Err(NetError::new(format!(
                    "a request to authenticate for '{service}', not {CONNECTION}"
                )));
            }
            key.verify(&signed, signature)?;
            Ok(Some(Authenticated {
                user,
                fingerprint: Some(key.fingerprint()),
                signature: Some(signature.to_vec()),
                signed: Some(signed),
            }))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::login::{nobody, only};

    #[test]
    fn signed_data_reads_back_as_what_it_says() {
        let key = crate::kex::fresh_ed25519();
        let public = PublicKey::ed25519(&key.verifying_key());
        let session = [0x5au8; 32];
        let data = signed_data(&session, "xmip", ED25519, public.blob());

        let read = SignedData::read(&data).expect("the shape of section 7");

        assert_eq!(read.session_id, session);
        assert_eq!(read.user, "xmip");
        assert_eq!(read.service, CONNECTION);
        assert_eq!(read.algorithm, ED25519);
        assert_eq!(read.blob, public.blob());
        assert!(SignedData::read(b"a challenge").is_none());
        let mut longer = data.clone();
        longer.push(0);
        assert!(SignedData::read(&longer).is_none(), "more than its shape");
    }

    #[test]
    fn a_public_key_request_is_admitted_only_over_its_own_session_and_user() {
        let key = crate::kex::fresh_ed25519();
        let public = PublicKey::ed25519(&key.verifying_key());
        let session = [0x5au8; 32];
        let signature =
            key::sign_ed25519(&key, &signed_data(&session, "xmip", ED25519, public.blob()));
        let request = |user: &str| {
            let mut message = Vec::new();
            message
                .byte(USERAUTH_REQUEST)
                .string(user.as_bytes())
                .string(CONNECTION.as_bytes())
                .string(PUBLICKEY.as_bytes())
                .boolean(true)
                .string(ED25519.as_bytes())
                .string(public.blob())
                .string(&signature);
            message
        };

        let who = admit(&request("xmip"), &session, &*nobody())
            .expect("verified")
            .expect("admitted");
        assert_eq!(who.fingerprint, Some(public.fingerprint()));
        assert!(
            admit(&request("xmip"), &[0u8; 32], &*nobody()).is_err(),
            "another session"
        );
        assert!(
            admit(&request("someone"), &session, &*nobody()).is_err(),
            "another user"
        );
    }

    fn password_request(user: &str, secret: &str) -> Vec<u8> {
        let mut request = Vec::new();
        request
            .byte(USERAUTH_REQUEST)
            .string(user.as_bytes())
            .string(CONNECTION.as_bytes())
            .string(PASSWORD.as_bytes())
            .boolean(false)
            .string(secret.as_bytes());
        request
    }

    #[test]
    fn a_password_the_check_admits_names_the_user_and_keeps_no_key() {
        let check = only("party", "pencil");
        let who = admit(&password_request("party", "pencil"), &[0u8; 32], &*check)
            .expect("read")
            .expect("admitted");
        assert_eq!(who.user, "party");
        assert!(who.fingerprint.is_none());
    }

    #[test]
    fn a_password_the_check_does_not_admit_is_turned_down() {
        let check = only("party", "pencil");
        for (user, secret) in [("party", "pen"), ("mallory", "pencil")] {
            let turned = admit(&password_request(user, secret), &[0u8; 32], &*check);
            assert!(turned.expect("read").is_none(), "{user}");
        }
        let anyone = admit(&password_request("party", "pencil"), &[0u8; 32], &*nobody());
        assert!(
            anyone.expect("read").is_none(),
            "a check that admits no one"
        );
    }
}
