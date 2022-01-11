use josekit::jwk::alg::ed::{EdCurve, EdKeyPair};
use josekit::jwk::{Jwk, KeyPair};
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt;
use josekit::jwt::JwtPayload;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ops::Add;
use std::process::exit;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Deserialize, Serialize)]
struct JwtClaims {
    user_id: usize,
    email: String,
    name: String,
    iat: usize,
    exp: usize,
    nbf: usize,
}

impl JwtClaims {
    fn new<S: Into<String>>(user_id: usize, email: S, name: S) -> Self {
        let now = OffsetDateTime::now_utc();

        Self {
            user_id,
            email: email.into(),
            name: name.into(),
            iat: now.unix_timestamp().try_into().unwrap_or(0),
            exp: now
                .add(Duration::hours(12))
                .unix_timestamp()
                .try_into()
                .unwrap_or(0),
            nbf: now.unix_timestamp().try_into().unwrap_or(0),
        }
    }

    fn to_payload(&self) -> JwtPayload {
        let value = serde_json::to_value(self).unwrap();
        JwtPayload::from_map(value.as_object().unwrap().clone()).unwrap()
    }
}

/// Generate and output a Ed25519 keypair for signing and verifying JWT tokens.
///
/// The process involves a few different steps for generating the keys and retaining the ability
/// to dump them into various formats.
///
/// > **NOTE** The PEM and DER formats given are for public/private key data, which is _not_ the
/// > same as an X509 certificate. [Google's JWT cert list in PEM format](https://www.googleapis.com/oauth2/v1/certs)
/// > are X509 certificates encoded in PEM format.
///
/// # Keypair Generation
///
/// First, we generate an [`EdKeyPair`]:
///
/// ```rust
/// use josekit::jwk::alg::ed::{EdCurve, EdKeyPair};
/// use josekit::jws::EdDSA;
///
/// let keypair: EdKeyPair = EdDSA.generate_key_pair(EdCurve::Ed25519).unwrap();
/// ```
///
/// From this value, we can generate DER, PEM, and JWK format keys.
///
/// # DER Output
///
/// Let's start with DER:
///
/// ```rust
/// let (public: Vec<u8>, private: Vec<u8>) = (keypair.to_der_public_key(), keypair.to_der_private_key());
/// ```
///
/// # PEM Output
///
/// Next, PEM-format:
///
/// ```rust
/// // -----BEGIN PUBLIC KEY-----
/// println!("{}", String::from_utf8(keypair.to_pem_public_key()).unwrap());
/// // -----BEGIN PRIVATE KEY-----
/// println!("{}", String::from_utf8(keypair.to_pem_private_key()).unwrap());
/// // -----BEGIN ED25519 PRIVATE KEY-----
/// println!("{}", String::from_utf8(keypair.to_traditional_pem_private_key()).unwrap());
/// ```
///
/// # JWK Output
///
/// JWK is a special format unique to JSON Web Tokens, certificate material is encoded as a JSON
/// dictionary. A JWK key can consist of public and/or private key material, other common metadata,
/// an optional user-chosen key id, and any other values as part of the JSON dictionary.
///
/// Example:
///
/// ```json
/// {
///   "kty": "OKP",
///   "use": "sig",
///   "crv": "Ed25519",
///   "d": "rt7_oCfoaI-8aSRjy277vSBNn7awRozI3CfYZWKwzxA",
///   "x": "4N4gqF6EhzI8Z0J2G8g7HAx13wRyk2kElBPH9Kn5PhY",
///   "kid": "1e54d823c6ef42964bb500506a0245e45d83afb3a24a256cb5045498e4e87fd7"
/// }
/// ```
///
/// Let's break these down:
///
///  - `kty`: Key type; for EdDSA keys, this will be `OKP`.
///  - `use`: Key usage; for sign/verify keys, this will be `sig`.
///  - `crv`: Elliptic Curve: for EdDSA keys, this will be either `Ed25519` or `Ed448` for the
///    algorithm's chosen elliptic curve.
///  - `d`: EdDSA private key material, encoded in URL-safe base-64 with no padding.
///  - `x`: EdDSA public key material, encoded in URL-safe base-64 with no padding.
///  - `kid`: Our chosen key ID, which is the SHA-256 hex digest of the decoded public key.
///
/// We can generate this value in-memory via:
///
/// ```rust
/// use josekit::jwk::Jwk;
///
/// let jwk: Jwk = keypair.to_jwk_keypair();
/// ```
///
/// This can be serialized via:
///
/// ```rust
/// println!("{}", serde_json::to_string_pretty(jwk.as_ref()).unwrap());
/// ```
///
/// **NOTE:** This will include both public _and_ private key data!
///
/// To obtain only the public key data:
///
/// ```rust
/// let public_jwk: Jwk = jwk.to_public_key().unwrap();
/// ```
///
///
fn main() {
    let keypair: EdKeyPair = EdDSA
        .generate_key_pair(EdCurve::Ed25519)
        .unwrap_or_else(|e| {
            eprintln!("Failed to generate the keypair: {}", e);
            exit(1)
        });

    // serialize keys to der (binary) format, but display as PEM via base64 encoding
    println!(
        "DER Public: {}",
        base64::encode_config(keypair.to_der_public_key(), base64::STANDARD)
    );
    println!(
        "DER Private: {}",
        base64::encode_config(keypair.to_der_private_key(), base64::STANDARD)
    );

    // serialize keys to pem format
    let (public, private, trad_private) = (
        // -----BEGIN PUBLIC KEY-----
        String::from_utf8(keypair.to_pem_public_key()).expect("unable to utf-8 public key"),
        // -----BEGIN PRIVATE KEY-----
        String::from_utf8(keypair.to_pem_private_key()).expect("unable to utf-8 private key"),
        // -----BEGIN ED25519 PRIVATE KEY-----
        String::from_utf8(keypair.to_traditional_pem_private_key())
            .expect("unable to utf-8 traditional private key"),
    );

    println!("PEM Public Key:\n{}", public);
    println!("PEM Private Key:\n{}", private);
    println!("PEM Private Key (Traditional):\n{}", trad_private);

    // to jwk pub+private
    let mut jwk_pub_priv: Jwk = keypair.to_jwk_key_pair();
    let mut jwk_pub: Jwk = jwk_pub_priv.to_public_key().unwrap();

    // generate our own key id which is a sha-256 fingerprint over the binary public key
    let key_id = jwk_pub_priv
        .parameter("x")
        .map(|v| v.as_str())
        .flatten()
        .map(|s| base64::decode_config(s, base64::URL_SAFE_NO_PAD).ok())
        .flatten()
        .map(|bytes| hex::encode(digest(&SHA256, bytes.as_ref()).as_ref()))
        .unwrap();

    jwk_pub.set_key_id(&key_id);
    jwk_pub_priv.set_key_id(&key_id);

    // serialize jwk pub+private
    println!(
        "JWK (Public + Private): {}",
        serde_json::to_string_pretty(jwk_pub_priv.as_ref()).unwrap()
    );

    // serialize jwk public only
    println!(
        "JWK (Public): {}",
        serde_json::to_string_pretty(jwk_pub.as_ref()).unwrap()
    );

    // create a signer; we only sign with one key
    let token_signer = EdDSA.signer_from_jwk(&jwk_pub_priv).unwrap();

    // create header
    let header = {
        let mut value = JwsHeader::new();
        value.set_key_id(jwk_pub.key_id().unwrap());
        value.set_algorithm(keypair.algorithm().unwrap());
        value
            .set_claim(
                "crv",
                Some(Value::String(EdCurve::Ed25519.name().to_string())),
            )
            .unwrap();
        value
    };

    println!(
        "JWT Header: {}",
        serde_json::to_string_pretty(header.as_ref()).unwrap()
    );

    // create claims
    let claims = JwtClaims::new(1024, "me@naftuli.wtf", "Naftuli Kay");

    println!(
        "JWT Claims: {}",
        serde_json::to_string_pretty(claims.to_payload().as_ref()).unwrap()
    );

    // create/sign token
    let token = jwt::encode_with_signer(&claims.to_payload(), &header, &token_signer).unwrap();

    println!("JWT Token: {}", token);

    // verify token
    let token_verifier = EdDSA.verifier_from_jwk(&jwk_pub).unwrap();

    let (_verified_claims, _verified_header) =
        jwt::decode_with_verifier_selector(token, |header| {
            if let Some(header_key_id) = header.key_id() {
                // if the header's key id matches our key's key id, use that as the verifier
                if header_key_id == key_id {
                    return Ok(Some(&token_verifier));
                }
            }

            Ok(None)
        })
        .unwrap_or_else(|e| {
            eprintln!("Failed to decode/verify token: {}", e);
            exit(1)
        });

    println!("Verified token!");
}
