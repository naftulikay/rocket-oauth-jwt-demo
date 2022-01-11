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

/// Generate and display an EdDSA/Curve25519 public/private keypair, generate a header/claims,
/// generate a signed token, and verify it to show `josekit` functionality.
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

    // FIXME ideally we'll use jwt::decode_with_verifier_in_jwk_set
    let (_verified_claims, _verified_header) = jwt::decode_with_verifier(token, &token_verifier)
        .map_err(|e| {
            eprintln!("Failed to verify token: {}", e);
        })
        .unwrap();

    println!("Verified token!");
}
