use josekit::jwk::alg::ed::{EdCurve, EdKeyPair};
use josekit::jwk::{Jwk, KeyPair};
use josekit::jws::alg::eddsa::{EddsaJwsSigner, EddsaJwsVerifier};
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt::{self, JwtPayload};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
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

    // create a key id; since we're using ed25519 and keys are 32 bytes, we simply just use the full
    // public key as the key id using the existing URL-safe, no padding base-64 encoding in the JWK
    let key_id = jwk_pub_priv
        .parameter("x")
        .map(|v| v.as_str())
        .flatten()
        .map(|s| s.to_string())
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
    let token_signer: EddsaJwsSigner = EdDSA.signer_from_jwk(&jwk_pub_priv).unwrap();

    // create header
    let header: JwsHeader = {
        let mut value = JwsHeader::new();
        value.set_key_id(jwk_pub.key_id().unwrap());
        value.set_algorithm(keypair.algorithm().unwrap());
        // create a 32-byte (256-bit) random nonce for the header
        value.set_nonce({
            let mut buf: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        });
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
    let token_verifier: EddsaJwsVerifier = EdDSA.verifier_from_jwk(&jwk_pub).unwrap();

    // verify the signed token; dynamically choose which verifier to use based on the header's key
    // id
    let (_verified_claims, _verified_header): (JwtPayload, JwsHeader) =
        jwt::decode_with_verifier_selector(token, |header| {
            if let Some(header_key_id) = header.key_id() {
                // if the header's key id matches our key's key id, use that as the verifier
                if header_key_id == jwk_pub.key_id().unwrap() {
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
