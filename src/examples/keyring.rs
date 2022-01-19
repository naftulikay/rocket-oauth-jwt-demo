use anyhow::Result;
use josekit::jwk::Jwk;
use rocket::tokio;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct JwkSerializer<'a> {
    #[serde(rename = "kty")]
    key_type: &'a str,
    #[serde(rename = "use")]
    key_use: &'a str,
    #[serde(rename = "alg")]
    algorithm: &'a str,
    #[serde(rename = "crv")]
    curve: &'a str,
    #[serde(rename = "d")]
    private_key: &'a str,
    #[serde(rename = "x")]
    public_key: &'a str,
    #[serde(rename = "kid")]
    key_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct JwkDeserializer {
    #[serde(rename = "kty")]
    key_type: String,
    #[serde(rename = "use")]
    key_use: String,
    #[serde(rename = "alg")]
    algorithm: String,
    #[serde(rename = "crv")]
    curve: String,
    #[serde(rename = "d")]
    private_key: String,
    #[serde(rename = "x")]
    public_key: String,
    #[serde(rename = "kid")]
    key_id: Option<String>,
}

impl From<JwkDeserializer> for Jwk {
    fn from(payload: JwkDeserializer) -> Self {
        let mut result = Jwk::new(payload.key_type.as_str());
        result.set_key_use(payload.key_use);
        result.set_algorithm(payload.algorithm);
        result.set_curve(payload.curve);
        result
            .set_parameter("d", Some(payload.private_key.into()))
            .unwrap();
        result
            .set_parameter("x", Some(payload.public_key.into()))
            .unwrap();

        if let Some(key_id) = payload.key_id {
            result.set_key_id(key_id);
        }

        result
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    Ok(())
}
