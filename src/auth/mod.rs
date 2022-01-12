use crate::models::JwtToken;
use josekit::JoseError;

pub struct JwtIssuer {}

impl JwtIssuer {
    pub fn issue(&self, _token: &JwtToken) -> Result<String, JoseError> {
        todo!()
    }
}

pub struct JwtVerifier {}

impl JwtVerifier {
    pub fn verify(&self, _token: impl AsRef<u8>) -> Result<JwtToken, JoseError> {
        todo!()
    }
}
