use serde::{Deserialize, Serialize};

/// The Google OAuth JWT claims format.
///
/// For more information on supported fields and their meanings,
/// [consult the Google documentation][google-docs].
///
///  [google-docs]: https://developers.google.com/identity/sign-in/web/backend-auth
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct GoogleJwtClaims {
    /// The user's email address.
    pub email: Option<String>,
    /// Whether the user's email is verified with Google.
    pub email_verified: Option<bool>,
    /// The full name of the user.
    pub name: Option<String>,
    /// The first name of the user.
    pub given_name: Option<String>,
    /// The last name of the user.
    pub family_name: Option<String>,
    /// A URL to the user's picture.
    pub picture: Option<String>,
    #[serde(rename = "hd")]
    pub hosted_domain: Option<String>,
    // common JWT fields
    /// The `iss` field representing the issuer of this token.
    #[serde(rename = "iss")]
    pub issuer: String,
    /// The `nbf` field representing "not before," such that this token is not valid before this
    /// UTC Unix timestamp in seconds.
    #[serde(rename = "nbf")]
    pub not_before: usize,
    /// The `iat` field representing "issued at," indicating when this token was issued as a UTC
    /// Unix timestamp in seconds.
    #[serde(rename = "iat")]
    pub issued_at: usize,
    /// The `exp` field representing "expires at," indicating when this token is no longer valid as
    /// a UTC Unix timestamp in seconds.
    #[serde(rename = "exp")]
    pub expires_at: usize,
    /// The `jti` field representing the "JWT id," uniquely identifying this token.
    #[serde(rename = "jti")]
    pub jwt_id: String,
    /// The `aud` field representing the "audience" for the token; this will be set to the value of
    /// the Google OAuth client ID.
    #[serde(rename = "aud")]
    pub audience: String,
    /// The `sub` field representing the "subject" for the token, the unique Google account ID of
    /// the user in question.
    #[serde(rename = "sub")]
    pub subject: String,
}

impl GoogleJwtClaims {
    #[allow(unused)]
    pub fn hd(&self) -> Option<&str> {
        self.hosted_domain.as_ref().map(|s| s.as_ref())
    }

    pub fn iss(&self) -> &str {
        self.issuer.as_ref()
    }

    pub fn nbf(&self) -> usize {
        self.not_before
    }

    #[allow(unused)]
    pub fn iat(&self) -> usize {
        self.issued_at
    }

    pub fn exp(&self) -> usize {
        self.expires_at
    }

    #[allow(unused)]
    pub fn jti(&self) -> &str {
        self.jwt_id.as_ref()
    }

    pub fn aud(&self) -> &str {
        self.audience.as_ref()
    }

    #[allow(unused)]
    pub fn sub(&self) -> &str {
        self.subject.as_ref()
    }
}
