use isahc::AsyncReadResponseExt;
use jwt::{AlgorithmType, PKeyWithDigest, Store, Token, Unverified, Verified, VerifyWithStore};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket::http::CookieJar;
use rocket::{get, post, routes, Build, Rocket};
use rocket::{FromForm, State};
use rocket_dyn_templates::Template;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::exit;

type JwtHeader = serde_json::Value;
type JwtClaims = serde_json::Value;

/// The environment variable containing the OAuth client ID.
const OAUTH_CLIENT_ID_VAR: &'static str = "GOOGLE_OAUTH_CLIENT_ID";

/// State for Rocket to maintain a read-only copy of the OAuth configuration.
struct OAuthConfig {
    client_id: String,
}

/// Response from www.googleapis.com/oauth2/v1/certs containing key IDs to PEM-encoded certificates.
#[derive(Deserialize)]
struct GoogleCertsResponse(HashMap<String, String>);

/// Key-store for Google JWT signing keys.
struct JwtKeystore(HashMap<String, PKeyWithDigest<Public>>);

impl TryFrom<GoogleCertsResponse> for JwtKeystore {
    type Error = openssl::error::ErrorStack;

    fn try_from(value: GoogleCertsResponse) -> Result<Self, Self::Error> {
        let mut result = HashMap::with_capacity(value.0.len());

        for (k, v) in value.0.into_iter() {
            result.insert(
                k,
                PKeyWithDigest {
                    key: X509::from_pem(v.as_bytes())?.public_key()?,
                    digest: MessageDigest::sha256(),
                },
            );
        }

        Ok(Self { 0: result })
    }
}

impl Store for JwtKeystore {
    type Algorithm = PKeyWithDigest<Public>;

    fn get(&self, key_id: &str) -> Option<&Self::Algorithm> {
        self.0.get(key_id)
    }
}

/// Form request sent from Google to our service containing authorization data.
#[derive(FromForm)]
struct OAuthCredentials<'r> {
    credential: &'r str,
    g_csrf_token: &'r str,
}

/// The root URL, which simply renders HTML including the Google sign-in button with the OAuth
/// client id.
#[get("/")]
fn index(oauth: &State<OAuthConfig>) -> Template {
    Template::render(
        "index",
        HashMap::from([("oauth_client_id", oauth.client_id.clone())]),
    )
}

/// Receive OAuth POST with credentials from Google, return HTML.
///
/// See Google's ["Verify the Google ID token on your server side"](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
/// for more information.
///
/// Receives a POST request with a form containing `application/x-www-form-urlencoded` with two
/// fields: `credential`, which is a base-64-encoded JWT string, and `g_csrf_token`, which is
/// specific to Google, and is a cross-site-request-forgery token to prevent certain security
/// issues. This handler _also_ receives a cookie named `g_csrf_token`, and this should be
/// compared to ensure that the cookie is equal in both places.
///
/// Verification according to the above Google documentation is:
///
///  1. CSRF:
///     1. Ensure that the CSRF cookie is present.
///     2. Ensure that the CSRF form field is present.
///     3. Ensure that both are the same.
///  2. JWT:
///     1. Verify that the token is signed using one of Google's keys: [JWK format][jwk] or
///        [PEM format][pem].
///     2. Verify that `aud` in the token is equal to the Google OAuth client ID.
///     3. Verify that `iss` is equal to `/(https\:\/\/)?accounts\.google\.com/`.
///     4. Verify expiration `exp` is not expired.
///     5. If you want to restrict only to your G-Suite domain, verify that the token has a `hd`
///       claim that matches your G-Suite domain.
///
/// If all you care about is sign-in/sign-up, you'll only need to do the verification. If you'd like
/// to _use_ the token, you'll need to store it and deal with it somehow.
///
///  [jwk]: https://www.googleapis.com/oauth2/v3/certs
///  [pem]: https://www.googleapis.com/oauth2/v1/certs
#[post("/oauth/success", data = "<form>")]
async fn oauth_success(
    oauth: &State<OAuthConfig>,
    keystore: &State<JwtKeystore>,
    cookies: &CookieJar<'_>,
    form: Form<OAuthCredentials<'_>>,
) -> std::io::Result<Template> {
    // verify that the request body's g_csrf_token field is equal to the g_csrf_token cookie
    if let Some(cookie) = cookies.get("g_csrf_token").map(|c| c.value()) {
        if !cookie.eq(form.g_csrf_token) {
            // FIXME return 400: csrf verification failed
        }
    } else {
        // FIXME return 400: did not receive csrf cookie
    }

    // parse jwt header and claims without verification
    let token: Token<JwtHeader, JwtClaims, Unverified> =
        Token::parse_unverified(form.credential).unwrap();

    // verify that jwt claims' `aud` is equal to the google oauth client id
    if let Some(actual_oauth_client_id) = token.claims().get("aud").map(|v| v.as_str()).flatten() {
        if !oauth.client_id.eq(actual_oauth_client_id) {
            // FIXME return 400: jwt `aud` field does not match our oauth client id
        }
    } else {
        // FIXME return 400: jwt `aud` field not set
    }

    // verify that jwt claims' `iss` is equal to /(https\:\/\/)?accounts\.google\.com/
    if let Some(token_issuer) = token.claims().get("iss").map(|v| v.as_str()).flatten() {
        if !token_issuer.eq("accounts.google.com")
            && !token_issuer.eq("https://accounts.google.com")
        {
            // FIXME return 400: jwt `iss` is not accounts.google.com
        }
    } else {
        // FIXME return 400: jwt `iss` field not set
    }

    // FIXME check that jwt `exp` is in the future and that `nbf` is now or before now

    Ok(Template::render(
        "login",
        HashMap::from([("header", token.header()), ("claims", token.claims())]),
    ))
}

/// Fetch static files from /static/.
#[get("/static/<file..>")]
async fn static_files(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).await.ok()
}

/// Start the Rocket server.
pub async fn start() -> Rocket<Build> {
    // get the google oauth client id from the environment
    let oauth_client_id = env::var(OAUTH_CLIENT_ID_VAR).unwrap_or_else(|e| {
        eprintln!(
            "ERROR: Please set the Google OAuth client ID in the {} variable: {}",
            OAUTH_CLIENT_ID_VAR, e
        );
        exit(1)
    });

    // fetch the google jwt signing certificates
    let certs: JwtKeystore = isahc::get_async("https://www.googleapis.com/oauth2/v1/certs")
        .await
        .unwrap_or_else(|e| {
            eprintln!("ERROR: Unable to fetch certificates: {}", e);
            exit(1)
        })
        .json::<GoogleCertsResponse>()
        .await
        .unwrap_or_else(|e| {
            eprintln!(
                "ERROR: Unable to deserialize certificates from JSON response: {}",
                e
            );
            exit(1)
        })
        .try_into()
        .unwrap_or_else(|e| {
            eprintln!("ERROR: Unable to parse certificate: {}", e);
            exit(1)
        });

    rocket::build()
        .mount("/", routes![index, static_files, oauth_success])
        .manage(OAuthConfig {
            client_id: oauth_client_id,
        })
        .manage(certs)
        .attach(Template::fairing())
}
