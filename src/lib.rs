pub(crate) mod fairings;
pub(crate) mod google;
pub(crate) mod routes;

use jwt::{Error as JwtError, Header as JwtHeader, Token, Verified, VerifyWithStore};
use log::LevelFilter;
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket::http::{CookieJar, Status};
use rocket::{catch, catchers, get, post, routes, Build, Rocket, State};
use rocket_dyn_templates::Template;
use std::collections::HashMap;
use std::env;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::exit;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::google::{GoogleJwtKeystore, OAuthConfig, OAuthCredentials, OAUTH_CLIENT_ID_VAR};

type JwtClaims = serde_json::Value;

/// The root URL, which simply renders HTML including the Google sign-in button with the OAuth
/// client id.
#[get("/")]
fn index(oauth: &State<OAuthConfig>) -> Template {
    Template::render(
        "index",
        HashMap::from([("oauth_client_id", oauth.client_id.clone())]),
    )
}

#[catch(400)]
fn oauth_bad_request() -> Template {
    Template::render("errors/oauth/400", ())
}

#[catch(500)]
fn oauth_server_error() -> Template {
    Template::render("errors/oauth/500", ())
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
    keystore: &State<GoogleJwtKeystore>,
    cookies: &CookieJar<'_>,
    form: Form<OAuthCredentials<'_>>,
) -> Result<Template, Status> {
    log::info!("Received login response from Google.");

    // verify that the request body's g_csrf_token field is equal to the g_csrf_token cookie
    if let Some(cookie) = cookies.get("g_csrf_token").map(|c| c.value()) {
        if !cookie.eq(form.g_csrf_token) {
            log::error!("CSRF token in the form does not match the CSRF token in the cookie.");
            return Err(Status::BadRequest);
        }
    } else {
        log::error!("Request did not include CSRF cookie.");
        return Err(Status::BadRequest);
    }

    // verify the received jwt token
    let token: Result<Token<JwtHeader, JwtClaims, Verified>, jwt::Error> = {
        // acquire and release the lock on the store; there should be N readers and one writer and writes will only
        // occur once every 12-24 hours, so reader priority is important
        form.credential
            .verify_with_store(keystore.inner().inner().read().deref())
    };

    if let Err(err) = token {
        log::error!("JWT verification error: {:?}", err);

        return match err {
            JwtError::InvalidSignature => {
                log::error!("Received JWT token with invalid signature.");
                Err(Status::BadRequest)
            }
            JwtError::Base64(_)
            | JwtError::Json(_)
            | JwtError::NoHeaderComponent
            | JwtError::NoClaimsComponent
            | JwtError::NoSignatureComponent
            | JwtError::NoKeyId
            | JwtError::TooManyComponents
            | JwtError::Utf8(_) => {
                log::error!("Received a JWT token which was unusable.");
                Err(Status::BadRequest)
            }
            JwtError::AlgorithmMismatch(_, _)
            | JwtError::OpenSsl(_)
            | JwtError::NoKeyWithKeyId(_) => {
                log::error!("Failed to verify using the JWT token due to an internal error.");
                Err(Status::InternalServerError)
            }
            _ => {
                // only other variants are rust crypto errors, i.e. not openssl
                log::error!("Unknown JWT verification error, this should not be possible.");
                Err(Status::InternalServerError)
            }
        };
    } else {
        log::info!("INFO: Token verified!");
    }

    let token = token.unwrap();

    // verify that jwt claims' `aud` is equal to the google oauth client id
    if let Some(actual_oauth_client_id) = token.claims().get("aud").map(|v| v.as_str()).flatten() {
        if !oauth.client_id.eq(actual_oauth_client_id) {
            log::error!(
                "JWT token's aud field does not match our client id, found {}, expected {}",
                actual_oauth_client_id,
                oauth.client_id
            );
            return Err(Status::BadRequest);
        }
    } else {
        log::error!(
            "JWT token's aud field is not present; it must be present and set to {}",
            oauth.client_id
        );
        return Err(Status::BadRequest);
    }

    // verify that jwt claims' `iss` is equal to /(https\:\/\/)?accounts\.google\.com/
    if let Some(token_issuer) = token.claims().get("iss").map(|v| v.as_str()).flatten() {
        if !token_issuer.eq("accounts.google.com")
            && !token_issuer.eq("https://accounts.google.com")
        {
            log::error!(
                "JWT token issuer is not accounts.google.com: {}",
                token_issuer
            );
            return Err(Status::BadRequest);
        }
    } else {
        log::error!(
            "JWT token issuer is not set; it must be present and set to accounts.google.com"
        );
        return Err(Status::BadRequest);
    }

    // check time constraints on the token, that exp is in the future and nbf is in the past
    let now = OffsetDateTime::now_utc();

    // check that the jwt field `exp` is in the future
    if let Some(Ok(exp)) = token
        .claims()
        .get("exp")
        .map(|v| v.as_u64())
        .flatten()
        .map(|n| {
            OffsetDateTime::from_unix_timestamp(n.try_into().unwrap_or(i64::MAX)).map_err(|e| {
                log::error!(
                    "Unable to parse date from Unix timestamp in JWT's 'exp' field: {}",
                    e
                );
                e
            })
        })
    {
        if exp <= now {
            log::error!(
                "Received an expired JWT token, expired at {}",
                exp.format(&Rfc3339).unwrap()
            );
            return Err(Status::BadRequest);
        }
    } else {
        log::error!("JWT token did not contain a usable expiration date.");
        return Err(Status::BadRequest);
    }

    // check that the jwt field `nbf` is in the past
    if let Some(Ok(nbf)) = token
        .claims()
        .get("nbf")
        .map(|v| v.as_u64())
        .flatten()
        .map(|n| {
            OffsetDateTime::from_unix_timestamp(n.try_into().unwrap_or(i64::MAX)).map_err(|e| {
                log::error!(
                    "Unable to parse date from Unix timestamp in JWT's 'exp' field: {}",
                    e
                );
                e
            })
        })
    {
        if nbf > now {
            log::error!(
                "Received a JWT token which is not valid yet, validity starts at: {}",
                nbf.format(&Rfc3339).unwrap()
            );
            // this is an internal server error because it's likely that our clock is off
            return Err(Status::InternalServerError);
        }
    }

    // convert the headers into a serde_json::Value for template rendering
    let headers_value = serde_json::to_value(token.header()).unwrap();

    Ok(Template::render(
        "login",
        HashMap::from([("header", &headers_value), ("claims", token.claims())]),
    ))
}

/// Fetch static files from /static/.
#[get("/static/<file..>")]
async fn static_files(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).await.ok()
}

/// Start the Rocket server.
pub async fn start() -> Rocket<Build> {
    env_logger::builder()
        .filter_level(LevelFilter::Error)
        .filter_module("rkt_oauth", LevelFilter::Debug)
        .filter_module("rocket", LevelFilter::Debug)
        .init();

    // get the google oauth client id from the environment
    let oauth_client_id = env::var(OAUTH_CLIENT_ID_VAR).unwrap_or_else(|e| {
        log::error!(
            "Please set the Google OAuth client ID in the {} variable: {}",
            OAUTH_CLIENT_ID_VAR,
            e
        );
        exit(1)
    });

    // fetch the google jwt signing certificates
    let certs = GoogleJwtKeystore::init().await.unwrap_or_else(|e| {
        log::error!("Unable to initialize the keystore: {}", e);
        exit(1)
    });

    rocket::build()
        .mount("/", routes![index, static_files, oauth_success])
        .manage(OAuthConfig {
            client_id: oauth_client_id,
        })
        .manage(certs)
        .register(
            "/oauth/success",
            catchers![oauth_bad_request, oauth_server_error],
        )
        .attach(Template::fairing())
}
