use jwt::{Token, Unverified};
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket::http::CookieJar;
use rocket::{get, post, routes, Build, Rocket};
use rocket::{FromForm, State};
use rocket_dyn_templates::Template;
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
    cookies: &CookieJar<'_>,
    form: Form<OAuthCredentials<'_>>,
) -> std::io::Result<Template> {
    if let Some(cookie) = cookies.get("g_csrf_token").map(|c| c.value()) {
        if !cookie.eq(form.g_csrf_token) {
            // FIXME return 400: csrf verification failed
        }
    } else {
        // FIXME return 400: did not receive csrf cookie
    }

    let token: Token<JwtHeader, JwtClaims, Unverified> =
        Token::parse_unverified(form.credential).unwrap();

    if let Some(actual_oauth_client_id) = token.claims().get("aud").map(|v| v.as_str()).flatten() {
        if !oauth.client_id.eq(actual_oauth_client_id) {
            // FIXME return 400: jwt `aud` field does not match our oauth client id
        }
    } else {
        // FIXME return 400: jwt `aud` field not set
    }

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
pub fn start() -> Rocket<Build> {
    let oauth_client_id = env::var(OAUTH_CLIENT_ID_VAR).unwrap_or_else(|e| {
        eprintln!(
            "ERROR: Please set the Google OAuth client ID in the {} variable: {}",
            OAUTH_CLIENT_ID_VAR, e
        );
        exit(1)
    });

    rocket::build()
        .mount("/", routes![index, static_files, oauth_success])
        .manage(OAuthConfig {
            client_id: oauth_client_id,
        })
        .attach(Template::fairing())
}
