pub(crate) mod catchers;
pub(crate) mod oauth;

pub(crate) use catchers::{catch_oauth_bad_request, catch_oauth_server_error};
pub(crate) use oauth::oauth_success_handler;

use crate::google::OAuthConfigService;
use rocket::fs::NamedFile;
use rocket::{get, State};
use rocket_dyn_templates::Template;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The root URL, which simply renders HTML including the Google sign-in button with the OAuth
/// client id.
#[get("/")]
pub(crate) fn index(oauth: &State<OAuthConfigService>) -> Template {
    Template::render(
        "index",
        HashMap::from([("oauth_client_id", oauth.client_id().clone())]),
    )
}

/// Fetch static files from /static/.
#[get("/static/<file..>")]
pub(crate) async fn static_files(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).await.ok()
}
