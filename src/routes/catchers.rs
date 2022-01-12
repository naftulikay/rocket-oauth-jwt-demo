use rocket::catch;
use rocket_dyn_templates::Template;

/// Catch a 400 response from the OAuth callback handler, usually an indication that we received a
/// bad request from Google.
#[catch(400)]
pub(crate) fn catch_oauth_bad_request() -> Template {
    Template::render("errors/oauth/400", ())
}

/// Catch a 500 response from the OAuth callback handler, usually an indication that we experienced
/// an internal server error during the handler.
#[catch(500)]
pub(crate) fn catch_oauth_server_error() -> Template {
    Template::render("errors/oauth/500", ())
}
