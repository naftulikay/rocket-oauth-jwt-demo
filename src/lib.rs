pub(crate) mod fairings;
pub(crate) mod google;
pub(crate) mod models;
pub(crate) mod routes;

use log::LevelFilter;
use rocket::{catchers, routes, Build, Rocket};
use rocket_dyn_templates::Template;
use std::process::exit;

use crate::google::{GoogleJwtKeystore, OAuthConfigService, OAuthCredentials};

/// Start the Rocket server.
pub async fn start() -> Rocket<Build> {
    env_logger::builder()
        .filter_level(LevelFilter::Error)
        .filter_module("rkt_oauth", LevelFilter::Debug)
        .filter_module("rocket", LevelFilter::Debug)
        .init();

    // fetch the google jwt signing certificates
    let certs = GoogleJwtKeystore::init().await.unwrap_or_else(|e| {
        log::error!("Unable to initialize the keystore: {}", e);
        exit(1)
    });

    rocket::build()
        .mount(
            "/",
            routes![
                routes::index,
                routes::static_files,
                routes::oauth_success_handler
            ],
        )
        .manage(OAuthConfigService::from_env().unwrap_or_else(|e| {
            log::error!("Unable to initialize the OAuth config service: {}", e);
            exit(1)
        }))
        .manage(certs)
        .register(
            "/oauth/success",
            catchers![
                routes::catch_oauth_bad_request,
                routes::catch_oauth_server_error
            ],
        )
        .attach(Template::fairing())
}
