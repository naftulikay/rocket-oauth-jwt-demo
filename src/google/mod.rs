#[cfg(test)]
mod tests;

use anyhow::{anyhow, Error};
use isahc::AsyncReadResponseExt;
use jwt::{PKeyWithDigest, Store};
use lazy_static::lazy_static;
use openssl::hash::MessageDigest;
use openssl::pkey::Public;
use openssl::x509::X509;
use parking_lot::RwLock;
use regex::Regex;
use rocket::http::uri::{Authority, Uri};
use rocket::{tokio, FromForm};
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::ops::Sub;
use std::sync::Arc;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{Duration, OffsetDateTime};

lazy_static! {
    /// Regular expression for replacing `UTC` or `GMT` at the end of a datetime string with the
    /// equivalent hour/minute timezone offset, i.e. `00:00`.
    static ref REGEX_GMT_TRANSPOSER: Regex = Regex::new(r"\b(?:GMT|UTC)\s*$").unwrap();
}

/// The time format for parsing a `time::OffsetDateTime` from the `Expires` header after
/// transposition.
///
/// Transposition replaces `/GMT$/` with `00:00` to make parsing possible, as timezone names are not
/// supported by the `time` crate.
static EXPIRES_TIME_FORMAT: &'static [FormatItem<'static>] = format_description!(
    "[weekday repr:short], [day padding:zero] [month repr:short] [year repr:full] \
        [hour repr:24 padding:zero]:[minute padding:zero]:[second padding:zero] \
        [offset_hour padding:zero]:[offset_minute padding:zero]"
);

/// The environment variable containing the OAuth client ID.
const OAUTH_CLIENT_ID_VAR: &'static str = "GOOGLE_OAUTH_CLIENT_ID";

/// State for Rocket to maintain a read-only copy of the OAuth configuration.
pub struct OAuthConfigService {
    client_id: String,
}

impl OAuthConfigService {
    /// Create and initialize a service instance by loading values from environment variables.
    ///
    /// Specifically, loads the `GOOGLE_OAUTH_CLIENT_ID` environment variable, verifies that it is a
    /// valid URI, and returns the initialized service.
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            client_id: env::var(OAUTH_CLIENT_ID_VAR)
                .map_err(|e| {
                    anyhow!("Unable to get OAuth client ID from the environment, please set it using the {} environment variable: {}", OAUTH_CLIENT_ID_VAR, e)
                })
                // strip whitespace around the value
                .map(|s| s.trim().to_string())
                .and_then(|s| {
                    // try parsing the contents as a URI; google's client ID is a URI
                    let _ = Uri::parse::<Authority>(s.as_ref())
                        .map_err(|e| {
                            anyhow!("Unable to parse the OAuth client ID as a URI, please pass a legitimate Google OAuth client ID: {}", e)
                        })?;
                    Ok(s)
                })?
        })
    }

    /// Create and initialize a service by providing the OAuth client ID directly.
    #[allow(unused)]
    pub fn new<S: Into<String>>(oauth_client_id: S) -> Result<Self, Error> {
        let client_id = oauth_client_id.into().trim().to_string();

        if let Err(e) = Uri::parse::<Authority>(client_id.as_ref()) {
            return Err(anyhow!("Unable to parse the OAuth client ID as a URI, please pass a legitimate Google OAuth client ID: {}", e));
        }

        Ok(Self { client_id })
    }

    pub fn client_id(&self) -> &str {
        self.client_id.as_ref()
    }
}

/// Response from www.googleapis.com/oauth2/v1/certs containing key IDs to PEM-encoded certificates.
#[derive(Deserialize)]
pub struct GoogleCertsResponse(HashMap<String, String>);

/// Key-store for Google JWT signing keys.
#[derive(Clone)]
pub struct GoogleJwtKeystore {
    inner: Arc<RwLock<GoogleJwtKeystoreInner>>,
}

impl GoogleJwtKeystore {
    pub fn inner(&self) -> &RwLock<GoogleJwtKeystoreInner> {
        &self.inner
    }
}

pub struct GoogleJwtKeystoreInner {
    expires_at: OffsetDateTime,
    keys: GoogleJwtKeystoreMap,
}

pub struct GoogleJwtKeystoreMap(HashMap<String, PKeyWithDigest<Public>>);

impl GoogleJwtKeystore {
    pub async fn init() -> Result<Self, Error> {
        let (resp, expiry) = Self::fetch_certificates().await?;

        let result = Self {
            inner: Arc::new(RwLock::new(GoogleJwtKeystoreInner {
                expires_at: expiry,
                keys: GoogleJwtKeystoreMap::try_from(resp).map_err(|e| Into::<Error>::into(e))?,
            })),
        };

        let worker_store = result.clone();

        let _updater = tokio::spawn(async move {
            log::info!("Starting background certificate refresh task.");

            loop {
                // extract the expiry and release the read lock
                let expiry = { worker_store.inner.read().expires_at.clone() };

                // sleep until one minute before the expiry, or at minimum ten seconds
                let sleep_duration = (expiry - OffsetDateTime::now_utc())
                    .sub(Duration::minutes(1))
                    .max(Duration::seconds(10));

                log::info!("Sleeping for {:?}", sleep_duration);

                tokio::time::sleep(sleep_duration.try_into().unwrap()).await;

                // perform the refresh
                match Self::fetch_certificates().await {
                    Ok((resp, expiry)) => {
                        log::info!("Updating certificate store with new results.");
                        let mut writer = worker_store.inner.write();

                        match GoogleJwtKeystoreMap::try_from(resp) {
                            Ok(m) => {
                                log::debug!("Successfully updated certificate store.");
                                writer.expires_at = expiry;
                                writer.keys = m;
                            }
                            Err(e) => {
                                log::error!("Unable to deserialize signing certificates from response, trying again in 5 seconds: {}", e);
                                writer.expires_at =
                                    OffsetDateTime::now_utc() + Duration::seconds(5);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Unable to update certificate chain: {}", e);
                    }
                }
            }
        });

        Ok(result)
    }

    async fn fetch_certificates() -> Result<(GoogleCertsResponse, OffsetDateTime), Error> {
        let mut resp = isahc::get_async("https://www.googleapis.com/oauth2/v1/certs")
            .await
            .map_err(|e| {
                log::error!("Unable to get certificates: {}", e);
                e
            })?;

        let now = OffsetDateTime::now_utc();

        let (default_expiry, min_expiry, max_expiry) = (
            now + Duration::hours(12),
            now + Duration::hours(1),
            now + Duration::hours(24),
        );

        let expiry = resp
            .headers()
            .get("expires")
            .map(|h| {
                h.to_str()
                    .expect("received non ascii characters in expires header")
            })
            .map(|s| REGEX_GMT_TRANSPOSER.replace(s, "00:00").to_string())
            .map(|s| {
                OffsetDateTime::parse(s.as_ref(), EXPIRES_TIME_FORMAT)
                    .map_err(|e| {
                        log::debug!("Unable to parse datetime from expires header: {}", e);
                        e
                    })
                    .unwrap_or(default_expiry)
            })
            .unwrap_or(default_expiry)
            .min(max_expiry)
            .max(min_expiry);

        Ok((
            resp.json().await.map_err(|e| {
                log::error!(
                    "Unable to deserialize certificates from JSON response: {}",
                    e
                );
                Into::<Error>::into(e)
            })?,
            expiry,
        ))
    }
}

impl TryFrom<GoogleCertsResponse> for GoogleJwtKeystoreMap {
    type Error = anyhow::Error;

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

impl Store for GoogleJwtKeystoreInner {
    type Algorithm = PKeyWithDigest<Public>;

    fn get(&self, key_id: &str) -> Option<&Self::Algorithm> {
        self.keys.0.get(key_id)
    }
}

/// Form request sent from Google to our service containing authorization data.
#[derive(FromForm)]
pub struct OAuthCredentials<'r> {
    pub credential: &'r str,
    pub g_csrf_token: &'r str,
}
