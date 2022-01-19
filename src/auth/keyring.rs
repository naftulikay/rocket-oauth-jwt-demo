#[cfg(test)]
mod tests;

use anyhow::Error;
use josekit::jwk::Jwk;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct JwkKeyring {
    file: PathBuf,
    store: JwkKeyringStore,
}

#[derive(Debug)]
struct JwkKeyringStore {
    signing_key: String,
    keys: HashMap<String, Jwk>,
}

impl JwkKeyring {
    pub async fn load<P: Into<PathBuf>>(_file: P) -> Result<Self, Error> {
        todo!()
    }

    pub fn insert<S: Into<String>>(&mut self, key_id: S, key: Jwk) {
        let key = {
            let mut value = key;
            value.set_key_id(key_id);
            value
        };

        self.store.keys.insert(key.key_id().unwrap().into(), key);
    }
}
