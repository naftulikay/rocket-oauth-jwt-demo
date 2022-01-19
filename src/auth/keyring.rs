use anyhow::Error;
use josekit::jwk::Jwk;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct JwkKeyring {
    file: PathBuf,
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

        self.keys.insert(key.key_id().unwrap().into(), key);
    }
}
