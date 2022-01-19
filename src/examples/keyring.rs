use anyhow::Result;
use rocket::tokio;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Default, Deserialize, Serialize)]
struct Transparent {
    #[serde(flatten)]
    map: Map<String, Value>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let source = {
        let mut r = Transparent::default();
        r.map.insert("kty".into(), "OKP".into());
        r.map.insert("use".into(), "sig".into());
        r.map.insert("alg".into(), "EdDSA".into());
        r.map.insert("crv".into(), "Ed25519".into());
        r.map.insert(
            "d".into(),
            "BoSEh29I4_3NHKQAJKFsWRErvz8yOzNBsLZ_WJvoduw".into(),
        );
        r.map.insert(
            "x".into(),
            "8jtrgTb-O67D5ru4xFlSK1PcPK6CX_Pa7xdADZZEDmg".into(),
        );
        r.map.insert("kid".into(), "my-key-v1".into());
        r
    };

    let serialized_str = serde_json::to_string_pretty(&source).unwrap();

    println!("Serialized: {}", serialized_str);

    let deserialized: Transparent = serde_json::from_str(serialized_str.as_str()).unwrap();

    println!("Deserialized: {:#?}", deserialized);

    Ok(())
}
