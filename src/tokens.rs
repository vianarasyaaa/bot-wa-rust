use serde::Deserialize;
use std::{collections::HashMap, sync::OnceLock};

#[derive(Deserialize)]
struct Raw {
    single: Vec<String>,
    double: Vec<Vec<String>>,
}

pub struct Tokens {
    pub single: Vec<String>,
    pub double: Vec<Vec<String>>,
    /// string -> (nomor dictionary jika token ganda, index)
    pub map: HashMap<String, (Option<u8>, u8)>,
}

static TOKENS: OnceLock<Tokens> = OnceLock::new();

pub fn tokens() -> &'static Tokens {
    TOKENS.get_or_init(|| {
        let raw: Raw = serde_json::from_str(include_str!("tokens.json")).expect("tokens.json rusak");
        let mut map = HashMap::new();
        for (d, list) in raw.double.iter().enumerate() {
            for (i, t) in list.iter().enumerate() {
                if !t.is_empty() && i < 256 {
                    map.insert(t.clone(), (Some(d as u8), i as u8));
                }
            }
        }
        for (i, t) in raw.single.iter().enumerate() {
            if !t.is_empty() && i < 236 {
                map.insert(t.clone(), (None, i as u8));
            }
        }
        Tokens { single: raw.single, double: raw.double, map }
    })
}
