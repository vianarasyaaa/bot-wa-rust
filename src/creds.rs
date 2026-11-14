use crate::crypto::{random_bytes, xeddsa_sign, KeyPair};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize)]
struct Stored {
    noise_priv: String,
    identity_priv: String,
    spk_priv: String,
    spk_sig: String,
    spk_id: u32,
    reg_id: u32,
    adv_secret: String,
    #[serde(default)]
    me_jid: Option<String>,
    #[serde(default)]
    me_lid: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    account_sig_key: Option<String>,
    #[serde(default)]
    registered: bool,
}

pub struct Creds {
    pub noise: KeyPair,
    pub identity: KeyPair,
    pub spk: KeyPair,
    pub spk_sig: [u8; 64],
    pub spk_id: u32,
    pub reg_id: u32,
    pub adv_secret: [u8; 32],
    pub me_jid: Option<String>,
    pub me_lid: Option<String>,
    pub account: Option<String>,
    pub account_sig_key: Option<String>,
    pub registered: bool,
}

fn h32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow!("kunci di creds.json rusak"))
}

impl Creds {
    pub fn save(&self, path: &str) -> Result<()> {
        let st = Stored {
            noise_priv: hex::encode(self.noise.private),
            identity_priv: hex::encode(self.identity.private),
            spk_priv: hex::encode(self.spk.private),
            spk_sig: hex::encode(self.spk_sig),
            spk_id: self.spk_id,
            reg_id: self.reg_id,
            adv_secret: hex::encode(self.adv_secret),
            me_jid: self.me_jid.clone(),
            me_lid: self.me_lid.clone(),
            account: self.account.clone(),
            account_sig_key: self.account_sig_key.clone(),
            registered: self.registered,
        };
        crate::storage::atomic_write(
            path,
            &serde_json::to_vec_pretty(&st)?,
        )?;
        Ok(())
    }
}

pub fn load_or_create(path: &str) -> Result<Creds> {
    if Path::new(path).exists() {
        let st: Stored = serde_json::from_str(&fs::read_to_string(path)?)?;
        let sig: [u8; 64] = hex::decode(&st.spk_sig)?
            .try_into()
            .map_err(|_| anyhow!("signature di creds.json rusak"))?;
        println!("[i] kredensial dimuat dari {path}");
        return Ok(Creds {
            noise: KeyPair::from_private(h32(&st.noise_priv)?),
            identity: KeyPair::from_private(h32(&st.identity_priv)?),
            spk: KeyPair::from_private(h32(&st.spk_priv)?),
            spk_sig: sig,
            spk_id: st.spk_id,
            reg_id: st.reg_id,
            adv_secret: h32(&st.adv_secret)?,
            me_jid: st.me_jid,
            me_lid: st.me_lid,
            account: st.account,
            account_sig_key: st.account_sig_key,
            registered: st.registered,
        });
    }

    let noise = KeyPair::generate();
    let identity = KeyPair::generate();
    let spk = KeyPair::generate();
    let mut m = vec![5u8];
    m.extend_from_slice(&spk.public);
    let spk_sig = xeddsa_sign(&identity.private, &m);
    let reg_id = (u16::from_be_bytes(random_bytes::<2>()) & 16383) as u32;
    let creds = Creds {
        noise,
        identity,
        spk,
        spk_sig,
        spk_id: 1,
        reg_id,
        adv_secret: random_bytes::<32>(),
        me_jid: None,
        me_lid: None,
        account: None,
        account_sig_key: None,
        registered: false,
    };
    creds.save(path)?;
    println!("[i] kredensial baru dibuat di {path}");
    Ok(creds)
}
