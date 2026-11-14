use crate::creds::Creds;
use crate::crypto::{dh, KeyPair};
use aes::Aes256;
use anyhow::{anyhow, bail, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::{fs, path::Path};

const MAX_SKIP: u32 = 2000;
const MAX_SESSIONS: usize = 5;
const MAX_CHAINS: usize = 5;

#[derive(Clone, PartialEq, ::prost::Message)]
struct SignalMessage {
    #[prost(bytes = "vec", optional, tag = "1")]
    ratchet_key: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "2")]
    counter: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    previous_counter: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    ciphertext: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct PreKeySignalMessage {
    #[prost(uint32, optional, tag = "1")]
    pre_key_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    base_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    identity_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    message: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "5")]
    registration_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    signed_pre_key_id: Option<u32>,
}

// ---------- util kripto ----------

fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn hkdf_fill(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, out).expect("hkdf");
}

fn p05(k: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![5u8];
    v.extend_from_slice(k);
    v
}

fn s05(b: &[u8]) -> Result<[u8; 32]> {
    let raw = if b.len() == 33 && b[0] == 5 { &b[1..] } else { b };
    <[u8; 32]>::try_from(raw).map_err(|_| anyhow!("kunci publik tidak valid ({} byte)", b.len()))
}

fn ratchet_step(root: &[u8; 32], their_pub: &[u8; 32], our_priv: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let shared = dh(our_priv, their_pub);
    let mut o = [0u8; 64];
    hkdf_fill(&shared, root, b"WhisperRatchet", &mut o);
    (o[..32].try_into().unwrap(), o[32..].try_into().unwrap())
}

/// chain key -> (seed message key, chain key berikutnya)
fn next_chain(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (hmac256(ck, &[&[1]]), hmac256(ck, &[&[2]]))
}

fn derive_message_keys(seed: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let mut o = [0u8; 80];
    hkdf_fill(seed, &[0u8; 32], b"WhisperMessageKeys", &mut o);
    (
        o[..32].try_into().unwrap(),
        o[32..64].try_into().unwrap(),
        o[64..].try_into().unwrap(),
    )
}

fn cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    let enc = cbc::Encryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| anyhow!("cbc key/iv"))?;
    Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(data))
}

fn cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    let dec = cbc::Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| anyhow!("cbc key/iv"))?;
    dec.decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| anyhow!("padding CBC tidak valid"))
}

// ---------- state sesi ----------

#[derive(Serialize, Deserialize, Clone)]
pub struct RecvChain {
    ratchet: [u8; 32],
    chain_key: [u8; 32],
    index: u32,
    skipped: Vec<(u32, [u8; 32])>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    root_key: [u8; 32],
    send_priv: [u8; 32],
    send_pub: [u8; 32],
    send_chain: [u8; 32],
    send_index: u32,
    prev_counter: u32,
    recv: Vec<RecvChain>,
    remote_identity: [u8; 32],
    base_key: [u8; 32],
}

fn fill_skipped(chain: &mut RecvChain, until: u32) -> Result<()> {
    if until.saturating_sub(chain.index) > MAX_SKIP {
        bail!("terlalu banyak pesan terlewat ({} -> {})", chain.index, until);
    }
    while chain.index < until {
        let (seed, next) = next_chain(&chain.chain_key);
        chain.skipped.push((chain.index, seed));
        chain.chain_key = next;
        chain.index += 1;
    }
    while chain.skipped.len() > MAX_SKIP as usize {
        chain.skipped.remove(0);
    }
    Ok(())
}

fn take_message_key(chain: &mut RecvChain, counter: u32) -> Result<[u8; 32]> {
    if counter < chain.index {
        let pos = chain
            .skipped
            .iter()
            .position(|(i, _)| *i == counter)
            .ok_or_else(|| anyhow!("pesan duplikat atau terlalu lama (counter {counter})"))?;
        return Ok(chain.skipped.remove(pos).1);
    }
    fill_skipped(chain, counter)?;
    let (seed, next) = next_chain(&chain.chain_key);
    chain.chain_key = next;
    chain.index = counter + 1;
    Ok(seed)
}

fn decrypt_signal(s: &mut Session, raw: &[u8], our_identity: &[u8; 32]) -> Result<Vec<u8>> {
    if raw.len() < 10 {
        bail!("SignalMessage terlalu pendek");
    }
    if raw[0] >> 4 != 3 {
        bail!("versi Signal {} tidak didukung", raw[0] >> 4);
    }
    let (body, mac) = raw.split_at(raw.len() - 8);
    let msg = SignalMessage::decode(&body[1..])?;
    let their_ratchet = s05(msg.ratchet_key.as_deref().unwrap_or_default())?;
    let counter = msg.counter.unwrap_or(0);
    let prev = msg.previous_counter.unwrap_or(0);
    let ct = msg.ciphertext.unwrap_or_default();

    if !s.recv.iter().any(|c| c.ratchet == their_ratchet) {
        if let Some(last) = s.recv.last_mut() {
            fill_skipped(last, prev)?;
        }
        let (root1, chain_key) = ratchet_step(&s.root_key, &their_ratchet, &s.send_priv);
        let new_pair = KeyPair::generate();
        let (root2, send_chain) = ratchet_step(&root1, &their_ratchet, &new_pair.private);
        s.recv.push(RecvChain { ratchet: their_ratchet, chain_key, index: 0, skipped: vec![] });
        if s.recv.len() > MAX_CHAINS {
            s.recv.remove(0);
        }
        s.prev_counter = s.send_index.saturating_sub(1);
        s.root_key = root2;
        s.send_priv = new_pair.private;
        s.send_pub = new_pair.public;
        s.send_chain = send_chain;
        s.send_index = 0;
    }

    let seed = {
        let chain = s
            .recv
            .iter_mut()
            .find(|c| c.ratchet == their_ratchet)
            .ok_or_else(|| anyhow!("receiver chain hilang"))?;
        take_message_key(chain, counter)?
    };
    let (ck, mk, iv) = derive_message_keys(&seed);

    let expect = hmac256(&mk, &[&[5], &s.remote_identity, &[5], our_identity, body]);
    if expect[..8] != *mac {
        bail!("MAC pesan tidak cocok");
    }
    cbc_decrypt(&ck, &iv, &ct)
}

fn encrypt_signal(s: &mut Session, plain: &[u8], our_identity: &[u8; 32]) -> Result<Vec<u8>> {
    let (seed, next) = next_chain(&s.send_chain);
    let (ck, mk, iv) = derive_message_keys(&seed);
    let ct = cbc_encrypt(&ck, &iv, plain)?;
    let msg = SignalMessage {
        ratchet_key: Some(p05(&s.send_pub)),
        counter: Some(s.send_index),
        previous_counter: Some(s.prev_counter),
        ciphertext: Some(ct),
    };
    let mut body = vec![0x33u8];
    body.extend_from_slice(&msg.encode_to_vec());
    let mac = hmac256(&mk, &[&[5], our_identity, &[5], &s.remote_identity, &body]);
    body.extend_from_slice(&mac[..8]);
    s.send_chain = next;
    s.send_index += 1;
    Ok(body)
}

fn build_recipient_session(
    pk: &PreKeySignalMessage,
    creds: &Creds,
    prekeys: &HashMap<u32, [u8; 32]>,
) -> Result<Session> {
    let their_identity = s05(pk.identity_key.as_deref().unwrap_or_default())?;
    let their_base = s05(pk.base_key.as_deref().unwrap_or_default())?;
    let spk_id = pk.signed_pre_key_id.unwrap_or(0);
    if spk_id != creds.spk_id {
        bail!("signed prekey id {spk_id} tidak dikenal");
    }
    let mut secrets = vec![0xFFu8; 32];
    secrets.extend_from_slice(&dh(&creds.spk.private, &their_identity));
    secrets.extend_from_slice(&dh(&creds.identity.private, &their_base));
    secrets.extend_from_slice(&dh(&creds.spk.private, &their_base));
    if let Some(id) = pk.pre_key_id {
        let p = prekeys
            .get(&id)
            .ok_or_else(|| anyhow!("one-time prekey {id} tidak ditemukan"))?;
        secrets.extend_from_slice(&dh(p, &their_base));
    }
    let mut o = [0u8; 64];
    hkdf_fill(&secrets, &[0u8; 32], b"WhisperText", &mut o);
    Ok(Session {
        root_key: o[..32].try_into().unwrap(),
        send_priv: creds.spk.private,
        send_pub: creds.spk.public,
        send_chain: o[32..].try_into().unwrap(),
        send_index: 0,
        prev_counter: 0,
        recv: vec![],
        remote_identity: their_identity,
        base_key: their_base,
    })
}

// ---------- store (prekey + sesi) ----------

#[derive(Serialize, Deserialize, Default)]
pub struct Store {
    #[serde(default)]
    pub prekeys: HashMap<u32, [u8; 32]>,
    #[serde(default)]
    pub next_prekey_id: u32,
    #[serde(default)]
    pub sessions: HashMap<String, Vec<Session>>,
}

impl Store {
    pub fn load(path: &str) -> Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Store::default());
        }
        Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        crate::storage::atomic_write(
            path,
            &serde_json::to_vec(self)?,
        )?;
        Ok(())
    }

    /// Buat n prekey sekali-pakai baru, kembalikan (id, public).
    pub fn gen_prekeys(&mut self, n: u32) -> Vec<(u32, [u8; 32])> {
        let start = self.next_prekey_id.max(1);
        let mut out = Vec::new();
        for i in 0..n {
            let kp = KeyPair::generate();
            self.prekeys.insert(start + i, kp.private);
            out.push((start + i, kp.public));
        }
        self.next_prekey_id = start + n;
        out
    }

    pub fn decrypt(&mut self, addr: &str, kind: &str, data: &[u8], creds: &Creds) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("data enc kosong");
        }
        let our_id = creds.identity.public;
        if kind == "pkmsg" {
            if data[0] >> 4 != 3 {
                bail!("versi PreKeySignalMessage {} tidak didukung", data[0] >> 4);
            }
            let pk = PreKeySignalMessage::decode(&data[1..])?;
            let inner = pk.message.clone().ok_or_else(|| anyhow!("pkmsg tanpa message"))?;
            let their_base = s05(pk.base_key.as_deref().unwrap_or_default())?;
            let list = self.sessions.entry(addr.to_string()).or_default();
            if let Some(pos) = list.iter().position(|s| s.base_key == their_base) {
                let mut s2 = list[pos].clone();
                let pt = decrypt_signal(&mut s2, &inner, &our_id)?;
                list.remove(pos);
                list.insert(0, s2);
                return Ok(pt);
            }
            let mut sess = build_recipient_session(&pk, creds, &self.prekeys)?;
            let pt = decrypt_signal(&mut sess, &inner, &our_id)?;
            if let Some(id) = pk.pre_key_id {
                self.prekeys.remove(&id);
            }
            list.insert(0, sess);
            list.truncate(MAX_SESSIONS);
            return Ok(pt);
        }

        let list = self
            .sessions
            .get_mut(addr)
            .ok_or_else(|| anyhow!("belum ada sesi untuk {addr}"))?;
        for i in 0..list.len() {
            let mut s2 = list[i].clone();
            if let Ok(pt) = decrypt_signal(&mut s2, data, &our_id) {
                list.remove(i);
                list.insert(0, s2);
                return Ok(pt);
            }
        }
        bail!("tidak ada sesi yang cocok untuk {addr}")
    }

    /// Enkripsi untuk sesi yang sudah ada (hasil: SignalMessage, type "msg").
    pub fn encrypt(&mut self, addr: &str, plain: &[u8], creds: &Creds) -> Result<Vec<u8>> {
        let s = self
            .sessions
            .get_mut(addr)
            .and_then(|l| l.first_mut())
            .ok_or_else(|| anyhow!("belum ada sesi dengan {addr}"))?;
        encrypt_signal(s, plain, &creds.identity.public)
    }
}
