use crate::adv::{AdvDeviceIdentity, AdvSignedDeviceIdentity, AdvSignedDeviceIdentityHmac};
use crate::binary::{Content, Node};
use crate::creds::Creds;
use crate::crypto::{dh, random_bytes, xeddsa_sign, xeddsa_verify, KeyPair};
use aes::Aes256;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message as _;
use sha2::Sha256;

const CROCKFORD: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";

/// Kode pairing 8 karakter (Crockford base32 dari 5 byte acak)
fn random_pairing_code() -> String {
    let bytes: [u8; 5] = random_bytes();
    let mut value: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = String::new();
    for b in bytes {
        value = (value << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            out.push(CROCKFORD[((value >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((value << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub struct PairingState {
    pub code: String,
    pub eph: KeyPair,
    pub jid: String,
}

impl PairingState {
    pub fn new(phone: &str) -> Self {
        Self {
            code: random_pairing_code(),
            eph: KeyPair::generate(),
            jid: format!("{phone}@s.whatsapp.net"),
        }
    }
    pub fn pretty(&self) -> String {
        format!("{}-{}", &self.code[..4], &self.code[4..])
    }
}

fn k32(b: &[u8]) -> Result<[u8; 32]> {
    // terima juga format 33 byte berawalan 0x05
    let b = if b.len() == 33 && b[0] == 5 { &b[1..] } else { b };
    <[u8; 32]>::try_from(b).map_err(|_| anyhow!("kunci harus 32 byte, dapat {}", b.len()))
}

fn derive_key(code: &str, salt: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(code.as_bytes(), salt, 2 << 16, &mut k);
    k
}

fn aes_ctr(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    let mut c = Ctr128BE::<Aes256>::new_from_slices(key, iv).expect("ctr key/iv");
    c.apply_keystream(&mut buf);
    buf
}

fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("hkdf");
    out
}

fn bytes_of(parent: &Node, tag: &str) -> Result<Vec<u8>> {
    let n = parent.child(tag).ok_or_else(|| anyhow!("node {tag} tidak ada"))?;
    match &n.content {
        Content::Bytes(b) => Ok(b.clone()),
        Content::Text(s) => Ok(s.as_bytes().to_vec()),
        _ => bail!("isi node {tag} kosong"),
    }
}

/// Tahap 1: companion_hello (kirim setelah menerima pair-device)
pub fn companion_hello(st: &PairingState, noise_pub: &[u8; 32], id: &str) -> Node {
    let salt: [u8; 32] = random_bytes();
    let iv: [u8; 16] = random_bytes();
    let key = derive_key(&st.code, &salt);
    let ct = aes_ctr(&key, &iv, &st.eph.public);
    let mut wrapped = Vec::with_capacity(80);
    wrapped.extend_from_slice(&salt);
    wrapped.extend_from_slice(&iv);
    wrapped.extend_from_slice(&ct);

    Node::new(
        "iq",
        &[("to", "s.whatsapp.net"), ("type", "set"), ("id", id), ("xmlns", "md")],
        Content::Nodes(vec![Node::new(
            "link_code_companion_reg",
            &[
                ("jid", &st.jid),
                ("stage", "companion_hello"),
                ("should_show_push_notification", "true"),
            ],
            Content::Nodes(vec![
                Node::new("link_code_pairing_wrapped_companion_ephemeral_pub", &[], Content::Bytes(wrapped)),
                Node::new("companion_server_auth_key_pub", &[], Content::Bytes(noise_pub.to_vec())),
                Node::new("companion_platform_id", &[], Content::Text("1".into())),
                Node::new("companion_platform_display", &[], Content::Text("Chrome (Ubuntu)".into())),
                Node::new("link_code_pairing_nonce", &[], Content::Text("0".into())),
            ]),
        )]),
    )
}

/// Tahap 2: balas primary_hello dari HP (notifikasi link_code_companion_reg)
pub fn companion_finish(st: &PairingState, creds: &mut Creds, reg: &Node, id: &str) -> Result<Node> {
    let pair_ref = bytes_of(reg, "link_code_pairing_ref")?;
    let primary_identity = k32(&bytes_of(reg, "primary_identity_pub")?)?;
    let wrapped = bytes_of(reg, "link_code_pairing_wrapped_primary_ephemeral_pub")?;
    if wrapped.len() < 80 {
        bail!("wrapped primary ephemeral terlalu pendek ({} byte)", wrapped.len());
    }
    let salt = &wrapped[..32];
    let iv: [u8; 16] = wrapped[32..48].try_into().map_err(|_| anyhow!("iv"))?;
    let key = derive_key(&st.code, salt);
    let primary_eph = k32(&aes_ctr(&key, &iv, &wrapped[48..80]))?;

    let companion_shared = dh(&st.eph.private, &primary_eph);
    let random: [u8; 32] = random_bytes();
    let link_salt: [u8; 32] = random_bytes();
    let expanded = hkdf32(
        &companion_shared,
        Some(&link_salt),
        b"link_code_pairing_key_bundle_encryption_key",
    );

    let mut plain = Vec::with_capacity(96);
    plain.extend_from_slice(&creds.identity.public);
    plain.extend_from_slice(&primary_identity);
    plain.extend_from_slice(&random);
    let enc_iv: [u8; 12] = random_bytes();
    let cipher = Aes256Gcm::new_from_slice(&expanded).map_err(|_| anyhow!("gcm key"))?;
    let enc = cipher
        .encrypt(Nonce::from_slice(&enc_iv), Payload { msg: &plain, aad: &[] })
        .map_err(|_| anyhow!("enkripsi key bundle gagal"))?;
    let mut bundle = Vec::new();
    bundle.extend_from_slice(&link_salt);
    bundle.extend_from_slice(&enc_iv);
    bundle.extend_from_slice(&enc);

    let identity_shared = dh(&creds.identity.private, &primary_identity);
    let mut idp = Vec::with_capacity(96);
    idp.extend_from_slice(&companion_shared);
    idp.extend_from_slice(&identity_shared);
    idp.extend_from_slice(&random);
    creds.adv_secret = hkdf32(&idp, None, b"adv_secret");

    Ok(Node::new(
        "iq",
        &[("to", "s.whatsapp.net"), ("type", "set"), ("id", id), ("xmlns", "md")],
        Content::Nodes(vec![Node::new(
            "link_code_companion_reg",
            &[("jid", &st.jid), ("stage", "companion_finish")],
            Content::Nodes(vec![
                Node::new("link_code_pairing_wrapped_key_bundle", &[], Content::Bytes(bundle)),
                Node::new("companion_identity_public", &[], Content::Bytes(creds.identity.public.to_vec())),
                Node::new("link_code_pairing_ref", &[], Content::Bytes(pair_ref)),
            ]),
        )]),
    ))
}

/// Proses iq pair-success: verifikasi HMAC + tanda tangan akun, lalu buat balasan pair-device-sign.
pub fn handle_pair_success(stanza: &Node, creds: &mut Creds) -> Result<(Node, String)> {
    let id = stanza.attr("id").unwrap_or("").to_string();
    let ps = stanza.child("pair-success").ok_or_else(|| anyhow!("pair-success tidak ada"))?;
    let di = ps.child("device-identity").ok_or_else(|| anyhow!("device-identity tidak ada"))?;
    let dev = ps.child("device").ok_or_else(|| anyhow!("node device tidak ada"))?;
    let jid = dev.attr("jid").ok_or_else(|| anyhow!("jid perangkat tidak ada"))?.to_string();
    let lid = dev.attr("lid").map(|s| s.to_string());

    let blob = match &di.content {
        Content::Bytes(b) => b.clone(),
        _ => bail!("device-identity bukan biner"),
    };
    let h = AdvSignedDeviceIdentityHmac::decode(blob.as_slice())?;
    let details = h.details.unwrap_or_default();
    let hmac_val = h.hmac.unwrap_or_default();

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&creds.adv_secret).map_err(|_| anyhow!("hmac key"))?;
    if h.account_type == Some(1) {
        mac.update(&[6, 5]);
    }
    mac.update(&details);
    mac.verify_slice(&hmac_val)
        .map_err(|_| anyhow!("Invalid account signature (HMAC tidak cocok)"))?;

    let mut account = AdvSignedDeviceIdentity::decode(details.as_slice())?;
    let sig_key_raw = account.account_signature_key.clone().unwrap_or_default();
    let sig_key = k32(&sig_key_raw)?;
    let acc_sig: [u8; 64] = account
        .account_signature
        .as_deref()
        .unwrap_or_default()
        .try_into()
        .map_err(|_| anyhow!("account signature bukan 64 byte"))?;
    let dd = account.details.clone().unwrap_or_default();
    let dev_identity = AdvDeviceIdentity::decode(dd.as_slice())?;
    let hosted = dev_identity.device_type == Some(1);

    let mut msg = Vec::new();
    msg.extend_from_slice(if hosted { &[6, 5] } else { &[6, 0] });
    msg.extend_from_slice(&dd);
    msg.extend_from_slice(&creds.identity.public);
    if !xeddsa_verify(&sig_key, &msg, &acc_sig) {
        bail!("Failed to verify account signature");
    }

    let mut dmsg = Vec::new();
    dmsg.extend_from_slice(if hosted { &[6, 6] } else { &[6, 1] });
    dmsg.extend_from_slice(&dd);
    dmsg.extend_from_slice(&creds.identity.public);
    dmsg.extend_from_slice(&sig_key_raw);
    account.device_signature = Some(xeddsa_sign(&creds.identity.private, &dmsg).to_vec());

    let with_key = account.encode_to_vec();
    let mut to_send = account.clone();
    to_send.account_signature_key = None;
    let enc = to_send.encode_to_vec();

    creds.me_jid = Some(jid.clone());
    creds.me_lid = lid;
    creds.account = Some(hex::encode(with_key));
    creds.account_sig_key = Some(hex::encode(sig_key));
    creds.registered = true;

    let key_index = dev_identity.key_index.unwrap_or(0).to_string();
    let reply = Node::new(
        "iq",
        &[("to", "s.whatsapp.net"), ("type", "result"), ("id", &id)],
        Content::Nodes(vec![Node::new(
            "pair-device-sign",
            &[],
            Content::Nodes(vec![Node::new(
                "device-identity",
                &[("key-index", &key_index)],
                Content::Bytes(enc),
            )]),
        )]),
    );
    Ok((reply, jid))
}
