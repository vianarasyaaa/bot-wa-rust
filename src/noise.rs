use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub const NOISE_MODE: &[u8] = b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0";
pub const WA_HEADER: [u8; 4] = [b'W', b'A', 6, 3];

pub struct Noise {
    hash: [u8; 32],
    salt: [u8; 32],
    enc_key: [u8; 32],
    dec_key: [u8; 32],
    read_ctr: u32,
    write_ctr: u32,
    finished: bool,
    sent_intro: bool,
    inbuf: Vec<u8>,
}

fn hkdf64(salt: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 64];
    hk.expand(&[], &mut out).expect("hkdf expand");
    (out[..32].try_into().unwrap(), out[32..].try_into().unwrap())
}

fn iv(ctr: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[8..].copy_from_slice(&ctr.to_be_bytes());
    iv
}

impl Noise {
    pub fn new(ephemeral_pub: &[u8]) -> Self {
        let mut mode = [0u8; 32];
        mode.copy_from_slice(NOISE_MODE);
        let mut n = Noise {
            hash: mode,
            salt: mode,
            enc_key: mode,
            dec_key: mode,
            read_ctr: 0,
            write_ctr: 0,
            finished: false,
            sent_intro: false,
            inbuf: Vec::new(),
        };
        n.authenticate(&WA_HEADER);
        n.authenticate(ephemeral_pub);
        n
    }

    pub fn authenticate(&mut self, data: &[u8]) {
        if !self.finished {
            let mut h = Sha256::new();
            h.update(self.hash);
            h.update(data);
            self.hash = h.finalize().into();
        }
    }

    fn aad(&self) -> &[u8] {
        if self.finished {
            &[]
        } else {
            &self.hash
        }
    }

    pub fn encrypt(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.enc_key).map_err(|_| anyhow!("key"))?;
        let nonce_bytes = iv(self.write_ctr);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: pt, aad: self.aad() })
            .map_err(|_| anyhow!("enkripsi gagal"))?;
        self.write_ctr += 1;
        self.authenticate(&ct);
        Ok(ct)
    }

    pub fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.dec_key).map_err(|_| anyhow!("key"))?;
        let ctr = if self.finished { self.read_ctr } else { self.write_ctr };
        let nonce_bytes = iv(ctr);
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: ct, aad: self.aad() })
            .map_err(|_| anyhow!("dekripsi gagal (tag GCM tidak cocok)"))?;
        if self.finished {
            self.read_ctr += 1;
        } else {
            self.write_ctr += 1;
        }
        self.authenticate(ct);
        Ok(pt)
    }

    pub fn mix_into_key(&mut self, data: &[u8]) {
        let (write, read) = hkdf64(&self.salt, data);
        self.salt = write;
        self.enc_key = read;
        self.dec_key = read;
        self.read_ctr = 0;
        self.write_ctr = 0;
    }

    pub fn finish_init(&mut self) {
        let (write, read) = hkdf64(&self.salt, &[]);
        self.enc_key = write;
        self.dec_key = read;
        self.read_ctr = 0;
        self.write_ctr = 0;
        self.finished = true;
    }

    pub fn encode_frame(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let body = if self.finished { self.encrypt(data)? } else { data.to_vec() };
        let mut out = Vec::with_capacity(body.len() + 7);
        if !self.sent_intro {
            out.extend_from_slice(&WA_HEADER);
            self.sent_intro = true;
        }
        let n = body.len();
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Masukkan chunk dari WebSocket, keluarkan frame utuh (belum didekripsi).
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.inbuf.extend_from_slice(chunk);
        let mut frames = Vec::new();
        loop {
            if self.inbuf.len() < 3 {
                break;
            }
            let n = ((self.inbuf[0] as usize) << 16) | ((self.inbuf[1] as usize) << 8) | self.inbuf[2] as usize;
            if self.inbuf.len() < 3 + n {
                break;
            }
            frames.push(self.inbuf[3..3 + n].to_vec());
            self.inbuf.drain(..3 + n);
        }
        frames
    }
}
