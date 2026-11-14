use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, X25519_BASEPOINT},
    montgomery::MontgomeryPoint,
    scalar::{clamp_integer, Scalar},
};
use rand::RngCore;
use sha2::{Digest, Sha512};

pub type Key32 = [u8; 32];

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

#[derive(Clone)]
pub struct KeyPair {
    pub private: Key32,
    pub public: Key32,
}

impl KeyPair {
    pub fn generate() -> Self {
        Self::from_private(random_bytes::<32>())
    }
    pub fn from_private(private: Key32) -> Self {
        let public = X25519_BASEPOINT.mul_clamped(private).to_bytes();
        Self { private, public }
    }
}

/// X25519 Diffie-Hellman
pub fn dh(private: &Key32, public: &Key32) -> Key32 {
    MontgomeryPoint(*public).mul_clamped(*private).to_bytes()
}

/// XEdDSA / curve25519_sign ala libsignal
pub fn xeddsa_sign(private: &Key32, msg: &[u8]) -> [u8; 64] {
    let a = Scalar::from_bytes_mod_order(clamp_integer(*private));
    let big_a = (ED25519_BASEPOINT_POINT * a).compress().to_bytes();
    let sign_bit = big_a[31] & 0x80;

    let z: [u8; 64] = random_bytes();
    let mut prefix = [0xFFu8; 32];
    prefix[0] = 0xFE;

    let r = Scalar::from_hash(
        Sha512::new()
            .chain_update(prefix)
            .chain_update(a.to_bytes())
            .chain_update(msg)
            .chain_update(z),
    );
    let big_r = (ED25519_BASEPOINT_POINT * r).compress().to_bytes();
    let h = Scalar::from_hash(
        Sha512::new()
            .chain_update(big_r)
            .chain_update(big_a)
            .chain_update(msg),
    );
    let s = r + h * a;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&s.to_bytes());
    sig[63] &= 0x7F;
    sig[63] |= sign_bit;
    sig
}

/// Verifikasi XEdDSA / curve25519_verify ala libsignal
pub fn xeddsa_verify(pubkey: &Key32, msg: &[u8], sig: &[u8; 64]) -> bool {
    let sign_bit = sig[63] >> 7;
    let a = match MontgomeryPoint(*pubkey).to_edwards(sign_bit) {
        Some(p) => p,
        None => return false,
    };
    let big_a = a.compress().to_bytes();
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    s_bytes[31] &= 0x7F;
    let s = Scalar::from_bytes_mod_order(s_bytes);
    let h = Scalar::from_hash(
        Sha512::new()
            .chain_update(&sig[..32])
            .chain_update(big_a)
            .chain_update(msg),
    );
    let r_check = (-a) * h + ED25519_BASEPOINT_POINT * s;
    r_check.compress().to_bytes()[..] == sig[..32]
}
