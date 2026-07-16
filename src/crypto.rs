use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, aead::Aead};
use rand::RngCore;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

pub fn generate_ephemeral_keypair() -> (x25519_dalek::EphemeralSecret, [u8; 32]) {
    let secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::thread_rng());
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret, *public.as_bytes())
}

pub struct SecureSession {
    cipher: ChaCha20Poly1305,
    fingerprint: String,
}

impl SecureSession {
    pub fn new(secret: x25519_dalek::EphemeralSecret, peer_public_bytes: [u8; 32]) -> Self {
        let peer_public = x25519_dalek::PublicKey::from(peer_public_bytes);
        let shared_secret = secret.diffie_hellman(&peer_public);
        let mut key_bytes = Sha256::digest(shared_secret.as_bytes());
        
        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Zeroize key bytes for security
        key_bytes.zeroize();
        
        // Create a security fingerprint of the session
        let fp_hash = Sha256::digest(&peer_public_bytes);
        let fingerprint = format!("{:04X}-{:04X}", 
            u16::from_be_bytes(fp_hash[0..2].try_into().unwrap()), 
            u16::from_be_bytes(fp_hash[2..4].try_into().unwrap())
        );
        
        Self { cipher, fingerprint }
    }
    
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = self.cipher.encrypt(nonce, plaintext)
            .map_err(|_| "Encryption failed")?;
            
        let mut packet = Vec::with_capacity(12 + ciphertext.len());
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
    
    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>, &'static str> {
        if packet.len() < 12 {
            return Err("Packet too short");
        }
        let nonce = Nonce::from_slice(&packet[0..12]);
        let ciphertext = &packet[12..];
        
        self.cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed")
    }
}
