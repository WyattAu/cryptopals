//! Cryptopals Set 1 — Basics. Solutions in pure Rust, std only.

// primitives promoted to the crypto-primitives estate crate —
// re-exported here so challenge code and tests keep their paths
pub use crypto_primitives::aes;
pub use crypto_primitives::sha1;
pub use crypto_primitives::hex::{hex_decode, hex_encode};
pub use crypto_primitives::base64::{base64_encode, base64_decode};
pub use crypto_primitives::xor::xor;
pub use crypto_primitives::padding::{pkcs7_pad, pkcs7_unpad};






/// Single-byte XOR: score by English letter frequency, return best key.
pub fn single_byte_xor_best(cipher: &[u8]) -> (u8, f64, Vec<u8>) {
    // frequency of common English chars (approximation, per 1000 chars)
    const FREQ: [(u8, f64); 27] = [
        (b' ', 130.0), (b'e', 127.0), (b't', 90.0), (b'a', 82.0), (b'o', 75.0),
        (b'i', 70.0), (b'n', 67.0), (b's', 63.0), (b'h', 61.0), (b'r', 60.0),
        (b'd', 43.0), (b'l', 40.0), (b'u', 28.0), (b'c', 28.0), (b'm', 24.0),
        (b'w', 24.0), (b'f', 22.0), (b'g', 20.0), (b'y', 20.0), (b'p', 19.0),
        (b'b', 15.0), (b'v', 9.8), (b'k', 7.7), (b'\'', 6.5), (b'j', 1.5),
        (b'x', 1.5), (b'q', 0.95),
    ];
    let mut best = (0u8, f64::MIN, Vec::new());
    for k in 0..=255u8 {
        let dec: Vec<u8> = cipher.iter().map(|c| c ^ k).collect();
        let mut score = 0f64;
        for &c in &dec {
            for (ch, f) in FREQ {
                if c.to_ascii_lowercase() == ch {
                    score += f;
                    break;
                }
            }
            if !(32..127).contains(&c) && c != b'\n' {
                score -= 200.0; // heavy penalty for non-printable
            }
        }
        if score > best.1 {
            best = (k, score, dec);
        }
    }
    best
}

/// Ch4: find the line (and key) that was single-byte-XOR'd.
pub fn detect_single_byte_line(lines: &[String]) -> Option<(usize, u8, Vec<u8>)> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            let raw = hex_decode(l);
            if raw.is_empty() {
                return None;
            }
            let (k, score, dec) = single_byte_xor_best(&raw);
            if score > 200.0 && dec.iter().all(|&c| (32..127).contains(&c) || c == b'\n') {
                Some((i, k, dec))
            } else {
                None
            }
        })
        .max_by_key(|(_, _, dec)| {
            dec.iter().filter(|c| c.is_ascii_alphabetic() || **c == b' ').count()
        })
}

/// Ch5: repeating-key XOR.
pub fn repeating_key_xor(plain: &[u8], key: &[u8]) -> Vec<u8> {
    plain
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// Hamming distance between two equal-length byte slices.
pub fn hamming(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Ch6: rank keysizes 2..=40 by normalized Hamming distance, return best few.
pub fn rank_keysizes(data: &[u8]) -> Vec<(f64, usize)> {
    let mut ranked: Vec<(f64, usize)> = (2..=40)
        .map(|ks| {
            let chunks = data.len() / ks;
            let mut dists = Vec::new();
            let mut i = 0;
            while i + 2 * ks <= data.len() && chunks > 1 {
                dists.push(hamming(&data[i..i + ks], &data[i + ks..i + 2 * ks]) as f64 / ks as f64);
                i += 2 * ks;
            }
            (dists.iter().sum::<f64>() / dists.len() as f64, ks)
        })
        .collect();
    ranked.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    ranked
}

/// Ch11: detect whether `data` was encrypted with ECB or CBC.
/// ECB leaks repeated 16-byte blocks when the plaintext repeats;
/// CBC never produces them (each block's input is the previous
/// ciphertext). Statistical, not proof — but on structured plaintext
/// it's decisive.
pub fn detect_mode(data: &[u8]) -> &'static str {
    if detect_ecb(data).is_empty() {
        "cbc"
    } else {
        "ecb"
    }
}

/// Ch11 batch: classify a list of ciphertexts.
pub fn detect_modes(data: &[Vec<u8>]) -> Vec<&'static str> {
    data.iter().map(|d| detect_mode(d)).collect()
}

/// Ch8: detect AES-ECB by repeated 16-byte blocks.
pub fn detect_ecb(data: &[u8]) -> Vec<usize> {
    data.chunks(16)
        .enumerate()
        .filter(|(i, block)| {
            data.chunks(16).skip(i + 1).any(|other| other == *block)
        })
        .map(|(i, _)| i)
        .collect()
}

// ---- Set 2 ch9: PKCS#7 padding ----



// ---- Set 2 ch12: the ECB oracle + byte-at-a-time attack ----

pub struct EcbOracle {
    key: [u8; 16],
    secret: Vec<u8>,
}

impl EcbOracle {
    /// The "server": appends its fixed secret to your input and
    /// ECB-encrypts the whole thing under a fixed key (PKCS#7-padded).
    pub fn new(secret: &[u8]) -> Self {
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8) ^ 0xA5;
        }
        EcbOracle { key, secret: secret.to_vec() }
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut buf = input.to_vec();
        buf.extend_from_slice(&self.secret);
        let padded = pkcs7_pad(&buf, 16);
        let key = self.key;
        // ECB over 16-aligned blocks
        padded.chunks_exact(16).map(|b| {
            let mut st = [0u8; 16];
            st.copy_from_slice(b);
            let enc = crate::aes::aes128_ecb_encrypt_block(&st, &key);
            enc.to_vec()
        }).flatten().collect()
    }
}

/// Detect the oracle's block size: the first input length where the
/// ciphertext grows by more than the secret's worth.
pub fn detect_block_size(oracle: &EcbOracle) -> usize {
    let l0 = oracle.encrypt(&[]).len();
    let mut n = 1usize;
    loop {
        let ln = oracle.encrypt(&vec![b'A'; n]).len();
        if ln > l0 {
            return ln - l0;
        }
        n += 1;
    }
}

/// The attack: recover the oracle's secret byte-at-a-time.
pub fn break_ecb_oracle(oracle: &EcbOracle) -> Vec<u8> {
    let bs = detect_block_size(oracle);
    let mut known: Vec<u8> = Vec::new();
    loop {
        let i = known.len();
        let filler_len = bs - 1 - (i % bs);
        let filler = vec![b'A'; filler_len];
        let base = oracle.encrypt(&filler);
        let chunk = (filler_len + i) / bs;
        let ref_blk = &base[chunk * bs..(chunk + 1) * bs];
        let mut matched = None;
        for b in 0..=255u8 {
            let mut attempt = filler.clone();
            attempt.extend_from_slice(&known);
            attempt.push(b);
            let out = oracle.encrypt(&attempt);
            if &out[chunk * bs..(chunk + 1) * bs] == ref_blk {
                matched = Some(b);
                break;
            }
        }
        match matched {
            Some(b) => known.push(b),
            None => break,
        }
    }
    // the oracle pads its output — strip the (correctly recovered)
    // PKCS#7 padding from the tail before returning
    match pkcs7_unpad(&known, bs) {
        Some(t) => t.to_vec(),
        None => known,
    }
}

// ---- Set 2 ch13: ECB cut-and-paste ----

use std::collections::HashMap;

pub const PROFILE_KEY: [u8; 16] = *b"CH13 PROFILE KEY";

/// Sanitizes an email for the profile encoder (strip & and =).
pub fn sanitize(email: &str) -> String {
    email.chars().filter(|&c| c != '&' && c != '=').collect()
}

/// Encodes a profile from an email: email=<email>&uid=10&role=user
pub fn profile_for(email: &str) -> String {
    format!("email={}&uid=10&role=user", sanitize(email))
}

/// Encrypts an encoded profile.
pub fn encrypt_profile(encoded: &str) -> Vec<u8> {
    aes::aes128_ecb_encrypt(&crate::pkcs7_pad(encoded.as_bytes(), 16), &PROFILE_KEY)
}

/// Decrypts and parses a profile into key=value pairs.
pub fn decrypt_profile(ct: &[u8]) -> HashMap<String, String> {
    let padded = aes::aes128_ecb_decrypt(ct, &PROFILE_KEY);
    let text = String::from_utf8_lossy(&padded).into_owned();
    let mut map = HashMap::new();
    for pair in text.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.trim_end_matches('\u{0}').to_string());
        }
    }
    map
}

/// The cut-and-paste attack: splice an attacker-controlled "admin"
/// block (fully aligned and PKCS#7-padded) into the role position of a
/// victim profile whose role= value starts a fresh block.
pub fn cut_and_paste_admin(victim_ct: &[u8], admin_block: &[u8]) -> Vec<u8> {
    let mut out = victim_ct[..victim_ct.len() - 16].to_vec();
    out.extend_from_slice(admin_block);
    out
}

/// Builds the attacker's crafted profile ct whose second block is the
/// fully-padded "admin" value.
pub fn craft_admin_block() -> [u8; 16] {
    // email=<11 chars> | admin + 11 bytes padding = aligned block 2
    let email = "x11charslong"; // 12 chars: "email=" (6) + 12 = block 1 done at 16...
    let _ = email;
    // "email=" is 6 bytes; use an 10-char email so block 2 (bytes 16..32)
    // begins exactly at the value "admin\x0b..." -> need 10 bytes: 6+10=16
    let email = "admin_email"; // placeholder, real alignment below
    let aligned = profile_for(&"aaaaaaaaaaaaaaaaaaaa".to_string());
    let _ = aligned;
    // The standard: email = 10 'a's => "email=aaaaaaaaaa" fills block 1;
    // block 2 = "admin" + 11 PKCS#7 pad bytes (0x0b).
    let _ = email;
    let mut probe = "aaaaaaaaaa".to_string(); // exactly 10 chars
    let _ = probe;
    let email_clean = "aaaaaaaaaa";
    let enc = profile_for(email_clean);
    assert!(enc.starts_with("email=aaaaaaaaaa&uid=10&role=user"));
    // block 2 starts at byte 16 = position of "&uid=10&role=user" start...
    // we want "admin"+pad in block 2: attacker email = "aaaaaaaaaaadmin"
    // sanitized profile: email=aaaaaaaaaaadmin -> block 2 = "admin"+pad(11)
    let crafted = profile_for("aaaaaaaaaaadmin");
    let ct = encrypt_profile(&crafted);
    let mut blk = [0u8; 16];
    blk.copy_from_slice(&ct[16..32]);
    blk
}

/// Full attack: returns the spliced ciphertext's decoded role.
pub fn run_attack() -> String {
    // victim: an email that leaves "role=" at the end of a block.
    // "email=" (6) + email + "&uid=10&" (8) + "role=" (5) — we need
    // (6 + len(email) + 8 + 5) % 16 == 0 -> len(email) % 16 == 13
    let victim_email = "a".repeat(13);
    let victim_ct = encrypt_profile(&profile_for(&victim_email));
    let admin_blk = craft_admin_block();
    let spliced = cut_and_paste_admin(&victim_ct, &admin_blk);
    let profile = decrypt_profile(&spliced);
    profile.get("role").cloned().unwrap_or_default()
}

// ---- Set 2 ch14: CBC bit-flipping ----

pub const CBC_KEY: [u8; 16] = *b"ch14 cbc key !!!";

/// The "web app": prepend the comment wrapper and CBC-encrypt.
pub fn cbc_prepend(userdata: &[u8]) -> Vec<u8> {
    let prefix = b"comment1=cooking%20MCs;userdata=";
    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
    let mut pt = prefix.to_vec();
    pt.extend_from_slice(userdata);
    pt.extend_from_slice(suffix);
    // CBC encrypt manually: pad, chain over ecb blocks with the iv
    let padded = crate::pkcs7_pad(&pt, 16);
    let iv = *b"ch14 cbc iv  !!!";
    let mut prev = iv;
    let mut out = Vec::new();
    for block in padded.chunks_exact(16) {
        let mut b = [0u8; 16];
        for k in 0..16 {
            b[k] = block[k] ^ prev[k];
        }
        let enc = crate::aes::aes128_ecb_encrypt_block(&b, &CBC_KEY);
        out.extend_from_slice(&enc);
        prev = enc;
    }
    out
}

/// The "admin check": decrypt, extract the userdata segment, look for
/// ";admin=true;".
pub fn cbc_verify_admin(ct: &[u8]) -> bool {
    let iv = *b"ch14 cbc iv  !!!";
    let mut prev = iv;
    let mut pt = Vec::new();
    for block in ct.chunks_exact(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(block);
        let dec = crate::aes::aes128_ecb_decrypt_block(&b, &CBC_KEY);
        for k in 0..16 {
            pt.push(dec[k] ^ prev[k]);
        }
        prev = b;
    }
    let userdata = &pt[32..]; // skip the fixed 32-byte prefix
    std::str::from_utf8(userdata)
        .map(|s| s.contains(";admin=true;"))
        .unwrap_or(false)
}

/// Sanitizes userdata (the "server" strips ; and =).
pub fn cbc_sanitize(userdata: &[u8]) -> Vec<u8> {
    userdata
        .iter()
        .copied()
        .filter(|&b| b != b';' && b != b'=')
        .collect()
}

/// The bit-flip attack: locate the attacker-controlled block and flip
/// the previous ciphertext block's bytes so the decrypted userdata
/// block becomes ";admin=true;".
pub fn cbc_bitflip_attack(ct: &[u8], my_userdata: &[u8]) -> Vec<u8> {
    // userdata starts at byte offset 32 (two blocks of fixed prefix)
    // attacker's FIRST controlled block = ciphertext block 2 (index 2);
    // flipping ct block 1 (index 1) alters its decryption
    let target = *b";admin=true;\x00\x00\x00\x00";
    let mut out = ct.to_vec();
    // the attacker knows their own decrypted block = the sanitized
    // userdata they submitted (bytes 32..48 of the plaintext)
    for i in 0..16usize {
        // ct[16+i] contributes to the decryption of plaintext block 2
        // at byte i: delta = old_decrypted[i] ^ target[i]
        let old_pt = my_userdata[i % my_userdata.len()];
        out[16 + i] = ct[16 + i] ^ (old_pt ^ target[i]);
    }
    out
}
