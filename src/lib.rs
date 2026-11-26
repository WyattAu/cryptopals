//! Cryptopals Set 1 — Basics. Solutions in pure Rust, std only.

// primitives promoted to the crypto-primitives estate crate —
// re-exported here so challenge code and tests keep their paths
pub use crypto_primitives::aes;
pub use crypto_primitives::sha1;
pub use crypto_primitives::hex::{hex_decode, hex_encode};
pub use crypto_primitives::base64::{base64_encode, base64_decode};
pub use crypto_primitives::xor::xor;
pub use crypto_primitives::padding::{pkcs7_pad, pkcs7_unpad};

pub mod md4;






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
    let probe = "aaaaaaaaaa".to_string(); // exactly 10 chars
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

// ---- Set 3 ch17: CBC padding oracle ----

pub const CH17_KEY: [u8; 16] = *b"ch17 oracle key!";
pub const CH17_IV: [u8; 16] = *b"ch17 oracle iv!!";

/// The "server": pads a user datum and CBC-encrypts it, emitting the
/// challenge's IV||CT format — the attacker is handed the whole blob
/// and feeds crafted variants back to the oracle.
pub fn oracle_encrypt(pt: &[u8]) -> Vec<u8> {
    let padded = pkcs7_pad(pt, 16);
    let mut out = CH17_IV.to_vec();
    out.extend(aes::cbc_encrypt(&padded, &CH17_KEY, &CH17_IV));
    out
}

/// The "oracle": decrypts (iv, body) from the supplied blob and reveals
/// ONLY whether the padding was valid — the classic error side channel
/// (Vaudenay 2002).
pub fn padding_valid(ct: &[u8]) -> bool {
    if ct.len() < 32 || ct.len() % 16 != 0 {
        return false;
    }
    let iv: [u8; 16] = ct[..16].try_into().unwrap();
    let pt = aes::cbc_decrypt(&ct[16..], &CH17_KEY, &iv);
    pkcs7_unpad(&pt, 16).is_some()
}

/// The padding-oracle attack. For each ciphertext block (except the
/// first), recover the AES-decrypted bytes byte-at-a-time from the end:
/// craft the previous block so the decrypted padding is valid for guess
/// `g`, then dec[pos] = g ^ pad_len and pt[pos] = dec[pos] ^ prev[pos].
///
/// Coincidence guard: at pos 15 a wrong guess can also validate (the
/// penultimate decrypted byte happens to be 0x02 and the guess makes a
/// 0x02 0x02 tail). After a hit at pos 15, perturb craft[14] and
/// re-query — a real 0x01 hit stops validating, a coincidental 0x02
/// 0x02 does not, so the search continues.
pub fn padding_oracle_attack(ct: &[u8]) -> Vec<u8> {
    assert!(ct.len() >= 32 && ct.len() % 16 == 0, "oracle input must be >= 32 bytes, 16-aligned");
    let mut plain = vec![0u8; ct.len() - 16];
    for bi in 1..ct.len() / 16 {
        let target: [u8; 16] = ct[bi * 16..bi * 16 + 16].try_into().unwrap();
        let orig_prev: [u8; 16] = ct[bi * 16 - 16..bi * 16].try_into().unwrap();
        let mut dec_known = [0u8; 16];
        for pos in (0..16).rev() {
            let pad_len = 16 - pos;
            let mut found = None;
            for g in 0..=255u8 {
                let mut craft = orig_prev;
                // the oracle decrypts pt_target = dec ^ craft, so to make
                // the padding bytes read pad_len: craft[j] = dec[j] ^ pad_len
                for j in (pos + 1)..16 {
                    craft[j] = dec_known[j] ^ (pad_len as u8);
                }
                craft[pos] = g;
                let mut probe = Vec::with_capacity(bi * 16 + 16);
                probe.extend_from_slice(&ct[..bi * 16 - 16]);
                probe.extend_from_slice(&craft);
                probe.extend_from_slice(&target);
                if padding_valid(&probe) {
                    if pos == 15 {
                        // coincidence guard: force the penultimate
                        // decrypted byte away from 0x02 and re-check
                        craft[14] ^= 0xff;
                        let mut recheck = Vec::with_capacity(bi * 16 + 16);
                        recheck.extend_from_slice(&ct[..bi * 16 - 16]);
                        recheck.extend_from_slice(&craft);
                        recheck.extend_from_slice(&target);
                        // true 0x01 hit: last byte unchanged -> still valid.
                        // coincidental 0x02 0x02: byte 14 perturbed -> invalid.
                        if !padding_valid(&recheck) {
                            continue; // coincidental — keep hunting
                        }
                    }
                    found = Some(g);
                    break;
                }
            }
            let g = found.expect("padding oracle: no guess validated at this byte");
            // decrypted[pos] = dec[pos] ^ g = pad_len -> dec[pos] = g ^ pad_len;
            // the REAL plaintext chains on orig_prev: pt[pos] = dec[pos] ^ prev[pos]
            dec_known[pos] = g ^ (pad_len as u8);
            plain[(bi - 1) * 16 + pos] = dec_known[pos] ^ orig_prev[pos];
        }
    }
    plain
}

// ---- Set 3 ch18: CTR mode (AES-128, LE nonce || LE counter) ----

/// AES-128-CTR. Keystream block i = ECB(nonce_le || i_le); XOR with the
/// data. Encryption and decryption are the same operation.
pub fn ctr128(key: &[u8; 16], nonce: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&nonce.to_le_bytes());
        block[8..].copy_from_slice(&(i as u64).to_le_bytes());
        let ks = aes::aes128_ecb_encrypt_block(&block, key);
        for (j, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[j]);
        }
    }
    out
}

// ---- Set 3 ch19+ch20: fixed-nonce CTR — keystream reuse break ----

/// Column scorer for the many-time-pad attack: English letter
/// frequency, small credit for any printable ASCII, and a hard
/// penalty for non-printables — the decisive signal, since English
/// decrypts to ASCII while a wrong key byte rarely does.
fn column_best_key(column: &[u8]) -> u8 {
    let mut best = (0u8, f64::MIN);
    for k in 0..=255u8 {
        let mut score = 0.0f64;
        for &c in column {
            let d = c ^ k;
            score += match d {
                b' ' => 13.0,
                b'e' => 12.7, b't' => 9.1, b'a' => 8.2, b'o' => 7.5, b'i' => 7.0,
                b'n' => 6.7, b's' => 6.3, b'h' => 6.1, b'r' => 6.0,
                b'd' | b'l' | b'u' => 4.0,
                b'c' | b'm' | b'w' | b'f' | b'g' | b'y' | b'p' | b'b' => 2.0,
                b'v' | b'k' | b'\'' | b'j' | b'x' | b'q' | b'z' | b'.' | b',' => 0.5,
                b'~' | b'{' | b'}' | b'|' | b'\\' | b'^' | b'`' | b'_' => -1.0,
                0x20..=0x7e | b'\n' | b'\t' => 0.0,
                _ => -15.0,
            };
        }
        if score > best.1 {
            best = (k, score);
        }
    }
    best.0
}

/// Breaks many-time-pad CTR: all ciphertexts used the SAME key+nonce,
/// so byte position j of every message is XORed with the same keystream
/// byte. Column j is a single-byte-XOR problem — the ch3 frequency
/// attack, applied per column. Returns the recovered keystream prefix.
pub fn recover_ctr_keystream(cts: &[&[u8]], klen: usize) -> Vec<u8> {
    let mut ks = Vec::with_capacity(klen);
    for j in 0..klen {
        let column: Vec<u8> = cts.iter().filter_map(|ct| ct.get(j).copied()).collect();
        if column.is_empty() {
            break;
        }
        ks.push(column_best_key(&column));
    }
    ks
}

/// XORs a keystream (repeating) over data — the decryption step once
/// the keystream is recovered.
pub fn xor_keystream(data: &[u8], ks: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ ks[i % ks.len()])
        .collect()
}

// ---- Set 3 ch21-23: MT19937 — implement, recover seed, clone ----

/// MT19937 (Matsumoto & Nishimura 1998), init_genrand seeding per the
/// ch21 spec and the published reference pseudocode. Validated against
/// the reference stream (seed 5489 → 3499211612, ...).
pub struct Mt19937 {
    mt: [u32; 624],
    idx: usize,
}

impl Mt19937 {
    pub fn new(seed: u32) -> Self {
        let mut mt = [0u32; 624];
        mt[0] = seed;
        for i in 1..624 {
            mt[i] = 1812433253u32
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Mt19937 { mt, idx: 624 }
    }

    fn twist(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x8000_0000) | (self.mt[(i + 1) % 624] & 0x7fff_ffff);
            let mut next = self.mt[(i + 397) % 624] ^ (y >> 1);
            if y & 1 != 0 {
                next ^= 0x9908_b0df;
            }
            self.mt[i] = next;
        }
        self.idx = 0;
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.idx >= 624 {
            self.twist();
        }
        let mut y = self.mt[self.idx];
        self.idx += 1;
        // tempering
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }
}

/// ch22: the seed was time.time() within a known window; the first
/// output is observed — brute-force the window.
pub fn recover_mt_seed(first_output: u32, lo: u32, hi: u32) -> Option<u32> {
    (lo..=hi).find(|&seed| Mt19937::new(seed).next_u32() == first_output)
}

/// Untempering: invert the four tempering steps by iterated
/// substitution (each step's inverse converges in ceil(32/shift) iters).
fn unshift_right(y: u32, shift: u32) -> u32 {
    let mut res = y;
    for _ in 0..32 / shift + 1 {
        res = y ^ (res >> shift);
    }
    res
}

fn unshift_left(y: u32, shift: u32, mask: u32) -> u32 {
    let mut res = y;
    for _ in 0..32 / shift + 1 {
        res = y ^ ((res << shift) & mask);
    }
    res
}

/// Inverts the tempering of one output, recovering the raw state word.
pub fn untemper(y: u32) -> u32 {
    let y = unshift_right(y, 18);
    let y = unshift_left(y, 15, 0xefc6_0000);
    let y = unshift_left(y, 7, 0x9d2c_5680);
    unshift_right(y, 11)
}

/// ch23: 624 consecutive outputs fully determine MT19937's internal
/// state — untremper them into the state array (idx = 624, forcing the
/// same regeneration schedule as the original) and the clone reproduces
/// the rest of the stream exactly.
pub fn clone_mt19937(outputs: &[u32; 624]) -> Mt19937 {
    let mut mt = [0u32; 624];
    for (i, &o) in outputs.iter().enumerate() {
        mt[i] = untemper(o);
    }
    Mt19937 { mt, idx: 624 }
}

// ---- Set 4 ch24: MT19937 stream cipher + 16-bit seed brute-force ----

/// MT19937 keystream cipher: the low 8 bits of each successive output
/// XOR the data, keystream seeded by a 16-bit secret. Encrypt ==
/// decrypt. The 16-bit seed is the whole security — and it is none.
pub fn mt_stream(key_seed: u16, data: &[u8]) -> Vec<u8> {
    let mut mt = Mt19937::new(key_seed as u32);
    data.iter().map(|&b| b ^ (mt.next_u32() & 0xff) as u8).collect()
}

/// The break: with a known plaintext prefix, brute-force all 65536
/// 16-bit seeds — the candidate whose keystream matches the prefix IS
/// the key, and then the entire message decrypts.
pub fn break_mt_stream(ct: &[u8], known_prefix: &[u8]) -> Option<Vec<u8>> {
    for seed in 0..=u16::MAX {
        let ks = mt_stream(seed, &ct[..known_prefix.len().min(ct.len())]);
        if ks[..known_prefix.len()] == *known_prefix {
            return Some(mt_stream(seed, ct));
        }
    }
    None
}

// ---- Set 4 ch25: random-access edit breaks CTR ----

const CH25_KEY: [u8; 16] = *b"ch25 ctr key!!!!";

/// The "server": stores a CTR-encrypted blob and offers a random-access
/// edit — seeks to `offset` and overwrites with CTR-encrypted `newtext`
/// (the same keystream). This is the edit-API leak of ch25.
pub fn ch25_edit(ct: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
    let ks = ctr128(&CH25_KEY, 0, &vec![0u8; ct.len()]);
    let mut out = ct.to_vec();
    for (i, &b) in newtext.iter().enumerate() {
        if offset + i < out.len() {
            out[offset + i] = b ^ ks[offset + i];
        }
    }
    out
}

/// The break: edit(ct, 0, zeros) hands back the RAW keystream (zeros
/// XOR keystream = keystream); XOR it over the ciphertext to recover
/// the whole plaintext without touching the key.
pub fn ch25_attack(ct: &[u8]) -> Vec<u8> {
    let keystream = ch25_edit(ct, 0, &vec![0u8; ct.len()]);
    ct.iter().zip(&keystream).map(|(a, b)| a ^ b).collect()
}

// ---- Set 4 ch26: CTR bit-flipping ----

const CH26_KEY: [u8; 16] = *b"ch26 ctr key!!!!";

/// The "server": wraps sanitized userdata and CTR-encrypts.
pub fn ch26_encrypt(userdata: &[u8]) -> Vec<u8> {
    let prefix = b"comment1=cooking%20MCs;userdata=";
    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
    let clean: Vec<u8> = userdata.iter().copied().filter(|&b| b != b';' && b != b'=').collect();
    let mut pt = prefix.to_vec();
    pt.extend(&clean);
    pt.extend(suffix);
    ctr128(&CH26_KEY, 0, &pt)
}

/// The admin check on decryption.
pub fn ch26_verify_admin(ct: &[u8]) -> bool {
    let pt = ctr128(&CH26_KEY, 0, ct);
    std::str::from_utf8(&pt)
        .map(|s| s.contains(";admin=true;"))
        .unwrap_or(false)
}

/// The attack: CTR applies the keystream linearly, so flipping
/// ct[i] by delta flips pt[i] by the same delta — no padding oracle
/// needed (the ch14 CBC dance, trivialized by stream-cipher malleability).
pub fn ch26_bitflip(ct: &[u8], submitted: &[u8], target: &[u8]) -> Vec<u8> {
    assert_eq!(submitted.len(), target.len());
    let mut out = ct.to_vec();
    for i in 0..target.len() {
        out[32 + i] = ct[32 + i] ^ submitted[i] ^ target[i];
    }
    out
}

// ---- Set 4 ch27: CBC with IV == key leaks the key ----

const CH27_KEY: [u8; 16] = *b"ch27 iv-eq-key!!";

/// The broken server: CBC-encrypts with the IV equal to the key.
pub fn ch27_encrypt(pt: &[u8]) -> Vec<u8> {
    let padded = pkcs7_pad(pt, 16);
    aes::cbc_encrypt(&padded, &CH27_KEY, &CH27_KEY)
}

/// The oracle: decrypts and, on invalid padding, RETURNS the decrypted
/// buffer (a "helpful" error message).
pub fn ch27_decrypt_or_padding_error(ct: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    let pt = aes::cbc_decrypt(ct, &CH27_KEY, &CH27_KEY);
    match pkcs7_unpad(&pt, 16) {
        Some(p) => Ok(p.to_vec()),
        None => Err(pt),
    }
}

/// The attack: submit C1 || 0^16 || C1. The decryption is
/// [D(C1)^KEY, D(0)^C1, D(C1)] — so KEY = P1 ^ P3, straight from the
/// leaked error buffer.
pub fn ch27_recover_key() -> [u8; 16] {
    let c1 = [0x41u8; 16];
    let mut probe = Vec::with_capacity(48);
    probe.extend_from_slice(&c1);
    probe.extend_from_slice(&[0u8; 16]);
    probe.extend_from_slice(&c1);
    let Err(pt) = ch27_decrypt_or_padding_error(&probe) else {
        panic!("crafted probe must produce invalid padding");
    };
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = pt[i] ^ pt[32 + i];
    }
    key
}

// ---- Set 4 ch28-29: SHA-1 keyed MAC + length extension ----

/// The naive keyed MAC the challenges attack: SHA1(key || msg).
/// Forgery-proof ONLY against attackers who can't extend the hash —
/// which SHA-1's structure does not provide.
pub fn sha1_mac(key: &[u8], msg: &[u8]) -> [u8; 20] {
    sha1::sha1(&[key, msg].concat())
}

/// ch29: forge a valid MAC for `key || msg || glue || suffix` WITHOUT
/// the key, from (mac, orig_len, key_len_guess). The original MAC is
/// the intermediate chaining state after the padding block; resume from
/// it with the glue padding accounted, then absorb the suffix.
/// Returns (forged_mac, glue) — the attacker sends msg||glue||suffix.
pub fn sha1_length_extend(
    mac: &[u8; 20],
    orig_len: usize,
    key_len_guess: usize,
    suffix: &[u8],
) -> ([u8; 20], Vec<u8>) {
    let mut h = [0u32; 5];
    for (i, w) in h.iter_mut().enumerate() {
        *w = u32::from_be_bytes(mac[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let base_len = (key_len_guess + orig_len) as u64;
    let glue = sha1::Sha1::glue_padding(base_len);
    let mut ext = sha1::Sha1::from_state(h, base_len + glue.len() as u64);
    ext.update(suffix);
    (ext.finalize(), glue)
}

/// Sweep key-length guesses — the attacker doesn't know the key length,
/// so try each and let the SERVER's verification pick the winner.
pub fn forge_admin_request(
    mac: &[u8; 20],
    msg: &[u8],
    suffix: &[u8],
    max_key_len: usize,
) -> Option<(usize, Vec<u8>, [u8; 20])> {
    for klen in 0..=max_key_len {
        let (forged, glue) = sha1_length_extend(mac, msg.len(), klen, suffix);
        let mut forged_msg = msg.to_vec();
        forged_msg.extend(&glue);
        forged_msg.extend(suffix);
        // the real check happens server-side with the real key; the
        // caller supplies the oracle (here, the test's verify closure)
        if VERIFY_ORACLE.with(|f| (f.borrow_mut())(&forged_msg, &forged)) {
            return Some((klen, forged_msg, forged));
        }
    }
    None
}

use std::cell::RefCell;
thread_local! {
    /// Server-side MAC oracle the attack may query (verified against
    /// the real key inside the test).
    pub static VERIFY_ORACLE: RefCell<Box<dyn FnMut(&[u8], &[u8]) -> bool>> =
        RefCell::new(Box::new(|_, _| false));
}

// ---- Set 4 ch30: MD4 keyed MAC + length extension ----

/// The naive MD4 keyed MAC (the ch30 server uses MD4, not SHA-1).
pub fn md4_mac(key: &[u8], msg: &[u8]) -> [u8; 16] {
    md4::md4(&[key, msg].concat())
}

/// Length extension over MD4: the 16-byte digest is the intermediate
/// 4-word chaining state (little-endian words), and MD4's glue padding
/// uses a LITTLE-endian length — both differ from the SHA-1 case.
pub fn md4_length_extend(
    mac: &[u8; 16],
    orig_len: usize,
    key_len_guess: usize,
    suffix: &[u8],
) -> ([u8; 16], Vec<u8>) {
    let mut h = [0u32; 4];
    for (i, w) in h.iter_mut().enumerate() {
        *w = u32::from_le_bytes(mac[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let base_len = (key_len_guess + orig_len) as u64;
    let glue = md4::Md4::glue_padding(base_len);
    let mut ext = md4::Md4::from_state(h, base_len + glue.len() as u64);
    ext.update(suffix);
    (ext.finalize(), glue)
}

/// Key-length sweep against the server oracle (the ch30 variant).
pub fn forge_admin_request_md4(
    mac: &[u8; 16],
    msg: &[u8],
    suffix: &[u8],
    max_key_len: usize,
) -> Option<(usize, Vec<u8>, [u8; 16])> {
    for klen in 0..=max_key_len {
        let (forged, glue) = md4_length_extend(mac, msg.len(), klen, suffix);
        let mut forged_msg = msg.to_vec();
        forged_msg.extend(&glue);
        forged_msg.extend(suffix);
        if VERIFY_ORACLE.with(|f| (f.borrow_mut())(&forged_msg, &forged)) {
            return Some((klen, forged_msg, forged));
        }
    }
    None
}

// ---- Set 4 ch31-32: HMAC-SHA1 + (simulated) timing leaks ----

/// HMAC-SHA1 per RFC 2104 (validated against RFC 2202 vectors).
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k = key.to_vec();
    if k.len() > 64 {
        k = sha1::sha1(&k).to_vec();
    }
    k.resize(64, 0);
    let inner = sha1::sha1(&[k.iter().map(|&b| b ^ 0x36).collect::<Vec<_>>(), msg.to_vec()].concat());
    sha1::sha1(&[k.iter().map(|&b| b ^ 0x5c).collect::<Vec<_>>(), inner.to_vec()].concat())
}

/// ch31's artificial timing leak, simulated: instead of sleeping per
/// matching byte, the oracle returns the count of leading bytes that
/// matched. Same information, deterministic test.
pub fn leaky_compare_mac(expected: &[u8; 20], candidate: &[u8]) -> usize {
    candidate.iter().zip(expected).take_while(|(a, b)| a == b).count()
}

/// The byte-at-a-time timing attack: maximize the reported match length
/// per position. Stops when no guess advances the match.
pub fn break_mac_by_timing<F>(mut oracle: F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> usize,
{
    let mut recovered = Vec::new();
    loop {
        let mut best = (0u8, recovered.len());
        for g in 0..=255u8 {
            let mut cand = recovered.clone();
            cand.push(g);
            let m = oracle(&cand);
            if m > best.1 {
                best = (g, m);
            }
        }
        if best.1 == recovered.len() {
            break; // no candidate extended the match — done (or noise won)
        }
        recovered.push(best.0);
    }
    recovered
}

/// ch32's noisy leak: the oracle reports match-count minus a jitter
/// value (0 or 1, deterministic from the candidate) — no free lunch,
/// the attacker must SAMPLE REPEATEDLY and take the max per candidate.
pub fn break_mac_by_noisy_timing<F>(mut oracle: F, samples: usize) -> Vec<u8>
where
    F: FnMut(&[u8]) -> usize,
{
    let mut recovered = Vec::new();
    loop {
        let mut best = (0u8, recovered.len());
        for g in 0..=255u8 {
            let mut cand = recovered.clone();
            cand.push(g);
            let mut m = 0usize;
            for _ in 0..samples {
                m = m.max(oracle(&cand));
            }
            if m > best.1 {
                best = (g, m);
            }
        }
        if best.1 == recovered.len() {
            break;
        }
        recovered.push(best.0);
    }
    recovered
}

// ---- Set 5: public-key crypto — modexp, modinv, DH, RSA ----

use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Modular exponentiation: (base^exp) mod m — square-and-multiply over
/// num-bigint, the workhorse of every public-key primitive here.
pub fn modexp(base: &BigUint, exp: &BigUint, m: &BigUint) -> BigUint {
    assert!(!m.is_zero(), "modulus must be nonzero");
    base.modpow(exp, m)
}

/// Modular inverse via extended Euclid (hand-rolled — the std crates
/// in use don't expose one; returns None when gcd(a, m) != 1).
pub fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    if m.is_zero() || m.is_one() {
        return None;
    }
    let (mut old_r, mut r) = (a % m, m.clone());
    let (mut old_s, mut s) = (BigUint::one(), BigUint::zero());
    while !r.is_zero() {
        let q = &old_r / &r;
        let new_r = &old_r - &q * &r;
        old_r = std::mem::replace(&mut r, new_r);
        // keep the Bezout coefficient in Z_m: BigUint is unsigned and
        // the raw coefficient goes negative mid-loop (this panicked the
        // ch39 keygen before the fix)
        let qs_mod = &q * &s % m;
        let new_s = (&old_s + m - &qs_mod) % m;
        old_s = std::mem::replace(&mut s, new_s);
    }
    if old_r != BigUint::one() {
        return None; // not invertible
    }
    Some(old_s % m)
}

/// Integer cube root (for Håstad's e=3 broadcast attack).
pub fn icbrt(n: &BigUint) -> BigUint {
    n.cbrt()
}

// ---- Set 5 ch33: Diffie-Hellman ----

/// A Diffie-Hellman party: private x, public g^x mod p.
pub struct DhParty {
    pub secret: BigUint,
    pub public: BigUint,
}

impl DhParty {
    pub fn new(g: &BigUint, p: &BigUint, secret: BigUint) -> Self {
        let public = modexp(g, &secret, p);
        DhParty { secret, public }
    }

    /// The shared session secret: (other's public)^my private mod p.
    pub fn session_key(&self, other_public: &BigUint, p: &BigUint) -> BigUint {
        modexp(other_public, &self.secret, p)
    }
}

/// MITM injection (ch34/ch35 family): the attacker replaces both
/// publics with g itself, forcing both session keys to g.
pub fn mitm_forced_session(g: &BigUint, p: &BigUint) -> (BigUint, BigUint) {
    (modexp(g, &BigUint::one(), p), modexp(g, &BigUint::one(), p))
}

// ---- Set 5 ch39: RSA ----

pub struct RsaKey {
    pub n: BigUint, // modulus
    pub e: BigUint, // public exponent
    pub d: BigUint, // private exponent
}

impl RsaKey {
    /// Keygen from distinct primes p, q and public exponent e:
    /// n = pq, phi = (p-1)(q-1), d = e^-1 mod phi.
    pub fn from_primes(p: &BigUint, q: &BigUint, e: &BigUint) -> Self {
        let n = p * q;
        let phi = (p - BigUint::one()) * (q - BigUint::one());
        let d = modinv(e, &phi).expect("e must be invertible mod phi");
        RsaKey { n, e: e.clone(), d }
    }

    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        modexp(m, &self.e, &self.n)
    }

    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        modexp(c, &self.d, &self.n)
    }

    /// Sign: exponentiate the message (a stand-in for a hash) with d.
    pub fn sign(&self, m: &BigUint) -> BigUint {
        self.decrypt(m)
    }

    /// Verify: exponentiate the signature with e, compare to message.
    pub fn verify(&self, m: &BigUint, sig: &BigUint) -> bool {
        self.encrypt(sig) == *m
    }
}

// ---- Set 5 ch40: e=3 broadcast attack (Håstad) ----

/// The same message sent to 3 recipients with e=3 and distinct moduli
/// (no padding!) is recoverable: CRT the ciphertexts, take the integer
/// cube root.
pub fn hastad_broadcast_attack(
    c: [&BigUint; 3],
    n: [&BigUint; 3],
) -> BigUint {
    // CRT via explicit construction: x = sum(c_i * N_i * M_i) mod N,
    // N_i = N/n_i, M_i = N_i^-1 mod n_i
    let big_n: BigUint = n.iter().fold(BigUint::one(), |acc, ni| acc * *ni);
    let mut total = BigUint::zero();
    for i in 0..3 {
        let ni = n[i];
        let n_i = &big_n / ni;
        let m_i = modinv(&n_i, ni).expect("CRT cofactor must be invertible");
        total += c[i] * &n_i * &m_i;
    }
    let x = total % &big_n;
    // x = m^3 (as an integer, since m < min(n_i) => m^3 < N); take cbrt
    icbrt(&x)
}

/// ch34: the MITM substitution attack, concretely. The attacker relays
/// crafted publics instead of the real ones: passing p makes each party
/// compute p^x mod p = 0; passing 1 gives 1; passing g gives g. All
/// three are KEY-FREE — the attacker reads every "encrypted" message.
pub fn mitm_substituted_key(substituted_public: &BigUint, exponent: &BigUint, p: &BigUint) -> BigUint {
    modexp(substituted_public, exponent, p)
}

// ---- Set 5 ch35: negotiated-group injection leaks key bits ----

/// Proposing g' = p-1 (order 2) as the "negotiated group": the session
/// key becomes 1 if the peer's exponent is even, p-1 if odd — the
/// attacker reads one bit of the secret per exchange. With g'=1 the
/// key is always 1.
pub fn negotiated_group_key(g_prime: &BigUint, exponent: &BigUint, p: &BigUint) -> BigUint {
    modexp(g_prime, exponent, p)
}

// ---- Set 5 ch36-38: SRP (Secure Remote Password) ----
// Deviations from the site spec, documented: H = SHA-1 (the site asks
// SHA-256; the protocol lessons are hash-agnostic) and k = 3 fixed
// (per the site). The arithmetic is SRP-6a.

pub fn srp_x(salt: &[u8], password: &[u8]) -> BigUint {
    let h = sha1::sha1(&[salt, password].concat());
    BigUint::from_bytes_be(&h)
}

fn srp_sub_mod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    // unsigned subtraction trap: wrap through the modulus
    (a + n - b) % n
}

pub struct SrpServer {
    pub n: BigUint,
    pub g: BigUint,
    pub salt: Vec<u8>,
    pub v: BigUint,   // verifier g^x mod N
    pub priv_b: BigUint,
    pub pub_b: BigUint, // B = 3v + g^b mod N
    pub u: BigUint,   // server-chosen u — the ch38 vulnerability
}

impl SrpServer {
    pub fn setup(n: &BigUint, g: &BigUint, salt: &[u8], password: &[u8], b: BigUint, u: BigUint) -> Self {
        let x = srp_x(salt, password);
        let v = modexp(g, &x, n);
        let k = BigUint::from(3u32);
        let pub_b = (&k * &v + modexp(g, &b, n)) % n;
        SrpServer { n: n.clone(), g: g.clone(), salt: salt.to_vec(), v, priv_b: b, pub_b, u }
    }

    /// Server-side session: S = (A * v^u)^b mod N; K = H(S).
    pub fn session(&self, client_pub_a: &BigUint) -> BigUint {
        let s = modexp(&(client_pub_a * &self.v.modpow(&self.u, &self.n) % &self.n), &self.priv_b, &self.n);
        let h = sha1::sha1(&s.to_bytes_be());
        BigUint::from_bytes_be(&h)
    }
}

pub struct SrpClient {
    pub n: BigUint,
    pub g: BigUint,
    pub priv_a: BigUint,
    pub pub_a: BigUint, // A = g^a mod N (or a forged value)
}

impl SrpClient {
    pub fn new(n: &BigUint, g: &BigUint, a: BigUint) -> Self {
        let pub_a = modexp(g, &a, n);
        SrpClient { n: n.clone(), g: g.clone(), priv_a: a, pub_a }
    }

    /// Client-side session: S = (B - 3*g^x)^(a + u*x) mod N.
    pub fn session(&self, salt: &[u8], password: &[u8], server_pub_b: &BigUint, u: &BigUint) -> BigUint {
        let x = srp_x(salt, password);
        let k = BigUint::from(3u32);
        let base = srp_sub_mod(server_pub_b, &(&k * &modexp(&self.g, &x, &self.n) % &self.n), &self.n);
        let exp = &self.priv_a + &(u * &x);
        let s = modexp(&base, &exp, &self.n);
        let h = sha1::sha1(&s.to_bytes_be());
        BigUint::from_bytes_be(&h)
    }
}

/// ch37: the A=0 attack — the client sends A=0, so the server computes
/// S = (0 * v^u)^b = 0 regardless of the stored password; a client that
/// also assumes S=0 produces the matching proof.
pub fn srp_zero_key_client() -> BigUint {
    let s = BigUint::zero();
    let h = sha1::sha1(&s.to_bytes_be());
    BigUint::from_bytes_be(&h)
}

/// ch38: offline dictionary attack against the server-chosen-u
/// variant. A fake server (it chose salt, B, u) records the client's
/// proof; for each dictionary password it recomputes the client-side
/// S/K OFFLINE and matches the proof.
pub fn srp_offline_dictionary(
    n: &BigUint,
    g: &BigUint,
    salt: &[u8],
    server_pub_b: &BigUint,
    u: &BigUint,
    _client_pub_a: &BigUint, // unused: the offline attack needs only (salt,B,u,a) and the proof
    client_priv_a: &BigUint,
    proof: &BigUint,
    dictionary: &[&str],
) -> Option<String> {
    for pw in dictionary {
        let x = srp_x(salt, pw.as_bytes());
        let k = BigUint::from(3u32);
        let base = srp_sub_mod(server_pub_b, &(&k * &modexp(g, &x, n) % n), n);
        let exp = client_priv_a + &(u * &x);
        let s = modexp(&base, &exp, n);
        let h = sha1::sha1(&s.to_bytes_be());
        let candidate = BigUint::from_bytes_be(&h);
        if &candidate == proof {
            return Some((*pw).to_string());
        }
    }
    None
}

// ---- Set 6 ch41: RSA parity oracle ----

/// PKCS#1 v1.5 type-2 pad: 0x00 0x02 || nonzero padding || 0x00 || msg.
/// The filler bytes here are a deterministic LCG — challenge scaffolding,
/// not a randomness recommendation.
pub fn rsa_pad(msg: &[u8], total: usize) -> Vec<u8> {
    assert!(total >= msg.len() + 11, "PKCS#1 needs >= 8 padding bytes");
    let mut out = vec![0x00u8, 0x02];
    let mut seed = 0xc0ffee_u64;
    while out.len() < total - msg.len() - 1 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let b = ((seed >> 33) & 0xff) as u8;
        if b != 0 {
            out.push(b);
        }
    }
    out.push(0x00);
    out.extend(msg);
    out
}

/// The inverse of rsa_pad; None on malformation.
pub fn rsa_unpad(m: &[u8]) -> Option<Vec<u8>> {
    if m.len() < 11 || m[0] != 0x00 || m[1] != 0x02 {
        return None;
    }
    let sep = m[2..].iter().position(|&b| b == 0x00)? + 2;
    if sep < 10 {
        return None; // padding must be >= 8 bytes
    }
    if m[2..sep].iter().any(|&b| b == 0) {
        return None;
    }
    Some(m[sep + 1..].to_vec())
}

/// The oracle: decrypts and reveals ONLY the parity of the plaintext
/// (true = odd). This single bit per query is enough to binary-search
/// the whole message.
pub fn parity_oracle_server(ct: &BigUint, key: &RsaKey) -> bool {
    let m = key.decrypt(ct);
    let _ = rsa_unpad(&m.to_bytes_be()); // server's normal processing
    let lsb = &m % BigUint::from(2u32);
    lsb == BigUint::one()
}

/// The attack: multiply the ciphertext by (2^e)^i mod n each round —
/// the plaintext doubles. Each parity bit refines the integer bounds
/// jlo/jhi on j_i = floor(2^i·m / n) — tracked EXACTLY as integers
/// (midpoint rounding on the m-scale drifts from the true dyadic
/// split, which misclassified m by a few units in tests). At the end
/// m is the unique integer in [jlo·n/2^K, jhi·n/2^K), verified by
/// re-encryption.
pub fn parity_oracle_attack(
    ct: &BigUint,
    e: &BigUint,
    n: &BigUint,
    oracle: &dyn Fn(&BigUint) -> bool,
) -> BigUint {
    let two = BigUint::from(2u32);
    let one = BigUint::one();
    let mult = modexp(&two, e, n); // E(2), computable from the public key
    let k = n.bits() + 8; // extra refinement so the window holds one integer
    let (mut jlo, mut jhi) = (BigUint::zero(), one.clone());
    let mut ct_i = ct.clone();
    for _ in 0..k {
        ct_i = &ct_i * &mult % n;
        if oracle(&ct_i) {
            // j_i odd: j = 2j_prev + 1
            jlo = &jlo * &two + &one;
            jhi *= &two;
        } else {
            // j_i even: j = 2j_prev
            jhi = &jhi * &two - &one;
            jlo *= &two;
        }
    }
    let scale = two.pow(k as u32);
    let lo_bound = &jlo * n;
    let hi_bound = &jhi * n;
    // unique integer in [lo_bound/scale, hi_bound/scale)
    let m = (&lo_bound + &scale - &one) / &scale;
    assert!(modexp(&m, e, n) == *ct, "parity oracle: recovered candidate must re-encrypt to ct");
    assert!(&m * &scale >= lo_bound && &m * &scale < hi_bound, "recovered m must sit in the j-window");
    m
}

// ---- Set 6 ch42: Bleichenbacher's e=3 signature forgery ----

/// Builds the PKCS#1-style block a naive e=3 verifier expects:
/// 0x00 0x01 FF..FF 0x00 || digest || garbage.
pub fn bleichenbacher_block(ff_bytes: usize, digest: &[u8], total_len: usize) -> Vec<u8> {
    let mut b = vec![0x00u8, 0x01];
    b.extend(std::iter::repeat(0xffu8).take(ff_bytes));
    b.push(0x00);
    b.extend(digest);
    b.resize(total_len, 0x00); // garbage region (zeros in the target)
    b
}

/// The forgery: pick sigma = icbrt(D) + 1 where D is the ideal block
/// with zeroed garbage. Then D <= sigma^3 < D + 3*sigma^2 + ... — the
/// difference stays inside the garbage region, so every byte the naive
/// verifier checks (header, digest) is intact. No key, no root-finding
/// beyond one cube root.
pub fn bleichenbacher_e3_forge(ff_bytes: usize, digest: &[u8], total_len: usize) -> BigUint {
    let block = bleichenbacher_block(ff_bytes, digest, total_len);
    let d = BigUint::from_bytes_be(&block);
    icbrt(&d) + BigUint::one()
}

// ---- Set 6 ch43-44: DSA + nonce-reuse private-key recovery ----

pub struct DsaKey {
    pub p: BigUint, // prime
    pub q: BigUint, // prime, q | p-1
    pub g: BigUint, // generator of the order-q subgroup
    pub x: BigUint, // private key
    pub y: BigUint, // public key g^x mod p
}

impl DsaKey {
    pub fn from_params(p: &BigUint, q: &BigUint, g: &BigUint, x: BigUint) -> Self {
        let y = modexp(g, &x, p);
        DsaKey { p: p.clone(), q: q.clone(), g: g.clone(), x, y }
    }

    /// Sign a SHA-1 digest with nonce k. r,s are mod q.
    pub fn sign(&self, digest: &[u8], k: &BigUint) -> (BigUint, BigUint) {
        let h = BigUint::from_bytes_be(digest) % &self.q;
        let r = modexp(&self.g, k, &self.p) % &self.q;
        assert!(!r.is_zero(), "r must be nonzero — pick another k");
        let k_inv = modinv(k, &self.q).expect("k invertible mod q");
        let s = &k_inv * (&h + &self.x * &r) % &self.q;
        (r, s)
    }

    /// Verify: v == r for a valid (r,s) over the digest.
    pub fn verify(&self, digest: &[u8], r: &BigUint, s: &BigUint) -> bool {
        if r.is_zero() || s.is_zero() {
            return false;
        }
        let h = BigUint::from_bytes_be(digest) % &self.q;
        let w = match modinv(s, &self.q) {
            Some(w) => w,
            None => return false,
        };
        let u1 = &h * &w % &self.q;
        let u2 = r * &w % &self.q;
        let v = (modexp(&self.g, &u1, &self.p) * modexp(&self.y, &u2, &self.p) % &self.p) % &self.q;
        &v == r
    }
}

/// ch44: two signatures over different messages with the SAME nonce k
/// give r1 == r2, and k = (H1 - H2) / (s1 - s2) mod q. Then the
/// private key falls out: x = (s·k - H) / r mod q.
pub fn dsa_recover_private_key_from_repeated_nonce(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    y: &BigUint,
    h1: &BigUint,
    s1: &BigUint,
    h2: &BigUint,
    s2: &BigUint,
    r: &BigUint,
) -> Option<BigUint> {
    let ds = srp_sub_mod(s1, s2, q); // (s1 - s2) mod q, unsigned-safe
    let dk = srp_sub_mod(h1, h2, q);
    let k = modinv(&ds, q)? * &dk % q;
    // x = (s1*k - H1) / r mod q — again unsigned-safe subtraction
    let sk = (s1 * &k) % q;
    let num = srp_sub_mod(&sk, h1, q);
    let r_inv = modinv(r, q)?;
    let x = r_inv * &num % q;
    // confirm: g^x == y
    if modexp(g, &x, p) == *y {
        Some(x)
    } else {
        None
    }
}

// ---- Set 6 ch45: DSA parameter injection ----

/// The tampered-param forgery: a verifier that accepts attacker-negotiated
/// g=1 has y=1, r=1, and v = (1^u1 · 1^u2) mod p mod q = 1 — so (1, any
/// nonzero s) verifies for EVERY message without any private key.
pub fn dsa_forge_tampered_g1(s: u64) -> (BigUint, BigUint) {
    (BigUint::from(1u32), BigUint::from(s))
}

// ---- Set 6 ch46: RSA+CBC hybrid — fixed-IV CCA ----

/// The "server": decrypts blob = [RSA block || CBC blocks]; the RSA
/// plaintext doubles as the CBC IV. Returns the unpadded plaintext on
/// success (a helpful error channel for the attacker).
pub fn hybrid_decrypt(key: &RsaKey, aes_key: &[u8; 16], blob: &[u8]) -> Result<Vec<u8>, ()> {
    let rsa_len = ((key.n.bits() + 7) / 8) as usize;
    if blob.len() < rsa_len + 16 || (blob.len() - rsa_len) % 16 != 0 {
        return Err(());
    }
    let iv = key.decrypt(&BigUint::from_bytes_be(&blob[..rsa_len]));
    let iv_bytes = iv.to_bytes_be();
    let mut ivb = [0u8; 16];
    if iv_bytes.len() <= 16 {
        ivb[16 - iv_bytes.len()..].copy_from_slice(&iv_bytes);
    } else {
        return Err(());
    }
    let mut pt = Vec::new();
    let mut prev = ivb;
    for chunk in blob[rsa_len..].chunks_exact(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(chunk);
        let dec = crypto_primitives::aes::aes128_ecb_decrypt_block(&b, aes_key);
        for k in 0..16 {
            pt.push(dec[k] ^ prev[k]);
        }
        prev = b;
    }
    pkcs7_unpad(&pt, 16).map(|p| p.to_vec()).ok_or(())
}

/// The CCA, properly: the attacker controls every CBC ciphertext byte
/// in the blob, so the final block becomes a CBC PADDING ORACLE target.
/// Probe = [0(RSA width) || prev || c2]: the final block decrypts to
/// AES_d(c2) ^ prev, and the attacker adapts prev byte-at-a-time (as in
/// ch17) until the padding validates — recovering AES_d(c2) — then
/// m1 = AES_d(c2) ^ P2 (the known plaintext block).
pub fn hybrid_cca_recover_session(
    c2: &[u8; 16],
    rsa_len: usize,
    p2_known: &[u8; 16],
    oracle: &dyn Fn(&[u8]) -> Result<Vec<u8>, ()>,
) -> Option<[u8; 16]> {
    let mut d = [0u8; 16]; // AES_d(c2), recovered tail-first
    for pos in (0..16).rev() {
        let pad_len = 16 - pos;
        let mut prev = [0u8; 16];
        for j in (pos + 1)..16 {
            prev[j] = d[j] ^ (pad_len as u8);
        }
        let mut found = None;
        for g in 0..=255u8 {
            prev[pos] = g;
            let mut probe = vec![0u8; rsa_len];
            probe.extend(prev);
            probe.extend(c2);
            if oracle(&probe).is_ok() {
                if pos == 15 {
                    // coincidence guard: a true 0x01 hit survives the
                    // perturbation, an accidental 0x02 0x02 does not
                    prev[14] ^= 0xff;
                    let mut re = vec![0u8; rsa_len];
                    re.extend(prev);
                    re.extend(c2);
                    if oracle(&re).is_err() {
                        continue;
                    }
                }
                found = Some(g);
                break;
            }
        }
        let g = found?;
        d[pos] = g ^ (pad_len as u8);
    }
    let mut m1 = [0u8; 16];
    for i in 0..16 {
        m1[i] = d[i] ^ p2_known[i];
    }
    Some(m1)
}

// ---- Set 6 ch47-48: Bleichenbacher's padding oracle (full CCA) ----

fn ceil_div(x: &BigUint, y: &BigUint) -> BigUint {
    (x + y - BigUint::one()) / y
}

/// PKCS#1 v1.5 type-2 conformance: 0x00 0x02, >= 8 nonzero bytes, a
/// zero separator. (The site's simplification checks only the first
/// two bytes; the full check is what a real oracle does.)
fn is_pkcs1_type2(m: &[u8]) -> bool {
    m.len() >= 11
        && m[0] == 0x00
        && m[1] == 0x02
        && m[2..10].iter().all(|&b| b != 0)
        && m[10..].iter().any(|&b| b == 0)
}

/// The oracle: decrypts and reveals ONLY whether the plaintext is
/// PKCS#1 type-2 conformant.
pub fn bleichenbacher_oracle(ct: &BigUint, key: &RsaKey) -> bool {
    let kb = ((key.n.bits() + 7) / 8) as usize;
    let mb = key.decrypt(ct).to_bytes_be();
    let mut buf = vec![0u8; kb - mb.len()];
    buf.extend(mb);
    is_pkcs1_type2(&buf)
}

fn merge_intervals(mut v: Vec<(BigUint, BigUint)>) -> Vec<(BigUint, BigUint)> {
    v.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out: Vec<(BigUint, BigUint)> = Vec::new();
    for (lo, hi) in v {
        let merged = match out.last() {
            Some(last) => lo <= &last.1 + &BigUint::one(),
            None => false,
        };
        if merged {
            let last = out.last_mut().unwrap();
            if hi > last.1 {
                last.1 = hi;
            }
        } else {
            out.push((lo, hi));
        }
    }
    out
}

/// The full adaptive chosen-ciphertext attack (Vaudenay-style
/// rendering of Bleichenbacher 1998). Recovers the padded plaintext
/// from nothing but the conformance oracle, e, and n.
pub fn bleichenbacher_attack(
    ct: &BigUint,
    e: &BigUint,
    n: &BigUint,
    oracle: &dyn Fn(&BigUint) -> bool,
) -> BigUint {
    let kbytes = ((n.bits() + 7) / 8) as usize;
    let b = BigUint::from(2u32).pow(8 * (kbytes as u32 - 2));
    let b2 = &b * BigUint::from(2u32);
    let b3 = &b * BigUint::from(3u32);
    let b31 = &b3 - BigUint::one();
    let zero = BigUint::zero();
    let one = BigUint::one();

    // M0 = [2B, 3B-1]
    let mut intervals = vec![(b2.clone(), b31.clone())];
    // s1: smallest s >= n/3B with conforming(ct * s^e mod n)
    let mut s = ceil_div(n, &b3);
    let mut c_cur;
    loop {
        c_cur = ct * modexp(&s, e, n) % n;
        if oracle(&c_cur) {
            break;
        }
        s += one.clone();
    }
    // interval update given s and previous intervals
    let update = |intervals: &[(BigUint, BigUint)], s: &BigUint| -> Vec<(BigUint, BigUint)> {
        let mut collected = Vec::new();
        for (a, b) in intervals {
            let asv = a * s;
            let bsv = b * s;
            // r >= (a*s - 3B + 1)/n  (>=0), r <= (b*s - 2B)/n
            let r_lo = if &asv + &one <= b3 {
                zero.clone()
            } else {
                ceil_div(&(&asv + &one - &b3), n)
            };
            if bsv < b2 {
                continue;
            }
            let r_hi = (&bsv - &b2) / n;
            if r_hi < r_lo {
                continue;
            }
            let mut r = r_lo;
            while r <= r_hi {
                let rn = &r * n;
                let lo = {
                    let cand = ceil_div(&(&b2 + &rn), s);
                    std::cmp::max(a.clone(), cand)
                };
                let hi = {
                    let cand = (&b31 + &rn) / s;
                    std::cmp::min(b.clone(), cand)
                };
                if lo <= hi {
                    collected.push((lo, hi));
                }
                r += one.clone();
            }
        }
        merge_intervals(collected)
    };

    intervals = update(&intervals, &s);
    let mut iters = 0usize;
    loop {
        iters += 1;
        assert!(iters < 512, "bleichenbacher: search did not terminate");
        if intervals.len() == 1 {
            let (a, b) = intervals[0].clone();
            if a == b {
                // m = a exactly — verify by re-encryption
                let m = a;
                assert!(
                    modexp(&m, e, n) == *ct,
                    "bleichenbacher: recovered m must re-encrypt to ct"
                );
                return m;
            }
            // single interval: targeted r/s search —
            // r starts at ceil(2(b·s_prev - 2B)/n)
            let mut r = ceil_div(&((&b * &s - &b2) * &two()), n);
            // targeted search: labeled loop returns the s that conforms
            s = 'outer: loop {
                let s_lo = ceil_div(&(&b2 + &r * n), &b);
                let s_hi = (&b31 + &r * n) / &a;
                let mut cand = s_lo;
                while cand <= s_hi {
                    let c_try = ct * modexp(&cand, e, n) % n;
                    if oracle(&c_try) {
                        break 'outer cand;
                    }
                    cand += one.clone();
                }
                r += one.clone();
            };
        } else {
            // multiple intervals: scan upward from s + 1
            loop {
                s += one.clone();
                let c_try = ct * modexp(&s, e, n) % n;
                if oracle(&c_try) {
                    break;
                }
            }
        }
        intervals = update(&intervals, &s);
    }
}

fn two() -> BigUint {
    BigUint::from(2u32)
}

// ---- Set 7 (old-site numbering): hashes & MACs ----

/// CBC-MAC over 16-byte blocks with a fixed IV (the ch49 protocol
/// primitive — secure ONLY for fixed-length messages).
pub fn cbc_mac(key: &[u8; 16], iv: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    assert!(msg.len() % 16 == 0 && !msg.is_empty(), "CBC-MAC needs non-empty 16-aligned input");
    let mut prev = *iv;
    let mut tag = [0u8; 16];
    for block in msg.chunks_exact(16) {
        let mut x = [0u8; 16];
        for j in 0..16 {
            x[j] = block[j] ^ prev[j];
        }
        tag = crypto_primitives::aes::aes128_ecb_encrypt_block(&x, key);
        prev = tag;
    }
    tag
}

/// ch49: the variable-length CBC-MAC forgery. With a FIXED IV, the tag
/// of a one-block message IS the chain state after that block. Query
/// tag(P1) = T1 (the prefix), know the victim's one-block message P2
/// with tag T2; then MAC(P1 || (P2 ^ T1)) = AES(T1 ^ (P2 ^ T1)) =
/// AES(P2) = T2 — the forged message carries the victim's tag.
pub fn cbc_mac_forgery(
    key: &[u8; 16],
    iv: &[u8; 16],
    prefix_p1: &[u8; 16],
    victim_p2: &[u8; 16],
) -> ([u8; 16], Vec<u8>) {
    let t1 = cbc_mac(key, iv, prefix_p1); // attacker's oracle query
    let mut second_block = [0u8; 16];
    for j in 0..16 {
        second_block[j] = victim_p2[j] ^ t1[j];
    }
    let mut forged = Vec::with_capacity(32);
    forged.extend(prefix_p1);
    forged.extend(second_block);
    let t2 = cbc_mac(key, iv, victim_p2);
    let forged_tag = cbc_mac(key, iv, &forged);
    assert_eq!(forged_tag, t2, "forged message must carry the victim's tag");
    (t2, forged)
}

/// A toy Merkle-Damgård hash: 32-bit state, one compression function
/// over 32-bit blocks. Small on purpose — collisions are findable in
/// ~2^16, which is the lesson.
pub fn toy_md_hash(state0: u32, blocks: &[u32]) -> u32 {
    let mut s = state0;
    for &b in blocks {
        s = (s ^ b).wrapping_mul(0x9E37_79B9).rotate_left(7) ^ (b >> 1);
    }
    s
}

/// ch52-style: find a colliding pair (a, b) for a GIVEN incoming
/// state — birthday search over the compression function's outputs.
/// Reusable as a suffix under ANY prefix (the Merkle-Damgård flaw).
pub fn toy_md_colliding_suffix(state: u32) -> (u32, u32, u32) {
    use std::collections::HashMap;
    let mut seen: HashMap<u32, u32> = HashMap::new();
    let mut x = 0u32;
    loop {
        let out = toy_md_hash(state, &[x]);
        if let Some(&prev) = seen.get(&out) {
            return (prev, x, out);
        }
        seen.insert(out, x);
        x = x.wrapping_add(1);
        // birthday bound: collision expected by ~2^17 steps
        assert!(x != 0, "toy collision search exhausted 2^32 (impossible)");
    }
}

// ---- Set 7 ch50: collision-based MAC forgery ----

/// Birthday search for a colliding pair whose blocks differ in the low
/// nibble (standing in for "different transfer amounts") — in the real
/// challenge this pair is precomputed research data handed to the
/// attacker.
pub fn toy_md_amount_pair(state: u32) -> (u32, u32) {
    use std::collections::HashMap;
    let mut seen: HashMap<u32, u32> = HashMap::new();
    let mut x = 0u32;
    loop {
        let out = toy_md_hash(state, &[x]);
        if let Some(&prev) = seen.get(&out) {
            if (prev & 0xf) != (x & 0xf) {
                return (prev, x);
            }
        } else {
            seen.insert(out, x);
        }
        x = x.wrapping_add(1);
        assert!(x != 0, "toy amount-pair search exhausted 2^32");
    }
}

/// The forgery: two orders sharing the known header but differing in
/// the colliding suffix blocks carry IDENTICAL MACs under the secret
/// key — the bank's "tag binds content" assumption fails.
pub fn collision_mac_orders_equal(secret_state: u32, header: u32, a: u32, b: u32) -> bool {
    toy_md_hash(secret_state, &[header, a]) == toy_md_hash(secret_state, &[header, b])
}

// ---- Set 7 ch51: CBC-MAC with IV = first message block ----

/// A documented-broken construction: the first block doubles as the
/// IV, the MAC chains over the remainder. One-block messages reduce to
/// AES(0) — a UNIVERSAL tag.
pub fn cbc_mac_iv_inheritance(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    assert!(msg.len() % 16 == 0 && !msg.is_empty());
    let iv: [u8; 16] = msg[..16].try_into().unwrap();
    if msg.len() == 16 {
        // IV cancels the block: AES(0)
        return crypto_primitives::aes::aes128_ecb_encrypt_block(&[0u8; 16], key);
    }
    let mut prev = iv;
    let mut tag = [0u8; 16];
    for block in msg[16..].chunks_exact(16) {
        let mut x = [0u8; 16];
        for j in 0..16 {
            x[j] = block[j] ^ prev[j];
        }
        tag = crypto_primitives::aes::aes128_ecb_encrypt_block(&x, key);
        prev = tag;
    }
    tag
}

// ---- Set 7 ch53: Kelsey second-preimages (16-bit toy, structure-scaled) ----

/// 16-bit MD compression function — same structure as the 32-bit toy,
/// scaled so targeted-state searches cost 2^16.
pub fn toy_md16_compress(s: u16, b: u16) -> u16 {
    ((s ^ b).wrapping_mul(0x9E37).rotate_left(5)) ^ b.rotate_left(3)
}

pub fn toy_md16(state0: u16, blocks: &[u16]) -> u16 {
    let mut s = state0;
    for &b in blocks {
        s = toy_md16_compress(s, b);
    }
    s
}

/// Exhaustive 1-block preimage of `target` from state `s` (2^16 scan).
/// None if the target has no preimage (~37% per target — the caller
/// tries several targets, making overall failure negligible).
pub fn targeted_preimage16(s: u16, target: u16) -> Option<u16> {
    for b in 0..=u16::MAX {
        if toy_md16_compress(s, b) == target {
            return Some(b);
        }
    }
    None
}

/// ch53a: Joux multicollision — `pairs` sequential 1-block collision
/// pairs, every one of the 2^pairs combinations hashing identically.
pub fn joux_multicollision16(state: u16, pairs: usize) -> Vec<(u16, u16)> {
    let mut s = state;
    let mut out = Vec::with_capacity(pairs);
    for _ in 0..pairs {
        // find an actual collision pair from state s: scan blocks,
        // map output->block, the first repeat is the pair (birthday,
        // ~2^8 steps — an arbitrary fixed block has NO partner ~37%
        // of the time, which the first version of this got wrong)
        use std::collections::HashMap;
        let mut seen: HashMap<u16, u16> = HashMap::new();
        let (mut b1, mut b2) = (None, None);
        for b in 0..=u16::MAX {
            let o = toy_md16_compress(s, b);
            if let Some(&prev) = seen.get(&o) {
                b1 = Some(prev);
                b2 = Some(b);
                break;
            }
            seen.insert(o, b);
        }
        let (b1, b2) = match (b1, b2) {
            (Some(a), Some(b)) => (a, b),
            _ => panic!("joux: full 2^16 scan found no collision (impossible)"),
        };
        out.push((b1, b2));
        s = toy_md16_compress(s, b1);
    }
    out
}

/// ch53b: Kelsey expandable messages. For each step j the branches are
/// 1 block and 2^{j-1}+1 blocks, both mapping S_{j-1} -> S_j — the
/// per-step length offsets are {1, 2, 4, ...}, so every total length
/// in [k, k+2^k-1] is reachable and all messages end at S_k.
pub struct Expandable16 {
    pub s_k: u16,
    pub k: usize,
    /// per step j (0-indexed): (x_j, zeros_len, z_j, c_j)
    pub steps: Vec<(u16, usize, u16, u16)>,
}

pub fn expandable16_build(state: u16, k: usize) -> Expandable16 {
    let mut s = state;
    let mut steps = Vec::with_capacity(k);
    for j in 1..=k {
        let zeros_len = 1usize << (j - 1);
        // long branch prefix: zeros from S_{j-1}
        let zeros: Vec<u16> = vec![0u16; zeros_len];
        let s_after_zeros = toy_md16(s, &zeros);
        // full coverage map of the SHORT branch's outputs
        use std::collections::HashMap;
        let mut map: HashMap<u16, u16> = HashMap::new();
        for x in 0..=u16::MAX {
            map.insert(toy_md16_compress(s, x), x);
        }
        // scan the long branch's final block until its output collides
        // with a short-branch output — expected a couple of steps
        let mut z = 0u16;
        let (x_j, c_j) = loop {
            let c = toy_md16_compress(s_after_zeros, z);
            if let Some(&x) = map.get(&c) {
                break (x, c);
            }
            z += 1;
        };
        steps.push((x_j, zeros_len, z, c_j));
        s = c_j;
    }
    Expandable16 { s_k: s, k, steps }
}

/// Assemble an expandable message of the requested length (must lie in
/// [k, k + 2^k - 1]); it ends at S_k.
pub fn expandable_message16(e: &Expandable16, length: usize) -> Option<Vec<u16>> {
    if length < e.k || length >= e.k + (1usize << e.k) {
        return None;
    }
    let offset = length - e.k;
    let mut blocks = Vec::new();
    for (j, (x_j, zeros_len, z_j, _)) in e.steps.iter().enumerate() {
        if offset & (1 << j) != 0 {
            blocks.extend(vec![0u16; *zeros_len]);
            blocks.push(*z_j);
        } else {
            blocks.push(*x_j);
        }
    }
    debug_assert_eq!(blocks.len(), length);
    Some(blocks)
}

/// ch53c: the second-preimage attack. Given the victim's blocks,
/// find a DIFFERENT message hashing identically but shorter: an
/// expandable prefix ending at S_k, a 1-block bridge onto one of the
/// victim's intermediate states, then the victim's remaining blocks.
pub fn second_preimage16(state0: u16, victim: &[u16], k: usize) -> Option<Vec<u16>> {
    let l = victim.len();
    assert!(l > k + 2, "victim must be long enough for the bridge math");
    let e = expandable16_build(state0, k);
    // victim's intermediate states after i blocks
    for i in (k + 2)..=l {
        let target = toy_md16(state0, &victim[..i]);
        // bridge from S_k onto that state
        if let Some(bridge) = targeted_preimage16(e.s_k, target) {
            // need an expandable message of length ℓ <= i-2 so the
            // second preimage is STRICTLY shorter than the victim
            let want = (i - 2).max(k); // any valid expandable length
            let Some(prefix) = expandable_message16(&e, want) else {
                continue;
            };
            let mut second = prefix.clone();
            second.push(bridge);
            second.extend(&victim[i..]);
            if toy_md16(state0, &second) == toy_md16(state0, victim) && second.len() < l {
                return Some(second);
            }
        }
    }
    None
}
