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
