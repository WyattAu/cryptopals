//! Cryptopals Set 1 — Basics. Solutions in pure Rust, std only.

pub fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn base64_encode(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

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
