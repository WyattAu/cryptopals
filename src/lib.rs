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
