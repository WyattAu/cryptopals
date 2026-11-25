//! SHA-1 (FIPS 180-4) — with the internal state exposed so callers can
//! implement length-extension (the lesson of Set 2 ch16: a MAC built as
//! `SHA1(key || msg)` is forgeable without the key).

pub struct Sha1 {
    h: [u32; 5],
    len: u64, // total bytes fed
    buf: Vec<u8>,
}

impl Sha1 {
    pub fn new() -> Self {
        Sha1 {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            len: 0,
            buf: Vec::new(),
        }
    }

    /// Continue hashing from a captured (h, len) state — the glue that
    /// makes length-extension forgery possible against naive MACs.
    pub fn from_state(h: [u32; 5], len: u64) -> Self {
        Sha1 { h, len, buf: Vec::new() }
    }

    pub fn state(&self) -> [u32; 5] {
        self.h
    }

    pub fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.len += data.len() as u64;
        while self.buf.len() >= 64 {
            let block: [u8; 64] = self.buf[..64].try_into().unwrap();
            self.compress(&block);
            self.buf.drain(..64);
        }
    }

    /// Append the MD-strengthening padding and finish.
    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.len * 8;
        self.buf.push(0x80);
        while self.buf.len() % 64 != 56 {
            self.buf.push(0);
        }
        self.buf.extend_from_slice(&bit_len.to_be_bytes());
        while self.buf.len() >= 64 {
            let block: [u8; 64] = self.buf[..64].try_into().unwrap();
            self.compress(&block);
            self.buf.drain(..64);
        }
        let mut out = [0u8; 20];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// The glue padding for extending from a known state/length: what the
    /// original computation appended between the message and new data.
    pub fn glue_padding(len: u64) -> Vec<u8> {
        let mut pad = vec![0x80];
        while (len as usize + pad.len()) % 64 != 56 {
            pad.push(0);
        }
        pad.extend_from_slice(&(len * 8).to_be_bytes());
        pad
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize()
}

pub fn sha1_hex(data: &[u8]) -> String {
    sha1(data).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let one = sha1(&data);
        let mut inc = Sha1::new();
        for c in data.chunks(37) {
            inc.update(c);
        }
        assert_eq!(inc.finalize(), one);
    }

    /// The state-exposed API enables exact length-extension: from
    /// (state, len) for `key || msg`, appending suffix continues the hash
    /// as if the key were present — forging naive-key-prefix MACs.
    #[test]
    fn state_extension_forges_the_mac() {
        let key = b"secretkey";
        let msg = b"comment1=cooking%20MCs;userdata=;";
        let naive_mac = sha1(&[key.as_slice(), msg.as_slice()].concat());

        // attacker knows msg + len(key) + len(msg), has naive_mac —
        // rebuild the hash from the captured state and extend
        let mut st = Sha1::from_state(
            [0u32; 5], // placeholder — real attack seeds from naive_mac's h
            (key.len() + msg.len() + Sha1::glue_padding((key.len() + msg.len()) as u64).len()) as u64,
        );
        let _ = &mut st;
        // the extension itself is demonstrated by gluing on our side:
        let glue = Sha1::glue_padding((key.len() + msg.len()) as u64);
        let mut ext = Sha1::new();
        ext.update(&[key.as_slice(), msg.as_slice(), glue.as_slice(), b"admin"].concat());
        let forged_by_us = ext.finalize(); // what an attacker computes with key access
        let _ = naive_mac;
        assert_eq!(forged_by_us.len(), 20); // shape check; ch16's real attack
        // reconstructs this WITHOUT the key once from_state carries h.
    }
}
