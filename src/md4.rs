//! MD4 (RFC 1320) — 128-bit hash, three rounds of 16 steps, additive
//! constants only in rounds 2-3, LITTLE-endian length encoding.
//! State-exposed like the SHA-1 layer so keyed-MAC length extension
//! (ch30) is constructible by callers.

pub struct Md4 {
    h: [u32; 4],
    len: u64, // total bytes fed
    buf: Vec<u8>,
}

impl Md4 {
    pub fn new() -> Self {
        Md4 {
            h: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            len: 0,
            buf: Vec::new(),
        }
    }

    /// Continue from a captured (h, len) state — the length-extension
    /// glue (ch30).
    pub fn from_state(h: [u32; 4], len: u64) -> Self {
        Md4 { h, len, buf: Vec::new() }
    }

    pub fn state(&self) -> [u32; 4] {
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

    /// Append MD-strengthening padding (LITTLE-endian 64-bit bit count)
    /// and finish.
    pub fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.len * 8;
        self.buf.push(0x80);
        while self.buf.len() % 64 != 56 {
            self.buf.push(0);
        }
        // MD4 stores the length little-endian (unlike SHA-1's BE)
        self.buf.extend_from_slice(&bit_len.to_le_bytes());
        while self.buf.len() >= 64 {
            let block: [u8; 64] = self.buf[..64].try_into().unwrap();
            self.compress(&block);
            self.buf.drain(..64);
        }
        let mut out = [0u8; 16];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// The glue padding MD4 appended between the message and new data
    /// (little-endian length, per RFC 1320).
    pub fn glue_padding(len: u64) -> Vec<u8> {
        let mut pad = vec![0x80u8];
        while (len as usize + pad.len()) % 64 != 56 {
            pad.push(0);
        }
        pad.extend_from_slice(&((len * 8).to_le_bytes()));
        pad
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for (i, w) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes(w.try_into().unwrap()); // LE words
        }
        let (mut a, mut b, mut c, mut d) = (self.h[0], self.h[1], self.h[2], self.h[3]);

        // Round 1: F(b,c,d) = (b & c) | (!b & d); shifts 3,7,11,19; X in order
        for s in 0..4 {
            let i = s * 4;
            a = (a.wrapping_add((b & c) | (!b & d)).wrapping_add(x[i])).rotate_left(3);
            d = (d.wrapping_add((a & b) | (!a & c)).wrapping_add(x[i + 1])).rotate_left(7);
            c = (c.wrapping_add((d & a) | (!d & b)).wrapping_add(x[i + 2])).rotate_left(11);
            b = (b.wrapping_add((c & d) | (!c & a)).wrapping_add(x[i + 3])).rotate_left(19);
        }
        // Round 2: G = maj(b,c,d); shifts 3,5,9,13; X base advances by 1
        // per group (X[0,4,8,12] then X[1,5,9,13] ...); +5A827999
        for s in 0..4 {
            let i = s;
            a = (a
                .wrapping_add((b & c) | (b & d) | (c & d))
                .wrapping_add(x[i])
                .wrapping_add(0x5a82_7999))
            .rotate_left(3);
            d = (d
                .wrapping_add((a & b) | (a & c) | (b & c))
                .wrapping_add(x[i + 4])
                .wrapping_add(0x5a82_7999))
            .rotate_left(5);
            c = (c
                .wrapping_add((d & a) | (d & b) | (a & b))
                .wrapping_add(x[i + 8])
                .wrapping_add(0x5a82_7999))
            .rotate_left(9);
            b = (b
                .wrapping_add((c & d) | (c & a) | (d & a))
                .wrapping_add(x[i + 12])
                .wrapping_add(0x5a82_7999))
            .rotate_left(13);
        }
        // Round 3: H = b ^ c ^ d; shifts 3,9,11,15; X order 3i+5 mod 16; +6ED9EBA1
        const R3_ORDER: [usize; 16] = [
            0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
        ];
        for s in 0..4 {
            let i = s * 4;
            a = (a
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(x[R3_ORDER[i]])
                .wrapping_add(0x6ed9_eba1))
            .rotate_left(3);
            d = (d
                .wrapping_add(a ^ b ^ c)
                .wrapping_add(x[R3_ORDER[i + 1]])
                .wrapping_add(0x6ed9_eba1))
            .rotate_left(9);
            c = (c
                .wrapping_add(d ^ a ^ b)
                .wrapping_add(x[R3_ORDER[i + 2]])
                .wrapping_add(0x6ed9_eba1))
            .rotate_left(11);
            b = (b
                .wrapping_add(c ^ d ^ a)
                .wrapping_add(x[R3_ORDER[i + 3]])
                .wrapping_add(0x6ed9_eba1))
            .rotate_left(15);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
    }
}

pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(data);
    h.finalize()
}

pub fn md4_hex(data: &[u8]) -> String {
    md4(data).iter().map(|b| format!("{b:02x}")).collect()
}
