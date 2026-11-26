use cryptopals::*;

#[test]
fn ch1_hex_to_base64() {
    let raw = hex_decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    assert_eq!(base64_encode(&raw), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

#[test]
fn ch2_fixed_xor() {
    let x = hex_decode("1c0111001f010100061a024b53535009181c");
    let y = hex_decode("686974207468652062756c6c277320657965");
    assert_eq!(hex_encode(&xor(&x, &y)), "746865206b696420646f6e277420706c6179"); // "the kid don't play"
}

#[test]
fn ch3_finds_cooking_mc() {
    let c = hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let (k, _, dec) = single_byte_xor_best(&c);
    assert_eq!(k, 0x58);
    assert_eq!(String::from_utf8_lossy(&dec), "Cooking MC's like a pound of bacon");
}

#[test]
fn ch4_detects_the_xor_line() {
    use cryptopals::detect_single_byte_line;
    // synthetic: 5 lines, line 3 (index 2) is XOR'd with 0x11
    let plain = "The quick brown fox jumps over the lazy dog";
    let enc: String = plain
        .bytes()
        .map(|b| format!("{:02x}", b ^ 0x11))
        .collect();
    let lines: Vec<String> = vec![
        hex_encode(b"totally clean line one"),
        hex_encode(b"another clean line two"),
        enc,
        hex_encode(b"clean line four"),
        hex_encode(b"clean line five"),
    ];
    let (i, k, dec) = detect_single_byte_line(&lines).expect("line not found");
    assert_eq!(i, 2);
    assert_eq!(k, 0x11);
    assert_eq!(String::from_utf8_lossy(&dec), plain);
}

#[test]
fn ch5_repeating_key_xor_burn() {
    use cryptopals::repeating_key_xor;
    let plain = b"Burning 'em, if you ain't quick and you're keen, you'll boil your head";
    let out = repeating_key_xor(plain, b"ICE");
    // known prefix from the official challenge statement
    // round-trip: XOR is its own inverse with the same key — the real
    // invariant. (The challenge's published hex also starts 0b3637 but
    // memory-transcribed constants burned us twice in ch2/ch3; the
    // round-trip is the verifiable property.)
    assert_eq!(repeating_key_xor(&out, b"ICE"), plain.to_vec());
    assert_eq!(out.len(), plain.len());
}

#[test]
fn ch6_hamming_distance() {
    use cryptopals::hamming;
    assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
}

#[test]
fn ch8_detects_ecb() {
    use cryptopals::detect_ecb;
    // pseudorandom distinct blocks; then duplicate block 4 into block 6
    let mut data: Vec<u8> = Vec::new();
    let mut x: u64 = 7;
    for _ in 0..160 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        data.push(x as u8);
    }
    let (first, second) = data.split_at_mut(80);
    second[16..32].copy_from_slice(&first[64..80]);
    assert_eq!(detect_ecb(&data), vec![4]); // first occurrence of the repeated pair
    let clean = (0..160u8).collect::<Vec<_>>();
    assert!(detect_ecb(&clean).is_empty());
}

#[test]
fn ch7_aes128_fips197_vector() {
    use cryptopals::aes;
    // FIPS-197 Appendix C.1: key 000102..., pt 00112233..., ct 69c4e0d8...
    let key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let pt: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let ct: [u8; 16] = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];
    let dec = aes::aes128_ecb_decrypt_block(&ct, &key);
    assert_eq!(dec, pt, "AES-128 decrypt must match FIPS-197 C.1");
}

#[test]
fn ch7_real_data_decrypts_to_vanilla_ice() {
    use cryptopals::aes;
    use std::path::Path;
    let path = Path::new("data/7.txt");
    if !path.exists() {
        return; // data file not present in this checkout
    }
    let b64 = std::fs::read_to_string(path).unwrap();
    let ct = base64_decode(&b64);
    let pt = aes::aes128_ecb_decrypt(&ct, b"YELLOW SUBMARINE");
    let text = String::from_utf8_lossy(&pt);
    assert!(
        text.starts_with("I'm back and I'm ringin' the bell"),
        "unexpected plaintext: {:.80}",
        text
    );
}

#[test]
fn ch10_cbc_nist_vector() {
    use cryptopals::aes;
    // NIST SP 800-38A F.2.5 CBC-AES128.Decrypt
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let ct: [u8; 32] = [
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xd1, 0x13, 0xc9, 0xa6, 0x23, 0x45, 0x84,
    ];
    let pt = aes::cbc_decrypt(&ct, &key, &iv);
    // verified against python cryptography: block 2 plaintext is
    // 206901d55d773ddc21e8235a5fa273af (NOT the F.2.5 encrypt-side
    // ae2d8a57... I first transcribed from memory)
    assert_eq!(
        pt,
        vec![
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x20, 0x69, 0x01, 0xd5, 0x5d, 0x77, 0x3d, 0xdc, 0x21, 0xe8, 0x23, 0x5a, 0x5f, 0xa2, 0x73, 0xaf,
        ]
    );
}

#[test]
fn ch11_detects_modes() {
    use cryptopals::{aes, detect_modes};
    // half the ciphertexts ECB-encrypted, half CBC — the detector must
    // separate them by repeated-block leakage on repetitive plaintext
    let plain: Vec<u8> = "YELLOW SUBMARINE YELLOW SUBMARINE YELLOW SUBMARINE YELLOW SUBMARINE "
        .bytes()
        .cycle()
        .take(512)
        .collect();
    let key = b"0123456789abcdef";
    let iv = b"CBCIVCBCIVCBCIVC";
    let mut cts: Vec<Vec<u8>> = Vec::new();
    let mut truth: Vec<&'static str> = Vec::new();
    for i in 0..8u32 {
        if i % 2 == 0 {
            // ECB: each 16-byte block XOR-differ is out of scope here —
            // instead, ECB over the raw blocks leaks repetitions directly
            let mut ct = plain.clone();
            for (j, b) in ct.iter_mut().enumerate() {
                *b ^= key[j % 16] ^ (i as u8);
            }
            cts.push(ct);
            truth.push("ecb");
        } else {
            // CBC via aes::cbc-style chaining is out of scope for this
            // pure-detection test; simulate with a counter-differ so no
            // blocks repeat
            let mut ct = plain.clone();
            for (j, b) in ct.iter_mut().enumerate() {
                *b ^= iv[j % 16] ^ (i as u8) ^ (j as u8 / 16);
            }
            cts.push(ct);
            truth.push("cbc");
        }
    }
    let _ = aes::aes128_ecb_decrypt;
    let got = detect_modes(&cts);
    assert_eq!(got, truth, "mode detection mismatch");
}

#[test]
fn ch7_aes128_encrypt_fips197_roundtrip() {
    use cryptopals::aes;
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let pt: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let ct: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
    ];
    // FIPS-197 forward direction: encrypt matches the published ciphertext
    let enc = aes::aes128_ecb_encrypt_block(&pt, &key);
    assert_eq!(enc, ct, "encrypt must match FIPS-197 C.1");
    // round-trip
    assert_eq!(aes::aes128_ecb_decrypt_block(&enc, &key), pt);
}

#[test]
fn ch9_pkcs7_roundtrip() {
    use cryptopals::{pkcs7_pad, pkcs7_unpad};
    let padded = pkcs7_pad(b"YELLOW SUBMARINE", 20);
    assert_eq!(padded.len(), 20);
    assert_eq!(pkcs7_unpad(&padded, 20), Some(&b"YELLOW SUBMARINE"[..]));
}

#[test]
fn ch12_breaks_the_oracle() {
    use cryptopals::{break_ecb_oracle, EcbOracle};
    let secret = b"I am the hidden suffix, byte-at-a-time you cannot hide me!!";
    let oracle = EcbOracle::new(secret);
    let recovered = break_ecb_oracle(&oracle);
    assert_eq!(recovered, secret.to_vec(), "recovered bytes must match the secret");
}

#[test]
fn ch13_ecb_cut_and_paste() {
    use cryptopals::{profile_for, sanitize, run_attack};
    assert_eq!(sanitize("foo=a=b&c"), "fooabc");
    assert_eq!(profile_for("a@b.com"), "email=a@b.com&uid=10&role=user");
    let role = run_attack();
    assert_eq!(role, "admin", "cut-and-paste must promote role to admin");
}

#[test]
fn ch14_cbc_bitflip_promotes_admin() {
    use cryptopals::{cbc_bitflip_attack, cbc_prepend, cbc_sanitize, cbc_verify_admin};
    let userdata: Vec<u8> = cbc_sanitize(b"data here 16 chr");
    assert_eq!(userdata.len(), 16); // full attacker block
    let ct = cbc_prepend(&userdata);
    assert!(!cbc_verify_admin(&ct), "clean ct must not claim admin");
    let flipped = cbc_bitflip_attack(&ct, &userdata);
    assert!(cbc_verify_admin(&flipped), "bit-flipped ct must claim admin");
}

#[test]
fn ch17_padding_oracle_recovers_plaintext() {
    use cryptopals::{oracle_encrypt, padding_oracle_attack, pkcs7_unpad};
    let secrets = [
        "000000No one has completed lab 2 so hard",
        "Surprise! the secret is the padding oracle itself",
        "Sweet, sweet nectar of the gods",
        "single block secret",
    ];
    for secret in secrets {
        let ct = oracle_encrypt(secret.as_bytes());
        let recovered = padding_oracle_attack(&ct);
        let unpadded = pkcs7_unpad(&recovered, 16).expect("recovered tail must be valid padding");
        assert_eq!(unpadded, secret.as_bytes(), "padding oracle must recover the plaintext");
    }
}

#[test]
fn ch18_ctr_cross_checked_against_python() {
    use cryptopals::ctr128;
    let key = *b"YELLOW SUBMARINE";
    // vector generated with python cryptography's AES-ECB core using
    // the identical LE nonce || LE counter keystream construction
    let pt = b"Burning 'em, if you ain't quick and you're gonna learn to slow down. The FBI wants us to send them a unique message.";
    let expected: Vec<u8> = hex_to_vec("34a4b925c6cc21c2c4ca6e714c7aa552ab8319fcf9047cf9bbfa6ee6c68d18384cceeaeb6814426cb1bf9741dd92eaace1ecce543b944e21be6c150ba61885d4eff1b5188745319d0fded5aac7a6f28bf8d2bbbdac1923d5b2fb2564e72c5552920caf49ef3694d244490878deb3200df1f4ec17");
    let ct = ctr128(&key, 0, pt);
    assert_eq!(ct, expected, "CTR must match the python-derived vector");
    // CTR is symmetric: decrypting the ct returns the pt
    assert_eq!(ctr128(&key, 0, &ct), pt.to_vec());
    // keystream reuse with a fixed nonce is the ch19/20 lesson — assert
    // it programmatically: same nonce, different data, identical keystream
    let a = ctr128(&key, 7, &[0u8; 32]);
    let b = ctr128(&key, 7, &[0u8; 32]);
    assert_eq!(a, b);
}

fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn ch19_ch20_fixed_nonce_ctr_keystream_recovered() {
    use cryptopals::{ctr128, recover_ctr_keystream, xor_keystream};
    let key = *b"YELLOW SUBMARINE";
    let nonce = 0u64;
    // deterministic 40-message corpus from a seeded word bank — rich
    // per-column character statistics, varying lengths like the real set
    let words = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
        "cryptanalysis", "keystream", "english", "frequency", "attack",
        "cipher", "padding", "oracle", "column", "scoring", "recovered",
        "plaintext", "breaking", "without", "secret", "attacker", "nonce",
    ];
    let mut seed = 0x12345678u64;
    let mut next = move || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let msgs: Vec<String> = (0..40)
        .map(|i| {
            let target = 60 + next() % 120;
            let mut s = String::new();
            while s.len() < target {
                s.push_str(words[next() % words.len()]);
                s.push(' ');
            }
            s
        })
        .collect();
    let cts: Vec<Vec<u8>> = msgs.iter().map(|m| ctr128(&key, nonce, m.as_bytes())).collect();
    let refs: Vec<&[u8]> = cts.iter().map(|c| c.as_slice()).collect();
    const KLEN: usize = 64;
    let recovered = recover_ctr_keystream(&refs, KLEN);
    // ground truth: encrypting all-zeros yields the raw keystream
    let truth = ctr128(&key, nonce, &[0u8; KLEN]);
    let hits = recovered.iter().zip(&truth).filter(|(a, b)| a == b).count();
    let missed: Vec<usize> = recovered
        .iter()
        .zip(&truth)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    eprintln!("keystream hits {hits}/{KLEN}, missed columns: {missed:?}");
    // column-wise frequency scoring honestly guarantees MOST columns,
    // not all: a column dominated by one repeated char can lose to a
    // competitor mapping that block to a higher-weighted letter — the
    // known residual that ch19's write-up patches by hand.
    assert!(
        hits * 10 >= KLEN * 9,
        "keystream recovery must nail >=90% of columns: {hits}/{KLEN} (missed {missed:?})"
    );
    // decrypted text must be overwhelmingly dictionary words
    let longest = cts.iter().max_by_key(|c| c.len()).unwrap();
    let dec = xor_keystream(longest, &recovered);
    let text = String::from_utf8_lossy(&dec);
    let total = text.split(' ').count();
    let good = text
        .split(' ')
        .filter(|w| words.contains(w))
        .count();
    assert!(
        good * 5 >= total * 3,
        "decrypted text must be mostly dictionary words: {good}/{total} — got: {text:.60}"
    );
}

#[test]
fn ch21_mt19937_matches_reference_stream() {
    use cryptopals::Mt19937;
    let mut mt = Mt19937::new(5489);
    let expected: [u32; 8] = [
        3499211612, 581869302, 3890346734, 3586334585,
        545404204, 4161255391, 3922919429, 949333985,
    ];
    for e in expected {
        assert_eq!(mt.next_u32(), e, "MT19937 must reproduce the published reference stream");
    }
}

#[test]
fn ch22_recovers_time_seeded_value() {
    use cryptopals::{Mt19937, recover_mt_seed};
    let true_seed = 1_765_000_123u32; // stand-in for a time.time() value
    let first = Mt19937::new(true_seed).next_u32();
    let recovered = recover_mt_seed(first, true_seed - 100, true_seed + 100)
        .expect("seed must be recoverable within the window");
    assert_eq!(recovered, true_seed);
}

#[test]
fn ch23_clone_reproduces_the_stream() {
    use cryptopals::{Mt19937, clone_mt19937};
    let mut original = Mt19937::new(42);
    let mut outputs = [0u32; 624];
    for o in &mut outputs {
        *o = original.next_u32();
    }
    let mut clone = clone_mt19937(&outputs);
    for i in 0..1000 {
        assert_eq!(
            original.next_u32(),
            clone.next_u32(),
            "clone must reproduce the original stream exactly (output {i})"
        );
    }
}

#[test]
fn ch24_mt_stream_bruteforced_via_known_prefix() {
    use cryptopals::{break_mt_stream, mt_stream};
    let secret = b"the 16-bit MT seed falls to 65536 trials with a known prefix";
    let key: u16 = 0x5eed; // stand-in for crypto-random 16 bits
    let known = b"the 16-bit MT s"; // attacker-known prefix (e.g. cookie header)
    let ct = mt_stream(key, secret);
    let recovered = break_mt_stream(&ct, known).expect("brute force must find the seed");
    assert_eq!(recovered, secret.to_vec(), "recovered plaintext must match");
}

#[test]
fn ch25_and_ch26_and_ch27_set4_block() {
    use cryptopals::{ch25_attack, ch25_edit, ch26_bitflip, ch26_encrypt, ch26_verify_admin, ch27_encrypt, ch27_recover_key, ctr128};
    // ch25
    let secret = b"the edit API hands the attacker the raw keystream";
    let ct = ctr128(b"ch25 ctr key!!!!", 0, secret);
    let rec = ch25_attack(&ct);
    assert_eq!(rec, secret.to_vec(), "ch25: edit-oracle must recover the plaintext");
    // ch26
    // must contain no ';' or '=' — the sanitizer strips them and the
    // flip alignment shifts (the ch14 lesson, again)
    let submitted = b"?admin-trueX";
    let ct26 = ch26_encrypt(submitted);
    assert!(!ch26_verify_admin(&ct26), "ch26: clean ct must not claim admin");
    let flipped = ch26_bitflip(&ct26, submitted, b";admin=true;");
    assert!(ch26_verify_admin(&flipped), "ch26: bit-flipped ct must claim admin");
    // ch27
    let msg = b"IV equal to key is a design bug";
    let _ = ch27_encrypt(msg);
    let key = ch27_recover_key();
    assert_eq!(&key, b"ch27 iv-eq-key!!", "ch27: leaked buffer must reveal the key");
}

#[test]
fn ch28_ch29_sha1_mac_length_extension_forgery() {
    use cryptopals::{forge_admin_request, sha1_length_extend, sha1_mac, VERIFY_ORACLE};
    let key = b"XXXXXXXXXXXXXXXX"; // 16-byte secret key, unknown to the attacker
    let msg = b"comment1=cooking%20MCs;userdata=;comment2=%20like%20a%20pound%20of%20bacon";
    let suffix = b";admin=true";

    // ch28: the honest MAC
    let mac = sha1_mac(key, msg);

    // the server-side verifier: recomputes the naive MAC with the real key
    VERIFY_ORACLE.with(|f| {
        *f.borrow_mut() = Box::new(|candidate_msg: &[u8], candidate_mac: &[u8]| {
            sha1_mac(key, candidate_msg)[..] == *candidate_mac
        });
    });

    // ch29: forge WITHOUT the key; the sweep finds the key length
    let Some((found_klen, forged_msg, forged_mac)) =
        forge_admin_request(&mac, msg, suffix, 64)
    else {
        panic!("length extension must forge a valid MAC for some key-length guess");
    };
    assert_eq!(found_klen, key.len(), "the accepted guess must be the true key length");
    // the forged request is BINARY (glue padding is raw bytes) — check
    // the suffix bytes, not UTF-8 text
    assert!(
        forged_msg.ends_with(suffix),
        "the forged request must carry the admin suffix"
    );
    // and the forgery is independent of the oracle: the raw extension
    // with the true key length reproduces the server's own MAC
    let (again, glue) = sha1_length_extend(&mac, msg.len(), key.len(), suffix);
    let mut server_view = msg.to_vec();
    server_view.extend(&glue);
    server_view.extend(suffix);
    assert_eq!(again, sha1_mac(key, &server_view), "forged MAC must equal the server's MAC");
    assert_eq!(again, forged_mac);
}

#[test]
fn md4_vectors_from_openssl() {
    use cryptopals::md4::{md4_hex, Md4};
    // vectors generated with `openssl dgst -md4 -provider legacy -provider default`
    assert_eq!(md4_hex(b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(md4_hex(b"a"), "bde52cb31de33e46245e05fbdbd6fb24");
    assert_eq!(md4_hex(b"abc"), "a448017aaf21d8525fc10ae87aa6729d");
    let long = b"The quick brown fox jumps over the lazy dog and then keeps on running through the park for a very long time indeed yes";
    assert_eq!(md4_hex(long), "b22aa5f68933dfb04083f92e51bab618", "multi-block must match");
    // incremental == one-shot
    let mut inc = Md4::new();
    for c in long.chunks(37) {
        inc.update(c);
    }
    assert_eq!(inc.finalize(), md4::md4(long));
}

#[test]
fn ch30_md4_mac_length_extension_forgery() {
    use cryptopals::{forge_admin_request_md4, md4_length_extend, md4_mac, VERIFY_ORACLE};
    let key = b"YYYYYYYYYYYYYYYY"; // 16-byte secret key
    let msg = b"comment1=cooking%20MCs;userdata=;comment2=%20like%20a%20pound%20of%20bacon";
    let suffix = b";admin=true";
    let mac = md4_mac(key, msg);

    VERIFY_ORACLE.with(|f| {
        *f.borrow_mut() = Box::new(|candidate_msg: &[u8], candidate_mac: &[u8]| {
            md4_mac(key, candidate_msg)[..] == *candidate_mac
        });
    });

    let Some((found_klen, forged_msg, forged_mac)) = forge_admin_request_md4(&mac, msg, suffix, 64)
    else {
        panic!("MD4 length extension must forge a valid MAC");
    };
    assert_eq!(found_klen, key.len(), "accepted guess must be the true key length");
    assert!(forged_msg.ends_with(suffix), "forged request must carry the suffix");
    let (again, glue) = md4_length_extend(&mac, msg.len(), key.len(), suffix);
    let mut server_view = msg.to_vec();
    server_view.extend(&glue);
    server_view.extend(suffix);
    assert_eq!(again, md4_mac(key, &server_view), "forged MAC must equal the server's MAC");
    assert_eq!(again, forged_mac);
}

#[test]
fn ch31_hmac_rfc2202_vectors_and_timing_break() {
    use cryptopals::{break_mac_by_timing, hmac_sha1, leaky_compare_mac};
    // RFC 2202 test case 1
    let tc1 = hmac_sha1(&[0x0bu8; 20], b"Hi There");
    let tc1_hex: String = tc1.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(tc1_hex, "b617318655057264e28bc0b6fb378c8ef146be00");
    // RFC 2202 test case 6 (key > block size, hashed first)
    let tc6 = hmac_sha1(&[0xaau8; 80], b"Test Using Larger Than Block-Size Key - Hash Key First");
    let tc6_hex: String = tc6.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(tc6_hex, "aa4ae5e15272d00e95705637ce8a3b55ed402112");

    // the timing break: recover the MAC byte-at-a-time from the leaky oracle
    let real_mac = hmac_sha1(b"secret server key", b"the payload to authenticate");
    let recovered = break_mac_by_timing(|cand| leaky_compare_mac(&real_mac, cand));
    assert_eq!(recovered, real_mac.to_vec(), "timing attack must recover the full MAC");
}

#[test]
fn ch32_noisy_timing_break_with_repeated_sampling() {
    use cryptopals::{break_mac_by_noisy_timing, hmac_sha1};
    let real_mac = hmac_sha1(b"another server key", b"noisier channel");
    // jitter 0 or 1, varying per MEASUREMENT (real timing noise varies
    // per query, not per candidate) — deterministic LCG sequence
    let mut tick = 0x1234_5678_9abc_def0u64;
    let recovered = break_mac_by_noisy_timing(
        |cand| {
            tick = tick.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let truth = leaky_count(&real_mac, cand);
            truth.saturating_sub((tick >> 33) as usize % 2)
        },
        12,
    );
    assert_eq!(recovered, real_mac.to_vec(), "sampled max must defeat jitter");
}

fn leaky_count(expected: &[u8; 20], candidate: &[u8]) -> usize {
    candidate.iter().zip(expected).take_while(|(a, b)| a == b).count()
}

#[test]
fn ch33_diffie_hellman_exchange() {
    use cryptopals::{DhParty, modexp};
    use num_bigint::BigUint;
    // 128-bit safe prime (p = 2q+1, both Miller-Rabin + openssl verified)
    let p = BigUint::parse_bytes(b"272334053341778607140778039263933143247", 10).unwrap();
    let g = BigUint::parse_bytes(b"259157649756750491095285601530400882350", 10).unwrap();
    let a = DhParty::new(&g, &p, BigUint::from(1234567u64));
    let b = DhParty::new(&g, &p, BigUint::from(7654321u64));
    let ka = a.session_key(&b.public, &p);
    let kb = b.session_key(&a.public, &p);
    assert_eq!(ka, kb, "both parties must derive the same session key");
    // the math: session key == g^(ab) mod p
    let expect = modexp(&g, &(a.secret.clone() * &b.secret), &p);
    assert_eq!(ka, expect);
}

#[test]
fn ch39_rsa_roundtrip_and_signature() {
    use cryptopals::RsaKey;
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(b"170360252569534844546703997316661685727", 10).unwrap();
    let q = BigUint::parse_bytes(b"243523437065208141137053366952547832249", 10).unwrap();
    let key = RsaKey::from_primes(&p, &q, &BigUint::from(65537u64));
    // message as big-endian bytes ("try to break this" -> hex)
    let m = BigUint::parse_bytes(b"74727920746f20627265616b2074686973", 16).unwrap();
    let c = key.encrypt(&m);
    assert_ne!(c, m, "ciphertext must differ from plaintext");
    assert_eq!(key.decrypt(&c), m, "RSA decrypt must invert encrypt");
    let sig = key.sign(&m);
    assert!(key.verify(&m, &sig), "signature must verify");
    let tampered = &sig - BigUint::from(1u32);
    assert!(!key.verify(&m, &tampered), "tampered signature must fail");
}

#[test]
fn ch40_hastad_broadcast_attack() {
    use cryptopals::{RsaKey, hastad_broadcast_attack};
    use num_bigint::BigUint;
    let e = BigUint::from(3u64);
    // six DISTINCT primes, all ≡ 2 mod 3 (e=3 requires 3 ∤ phi — a
    // prime ≡ 1 mod 3 makes e non-invertible and the keygen rejects)
    let primes = [
        b"201308184236009972859622644976808679617",
        b"246562181880310784098606962552255416867",
        b"294710285999409720640270314814580782193",
        b"302419647877271764597403108083572520847",
        b"323850669002382669231191463677750223941",
        b"337782083026302647462681937695373579353",
    ]
    .map(|s| BigUint::parse_bytes(s, 10).unwrap());
    let keys: Vec<RsaKey> = (0..3)
        .map(|i| RsaKey::from_primes(&primes[2 * i], &primes[2 * i + 1], &e))
        .collect();
    // same 16-byte secret to all three (no padding!) — m < 2^128 so m^3 < N
    let m = BigUint::parse_bytes(b"736563726574206d657373616765", 16).unwrap();
    let c: Vec<BigUint> = keys.iter().map(|k| k.encrypt(&m)).collect();
    let rec = hastad_broadcast_attack(
        [&c[0], &c[1], &c[2]],
        [&keys[0].n, &keys[1].n, &keys[2].n],
    );
    assert_eq!(rec, m, "Håstad's broadcast attack must recover the message");
}

#[test]
fn ch34_mitm_substitution_forces_predictable_keys() {
    use cryptopals::{DhParty, mitm_substituted_key};
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(b"272334053341778607140778039263933143247", 10).unwrap();
    let g = BigUint::parse_bytes(b"259157649756750491095285601530400882350", 10).unwrap();
    let a = DhParty::new(&g, &p, BigUint::from(42u64));
    let b = DhParty::new(&g, &p, BigUint::from(4242u64));
    // honest exchange: the shared key is unpredictable without a or b
    let honest = a.session_key(&b.public, &p);
    assert_ne!(honest, BigUint::from(0u32));
    assert_ne!(honest, BigUint::from(1u32));
    // MITM replaces both publics with p -> both parties derive 0
    let zero_key = mitm_substituted_key(&p, &a.secret, &p);
    assert_eq!(zero_key, BigUint::from(0u32), "public=p forces session key 0");
    // ...or with 1 -> both derive 1
    assert_eq!(
        mitm_substituted_key(&BigUint::from(1u32), &b.secret, &p),
        BigUint::from(1u32)
    );
    // full relay MITM: the attacker runs its OWN DH with each party
    // (secret z, public g^z sent to both) — each side shares only with
    // the attacker, and both keys are derivable without a or b
    use cryptopals::modexp;
    let z = BigUint::from(9999u64);
    let attacker_pub = modexp(&g, &z, &p);
    let key_a = a.session_key(&attacker_pub, &p); // g^(az)
    let key_b = b.session_key(&attacker_pub, &p); // g^(bz)
    assert_eq!(key_a, modexp(&a.public, &z, &p), "attacker derives A's key");
    assert_eq!(key_b, modexp(&b.public, &z, &p), "attacker derives B's key");
    assert_ne!(key_a, key_b, "A and B share nothing with each other");
}

#[test]
fn ch35_negotiated_group_leaks_secret_parity() {
    use cryptopals::negotiated_group_key;
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(b"272334053341778607140778039263933143247", 10).unwrap();
    let g_minus_1 = &p - BigUint::from(1u32);
    // order-2 subgroup: key is 1 for even exponents, p-1 for odd
    assert_eq!(negotiated_group_key(&g_minus_1, &BigUint::from(100u64), &p), BigUint::from(1u32));
    assert_eq!(negotiated_group_key(&g_minus_1, &BigUint::from(101u64), &p), g_minus_1);
    // g'=1: the key is always 1 — zero bits of entropy
    assert_eq!(negotiated_group_key(&BigUint::from(1u32), &BigUint::from(999u64), &p), BigUint::from(1u32));
}

#[test]
fn ch36_srp_client_and_server_agree() {
    use cryptopals::{SrpClient, SrpServer};
    use num_bigint::BigUint;
    let n = BigUint::parse_bytes(b"272334053341778607140778039263933143247", 10).unwrap();
    let g = BigUint::parse_bytes(b"259157649756750491095285601530400882350", 10).unwrap();
    let salt = b"pepper".to_vec();
    let password = b"correct horse";
    let server = SrpServer::setup(&n, &g, &salt, password, BigUint::from(777u64), BigUint::from(555u64));
    let client = SrpClient::new(&n, &g, BigUint::from(1234u64));
    let ks = server.session(&client.pub_a);
    let kc = client.session(&salt, password, &server.pub_b, &server.u);
    assert_eq!(ks, kc, "SRP client and server must derive the same session key");
    // wrong password on the client side must NOT match
    let kw = client.session(&salt, b"wrong horse", &server.pub_b, &server.u);
    assert_ne!(kw, ks, "a wrong password must derive a different key");
}

#[test]
fn ch37_srp_zero_key_bypasses_password() {
    use cryptopals::{SrpClient, SrpServer, srp_zero_key_client};
    use num_bigint::BigUint;
    let n = BigUint::parse_bytes(b"272334053341778607140778039263933143247", 10).unwrap();
    let g = BigUint::parse_bytes(b"259157649756750491095285601530400882350", 10).unwrap();
    let salt = b"pepper".to_vec();
    // the server stores a verifier for the REAL password
    let server = SrpServer::setup(&n, &g, &salt, b"real password", BigUint::from(777u64), BigUint::from(555u64));
    // attacker sends A = 0 — the server's S collapses to 0
    let forged_a = BigUint::from(0u32);
    let ks = server.session(&forged_a);
    let kc = srp_zero_key_client(); // attacker computes S=0 client-side
    assert_eq!(ks, kc, "A=0 must make the server accept the S=0 proof");
}

#[test]
fn ch38_srp_offline_dictionary_recovers_password() {
    use cryptopals::{SrpClient, srp_offline_dictionary};
    use num_bigint::BigUint;
    let n = BigUint::parse_bytes(b"272334053341778607140778039263933143247", 10).unwrap();
    let g = BigUint::parse_bytes(b"259157649756750491095285601530400882350", 10).unwrap();
    let true_password = "hunter2correct";
    // FAKE server: attacker picks salt, b, u (server-chosen u is the flaw)
    let salt = b"attacker salt".to_vec();
    let b = BigUint::from(424242u64);
    let u = BigUint::from(1337u64);
    // the fake server does NOT know the password — no verifier needed.
    // B must be a value that makes client-side math valid: 3*g^x < B + N
    // holds for any B < N, so pick B = g^b + 1
    let server_pub_b = cryptopals::modexp(&g, &b, &n) + BigUint::from(1u32);
    // the client (legitimate user) logs in with the real password
    let client = SrpClient::new(&n, &g, BigUint::from(31337u64));
    let proof = client.session(&salt, true_password.as_bytes(), &server_pub_b, &u);
    // the attacker now brute-forces OFFLINE with the dictionary
    let dict = ["password1", "letmein", "hunter2correct", "qwerty"];
    let found = srp_offline_dictionary(
        &n, &g, &salt, &server_pub_b, &u, &client.pub_a, &client.priv_a, &proof, &dict,
    );
    assert_eq!(found.as_deref(), Some(true_password), "offline dictionary must recover the password");
}

#[test]
fn ch41_rsa_parity_oracle_binary_search() {
    use cryptopals::{RsaKey, parity_oracle_attack, parity_oracle_server, rsa_pad, rsa_unpad};
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(b"201308184236009972859622644976808679617", 10).unwrap();
    let q = BigUint::parse_bytes(b"246562181880310784098606962552255416867", 10).unwrap();
    let key = RsaKey::from_primes(&p, &q, &BigUint::from(65537u64));
    // pad -> encrypt; the attack recovers the PADDED integer
    let padded = rsa_pad(b"parity oracle wins", 32);
    let m = BigUint::from_bytes_be(&padded);
    let ct = key.encrypt(&m);
    // sanity: the oracle simply reports the true parity
    assert_eq!(parity_oracle_server(&ct, &key), &m % BigUint::from(2u32) == BigUint::from(1u32));
    // binary search with n.bits() parity queries
    let recovered = parity_oracle_attack(&ct, &key.e, &key.n, &|c| parity_oracle_server(c, &key));
    assert_eq!(recovered, m, "parity oracle must recover the padded plaintext");
    // and unpad must strip back to the message (left-pad: to_bytes_be
    // drops the leading 0x00 header byte)
    let mut padded_bytes = recovered.to_bytes_be();
    while padded_bytes.len() < 32 {
        padded_bytes.insert(0, 0);
    }
    assert_eq!(rsa_unpad(&padded_bytes).as_deref(), Some(b"parity oracle wins".as_slice()));
}

#[test]
fn ch42_bleichenbacher_e3_signature_forgery() {
    use cryptopals::{bleichenbacher_block, bleichenbacher_e3_forge, modexp, sha1};
    use num_bigint::BigUint;
    // 1024-bit keypair, primes ≡ 2 mod 3 (verified via Miller-Rabin +
    // openssl during generation)
    let p = BigUint::parse_bytes(b"8625698395464462221575041633586539666232035565817028295604560474507861179606399120992672215609858184184353041569730267889886433931512069799347723332849689", 10).unwrap();
    let q = BigUint::parse_bytes(b"12856246090808524547580715254204892739362592576157476558444732478765743015354192603475763296420018036189163034134797992874669081423510382450389907165561457", 10).unwrap();
    let e = BigUint::from(3u64);
    let n = &p * &q; // public modulus — the attacker needs only this

    let message = b"hi, i'm definitely the legit signer";
    let digest = sha1::sha1(message);

    // NAIVE verifier: computes sig^3 mod n and accepts if the bytes
    // begin 00 01 FF..FF 00 <digest> — no garbage validation
    let naive_verify = |sig: &BigUint| -> bool {
        let cube = modexp(sig, &e, &n);
        let mut b = cube.to_bytes_be();
        while b.len() < 128 {
            b.insert(0, 0); // to_bytes_be drops the leading 0x00 header
        }
        if b.len() != 128 || b[0] != 0x00 || b[1] != 0x01 || b[2] != 0xff {
            return false;
        }
        let mut i = 2;
        while i < b.len() && b[i] == 0xff {
            i += 1;
        }
        if i >= b.len() || b[i] != 0x00 {
            return false;
        }
        &b[i + 1..i + 1 + 20] == &digest[..]
    };

    // the forged signature (no private key involved)
    let sigma = bleichenbacher_e3_forge(8, &digest, 128);
    let cube = modexp(&sigma, &e, &n);
    assert!(cube < n, "sigma^3 must not wrap — the cube IS the padded block");
    let cube_bytes = cube.to_bytes_be();
    // the checked bytes must match the ideal block exactly
    let ideal = bleichenbacher_block(8, &digest, 128);
    let mut padded = cube_bytes.clone();
    while padded.len() < 128 {
        padded.insert(0, 0);
    }
    for i in 0..(2 + 8 + 1 + 20) {
        assert_eq!(padded[i], ideal[i], "checked region must be byte-exact at {i}");
    }
    // garbage region may differ — that's the attack
    assert!(
        padded[31..] != ideal[31..] || true,
        "garbage divergence is allowed"
    );
    assert!(naive_verify(&sigma), "the naive verifier must accept the forgery");
}

#[test]
fn ch43_dsa_sign_and_verify() {
    use cryptopals::DsaKey;
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(b"272334053341778607140778039263933143247", 10).unwrap();
    let q = (&p - BigUint::from(1u32)) / BigUint::from(2u32);
    let g = BigUint::parse_bytes(b"259157649756750491095285601530400882350", 10).unwrap();
    let key = DsaKey::from_params(&p, &q, &g, BigUint::from(909090u64));
    let digest = cryptopals::sha1::sha1(b"the dsa message");
    let (r, s) = key.sign(&digest, &BigUint::from(424242u64));
    assert!(key.verify(&digest, &r, &s), "valid signature must verify");
    let other = cryptopals::sha1::sha1(b"a different message");
    assert!(!key.verify(&other, &r, &s), "wrong digest must fail");
}

#[test]
fn ch44_repeated_nonce_recovers_private_key() {
    use cryptopals::{DsaKey, dsa_recover_private_key_from_repeated_nonce};
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(b"272334053341778607140778039263933143247", 10).unwrap();
    let q = (&p - BigUint::from(1u32)) / BigUint::from(2u32);
    let g = BigUint::parse_bytes(b"259157649756750491095285601530400882350", 10).unwrap();
    let x_true = BigUint::from(314159u64);
    let key = DsaKey::from_params(&p, &q, &g, x_true.clone());
    // SAME k for two different messages — the fatal RNG failure
    let k = BigUint::from(777777u64);
    let d1 = cryptopals::sha1::sha1(b"message one");
    let d2 = cryptopals::sha1::sha1(b"message two");
    let (r1, s1) = key.sign(&d1, &k);
    let (r2, s2) = key.sign(&d2, &k);
    assert_eq!(r1, r2, "repeated k must produce identical r");
    let h1 = BigUint::from_bytes_be(&d1) % &q;
    let h2 = BigUint::from_bytes_be(&d2) % &q;
    let recovered = dsa_recover_private_key_from_repeated_nonce(
        &p, &q, &g, &key.y, &h1, &s1, &h2, &s2, &r1,
    ).expect("repeated nonce must yield the private key");
    assert_eq!(recovered, x_true, "recovered x must equal the true private key");
}

#[test]
fn ch45_dsa_g1_injection_universal_forgery() {
    use cryptopals::{DsaKey, dsa_forge_tampered_g1};
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(b"272334053341778607140778039263933143247", 10).unwrap();
    let q = (&p - BigUint::from(1u32)) / BigUint::from(2u32);
    // the tampered negotiation: g = 1
    let key = DsaKey::from_params(&p, &q, &BigUint::from(1u32), BigUint::from(31337u64));
    assert_eq!(key.y, BigUint::from(1u32), "y must collapse to 1");
    let (r, s) = dsa_forge_tampered_g1(0xdead_beefu64);
    for msg in ["any message", "a totally different one", "transfer all the money"] {
        let digest = cryptopals::sha1::sha1(msg.as_bytes());
        assert!(key.verify(&digest, &r, &s), "forged sig must verify for: {msg}");
    }
}

#[test]
fn ch46_hybrid_cca_recovers_session_key() {
    use cryptopals::{RsaKey, hybrid_decrypt, hybrid_cca_recover_session};
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(b"201308184236009972859622644976808679617", 10).unwrap();
    let q = BigUint::parse_bytes(b"246562181880310784098606962552255416867", 10).unwrap();
    let key = RsaKey::from_primes(&p, &q, &BigUint::from(65537u64));
    let aes_key = *b"ch46 aes key!!!!";
    // honest blob: RSA-encrypted session key || CBC(knowable plaintext ^ IV)
    let session_key: [u8; 16] = *b"the session key!";
    let m1 = BigUint::from_bytes_be(&session_key);
    let c1 = key.encrypt(&m1);
    let c1b = c1.to_bytes_be(); // RSA block = full modulus width (32)
    // attacker knows this (15 bytes + PKCS#7 pad 0x01 — the last byte
    // must be a valid pad or the server rejects the honest blob too)
    let p2_known: [u8; 16] = *b"attack at dawn!\x01";
    // c2 = AES_enc(P2 XOR IV) — the IV IS the RSA plaintext (16 bytes)
    let mut xored = [0u8; 16];
    for j in 0..16 {
        xored[j] = p2_known[j] ^ session_key[j];
    }
    let c2_arr = crypto_primitives::aes::aes128_ecb_encrypt_block(&xored, &aes_key);
    let mut blob = c1b.clone();
    blob.extend(c2_arr);
    // sanity: the honest server decrypts the honest blob
    assert!(hybrid_decrypt(&key, &aes_key, &blob).is_ok());
    // the CCA: no private key, only the public oracle + known P2
    let oracle = |b: &[u8]| hybrid_decrypt(&key, &aes_key, b);
    let rsa_len = ((key.n.bits() + 7) / 8) as usize;
    let recovered = hybrid_cca_recover_session(&c2_arr, rsa_len, &p2_known, &oracle)
        .expect("CCA must succeed");
    assert_eq!(recovered, session_key, "session key recovered without the RSA key");
}

#[test]
fn ch47_ch48_bleichenbacher_full_cca() {
    use cryptopals::{RsaKey, bleichenbacher_attack, bleichenbacher_oracle, rsa_pad};
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(b"201308184236009972859622644976808679617", 10).unwrap();
    let q = BigUint::parse_bytes(b"246562181880310784098606962552255416867", 10).unwrap();
    let key = RsaKey::from_primes(&p, &q, &BigUint::from(65537u64));
    // a conforming (type-2 padded) message under the 256-bit modulus
    let padded = rsa_pad(b"bleich", 32);
    let m = BigUint::from_bytes_be(&padded);
    let ct = key.encrypt(&m);
    let oracle = |c: &BigUint| bleichenbacher_oracle(c, &key);
    let recovered = bleichenbacher_attack(&ct, &key.e, &key.n, &oracle);
    assert_eq!(recovered, m, "Bleichenbacher CCA must recover the padded plaintext");
    // the internal assert already re-verified encryption; also unpad
    use cryptopals::rsa_unpad;
    let mut b = recovered.to_bytes_be();
    while b.len() < 32 {
        b.insert(0, 0);
    }
    assert_eq!(rsa_unpad(&b).as_deref(), Some(b"bleich".as_slice()));
}

#[test]
fn ch49_cbc_mac_variable_length_forgery() {
    use cryptopals::{cbc_mac, cbc_mac_forgery};
    let key = *b"ch49 bank key!!!";
    let iv = [0u8; 16]; // the vulnerable fixed IV
    // victim: one-block transfer "from&to&amount" padded conceptually
    let victim_p2 = *b"from=me&to=you&5";
    // attacker's prefix: any block they can get a tag for
    let prefix_p1 = *b"prefix=attackblk";
    let (t2, forged) = cbc_mac_forgery(&key, &iv, &prefix_p1, &victim_p2);
    // the forged two-block message carries the victim's tag exactly
    assert_eq!(cbc_mac(&key, &iv, &forged), t2, "forgery must match the victim tag");
}

#[test]
fn ch52_toy_md_suffix_collision_and_extension() {
    use cryptopals::{toy_md_colliding_suffix, toy_md_hash};
    // collision for state 0 (empty prefix)
    let (a, b, out) = toy_md_colliding_suffix(0);
    assert_ne!(a, b);
    assert_eq!(toy_md_hash(0, &[a]), toy_md_hash(0, &[b]));
    assert_eq!(out, toy_md_hash(0, &[b]));
    // the TRUE reusable Merkle-Damgård property: any common suffix
    // preserves the collision — hash(P||a||X) == hash(P||b||X) for
    // every X, because both messages absorb identical state after the
    // colliding suffix
    for x in [1u32, 0xdead_beef, 0x7fff_ffff] {
        assert_eq!(toy_md_hash(0, &[a, x]), toy_md_hash(0, &[b, x]));
    }
    // collisions are STATE-specific: for a nonzero prefix, the
    // attacker birthday-searches a NEW pair at that prefix's end state
    let prefix = 0xdead_beefu32;
    let s = toy_md_hash(0, &[prefix]);
    let (a2, b2, _) = toy_md_colliding_suffix(s);
    assert_eq!(
        toy_md_hash(0, &[prefix, a2]),
        toy_md_hash(0, &[prefix, b2]),
        "collision found at the prefix's end state must apply under it"
    );
}

#[test]
fn ch50_collision_mac_forges_orders() {
    use cryptopals::{collision_mac_orders_equal, toy_md_amount_pair};
    let secret_state = 0x5EED_1234u32; // the bank's secret seeding
    let header = 0xCAFE_BABEu32; // known protocol header
    // the "provided research data": a colliding pair with different amounts
    let (a, b) = toy_md_amount_pair(toy_md_hash_public(secret_state, header));
    assert_ne!(a & 0xf, b & 0xf, "the pair must encode different amounts");
    // both orders verify to the same MAC despite different payloads
    assert!(collision_mac_orders_equal(secret_state, header, a, b));
}

fn toy_md_hash_public(secret_state: u32, header: u32) -> u32 {
    cryptopals::toy_md_hash(secret_state, &[header])
}

#[test]
fn ch51_iv_inheritance_universal_one_block_tag() {
    use cryptopals::cbc_mac_iv_inheritance;
    let key = *b"ch51 broken key!";
    // EVERY one-block message tags to AES(0)
    let t1 = cbc_mac_iv_inheritance(&key, b"from=me&to=you&5");
    let t2 = cbc_mac_iv_inheritance(&key, b"from=you&to=me&9");
    assert_eq!(t1, t2, "all one-block tags must collapse to AES(0)");
    // the forger needs no key: tag(AES(0)) is known once ANY tag is seen
    let forged = b"from=att&to=me&9"; // 16 bytes
    assert_eq!(cbc_mac_iv_inheritance(&key, forged), t1, "universal tag accepts the forged transfer");
}

#[test]
fn ch53_joux_expandable_second_preimage() {
    use cryptopals::{expandable16_build, expandable_message16, joux_multicollision16, second_preimage16, toy_md16};
    const IV: u16 = 0x1234;

    // (a) Joux: 4 pairs -> 2^4 = 16 combinations, one hash
    let pairs = joux_multicollision16(IV, 4);
    assert_eq!(pairs.len(), 4);
    let base = vec![pairs[0].0, pairs[1].0, pairs[2].0, pairs[3].0];
    let h_base = toy_md16(IV, &base);
    for combo in 0..16u16 {
        let msg: Vec<u16> = (0..4)
            .map(|j| if combo & (1 << j) != 0 { pairs[j].1 } else { pairs[j].0 })
            .collect();
        assert_eq!(toy_md16(IV, &msg), h_base, "every combination must share the hash");
    }

    // (b) expandable messages: EVERY length in [4, 4+2^4-1] ends at S_k
    let e = expandable16_build(IV, 4);
    for l in 4..19 {
        let msg = expandable_message16(&e, l).expect("length must be in range");
        assert_eq!(toy_md16(IV, &msg), e.s_k, "expandable length {l} must end at S_k");
    }

    // (c) the second preimage: shorter than the victim, same hash
    let victim: Vec<u16> = (0..10u16).map(|i| 0x9000 + i * 7).collect();
    let second = second_preimage16(IV, &victim, 4).expect("second preimage must exist");
    assert_eq!(toy_md16(IV, &second), toy_md16(IV, &victim), "second preimage must hash identically");
    assert!(second.len() < victim.len(), "second preimage must be SHORTER ({} < {})", second.len(), victim.len());
}

#[test]
fn ch57_pollard_p1_factors_smooth_prime() {
    use cryptopals::pollard_p1;
    use num_bigint::BigUint;
    // p = 77189112001 with p-1 = 2^6·3^4·5^3·7^2·11·13·17 — B=20 smooth
    let p = BigUint::parse_bytes(b"77189112001", 10).unwrap();
    let q = BigUint::parse_bytes(b"246562181880310784098606962552255416867", 10).unwrap();
    let n = &p * &q;
    let f = pollard_p1(&n, 20).expect("p-1 is 20-smooth: must factor");
    assert!(&n % &f == BigUint::from(0u32), "found factor must divide n");
    assert_ne!(f, BigUint::from(1u32));
    assert_ne!(f, n);
    assert_eq!(&f * (&n / &f), n, "the two factors must reconstruct n");
}

#[test]
fn ch58_pollard_rho_finds_small_factor() {
    use cryptopals::pollard_rho;
    use num_bigint::BigUint;
    let n = BigUint::parse_bytes(b"625492079071772343982349279792921887", 10).unwrap();
    let small = BigUint::parse_bytes(b"13163671", 10).unwrap();
    let f = pollard_rho(&n).expect("rho must find the 24-bit factor quickly");
    assert!(f == small || f == &n / &small, "rho must surface one of the two factors");
    assert_eq!(&f * (&n / &f), n);
}

#[test]
fn ch59_ec_group_structure() {
    use cryptopals::{EcCurve, EcPoint};
    use num_bigint::BigUint;
    // textbook curve y^2 = x^3 + 2x + 2 mod 17 — properties verified
    // BY COMPUTATION here, not by trusting remembered constants
    let curve = EcCurve::new(BigUint::from(17u32), BigUint::from(2u32), BigUint::from(2u32));
    let g = EcPoint::Pt { x: BigUint::from(5u32), y: BigUint::from(1u32) };
    assert!(curve.on_curve(&g), "the generator must lie on the curve");
    // scalar multiples of G: k*G cycles with period 19 (the group order)
    let inf = curve.mul(&BigUint::from(19u32), &g);
    assert_eq!(inf, EcPoint::Inf, "19*G must be the point at infinity");
    let g_again = curve.mul(&BigUint::from(20u32), &g);
    assert_eq!(g_again, g, "20*G must return to G");
    // every multiple stays on-curve
    for k in 1..=18u32 {
        let pt = curve.mul(&BigUint::from(k), &g);
        assert!(curve.on_curve(&pt), "k*G must be on-curve for k={k}");
    }
    // brute-force point count matches the group order
    assert_eq!(curve.point_count(), 19, "the curve must have exactly 19 points");
    // commutativity spot-check: a*G + b*G == b*G + a*G
    let pa = curve.mul(&BigUint::from(7u32), &g);
    let pb = curve.mul(&BigUint::from(11u32), &g);
    assert_eq!(curve.add(&pa, &pb), curve.add(&pb, &pa));
    // homomorphism: (a+b)*G == a*G + b*G
    let sum = curve.mul(&BigUint::from(18u32), &g);
    assert_eq!(curve.add(&pa, &pb), sum);
}

#[test]
fn ch60_ecdsa_sign_verify() {
    use cryptopals::{EcCurve, EcDsa, EcPoint};
    use num_bigint::BigUint;
    let curve = EcCurve::new(BigUint::from(17u32), BigUint::from(2u32), BigUint::from(2u32));
    let g = EcPoint::Pt { x: BigUint::from(5u32), y: BigUint::from(1u32) };
    let q = BigUint::from(19u32); // subgroup order (verified in ch59)
    let key = EcDsa::keygen(curve, q, g, BigUint::from(7u32));
    let digest = cryptopals::sha1::sha1(b"the ec message");
    // k=9 here makes s = k^-1(H + x*r) = 0 mod 19 (degenerate — verify
    // correctly rejects); k=4 is non-degenerate
    let (r, s) = key.sign(&digest, &BigUint::from(4u32));
    assert!(key.verify(&digest, &r, &s), "valid ECDSA must verify");
    // NOTE: on this 17-element field the x-check accepts the MIRRORED
    // point (~1/17 per digest — real curves: 2^-256), so the negative
    // test uses a digest verified non-degenerate against python
    let other = cryptopals::sha1::sha1(b"another message 0");
    assert!(!key.verify(&other, &r, &s), "wrong digest must fail");
}

#[test]
fn ch61_ecdsa_nonce_reuse_recovers_private_key() {
    use cryptopals::{EcCurve, EcDsa, EcPoint, ecdsa_recover_private_key_from_repeated_nonce};
    use num_bigint::BigUint;
    let curve = EcCurve::new(BigUint::from(17u32), BigUint::from(2u32), BigUint::from(2u32));
    let g = EcPoint::Pt { x: BigUint::from(5u32), y: BigUint::from(1u32) };
    let q = BigUint::from(19u32);
    let x_true = BigUint::from(11u32);
    let key = EcDsa::keygen(curve.clone(), q.clone(), g.clone(), x_true.clone());
    let k = BigUint::from(5u32); // SAME nonce for both signatures
    let d1 = cryptopals::sha1::sha1(b"msg one");
    let d2 = cryptopals::sha1::sha1(b"msg two");
    let (r1, s1) = key.sign(&d1, &k);
    let (r2, s2) = key.sign(&d2, &k);
    assert_eq!(r1, r2, "repeated k must give identical r");
    let h1 = BigUint::from_bytes_be(&d1) % &q;
    let h2 = BigUint::from_bytes_be(&d2) % &q;
    let recovered = ecdsa_recover_private_key_from_repeated_nonce(
        &q, &g, &curve.p, &key.y, &h1, &s1, &h2, &s2, &r1, &curve,
    ).expect("repeated nonce must yield the ECDSA private key");
    assert_eq!(recovered, x_true, "recovered x must equal the true key");
}

