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
