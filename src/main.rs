use cryptopals::*;

fn main() {
    // Challenge 1: hex -> base64
    let raw = hex_decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    println!("ch1: {}", base64_encode(&raw));
    // Challenge 2: fixed XOR
    let x = hex_decode("1c0111001f010100061a024b53535009181c");
    let y = hex_decode("686974207468652062756c6c277320657965");
    println!("ch2: {}", hex_encode(&xor(&x, &y)));
    // Challenge 3: single-byte XOR
    let c = hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let (k, score, dec) = single_byte_xor_best(&c);
    println!("ch3: key=0x{k:02x} score={score} plain={}", String::from_utf8_lossy(&dec));
}
