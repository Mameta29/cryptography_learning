extern crate base64;
extern crate rand;
extern crate rsa;

use base64::{decode, encode};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

fn main() {
    // 1. 鍵の生成
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    // 公開鍵と秘密鍵を表示
    println!("Private Key: {:?}", private_key);
    println!("Public Key: {:?}", public_key);

    // 2. メッセージの暗号化
    let message = "Hello, RSA!";
    print!("-----------------------------------------------\n");
    println!("Original message: {}", message);
    let encrypted_data = public_key
        .encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &message.as_bytes(),
        )
        .expect("Failed to encrypt");

    // 暗号文をBase64でエンコードして表示
    let encoded_encrypted_data = encode(&encrypted_data);
    println!("Encrypted message: {}", encoded_encrypted_data);

    // 3. 暗号文の復号化
    let decoded_encrypted_data = decode(&encoded_encrypted_data).expect("Failed to decode base64");
    let decrypted_data = private_key
        .decrypt(
            PaddingScheme::new_pkcs1v15_encrypt(),
            &decoded_encrypted_data,
        )
        .expect("Failed to decrypt");

    // 復号化されたメッセージを表示
    let decrypted_message = String::from_utf8(decrypted_data).expect("Failed to convert to string");
    println!("Decrypted message: {}", decrypted_message);
}
