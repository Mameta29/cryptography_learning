extern crate base64;
extern crate rand;
extern crate rsa;
extern crate sha2;

use base64::{decode, encode};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

fn main() {
    // 1. 鍵の生成
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    // 公開鍵と秘密鍵を表示
    println!("Private Key: {:?}", private_key);
    println!("Public Key: {:?}", public_key);

    // 2. メッセージのハッシュ値の計算
    let message = "Hello, RSA!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hashed = hasher.finalize();

    // 3. 署名の生成
    let signature = private_key
        .sign(
            PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256)),
            &hashed,
        )
        .expect("Failed to sign");

    // 署名をBase64でエンコードして表示
    let encoded_signature = encode(&signature);
    println!("Signature: {}", encoded_signature);

    // 4. 署名の検証
    let decoded_signature = decode(&encoded_signature).expect("Failed to decode base64");
    match public_key.verify(
        PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256)),
        &hashed,
        &decoded_signature,
    ) {
        Ok(_) => println!("Signature is valid."),
        Err(_) => println!("Signature is invalid."),
    }
}
