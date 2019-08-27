
use crypto::aessafe::*;
use crypto::blockmodes::*;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer, symmetriccipher};
use rand::{OsRng, Rng};
use std::str;
use std::{thread, time};
fn main() {
    let sleep_seconds = time::Duration::from_secs(1000);
    let message = "I love Rust,Julia & Python, they are so cool! ";

    // let mut key: [u8; 32] = [0; 32];
    // let mut iv: [u8; 16] = [0; 16];

    // let mut rng = OsRng::new().ok().unwrap();
    // rng.fill_bytes(&mut key);
    // rng.fill_bytes(&mut iv);
    // println!("key:{:?}", key);
    // println!("iv:{:?}", iv);
    let key = "ABCDEFGHIJKLMNOPQRWTUVWXYZSHAIPE".as_bytes();
    // let iv = [
    // 0x41, 0x72, 0x65, 0x79, 0x6F, 0x75, 0x6D, 0x79, 0x53, 0x6E, 0x6F, 0x77, 0x6D, 0x61, 0x6E,
    // 0x3F,
    // ];
    let iv = [
        65, 114, 101, 121, 111, 117, 109, 121, 83, 110, 111, 119, 109, 97, 110, 63,
    ];

    //aes 加密
    let encrypted_data = aes256_cbc_encrypt(message.as_bytes(), &key, &iv)
        .ok()
        .unwrap();

    //编码成base64
    let mut base64_encode = String::new();
    base64::encode_config_buf(&encrypted_data, base64::STANDARD, &mut base64_encode);

    let mut base64_decode = Vec::<u8>::new();
    base64::decode_config_buf(&base64_encode, base64::STANDARD, &mut base64_decode).unwrap();
    println!(
        "base64_encode={:?}base64_decode={:?}",
        base64_encode, base64_decode
    );
    // aes 解码
    let decrypted_data = aes256_cbc_decrypt(&base64_decode[..], &key, &iv)
        .ok()
        .unwrap();
    //转换成string
    let the_string = str::from_utf8(&decrypted_data).expect("not UTF-8");
    println!("decrypted_data={:?}", the_string);

    thread::sleep(sleep_seconds);
}
pub fn aes_cbc_mode() {
    let message = "Hello World!";

    let mut key: [u8; 32] = [0; 32];
    let mut iv: [u8; 16] = [0; 16];

    // In a real program, the key and iv may be determined
    // using some other mechanism. If a password is to be used
    // as a key, an algorithm like PBKDF2, Bcrypt, or Scrypt (all
    // supported by Rust-Crypto!) would be a good choice to derive
    // a password. For the purposes of this example, the key and
    // iv are just random values.
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    let encrypted_data = aes256_cbc_encrypt(message.as_bytes(), &key, &iv)
        .ok()
        .unwrap();
    let decrypted_data = aes256_cbc_decrypt(&encrypted_data[..], &key, &iv)
        .ok()
        .unwrap();

    let crypt_message = str::from_utf8(decrypted_data.as_slice()).unwrap();
    let crypt_encrypty = str::from_utf8(encrypted_data.as_slice()).unwrap();
    assert_eq!(message, crypt_message);
    println!("{},crypt_encrypty={:?}", crypt_message, crypt_encrypty);
}

// Encrypt a buffer with the given key and iv using AES-256/CBC/Pkcs encryption.
fn aes256_cbc_encrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = (encryptor.encrypt(&mut read_buffer, &mut write_buffer, true))?;

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

// Decrypts a buffer with the given key and iv using AES-256/CBC/Pkcs encryption.
fn aes256_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = (decryptor.decrypt(&mut read_buffer, &mut write_buffer, true))?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}
