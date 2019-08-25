use std::str;
use rand::{OsRng, Rng};
use crypto::buffer::{ReadBuffer,WriteBuffer,BufferResult};
use crypto::{symmetriccipher,buffer,aes,blockmodes};
use crypto::aessafe::*;
use crypto::blockmodes::*;
use crypto::symmetriccipher::*;
extern crate base64;
use std::{thread, time};
fn main() {
    let sleep_seconds = time::Duration::from_secs(1000);
    let message = "I love Rust,Julia & Python, they are so cool! ";

    let mut key: [u8; 32] = [0; 32];
    let mut iv: [u8; 16] = [0; 16];

    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);
    println!("key:{:?}", key);
    println!("iv:{:?}", iv);

    let encrypted_data = aes256_cbc_encrypt(message.as_bytes(), &key, &iv).ok().unwrap();
  
    let message_bytes = message.as_bytes();
    println!(
        "message->as_bytes:{:?}, byte_len:{}",
        message_bytes,
        message_bytes.len()
    );
    println!(
        "message->encrypted:{:?} byte_len:{}",
        encrypted_data,
        encrypted_data.len()
    );

    let decrypted_data = aes256_cbc_decrypt(&encrypted_data[..], &key, &iv).ok().unwrap();


    let the_string = str::from_utf8(&decrypted_data).expect("not UTF-8");

    assert!(message_bytes == &decrypted_data[..]);

    assert!(message == the_string);

    println!("the_string:{:?}", the_string);
      let mut buf = String::new();
    base64::encode_config_buf(encrypted_data, base64::STANDARD, &mut buf);
    let mut buffer = Vec::<u8>::new();
    base64::decode_config_buf(buf, base64::STANDARD, &mut buffer).unwrap();
    println!("{:?}", buffer);

    buffer.clear();



    thread::sleep(sleep_seconds);
}
pub fn aes_cbc_mode(){
    let message="Hello World!";

    let mut key:[u8;32]=[0;32];
    let mut iv:[u8;16]=[0;16];

    // In a real program, the key and iv may be determined
    // using some other mechanism. If a password is to be used
    // as a key, an algorithm like PBKDF2, Bcrypt, or Scrypt (all
    // supported by Rust-Crypto!) would be a good choice to derive
    // a password. For the purposes of this example, the key and
    // iv are just random values.
    let mut rng=OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    let encrypted_data=aes256_cbc_encrypt(message.as_bytes(),&key,&iv).ok().unwrap();
    let decrypted_data=aes256_cbc_decrypt(&encrypted_data[..],&key,&iv).ok().unwrap();

    let crypt_message=str::from_utf8(decrypted_data.as_slice()).unwrap();
    let crypt_encrypty=str::from_utf8(encrypted_data.as_slice()).unwrap();
    assert_eq!(message,crypt_message);
    println!("{},crypt_encrypty={:?}",crypt_message,crypt_encrypty);
}

// Encrypt a buffer with the given key and iv using AES-256/CBC/Pkcs encryption.
fn aes256_cbc_encrypt(data: &[u8],key: &[u8], iv: &[u8])->Result<Vec<u8>,symmetriccipher::SymmetricCipherError>{
    let mut encryptor=aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding);

    let mut final_result=Vec::<u8>::new();
    let mut read_buffer=buffer::RefReadBuffer::new(data);
    let mut buffer=[0;4096];
    let mut write_buffer=buffer::RefWriteBuffer::new(&mut buffer);

    loop{
        let result=(encryptor.encrypt(&mut read_buffer,&mut write_buffer,true))?;

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow=>break,
            BufferResult::BufferOverflow=>{},
        }
    }

    Ok(final_result)
}

// Decrypts a buffer with the given key and iv using AES-256/CBC/Pkcs encryption.
fn aes256_cbc_decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = (decryptor.decrypt(&mut read_buffer, &mut write_buffer, true))?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}
