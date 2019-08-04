use std::str;
use rand::{OsRng, Rng};
use crypto::buffer::{ReadBuffer,WriteBuffer,BufferResult};
use crypto::{symmetriccipher,buffer,aes,blockmodes};
use crypto::aessafe::*;
use crypto::blockmodes::*;
use crypto::symmetriccipher::*;

fn main() {
    println!("Hello, world!");
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

    assert_eq!(message,crypt_message);
    println!("{}",crypt_message);
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
