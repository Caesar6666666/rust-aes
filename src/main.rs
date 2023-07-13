use clap::{arg, command, value_parser};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key,
    Nonce,
};
fn main() {
    let matches = command!()
        .arg(
            arg!([name] "file to operate on")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(-d --decrypto ... "turn decrypto mode on"))
        .arg(
            arg!(-o --output <file> "output file")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(-k --key <key> "aes key(256 bit)").required(false))
        .get_matches();
    let name = matches.get_one::<PathBuf>("name").expect("file not found");

    let decrypto = matches.get_one::<u8>("decrypto").unwrap_or(&0);

    let mut key = [42u8; 32];
    if let Some(k) = matches.get_one::<String>("key") {
        let mut i = 0;
        for c in k.bytes() {
            key[i] = c;
            i += 1;
        }
    }
    let key: &Key<Aes256Gcm> = &key.into();

    // read file
    let mut input_file = fs::File::open(name).expect("file not found");

    let block_size = 16 * 1000 * 1000;
    let mut buffer = vec![0u8; block_size + 16 + 12];
    if *decrypto == 0 {
        let mut output_file = name.clone();
        if let Some(path) = matches.get_one::<PathBuf>("output") {
            output_file = path.clone();
        } else {
            output_file.as_mut_os_string().push(".aes");
        }
        let mut output_file = fs::File::create(output_file).expect("create output file failed");
        loop {
            let bytes_read = input_file
                .read(&mut buffer[..block_size])
                .expect("read file failed");
            if bytes_read == 0 {
                break;
            }
            let cipher = Aes256Gcm::new(&key);
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
            let ciphertext = cipher
                .encrypt(&nonce, buffer[..bytes_read].as_ref())
                .expect("encrypt failed");
            //println!("nonce len {}\nbytes_read: {} \naes encrypt len: {}\n", nonce.len(), bytes_read, ciphertext.len());
            output_file
                .write_all(&nonce)
                .expect("write output file failed");
            output_file
                .write_all(&ciphertext)
                .expect("write output file failed");
        }
    } else {
        let mut output_file = name.clone();

        if let Some(path) = matches.get_one::<PathBuf>("output") {
            output_file = path.clone();
        } else {
            output_file.set_extension("");
        }
        let mut output_file = fs::File::create(output_file).expect("create output file failed");
        loop {
            let bytes_read = input_file
                .read(&mut buffer[..])
                .expect("read input file failed");
            if bytes_read == 0 {
                break;
            }
            //println!("bytes_read: {} \n", bytes_read);
            let cipher = Aes256Gcm::new(&key);
            let nonce = Nonce::from_slice(&buffer[..12]); // 96-bits; unique per message
            let plaintext = cipher
                .decrypt(nonce, buffer[12..bytes_read].as_ref())
                .expect("decrypt failed");
            //println!("bytes_read: {} \naes decrypt len: {}\n", bytes_read, plaintext.len());
            output_file
                .write_all(&plaintext)
                .expect("write output file failed");
        }
    }
}