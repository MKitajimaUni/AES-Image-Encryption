extern crate image;

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use image::{RgbImage};
use rand::Rng;
use rayon::prelude::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    // arg[0] = run
    // arg[1] = type (-e for encryption, -d for decryption)
    // arg[2] = image path (both for encryption and decryption)
    // arg[3] = xor key (for decryption)
    // arg[4] = output path (both for encryption and decryption)
    if args.len() < 4 {
        println!(
            "Usage for encryption: cargo run <type> <image_path> <output-path>\n\
                 Usage for decryption: cargo run <type> <image_path> <xor_key> <output-path>\n\
                 <type> can be 'e' for encryption and 'd' for decryption.\n\
            "
        );
        return;
    }

    match args[1].clone().as_str() {
        "e" => encrypt(args),
        "d" => decrypt(args),
        _ => {
            println!("Invalid type. Use 'e' for encryption or 'd' for decryption.");
            return;
        }
    }
}

fn encrypt(args: Vec<String>) {
    // generate xor key
    let image_path = args[2].clone();
    let output_path = args[3].clone();
    let img = image::open(&image_path).unwrap().to_rgb8();
    let size_x = img.width();
    let size_y = img.height();
    let key = generate_aes256_key();
    let xor_pad = generate_aes_pad(&key, size_x, size_y);
    output_image_rgb(xor_image_rgb(img, xor_pad), output_path.clone());

    println!(
        "Encrypted image saved to {}.\n\
        Key: {:?}. Do not share.",
        output_path,
        hex::encode(&key)
    );
}

fn decrypt(args: Vec<String>) {
    // use the xor key to decrypt the image
    let image_path = args[2].clone();
    let key = hex_to_key(&args[3].clone());
    let output_path = args[4].clone();

    let img = image::open(&image_path).unwrap().to_rgb8();
    let x = img.width();
    let y = img.height();
    output_image_rgb(
        xor_image_rgb(img, generate_aes_pad(&key, x, y)),
        output_path,
    );

    println!("Decrypted image saved.");
}

fn xor_image_rgb(mut img: RgbImage, xor_key: RgbImage) -> RgbImage {
    // xor implementation
    let img_buf = img.as_mut();
    let key_buf = xor_key.into_raw(); // Vec<u8> で取り出す

    img_buf
        .par_rchunks_mut(3) // 画像の各ピクセル(R,G,B)を並列で処理
        .enumerate()
        .for_each(|(i, pixel)| {
            let j = i * 3;
            pixel[0] ^= key_buf[j];
            pixel[1] ^= key_buf[j + 1];
            pixel[2] ^= key_buf[j + 2];
        });

    img
}

fn generate_aes256_key() -> [u8; 32] {
    let mut raw_key = [0u8; 32];
    rand::thread_rng().fill(&mut raw_key);
    raw_key
}

fn generate_aes_pad(key: &[u8; 32], width: u32, height: u32) -> RgbImage {
    let aes_block_size = 16;
    let cipher = Aes256::new(GenericArray::from_slice(key));

    let total_bytes = (width * height * 3) as usize;
    let mut keystream = vec![0u8; total_bytes];

    keystream
        .par_chunks_mut(aes_block_size)
        .enumerate()
        .for_each(|(i, block)| {
            let mut counter_block = GenericArray::clone_from_slice(&((i as u128).to_be_bytes()));
            cipher.encrypt_block(&mut counter_block);

            let len = block.len();
            block.copy_from_slice(&counter_block[..len]);
        });

    RgbImage::from_raw(width, height, keystream).expect("Failed to create RgbImage from keystream")
}

fn output_image_rgb(img: RgbImage, output_path: String) {
    // save the image
    img.save(output_path).unwrap();
}

fn hex_to_key(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("Invalid hex string");
    assert_eq!(
        bytes.len(),
        32,
        "Key must be exactly 32 bytes (64 hex chars)"
    );

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    key
}
