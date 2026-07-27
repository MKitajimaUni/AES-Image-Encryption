use crate::ciphermode::Ciphermode;
use crate::imagecrypt::ImageCrypt;

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

use image::RgbaImage;

use rand::Rng;

use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelSliceMut;
use rayon::slice::ParallelSlice;

use md5;
use xxhash_rust::xxh64::xxh64;


pub(crate) struct PNGImageCrypt {
    image_path: String,
    output_path: String,
    cipher_mode: Ciphermode,
}

impl ImageCrypt for PNGImageCrypt {
    fn encrypt(&self) {
        // generate xor key
        let img = image::open(&self.image_path).unwrap().to_rgba8();
        let size_x = img.width();
        let size_y = img.height();
        let key = Self::generate_key(&self);

        let entropy_before = self.get_entropy(&img);
        let mut entropy_after = f64::default();

        let start = std::time::Instant::now();

        if self.cipher_mode == Ciphermode::ECB {
            let encrypted_img = self.ecb_cipher(img.clone(), &key, true);
            entropy_after = self.get_entropy(&encrypted_img);

            Self::save_image(
                &self,
                encrypted_img,
                self.output_path.parse().unwrap(),
            );

        } else if self.cipher_mode == Ciphermode::CBC {
            let encrypted_img = self.cbc_encryption(img.clone(), &key);
            entropy_after = self.get_entropy(&encrypted_img);

            Self::save_image(
                &self,
                encrypted_img,
                self.output_path.parse().unwrap(),
            );

        } else if self.cipher_mode == Ciphermode::CTR {
            let encrypted_img = self.xor_image(img.clone(), self.generate_xor_pad(&key, size_x, size_y));
            entropy_after = self.get_entropy(&encrypted_img);

            Self::save_image(
                &self,
                encrypted_img,
                self.output_path.parse().unwrap(),
            );
        }

        let duration = start.elapsed().as_millis();

        println!(
            "Encrypted image saved to {}.\n\
            =================LOG=================\n\
            Image Size: {}x{}\n\
            Ciphermode: {}\n\
            Time: {} ms\n\
            Entropy: {} -> {}\n\
            =====================================\n\
            Key: {:?}. Do not share.",
            self.output_path,
            size_x,
            size_y,
            match self.cipher_mode {
                Ciphermode::ECB => "ECB",
                Ciphermode::CBC => "CBC",
                Ciphermode::CTR => "CTR",
            },
            duration,
            entropy_before,
            entropy_after,
            hex::encode(&key)
        );
    }

    fn decrypt(&self, key: String) {
        // use the xor key to decrypt the image
        let img = image::open(&self.image_path).unwrap().to_rgba8();
        let x = img.width();
        let y = img.height();

        let entropy_before = self.get_entropy(&img);
        let mut entropy_after = f64::default();

        let start = std::time::Instant::now();

        if self.cipher_mode == Ciphermode::ECB {
            let decrypted_img = self.ecb_cipher(img.clone(), &self.hex_to_key(&key), false);
            entropy_after = self.get_entropy(&decrypted_img);

            Self::save_image(
                &self,
                decrypted_img,
                self.output_path.parse().unwrap(),
            );

        } else if self.cipher_mode == Ciphermode::CBC {
            let decrypted_img = self.cbc_decryption(img.clone(), &self.hex_to_key(&key));
            entropy_after = self.get_entropy(&decrypted_img);

            Self::save_image(
                &self,
                decrypted_img,
                self.output_path.parse().unwrap(),
            );

        } else if self.cipher_mode == Ciphermode::CTR {
            let decrypted_img = self.xor_image(img.clone(), self.generate_xor_pad(&self.hex_to_key(&key), x, y));
            entropy_after = self.get_entropy(&decrypted_img);

            Self::save_image(
                &self,
                decrypted_img,
                self.output_path.clone(),
            );
        }

        let duration = start.elapsed().as_millis();

        println!(
            "Decrypted image saved to {}.\n\
            =================LOG=================\n\
            Image Size: {}x{}\n\
            Ciphermode: {}\n\
            Time: {} ms\n\
            Entropy: {} -> {}\n\
            =====================================",
            self.output_path,
            x,
            y,
            match self.cipher_mode {
                Ciphermode::ECB => "ECB",
                Ciphermode::CBC => "CBC",
                Ciphermode::CTR => "CTR",
            },
            duration,
            entropy_before,
            entropy_after,
        );
    }
}

impl PNGImageCrypt {
    pub const AES_BLOCK_IN_BYTE: usize = 16;
    pub const CHANNELS: u32 = 4;

    pub(crate) fn new(
        image_path: String,
        output_path: String,
        cipher_mode: Ciphermode,
    ) -> PNGImageCrypt {
        PNGImageCrypt {
            image_path,
            output_path,
            cipher_mode,
        }
    }

    // image encryption functions for CTR
    fn generate_xor_pad(&self, key: &[u8; 32], width: u32, height: u32) -> RgbaImage {
        let cipher = Aes256::new(GenericArray::from_slice(key));

        let nonce = (xxh64(key, 0) as u128) << 64;

        let total = (width * height * Self::CHANNELS) as usize;
        let mut ks = vec![0u8; total];

        ks.par_chunks_mut(Self::AES_BLOCK_IN_BYTE)
            .enumerate()
            .for_each(|(i, block)| {
                // counter with nonce as offset (left 64-bit) and i as counter (right 64-bit)
                let mut ctr = GenericArray::clone_from_slice(&(nonce + i as u128).to_le_bytes());
                cipher.encrypt_block(&mut ctr);
                block.copy_from_slice(&ctr[..block.len()]);
            });

        RgbaImage::from_raw(width, height, ks).expect("keystream layout mismatch")
    }

    fn xor_image(&self, mut img: RgbaImage, xor_key: RgbaImage) -> RgbaImage {
        let img_buf = img.as_mut(); // &mut [u8]
        let key_buf = xor_key.into_raw(); 

        // combine chunks of key and image buffer
        img_buf
            .par_chunks_mut(Self::CHANNELS as usize)
            .zip(key_buf.par_chunks(Self::CHANNELS as usize))
            .for_each(|(pix, k)| {
                pix[0] ^= k[0];
                pix[1] ^= k[1];
                pix[2] ^= k[2];
                pix[3] ^= k[3];
            });

        img
    }

    // image cipher functions for ECB
    fn ecb_cipher(&self, mut img: RgbaImage, key: &[u8; 32], is_encryption: bool) -> RgbaImage {
        let cipher = Aes256::new(GenericArray::from_slice(key));

        let img_buf = img.as_mut(); // &mut [u8]

        img_buf.par_chunks_mut(Self::AES_BLOCK_IN_BYTE).for_each(|block| {
            let mut b = GenericArray::default();
            b[..block.len()].copy_from_slice(block);

            if is_encryption {
                cipher.encrypt_block(&mut b);
            } else {
                cipher.decrypt_block(&mut b);
            }
            block.copy_from_slice(&b[..block.len()]);
        });

        img
    }

    // image encryption functions for CBC
    fn cbc_encryption(&self, mut img: RgbaImage, key: &[u8; 32]) -> RgbaImage {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        
        let iv = GenericArray::clone_from_slice(&md5::compute(key).0);
        let mut before = iv;
        let img_buf = img.as_mut(); // &mut [u8]

        img_buf.chunks_mut(Self::AES_BLOCK_IN_BYTE).for_each(|block| {
            let mut b = GenericArray::default();
            b[..block.len()].copy_from_slice(block);

            for (bl, be) in 
            b.iter_mut().zip(before.iter()) {
                *bl ^= *be;
            }

            cipher.encrypt_block(&mut b);

            block.copy_from_slice(&b[..block.len()]);
            before = b;
        });

        img
    }

    // image decryption functions for CBC
    fn cbc_decryption(&self, mut img: RgbaImage, key: &[u8; 32]) -> RgbaImage {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        
        let iv = GenericArray::clone_from_slice(&md5::compute(key).0);
        let mut before = iv;
        let img_buf = img.as_mut(); // &mut [u8]

        img_buf.chunks_mut(Self::AES_BLOCK_IN_BYTE).for_each(|block| {
            
            let mut b = GenericArray::default();
            b[..block.len()].copy_from_slice(block);
            let b_temp = b.clone();
            
            cipher.decrypt_block(&mut b);

            for (bl, be) in 
            b.iter_mut().zip(before.iter()) {
                *bl ^= *be;
            }
            before = b_temp;


            block.copy_from_slice(&b[..block.len()]);
        });
        
        img
    }
    
    
    // helper functions 
    fn generate_key(&self) -> [u8; 32] {
        let mut raw_key = [0u8; 32];
        rand::thread_rng().fill(&mut raw_key);
        raw_key
    }

    fn save_image(&self, img: RgbaImage, output_path: String) {
        // save the image
        img.save(output_path).unwrap();
    }

    fn hex_to_key(&self, hex_str: &str) -> [u8; 32] {
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

    fn get_entropy(&self, img: &RgbaImage) -> f64 {
        let bytes = img.as_raw();
        if bytes.is_empty() {
            return 0.0;
        }

        let mut counts = [0u64; 256];
        for &byte in bytes {
            counts[byte as usize] += 1;
        }

        let total = bytes.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = (count as f64) / total;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}
