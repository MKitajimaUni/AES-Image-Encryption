use crate::imagecrypt::ImageCrypt;
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use image::{RgbaImage};
use rand::Rng;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelSliceMut;
use rayon::slice::ParallelSlice;

pub(crate) struct PNGImageCrypt {
    image_path: String,
    output_path: String,
}

impl ImageCrypt for PNGImageCrypt {
    fn encrypt(&self) {
        // generate xor key
        let img = image::open(&self.image_path).unwrap().to_rgba8();
        let size_x = img.width();
        let size_y = img.height();
        let key = Self::generate_key(&self);
        
        Self::save_image(
            &self,
            self.xor_image(img, self.generate_xor_pad(&key, size_x, size_y)),
            self.output_path.parse().unwrap()
        );

        println!(
            "Encrypted image saved to {}.\n\
        Key: {:?}. Do not share.",
            self.output_path,
            hex::encode(&key)
        );
    }

    fn decrypt(&self, key: String) {
        // use the xor key to decrypt the image
        let img = image::open(&self.image_path).unwrap().to_rgba8();
        let x = img.width();
        let y = img.height();
        self.save_image(
            self.xor_image(img, self.generate_xor_pad(&self.hex_to_key(&key), x, y)),
            self.output_path.clone()
        );

        println!("Decrypted image saved.");
    }

    fn xor_image(&self, mut img: RgbaImage, xor_key: RgbaImage) -> RgbaImage {
        let channels = 4;

        let img_buf = img.as_mut();          // &mut [u8]
        let key_buf = xor_key.into_raw();    // Vec<u8>, 長さは width*height*4

        // 前方向に 4 バイトずつ（=1ピクセル）処理する
        img_buf
            .par_chunks_mut(channels) // ← par_rchunks_mut から変更
            .zip(key_buf.par_chunks(channels))
            .for_each(|(pix, k)| {
                pix[0] ^= k[0];
                pix[1] ^= k[1];
                pix[2] ^= k[2];
                pix[3] ^= k[3];
            });

        img
    }

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
}

impl PNGImageCrypt {
    pub(crate) fn new(image_path: String, output_path: String) -> PNGImageCrypt {
        PNGImageCrypt {
            image_path,
            output_path,
        }
    }

    fn generate_xor_pad(&self, key: &[u8; 32], width: u32, height: u32) -> RgbaImage {
        let channels = 4;
        let aes_block = 16;
        let cipher = Aes256::new(GenericArray::from_slice(key));

        let total = (width * height * channels) as usize;
        let mut ks = vec![0u8; total];

        ks.par_chunks_mut(aes_block)
            .enumerate()
            .for_each(|(i, block)| {
                let mut ctr = GenericArray::clone_from_slice(&(i as u128).to_be_bytes());
                cipher.encrypt_block(&mut ctr);
                block.copy_from_slice(&ctr[..block.len()]);
            });

        debug_assert_eq!(ks.len(), total);
        RgbaImage::from_raw(width, height, ks)
            .expect("keystream layout mismatch")
    }
}
