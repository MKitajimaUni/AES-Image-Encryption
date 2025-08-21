use crate::imagecrypt::ImageCrypt;
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use image::RgbImage;
use rand::Rng;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelSliceMut;

pub(crate) struct PNGImageCrypt {
    image_path: String,
    output_path: String,
}

impl ImageCrypt for PNGImageCrypt {
    fn encrypt(&self) {
        // generate xor key
        let img = image::open(&self.image_path).unwrap().to_rgb8();
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
        let img = image::open(&self.image_path).unwrap().to_rgb8();
        let x = img.width();
        let y = img.height();
        self.save_image(
            self.xor_image(img, self.generate_xor_pad(&self.hex_to_key(&key), x, y)),
            self.output_path.clone()
        );

        println!("Decrypted image saved.");
    }

    fn xor_image(&self, mut img: RgbImage, xor_key: RgbImage) -> RgbImage {
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

    fn generate_key(&self) -> [u8; 32] {
        let mut raw_key = [0u8; 32];
        rand::thread_rng().fill(&mut raw_key);
        raw_key
    }

    fn generate_xor_pad(&self, key: &[u8; 32], width: u32, height: u32) -> RgbImage {
        let aes_block_size = 16;
        let cipher = Aes256::new(GenericArray::from_slice(key));

        let total_bytes = (width * height * 3) as usize;
        let mut keystream = vec![0u8; total_bytes];

        keystream
            .par_chunks_mut(aes_block_size)
            .enumerate()
            .for_each(|(i, block)| {
                let mut counter_block =
                    GenericArray::clone_from_slice(&((i as u128).to_be_bytes()));
                cipher.encrypt_block(&mut counter_block);

                let len = block.len();
                block.copy_from_slice(&counter_block[..len]);
            });

        RgbImage::from_raw(width, height, keystream)
            .expect("Failed to create RgbImage from keystream")
    }

    fn save_image(&self, img: RgbImage, output_path: String) {
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
}
