use crate::imagecrypt::ImageCrypt;
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use gif::{DecodeOptions, Encoder, Frame};
use image::{Rgba, RgbaImage};
use rand::Rng;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::prelude::ParallelSliceMut;
use std::fs::File;

pub struct GIFImageCrypt {
    image_path: String,
    output_path: String,
    gif_frames: Vec<RgbaImage>,
}

impl ImageCrypt for GIFImageCrypt {
    fn encrypt(&self) {
        let key = Self::generate_key(&self);

        let encrypted_gif = self
            .gif_frames
            .par_iter()
            .enumerate()
            .map(|(idx, frame)| {
                let width = frame.width();
                let height = frame.height();

                self.xor_image(
                    frame.clone(),
                    self.generate_xor_pad(idx as u128, &key, width, height),
                )
            })
            .collect();

        self.save_gif(encrypted_gif, self.output_path.clone());

        println!(
            "Encrypted image saved to {}.\n\
        Key: {:?}. Do not share.",
            self.output_path,
            hex::encode(&key)
        );
    }

    fn decrypt(&self, key: String) {
        let key = self.hex_to_key(&key);

        let encrypted_gif = self
            .gif_frames
            .par_iter()
            .enumerate()
            .map(|(idx, frame)| {
                let width = frame.width();
                let height = frame.height();

                self.xor_image(
                    frame.clone(),
                    self.generate_xor_pad(idx as u128, &key, width, height),
                )
            })
            .collect();

        self.save_gif(encrypted_gif, self.output_path.clone());

        println!("Decrypted image saved.");
    }

    fn xor_image(&self, mut img: RgbaImage, xor_key: RgbaImage) -> RgbaImage {
        // xor implementation
        let channels = 4;
        let img_buf = img.as_mut();
        let key_buf = xor_key.into_raw(); // Vec<u8> で取り出す

        img_buf
            .par_rchunks_mut(channels) // 画像の各ピクセル(R,G,B)を並列で処理
            .enumerate()
            .for_each(|(i, pixel)| {
                let j = i * 4;
                pixel[0] ^= key_buf[j];
                pixel[1] ^= key_buf[j + 1];
                pixel[2] ^= key_buf[j + 2];
                pixel[3] ^= key_buf[j + 3];
            });

        img
    }

    fn generate_key(&self) -> [u8; 32] {
        let mut raw_key = [0u8; 32];
        rand::thread_rng().fill(&mut raw_key);
        raw_key
    }

    fn save_image(&self, img: RgbaImage, output_path: String) {}

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

impl GIFImageCrypt {
    pub(crate) fn new(image_path: String, output_path: String) -> Self {
        let mut decoder = DecodeOptions::new();
        decoder.set_color_output(gif::ColorOutput::RGBA);
        let file = File::open(image_path.clone()).unwrap();
        let mut reader = decoder.read_info(std::io::BufReader::new(file)).unwrap();

        let mut frames = Vec::new();
        while let Some(frame) = reader.read_next_frame().unwrap() {
            let buffer = &frame.buffer;
            let mut img = RgbaImage::new(frame.width.into(), frame.height.into());

            for (x, y, pixel) in img.enumerate_pixels_mut() {
                let i = (y as usize * frame.width as usize + x as usize) * 4;

                *pixel = Rgba([buffer[i], buffer[i + 1], buffer[i + 2], buffer[i + 3]]);
            }

            frames.push(img);
        }

        GIFImageCrypt {
            image_path,
            output_path,
            gif_frames: frames,
        }
    }

    fn save_gif(&self, frames: Vec<RgbaImage>, output_path: String) {
        // 出力ファイルを開く
        let mut image_file = File::create(output_path).expect("Failed to create file");

        let width = frames[0].width() as u16;
        let height = frames[0].height() as u16;
        let mut encoder =
            Encoder::new(&mut image_file, width, height, &[]).expect("Failed to create encoder");

        let frames_to_write: Vec<Frame> = frames
            .par_iter()
            .map(|img| {
                let width = img.width() as u16;
                let height = img.height() as u16;

                let mut buffer = img.clone().into_raw();

                let mut frame = Frame::from_rgba(width, height, &mut *buffer);
                frame.delay = 10;
                frame
            })
            .collect();

        // 書き込みは逐次処理
        for frame in frames_to_write {
            encoder.write_frame(&frame).expect("Failed to write frame");
        }
    }

    fn generate_xor_pad(
        &self,
        frame_idx: u128,
        key: &[u8; 32],
        width: u32,
        height: u32,
    ) -> RgbaImage {
        let aes_block_size = 16;
        let channels = 4;
        let cipher = Aes256::new(GenericArray::from_slice(key));

        let total_bytes = (width * height * channels) as usize;
        let mut keystream = vec![0u8; total_bytes];

        keystream
            .par_chunks_mut(aes_block_size)
            .enumerate()
            .for_each(|(i, block)| {
                let idx = i as u128 + (total_bytes as u128 * frame_idx);
                let mut counter_block = GenericArray::clone_from_slice(&(idx.to_be_bytes()));
                cipher.encrypt_block(&mut counter_block);

                let len = block.len();
                block.copy_from_slice(&counter_block[..len]);
            });

        RgbaImage::from_raw(width, height, keystream)
            .expect("Failed to create RgbImage from keystream")
    }
}
