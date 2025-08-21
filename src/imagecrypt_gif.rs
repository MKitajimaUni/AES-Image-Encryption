use std::fs::File;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::iter::IndexedParallelIterator;
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use image::{Rgb, RgbImage};
use crate::imagecrypt::ImageCrypt;
use gif::{DecodeOptions, Encoder, Frame, Repeat};
use rand::Rng;
use rayon::prelude::ParallelSliceMut;

pub struct GIFImageCrypt {
    image_path: String,
    output_path: String,
    gif_frames: Vec<RgbImage>
}

impl ImageCrypt for GIFImageCrypt {

    fn encrypt(&self) {
        let key = Self::generate_key(&self);

        let encrypted_gif = self.gif_frames.par_iter().map(|frame| {
            let width = frame.width();
            let height = frame.height();

            self.xor_image(frame.clone(), self.generate_xor_pad(&key, width, height))
        }).collect();

        self.save_gif(encrypted_gif, self.output_path.clone());

        println!(
            "Encrypted image saved to {}.\n\
        Key: {:?}. Do not share.",
            self.output_path,
            hex::encode(&key)
        );
    }

    fn decrypt(&self, key: String) {
        let encrypted_gif = self.gif_frames.par_iter().map(|frame| {
            let width = frame.width();
            let height = frame.height();

            self.xor_image(frame.clone(), self.generate_xor_pad(&self.hex_to_key(&key), width, height))
        }).collect();

        self.save_gif(encrypted_gif, self.output_path.clone());

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

    fn save_image(&self, img: RgbImage, output_path: String) {}

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
        let file = std::fs::File::open(image_path.clone()).unwrap();
        let mut reader = decoder.read_info(std::io::BufReader::new(file)).unwrap();

        let mut frames = Vec::new();
        while let Some(frame) = reader.read_next_frame().unwrap() {
            let buffer = &frame.buffer;
            let mut img = RgbImage::new(frame.width.into(), frame.height.into());
            for (x, y, pixel) in img.enumerate_pixels_mut() {
                let i = (y as usize * frame.width as usize + x as usize) * 4;
                *pixel = Rgb([buffer[i], buffer[i+1], buffer[i+2]]);
            }
            frames.push(img);
        }

        GIFImageCrypt {
            image_path,
            output_path,
            gif_frames: frames
        }
    }

    fn save_gif(&self, frames: Vec<RgbImage>, output_path: String) {
        // 出力ファイルを開く
        let mut image_file = File::create(output_path).expect("Failed to create file");

        // GIF エンコーダを作成（キャンバスサイズは最初のフレームに合わせる）
        let width = frames[0].width() as u16;
        let height = frames[0].height() as u16;
        let mut encoder = Encoder::new(&mut image_file, width, height, &[]).expect("Failed to create encoder");

        encoder.set_repeat(Repeat::Infinite).expect("Failed to set repeat size");

        for img in frames {
            let width = img.width() as u16;
            let height = img.height() as u16;

            // RGB を GIF 用に変換（簡易: TrueColor をそのまま 24bit → 256色変換せず）
            let buffer = img.into_raw(); // Vec<u8>

            // フレーム生成（100ms のディレイ = 10fps）
            let mut frame = Frame::from_rgb(width, height, &buffer);
            frame.delay = 10; // 100ms

            encoder.write_frame(&frame).expect("Failed to write frame");
        }
    }
}