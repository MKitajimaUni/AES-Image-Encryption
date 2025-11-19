use crate::imagecrypt::ImageCrypt;
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use gif::{DecodeOptions, Encoder, Frame, Repeat};
use image::{Rgba, RgbaImage};
use rand::Rng;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::prelude::ParallelSliceMut;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

pub struct GIFImageCrypt {
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

        self.save_gif_in_dir(encrypted_gif, self.output_path.clone());

        println!(
            "Encrypted image saved to {}.\n\
        Key: {:?}. Do not share.",
            self.output_path,
            hex::encode(&key)
        );
    }

    fn decrypt(&self, key: String) {
        const DELAY: i32 = 10;
        let key = self.hex_to_key(&key);

        let decrypted_gif = self
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

        self.pngs_to_gif(decrypted_gif, &self.output_path, DELAY);

        println!("Decrypted image or gif saved.");
    }

    fn xor_image(&self, mut img: RgbaImage, xor_key: RgbaImage) -> RgbaImage {
        // xor implementation
        let channels = 4;
        let img_buf = img.as_mut();
        let mut key_buf = xor_key.into_raw(); // raw buffer of RGBA image

        img_buf
            .par_rchunks_mut(channels) // XOR each pixel
            .zip(key_buf.par_chunks_mut(channels))
            .for_each(|(img_buf, key_buf)| {
                img_buf[0] ^= key_buf[0];
                img_buf[1] ^= key_buf[1];
                img_buf[2] ^= key_buf[2];
                img_buf[3] ^= key_buf[3];
            });

        img
    }

    fn generate_key(&self) -> [u8; 32] {
        let mut raw_key = [0u8; 32];
        rand::thread_rng().fill(&mut raw_key);
        raw_key
    }

    fn save_image(&self, _img: RgbaImage, _output_path: String) {}

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
        let path = Path::new(&image_path);

        let frames = if path.is_file() && path.extension().map(|e| e == "gif").unwrap_or(false) {
            // encoding gif
            let mut decoder = DecodeOptions::new();
            decoder.set_color_output(gif::ColorOutput::RGBA);
            let file =
                File::open(path).unwrap_or_else(|_| panic!("Could not open file: {:?}", path));
            let mut reader = decoder.read_info(std::io::BufReader::new(file)).unwrap();

            let mut frames = Vec::new();
            // code referred from official document. Non-parallel because frames must keep the original order
            while let Some(frame) = reader.read_next_frame().unwrap() {
                let buffer = &frame.buffer;
                let mut img = RgbaImage::new(frame.width.into(), frame.height.into());

                for (x, y, pixel) in img.enumerate_pixels_mut() {
                    let i = (y as usize * frame.width as usize + x as usize) * 4;
                    *pixel = Rgba([buffer[i], buffer[i + 1], buffer[i + 2], buffer[i + 3]]);
                }

                frames.push(img);
            }
            frames
        } else if path.is_dir() {
            let mut frames = Vec::new();

            let mut entries: Vec<PathBuf> = fs::read_dir(path)
                .unwrap()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().map(|e| e == "png").unwrap_or(false))
                .collect();

            entries.sort(); // frame0.png, frame1.png...

            for entry in entries {
                let img = image::open(&entry).unwrap().to_rgba8();
                frames.push(img);
            }

            frames
        } else {
            panic!("Unsupported input path: {:?}", path);
        };

        GIFImageCrypt {
            output_path,
            gif_frames: frames,
        }
    }

    pub fn save_gif_in_dir(&self, frames: Vec<RgbaImage>, output_path: String) {
        let path = Path::new(&output_path);
        // save encrypted gif as a directory of images
        fs::create_dir_all(path).unwrap();

        for (idx, img) in frames.iter().enumerate() {
            let out_path = path.join(format!("frame{:03}.png", idx));
            img.save(out_path).unwrap();
        }
    }

    fn pngs_to_gif(&self, frames: Vec<RgbaImage>, output_path: &str, delay: i32) {
        let width = frames[0].width() as u16;
        let height = frames[0].height() as u16;

        let mut image_file = File::create(output_path).expect("Failed to create GIF file");
        let mut encoder =
            Encoder::new(&mut image_file, width, height, &[]).expect("Failed to create encoder");

        encoder
            .set_repeat(Repeat::Infinite)
            .expect("Failed to set repeat size");

        for img in frames {
            let mut buffer = img.into_raw(); // RGBA → Vec<u8>
            let frame = Frame::from_rgba_speed(width, height, &mut buffer, delay);
            encoder.write_frame(&frame).unwrap();
        }
    }

    fn generate_xor_pad(
        &self,
        frame_idx: u128,
        key: &[u8; 32],
        width: u32,
        height: u32,
    ) -> RgbaImage {
        const AES_BLOCK_SIZE: usize = 16;
        const CHANNELS: u32 = 4; // because RGBA
        let cipher = Aes256::new(GenericArray::from_slice(key));

        let total_bytes = (width * height * CHANNELS) as usize;
        let mut keystream = vec![0u8; total_bytes]; // zeroed-vector

        keystream
            .par_chunks_mut(AES_BLOCK_SIZE)
            .enumerate()
            .for_each(|(i, block)| {
                let idx = i as u128 + (total_bytes as u128 * frame_idx);
                let mut counter_block = GenericArray::clone_from_slice(&(idx.to_be_bytes()));
                cipher.encrypt_block(&mut counter_block);

                // if chunk_size = n < 16, copy only first n bytes
                let len = block.len();
                block.copy_from_slice(&counter_block[..len]);
            });

        RgbaImage::from_raw(width, height, keystream)
            .expect("Failed to create RgbImage from keystream")
    }
}
