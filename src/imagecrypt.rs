use image::{RgbaImage};

pub trait ImageCrypt {

    fn encrypt(&self);
    fn decrypt(&self, key: String);

    // generator and encrypt/decrypt
    fn xor_image(&self, img: RgbaImage, xor_key: RgbaImage) -> RgbaImage;
    fn generate_key(&self) -> [u8; 32];

    // helper functions
    fn save_image(&self, img: RgbaImage, output_path: String);
    fn hex_to_key(&self, hex_str: &str) -> [u8; 32];
}
