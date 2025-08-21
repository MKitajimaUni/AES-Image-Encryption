use image::RgbImage;

pub trait ImageCrypt {

    fn encrypt(&self);
    fn decrypt(&self, key: String);

    // generator and encrypt/decrypt
    fn xor_image(&self, img: RgbImage, xor_key: RgbImage) -> RgbImage;
    fn generate_key(&self) -> [u8; 32];
    fn generate_xor_pad(&self, key: &[u8; 32], width: u32, height: u32) -> RgbImage;

    // helper functions
    fn save_image(&self, img: RgbImage, output_path: String);
    fn hex_to_key(&self, hex_str: &str) -> [u8; 32];
}
