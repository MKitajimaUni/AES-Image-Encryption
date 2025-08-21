use image::RgbImage;
use crate::imagecrypt::ImageCrypt;
use crate::imagecrypt_png::PNGImageCrypt;

pub struct GIFImageCrypt {
    image_path: String,
    output_path: String,
    gif_frames: Vec<RgbImage>
}

impl ImageCrypt for GIFImageCrypt {

    fn encrypt(&self) {
        todo!()
    }

    fn decrypt(&self, key: String) {
        todo!()
    }

    fn xor_image(&self, img: RgbImage, xor_key: RgbImage) -> RgbImage {
        todo!()
    }

    fn generate_key(&self) -> [u8; 32] {
        todo!()
    }

    fn generate_xor_pad(&self, key: &[u8; 32], width: u32, height: u32) -> RgbImage {
        todo!()
    }

    fn save_image(&self, img: RgbImage, output_path: String) {
        todo!()
    }

    fn hex_to_key(&self, hex_str: &str) -> [u8; 32] {
        todo!()
    }
}

impl GIFImageCrypt {
    pub(crate) fn new(image_path: String, output_path: String) -> Self {
        GIFImageCrypt {
            image_path,
            output_path,
            gif_frames: vec![]
        }


    }
}