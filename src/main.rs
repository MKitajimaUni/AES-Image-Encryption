mod imagecrypt;
mod imagecrypt_gif;
mod imagecrypt_png;

extern crate image;
use imagecrypt::ImageCrypt;
use imagecrypt_png::PNGImageCrypt;
use std::env;
use std::path::Path;
use crate::imagecrypt_gif::GIFImageCrypt;

fn main() {
    let args: Vec<String> = env::args().collect();
    // arg[0] = run
    // arg[1] = type (-e for encryption, -d for decryption)
    // arg[2] = image path (both for encryption and decryption)
    // arg[3] = output path (both for encryption and decryption)
    // arg[4] = xor key (for decryption)
    if args.len() < 4 {
        println!(
            "Usage for encryption: cargo run <type> <image_path> <output-path>\n\
                 Usage for decryption: cargo run <type> <image_path> <output-path>　<xor_key>\n\
                 <type> can be 'e' for encryption and 'd' for decryption.\n\
            "
        );
        return;
    }

    let path = Path::new(&args[2]);
    // which extension type?
    let img_crypt: Box<dyn ImageCrypt> = if args[2].ends_with(".png")
        || args[2].ends_with(".jpg")
        || args[2].ends_with(".jpeg")
    {
        Box::new(PNGImageCrypt::new(args[2].clone(), args[3].clone()))
    } else if path.is_dir() || args[2].ends_with(".gif") {
        Box::new(GIFImageCrypt::new(args[2].clone(), args[3].clone()))
    } else {
        panic!("Unsupported file type");
    };

    // encrypt or decrypt?
    match args[1].clone().as_str() {
        "e" => {
            img_crypt.encrypt()
        }
        "d" => {
            img_crypt.decrypt(args[4].clone())
        }
        _ => {
            panic!("Invalid type. Use 'e' for encryption or 'd' for decryption.");
        }
    }
}
