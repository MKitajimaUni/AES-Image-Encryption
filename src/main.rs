mod imagecrypt;
mod imagecrypt_gif;
mod imagecrypt_png;
mod ciphermode;

extern crate image;
use imagecrypt::ImageCrypt;
use imagecrypt_png::PNGImageCrypt;
use std::env;
use std::path::Path;
use crate::imagecrypt_gif::GIFImageCrypt;
pub use ciphermode::Ciphermode;

fn main() {
    let args: Vec<String> = env::args().collect();
    // arg[0] = run
    // arg[1] = type (-e for encryption, -d for decryption)
    // arg[2] = cipher mode (both for encryption and decryption)
    // arg[3] = image path (both for encryption and decryption)
    // arg[4] = output path (both for encryption and decryption)
    // arg[5] = xor key (for decryption)

    if args.len() < 5 {
        println!(
            "Usage for encryption: cargo run -- <type> <cipher-mode> <image_path> <output-path>\n\
                 Usage for decryption: cargo run -- <type> <cipher-mode> <image_path> <output-path>　<xor_key>\n\
                 <type> can be 'e' for encryption and 'd' for decryption.\n\
                 <cipher-mode> can be 'ECB' or 'CBC' or 'CTR'.\n"
        );
        return;
    }
    
    // which cipher mode?
    let ciphermode = match args[2].clone().as_str() {
        "ECB" => Ciphermode::ECB,
        "CBC" => Ciphermode::CBC,
        "CTR" => Ciphermode::CTR,
        _ => panic!("Invalid cipher mode"),
    };

    // which extension type?
    let path = Path::new(&args[3]);
    let img_crypt: Box<dyn ImageCrypt> = if args[3].ends_with(".png")
        || args[3].ends_with(".jpg")
        || args[3].ends_with(".jpeg")
    {
        Box::new(PNGImageCrypt::new(args[3].clone(), args[4].clone(), ciphermode))
    } else if path.is_dir() || args[3].ends_with(".gif") {
        Box::new(GIFImageCrypt::new(args[3].clone(), args[4].clone()))
    } else {
        panic!("Unsupported file type");
    };


    // encrypt or decrypt?
    match args[1].clone().as_str() {
        "e" => {
            img_crypt.encrypt()
        }
        "d" => {
            img_crypt.decrypt(args[5].clone())
        }
        _ => {
            panic!("Invalid type. Use 'e' for encryption or 'd' for decryption.");
        }
    }
}
