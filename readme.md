# AES-CTR XOR Pad for Images

This Rust program provides **image encryption and decryption** using **AES-256 in Counter (CTR) mode**.  
It generates a keystream from AES-256, which is then XORed with each pixel of an image. This process is **reversible**: applying the same operation again with the same key restores the original image.

---
## ⚠️Important Notes
   - This program just demonstrates AES-CTR for images.
   - Hence, this program is not intended for any serious use.
   - Only `.png` and `.gif` is supported for the output type. You can encrypt other formats like `.jpeg` or `.jpg`, but the output image must be in `.png` (or `.gif`).
   - All images are encoded/decoded with RGB.
   - `.gif` encryption and decryption is incomplete. 
---

## 🔐 How It Works

1. **AES-CTR mode**
    - AES-256 is used as a block cipher.
    - A counter value (`u128`) is encrypted with AES to generate a pseudorandom block of bytes.
    - The counter is incremented for each block, ensuring a unique keystream for every part of the image.
    - The result is a keystream of bytes, as long as the image data.

2. **XOR with Image Data**
    - The RGB pixel data of the image is extracted.
    - Each byte of the image (R, G, B channels) is XORed with the corresponding byte from the keystream.
    - This produces the encrypted image.
    - Decryption is the same process: XORing again with the same keystream restores the original image.

3. **Optimizations**
    - **Parallel Keystream Generation:**  
      Using [Rayon](https://github.com/rayon-rs/rayon), AES blocks are generated in parallel (`par_chunks_mut`), making full use of multi-core CPUs.
    - **Parallel Pixel XOR:**  
      The XOR operation is applied per pixel (`par_rchunks_mut`) in parallel, again leveraging multiple cores for speed.
---

## 🚀 Usage

### Build
```bash
cargo build --release
```
### Run
#### Encryption
```
cargo run -- e <image_path> <output-path>
```
#### Try:
```
cargo run -- e img_example_bologna.jpeg img_encrypted.png
```
#### Decryption
```
cargo run -- d <image_path> <output-path> <xor_key>
```
#### Try:
```
cargo run -- d img_encrypted.png img_decrypted.png <your_own_key>
```