# Image Encryption with Block Cipher Modes (AES-256-CTR, AES-256-CBC, AES-256-ECB)

# Usage and Examples

### Build
```bash
cargo build --release
```
### Run
```
<cipher_mode> = [ECB | CBC | CTR]
<image_path> = path to the image file
<output_path> = path to save the encrypted/decrypted image
<xor_key> = xor key (for decryption)
```
#### Encryption
For `.png`:
```
cargo run -- e <cipher_mode> <image_path> <output-path>
```
For `.gif`:
```
cargo run -- e <cipher_mode> <image_path> <output-dir-path>
```
#### Try:
For `.png`:
```
cargo run -- e ECB img_example_bologna.jpeg img_encrypted.png
```
For `.gif`:
```
cargo run -- e CTR gif_example_cat.gif encrypted
```
#### Decryption
For `.png`:
```
cargo run -- d <cipher_mode> <image_path> <output_path> <xor_key>
```
For `.gif`:
```
cargo run -- d <cipher_mode> <dir_path> <gif_output_path> <xor_key>
```
#### Try:
For `.png`:
```
cargo run -- d ECB img_encrypted.png img_decrypted.png <your_own_key>
```
For `.gif`:
```
cargo run -- d CTR encrypted decrypted.gif <your_own_key>
```