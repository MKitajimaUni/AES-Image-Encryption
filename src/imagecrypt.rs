pub trait ImageCrypt {
    fn encrypt(&self);
    fn decrypt(&self, key: String);
}
