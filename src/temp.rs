// zeroize only
#[cfg(feature = "zeroize")]
impl Zeroize for Secure<Vec<u8>> {
    fn zeroize(&mut self) {
        self.expose_mut().as_mut_slice().zeroize();
    }
}

#[cfg(feature = "unsafe-wipe")]
impl Zeroize for Secure<String> {
    fn zeroize(&mut self) {
        unsafe {
            self.expose_mut().as_mut_vec().zeroize();
        }
    }
}

// zeroize || no-default-features) !! not(unsafe-wipe)
#[cfg(not(feature = "unsafe-wipe"))]
impl Zeroize for Secure<String> {
    fn zeroize(&mut self) {
        let len = self.expose().len();
        let zeros = "\0".repeat(len);
        self.expose_mut().replace_range(..len, &zeros);
    }
}
