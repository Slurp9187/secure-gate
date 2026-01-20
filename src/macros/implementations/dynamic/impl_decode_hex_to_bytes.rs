#[macro_export(local_inner_macros)]
macro_rules! impl_decode_hex_to_bytes {
    () => {
        #[cfg(feature = "encoding-hex")]
        impl $crate::Dynamic<String> {
            /// Decode the string as hex to bytes (assumes validated hex string).
            pub fn decode_hex_to_bytes(&self) -> Vec<u8> {
                use hex as hex_crate;
                hex_crate::decode(self.expose_secret()).expect("validated hex string should decode")
            }

            /// Consuming version: decode as hex and immediately drop the wrapper.
            pub fn decode_hex_into_bytes(self) -> Vec<u8> {
                use hex as hex_crate;
                hex_crate::decode(self.expose_secret()).expect("validated hex string should decode")
            }
        }
    };
}
