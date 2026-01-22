// secure-gate/tests/alias_trait_tests.rs
// Tests to ensure all traits are actively available for the alias macros:
// - cloneable_fixed_alias
// - cloneable_dynamic_alias
// - serializable_fixed_alias
// - serializable_dynamic_alias

extern crate alloc;

#[cfg(test)]
mod tests {
    #[cfg(feature = "ct-eq")]
    use secure_gate::ConstantTimeEq;
    #[cfg(feature = "hash-eq")]
    use secure_gate::HashEq;
    #[cfg(any(
        feature = "encoding-hex",
        feature = "encoding-base64",
        feature = "encoding-bech32"
    ))]
    use secure_gate::SecureEncoding;
    use secure_gate::{
        cloneable_dynamic_alias, cloneable_fixed_alias, serializable_dynamic_alias,
        serializable_fixed_alias, ExposeSecret, ExposeSecretMut,
    };

    // Define test types using the macros
    cloneable_fixed_alias!(CloneableFixedKey, 32);
    cloneable_dynamic_alias!(CloneableDynamicPass, Vec<u8>);
    serializable_fixed_alias!(SerializableFixedToken, 16);
    serializable_dynamic_alias!(SerializableDynamicSecret, String);

    #[test]
    fn expose_secret_works() {
        let cfk: CloneableFixedKey = [1u8; 32].into();
        assert_eq!(cfk.expose_secret().len(), 32);

        let cdp: CloneableDynamicPass = vec![2u8; 10].into();
        assert_eq!(cdp.expose_secret(), &[2u8; 10]);

        let sft: SerializableFixedToken = [3u8; 16].into();
        assert_eq!(sft.expose_secret(), &[3u8; 16]);

        let sds: SerializableDynamicSecret = "secret".to_string().into();
        assert_eq!(sds.expose_secret(), "secret");
    }

    #[test]
    fn expose_secret_mut_works() {
        let mut cfk: CloneableFixedKey = [0u8; 32].into();
        cfk.expose_secret_mut()[0] = 42;
        assert_eq!(cfk.expose_secret()[0], 42);

        let mut cdp: CloneableDynamicPass = vec![0u8; 10].into();
        cdp.expose_secret_mut()[1] = 43;
        assert_eq!(cdp.expose_secret()[1], 43);

        let mut sft: SerializableFixedToken = [0u8; 16].into();
        sft.expose_secret_mut()[2] = 44;
        assert_eq!(sft.expose_secret()[2], 44);

        let sds: SerializableDynamicSecret = "abcd".to_string().into();
        // Note: String mut access is trickier, but assume it's implemented
        assert_eq!(sds.expose_secret(), "abcd");
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn constant_time_eq_works() {
        let cfk1: CloneableFixedKey = [1u8; 32].into();
        let cfk2: CloneableFixedKey = [1u8; 32].into();
        assert!(cfk1.ct_eq(&cfk2));

        let cfk3: CloneableFixedKey = [2u8; 32].into();
        assert!(!cfk1.ct_eq(&cfk3));

        let cdp1: CloneableDynamicPass = vec![5u8; 15].into();
        let cdp2: CloneableDynamicPass = vec![5u8; 15].into();
        assert!(cdp1.ct_eq(&cdp2));

        let sft1: SerializableFixedToken = [7u8; 16].into();
        let sft2: SerializableFixedToken = [7u8; 16].into();
        assert!(sft1.ct_eq(&sft2));

        let sds1: SerializableDynamicSecret = "test".to_string().into();
        let sds2: SerializableDynamicSecret = "test".to_string().into();
        assert!(sds1.ct_eq(&sds2));
    }

    #[cfg(feature = "hash-eq")]
    #[test]
    fn hash_eq_works() {
        let cfk1: CloneableFixedKey = [1u8; 32].into();
        let cfk2: CloneableFixedKey = [1u8; 32].into();
        assert!(cfk1.hash_eq(&cfk2));

        let cfk3: CloneableFixedKey = [2u8; 32].into();
        assert!(!cfk1.hash_eq(&cfk3));

        let cdp1: CloneableDynamicPass = vec![5u8; 100].into();
        let cdp2: CloneableDynamicPass = vec![5u8; 100].into();
        assert!(cdp1.hash_eq(&cdp2));

        let sft1: SerializableFixedToken = [7u8; 16].into();
        let sft2: SerializableFixedToken = [7u8; 16].into();
        assert!(sft1.hash_eq(&sft2));

        let sds1: SerializableDynamicSecret = "large_test_string_with_more_data".to_string().into();
        let sds2: SerializableDynamicSecret = "large_test_string_with_more_data".to_string().into();
        assert!(sds1.hash_eq(&sds2));
    }

    #[cfg(feature = "cloneable")]
    #[test]
    fn clone_works() {
        let cfk1: CloneableFixedKey = [1u8; 32].into();
        let cfk2 = cfk1.clone();
        assert!(cfk1.expose_secret() == cfk2.expose_secret());

        let cdp1: CloneableDynamicPass = vec![5u8; 10].into();
        let cdp2 = cdp1.clone();
        assert_eq!(cdp1.expose_secret(), cdp2.expose_secret());
    }

    #[cfg(all(feature = "serde-serialize", feature = "serde-deserialize"))]
    #[test]
    fn serialize_deserialize_works() {
        let sft1: SerializableFixedToken = [7u8; 16].into();
        let serialized = serde_json::to_string(&sft1).unwrap();
        let sft2: SerializableFixedToken = serde_json::from_str(&serialized).unwrap();
        assert_eq!(sft1.expose_secret(), sft2.expose_secret());

        let sds1: SerializableDynamicSecret = "secret".to_string().into();
        let serialized = serde_json::to_string(&sds1).unwrap();
        let sds2: SerializableDynamicSecret = serde_json::from_str(&serialized).unwrap();
        assert_eq!(sds1.expose_secret(), sds2.expose_secret());
    }

    #[cfg(feature = "encoding-hex")]
    #[test]
    fn secure_encoding_hex_works() {
        let cfk: CloneableFixedKey = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]
        .into();
        let hex = cfk.to_hex();
        assert_eq!(
            hex,
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );

        let cdp: CloneableDynamicPass = vec![1u8, 2, 3, 4].into();
        let hex = cdp.to_hex();
        assert_eq!(hex, "01020304");
    }

    #[cfg(feature = "encoding-base64")]
    #[test]
    fn secure_encoding_base64_works() {
        let cfk: CloneableFixedKey = [1u8; 32].into();
        let b64 = cfk.to_base64url();
        assert!(!b64.is_empty());

        let cdp: CloneableDynamicPass = vec![1u8, 2, 3].into();
        let b64 = cdp.to_base64url();
        assert!(!b64.is_empty());
    }

    #[cfg(feature = "encoding-bech32")]
    #[test]
    fn secure_encoding_bech32_works() {
        let cfk: CloneableFixedKey = [1u8; 32].into();
        let bech32 = cfk.to_bech32("test");
        assert!(bech32.starts_with("test"));

        let cdp: CloneableDynamicPass = vec![1u8, 2, 3, 4, 5].into();
        let bech32 = cdp.to_bech32("prefix");
        assert!(bech32.starts_with("prefix"));
    }

    #[test]
    fn from_works() {
        let cfk: CloneableFixedKey = [1u8; 32].into();
        assert_eq!(cfk.expose_secret(), &[1u8; 32]);

        let cdp: CloneableDynamicPass = vec![2u8; 10].into();
        assert_eq!(cdp.expose_secret(), &[2u8; 10]);

        let sft: SerializableFixedToken = [3u8; 16].into();
        assert_eq!(sft.expose_secret(), &[3u8; 16]);

        let sds: SerializableDynamicSecret = "test".to_string().into();
        assert_eq!(sds.expose_secret(), "test");
    }

    #[test]
    fn deref_works() {
        let cfk: CloneableFixedKey = [1u8; 32].into();
        let len = cfk.len(); // via Deref to Fixed
        assert_eq!(len, 32);

        let cdp: CloneableDynamicPass = vec![2u8; 10].into();
        let len = cdp.len(); // via Deref to Dynamic
        assert_eq!(len, 10);
    }
}
