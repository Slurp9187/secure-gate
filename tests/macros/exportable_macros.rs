#[cfg(feature = "serde-serialize")]
mod test_fixed_exportable_alias {
    use secure_gate::{fixed_exportable_alias, Fixed};

    fixed_exportable_alias!(TestFixedExported, 32);

    #[test]
    fn test_fixed_exportable_creation_and_serialization() {
        // Test From impl
        let inner = TestFixedExported::from([42u8; 32]);
        assert_eq!(inner.inner.len(), 32);
        assert_eq!(inner.inner[0], 42);

        // Test wrapping in Fixed
        let wrapped = Fixed::new(inner);

        // Test serialization
        let json = serde_json::to_string(&wrapped).unwrap();
        // Should be a JSON array of 32 numbers
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
    }

    fixed_exportable_alias!(TestFixedExportedWithDoc, 16, "Test doc");

    #[test]
    fn test_fixed_exportable_with_doc() {
        let inner = TestFixedExportedWithDoc::from([0u8; 16]);
        let wrapped = Fixed::new(inner);
        let _json = serde_json::to_string(&wrapped).unwrap();
        // If it compiles and serializes, it's good
    }
}

mod test_fixed_exportable_no_serde {
    use secure_gate::fixed_exportable_alias;

    fixed_exportable_alias!(TestNoSerde, 8);

    #[test]
    fn test_fixed_exportable_no_serde() {
        let inner = TestNoSerde::from([1u8; 8]);
        assert_eq!(inner.inner.len(), 8);
    }
}

#[cfg(feature = "serde-serialize")]
mod test_dynamic_exportable_alias {
    use secure_gate::{dynamic_exportable_alias, Dynamic};

    dynamic_exportable_alias!(TestDynamicVec, Vec<u8>);

    #[test]
    fn test_dynamic_vec_creation_and_serialization() {
        // Test From impl
        let inner = TestDynamicVec::from(vec![42u8; 16]);
        assert_eq!(inner.inner.len(), 16);
        assert_eq!(inner.inner[0], 42);

        // Test wrapping in Dynamic
        let wrapped = Dynamic::new(inner);

        // Test serialization
        let json = serde_json::to_string(&wrapped).unwrap();
        // Should be a JSON array
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
    }

    dynamic_exportable_alias!(TestDynamicString, String);

    #[test]
    fn test_dynamic_string_creation_and_serialization() {
        let inner = TestDynamicString::from("hello".to_string());
        assert_eq!(inner.inner, "hello");

        let wrapped = Dynamic::new(inner);

        let json = serde_json::to_string(&wrapped).unwrap();
        // Should be a JSON string
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
    }

    dynamic_exportable_alias!(TestDynamicVecDoc, Vec<u8>, "Test doc");

    #[test]
    fn test_dynamic_with_doc() {
        let inner = TestDynamicVecDoc::from(vec![1u8; 8]);
        let wrapped = Dynamic::new(inner);
        let _json = serde_json::to_string(&wrapped).unwrap();
    }
}

mod test_dynamic_exportable_no_serde {
    use secure_gate::dynamic_exportable_alias;

    dynamic_exportable_alias!(TestNoSerdeVec, Vec<u8>);

    #[test]
    fn test_dynamic_no_serde() {
        let inner = TestNoSerdeVec::from(vec![2u8; 4]);
        assert_eq!(inner.inner.len(), 4);
    }
}

#[test]
fn dummy() {
    // No-op test
}
