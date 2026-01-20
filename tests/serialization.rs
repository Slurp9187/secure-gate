#[cfg(feature = "serde-serialize")]
use secure_gate::ExportableArray;
#[cfg(feature = "serde-serialize")]
use secure_gate::{Dynamic, ExposeSecret, Fixed};

#[cfg(feature = "serde-serialize")]
mod exportable_roundtrips {
    use super::*;
    use secure_gate::{ExportableArray, ExportableString, ExportableVec};

    #[test]
    fn exportable_array_roundtrip() {
        let original: ExportableArray<4> = [1, 2, 3, 4].into();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "[1,2,3,4]");

        let deserialized: Fixed<[u8; 4]> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expose_secret(), &[1, 2, 3, 4]);
    }

    #[test]
    fn exportable_vec_roundtrip() {
        let original: ExportableVec = vec![10, 20, 30].into();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "[10,20,30]");

        let deserialized: Dynamic<Vec<u8>> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expose_secret(), &[10, 20, 30]);
    }

    #[test]
    fn exportable_string_roundtrip() {
        let original: ExportableString = "test".into();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"test\"");

        let deserialized: Dynamic<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expose_secret(), "test");
    }
}

#[cfg(all(feature = "serde-serialize", feature = "encoding-hex"))]
mod encoded_conversions {
    use super::*;
    use secure_gate::{encoding::hex::HexString, ExportableString, ExportableVec};

    #[test]
    fn hex_to_exportable_vec_roundtrip() {
        let hex = HexString::new("deadbeef".to_string()).unwrap();
        let exportable: ExportableVec = hex.into();
        let json = serde_json::to_string(&exportable).unwrap();
        assert_eq!(json, "[222,173,190,239]"); // Decoded bytes

        let deserialized: Dynamic<Vec<u8>> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expose_secret(), &[222, 173, 190, 239]);
    }

    #[test]
    fn hex_to_exportable_string() {
        let hex = HexString::new("cafebabe".to_string()).unwrap();
        let exportable: ExportableString = hex.into();
        let json = serde_json::to_string(&exportable).unwrap();
        assert_eq!(json, "\"cafebabe\""); // Encoded string

        let deserialized: Dynamic<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expose_secret(), "cafebabe");
    }
}

#[cfg(feature = "serde-serialize")]
mod conversions {
    use super::*;
    use secure_gate::{ExportableArray, ExportableString, ExportableVec};

    #[cfg(feature = "zeroize")]
    use secure_gate::{CloneableArray, CloneableString, CloneableVec};

    #[test]
    fn core_to_exportable_conversions() {
        // Fixed to ExportableArray
        let fixed: Fixed<[u8; 3]> = Fixed::new([5, 6, 7]);
        let exportable: ExportableArray<3> = fixed.into();
        let json = serde_json::to_string(&exportable).unwrap();
        assert_eq!(json, "[5,6,7]");

        // Dynamic to ExportableVec
        let dynamic: Dynamic<Vec<u8>> = Dynamic::new(vec![8, 9, 10]);
        let exportable: ExportableVec = dynamic.into();
        let json = serde_json::to_string(&exportable).unwrap();
        assert_eq!(json, "[8,9,10]");

        // Dynamic to ExportableString
        let dynamic: Dynamic<String> = Dynamic::new("hello".to_string());
        let exportable: ExportableString = dynamic.into();
        let json = serde_json::to_string(&exportable).unwrap();
        assert_eq!(json, "\"hello\"");
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn cloneable_to_exportable_conversions() {
        // CloneableArray to ExportableArray
        let cloneable: CloneableArray<2> = [11, 12].into();
        let exportable: ExportableArray<2> = cloneable.into();
        let json = serde_json::to_string(&exportable).unwrap();
        assert_eq!(json, "[11,12]");

        // CloneableVec to ExportableVec
        let cloneable: CloneableVec = vec![13, 14, 15].into();
        let exportable: ExportableVec = cloneable.into();
        let json = serde_json::to_string(&exportable).unwrap();
        assert_eq!(json, "[13,14,15]");

        // CloneableString to ExportableString
        let cloneable: CloneableString = "world".into();
        let exportable: ExportableString = cloneable.into();
        let json = serde_json::to_string(&exportable).unwrap();
        assert_eq!(json, "\"world\"");
    }

    #[cfg(feature = "rand")]
    #[test]
    fn random_to_exportable_conversions() {
        use secure_gate::random::{DynamicRandom, FixedRandom};

        // FixedRandom to ExportableArray
        let random: FixedRandom<4> = FixedRandom::generate();
        let fixed: Fixed<[u8; 4]> = random.into();
        let exportable: ExportableArray<4> = fixed.into();
        let json = serde_json::to_string(&exportable).unwrap();
        // JSON should be an array of 4 bytes
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        let deserialized: Fixed<[u8; 4]> = serde_json::from_str(&json).unwrap();
        // Since it's random, just check it deserializes correctly (non-zero bytes likely)
        assert_eq!(deserialized.expose_secret().len(), 4);

        // DynamicRandom to ExportableVec
        let random: DynamicRandom = DynamicRandom::generate(3);
        let dynamic: Dynamic<Vec<u8>> = random.into();
        let exportable: ExportableVec = dynamic.into();
        let json = serde_json::to_string(&exportable).unwrap();
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        let deserialized: Dynamic<Vec<u8>> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expose_secret().len(), 3);
    }
}

#[cfg(feature = "serde-serialize")]
#[test]
fn exportable_serialization_requires_feature() {
    // This test is a no-op but documents that Exportable* types require serde-serialize
    // Without the feature, these types don't exist, preventing compilation.
}

#[cfg(feature = "serde-serialize")]
#[test]
fn no_direct_core_serialization_without_marker() {
    // Core Fixed<T> doesn't serialize unless T: ExportableType
    let fixed: Fixed<[u8; 2]> = Fixed::new([1, 2]);
    // This would fail to compile if attempted: serde_json::to_string(&fixed);
    // Instead, convert to Exportable*
    let exportable: ExportableArray<2> = fixed.into();
    let json = serde_json::to_string(&exportable).unwrap();
    assert_eq!(json, "[1,2]");
}
