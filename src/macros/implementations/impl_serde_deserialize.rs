/// Macro to implement serde Deserialize for secret wrapper types.
///
/// This provides safe deserialization by delegating to the inner type's Deserialize.
/// Requires the "serde-deserialize" feature.
/// Macro to implement serde Deserialize for Fixed-like secret wrapper types.
///
/// This provides safe deserialization for Fixed types by delegating to the inner type's Deserialize.
/// Requires the "serde-deserialize" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_serde_deserialize_fixed {
    ($type:ty) => {
        /// Serde deserialization support (unconditional; requires serde-deserialize feature).
        #[cfg(feature = "serde-deserialize")]
        impl<'de, T> serde::Deserialize<'de> for $type
        where
            T: serde::Deserialize<'de>,
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let inner = T::deserialize(deserializer)?;
                Ok(Self::new(inner))
            }
        }
    };
}

/// Macro to implement serde Deserialize for Dynamic-like secret wrapper types.
///
/// This provides safe deserialization for Dynamic types by delegating to the inner type's Deserialize.
/// Requires the "serde-deserialize" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_serde_deserialize_dynamic {
    ($type:ty) => {
        /// Serde deserialization support (always available with serde-deserialize feature).
        #[cfg(feature = "serde-deserialize")]
        impl<'de, T> serde::Deserialize<'de> for $type
        where
            T: serde::de::DeserializeOwned,
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let inner = T::deserialize(deserializer)?;
                Ok(Self::new(inner))
            }
        }
    };
}
