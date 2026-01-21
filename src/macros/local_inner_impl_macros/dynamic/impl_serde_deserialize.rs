/// Macro to implement serde Deserialize for Dynamic-like secret wrapper types.
///
/// This provides safe deserialization for Dynamic types by delegating to the inner type's Deserialize.
/// Requires the "serde-deserialize" feature.
#[doc(hidden)]
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
