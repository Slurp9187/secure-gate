// ==========================================================================
// src/serde.rs
// ==========================================================================

#[cfg(feature = "serde")]
use serde::{de, ser, Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::{Dynamic, Fixed};

#[cfg(feature = "serde")]
impl<T> Serialize for Fixed<T> {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Err(ser::Error::custom(
            "serialization of Fixed<T> is intentionally disabled — secrets must never be automatically serialized",
        ))
    }
}

#[cfg(feature = "serde")]
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Fixed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Fixed::new)
    }
}

#[cfg(feature = "serde")]
impl<T: ?Sized> Serialize for Dynamic<T> {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Err(ser::Error::custom(
            "serialization of Dynamic<T> is intentionally disabled — secrets must never be automatically serialized",
        ))
    }
}

#[cfg(feature = "serde")]
impl<'de, T: ?Sized> Deserialize<'de> for Dynamic<T> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Err(de::Error::custom(
            "deserialization of Dynamic<T> is intentionally disabled for security reasons.\n\
             Secrets should never be automatically loaded from untrusted input.\n\
             Instead, deserialize into the inner type first, then wrap with Dynamic::new().",
        ))
    }
}
