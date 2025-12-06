#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::{Dynamic, Fixed};

#[cfg(feature = "serde")]
impl<T: Serialize> Serialize for Fixed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Fixed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Fixed)
    }
}

#[cfg(feature = "serde")]
impl<T: ?Sized + Serialize> Serialize for Dynamic<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: ?Sized> Deserialize<'de> for Dynamic<T> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "Deserialization of Dynamic<T> is intentionally disabled for security reasons.\n\
             Secrets should never be automatically loaded from untrusted input.\n\
             Instead, deserialize into the inner type first, then wrap with Dynamic::new().",
        ))
    }
}
