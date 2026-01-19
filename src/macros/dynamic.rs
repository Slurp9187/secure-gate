/// Creates a type alias for a heap-allocated secure secret with optional custom documentation.
///
/// # Syntax
///
/// - `dynamic_alias!(vis Name, Type);` — visibility required (e.g., `pub`, `pub(crate)`, or omit for private)
/// - `dynamic_alias!(vis Name, Type, doc);` — with optional custom doc string
///
/// # Examples
///
/// Public alias:
/// ```
/// use secure_gate::{dynamic_alias, ExposeSecret};
/// dynamic_alias!(pub Password, String);
/// let pw: Password = "hunter2".into();
/// assert_eq!(pw.expose_secret(), "hunter2");
/// ```
///
/// Private alias:
/// ```
/// use secure_gate::{dynamic_alias, ExposeSecret};
/// dynamic_alias!(SecretString, String); // No visibility modifier = private
/// let secret = SecretString::new("hidden".to_string());
/// ```
///
/// With custom documentation:
/// ```
/// use secure_gate::{dynamic_alias, ExposeSecret};
/// dynamic_alias!(pub Token, Vec<u8>, "OAuth token for API access");
/// let token: Token = vec![1, 2, 3].into();
/// ```
#[macro_export]
macro_rules! dynamic_alias {
    ($vis:vis $name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($vis:vis $name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        type $name = $crate::Dynamic<$inner>;
    };
    ($name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        type $name = $crate::Dynamic<$inner>;
    };
}

/// Creates a generic heap-allocated secure secret type alias.
///
/// # Examples
///
/// ```
/// use secure_gate::{dynamic_generic_alias, ExposeSecret};
/// dynamic_generic_alias!(pub SecureVec, Vec<u8>, "Secure dynamic byte vector");
/// let vec = SecureVec::new(vec![1, 2, 3]);
/// assert_eq!(vec.len(), 3);
/// ```
#[macro_export]
macro_rules! dynamic_generic_alias {
    ($vis:vis $name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($vis:vis $name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        $vis type $name = $crate::Dynamic<$inner>;
    };
}

/// Creates a type alias for a heap-allocated exportable secret (opt-in serialization).
///
/// This macro generates an inner newtype for raw dynamic data (Vec<u8> or String), implements SerializableSecret for opt-in serialization,
/// and creates a type alias to `Dynamic<Inner>`. For encoded types (e.g., HexString), it creates an alias with Serialize forwarding to the encoded string.
///
/// Requires the "serde-serialize" feature to compile.
///
/// # Syntax
///
/// - `dynamic_exportable_alias!(vis Name, inner_ty);` — for raw (`Vec<u8>`/String) or encoded types
/// - `dynamic_exportable_alias!(vis Name, inner_ty, doc);` — with optional custom doc string
///
/// # Security Warning
///
/// For raw types, only use where raw serialization is necessary and secure. For encoded, prefer for non-sensitive encoded forms.
#[macro_export]
macro_rules! dynamic_exportable_alias {
    // Raw Vec<u8>
    ($vis:vis $name:ident, Vec<u8>, $doc:literal) => {
        #[doc = $doc]
        $vis struct $name {
            pub inner: Vec<u8>,
        }

        #[cfg(feature = "serde-serialize")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.inner.serialize(serializer)
            }
        }

        #[cfg(feature = "serde-serialize")]
        impl $crate::SerializableSecret for $name {}

        impl From<Vec<u8>> for $name {
            fn from(v: Vec<u8>) -> Self {
                Self { inner: v }
            }
        }
    };
    ($vis:vis $name:ident, Vec<u8>) => {
        #[doc = "Dynamic exportable byte vector"]
        $vis struct $name {
            pub inner: Vec<u8>,
        }

        #[cfg(feature = "serde-serialize")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.inner.serialize(serializer)
            }
        }

        #[cfg(feature = "serde-serialize")]
        impl $crate::SerializableSecret for $name {}

        impl From<Vec<u8>> for $name {
            fn from(v: Vec<u8>) -> Self {
                Self { inner: v }
            }
        }
    };
    // Raw String
    ($vis:vis $name:ident, String, $doc:literal) => {
        #[doc = $doc]
        $vis struct $name {
            pub inner: String,
        }

        #[cfg(feature = "serde-serialize")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.inner.serialize(serializer)
            }
        }

        #[cfg(feature = "serde-serialize")]
        impl $crate::SerializableSecret for $name {}

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self { inner: s }
            }
        }
    };
    ($vis:vis $name:ident, String) => {
        #[doc = "Dynamic exportable string"]
        $vis struct $name {
            pub inner: String,
        }

        #[cfg(feature = "serde-serialize")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.inner.serialize(serializer)
            }
        }

        #[cfg(feature = "serde-serialize")]
        impl $crate::SerializableSecret for $name {}

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self { inner: s }
            }
        }
    };
    // Encoded (forward to encoded Serialize)
    ($vis:vis $name:ident, $encoded:ty, $doc:literal) => {
        #[doc = $doc]
        $vis type $name = $crate::Dynamic<$encoded>;

        #[cfg(feature = "serde-serialize")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.expose_secret().expose_secret().serialize(serializer)
            }
        }
    };
    ($vis:vis $name:ident, $encoded:ty) => {
        #[doc = concat!("Dynamic encoded secret (", stringify!($encoded), ")")]
        $vis type $name = $crate::Dynamic<$encoded>;

        #[cfg(feature = "serde-serialize")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.expose_secret().expose_secret().serialize(serializer)
            }
        }
    };
}
