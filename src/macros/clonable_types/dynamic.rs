// Creates a cloneable type alias for a dynamic heap-allocated secure secret.
///
/// This macro generates a newtype around `Dynamic<T>` with implementations for `Clone` and `CloneableType`.
/// It inherits the security properties of `Dynamic` but allows explicit duplication via `Clone`.
///
/// # Syntax
///
/// `cloneable_dynamic_alias!(vis Name, Type);` — visibility required (e.g., `pub`), Type is the inner type like `String` or `Vec<u8>`
#[macro_export]
macro_rules! cloneable_dynamic_alias {
    ($vis:vis $name:ident, $type:ty) => {
        #[doc = concat!("Cloneable dynamic secure secret (", stringify!($type), ")")]
        $vis struct $name($crate::Dynamic<$type>);

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self($crate::Dynamic::new(self.0.expose_secret().clone()))
            }
        }

        impl $crate::CloneableType for $name {}

        impl $crate::ExposeSecret for $name {
            type Inner = $type;

            #[inline(always)]
            fn expose_secret(&self) -> &$type {
                self.0.expose_secret()
            }

            #[inline(always)]
            fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl From<$type> for $name {
            fn from(value: $type) -> Self {
                Self($crate::Dynamic::new(value))
            }
        }
    };
}
