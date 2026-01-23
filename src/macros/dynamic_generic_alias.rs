/// Creates a generic heap-allocated secure secret type alias.
///
/// # Examples
///
/// ```
/// use secure_gate::{dynamic_generic_alias, ExposeSecret};
/// dynamic_generic_alias!(pub SecureVec, "Secure dynamic byte vector");
/// let vec = SecureVec::<Vec<u8>>::new(vec![1, 2, 3]);
/// assert_eq!(vec.len(), 3);
/// ```
#[macro_export]
macro_rules! dynamic_generic_alias {
    ($vis:vis $name:ident, $doc:literal) => {
        #[doc = $doc]
        $vis type $name<T> = $crate::Dynamic<T>;
    };
    ($vis:vis $name:ident) => {
        #[doc = "Generic secure heap wrapper"]
        $vis type $name<T> = $crate::Dynamic<T>;
    };
}
