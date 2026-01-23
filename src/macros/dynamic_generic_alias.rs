/// Creates a generic dynamic-sized heap-allocated secure secret type.
///
/// This macro generates a type alias to `Dynamic<T>` with a custom doc string.
/// Useful for libraries providing generic dynamic-sized secret wrappers.
///
/// # Examples
///
/// With custom doc:
/// ```
/// use secure_gate::dynamic_generic_alias;
/// dynamic_generic_alias!(pub SecureVec, "Secure dynamic byte vector");
/// ```
///
/// With default doc:
/// ```
/// use secure_gate::dynamic_generic_alias;
/// dynamic_generic_alias!(pub(crate) Wrapper);
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
