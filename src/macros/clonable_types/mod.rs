// Creates cloneable type aliases for fixed-size and dynamic secure secrets.
mod dynamic;
///
/// This module provides macros to generate newtypes around `Fixed<[u8; N]>` and `Dynamic<T>`
/// with implementations for `Clone` and `CloneableType`, allowing explicit duplication while
/// maintaining security properties.
mod fixed;
