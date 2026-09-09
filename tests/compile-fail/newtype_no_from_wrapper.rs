//! R2: a newtype must not be reachable from its base wrapper by `.into()`.
//!
//! In a mixed tree some aliases stay plain (`FileId` here is still a synonym
//! for `Dynamic<String>`) while others become newtypes. If the macro generated
//! `From<Dynamic<String>>`, an alias-typed value would flow into the newtype
//! through a one-line `.into()`, and distinctness would buy nothing.
use secure_gate::{dynamic_alias, dynamic_newtype, fixed_alias, fixed_newtype};

dynamic_alias!(pub FileId, String);
dynamic_newtype!(pub PublicId, String);
fixed_alias!(pub VaultKey32, 32);
fixed_newtype!(pub FileKey32, 32);

fn main() {
    let file_id: FileId = "never-crosses-ipc".into();
    let _leaked: PublicId = file_id.into();

    let vault: VaultKey32 = [7u8; 32].into();
    let _per_file: FileKey32 = vault.into();
}
