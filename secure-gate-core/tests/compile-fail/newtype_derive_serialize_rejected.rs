//! `derive: [Serialize]` must be rejected with an explanatory error.
//!
//! Serialization exposes the full secret; a generated impl would bypass the
//! `SerializableSecret` opt-in. Callers write it by hand if they mean it.
use secure_gate::{Fixed, __sg_newtype_base};

__sg_newtype_base!(pub BackupKey(Fixed<[u8; 32]>), derive: [Serialize]);

fn main() {}
