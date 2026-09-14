//! The secret roles this consumer declares. Ordinary, documented `secure-gate` usage.

use secure_gate::dynamic_newtype;

dynamic_newtype!(pub SessionToken, Vec<u8>, "Opaque session token bytes.");
dynamic_newtype!(pub Passphrase, String, "A user-supplied passphrase.");
dynamic_newtype!(
    pub ShardSet,
    generic Vec<Vec<u8>>,
    "A set of key shards, each an independent buffer.",
    derive: [WrapperAccess]
);
