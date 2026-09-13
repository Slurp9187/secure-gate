//! More generic buffer utilities. Like `util_pad`, this file imports nothing from `secure-gate` and
//! names no secret type, so no access route anchors a window here.
//!
//! Everything in this module is the *mechanism* of a leak in some other file. Nothing in it is
//! wrong on its own: these are the routines any byte-wrangling crate has.

use std::fmt::Write as _;

/// A consumer's own trait for appending material. One crate's vocabulary.
pub trait Soak {
    fn soak(&mut self, material: &[u8]);
}

impl Soak for Vec<u8> {
    fn soak(&mut self, material: &[u8]) {
        self.extend_from_slice(material);
    }
}

/// A consumer's own trait for appending one byte.
pub trait Put {
    fn put(&mut self, byte: u8);
}

impl Put for Vec<u8> {
    fn put(&mut self, byte: u8) {
        self.push(byte);
    }
}

/// Formats a counter onto the end of a string, through `core::fmt::Write`.
pub fn stamp(text: &mut String, counter: u32) {
    let _ = write!(text, "#{counter}");
}

/// Rebuilds a buffer from its own contents: same length, same capacity, new allocation.
pub fn recode(buf: &mut Vec<u8>) {
    *buf = buf.iter().copied().collect();
}

/// Case-folds in place, by replacing the buffer.
pub fn upper(text: &mut String) {
    *text = text.to_uppercase();
}

/// A macro that expands to a growth. Exported from a module with no secret types in it; in a real
/// consumer it would as likely live in a separate utility crate, outside any sweep of this one.
#[macro_export]
macro_rules! absorb {
    ($target:expr, $material:expr) => {
        $target.extend_from_slice($material)
    };
}
