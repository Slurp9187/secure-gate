// tests/common/mod.rs
// ← DELETE THIS ENTIRE FILE WHEN PUBLISHING 1.0.0 →
//
// Temporary bridge for 0.4.0 → 1.0.0 transition
// Makes every existing test compile unchanged

#![allow(deprecated)]
use secure_gate::deprecated::*;

// Re-export the most common old names so imports aren’t even needed
pub use secure_gate::secure;
pub use secure_gate::secure_new;
pub use secure_gate::Secure;
pub use secure_gate::SecureBytes;
pub use secure_gate::SecureKey32;
pub use secure_gate::SecurePassword;
pub use secure_gate::SecureStr;
// add more if you use them heavily
