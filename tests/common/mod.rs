// tests/common/mod.rs
//
// Temporary bridge for 0.4.0 → 1.0.0 transition
// Makes every existing test compile unchanged
// Delete this entire file when publishing 1.0.0

#[allow(deprecated)] // ← Suppresses deprecation warnings in all tests
use secure_gate::deprecated::*;

// Re-export common old names so tests don't need extra imports
pub use secure_gate::secure;
pub use secure_gate::secure_new;
pub use secure_gate::Secure;
pub use secure_gate::SecureBytes;
pub use secure_gate::SecureKey32;
pub use secure_gate::SecurePassword;
pub use secure_gate::SecureStr;
