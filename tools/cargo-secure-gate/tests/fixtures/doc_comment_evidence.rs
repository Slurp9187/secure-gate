// A regex implementation sliced raw source for a struct body and flagged this
// at its highest severity, quoting the developer's own safety comment back as
// the evidence: documenting why a type is safe earned a CRITICAL.
// Must be clean -- a doc comment is an attribute, not a field.
use secure_gate::FixedStorage;

/// Deliberately not a `Vec<u8>`: the length is fixed at construction, so there
/// is no `String` or `Vec` here for a capacity change to abandon.
struct Safe {
    material: [u8; 32],
}
impl FixedStorage for Safe {}
