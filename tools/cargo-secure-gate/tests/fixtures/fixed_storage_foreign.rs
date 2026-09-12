// The asserted type's field is defined outside the scanned files.
// Must be reported as unresolved: the assertion may well be correct.
use secure_gate::FixedStorage;

struct Wrapped {
    inner: some_other_crate::Opaque,
}
impl FixedStorage for Wrapped {}
