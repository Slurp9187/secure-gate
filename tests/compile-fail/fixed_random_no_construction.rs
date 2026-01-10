// This file should NOT compile - it tests that FixedRandom cannot be constructed from bytes
// The freshness invariant requires FixedRandom values to only come from secure random generation
//
// This test is only relevant when the 'rand' feature is enabled, as FixedRandom only exists then.

#[cfg(feature = "rand")]
fn main() {
    use secure_gate::random::FixedRandom;

    // This should fail: no FixedRandom::new constructor
    let _bad = FixedRandom::<32>::new([0u8; 32]);

    // This should fail: no From<[u8; N]> impl for FixedRandom<N>
    let _bad2: FixedRandom<32> = [0u8; 32].into();

    // This should fail: no FixedRandom::from implementation
    let _bad3 = FixedRandom::<32>::from([0u8; 32]);
}

#[cfg(not(feature = "rand"))]
fn main() {
    // When rand feature is disabled, this test should not run at all
    // The compile-fail test runner will skip files that don't have a main function
    // or we'll just have an empty main that does nothing
}
