// The literal below was an AWS documentation example key. It is replaced with an
// unmistakably synthetic string: the original matches GitHub's AWS access-key-ID
// push-protection pattern, which can block a push outright. What this case tests --
// that a tool may copy a matched literal into its own output, and so into CI logs --
// is unchanged by the substitution.
pub fn prod() -> Dynamic<Vec<u8>> {
    Dynamic::from("EXAMPLE-NOT-A-REAL-KEY-0000/placeholder-secret")
}
