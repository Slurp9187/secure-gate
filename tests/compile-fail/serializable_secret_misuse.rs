// This should fail to compile without the SerializableSecret marker
// NOTE: compile-fail test for serializable_secret_misuse is temporarily disabled due to
// trybuild snapshot drift between stable/nightly. Behavior is still verified via runtime
// tests in core_tests.rs and integration suite.
use secure_gate::{Dynamic, Fixed};

#[derive(serde::Serialize, serde::Deserialize)]
struct BadSecret(Vec<u8>);

fn main() {
    let _ = serde_json::to_string(&Dynamic::<BadSecret>::new(BadSecret(vec![])));
    //~^ ERROR the trait bound `BadSecret: zeroize::DefaultIsZeroes` is not satisfied
    //~| HELP the trait `zeroize::DefaultIsZeroes` is not implemented for `BadSecret`
    //~| NOTE required for `BadSecret` to implement `zeroize::Zeroize`
    //~| NOTE required by a bound in `Dynamic`

    let _ = serde_json::to_string(&Fixed::<[u8; 32]>::new([0; 32]));
    //~^ ERROR the trait bound `[u8; 32]: SerializableSecret` is not satisfied
    //~| HELP the trait `Serialize` is implemented for `Fixed<T>`
    //~| NOTE required for `Fixed<[u8; 32]>` to implement `Serialize`
}
