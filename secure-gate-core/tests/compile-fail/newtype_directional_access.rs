//! Base-wrapper access is split by direction. `IntoWrapper` adds only the
//! outbound accessors; `FromWrapper` adds only the inbound constructor. A
//! boundary type that opts into `IntoWrapper` must not gain `from_wrapper`.
use secure_gate::{Dynamic, dynamic_newtype};

dynamic_newtype!(pub PublicId, String, derive: [IntoWrapper]);
dynamic_newtype!(pub FileId, String, derive: [FromWrapper]);

fn main() {
    let base: Dynamic<String> = Dynamic::from("x");
    let _p = PublicId::from_wrapper(base); // not opted in

    let f = FileId::new("y");
    let _b: Dynamic<String> = f.into_wrapper(); // not opted in
}
