#![cfg(feature = "sealed")]
//! Does the stack scrub also run when an access ends by panicking? Same method as
//! probe_stack.rs: commit and zero the stack, do one thing, read 48 KiB below the test frame.
use secure_gate::{Fixed, Prekey, SealedFixed};
use std::hint::black_box;
use std::panic::{AssertUnwindSafe, catch_unwind};

const SPAN: usize = 48 * 1024;

#[inline(never)]
fn commit_stack() {
    let mut a = [0u8; 96 * 1024];
    black_box(&mut a);
}

#[inline(never)]
fn access(s: &SealedFixed<32>) -> u8 {
    s.with_secret(|b| black_box(b[0]))
}

#[inline(never)]
fn access_panics(s: &SealedFixed<32>) {
    let r = catch_unwind(AssertUnwindSafe(|| {
        s.with_secret(|b| {
            black_box(b[0]);
            panic!("closure failed")
        })
    }));
    assert!(r.is_err());
}

#[inline(never)]
fn access_mut_panics(s: &mut SealedFixed<32>) {
    let r = catch_unwind(AssertUnwindSafe(|| {
        s.with_secret_mut(|b| {
            black_box(b[0]);
            panic!("closure failed")
        })
    }));
    assert!(r.is_err());
}

#[inline(never)]
fn corrupt_open_panics(s: &SealedFixed<32>) {
    let r = catch_unwind(AssertUnwindSafe(|| s.with_secret(|b| black_box(b[0]))));
    assert!(r.is_err(), "a flipped ciphertext byte must fail to authenticate");
}

#[inline(never)]
fn unseal_once(s: SealedFixed<32>) -> u8 {
    use secure_gate::RevealSecret;
    s.unseal().expose_secret()[0]
}

#[inline(never)]
fn snapshot(top: usize, out: &mut [u8]) {
    let start = top - 64 - out.len();
    for i in 0..out.len() {
        out[i] = unsafe { core::ptr::read_volatile((start + i) as *const u8) };
    }
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

#[inline(never)]
fn key_vec(s: &SealedFixed<32>) -> Vec<u8> {
    s.__probe_key().to_vec()
}

fn run(label: &str) {
    let marker = 0u8;
    let top = black_box(&marker as *const u8 as usize);
    let prekey = Prekey::new();
    let plain: Vec<u8> = (0..32u8).map(|i| 0x5A ^ i.wrapping_mul(37)).collect();
    let mut s = SealedFixed::<32>::seal(
        Fixed::new_with(|b: &mut [u8; 32]| b.copy_from_slice(&plain)),
        &prekey,
    );
    let mut c = SealedFixed::<32>::seal(
        Fixed::new_with(|b: &mut [u8; 32]| b.copy_from_slice(&plain)),
        &prekey,
    );
    let mut snap = vec![0u8; SPAN];
    let k0 = key_vec(&s);
    let kc = key_vec(&c);
    c.__probe_flip();

    commit_stack();
    snapshot(top, &mut snap);
    println!(
        "[{label}] baseline: key hits={} plaintext hits={}",
        count(&snap, &k0),
        count(&snap, &plain)
    );

    commit_stack();
    black_box(access(&s));
    snapshot(top, &mut snap);
    println!(
        "[{label}] with_secret, normal return: key hits={} plaintext hits={}",
        count(&snap, &k0),
        count(&snap, &plain)
    );

    commit_stack();
    access_panics(&s);
    snapshot(top, &mut snap);
    println!(
        "[{label}] with_secret, closure panics: key hits={} plaintext hits={}",
        count(&snap, &k0),
        count(&snap, &plain)
    );

    commit_stack();
    access_mut_panics(&mut s);
    snapshot(top, &mut snap);
    println!(
        "[{label}] with_secret_mut, closure panics: key hits={} plaintext hits={}",
        count(&snap, &k0),
        count(&snap, &plain)
    );

    let u = SealedFixed::<32>::seal(
        Fixed::new_with(|b: &mut [u8; 32]| b.copy_from_slice(&plain)),
        &prekey,
    );
    let ku = key_vec(&u);
    commit_stack();
    black_box(unseal_once(u));
    snapshot(top, &mut snap);
    println!(
        "[{label}] unseal, result dropped: key hits={} plaintext hits={}",
        count(&snap, &ku),
        count(&snap, &plain)
    );

    commit_stack();
    corrupt_open_panics(&c);
    snapshot(top, &mut snap);
    println!(
        "[{label}] with_secret, tag mismatch panics: key hits={}",
        count(&snap, &kc)
    );
}

#[test]
fn probe_panic_paths_default_hook() {
    run("default hook");
}

#[test]
fn probe_panic_paths_silent_hook() {
    std::panic::set_hook(Box::new(|_| {}));
    run("silent hook");
    let _ = std::panic::take_hook();
}
