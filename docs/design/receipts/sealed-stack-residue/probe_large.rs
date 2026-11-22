#![cfg(feature = "sealed")]
//! Large keys: a `SealedFixed<N>` access keeps N bytes of plaintext on the stack, and each
//! by-value move of it can leave a copy deeper down, so the scrub has to reach further the
//! larger N is. N = 40,000 is past the point where the first 32 KiB frame stops covering it
//! in both profiles. Runs on a 64 MiB thread: a debug build's role access alone uses about
//! 9·N of stack.
use secure_gate::{fixed_newtype, sealed_fixed_newtype, Fixed, Prekey, SealedFixed};
use std::hint::black_box;
use std::sync::Arc;

const N: usize = 40_000;
const SPAN: usize = 768 * 1024;
const PERIOD: usize = 61;

fixed_newtype!(pub BigKey, 40_000);
sealed_fixed_newtype!(pub SealedBigKey, BigKey);

#[inline(never)]
fn commit_stack() { let mut a = [0u8; 1024 * 1024]; black_box(&mut a); }

/// Reads the SPAN bytes below `top` (an address in the caller's frame).
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

/// Repeats every PERIOD bytes, so any copy of PERIOD bytes or more of it is found.
fn pattern() -> Vec<u8> { (0..N).map(|i| ((i % PERIOD) as u8).wrapping_mul(7) ^ 0xC3).collect() }

#[inline(never)]
fn access(s: &SealedFixed<N>) { s.with_secret(|b| { black_box(b); }) }
#[inline(never)]
fn access_mut(s: &mut SealedFixed<N>) { s.with_secret_mut(|b| { black_box(b); }) }
#[inline(never)]
fn role(s: &SealedBigKey) { s.with_role(|k| { black_box(k); }) }
#[inline(never)]
fn role_mut(s: &mut SealedBigKey) { s.with_role_mut(|k| { black_box(k); }) }
#[inline(never)]
fn key_vec(s: &SealedFixed<N>) -> Vec<u8> { s.__probe_key().to_vec() }

#[inline(never)]
fn seal_plain(p: &Arc<Prekey>, src: &[u8]) -> Box<SealedFixed<N>> {
    Box::new(SealedFixed::seal(Fixed::new_with(|b: &mut [u8; N]| b.copy_from_slice(src)), p))
}
#[inline(never)]
fn seal_role(p: &Arc<Prekey>, src: &[u8]) -> Box<SealedBigKey> {
    Box::new(SealedBigKey::seal(BigKey::new_with(|b: &mut [u8; N]| b.copy_from_slice(src)), p))
}

fn run() {
    let marker = 0u8;
    let top = black_box(&marker as *const u8 as usize);
    let prekey = Prekey::new();
    let plain = pattern();
    let needle = &plain[..PERIOD];
    let mut snap = vec![0u8; SPAN];

    commit_stack();
    snapshot(top, &mut snap);
    println!("large baseline after wipe: plaintext hits={}", count(&snap, needle));

    let mut s = seal_plain(&prekey, &plain);
    commit_stack();
    access(&s);
    snapshot(top, &mut snap);
    let k0 = key_vec(&s);
    println!("large with_secret: key hits={} plaintext hits={}", count(&snap, &k0), count(&snap, needle));

    commit_stack();
    access_mut(&mut s);
    snapshot(top, &mut snap);
    let k1 = key_vec(&s);
    println!("large with_secret_mut: old key hits={} new key hits={} plaintext hits={}",
        count(&snap, &k0), count(&snap, &k1), count(&snap, needle));

    let mut r = seal_role(&prekey, &plain);
    commit_stack();
    role(&r);
    snapshot(top, &mut snap);
    println!("large with_role: plaintext hits={}", count(&snap, needle));

    commit_stack();
    role_mut(&mut r);
    snapshot(top, &mut snap);
    println!("large with_role_mut: plaintext hits={}", count(&snap, needle));
}

#[test]
fn probe() {
    std::thread::Builder::new().stack_size(64 << 20).spawn(run).unwrap().join().unwrap();
}
