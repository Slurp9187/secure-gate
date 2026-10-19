#![cfg(feature = "sealed")]
use secure_gate::{Fixed, Prekey, SealedFixed};
use std::hint::black_box;

const SPAN: usize = 48 * 1024;

#[inline(never)]
fn commit_stack() { let mut a = [0u8; 96 * 1024]; black_box(&mut a); }

#[inline(never)]
fn access(s: &SealedFixed<32>) -> u8 { s.with_secret(|b| black_box(b[0])) }

#[inline(never)]
fn access_mut(s: &mut SealedFixed<32>) { s.with_secret_mut(|b| { black_box(b); }) }

#[inline(never)]
fn leak_pattern(p: &[u8; 32]) { let mut a = [0u8; 32]; a.copy_from_slice(p); black_box(&mut a); }

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


#[inline(never)]
fn key_vec(s: &SealedFixed<32>) -> Vec<u8> { s.__probe_key().to_vec() }

#[test]
fn probe() {
    let marker = 0u8;
    let top = black_box(&marker as *const u8 as usize);
    let prekey = Prekey::new();
    let plain: Vec<u8> = (0..32u8).map(|i| 0x5A ^ i.wrapping_mul(37)).collect();
    let mut s = SealedFixed::<32>::seal(Fixed::new_with(|b: &mut [u8; 32]| b.copy_from_slice(&plain)), &prekey);
    let mut snap = vec![0u8; SPAN];
    let pat: Vec<u8> = vec![0xA7u8; 32];

    commit_stack();
    leak_pattern(&[0xA7u8; 32]);
    snapshot(top, &mut snap);
    println!("control hits={}", count(&snap, &pat));

    let k0 = key_vec(&s);
    commit_stack();
    snapshot(top, &mut snap);
    println!("baseline after wipe: key hits={} plaintext hits={}", count(&snap, &k0), count(&snap, &plain));

    commit_stack();
    black_box(access(&s));
    snapshot(top, &mut snap);
    println!("with_secret: key hits={} plaintext hits={}", count(&snap, &k0), count(&snap, &plain));
    for (i, w) in snap.windows(32).enumerate() { if w == &k0[..] { let pre = if i >= 16 { &snap[i-16..i] } else { &snap[..0] }; println!("  key at {i}, 16 bytes before = {:?}", String::from_utf8_lossy(pre)); } }
    for (i, w) in snap.windows(32).enumerate() { if w == &plain[..] { println!("  plaintext at {i}"); } }

    commit_stack();
    s.__probe_derive_only();
    snapshot(top, &mut snap);
    println!("sealing_key only (SHA-256 into Fixed, dropped): key hits={}", count(&snap, &k0));

    commit_stack();
    s.__probe_cipher_only();
    snapshot(top, &mut snap);
    println!("cipher only (key derived, ChaCha20Poly1305::new, dropped): key hits={}", count(&snap, &k0));

    commit_stack();
    access_mut(&mut s);
    snapshot(top, &mut snap);
    let k1 = key_vec(&s);
    println!("with_secret_mut: old key hits={} new key hits={} plaintext hits={}",
        count(&snap, &k0), count(&snap, &k1), count(&snap, &plain));
}
