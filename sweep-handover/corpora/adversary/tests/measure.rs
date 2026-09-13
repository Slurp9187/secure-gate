//! Watch-mode allocator instrument, in the style of
//! /home/user/secure-gate/tests/lifecycle_trace_heap.rs: `realloc` is deliberately
//! NOT overridden, so a Vec/String capacity change routes through alloc+copy+dealloc
//! and the abandoned block passes through `dealloc` where its bytes can be counted.
//! This forces the worst case on purpose.
use atk_consumer::evade::*;
use secure_gate::{Dynamic, Fixed, RevealSecret, RevealSecretMut};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use zeroize::Zeroize;

static WATCH_ACTIVE: AtomicBool = AtomicBool::new(false);
static WATCH_PTR: AtomicUsize = AtomicUsize::new(0);
static WATCH_HITS: AtomicUsize = AtomicUsize::new(0);
static WATCH_SIZE: AtomicUsize = AtomicUsize::new(0);
static WATCH_NONZERO: AtomicUsize = AtomicUsize::new(0);

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Proxy;
unsafe impl GlobalAlloc for Proxy {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, l: Layout) {
        if WATCH_ACTIVE.load(Ordering::SeqCst) && ptr as usize == WATCH_PTR.load(Ordering::SeqCst) {
            let nz = (0..l.size())
                .filter(|&i| unsafe { core::ptr::read(ptr.add(i)) } != 0)
                .count();
            WATCH_SIZE.store(l.size(), Ordering::SeqCst);
            WATCH_NONZERO.store(nz, Ordering::SeqCst);
            WATCH_HITS.fetch_add(1, Ordering::SeqCst);
            WATCH_ACTIVE.store(false, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, l) }
    }
}
#[global_allocator]
static P: Proxy = Proxy;

struct WatchGuard;
impl Drop for WatchGuard {
    fn drop(&mut self) {
        WATCH_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Watch `ptr` across `f`; returns (freed, inspected_bytes, nonzero_bytes).
fn watch<F: FnOnce()>(ptr: *const u8, f: F) -> (bool, usize, usize) {
    WATCH_HITS.store(0, Ordering::SeqCst);
    WATCH_SIZE.store(0, Ordering::SeqCst);
    WATCH_NONZERO.store(0, Ordering::SeqCst);
    WATCH_PTR.store(ptr as usize, Ordering::SeqCst);
    WATCH_ACTIVE.store(true, Ordering::SeqCst);
    let _g = WatchGuard;
    f();
    WATCH_ACTIVE.store(false, Ordering::SeqCst);
    (
        WATCH_HITS.load(Ordering::SeqCst) > 0,
        WATCH_SIZE.load(Ordering::SeqCst),
        WATCH_NONZERO.load(Ordering::SeqCst),
    )
}

const PAY: u8 = 0xD7;
const CAP: usize = 1008;

/// A Vec filled to exactly capacity CAP with non-zero payload. Growing it by one
/// byte must reallocate.
fn full_vec() -> Vec<u8> {
    let mut v = Vec::with_capacity(CAP);
    v.resize(CAP, PAY);
    assert_eq!(v.capacity(), CAP);
    assert_eq!(v.len(), CAP);
    v
}

fn report(name: &str, freed: bool, size: usize, nz: usize) {
    println!("{name:<28} freed={freed} inspected={size} nonzero={nz}");
    assert!(freed, "{name}: watched block was never released - nothing abandoned, so there is nothing to measure (in-place resize)");
    assert!(nz > 0, "{name}: abandoned block held no secret bytes");
}

#[test]
fn correct_code_leaks_nothing() {
    use atk_consumer::good::*;
    // FP5: zeroize() then extend_from_slice. The tool reports HIGH severity.
    {
        let mut d = Dynamic::new(full_vec());
        let p = d.with_secret(|v: &Vec<u8>| v.as_ptr());
        let longer = vec![0x5Au8; CAP * 2];
        let (f, s, nz) = watch(p, || fp5_refill(&mut d, &longer));
        println!("FP5 zeroize+grow        freed={f} inspected={s} nonzero={nz}");
        assert!(f, "FP5: the old buffer WAS abandoned (so the route is real)");
        assert_eq!(nz, 0, "FP5 leaked {nz} bytes");
    }
    // FP2/FP3/FP4: inline storage only. Count heap traffic across the whole op.
    {
        let mut k: Fixed<[u8; 32]> = Fixed::new([1u8; 32]);
        let mut c: Fixed<u64> = Fixed::new(7);
        let mut b = Fixed::new(make_arraybuf());
        let before = ALLOCS.load(Ordering::SeqCst);
        fp2_rotate(&mut k, [2u8; 32]);
        fp3_bump(&mut c);
        fp4_append(&mut b, 0x9E);
        let after = ALLOCS.load(Ordering::SeqCst);
        println!("FP2+FP3+FP4 allocations = {}", after - before);
        assert_eq!(after - before, 0, "inline-storage ops allocated");
    }
}

#[test]
fn evasions_leak_for_real() {
    // ---- E1 field access through a composite secret in Dynamic ----
    {
        let mut d = Dynamic::new(Session { id: [9u8; 8], token: full_vec() });
        let (_, p) = e1_cap(&d);
        let (f, s, nz) = watch(p, || e1_grow(&mut d, PAY));
        report("E1 field push", f, s, nz);
        d.with_secret(|s| assert_eq!(s.token.len(), CAP + 1));
    }
    // ---- E2 rebind inside the closure ----
    {
        let mut d = Dynamic::new(full_vec());
        let p = d.with_secret(|v: &Vec<u8>| v.as_ptr());
        let (f, s, nz) = watch(p, || e2_grow(&mut d, PAY));
        report("E2 rebind", f, s, nz);
    }
    // ---- E3 UFCS trait call ----
    {
        let mut d = Dynamic::new(full_vec());
        let p = d.with_secret(|v: &Vec<u8>| v.as_ptr());
        let (f, s, nz) = watch(p, || e3_grow(&mut d, PAY));
        report("E3 UFCS trait", f, s, nz);
    }
    // ---- E4 fn item as the closure ----
    {
        let mut d = Dynamic::new(full_vec());
        let p = d.with_secret(|v: &Vec<u8>| v.as_ptr());
        let (f, s, nz) = watch(p, || e4_grow(&mut d));
        report("E4 fn item", f, s, nz);
    }
    // ---- E5 clone_from ----
    {
        let mut d = Dynamic::new(full_vec());
        let p = d.with_secret(|v: &Vec<u8>| v.as_ptr());
        let longer = vec![PAY; CAP * 2];
        let (f, s, nz) = watch(p, || e5_grow(&mut d, &longer));
        report("E5 clone_from", f, s, nz);
    }
    // ---- E6 UFCS Vec::push ----
    {
        let mut d = Dynamic::new(full_vec());
        let p = d.with_secret(|v: &Vec<u8>| v.as_ptr());
        let (f, s, nz) = watch(p, || e6_grow(&mut d, PAY));
        report("E6 UFCS Vec::push", f, s, nz);
    }
    // ---- E7 lying marker, non-ASCII name: growth INSIDE Fixed inline storage ----
    {
        let mut k = e7_build(full_vec());
        let p = k.with_secret(|x| x.payload.as_ptr());
        let (f, s, nz) = watch(p, || {
            k.with_secret_mut(|x| x.payload.push(PAY));
        });
        report("E7 Fixed<Ключ> push", f, s, nz);
    }
    // ---- E8 growable field behind a type alias ----
    {
        let mut w = e8_build(full_vec());
        let p = w.with_secret(|x| x.body.as_ptr());
        let (f, s, nz) = watch(p, || {
            w.with_secret_mut(|x| x.body.push(PAY));
        });
        report("E8 Fixed<Sneaky> push", f, s, nz);
    }
    // ---- E9 generic carrier ----
    {
        let mut h = e9_build(full_vec());
        let p = h.with_secret(|x| x.0.as_ptr());
        let (f, s, nz) = watch(p, || {
            h.with_secret_mut(|x| x.0.push(PAY));
        });
        report("E9 Fixed<Holder<Vec>>", f, s, nz);
    }
    // ---- E10 helper fn ----
    {
        let mut d = Dynamic::new(full_vec());
        let p = d.with_secret(|v: &Vec<u8>| v.as_ptr());
        let (f, s, nz) = watch(p, || e10_grow(&mut d, PAY));
        report("E10 helper fn", f, s, nz);
    }
    // ---- E11 renamed import + reborrow ----
    {
        let mut d: Fixed<[u8; 4]> = Fixed::new([0; 4]);
        d.zeroize();
        let mut d = Dynamic::new(full_vec());
        let p = d.with_secret(|v: &Vec<u8>| v.as_ptr());
        let (f, s, nz) = watch(p, || e11_grow(&mut d, PAY));
        report("E11 renamed+reborrow", f, s, nz);
    }
}
