
use std::alloc::{alloc, dealloc, Layout};
use zeroizing_alloc::ZeroAlloc;
#[global_allocator] static A: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);
#[inline(never)]
fn churn_small(pat: u8) { let v = vec![pat; 64]; std::hint::black_box(&v); }
#[inline(never)]
fn churn_bulk(pat: u8) { let v = vec![pat; 4096]; std::hint::black_box(&v); }
#[inline(never)]
fn recover(size: usize, iters: usize) -> (u32, bool) {
    let layout = Layout::from_size_align(size, 16).unwrap();
    let mut last = (0u32, false);
    for _ in 0..iters {
        unsafe {
            let p = alloc(layout);
            assert!(!p.is_null());
            core::ptr::write_bytes(p, 0xA5u8, size);
            std::hint::black_box(p);
            dealloc(p, layout);
            let q = alloc(layout);
            assert!(!q.is_null());
            let a = (q.add(16) as *const u64).read_volatile();
            let b = (q.add(24) as *const u64).read_volatile();
            let hits = a.to_ne_bytes().iter().chain(b.to_ne_bytes().iter()).filter(|&&x| x == 0xA5).count() as u32;
            last = (hits, q == p);
            core::ptr::write_bytes(q, 0u8, size);
            dealloc(q, layout);
        }
    }
    last
}
fn main() {
    for _ in 0..100_000 { churn_small(0xA5); churn_bulk(0x5A); }
    let iters = std::hint::black_box(300_000usize);
    for size in [64usize, 4096] {
        let (hits, same) = recover(size, iters);
        println!("RECOVER size={size} hits={hits} same={same}");
    }
}
