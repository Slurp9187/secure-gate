set -u
CARGO=/home/dev/.cargo/bin/cargo
RUSTC=/home/dev/.cargo/bin/rustc
ROOT=$HOME/pgo-compare
LIB=$ROOT/_strawman_lib
PROFDATA=$(find "$($RUSTC --print sysroot)" -name llvm-profdata -type f 2>/dev/null | head -1)

rm -rf "$LIB" "$ROOT/sw"; mkdir -p "$LIB/src" "$ROOT/sw/src"
cat > "$LIB/Cargo.toml" <<'EOF'
[package]
name = "strawman"
version = "0.0.0"
edition = "2021"
EOF
# verbatim from secure-gate-zalloc tests/recover.rs CONTROL_LIB
cat > "$LIB/src/lib.rs" <<'EOF'
#![no_std]
use core::alloc::{GlobalAlloc, Layout};
pub struct Wrap<A: GlobalAlloc>(pub A);
unsafe fn clear_bytes(ptr: *mut u8, len: usize) { ptr.write_bytes(0, len); }
#[used]
static WIPER: unsafe fn(*mut u8, usize) = clear_bytes;
#[inline]
unsafe fn zero(ptr: *mut u8, len: usize) {
    let wipe = core::ptr::read_volatile(&raw const WIPER);
    wipe(ptr, len);
}
unsafe impl<A: GlobalAlloc> GlobalAlloc for Wrap<A> {
    #[inline] unsafe fn alloc(&self, l: Layout) -> *mut u8 { self.0.alloc(l) }
    #[inline] unsafe fn dealloc(&self, p: *mut u8, l: Layout) { zero(p, l.size()); self.0.dealloc(p, l) }
    #[inline] unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 { self.0.alloc_zeroed(l) }
}
EOF

cat > "$ROOT/sw/Cargo.toml" <<EOF
[package]
name = "p_sw"
version = "0.0.0"
edition = "2021"

[dependencies]
strawman = { path = "$LIB" }

[profile.release]
lto = "fat"
codegen-units = 1
EOF

cat > "$ROOT/sw/src/main.rs" <<'EOF'
use std::alloc::{alloc, dealloc, Layout};
use strawman::Wrap;
#[global_allocator] static A: Wrap<std::alloc::System> = Wrap(std::alloc::System);
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
EOF

d=$ROOT/sw
prof=$d/prof; rm -rf "$prof"; mkdir -p "$prof"
RUSTFLAGS="-Cprofile-generate=$prof" $CARGO build --release --manifest-path "$d/Cargo.toml" --target-dir "$d/t1" 2>&1 | grep -E "^error" | head -5
"$d/t1/release/p_sw" >/dev/null 2>&1
"$PROFDATA" merge -o "$d/merged.profdata" "$prof" >/dev/null 2>&1
RUSTFLAGS="-Cprofile-use=$d/merged.profdata" $CARGO build --release --manifest-path "$d/Cargo.toml" --target-dir "$d/t2" 2>&1 | grep -E "^error" | head -5
echo "strawman (secure-gate-zalloc's own control: fn-pointer, NO volatile read of ptr):"
"$d/t2/release/p_sw" 2>&1 | sed 's/^/    /'
