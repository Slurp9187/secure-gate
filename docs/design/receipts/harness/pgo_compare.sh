set -u
CARGO=/home/dev/.cargo/bin/cargo
RUSTC=/home/dev/.cargo/bin/rustc
ROOT=$HOME/pgo-compare
rm -rf "$ROOT"; mkdir -p "$ROOT"

PROFDATA=$(find "$($RUSTC --print sysroot)" -name llvm-profdata -type f 2>/dev/null | head -1)
if [ -z "$PROFDATA" ]; then
  echo "llvm-profdata missing; installing llvm-tools"
  /home/dev/.cargo/bin/rustup component add llvm-tools >/dev/null 2>&1 || true
  PROFDATA=$(find "$($RUSTC --print sysroot)" -name llvm-profdata -type f 2>/dev/null | head -1)
fi
[ -n "$PROFDATA" ] || { echo "FATAL: no llvm-profdata"; exit 1; }
echo "llvm-profdata: $PROFDATA"
echo "toolchain: $($RUSTC -vV | grep '^release')"
echo

# the strawman: secure-gate-zalloc's control -- function pointer, NO volatile read of ptr
mkdir -p "$ROOT/strawman/src"
cat > "$ROOT/strawman/Cargo.toml" <<'EOF'
[package]
name = "strawman"
version = "0.0.0"
edition = "2021"
EOF
cat > "$ROOT/strawman/src/lib.rs" <<'EOF'
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

PROBE_BODY='
use std::alloc::{alloc, dealloc, Layout};
__ALLOC__
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
'

measure() {
  name="$1"; dep="$2"; allocdecl="$3"
  d="$ROOT/$name"; mkdir -p "$d/src"
  printf '[package]\nname = "p_%s"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\n%s\n\n[profile.release]\nlto = "fat"\ncodegen-units = 1\n' "$name" "$dep" > "$d/Cargo.toml"
  printf '%s' "${PROBE_BODY/__ALLOC__/$allocdecl}" > "$d/src/main.rs"

  prof="$d/prof"; rm -rf "$prof"; mkdir -p "$prof"
  RUSTFLAGS="-Cprofile-generate=$prof" $CARGO build --release --manifest-path "$d/Cargo.toml" --target-dir "$d/t1" >/dev/null 2>&1 || { echo "$name: BUILD FAILED (gen)"; return; }
  "$d/t1/release/p_$name" >/dev/null 2>&1
  "$PROFDATA" merge -o "$d/merged.profdata" "$prof" >/dev/null 2>&1 || { echo "$name: PROFMERGE FAILED"; return; }
  RUSTFLAGS="-Cprofile-use=$d/merged.profdata" $CARGO build --release --manifest-path "$d/Cargo.toml" --target-dir "$d/t2" >/dev/null 2>&1 || { echo "$name: BUILD FAILED (use)"; return; }
  out=$("$d/t2/release/p_$name" 2>&1)
  echo "$name:"; echo "$out" | sed 's/^/    /'
}

echo "### PGO (-Cprofile-use) + fat LTO + codegen-units=1"
echo "### hits = pattern bytes recovered out of 16 from a freed block"
echo
measure none      ""                                                              ""
measure strawman  "strawman = { path = \"$ROOT/strawman\" }"                       "use strawman::Wrap;
#[global_allocator] static A: Wrap<std::alloc::System> = Wrap(std::alloc::System);"
measure onepass   "zeroizing-alloc = \"0.1.1\""                                    "use zeroizing_alloc::ZeroAlloc;
#[global_allocator] static A: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);"
measure sgza      "secure-gate-zalloc = { path = \"/home/dev/zalloc-test/secure-gate-zalloc\" }" "use secure_gate_zalloc::ZeroizingAlloc;
#[global_allocator] static A: ZeroizingAlloc<std::alloc::System> = ZeroizingAlloc(std::alloc::System);"
