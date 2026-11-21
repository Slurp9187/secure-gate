// Stateful fuzz target for the `sealed` module: `Prekey`, `SealedFixed`, `SealedDynamic`,
// and the roles made by `sealed_fixed_newtype!` and `sealed_dynamic_newtype!`.
//
// The fuzzer drives a sequence of operations over a few sealed values and pre-keys (both
// modes), and every value is checked against a plain model after each one. On top of
// AddressSanitizer, three oracles run:
//
// 1. Model: what a sealed value opens to is what was sealed, as changed by every
//    `with_secret_mut` / `with_role_mut` that returned, and by none that panicked.
// 2. Heap residue: every plaintext starts with `CANARY`, and the global allocator below
//    looks for it in each block the process frees. A hit is a plaintext buffer that went
//    back to the allocator unwiped: a temporary, a reallocation, an unwind path. The one
//    plaintext without the canary is what `SealedFixed::from_random` generates; it is
//    covered by oracle 3 until the canary is written into it.
// 3. Allocation count: an access to a fixed-size sealed value allocates nothing, and
//    neither does `SealedFixed::from_random`.
//
// What the oracles do not see: the stack (the 32 KiB scrub is measured elsewhere, see
// `docs/design/receipts/sealed-stack-residue/`), registers, and a tampered ciphertext,
// which the public API cannot produce (unit tests in `src/sealed/` cover it).
//
// Build with `--features sealed`; the target is not part of the default feature set, so
// the other targets keep fuzzing the `alloc`-only configuration.
#![no_main]

use std::alloc::{GlobalAlloc, Layout, System};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once};

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

use secure_gate::scoped::RevealScoped;
use secure_gate::{
    ConstantTimeEq, Dynamic, Fixed, Prekey, RevealSecret, RevealSecretMut, SealedDynamic,
    SealedFixed, SecretLen, dynamic_newtype, fixed_newtype, sealed_dynamic_newtype,
    sealed_fixed_newtype,
};

fixed_newtype!(Key, 32);
sealed_fixed_newtype!(SealedKey, Key);
dynamic_newtype!(Blob, Vec<u8>);
sealed_dynamic_newtype!(SealedBlob, Blob);
dynamic_newtype!(Password, String);
sealed_dynamic_newtype!(SealedPassword, Password);

// ---------------------------------------------------------------------------
// Heap oracle
// ---------------------------------------------------------------------------

/// The first 16 bytes of every plaintext this target seals. ASCII, so it fits a `String`.
const CANARY: [u8; 16] = *b"\x01sg-fuzz-canary\x01";

static WATCH: AtomicBool = AtomicBool::new(false);
static RESIDUE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

/// Passes everything to the system allocator (AddressSanitizer's, in a fuzz build), and
/// records each freed block that still holds `CANARY`. It only records: `dealloc` must not
/// panic. `realloc` is left at its default, which is alloc + copy + `dealloc`, so a buffer
/// that grows shows its old block here too.
struct Probe;

// SAFETY: every call is forwarded unchanged to `System`. The block passed to `dealloc` is
// still allocated while it is read, and is `layout.size()` bytes long by the allocator
// contract. Bytes of it the owner never wrote are read as `u8`, which is how
// `tests/heap_zeroize.rs` inspects freed blocks as well.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCH.load(Ordering::Relaxed) && layout.size() >= CANARY.len() {
            let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(CANARY.len()).any(|w| w == CANARY) {
                RESIDUE.fetch_add(1, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static PROBE: Probe = Probe;

/// Proves once per process that the heap oracle is not vacuous: an unwiped buffer holding
/// the canary is seen when it is freed, and a wiped one is not.
fn oracle_self_test() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        WATCH.store(true, Ordering::Relaxed);
        let mut unwiped = Vec::with_capacity(64);
        unwiped.extend_from_slice(&CANARY);
        drop(core::hint::black_box(unwiped));
        assert_eq!(
            RESIDUE.swap(0, Ordering::Relaxed),
            1,
            "the heap oracle missed an unwiped canary"
        );
        drop(model_of(b"positive control"));
        assert_eq!(
            RESIDUE.load(Ordering::Relaxed),
            0,
            "the heap oracle flagged a wiped buffer"
        );
    });
}

fn assert_no_residue(after: &dyn core::fmt::Debug) {
    assert_eq!(
        RESIDUE.load(Ordering::Relaxed),
        0,
        "plaintext was left in a freed heap block after {after:?}"
    );
}

// ---------------------------------------------------------------------------
// Expected panics
// ---------------------------------------------------------------------------

/// The payload of every panic this target raises on purpose.
struct Expected;

/// Runs `f`, which must panic with [`Expected`]. libFuzzer's panic hook aborts the process,
/// so it is set aside for the call. Any other panic in the region still aborts, with its
/// message.
fn expect_panic(f: impl FnOnce()) {
    let libfuzzer_hook = panic::take_hook();
    panic::set_hook(Box::new(|info| {
        if !info.payload().is::<Expected>() {
            eprintln!("unexpected panic where only the injected one may occur: {info}");
            std::process::abort();
        }
    }));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    panic::set_hook(libfuzzer_hook);
    match result {
        Err(payload) if payload.is::<Expected>() => {}
        _ => panic!("the injected panic did not come back out of the sealed access"),
    }
}

// ---------------------------------------------------------------------------
// The six sealed types behind one interface
// ---------------------------------------------------------------------------

/// A byte view of what a sealed type opens to.
trait Bytes {
    fn bytes(&self) -> &[u8];
}
impl Bytes for [u8; 32] {
    fn bytes(&self) -> &[u8] {
        self
    }
}
impl Bytes for Vec<u8> {
    fn bytes(&self) -> &[u8] {
        self
    }
}
impl Bytes for String {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// What `with_secret_mut` hands out.
enum View<'a> {
    Bytes(&'a mut [u8]),
    Text(&'a mut str),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Via {
    Secret,
    Role,
    Scoped,
}

fn scoped<S, R>(sealed: &S, f: impl FnOnce(&[u8]) -> R) -> R
where
    S: RevealScoped,
    S::Inner: Bytes,
{
    RevealScoped::with_secret(sealed, |p| f(p.bytes()))
}

trait Subject: Sized + ConstantTimeEq + core::fmt::Debug {
    /// Fixed-size: accesses must not allocate.
    const FIXED: bool;
    /// `String` payload: the plaintext must be UTF-8, and edits keep it so.
    const TEXT: bool;

    /// Seals a copy of `plain`. The copy is made straight into the wiping wrapper, so the
    /// harness leaves no plaintext of its own for the heap oracle to trip over.
    fn seal_from(plain: &[u8], prekey: &Arc<Prekey>) -> Self;
    fn read<R>(&self, via: Via, f: impl FnOnce(&[u8]) -> R) -> R;
    fn edit<R>(&mut self, via_role: bool, f: impl FnOnce(View<'_>) -> R) -> R;
    /// Unseals, shows the plaintext to `check`, and seals the unsealed value again under
    /// `prekey` if there is one.
    fn unseal_then(self, prekey: Option<&Arc<Prekey>>, check: impl FnOnce(&[u8])) -> Option<Self>;
    fn subject_len(&self) -> usize;
}

impl Subject for SealedFixed<32> {
    const FIXED: bool = true;
    const TEXT: bool = false;

    fn seal_from(plain: &[u8], prekey: &Arc<Prekey>) -> Self {
        Self::seal(
            Fixed::new_with(|b: &mut [u8; 32]| b.copy_from_slice(plain)),
            prekey,
        )
    }
    fn read<R>(&self, via: Via, f: impl FnOnce(&[u8]) -> R) -> R {
        match via {
            Via::Secret | Via::Role => self.with_secret(|p| f(p)),
            Via::Scoped => scoped(self, f),
        }
    }
    fn edit<R>(&mut self, _via_role: bool, f: impl FnOnce(View<'_>) -> R) -> R {
        self.with_secret_mut(|p| f(View::Bytes(p)))
    }
    fn unseal_then(self, prekey: Option<&Arc<Prekey>>, check: impl FnOnce(&[u8])) -> Option<Self> {
        let plain = self.unseal();
        RevealSecret::with_secret(&plain, |p| check(p));
        prekey.map(|pk| Self::seal(plain, pk))
    }
    fn subject_len(&self) -> usize {
        assert!(!self.is_empty());
        self.len()
    }
}

impl Subject for SealedKey {
    const FIXED: bool = true;
    const TEXT: bool = false;

    fn seal_from(plain: &[u8], prekey: &Arc<Prekey>) -> Self {
        Self::seal(Key::new_with(|b| b.copy_from_slice(plain)), prekey)
    }
    fn read<R>(&self, via: Via, f: impl FnOnce(&[u8]) -> R) -> R {
        match via {
            Via::Secret => self.with_secret(|p| f(p)),
            Via::Role => self.with_role(|key: &Key| RevealSecret::with_secret(key, |p| f(p))),
            Via::Scoped => scoped(self, f),
        }
    }
    fn edit<R>(&mut self, via_role: bool, f: impl FnOnce(View<'_>) -> R) -> R {
        if via_role {
            self.with_role_mut(|key: &mut Key| {
                RevealSecretMut::with_secret_mut(key, |p| f(View::Bytes(p)))
            })
        } else {
            self.with_secret_mut(|p| f(View::Bytes(p)))
        }
    }
    fn unseal_then(self, prekey: Option<&Arc<Prekey>>, check: impl FnOnce(&[u8])) -> Option<Self> {
        let plain: Key = self.unseal();
        RevealSecret::with_secret(&plain, |p| check(p));
        prekey.map(|pk| Self::seal(plain, pk))
    }
    fn subject_len(&self) -> usize {
        assert!(!self.is_empty());
        self.len()
    }
}

fn text(plain: &[u8]) -> String {
    // Exact capacity, and moved into the wrapper that wipes it.
    String::from(core::str::from_utf8(plain).expect("text plaintext is UTF-8"))
}

/// The four variable-length types differ only in how the plain value is built, whether
/// they have `with_role`, and which view `with_secret_mut` hands out.
macro_rules! dynamic_subject {
    ($sealed:ty, text: $text:literal, view: $view:ident, role: $role:tt,
     build: |$plain:ident| $build:expr) => {
        impl Subject for $sealed {
            const FIXED: bool = false;
            const TEXT: bool = $text;

            fn seal_from($plain: &[u8], prekey: &Arc<Prekey>) -> Self {
                Self::seal($build, prekey)
            }
            fn read<R>(&self, via: Via, f: impl FnOnce(&[u8]) -> R) -> R {
                match via {
                    Via::Scoped => scoped(self, f),
                    Via::Role => dynamic_subject!(@role $role, self, f),
                    Via::Secret => self.with_secret(|p| f(p.bytes())),
                }
            }
            fn edit<R>(&mut self, _via_role: bool, f: impl FnOnce(View<'_>) -> R) -> R {
                self.with_secret_mut(|p| f(View::$view(p)))
            }
            fn unseal_then(
                self,
                prekey: Option<&Arc<Prekey>>,
                check: impl FnOnce(&[u8]),
            ) -> Option<Self> {
                let plain = self.unseal();
                RevealSecret::with_secret(&plain, |p| check(p.bytes()));
                prekey.map(|pk| Self::seal(plain, pk))
            }
            fn subject_len(&self) -> usize {
                assert_eq!(self.is_empty(), self.len() == 0);
                self.len()
            }
        }
    };
    (@role none, $self:ident, $f:ident) => {
        $self.with_secret(|p| $f(p.bytes()))
    };
    (@role $role:ty, $self:ident, $f:ident) => {
        $self.with_role(|role: &$role| RevealSecret::with_secret(role, |p| $f(p.bytes())))
    };
}

dynamic_subject!(SealedDynamic<Vec<u8>>, text: false, view: Bytes, role: none,
    build: |plain| Dynamic::<Vec<u8>>::new_with(plain.len(), |b| b.copy_from_slice(plain)));
dynamic_subject!(SealedDynamic<String>, text: true, view: Text, role: none,
    build: |plain| Dynamic::<String>::new(text(plain)));
dynamic_subject!(SealedBlob, text: false, view: Bytes, role: Blob,
    build: |plain| Blob::new_with(plain.len(), |b| b.copy_from_slice(plain)));
dynamic_subject!(SealedPassword, text: true, view: Text, role: Password,
    build: |plain| Password::new(text(plain)));

enum Obj {
    Fixed(SealedFixed<32>),
    Key(SealedKey),
    Bytes(SealedDynamic<Vec<u8>>),
    Text(SealedDynamic<String>),
    Blob(SealedBlob),
    Password(SealedPassword),
}

/// Runs `$body` with `$s` bound to whichever sealed type `$obj` holds.
macro_rules! on {
    ($obj:expr, $s:ident => $body:expr) => {
        match $obj {
            Obj::Fixed($s) => $body,
            Obj::Key($s) => $body,
            Obj::Bytes($s) => $body,
            Obj::Text($s) => $body,
            Obj::Blob($s) => $body,
            Obj::Password($s) => $body,
        }
    };
}

fn is_fixed<S: Subject>(_: &S) -> bool {
    S::FIXED
}

fn is_text<S: Subject>(_: &S) -> bool {
    S::TEXT
}

struct Slot {
    obj: Obj,
    /// The plaintext the sealed value must open to. In a wiping buffer of exact capacity
    /// that never grows, so the model itself never trips the heap oracle.
    model: Zeroizing<Vec<u8>>,
}

fn model_of(tail: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut model = Zeroizing::new(Vec::with_capacity(CANARY.len() + tail.len()));
    model.extend_from_slice(&CANARY);
    model.extend_from_slice(tail);
    model
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Kind {
    Fixed,
    Key,
    Bytes,
    Text,
    Blob,
    Password,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Change {
    Nothing,
    Fill(u8),
    Set(u16, u8),
    Reverse,
    Rotate(u16),
    Sort,
    Upper,
    Lower,
}

impl Change {
    /// Byte-level effect, used for the model and for `&mut [u8]` views. A text secret only
    /// takes the changes that keep it UTF-8, so the others fold onto the two case changes.
    fn apply_bytes(self, b: &mut [u8], text: bool) {
        match (self, text) {
            (Change::Nothing, _) => {}
            (Change::Upper, _) | (Change::Fill(_) | Change::Set(..) | Change::Sort, true) => {
                b.make_ascii_uppercase()
            }
            (Change::Lower, _) | (Change::Reverse | Change::Rotate(_), true) => {
                b.make_ascii_lowercase()
            }
            (Change::Fill(v), false) => b.fill(v),
            (Change::Set(i, v), false) => {
                if !b.is_empty() {
                    b[i as usize % b.len()] = v;
                }
            }
            (Change::Reverse, false) => b.reverse(),
            (Change::Rotate(n), false) => {
                if !b.is_empty() {
                    b.rotate_left(n as usize % b.len());
                }
            }
            (Change::Sort, false) => b.sort_unstable(),
        }
    }

    fn apply(self, view: View<'_>) {
        match view {
            View::Bytes(b) => self.apply_bytes(b, false),
            View::Text(s) => match self {
                Change::Nothing => {}
                Change::Upper | Change::Fill(_) | Change::Set(..) | Change::Sort => {
                    s.make_ascii_uppercase()
                }
                Change::Lower | Change::Reverse | Change::Rotate(_) => s.make_ascii_lowercase(),
            },
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Op {
    /// Seal a new value (canary + up to `len` input bytes) into `slot`, replacing what is there.
    Seal {
        slot: u8,
        kind: Kind,
        prekey: u8,
        len: u16,
    },
    /// `SealedFixed::from_random` into `slot`; the model is whatever it first opens to.
    Random {
        slot: u8,
        prekey: u8,
    },
    Read {
        slot: u8,
        via: Via,
    },
    Edit {
        slot: u8,
        change: Change,
        via_role: bool,
    },
    /// The closure changes the plaintext and then panics: the sealed value must not change.
    EditThenPanic {
        slot: u8,
        change: Change,
        via_role: bool,
    },
    ReadThenPanic {
        slot: u8,
        via: Via,
    },
    /// Open `outer`, and inside its closure edit `inner`.
    Nested {
        outer: u8,
        inner: u8,
        change: Change,
    },
    CtEq {
        a: u8,
        b: u8,
    },
    /// Compare against a second seal of the same plaintext with one byte changed, or (for
    /// the variable-length types) one byte shorter.
    CtEqNear {
        slot: u8,
        prekey: u8,
        at: u16,
        shorter: bool,
    },
    /// Unseal, check, and seal the unsealed value again under another pre-key.
    Reseal {
        slot: u8,
        prekey: u8,
    },
    /// Unseal, check, drop.
    Unseal {
        slot: u8,
    },
    Drop {
        slot: u8,
    },
    NewPrekey {
        idle_noaccess: bool,
    },
    /// Drop the harness's reference; values sealed under it keep it alive.
    DropPrekey {
        prekey: u8,
    },
}

const SLOTS: usize = 4;
const PREKEYS: usize = 3;
const MAX_OPS: usize = 48;
const MAX_TAIL: usize = 2048;

struct World {
    slots: [Option<Slot>; SLOTS],
    prekeys: Vec<Arc<Prekey>>,
}

impl World {
    fn prekey(&mut self, pick: u8) -> Arc<Prekey> {
        if self.prekeys.is_empty() {
            self.prekeys.push(if pick & 1 == 0 {
                Prekey::new()
            } else {
                Prekey::new_idle_noaccess()
            });
        }
        Arc::clone(&self.prekeys[pick as usize % self.prekeys.len()])
    }

    fn step(&mut self, op: Op, u: &mut Unstructured<'_>) {
        match op {
            Op::Seal {
                slot,
                kind,
                prekey,
                len,
            } => {
                let prekey = self.prekey(prekey);
                let fixed = matches!(kind, Kind::Fixed | Kind::Key);
                let want = if fixed {
                    16
                } else {
                    len as usize % (MAX_TAIL + 1)
                };
                let mut tail = u.bytes(want.min(u.len())).unwrap_or(&[]);
                if matches!(kind, Kind::Text | Kind::Password) {
                    if let Err(e) = core::str::from_utf8(tail) {
                        tail = &tail[..e.valid_up_to()];
                    }
                }
                // A fixed secret is always 32 bytes: a short tail is padded with zeros.
                let mut padded = [0u8; 16];
                if fixed {
                    padded[..tail.len()].copy_from_slice(tail);
                    tail = &padded;
                }
                let model = model_of(tail);
                let obj = match kind {
                    Kind::Fixed => Obj::Fixed(Subject::seal_from(&model, &prekey)),
                    Kind::Key => Obj::Key(Subject::seal_from(&model, &prekey)),
                    Kind::Bytes => Obj::Bytes(Subject::seal_from(&model, &prekey)),
                    Kind::Text => Obj::Text(Subject::seal_from(&model, &prekey)),
                    Kind::Blob => Obj::Blob(Subject::seal_from(&model, &prekey)),
                    Kind::Password => Obj::Password(Subject::seal_from(&model, &prekey)),
                };
                self.slots[slot as usize % SLOTS] = Some(Slot { obj, model });
            }

            Op::Random { slot, prekey } => {
                let prekey = self.prekey(prekey);
                // The random secret has no canary, so the heap oracle cannot see it. It
                // does not need to: generating and sealing it must not touch the heap at
                // all. The canary is then written over its first half, so every later
                // operation on this value is under the heap oracle like any other.
                let before = ALLOCS.load(Ordering::Relaxed);
                let mut sealed = SealedFixed::<32>::from_random(&prekey);
                let random_tail = sealed.with_secret_mut(|p| {
                    let nonzero = p.iter().any(|&b| b != 0);
                    p[..CANARY.len()].copy_from_slice(&CANARY);
                    let mut tail = [0u8; 16];
                    tail.copy_from_slice(&p[CANARY.len()..]);
                    (nonzero, tail)
                });
                assert_eq!(
                    ALLOCS.load(Ordering::Relaxed),
                    before,
                    "from_random allocated"
                );
                assert!(random_tail.0, "from_random gave all zeros");
                self.slots[slot as usize % SLOTS] = Some(Slot {
                    obj: Obj::Fixed(sealed),
                    model: model_of(&random_tail.1),
                });
            }

            Op::Read { slot, via } => {
                let Some(Slot { obj, model }) = &self.slots[slot as usize % SLOTS] else {
                    return;
                };
                on!(obj, s => {
                    let before = ALLOCS.load(Ordering::Relaxed);
                    s.read(via, |p| assert_eq!(p, &model[..], "opened to something else"));
                    if is_fixed(s) {
                        assert_eq!(ALLOCS.load(Ordering::Relaxed), before, "a fixed read allocated");
                    }
                    assert_eq!(s.subject_len(), model.len());
                    assert_eq!(format!("{s:?}"), "[REDACTED]");
                });
            }

            Op::Edit {
                slot,
                change,
                via_role,
            } => {
                let Some(Slot { obj, model }) = &mut self.slots[slot as usize % SLOTS] else {
                    return;
                };
                on!(obj, s => {
                    let before = ALLOCS.load(Ordering::Relaxed);
                    let seen = s.edit(via_role, |view| {
                        change.apply(view);
                        0x5eed_u32
                    });
                    if is_fixed(s) {
                        assert_eq!(ALLOCS.load(Ordering::Relaxed), before, "a fixed edit allocated");
                    }
                    assert_eq!(seen, 0x5eed, "the closure's result was not returned");
                    change.apply_bytes(model, is_text(s));
                    s.read(Via::Secret, |p| assert_eq!(p, &model[..], "the edit did not persist"));
                });
            }

            Op::EditThenPanic {
                slot,
                change,
                via_role,
            } => {
                let Some(Slot { obj, model }) = &mut self.slots[slot as usize % SLOTS] else {
                    return;
                };
                on!(obj, s => {
                    expect_panic(|| {
                        s.edit(via_role, |view| {
                            change.apply(view);
                            panic::panic_any(Expected)
                        })
                    });
                    s.read(Via::Secret, |p| {
                        assert_eq!(p, &model[..], "a panicking edit changed the sealed value")
                    });
                });
            }

            Op::ReadThenPanic { slot, via } => {
                let Some(Slot { obj, model }) = &self.slots[slot as usize % SLOTS] else {
                    return;
                };
                on!(obj, s => {
                    expect_panic(|| {
                        s.read(via, |p| {
                            assert_eq!(p, &model[..]);
                            panic::panic_any(Expected)
                        })
                    });
                    s.read(Via::Secret, |p| assert_eq!(p, &model[..]));
                });
            }

            Op::Nested {
                outer,
                inner,
                change,
            } => {
                let (outer, inner) = (outer as usize % SLOTS, inner as usize % SLOTS);
                if outer == inner {
                    return;
                }
                let Some(mut taken) = self.slots[inner].take() else {
                    return;
                };
                if let Some(Slot { obj, model }) = &self.slots[outer] {
                    on!(obj, o => o.read(Via::Secret, |p| {
                        assert_eq!(p, &model[..]);
                        on!(&mut taken.obj, i => {
                            i.edit(false, |view| change.apply(view));
                            change.apply_bytes(&mut taken.model, is_text(i));
                            i.read(Via::Secret, |q| assert_eq!(q, &taken.model[..]));
                        });
                        // The outer plaintext is still the outer one after the inner
                        // seal, open and stack scrub ran beneath it.
                        assert_eq!(p, &model[..], "a nested access disturbed the outer plaintext");
                    }));
                }
                self.slots[inner] = Some(taken);
            }

            Op::CtEq { a, b } => {
                let (Some(a), Some(b)) = (
                    &self.slots[a as usize % SLOTS],
                    &self.slots[b as usize % SLOTS],
                ) else {
                    return;
                };
                let equal = match (&a.obj, &b.obj) {
                    (Obj::Fixed(x), Obj::Fixed(y)) => x.ct_eq(y),
                    (Obj::Key(x), Obj::Key(y)) => x.ct_eq(y),
                    (Obj::Bytes(x), Obj::Bytes(y)) => x.ct_eq(y),
                    (Obj::Text(x), Obj::Text(y)) => x.ct_eq(y),
                    (Obj::Blob(x), Obj::Blob(y)) => x.ct_eq(y),
                    (Obj::Password(x), Obj::Password(y)) => x.ct_eq(y),
                    _ => return,
                };
                assert_eq!(
                    equal,
                    a.model == b.model,
                    "ct_eq disagrees with the plaintexts"
                );
            }

            Op::CtEqNear {
                slot,
                prekey,
                at,
                shorter,
            } => {
                let prekey = self.prekey(prekey);
                let Some(Slot { obj, model }) = &self.slots[slot as usize % SLOTS] else {
                    return;
                };
                on!(obj, s => {
                    let twin = seal_like(s, model, &prekey);
                    assert!(s.ct_eq(&twin), "two seals of one plaintext compare unequal");
                    let mut near = Zeroizing::new(Vec::with_capacity(model.len()));
                    near.extend_from_slice(model);
                    if shorter && !is_fixed(s) && near.last().is_some_and(u8::is_ascii) {
                        // An ASCII last byte is a whole character, so text stays text.
                        let cut = near.len() - 1;
                        near.truncate(cut);
                    } else {
                        // Within the canary: ASCII both before and after, so text stays text.
                        near[at as usize % CANARY.len()] ^= 0x20;
                    }
                    let near = seal_like(s, &near, &prekey);
                    assert!(!s.ct_eq(&near), "different plaintexts compare equal");
                });
            }

            Op::Reseal { slot, prekey } => {
                let prekey = self.prekey(prekey);
                let Some(Slot { obj, model }) = self.slots[slot as usize % SLOTS].take() else {
                    return;
                };
                let check = |p: &[u8]| assert_eq!(p, &model[..], "unsealed to something else");
                let obj = match obj {
                    Obj::Fixed(s) => s.unseal_then(Some(&prekey), check).map(Obj::Fixed),
                    Obj::Key(s) => s.unseal_then(Some(&prekey), check).map(Obj::Key),
                    Obj::Bytes(s) => s.unseal_then(Some(&prekey), check).map(Obj::Bytes),
                    Obj::Text(s) => s.unseal_then(Some(&prekey), check).map(Obj::Text),
                    Obj::Blob(s) => s.unseal_then(Some(&prekey), check).map(Obj::Blob),
                    Obj::Password(s) => s.unseal_then(Some(&prekey), check).map(Obj::Password),
                }
                .expect("a pre-key was given");
                on!(&obj, s => s.read(Via::Secret, |p| assert_eq!(p, &model[..])));
                self.slots[slot as usize % SLOTS] = Some(Slot { obj, model });
            }

            Op::Unseal { slot } => {
                let Some(Slot { obj, model }) = self.slots[slot as usize % SLOTS].take() else {
                    return;
                };
                let check = |p: &[u8]| assert_eq!(p, &model[..], "unsealed to something else");
                on!(obj, s => assert!(s.unseal_then(None, check).is_none()));
            }

            Op::Drop { slot } => {
                self.slots[slot as usize % SLOTS] = None;
            }

            Op::NewPrekey { idle_noaccess } => {
                if self.prekeys.len() < PREKEYS {
                    let prekey = if idle_noaccess {
                        Prekey::new_idle_noaccess()
                    } else {
                        Prekey::new()
                    };
                    assert_eq!(prekey.is_idle_noaccess(), idle_noaccess);
                    // Whether the lock was granted depends on the machine; only its
                    // reporting is exercised.
                    if let Err(why) = prekey.lock_status() {
                        let _ = (why.raw_os_error(), why.idle_noaccess(), why.forked());
                        assert!(!why.to_string().is_empty());
                    }
                    assert_eq!(format!("{prekey:?}"), "[REDACTED]");
                    self.prekeys.push(prekey);
                }
            }

            Op::DropPrekey { prekey } => {
                if !self.prekeys.is_empty() {
                    let at = prekey as usize % self.prekeys.len();
                    self.prekeys.swap_remove(at);
                }
            }
        }
    }
}

fn seal_like<S: Subject>(_: &S, plain: &[u8], prekey: &Arc<Prekey>) -> S {
    S::seal_from(plain, prekey)
}

fuzz_target!(|data: &[u8]| {
    oracle_self_test();

    let mut u = Unstructured::new(data);
    let mut world = World {
        slots: [const { None }; SLOTS],
        prekeys: Vec::with_capacity(PREKEYS),
    };

    for _ in 0..MAX_OPS {
        let Ok(op) = Op::arbitrary(&mut u) else { break };
        world.step(op, &mut u);
        assert_no_residue(&op);
        if u.is_empty() {
            break;
        }
    }

    // Everything sealed is still intact at the end, whatever the sequence was.
    for slot in world.slots.iter().flatten() {
        on!(&slot.obj, s => s.read(Via::Secret, |p| assert_eq!(p, &slot.model[..])));
    }
    drop(world);
    assert_no_residue(&"dropping every sealed value and pre-key");
});
