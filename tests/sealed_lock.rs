//! Pre-key page locking, in a process of its own: every lock in a process draws on one
//! quota (the working set on Windows, `RLIMIT_MEMLOCK` on Unix), so this binary holds a
//! single test and runs nothing beside it.
#![cfg(feature = "sealed")]

use secure_gate::{Fixed, Prekey, SealedFixed};

/// Enough pre-keys (16 KiB each) to exhaust Windows' default working-set quota many times
/// over; on Unix the limit may be higher than this, which the test allows.
const MANY: usize = 1024;

/// The pre-key's shape: 16 KiB at 16 KiB alignment.
#[repr(C, align(16384))]
struct Spacer([u8; 16384]);

#[test]
fn locks_succeed_fail_softly_and_are_released_on_drop() {
    // A first pre-key, alone in the process, locks.
    let first = Prekey::new();
    assert_eq!(first.lock_status(), Ok(()), "a lone pre-key locks");
    drop(first);

    // Keep creating until the quota refuses one. A refusal is reported, never a panic, and
    // the refused pre-key still seals and opens.
    let mut held = Vec::new();
    let mut refused = None;
    for _ in 0..MANY {
        let k = Prekey::new();
        let status = k.lock_status();
        held.push(k);
        if let Err(e) = status {
            refused = Some(e);
            break;
        }
    }

    #[cfg(windows)]
    {
        let e = refused.expect("Windows' default working-set quota refuses a lock");
        assert_eq!(e.raw_os_error(), Some(1453), "ERROR_WORKING_SET_QUOTA");
    }

    if refused.is_some() {
        let last = held.last().unwrap();
        let s = SealedFixed::seal(Fixed::new([3u8; 32]), last);
        s.with_secret(|b| assert_eq!(b[0], 3));

        // Dropping the pre-keys unlocks their pages, so the quota is free again. The freed
        // slots are filled with same-shaped spacers first, so the new pre-keys land on
        // other pages: re-locking a page that was never unlocked costs no quota, and would
        // let a missing unlock pass.
        let count = held.len();
        drop(s);
        held.clear();
        let spacers: Vec<_> = (0..count).map(|_| Box::new(Spacer([1u8; 16384]))).collect();
        let again: Vec<_> = (0..count - 1).map(|_| Prekey::new()).collect();
        for k in &again {
            assert_eq!(
                k.lock_status(),
                Ok(()),
                "dropped pre-keys gave their quota back"
            );
        }
        drop(spacers);
    }
}
