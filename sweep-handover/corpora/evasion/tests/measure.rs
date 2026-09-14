//! Measures every corpus case. A case that cannot be measured is not a finding.
//!
//! One aggregate `#[test]`, for the reason `secure-gate/tests/lifecycle_trace_heap.rs` documents:
//! watch mode and census mode are process-global, and parallel allocator traffic interleaves with
//! them. Every number printed below comes from the `dealloc` hook — what the next allocation of that
//! address would have found.

mod instrument;

use instrument::{census, count_allocs, total_nonzero, watch_block, PAYLOAD, TAIL};

use evasion_corpus::corpus::{
    case01_helper_fn as c1, case02_trait_method as c2, case03_nested as c3,
    case04_as_mut_vec as c4, case05_orphans as c5, case06_aliases as c6,
    case07_lying_fixedstorage as c7, case08_whole_buffer as c8,
};
use evasion_corpus::corpus::roles::{Passphrase, SessionToken, ShardSet};
use secure_gate::{Dynamic, RevealSecret, RevealSecretMut};

/// A token of `len` payload bytes in a buffer of capacity exactly `len`.
fn exact_token(len: usize) -> SessionToken {
    let tok = SessionToken::new_with(|v| {
        v.reserve_exact(len);
        v.extend(std::iter::repeat(PAYLOAD).take(len));
    });
    assert_eq!(
        tok.with_secret(Vec::capacity),
        len,
        "token capacity is not exact; the size assertions would be vacuous"
    );
    tok
}

/// A passphrase of `len` ASCII bytes in a buffer of capacity exactly `len`.
fn exact_pass(len: usize) -> Passphrase {
    let pw = Passphrase::new_with(|s| {
        s.reserve_exact(len);
        s.extend(std::iter::repeat('q').take(len));
    });
    assert_eq!(
        pw.with_secret(String::capacity),
        len,
        "passphrase capacity is not exact; the size assertions would be vacuous"
    );
    pw
}

/// Reports one watched orphan and asserts it was really abandoned with the secret in it.
fn expect_orphan(label: &str, w: instrument::Witness, expect_size: usize) {
    assert!(
        w.freed,
        "{label}: the buffer was not released, so it was resized in place; the residue is real but \
         invisible to this instrument and this case is not measured"
    );
    assert_eq!(
        w.size, expect_size,
        "{label}: the allocator inspected {} bytes, not the buffer's whole capacity",
        w.size
    );
    assert!(
        w.nonzero > 0,
        "{label}: the abandoned buffer was empty at release, so there is no leak to report"
    );
    println!("{label}: {} of {} bytes abandoned non-zero", w.nonzero, w.size);
}

#[test]
fn corpus_leaks_are_real() {
    // ---------------------------------------------------------------- case 01
    {
        let mut tok = exact_token(1008);
        let old = tok.expose_secret().as_ptr();
        let tail = vec![TAIL; 96];
        let w = watch_block(old, || c1::extend_token(&mut tok, &tail));
        expect_orphan("case01 with_secret_mut + helper fn (Vec)", w, 1008);
        assert_eq!(w.nonzero, 1008, "the whole payload should still be there");
    }
    {
        let mut pw = exact_pass(1040);
        let old = pw.expose_secret().as_ptr();
        let w = watch_block(old, || c1::extend_passphrase(&mut pw, "xy"));
        expect_orphan("case01 with_secret_mut + helper fn (String)", w, 1040);
    }
    {
        let mut tok = exact_token(1024);
        let old = tok.expose_secret().as_ptr();
        let tail = vec![TAIL; 32];
        let w = watch_block(old, || c1::absorb_quietly(&mut tok, &tail));
        expect_orphan("case01 expose_secret_mut + helper fn", w, 1024);
    }
    {
        let mut tok = exact_token(992);
        let old = tok.expose_secret().as_ptr();
        let w = watch_block(old, || c1::reserve_for_later(&mut tok, 16));
        expect_orphan("case01 reserve only, no payload written", w, 992);
        assert_eq!(w.nonzero, 992);
    }

    // ---------------------------------------------------------------- case 02
    {
        let mut tok = exact_token(960);
        let old = tok.expose_secret().as_ptr();
        let m = vec![TAIL; 64];
        let w = watch_block(old, || c2::soak_token(&mut tok, &m));
        expect_orphan("case02 consumer trait method (Soak::soak)", w, 960);
    }
    {
        let mut pw = exact_pass(928);
        let old = pw.expose_secret().as_ptr();
        let w = watch_block(old, || c2::stamp_passphrase(&mut pw, 7));
        expect_orphan("case02 fmt::Write via write!", w, 928);
    }
    {
        let mut tok = exact_token(896);
        let old = tok.expose_secret().as_ptr();
        let rec = vec![TAIL; 48];
        let w = watch_block(old, || c2::log_into_token(&mut tok, &rec));
        expect_orphan("case02 io::Write write_all on the inner Vec<u8>", w, 896);
    }
    {
        let mut pw = exact_pass(864);
        let old = pw.expose_secret().as_ptr();
        let w = watch_block(old, || c2::stamp_passphrase_indirect(&mut pw, 9));
        expect_orphan("case02 fmt::Write one function away", w, 864);
    }
    {
        let mut tok = exact_token(832);
        let old = tok.expose_secret().as_ptr();
        let mut src = std::io::Cursor::new(vec![TAIL; 48]);
        let w = watch_block(old, || c2::drain_into_token(&mut tok, &mut src));
        expect_orphan("case02 io::copy into the inner Vec<u8>", w, 832);
    }

    // ---------------------------------------------------------------- case 03
    {
        let body: Vec<u8> = {
            let mut v = Vec::with_capacity(1200);
            v.extend(std::iter::repeat(PAYLOAD).take(1200));
            assert_eq!(v.capacity(), 1200);
            v
        };
        let mut env = Dynamic::from(c3::Envelope::new(body));
        let old = env.with_secret(|e| e.body.as_ptr());
        let more = vec![TAIL; 64];
        let w = watch_block(old, || c3::absorb_into_envelope(&mut env, &more));
        expect_orphan("case03 Dynamic<Envelope>, grown via Envelope::absorb", w, 1200);
    }
    {
        let shard: Vec<u8> = {
            let mut v = Vec::with_capacity(1136);
            v.extend(std::iter::repeat(PAYLOAD).take(1136));
            assert_eq!(v.capacity(), 1136);
            v
        };
        let mut shards = ShardSet::new(vec![shard]);
        let outer_cap_before = shards.with_secret(Vec::capacity);
        let old = c3::shard_ptr(&shards, 0);
        let more = vec![TAIL; 32];
        let w = watch_block(old, || c3::grow_shard(&mut shards, 0, &more));
        expect_orphan("case03 Dynamic<Vec<Vec<u8>>>, inner shard grown", w, 1136);
        assert_eq!(
            shards.with_secret(Vec::capacity),
            outer_cap_before,
            "the outer Vec's capacity changed, so this was not the nested case"
        );
    }
    {
        let shard: Vec<u8> = {
            let mut v = Vec::with_capacity(1072);
            v.extend(std::iter::repeat(PAYLOAD).take(1072));
            assert_eq!(v.capacity(), 1072);
            v
        };
        let mut shards = ShardSet::new(vec![shard]);
        let old = c3::shard_ptr(&shards, 0);
        let more = vec![TAIL; 32];
        let w = watch_block(old, || c3::grow_shard_via_wrapper(&mut shards, 0, &more));
        expect_orphan("case03 same, reached through as_wrapper_mut", w, 1072);
    }

    // ---------------------------------------------------------------- case 04
    {
        let mut pw = exact_pass(1264);
        let old = pw.expose_secret().as_ptr();
        let w = watch_block(old, || c4::append_raw(&mut pw, b"AB"));
        expect_orphan("case04 as_mut_vec, growth at the call site (control)", w, 1264);
    }
    {
        let mut pw = exact_pass(1232);
        let old = pw.expose_secret().as_ptr();
        let w = watch_block(old, || c4::append_via_borrow(&mut pw, b"AB"));
        expect_orphan("case04 as_mut_vec split from the growth (in repo)", w, 1232);
    }
    {
        let mut pw = exact_pass(1200);
        let old = pw.expose_secret().as_ptr();
        let w = watch_block(old, || c4::append_via_dep(&mut pw, b"AB"));
        expect_orphan("case04 as_mut_vec inside a dependency", w, 1200);
    }

    // ---------------------------------------------------------------- case 05
    {
        let mut tok = exact_token(1008);
        let tail = c5::rotate_tail(&mut tok, 504);
        let tail_ptr = tail.as_ptr();
        let tail_cap = tail.capacity();
        let tail_len = tail.len();
        let w = watch_block(tail_ptr, move || drop(tail));
        assert!(w.freed, "case05 split_off: the tail buffer was never released");
        assert!(
            w.nonzero >= tail_len,
            "case05 split_off: only {} of {tail_len} tail bytes survived",
            w.nonzero
        );
        println!(
            "case05 split_off returned tail: {} of {} bytes abandoned non-zero (cap {tail_cap})",
            w.nonzero, w.size
        );
    }
    {
        let mut tok = exact_token(2048);
        let mut staging: Vec<u8> = Vec::with_capacity(512);
        staging.extend(std::iter::repeat(PAYLOAD).take(512));
        assert_eq!(staging.capacity(), 512);
        let donor = staging.as_ptr();
        c5::absorb_staging(&mut tok, &mut staging);
        assert!(staging.is_empty(), "append did not drain the donor");
        assert_eq!(staging.capacity(), 512, "the donor gave up its allocation");
        let w = watch_block(donor, move || drop(staging));
        expect_orphan("case05 append donor, drained but not wiped", w, 512);
        assert_eq!(w.nonzero, 512);
    }
    {
        // 1500 payload bytes as a JSON byte array: the visitor grows a Vec<u8> on the way in.
        let mut json = String::from("[");
        for i in 0..1500 {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&PAYLOAD.to_string());
        }
        json.push(']');
        let mut parsed: Option<Dynamic<Vec<u8>>> = None;
        let blocks = census(|| parsed = Some(c5::from_json(&json)));
        let parsed = parsed.expect("parsed");
        assert!(
            !blocks.is_empty(),
            "case05 Deserialize: no payload-bearing block was released on the success path"
        );
        println!(
            "case05 Deserialize success path: {} bytes of payload left across {} upstream blocks \
             (sizes {:?})",
            total_nonzero(&blocks),
            blocks.len(),
            blocks.iter().map(|b| b.size).collect::<Vec<_>>()
        );
        assert_eq!(parsed.expose_secret().len(), 1500);
        drop(parsed);
    }

    // ---------------------------------------------------------------- case 06
    {
        let mut tok = exact_token(1456);
        let old = tok.expose_secret().as_ptr();
        let extra = vec![TAIL; 32];
        let w = watch_block(old, || c6::via_macro(&mut tok, &extra));
        expect_orphan("case06 consumer macro absorb!", w, 1456);
    }
    {
        let mut tok = exact_token(1424);
        let old = tok.expose_secret().as_ptr();
        let extra = vec![TAIL; 32];
        let m = c6::Mutator::appending();
        let w = watch_block(old, || c6::via_mutator(&mut tok, &m, &extra));
        expect_orphan("case06 fn pointer in a struct field", w, 1424);
    }
    {
        let bytes = vec![PAYLOAD; 1000];
        let mut tok = None;
        let blocks = census(|| tok = Some(c6::fill_byte_by_byte(&bytes)));
        let tok = tok.expect("built");
        assert!(
            !blocks.is_empty(),
            "case06 new_with byte-by-byte: no payload-bearing block was released"
        );
        println!(
            "case06 new_with byte-by-byte fill: {} bytes of payload left across {} blocks \
             (sizes {:?})",
            total_nonzero(&blocks),
            blocks.len(),
            blocks.iter().map(|b| b.size).collect::<Vec<_>>()
        );
        assert_eq!(tok.expose_secret().len(), 1000);
    }

    // ---------------------------------------------------------------- case 07
    {
        let material: Vec<u8> = {
            let mut v = Vec::with_capacity(1360);
            v.extend(std::iter::repeat(PAYLOAD).take(1360));
            assert_eq!(v.capacity(), 1360);
            v
        };
        let mut cred = c7::wrap(material);
        let old = c7::material_ptr(&cred);
        let more = vec![TAIL; 32];
        let w = watch_block(old, || c7::grow(&mut cred, &more));
        expect_orphan("case07 Fixed<Credential> with an indirect Vec", w, 1360);
    }

    // ---------------------------------------------------------------- case 08
    {
        let mut tok = exact_token(1584);
        let cap_before = tok.with_secret(Vec::capacity);
        let old = tok.expose_secret().as_ptr();
        let w = watch_block(old, || c8::normalize(&mut tok));
        let cap_after = tok.with_secret(Vec::capacity);
        expect_orphan("case08 *buf = buf.iter().copied().collect()", w, 1584);
        assert_eq!(w.nonzero, 1584);
        assert_eq!(
            cap_before, cap_after,
            "capacity changed, so this is not the capacity-stable case"
        );
        assert_ne!(
            tok.expose_secret().as_ptr(),
            old,
            "the buffer was not replaced"
        );
        println!("case08 capacity before == after == {cap_after}, buffer replaced anyway");
    }
    {
        let mut pw = exact_pass(1520);
        let cap_before = pw.with_secret(String::capacity);
        let old = pw.expose_secret().as_ptr();
        let w = watch_block(old, || c8::fold_case(&mut pw));
        expect_orphan("case08 *text = text.to_uppercase() (control)", w, 1520);
        println!(
            "case08 String capacity before {cap_before}, after {}",
            pw.with_secret(String::capacity)
        );
    }
    {
        let mut pw = exact_pass(1488);
        let old = pw.expose_secret().as_ptr();
        let w = watch_block(old, || c8::fold_case_indirect(&mut pw));
        expect_orphan("case08 same replacement one function away", w, 1488);
    }

    // ---------------------------------------------- benign.rs is really benign
    // Calling that file "correct" is a claim; here it is measured. If any of these abandon a
    // buffer, the precision numbers computed from that file are meaningless.
    {
        use evasion_corpus::benign;
        let material = vec![PAYLOAD; 1776];
        let mut built = None;
        let blocks = census(|| built = Some(benign::seal(&material)));
        assert!(
            blocks.is_empty(),
            "benign::seal released {} payload-bearing block(s); it is the pre-sizing idiom the docs \
             recommend, so it must abandon nothing",
            blocks.len()
        );
        let mut tok = built.expect("sealed");
        let p = tok.expose_secret().as_ptr();
        let w = watch_block(p, || benign::mask(&mut tok, 0x11));
        assert!(!w.freed, "benign::mask abandoned a buffer");
        let w = watch_block(p, || benign::clip(&mut tok, 16));
        assert!(!w.freed, "benign::clip abandoned a buffer");
        assert_eq!(benign::size(&tok), 16);
        let mut pw = exact_pass(1712);
        let q = pw.expose_secret().as_ptr();
        let w = watch_block(q, || benign::upcase(&mut pw));
        assert!(!w.freed, "benign::upcase abandoned a buffer");
        println!("benign: seal/mask/clip/upcase abandoned nothing");
    }

    // ------------------------------------------------- negative control
    // A capacity-stable, in-place mutation abandons nothing. Without this, every number above
    // could be an artifact of the instrument rather than of the code under test.
    {
        let mut tok = exact_token(2048);
        let old = tok.expose_secret().as_ptr();
        let w = watch_block(old, || {
            tok.with_secret_mut(|v: &mut Vec<u8>| {
                for b in v.iter_mut() {
                    *b = TAIL;
                }
            })
        });
        assert!(
            !w.freed,
            "control: an in-place overwrite released the buffer, so the instrument is mismeasuring"
        );
        println!("control: in-place overwrite abandoned nothing");
    }
    // And the crate's own io::Write forward, which grows by hand and wipes first.
    {
        use std::io::Write as _;
        let mut d: Dynamic<Vec<u8>> = {
            let mut v = Vec::with_capacity(1008);
            v.extend(std::iter::repeat(PAYLOAD).take(1008));
            assert_eq!(v.capacity(), 1008);
            Dynamic::from(v)
        };
        let old = d.expose_secret().as_ptr();
        let w = watch_block(old, || {
            let _ = d.write_all(&[TAIL; 96]);
        });
        if w.freed {
            println!(
                "control: crate io::Write forward abandoned {} of {} bytes non-zero",
                w.nonzero, w.size
            );
            assert_eq!(
                w.nonzero, 0,
                "the crate's own io::Write forward left {} secret bytes in the abandoned buffer",
                w.nonzero
            );
        } else {
            println!("control: crate io::Write forward resized in place, nothing abandoned");
        }
    }
    // Construction moves rather than copies, so the numbers above are not measuring a stray copy.
    {
        let mut v: Vec<u8> = Vec::with_capacity(777);
        v.extend(std::iter::repeat(PAYLOAD).take(777));
        let mut held = None;
        let n = count_allocs(|| held = Some(SessionToken::new(v)));
        let held = held.expect("built");
        println!("control: SessionToken::new performed {n} allocation(s)");
        assert_eq!(held.expose_secret().len(), 777);
    }
}
