//! Throwaway probe: where does a pre-key land relative to C heap buffers, can a 64 KiB
//! linear over-read from one of them capture it, and what do guard pages / idle no-access
//! cost. Unsafe and UB-adjacent by design (it performs the over-read). Not shipped.
#![allow(clippy::missing_safety_doc)]

use region::Protection;
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::Instant;

const PREKEY_LEN: usize = 16384;
const OVERREAD: usize = 65536;

#[repr(C, align(16384))]
struct Block([u8; PREKEY_LEN]);
#[repr(C, align(4096))]
struct Page([u8; 4096]);

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn size(&mut self) -> usize {
        // Log-uniform 16 B .. 16 KiB, like TLS records and OpenSSL/SQLCipher structs.
        let bits = 4 + (self.next() % 11) as u32; // 2^4 .. 2^14
        let base = 1usize << bits;
        base + (self.next() as usize % base)
    }
    fn fill(&mut self, b: &mut [u8]) {
        for c in b.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
    }
}

/// The pre-key's live pieces as (address, len), plus whatever owns them.
#[allow(dead_code)]
enum Held {
    Block(Box<Block>),
    Split(Vec<Box<Page>>),
    Map(region::Allocation),
}

struct Prekey {
    pieces: Vec<(usize, usize)>,
    _held: Held,
}

fn make(layout: &str, rng: &mut Rng, cbufs: &mut Vec<(usize, usize)>, interleave: bool) -> Prekey {
    let page = region::page::size();
    match layout {
        "block" => {
            let mut b = Box::new(Block([0; PREKEY_LEN]));
            rng.fill(&mut b.0);
            let a = b.0.as_ptr() as usize;
            Prekey { pieces: vec![(a, PREKEY_LEN)], _held: Held::Block(b) }
        }
        "split" => {
            let mut v = Vec::new();
            let mut pieces = Vec::new();
            for _ in 0..4 {
                let mut p = Box::new(Page([0; 4096]));
                rng.fill(&mut p.0);
                pieces.push((p.0.as_ptr() as usize, 4096));
                v.push(p);
                if interleave {
                    for _ in 0..8 {
                        let n = rng.size();
                        cbufs.push((unsafe { libc::malloc(n) } as usize, n));
                    }
                }
            }
            Prekey { pieces, _held: Held::Split(v) }
        }
        "bare" => {
            let mut m = region::alloc(PREKEY_LEN, Protection::READ_WRITE).unwrap();
            let p = m.as_mut_ptr::<u8>();
            rng.fill(unsafe { std::slice::from_raw_parts_mut(p, PREKEY_LEN) });
            Prekey { pieces: vec![(p as usize, PREKEY_LEN)], _held: Held::Map(m) }
        }
        "guarded" => {
            let mut m = region::alloc(PREKEY_LEN + 2 * page, Protection::READ_WRITE).unwrap();
            let base = m.as_mut_ptr::<u8>();
            let p = unsafe { base.add(page) };
            rng.fill(unsafe { std::slice::from_raw_parts_mut(p, PREKEY_LEN) });
            unsafe {
                region::protect(base, page, Protection::NONE).unwrap();
                region::protect(p.add(PREKEY_LEN), page, Protection::NONE).unwrap();
                region::protect(p, PREKEY_LEN, Protection::READ).unwrap();
            }
            Prekey { pieces: vec![(p as usize, PREKEY_LEN)], _held: Held::Map(m) }
        }
        _ => panic!("layout: block | split | bare | guarded"),
    }
}

/// First address in [s, s+len) that a read would fault on, or s+len.
fn first_unreadable(s: usize, len: usize) -> usize {
    let mut at = s;
    let end = s + len;
    while at < end {
        match region::query(at as *const u8) {
            Ok(r) if r.is_readable() && r.is_committed() => {
                at = r.as_range().end;
            }
            _ => return at,
        }
    }
    end
}

fn overlap(a: (usize, usize), b: (usize, usize)) -> usize {
    let lo = a.0.max(b.0);
    let hi = a.1.min(b.1);
    hi.saturating_sub(lo)
}

/// Prekey bytes a 64 KiB read starting at `s` gets before it faults.
fn captured(s: usize, pk: &Prekey) -> usize {
    let stop = first_unreadable(s, OVERREAD);
    pk.pieces.iter().map(|&(a, n)| overlap((s, stop), (a, a + n))).sum()
}

fn adj(layout: &str, variant: &str, seed: u64, real: bool) {
    let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
    let mut cbufs: Vec<(usize, usize)> = Vec::new();
    let warm = variant != "cold";
    if warm {
        for _ in 0..400 {
            let n = rng.size();
            cbufs.push((unsafe { libc::malloc(n) } as usize, n));
            if rng.next() % 10 < 4 && !cbufs.is_empty() {
                let i = rng.next() as usize % cbufs.len();
                let (p, _) = cbufs.swap_remove(i);
                unsafe { libc::free(p as *mut _) };
            }
        }
    }
    let pk = make(layout, &mut rng, &mut cbufs, variant == "interleaved");
    for _ in 0..400 {
        let n = rng.size();
        cbufs.push((unsafe { libc::malloc(n) } as usize, n));
        if warm && rng.next() % 10 < 3 {
            let i = rng.next() as usize % cbufs.len();
            let (p, _) = cbufs.swap_remove(i);
            unsafe { libc::free(p as *mut _) };
        }
    }
    let lo = pk.pieces.iter().map(|p| p.0).min().unwrap();
    let hi = pk.pieces.iter().map(|p| p.0 + p.1).max().unwrap();
    let mut below = 0;
    let mut any = 0;
    let mut full = 0;
    let mut best = (0usize, 0usize);
    let mut nearest_gap = usize::MAX;
    for &(s, n) in &cbufs {
        if s >= hi {
            continue;
        }
        if s + n <= lo {
            nearest_gap = nearest_gap.min(lo - (s + n));
        }
        if s + OVERREAD <= lo {
            continue;
        }
        below += 1;
        let c = captured(s, &pk);
        if c > 0 {
            any += 1;
        }
        if c == PREKEY_LEN {
            full += 1;
        }
        if c > best.1 {
            best = (s, c);
        }
    }
    let span = hi - lo;
    let mut gaps: Vec<usize> = Vec::new();
    let mut sorted = pk.pieces.clone();
    sorted.sort();
    for w in sorted.windows(2) {
        gaps.push(w[1].0 - (w[0].0 + w[0].1));
    }
    let ng = if nearest_gap == usize::MAX { -1i64 } else { nearest_gap as i64 };
    print!(
        "layout={layout} variant={variant} seed={seed} span={span} gaps={gaps:?} \
         cbufs_within_64k_below={below} capture_any={any} capture_full={full} \
         max_captured={} nearest_cbuf_gap={ng}",
        best.1
    );
    if real {
        // The real over-read, from the C buffer nearest below the pre-key (the attacker's
        // best start), or the best-capturing one if any.
        let start = if best.1 > 0 {
            best.0
        } else {
            cbufs.iter().filter(|b| b.0 + b.1 <= lo).map(|b| b.0).max().unwrap_or(lo - 64)
        };
        let mut dst = region::alloc(OVERREAD, Protection::READ_WRITE).unwrap();
        let d = dst.as_mut_ptr::<u8>();
        use std::io::Write;
        print!(" real_from=-{}", lo - start);
        std::io::stdout().flush().unwrap();
        unsafe { libc::memcpy(d as *mut _, start as *const _, OVERREAD) };
        let copy = unsafe { std::slice::from_raw_parts(d, OVERREAD) };
        let mut got = 0;
        for &(a, n) in &pk.pieces {
            for i in 0..n {
                let addr = a + i;
                if addr >= start && addr < start + OVERREAD {
                    let src = unsafe { *(addr as *const u8) };
                    if copy[addr - start] == src {
                        got += 1;
                    }
                }
            }
        }
        print!(" real_captured={got}");
    }
    println!();
}

fn quota(layout: &str) {
    let mut rng = Rng(7);
    let mut cb = Vec::new();
    let mut held = Vec::new();
    let mut ok = 0;
    for _ in 0..1024 {
        let pk = make(layout, &mut rng, &mut cb, false);
        let page = region::page::size();
        let mut guards = Vec::new();
        let mut failed = false;
        for &(a, n) in &pk.pieces {
            match region::lock(a as *const u8, n.max(page)) {
                Ok(g) => guards.push(g),
                Err(e) => {
                    println!("layout={layout} locked_prekeys={ok} first_error={e}");
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            return;
        }
        ok += 1;
        held.push((pk, guards));
    }
    println!("layout={layout} locked_prekeys>={ok}");
}

fn spin(stop: &std::sync::atomic::AtomicBool) {
    let mut v = vec![0u64; 4096];
    let mut i = 0usize;
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        v[i % 4096] = v[i % 4096].wrapping_add(i as u64);
        i = i.wrapping_add(1);
    }
    black_box(v);
}

fn bench(busy: usize) {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    let stop = Arc::new(AtomicBool::new(false));
    let hs: Vec<_> = (0..busy)
        .map(|_| {
            let s = stop.clone();
            std::thread::spawn(move || spin(&s))
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut rng = Rng(11);
    let mut cb = Vec::new();
    let g = make("guarded", &mut rng, &mut cb, false);
    let (gp, _) = g.pieces[0];
    let s = make("split", &mut rng, &mut cb, false);
    let salt = [5u8; 32];
    let block: &[u8] = unsafe { std::slice::from_raw_parts(gp as *const u8, PREKEY_LEN) };
    let pages: Vec<&[u8]> =
        s.pieces.iter().map(|&(a, n)| unsafe { std::slice::from_raw_parts(a as *const u8, n) }).collect();

    let one = || {
        let mut h = Sha256::new();
        h.update(salt);
        h.update(block);
        black_box(h.finalize());
    };
    let four = || {
        let mut h = Sha256::new();
        h.update(salt);
        for p in &pages {
            h.update(p);
        }
        black_box(h.finalize());
    };
    let idle = || unsafe {
        region::protect(gp as *const u8, PREKEY_LEN, Protection::READ).unwrap();
        let mut h = Sha256::new();
        h.update(salt);
        h.update(block);
        black_box(h.finalize());
        region::protect(gp as *const u8, PREKEY_LEN, Protection::NONE).unwrap();
    };
    let protect_only = || unsafe {
        region::protect(gp as *const u8, PREKEY_LEN, Protection::READ).unwrap();
        region::protect(gp as *const u8, PREKEY_LEN, Protection::NONE).unwrap();
    };
    fn med(f: &dyn Fn()) -> f64 {
        let n = 5000;
        for _ in 0..500 {
            f();
        }
        let mut r: Vec<f64> = (0..9)
            .map(|_| {
                let t = Instant::now();
                for _ in 0..n {
                    f();
                }
                t.elapsed().as_nanos() as f64 / n as f64
            })
            .collect();
        r.sort_by(|a, b| a.partial_cmp(b).unwrap());
        r[4]
    }
    // Hashes are equal: the split's derivation is the block's for the same bytes.
    let eq = {
        let mut a = Sha256::new();
        a.update(salt);
        for p in &pages {
            a.update(p);
        }
        let mut b = Sha256::new();
        b.update(salt);
        b.update(pages.concat());
        a.finalize() == b.finalize()
    };
    let r1 = med(&one);
    let r4 = med(&four);
    let ri = med(&idle);
    let rp = med(&protect_only);
    // Leave the guarded block readable (its last protect is NONE after `idle`).
    unsafe { region::protect(gp as *const u8, PREKEY_LEN, Protection::READ).unwrap() };
    println!(
        "busy_threads={busy} hash_one_update_ns={r1:.0} hash_four_updates_ns={r4:.0} \
         idle_noaccess_access_ns={ri:.0} protect_pair_only_ns={rp:.0} split_hash_equals_concat={eq}"
    );
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for h in hs {
        h.join().unwrap();
    }
}

#[cfg(windows)]
fn dump_child(mode: &str) {
    let mut rng = Rng(99);
    let mut cb = Vec::new();
    let layout = if mode == "heap" { "block" } else { "guarded" };
    let pk = make(layout, &mut rng, &mut cb, false);
    let (a, _) = pk.pieces[0];
    let marker: Vec<u8> = unsafe { std::slice::from_raw_parts((a + 1000) as *const u8, 32) }.to_vec();
    if mode == "noaccess" {
        unsafe { region::protect(a as *const u8, PREKEY_LEN, Protection::NONE).unwrap() };
    }
    let mut marker = marker;
    let mut hex: String = marker.iter().map(|b| format!("{b:02x}")).collect();
    println!("{a} {hex}");
    // The probe's own copy of the marker must not be what the dump finds.
    for b in marker.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    drop(marker);
    unsafe { hex.as_bytes_mut().iter_mut().for_each(|b| std::ptr::write_volatile(b, b'0')) };
    drop(hex);
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).unwrap();
    black_box(&pk);
}

#[cfg(windows)]
fn dump_parent(mode: &str, out: &str) {
    use std::io::{BufRead, BufReader, Write};
    use std::os::windows::io::AsRawHandle;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        MiniDumpWithFullMemory, MiniDumpWriteDump, ReadProcessMemory,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args(["dump-child", mode])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    let mut it = line.split_whitespace();
    let addr: usize = it.next().unwrap().parse().unwrap();
    let hex = it.next().unwrap().to_string();
    let marker: Vec<u8> =
        (0..32).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect();
    let pid = child.id();
    let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    assert!(!h.is_null());
    let mut buf = [0u8; 32];
    let mut n = 0usize;
    let rpm = unsafe {
        ReadProcessMemory(h, (addr + 1000) as *const _, buf.as_mut_ptr().cast(), 32, &mut n)
    };
    let rpm_ok = rpm != 0 && n == 32 && buf[..] == marker[..];
    let f = std::fs::File::create(out).unwrap();
    let ok = unsafe {
        MiniDumpWriteDump(
            h,
            pid,
            f.as_raw_handle() as _,
            MiniDumpWithFullMemory,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    drop(f);
    unsafe { CloseHandle(h) };
    child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    child.wait().unwrap();
    let dump = std::fs::read(out).unwrap();
    let found = dump.windows(32).any(|w| w == &marker[..]);
    println!(
        "mode={mode} read_process_memory_got_prekey={rpm_ok} minidump_written={} \
         dump_bytes={} prekey_marker_in_full_memory_dump={found}",
        ok != 0,
        dump.len()
    );
    std::fs::remove_file(out).ok();
}

#[cfg(target_os = "linux")]
fn dontdump() {
    let mut rng = Rng(5);
    let mut cb = Vec::new();
    let pk = make("guarded", &mut rng, &mut cb, false);
    let (a, n) = pk.pieces[0];
    let flags = |a: usize| -> String {
        let s = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut hit = false;
        for l in s.lines() {
            if let Some((r, _)) = l.split_once(' ') {
                if let Some((lo, hi)) = r.split_once('-') {
                    if let (Ok(lo), Ok(hi)) =
                        (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
                    {
                        hit = lo <= a && a < hi;
                        continue;
                    }
                }
            }
            if hit && l.starts_with("VmFlags:") {
                return l.to_string();
            }
        }
        "none".into()
    };
    let before = flags(a);
    let r = unsafe { libc::madvise(a as *mut _, n, libc::MADV_DONTDUMP) };
    let after = flags(a);
    println!("madvise_ret={r} before=[{before}] after=[{after}]");
}

/// Worst case for a mapping: readable memory directly below it (what `mmap` packing gives on
/// Linux), built as one allocation [64 KiB readable][layout][64 KiB readable], and a 64 KiB read starting
/// 1 KiB below the layout.
fn neighbor(layout: &str) {
    let page = region::page::size();
    let guard = if layout == "guarded" { page } else { 0 };
    let total = 65536 + guard + PREKEY_LEN + guard + 65536;
    let mut m = region::alloc(total, Protection::READ_WRITE).unwrap();
    let base = m.as_mut_ptr::<u8>();
    let mut rng = Rng(3);
    unsafe { std::ptr::write_bytes(base, 0xAB, 65536) };
    let a = unsafe { base.add(65536 + guard) };
    unsafe { std::ptr::write_bytes(a.add(PREKEY_LEN + guard), 0xCD, 65536) };
    rng.fill(unsafe { std::slice::from_raw_parts_mut(a, PREKEY_LEN) });
    if guard > 0 {
        unsafe {
            region::protect(base.add(65536), page, Protection::NONE).unwrap();
            region::protect(a.add(PREKEY_LEN), page, Protection::NONE).unwrap();
            region::protect(a, PREKEY_LEN, Protection::READ).unwrap();
        }
    }
    let start = unsafe { base.add(65536 - 1024) };
    let mut dst = region::alloc(OVERREAD, Protection::READ_WRITE).unwrap();
    use std::io::Write;
    print!("layout={layout} readable_neighbor_directly_below=true read_from=layout-1024 len=65536 ");
    std::io::stdout().flush().unwrap();
    unsafe { libc::memcpy(dst.as_mut_ptr::<u8>() as *mut _, start as *const _, OVERREAD) };
    let copy = unsafe { std::slice::from_raw_parts(dst.as_ptr::<u8>(), OVERREAD) };
    let pkb = unsafe { std::slice::from_raw_parts(a, PREKEY_LEN) };
    let off = a as usize - start as usize;
    let got = copy[off..off + PREKEY_LEN].iter().zip(pkb).filter(|(x, y)| x == y).count();
    println!("survived=true prekey_bytes_matching={got}/16384");
}

/// Does a locked block stay locked across READ -> NONE -> READ? Checked three ways: the
/// quota (does NONE free quota for one more lock?), a final unlock (does it say "not
/// locked"?) and, on Linux, the smaps `lo` flag.
fn lockcycle(to: Protection) {
    let page = region::page::size();
    let mk = || {
        let mut m = region::alloc(PREKEY_LEN + 2 * page, Protection::READ_WRITE).unwrap();
        let p = unsafe { m.as_mut_ptr::<u8>().add(page) };
        (m, p as usize)
    };
    // Fill the quota.
    let mut held = Vec::new();
    loop {
        let (m, p) = mk();
        match region::lock(p as *const u8, PREKEY_LEN) {
            Ok(g) => held.push((m, p, g)),
            Err(e) => {
                println!("filled quota with {} locked blocks ({e})", held.len());
                break;
            }
        }
        if held.len() >= 64 {
            println!("quota not reached at 64 blocks (Linux limit high); continuing");
            break;
        }
    }
    #[cfg(target_os = "linux")]
    let lo = |a: usize| -> bool {
        let s = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut hit = false;
        for l in s.lines() {
            if let Some((r, _)) = l.split_once(' ') {
                if let Some((x, y)) = r.split_once('-') {
                    if let (Ok(x), Ok(y)) = (usize::from_str_radix(x, 16), usize::from_str_radix(y, 16)) {
                        hit = x <= a && a < y;
                        continue;
                    }
                }
            }
            if hit && l.starts_with("VmFlags:") {
                return l.split_whitespace().any(|f| f == "lo");
            }
        }
        false
    };
    let _p0 = held[0].1;
    println!("cycle: READ_WRITE -> {to:?} -> READ");
    #[cfg(target_os = "linux")]
    println!("linux lo flag before NONE: {}", lo(_p0));
    for (_, p, _) in &held {
        unsafe { region::protect(*p as *const u8, PREKEY_LEN, to).unwrap() };
    }
    #[cfg(target_os = "linux")]
    println!("linux lo flag while NONE: {}", lo(_p0));
    // If NONE released the locks, the quota has room again.
    let (m2, p2) = mk();
    let extra = region::lock(p2 as *const u8, PREKEY_LEN);
    println!("extra lock while all NONE: {}", if extra.is_ok() { "SUCCEEDED (quota freed => locks dropped?)" } else { "refused (quota still held)" });
    drop(extra);
    drop(m2);
    for (_, p, _) in &held {
        unsafe { region::protect(*p as *const u8, PREKEY_LEN, Protection::READ).unwrap() };
    }
    #[cfg(target_os = "linux")]
    println!("linux lo flag after READ again: {}", lo(_p0));
    let (m3, p3) = mk();
    let extra2 = region::lock(p3 as *const u8, PREKEY_LEN);
    println!("extra lock after READ again: {}", if extra2.is_ok() { "SUCCEEDED" } else { "refused" });
    drop(extra2);
    drop(m3);
    // Unlock each by hand: an error means the lock was gone.
    let mut ok = 0;
    let mut gone = 0;
    for (m, p, g) in held {
        std::mem::forget(g);
        match unsafe { region::unlock(p as *const u8, PREKEY_LEN) } {
            Ok(()) => ok += 1,
            Err(e) => {
                if gone == 0 {
                    println!("first unlock error: {e}");
                }
                gone += 1
            }
        }
        drop(m);
    }
    println!("after NONE/READ cycle: unlock ok={ok} not-locked={gone}");
}

#[cfg(windows)]
fn wsex() {
    use windows_sys::Win32::System::ProcessStatus::{K32QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let page = region::page::size();
    let mut m = region::alloc(PREKEY_LEN + 2 * page, Protection::READ_WRITE).unwrap();
    let p = unsafe { m.as_mut_ptr::<u8>().add(page) };
    unsafe { std::ptr::write_bytes(p, 0x5A, PREKEY_LEN) };
    let g = region::lock(p, PREKEY_LEN).unwrap();
    let q = |label: &str| {
        let mut info: [PSAPI_WORKING_SET_EX_INFORMATION; 4] = unsafe { std::mem::zeroed() };
        for (i, e) in info.iter_mut().enumerate() {
            e.VirtualAddress = unsafe { p.add(i * 4096) } as *mut _;
        }
        let ok = unsafe {
            K32QueryWorkingSetEx(GetCurrentProcess(), info.as_mut_ptr().cast(), std::mem::size_of_val(&info) as u32)
        };
        let flags: Vec<String> = info
            .iter()
            .map(|e| {
                let f = unsafe { e.VirtualAttributes.Flags };
                format!("valid={} locked={}", f & 1, (f >> 22) & 1)
            })
            .collect();
        println!("{label}: query_ok={} pages=[{}]", ok != 0, flags.join("; "));
    };
    q("locked READ_WRITE");
    unsafe { region::protect(p, PREKEY_LEN, Protection::READ).unwrap() };
    q("after READ");
    unsafe { region::protect(p, PREKEY_LEN, Protection::NONE).unwrap() };
    q("after NONE");
    unsafe { region::protect(p, PREKEY_LEN, Protection::READ).unwrap() };
    q("after READ again (not touched)");
    let _ = unsafe { std::ptr::read_volatile(p) };
    q("after READ again and a read");
    std::mem::forget(g);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a[1].as_str() {
        "adj" => adj(&a[2], &a[3], a[4].parse().unwrap(), a.get(5).map(|s| s == "real").unwrap_or(false)),
        "quota" => quota(&a[2]),
        "bench" => bench(a[2].parse().unwrap()),
        #[cfg(windows)]
        "dump-child" => dump_child(&a[2]),
        #[cfg(windows)]
        "dump" => dump_parent(&a[2], &a[3]),
        #[cfg(target_os = "linux")]
        "dontdump" => dontdump(),
        "neighbor" => neighbor(&a[2]),
        "lockcycle" => lockcycle(if a[2] == "none" { Protection::NONE } else { Protection::READ }),
        #[cfg(windows)]
        "wsex" => wsex(),
        "page" => println!("page={}", region::page::size()),
        _ => panic!("subcommand"),
    }
}
