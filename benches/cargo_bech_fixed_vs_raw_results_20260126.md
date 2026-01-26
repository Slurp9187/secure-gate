## BENCH RUN #1 OF 3
cargo bench --all-features --bench fixed_vs_raw
    Finished `bench` profile [optimized] target(s) in 3.02s
     Running benches\fixed_vs_raw.rs (target\release\deps\fixed_vs_raw-bf80321c681dc99f.exe)
Benchmarking raw_32b/single index access
Benchmarking raw_32b/single index access: Warming up for 3.0000 s
Benchmarking raw_32b/single index access: Collecting 100 samples in estimated 5.0000 s (11B iterations)
Benchmarking raw_32b/single index access: Analyzing
raw_32b/single index access
                        time:   [450.94 ps 455.37 ps 460.45 ps]
Found 9 outliers among 100 measurements (9.00%)
  8 (8.00%) high mild
  1 (1.00%) high severe
Benchmarking raw_32b/full array XOR (crypto-like)
Benchmarking raw_32b/full array XOR (crypto-like): Warming up for 3.0000 s
Benchmarking raw_32b/full array XOR (crypto-like): Collecting 100 samples in estimated 5.0000 s (11B iterations)
Benchmarking raw_32b/full array XOR (crypto-like): Analyzing
raw_32b/full array XOR (crypto-like)
                        time:   [460.94 ps 470.88 ps 481.88 ps]
Found 2 outliers among 100 measurements (2.00%)
  1 (1.00%) high mild
  1 (1.00%) high severe

Benchmarking fixed_explicit_32b/single index access
Benchmarking fixed_explicit_32b/single index access: Warming up for 3.0000 s
Benchmarking fixed_explicit_32b/single index access: Collecting 100 samples in estimated 5.0000 s (9.7B iterations)
Benchmarking fixed_explicit_32b/single index access: Analyzing
fixed_explicit_32b/single index access
                        time:   [496.11 ps 500.87 ps 505.90 ps]
Found 13 outliers among 100 measurements (13.00%)
  8 (8.00%) high mild
  5 (5.00%) high severe
Benchmarking fixed_explicit_32b/full array XOR (crypto-like)
Benchmarking fixed_explicit_32b/full array XOR (crypto-like): Warming up for 3.0000 s
Benchmarking fixed_explicit_32b/full array XOR (crypto-like): Collecting 100 samples in estimated 5.0000 s (10B iterations)
Benchmarking fixed_explicit_32b/full array XOR (crypto-like): Analyzing
fixed_explicit_32b/full array XOR (crypto-like)
                        time:   [449.47 ps 453.82 ps 458.88 ps]
Found 6 outliers among 100 measurements (6.00%)
  5 (5.00%) high mild
  1 (1.00%) high severe
Benchmarking fixed_explicit_32b/mutable access (write + read)
Benchmarking fixed_explicit_32b/mutable access (write + read): Warming up for 3.0000 s
Benchmarking fixed_explicit_32b/mutable access (write + read): Collecting 100 samples in estimated 5.0000 s (7.1B iterations)
Benchmarking fixed_explicit_32b/mutable access (write + read): Analyzing
fixed_explicit_32b/mutable access (write + read)
                        time:   [728.49 ps 736.90 ps 745.73 ps]
Found 6 outliers among 100 measurements (6.00%)
  2 (2.00%) low mild
  4 (4.00%) high mild

Benchmarking fixed_alias_rawkey_32b/single index access
Benchmarking fixed_alias_rawkey_32b/single index access: Warming up for 3.0000 s
Benchmarking fixed_alias_rawkey_32b/single index access: Collecting 100 samples in estimated 5.0000 s (10B iterations)
Benchmarking fixed_alias_rawkey_32b/single index access: Analyzing
fixed_alias_rawkey_32b/single index access
                        time:   [486.69 ps 489.17 ps 491.82 ps]
Found 11 outliers among 100 measurements (11.00%)
  8 (8.00%) high mild
  3 (3.00%) high severe
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like)
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like): Warming up for 3.0000 s
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like): Collecting 100 samples in estimated 5.0000 s (11B iterations)
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like): Analyzing
fixed_alias_rawkey_32b/full array XOR (crypto-like)
                        time:   [462.92 ps 468.26 ps 473.83 ps]
Found 7 outliers among 100 measurements (7.00%)
  7 (7.00%) high mild
Benchmarking fixed_alias_rawkey_32b/mutable access
Benchmarking fixed_alias_rawkey_32b/mutable access: Warming up for 3.0000 s
Benchmarking fixed_alias_rawkey_32b/mutable access: Collecting 100 samples in estimated 5.0000 s (6.9B iterations)
Benchmarking fixed_alias_rawkey_32b/mutable access: Analyzing
fixed_alias_rawkey_32b/mutable access
                        time:   [729.73 ps 739.96 ps 751.04 ps]
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild

## BENCH RUN #2 OF 3
cargo bench --all-features --bench fixed_vs_raw
    Finished `bench` profile [optimized] target(s) in 0.23s
     Running benches\fixed_vs_raw.rs (target\release\deps\fixed_vs_raw-bf80321c681dc99f.exe)
Benchmarking raw_32b/single index access
Benchmarking raw_32b/single index access: Warming up for 3.0000 s
Benchmarking raw_32b/single index access: Collecting 100 samples in estimated 5.0000 s (9.7B iterations)
Benchmarking raw_32b/single index access: Analyzing
raw_32b/single index access
                        time:   [503.98 ps 508.86 ps 514.13 ps]
                        change: [+9.3379% +10.796% +12.235%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 8 outliers among 100 measurements (8.00%)
  6 (6.00%) high mild
  2 (2.00%) high severe
Benchmarking raw_32b/full array XOR (crypto-like)
Benchmarking raw_32b/full array XOR (crypto-like): Warming up for 3.0000 s
Benchmarking raw_32b/full array XOR (crypto-like): Collecting 100 samples in estimated 5.0000 s (10B iterations)
Benchmarking raw_32b/full array XOR (crypto-like): Analyzing
raw_32b/full array XOR (crypto-like)
                        time:   [482.30 ps 487.84 ps 493.84 ps]
                        change: [+1.1722% +3.6692% +6.2077%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 8 outliers among 100 measurements (8.00%)
  5 (5.00%) high mild
  3 (3.00%) high severe

Benchmarking fixed_explicit_32b/single index access
Benchmarking fixed_explicit_32b/single index access: Warming up for 3.0000 s
Benchmarking fixed_explicit_32b/single index access: Collecting 100 samples in estimated 5.0000 s (9.6B iterations)
Benchmarking fixed_explicit_32b/single index access: Analyzing
fixed_explicit_32b/single index access
                        time:   [506.35 ps 510.53 ps 515.07 ps]
                        change: [+2.0242% +3.1091% +4.2515%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 12 outliers among 100 measurements (12.00%)
  3 (3.00%) low mild
  4 (4.00%) high mild
  5 (5.00%) high severe
Benchmarking fixed_explicit_32b/full array XOR (crypto-like)
Benchmarking fixed_explicit_32b/full array XOR (crypto-like): Warming up for 3.0000 s
Benchmarking fixed_explicit_32b/full array XOR (crypto-like): Collecting 100 samples in estimated 5.0000 s (10B iterations)
Benchmarking fixed_explicit_32b/full array XOR (crypto-like): Analyzing
fixed_explicit_32b/full array XOR (crypto-like)
                        time:   [480.91 ps 488.24 ps 496.79 ps]
                        change: [+5.1210% +7.0780% +9.1381%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 10 outliers among 100 measurements (10.00%)
  8 (8.00%) high mild
  2 (2.00%) high severe
Benchmarking fixed_explicit_32b/mutable access (write + read)
Benchmarking fixed_explicit_32b/mutable access (write + read): Warming up for 3.0000 s
Benchmarking fixed_explicit_32b/mutable access (write + read): Collecting 100 samples in estimated 5.0000 s (6.8B iterations)
Benchmarking fixed_explicit_32b/mutable access (write + read): Analyzing
fixed_explicit_32b/mutable access (write + read)
                        time:   [711.67 ps 716.27 ps 721.50 ps]
                        change: [ΓêÆ3.6337% ΓêÆ2.5197% ΓêÆ1.4105%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 10 outliers among 100 measurements (10.00%)
  1 (1.00%) low mild
  6 (6.00%) high mild
  3 (3.00%) high severe

Benchmarking fixed_alias_rawkey_32b/single index access
Benchmarking fixed_alias_rawkey_32b/single index access: Warming up for 3.0000 s
Benchmarking fixed_alias_rawkey_32b/single index access: Collecting 100 samples in estimated 5.0000 s (9.6B iterations)
Benchmarking fixed_alias_rawkey_32b/single index access: Analyzing
fixed_alias_rawkey_32b/single index access
                        time:   [507.03 ps 510.08 ps 513.22 ps]
                        change: [+2.7035% +3.9225% +5.4108%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 10 outliers among 100 measurements (10.00%)
  3 (3.00%) low mild
  3 (3.00%) high mild
  4 (4.00%) high severe
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like)
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like): Warming up for 3.0000 s
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like): Collecting 100 samples in estimated 5.0000 s (9.8B iterations)
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like): Analyzing
fixed_alias_rawkey_32b/full array XOR (crypto-like)
                        time:   [489.01 ps 493.79 ps 498.82 ps]
                        change: [+4.1581% +5.4659% +6.8985%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 6 outliers among 100 measurements (6.00%)
  4 (4.00%) high mild
  2 (2.00%) high severe
Benchmarking fixed_alias_rawkey_32b/mutable access
Benchmarking fixed_alias_rawkey_32b/mutable access: Warming up for 3.0000 s
Benchmarking fixed_alias_rawkey_32b/mutable access: Collecting 100 samples in estimated 5.0000 s (6.9B iterations)
Benchmarking fixed_alias_rawkey_32b/mutable access: Analyzing
fixed_alias_rawkey_32b/mutable access
                        time:   [716.04 ps 729.31 ps 743.51 ps]
                        change: [ΓêÆ5.3271% ΓêÆ3.6668% ΓêÆ1.9555%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 16 outliers among 100 measurements (16.00%)
  7 (7.00%) high mild
  9 (9.00%) high severe

## BENCH RUN #3 OF 3
cargo bench --all-features --bench fixed_vs_raw
    Finished `bench` profile [optimized] target(s) in 0.20s
     Running benches\fixed_vs_raw.rs (target\release\deps\fixed_vs_raw-bf80321c681dc99f.exe)
Benchmarking raw_32b/single index access
Benchmarking raw_32b/single index access: Warming up for 3.0000 s
Benchmarking raw_32b/single index access: Collecting 100 samples in estimated 5.0000 s (10B iterations)
Benchmarking raw_32b/single index access: Analyzing
raw_32b/single index access
                        time:   [619.21 ps 634.70 ps 651.68 ps]
                        change: [+12.081% +15.467% +19.168%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild
Benchmarking raw_32b/full array XOR (crypto-like)
Benchmarking raw_32b/full array XOR (crypto-like): Warming up for 3.0000 s
Benchmarking raw_32b/full array XOR (crypto-like): Collecting 100 samples in estimated 5.0000 s (11B iterations)
Benchmarking raw_32b/full array XOR (crypto-like): Analyzing
raw_32b/full array XOR (crypto-like)
                        time:   [456.81 ps 460.95 ps 465.52 ps]
                        change: [ΓêÆ7.5215% ΓêÆ5.7595% ΓêÆ4.0558%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

Benchmarking fixed_explicit_32b/single index access
Benchmarking fixed_explicit_32b/single index access: Warming up for 3.0000 s
Benchmarking fixed_explicit_32b/single index access: Collecting 100 samples in estimated 5.0000 s (9.8B iterations)
Benchmarking fixed_explicit_32b/single index access: Analyzing
fixed_explicit_32b/single index access
                        time:   [530.35 ps 539.30 ps 548.69 ps]
                        change: [+2.3633% +3.7895% +5.3898%] (p = 0.00 < 0.05)
                        Performance has regressed.
Benchmarking fixed_explicit_32b/full array XOR (crypto-like)
Benchmarking fixed_explicit_32b/full array XOR (crypto-like): Warming up for 3.0000 s
Benchmarking fixed_explicit_32b/full array XOR (crypto-like): Collecting 100 samples in estimated 5.0000 s (10B iterations)
Benchmarking fixed_explicit_32b/full array XOR (crypto-like): Analyzing
fixed_explicit_32b/full array XOR (crypto-like)
                        time:   [483.89 ps 487.82 ps 491.94 ps]
                        change: [ΓêÆ2.2570% ΓêÆ0.5712% +1.0134%] (p = 0.51 > 0.05)
                        No change in performance detected.
Found 6 outliers among 100 measurements (6.00%)
  5 (5.00%) high mild
  1 (1.00%) high severe
Benchmarking fixed_explicit_32b/mutable access (write + read)
Benchmarking fixed_explicit_32b/mutable access (write + read): Warming up for 3.0000 s
Benchmarking fixed_explicit_32b/mutable access (write + read): Collecting 100 samples in estimated 5.0000 s (6.6B iterations)
Benchmarking fixed_explicit_32b/mutable access (write + read): Analyzing
fixed_explicit_32b/mutable access (write + read)
                        time:   [840.30 ps 850.07 ps 859.35 ps]
                        change: [+10.413% +12.441% +14.478%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking fixed_alias_rawkey_32b/single index access
Benchmarking fixed_alias_rawkey_32b/single index access: Warming up for 3.0000 s
Benchmarking fixed_alias_rawkey_32b/single index access: Collecting 100 samples in estimated 5.0000 s (9.2B iterations)
Benchmarking fixed_alias_rawkey_32b/single index access: Analyzing
fixed_alias_rawkey_32b/single index access
                        time:   [537.16 ps 541.53 ps 546.12 ps]
                        change: [+4.5459% +5.9705% +7.2456%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) high mild
  2 (2.00%) high severe
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like)
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like): Warming up for 3.0000 s
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like): Collecting 100 samples in estimated 5.0000 s (8.8B iterations)
Benchmarking fixed_alias_rawkey_32b/full array XOR (crypto-like): Analyzing
fixed_alias_rawkey_32b/full array XOR (crypto-like)
                        time:   [547.17 ps 556.16 ps 565.64 ps]
                        change: [+12.874% +14.468% +16.065%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 5 outliers among 100 measurements (5.00%)
  2 (2.00%) low mild
  3 (3.00%) high mild
Benchmarking fixed_alias_rawkey_32b/mutable access
Benchmarking fixed_alias_rawkey_32b/mutable access: Warming up for 3.0000 s
Benchmarking fixed_alias_rawkey_32b/mutable access: Collecting 100 samples in estimated 5.0000 s (6.7B iterations)
Benchmarking fixed_alias_rawkey_32b/mutable access: Analyzing
fixed_alias_rawkey_32b/mutable access
                        time:   [781.54 ps 796.15 ps 809.55 ps]
                        change: [+4.2496% +6.0727% +7.8748%] (p = 0.00 < 0.05)
                        Performance has regressed.
