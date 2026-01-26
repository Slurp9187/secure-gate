## BENCH RUN #1 OF 3
cargo bench --all-features --bench ct_eq_auto
    Finished `bench` profile [optimized] target(s) in 3.15s
     Running benches\ct_eq_auto.rs (target\release\deps\ct_eq_auto-5728c6dc1fed2bb2.exe)
fixed_ct_eq_auto_16b/default_32b
                        time:   [63.923 ns 64.568 ns 65.308 ns]
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild
fixed_ct_eq_auto_16b/thresh_0_force_hash
                        time:   [255.33 ns 258.73 ns 262.63 ns]
Found 9 outliers among 100 measurements (9.00%)
  7 (7.00%) high mild
  2 (2.00%) high severe
fixed_ct_eq_auto_16b/thresh_16_force_ct_eq
                        time:   [63.974 ns 64.672 ns 65.494 ns]
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild
fixed_ct_eq_auto_16b/thresh_64_force_ct_eq
                        time:   [64.267 ns 65.036 ns 65.897 ns]
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

fixed_ct_eq_auto_32b/default_32b
                        time:   [123.43 ns 124.75 ns 126.33 ns]
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild
fixed_ct_eq_auto_32b/thresh_0_force_hash
                        time:   [260.33 ns 262.38 ns 264.76 ns]
Found 14 outliers among 100 measurements (14.00%)
  10 (10.00%) high mild
  4 (4.00%) high severe
fixed_ct_eq_auto_32b/thresh_16_force_ct_eq
                        time:   [268.84 ns 273.01 ns 277.25 ns]
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild
fixed_ct_eq_auto_32b/thresh_64_force_hash
                        time:   [123.73 ns 124.90 ns 126.22 ns]
Found 9 outliers among 100 measurements (9.00%)
  7 (7.00%) high mild
  2 (2.00%) high severe

fixed_ct_eq_auto_64b/default_32b
                        time:   [275.17 ns 278.01 ns 281.31 ns]
Found 14 outliers among 100 measurements (14.00%)
  9 (9.00%) high mild
  5 (5.00%) high severe
fixed_ct_eq_auto_64b/thresh_0_force_hash
                        time:   [278.67 ns 281.64 ns 284.92 ns]
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild
fixed_ct_eq_auto_64b/thresh_64_force_ct_eq
                        time:   [245.26 ns 248.48 ns 252.06 ns]
Found 8 outliers among 100 measurements (8.00%)
  8 (8.00%) high mild
fixed_ct_eq_auto_64b/thresh_128_force_ct_eq
                        time:   [250.80 ns 254.45 ns 258.56 ns]
Found 6 outliers among 100 measurements (6.00%)
  6 (6.00%) high mild

dynamic_ct_eq_auto_128b/default_32b
                        time:   [374.52 ns 377.19 ns 380.07 ns]
Found 5 outliers among 100 measurements (5.00%)
  3 (3.00%) high mild
  2 (2.00%) high severe
dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq
                        time:   [378.62 ns 381.86 ns 385.42 ns]
Found 13 outliers among 100 measurements (13.00%)
  8 (8.00%) high mild
  5 (5.00%) high severe
dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq
                        time:   [494.61 ns 498.66 ns 503.45 ns]
Found 10 outliers among 100 measurements (10.00%)
  7 (7.00%) high mild
  3 (3.00%) high severe

dynamic_ct_eq_auto_1kb/default_32b
                        time:   [1.7657 µs 1.7774 µs 1.7913 µs]
Found 13 outliers among 100 measurements (13.00%)
  8 (8.00%) high mild
  5 (5.00%) high severe
dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq
                        time:   [1.7616 µs 1.7821 µs 1.8073 µs]
Found 17 outliers among 100 measurements (17.00%)
  5 (5.00%) high mild
  12 (12.00%) high severe
dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq
                        time:   [3.9086 µs 3.9545 µs 4.0077 µs]
Found 16 outliers among 100 measurements (16.00%)
  8 (8.00%) high mild
  8 (8.00%) high severe

## BENCH RUN #2 OF 3
cargo bench --all-features --bench ct_eq_auto
    Finished `bench` profile [optimized] target(s) in 0.21s
     Running benches\ct_eq_auto.rs (target\release\deps\ct_eq_auto-5728c6dc1fed2bb2.exe)
Benchmarking fixed_ct_eq_auto_16b/default_32b
Benchmarking fixed_ct_eq_auto_16b/default_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_16b/default_32b: Collecting 100 samples in estimated 5.0001 s (76M iterations)
Benchmarking fixed_ct_eq_auto_16b/default_32b: Analyzing
fixed_ct_eq_auto_16b/default_32b
                        time:   [63.582 ns 64.058 ns 64.638 ns]
                        change: [ΓêÆ1.5957% ΓêÆ0.0378% +1.5702%] (p = 0.96 > 0.05)
                        No change in performance detected.
Found 2 outliers among 100 measurements (2.00%)
  1 (1.00%) high mild
  1 (1.00%) high severe
Benchmarking fixed_ct_eq_auto_16b/thresh_0_force_hash
Benchmarking fixed_ct_eq_auto_16b/thresh_0_force_hash: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_16b/thresh_0_force_hash: Collecting 100 samples in estimated 5.0003 s (19M iterations)
Benchmarking fixed_ct_eq_auto_16b/thresh_0_force_hash: Analyzing
fixed_ct_eq_auto_16b/thresh_0_force_hash
                        time:   [254.45 ns 256.83 ns 259.39 ns]
                        change: [ΓêÆ4.9694% ΓêÆ2.9999% ΓêÆ1.1181%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 8 outliers among 100 measurements (8.00%)
  8 (8.00%) high mild
Benchmarking fixed_ct_eq_auto_16b/thresh_16_force_ct_eq
Benchmarking fixed_ct_eq_auto_16b/thresh_16_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_16b/thresh_16_force_ct_eq: Collecting 100 samples in estimated 5.0001 s (70M iterations)
Benchmarking fixed_ct_eq_auto_16b/thresh_16_force_ct_eq: Analyzing
fixed_ct_eq_auto_16b/thresh_16_force_ct_eq
                        time:   [72.122 ns 73.065 ns 74.045 ns]
                        change: [+10.043% +12.132% +14.350%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high severe
Benchmarking fixed_ct_eq_auto_16b/thresh_64_force_ct_eq
Benchmarking fixed_ct_eq_auto_16b/thresh_64_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_16b/thresh_64_force_ct_eq: Collecting 100 samples in estimated 5.0001 s (74M iterations)
Benchmarking fixed_ct_eq_auto_16b/thresh_64_force_ct_eq: Analyzing
fixed_ct_eq_auto_16b/thresh_64_force_ct_eq
                        time:   [66.046 ns 66.781 ns 67.616 ns]
                        change: [ΓêÆ0.0518% +1.3778% +2.8942%] (p = 0.07 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  8 (8.00%) high mild
  2 (2.00%) high severe

Benchmarking fixed_ct_eq_auto_32b/default_32b
Benchmarking fixed_ct_eq_auto_32b/default_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_32b/default_32b: Collecting 100 samples in estimated 5.0005 s (39M iterations)
Benchmarking fixed_ct_eq_auto_32b/default_32b: Analyzing
fixed_ct_eq_auto_32b/default_32b
                        time:   [125.71 ns 126.86 ns 128.11 ns]
                        change: [ΓêÆ1.0903% +0.1740% +1.4579%] (p = 0.79 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  9 (9.00%) high mild
  1 (1.00%) high severe
Benchmarking fixed_ct_eq_auto_32b/thresh_0_force_hash
Benchmarking fixed_ct_eq_auto_32b/thresh_0_force_hash: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_32b/thresh_0_force_hash: Collecting 100 samples in estimated 5.0013 s (18M iterations)
Benchmarking fixed_ct_eq_auto_32b/thresh_0_force_hash: Analyzing
fixed_ct_eq_auto_32b/thresh_0_force_hash
                        time:   [270.39 ns 272.15 ns 274.10 ns]
                        change: [+0.6297% +2.2712% +3.7435%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 15 outliers among 100 measurements (15.00%)
  1 (1.00%) low mild
  8 (8.00%) high mild
  6 (6.00%) high severe
Benchmarking fixed_ct_eq_auto_32b/thresh_16_force_ct_eq
Benchmarking fixed_ct_eq_auto_32b/thresh_16_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_32b/thresh_16_force_ct_eq: Collecting 100 samples in estimated 5.0001 s (18M iterations)
Benchmarking fixed_ct_eq_auto_32b/thresh_16_force_ct_eq: Analyzing
fixed_ct_eq_auto_32b/thresh_16_force_ct_eq
                        time:   [272.43 ns 273.93 ns 275.56 ns]
                        change: [+0.0267% +1.3680% +2.6807%] (p = 0.05 < 0.05)
                        Change within noise threshold.
Found 13 outliers among 100 measurements (13.00%)
  8 (8.00%) high mild
  5 (5.00%) high severe
Benchmarking fixed_ct_eq_auto_32b/thresh_64_force_hash
Benchmarking fixed_ct_eq_auto_32b/thresh_64_force_hash: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_32b/thresh_64_force_hash: Collecting 100 samples in estimated 5.0003 s (38M iterations)
Benchmarking fixed_ct_eq_auto_32b/thresh_64_force_hash: Analyzing
fixed_ct_eq_auto_32b/thresh_64_force_hash
                        time:   [128.21 ns 129.58 ns 131.09 ns]
                        change: [+0.9624% +2.5840% +4.3414%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 6 outliers among 100 measurements (6.00%)
  5 (5.00%) high mild
  1 (1.00%) high severe

Benchmarking fixed_ct_eq_auto_64b/default_32b
Benchmarking fixed_ct_eq_auto_64b/default_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_64b/default_32b: Collecting 100 samples in estimated 5.0006 s (17M iterations)
Benchmarking fixed_ct_eq_auto_64b/default_32b: Analyzing
fixed_ct_eq_auto_64b/default_32b
                        time:   [282.65 ns 284.35 ns 286.18 ns]
                        change: [+2.0028% +3.2053% +4.4988%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 10 outliers among 100 measurements (10.00%)
  8 (8.00%) high mild
  2 (2.00%) high severe
Benchmarking fixed_ct_eq_auto_64b/thresh_0_force_hash
Benchmarking fixed_ct_eq_auto_64b/thresh_0_force_hash: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_64b/thresh_0_force_hash: Collecting 100 samples in estimated 5.0014 s (17M iterations)
Benchmarking fixed_ct_eq_auto_64b/thresh_0_force_hash: Analyzing
fixed_ct_eq_auto_64b/thresh_0_force_hash
                        time:   [283.89 ns 285.86 ns 288.17 ns]
                        change: [+0.9747% +2.0126% +3.1211%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 11 outliers among 100 measurements (11.00%)
  7 (7.00%) high mild
  4 (4.00%) high severe
Benchmarking fixed_ct_eq_auto_64b/thresh_64_force_ct_eq
Benchmarking fixed_ct_eq_auto_64b/thresh_64_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_64b/thresh_64_force_ct_eq: Collecting 100 samples in estimated 5.0003 s (19M iterations)
Benchmarking fixed_ct_eq_auto_64b/thresh_64_force_ct_eq: Analyzing
fixed_ct_eq_auto_64b/thresh_64_force_ct_eq
                        time:   [251.23 ns 254.60 ns 258.37 ns]
                        change: [+0.3966% +2.0160% +3.5713%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 13 outliers among 100 measurements (13.00%)
  10 (10.00%) high mild
  3 (3.00%) high severe
Benchmarking fixed_ct_eq_auto_64b/thresh_128_force_ct_eq
Benchmarking fixed_ct_eq_auto_64b/thresh_128_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_64b/thresh_128_force_ct_eq: Collecting 100 samples in estimated 5.0001 s (19M iterations)
Benchmarking fixed_ct_eq_auto_64b/thresh_128_force_ct_eq: Analyzing
fixed_ct_eq_auto_64b/thresh_128_force_ct_eq
                        time:   [252.73 ns 254.42 ns 256.24 ns]
                        change: [ΓêÆ2.3324% ΓêÆ0.8511% +0.5780%] (p = 0.26 > 0.05)
                        No change in performance detected.
Found 8 outliers among 100 measurements (8.00%)
  6 (6.00%) high mild
  2 (2.00%) high severe

Benchmarking dynamic_ct_eq_auto_128b/default_32b
Benchmarking dynamic_ct_eq_auto_128b/default_32b: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_128b/default_32b: Collecting 100 samples in estimated 5.0010 s (13M iterations)
Benchmarking dynamic_ct_eq_auto_128b/default_32b: Analyzing
dynamic_ct_eq_auto_128b/default_32b
                        time:   [381.35 ns 384.03 ns 386.88 ns]
                        change: [+0.2872% +1.2173% +2.1325%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 20 outliers among 100 measurements (20.00%)
  1 (1.00%) low severe
  7 (7.00%) low mild
  5 (5.00%) high mild
  7 (7.00%) high severe
Benchmarking dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq
Benchmarking dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq: Collecting 100 samples in estimated 5.0004 s (13M iterations)
Benchmarking dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq: Analyzing
dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq
                        time:   [379.49 ns 382.29 ns 385.51 ns]
                        change: [ΓêÆ0.8713% +0.1690% +1.2109%] (p = 0.74 > 0.05)
                        No change in performance detected.
Found 11 outliers among 100 measurements (11.00%)
  10 (10.00%) high mild
  1 (1.00%) high severe
Benchmarking dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq
Benchmarking dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq: Collecting 100 samples in estimated 5.0015 s (9.6M iterations)
Benchmarking dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq: Analyzing
dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq
                        time:   [493.67 ns 498.00 ns 503.03 ns]
                        change: [ΓêÆ1.1305% ΓêÆ0.0366% +1.0481%] (p = 0.95 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  7 (7.00%) high mild
  3 (3.00%) high severe

Benchmarking dynamic_ct_eq_auto_1kb/default_32b
Benchmarking dynamic_ct_eq_auto_1kb/default_32b: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_1kb/default_32b: Collecting 100 samples in estimated 5.0046 s (2.8M iterations)
Benchmarking dynamic_ct_eq_auto_1kb/default_32b: Analyzing
dynamic_ct_eq_auto_1kb/default_32b
                        time:   [1.7654 ┬╡s 1.7797 ┬╡s 1.7966 ┬╡s]
                        change: [ΓêÆ1.8479% ΓêÆ0.8095% +0.3037%] (p = 0.14 > 0.05)
                        No change in performance detected.
Found 14 outliers among 100 measurements (14.00%)
  6 (6.00%) high mild
  8 (8.00%) high severe
Benchmarking dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq
Benchmarking dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq: Collecting 100 samples in estimated 5.0081 s (2.8M iterations)
Benchmarking dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq: Analyzing
dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq
                        time:   [1.7679 ┬╡s 1.7853 ┬╡s 1.8063 ┬╡s]
                        change: [ΓêÆ1.8645% ΓêÆ0.6159% +0.5976%] (p = 0.33 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  3 (3.00%) high mild
  9 (9.00%) high severe
Benchmarking dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq
Benchmarking dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq: Collecting 100 samples in estimated 5.0019 s (1.2M iterations)
Benchmarking dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq: Analyzing
dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq
                        time:   [4.4229 ┬╡s 4.5323 ┬╡s 4.6487 ┬╡s]
                        change: [+10.411% +12.673% +15.207%] (p = 0.00 < 0.05)
                        Performance has regressed.

## BENCH RUN #3 OF 3
cargo bench --all-features --bench ct_eq_auto
    Finished `bench` profile [optimized] target(s) in 0.22s
     Running benches\ct_eq_auto.rs (target\release\deps\ct_eq_auto-5728c6dc1fed2bb2.exe)
Benchmarking fixed_ct_eq_auto_16b/default_32b
Benchmarking fixed_ct_eq_auto_16b/default_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_16b/default_32b: Collecting 100 samples in estimated 5.0003 s (74M iterations)
Benchmarking fixed_ct_eq_auto_16b/default_32b: Analyzing
fixed_ct_eq_auto_16b/default_32b
                        time:   [64.971 ns 65.614 ns 66.341 ns]
                        change: [+1.6199% +3.3411% +5.1045%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild
Benchmarking fixed_ct_eq_auto_16b/thresh_0_force_hash
Benchmarking fixed_ct_eq_auto_16b/thresh_0_force_hash: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_16b/thresh_0_force_hash: Collecting 100 samples in estimated 5.0007 s (18M iterations)
Benchmarking fixed_ct_eq_auto_16b/thresh_0_force_hash: Analyzing
fixed_ct_eq_auto_16b/thresh_0_force_hash
                        time:   [279.02 ns 284.04 ns 288.97 ns]
                        change: [+6.9129% +8.8354% +10.770%] (p = 0.00 < 0.05)
                        Performance has regressed.
Benchmarking fixed_ct_eq_auto_16b/thresh_16_force_ct_eq
Benchmarking fixed_ct_eq_auto_16b/thresh_16_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_16b/thresh_16_force_ct_eq: Collecting 100 samples in estimated 5.0001 s (70M iterations)
Benchmarking fixed_ct_eq_auto_16b/thresh_16_force_ct_eq: Analyzing
fixed_ct_eq_auto_16b/thresh_16_force_ct_eq
                        time:   [66.080 ns 66.880 ns 67.754 ns]
                        change: [ΓêÆ9.8745% ΓêÆ8.1937% ΓêÆ6.4934%] (p = 0.00 < 0.05)
                        Performance has improved.
Benchmarking fixed_ct_eq_auto_16b/thresh_64_force_ct_eq
Benchmarking fixed_ct_eq_auto_16b/thresh_64_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_16b/thresh_64_force_ct_eq: Collecting 100 samples in estimated 5.0002 s (75M iterations)
Benchmarking fixed_ct_eq_auto_16b/thresh_64_force_ct_eq: Analyzing
fixed_ct_eq_auto_16b/thresh_64_force_ct_eq
                        time:   [65.677 ns 66.198 ns 66.767 ns]
                        change: [ΓêÆ1.4709% ΓêÆ0.2080% +1.0735%] (p = 0.74 > 0.05)
                        No change in performance detected.
Found 5 outliers among 100 measurements (5.00%)
  4 (4.00%) high mild
  1 (1.00%) high severe

Benchmarking fixed_ct_eq_auto_32b/default_32b
Benchmarking fixed_ct_eq_auto_32b/default_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_32b/default_32b: Collecting 100 samples in estimated 5.0006 s (39M iterations)
Benchmarking fixed_ct_eq_auto_32b/default_32b: Analyzing
fixed_ct_eq_auto_32b/default_32b
                        time:   [126.10 ns 127.76 ns 129.66 ns]
                        change: [ΓêÆ0.2921% +1.0004% +2.3004%] (p = 0.14 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  6 (6.00%) high mild
  6 (6.00%) high severe
Benchmarking fixed_ct_eq_auto_32b/thresh_0_force_hash
Benchmarking fixed_ct_eq_auto_32b/thresh_0_force_hash: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_32b/thresh_0_force_hash: Collecting 100 samples in estimated 5.0008 s (18M iterations)
Benchmarking fixed_ct_eq_auto_32b/thresh_0_force_hash: Analyzing
fixed_ct_eq_auto_32b/thresh_0_force_hash
                        time:   [269.36 ns 271.38 ns 273.72 ns]
                        change: [ΓêÆ0.7325% +0.2639% +1.4326%] (p = 0.63 > 0.05)
                        No change in performance detected.
Found 15 outliers among 100 measurements (15.00%)
  1 (1.00%) low mild
  8 (8.00%) high mild
  6 (6.00%) high severe
Benchmarking fixed_ct_eq_auto_32b/thresh_16_force_ct_eq
Benchmarking fixed_ct_eq_auto_32b/thresh_16_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_32b/thresh_16_force_ct_eq: Collecting 100 samples in estimated 5.0001 s (17M iterations)
Benchmarking fixed_ct_eq_auto_32b/thresh_16_force_ct_eq: Analyzing
fixed_ct_eq_auto_32b/thresh_16_force_ct_eq
                        time:   [278.62 ns 280.87 ns 283.28 ns]
                        change: [+2.3115% +3.4809% +4.7438%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 2 outliers among 100 measurements (2.00%)
  1 (1.00%) high mild
  1 (1.00%) high severe
Benchmarking fixed_ct_eq_auto_32b/thresh_64_force_hash
Benchmarking fixed_ct_eq_auto_32b/thresh_64_force_hash: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_32b/thresh_64_force_hash: Collecting 100 samples in estimated 5.0005 s (36M iterations)
Benchmarking fixed_ct_eq_auto_32b/thresh_64_force_hash: Analyzing
fixed_ct_eq_auto_32b/thresh_64_force_hash
                        time:   [139.45 ns 142.59 ns 145.70 ns]
                        change: [+7.5959% +9.3281% +11.160%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 6 outliers among 100 measurements (6.00%)
  1 (1.00%) low mild
  5 (5.00%) high mild

Benchmarking fixed_ct_eq_auto_64b/default_32b
Benchmarking fixed_ct_eq_auto_64b/default_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_64b/default_32b: Collecting 100 samples in estimated 5.0012 s (16M iterations)
Benchmarking fixed_ct_eq_auto_64b/default_32b: Analyzing
fixed_ct_eq_auto_64b/default_32b
                        time:   [293.62 ns 296.71 ns 300.21 ns]
                        change: [+3.4014% +4.7537% +6.2654%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 6 outliers among 100 measurements (6.00%)
  5 (5.00%) high mild
  1 (1.00%) high severe
Benchmarking fixed_ct_eq_auto_64b/thresh_0_force_hash
Benchmarking fixed_ct_eq_auto_64b/thresh_0_force_hash: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_64b/thresh_0_force_hash: Collecting 100 samples in estimated 5.0006 s (16M iterations)
Benchmarking fixed_ct_eq_auto_64b/thresh_0_force_hash: Analyzing
fixed_ct_eq_auto_64b/thresh_0_force_hash
                        time:   [289.48 ns 291.72 ns 294.33 ns]
                        change: [+1.0119% +1.8540% +2.6919%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 17 outliers among 100 measurements (17.00%)
  4 (4.00%) low mild
  6 (6.00%) high mild
  7 (7.00%) high severe
Benchmarking fixed_ct_eq_auto_64b/thresh_64_force_ct_eq
Benchmarking fixed_ct_eq_auto_64b/thresh_64_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_64b/thresh_64_force_ct_eq: Collecting 100 samples in estimated 5.0006 s (18M iterations)
Benchmarking fixed_ct_eq_auto_64b/thresh_64_force_ct_eq: Analyzing
fixed_ct_eq_auto_64b/thresh_64_force_ct_eq
                        time:   [272.37 ns 275.98 ns 279.68 ns]
                        change: [+9.0441% +10.749% +12.515%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 6 outliers among 100 measurements (6.00%)
  1 (1.00%) low mild
  3 (3.00%) high mild
  2 (2.00%) high severe
Benchmarking fixed_ct_eq_auto_64b/thresh_128_force_ct_eq
Benchmarking fixed_ct_eq_auto_64b/thresh_128_force_ct_eq: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_auto_64b/thresh_128_force_ct_eq: Collecting 100 samples in estimated 5.0010 s (19M iterations)
Benchmarking fixed_ct_eq_auto_64b/thresh_128_force_ct_eq: Analyzing
fixed_ct_eq_auto_64b/thresh_128_force_ct_eq
                        time:   [267.42 ns 270.88 ns 274.31 ns]
                        change: [+3.5424% +4.8780% +6.1387%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking dynamic_ct_eq_auto_128b/default_32b
Benchmarking dynamic_ct_eq_auto_128b/default_32b: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_128b/default_32b: Collecting 100 samples in estimated 5.0001 s (13M iterations)
Benchmarking dynamic_ct_eq_auto_128b/default_32b: Analyzing
dynamic_ct_eq_auto_128b/default_32b
                        time:   [390.25 ns 394.94 ns 400.52 ns]
                        change: [+1.9183% +3.0658% +4.1736%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild
Benchmarking dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq
Benchmarking dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq: Collecting 100 samples in estimated 5.0011 s (12M iterations)
Benchmarking dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq: Analyzing
dynamic_ct_eq_auto_128b/thresh_64_force_ct_eq
                        time:   [393.24 ns 396.93 ns 401.10 ns]
                        change: [+3.3643% +4.7787% +6.0918%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 11 outliers among 100 measurements (11.00%)
  3 (3.00%) high mild
  8 (8.00%) high severe
Benchmarking dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq
Benchmarking dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq: Collecting 100 samples in estimated 5.0017 s (9.2M iterations)
Benchmarking dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq: Analyzing
dynamic_ct_eq_auto_128b/thresh_256_force_ct_eq
                        time:   [505.27 ns 510.34 ns 516.02 ns]
                        change: [+0.2812% +1.3678% +2.5333%] (p = 0.02 < 0.05)
                        Change within noise threshold.
Found 8 outliers among 100 measurements (8.00%)
  8 (8.00%) high mild

Benchmarking dynamic_ct_eq_auto_1kb/default_32b
Benchmarking dynamic_ct_eq_auto_1kb/default_32b: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_1kb/default_32b: Collecting 100 samples in estimated 5.0019 s (2.7M iterations)
Benchmarking dynamic_ct_eq_auto_1kb/default_32b: Analyzing
dynamic_ct_eq_auto_1kb/default_32b
                        time:   [1.7947 ┬╡s 1.8088 ┬╡s 1.8236 ┬╡s]
                        change: [ΓêÆ0.0307% +1.0016% +2.0310%] (p = 0.05 < 0.05)
                        Change within noise threshold.
Found 13 outliers among 100 measurements (13.00%)
  12 (12.00%) high mild
  1 (1.00%) high severe
Benchmarking dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq
Benchmarking dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq: Collecting 100 samples in estimated 5.0036 s (2.6M iterations)
Benchmarking dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq: Analyzing
dynamic_ct_eq_auto_1kb/thresh_512_force_ct_eq
                        time:   [1.7762 ┬╡s 1.7936 ┬╡s 1.8139 ┬╡s]
                        change: [ΓêÆ0.1964% +0.8498% +1.9506%] (p = 0.12 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  4 (4.00%) high mild
  6 (6.00%) high severe
Benchmarking dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq
Benchmarking dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq: Collecting 100 samples in estimated 5.0071 s (1.2M iterations)
Benchmarking dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq: Analyzing
dynamic_ct_eq_auto_1kb/thresh_2048_force_ct_eq
                        time:   [4.0024 ┬╡s 4.0675 ┬╡s 4.1409 ┬╡s]
                        change: [ΓêÆ10.996% ΓêÆ8.7817% ΓêÆ6.4967%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild
