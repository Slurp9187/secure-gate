## BENCH RUN #1 OF 3
cargo bench --all-features ct_eq_hash_vs_standard
    Finished `bench` profile [optimized] target(s) in 4.15s
     Running benches\ct_eq_hash_vs_standard.rs (target\release\deps\ct_eq_hash_vs_standard-dc5560ce4977ee60.exe)
Benchmarking fixed_ct_eq_hash_32b
Benchmarking fixed_ct_eq_hash_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_hash_32b: Collecting 100 samples in estimated 5.0005 s (19M iterations)
Benchmarking fixed_ct_eq_hash_32b: Analyzing
fixed_ct_eq_hash_32b    time:   [251.45 ns 253.97 ns 256.74 ns]
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

Benchmarking fixed_ct_eq_32b
Benchmarking fixed_ct_eq_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_32b: Collecting 100 samples in estimated 5.0005 s (40M iterations)
Benchmarking fixed_ct_eq_32b: Analyzing
fixed_ct_eq_32b         time:   [123.33 ns 124.79 ns 126.37 ns]
Found 10 outliers among 100 measurements (10.00%)
  5 (5.00%) high mild
  5 (5.00%) high severe

Benchmarking dynamic_ct_eq_hash_1kb
Benchmarking dynamic_ct_eq_hash_1kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_hash_1kb: Collecting 100 samples in estimated 5.0011 s (3.0M iterations)
Benchmarking dynamic_ct_eq_hash_1kb: Analyzing
dynamic_ct_eq_hash_1kb  time:   [1.6548 ┬╡s 1.6795 ┬╡s 1.7053 ┬╡s]
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild

Benchmarking dynamic_ct_eq_1kb
Benchmarking dynamic_ct_eq_1kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_1kb: Collecting 100 samples in estimated 5.0148 s (1.3M iterations)
Benchmarking dynamic_ct_eq_1kb: Analyzing
dynamic_ct_eq_1kb       time:   [3.9083 ┬╡s 3.9905 ┬╡s 4.0782 ┬╡s]
Found 9 outliers among 100 measurements (9.00%)
  8 (8.00%) high mild
  1 (1.00%) high severe

Benchmarking dynamic_ct_eq_hash_100kb
Benchmarking dynamic_ct_eq_hash_100kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_hash_100kb: Collecting 100 samples in estimated 5.0267 s (81k iterations)
Benchmarking dynamic_ct_eq_hash_100kb: Analyzing
dynamic_ct_eq_hash_100kb
                        time:   [60.899 ┬╡s 61.423 ┬╡s 62.029 ┬╡s]
Found 11 outliers among 100 measurements (11.00%)
  1 (1.00%) low mild
  5 (5.00%) high mild
  5 (5.00%) high severe

Benchmarking dynamic_ct_eq_100kb
Benchmarking dynamic_ct_eq_100kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_100kb: Collecting 100 samples in estimated 6.2315 s (15k iterations)
Benchmarking dynamic_ct_eq_100kb: Analyzing
dynamic_ct_eq_100kb     time:   [401.91 ┬╡s 406.72 ┬╡s 411.82 ┬╡s]
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

Benchmarking dynamic_ct_eq_hash_1mb
Benchmarking dynamic_ct_eq_hash_1mb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_hash_1mb: Collecting 100 samples in estimated 9.7800 s (10k iterations)
Benchmarking dynamic_ct_eq_hash_1mb: Analyzing
dynamic_ct_eq_hash_1mb  time:   [940.56 ┬╡s 949.22 ┬╡s 958.32 ┬╡s]
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

Benchmarking dynamic_ct_eq_1mb
Benchmarking dynamic_ct_eq_1mb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_1mb: Collecting 100 samples in estimated 5.0773 s (1100 iterations)
Benchmarking dynamic_ct_eq_1mb: Analyzing
dynamic_ct_eq_1mb       time:   [4.5332 ms 4.5761 ms 4.6210 ms]

Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end
Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end: Warming up for 3.0000 s
Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end: Collecting 100 samples in estimated 5.0011 s (2.5M iterations)
Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end: Analyzing
dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end
                        time:   [1.9181 ┬╡s 1.9374 ┬╡s 1.9600 ┬╡s]
Found 13 outliers among 100 measurements (13.00%)
  8 (8.00%) high mild
  5 (5.00%) high severe
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end: Warming up for 3.0000 s
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end: Collecting 100 samples in estimated 5.0135 s (1.2M iterations)
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end: Analyzing
dynamic_unequal_end_1kb/ct_eq_differ_at_end
                        time:   [4.1327 ┬╡s 4.1807 ┬╡s 4.2310 ┬╡s]
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

Benchmarking ct_eq_hash_fixed_data_32b
Benchmarking ct_eq_hash_fixed_data_32b: Warming up for 3.0000 s
Benchmarking ct_eq_hash_fixed_data_32b: Collecting 100 samples in estimated 5.0002 s (18M iterations)
Benchmarking ct_eq_hash_fixed_data_32b: Analyzing
ct_eq_hash_fixed_data_32b
                        time:   [266.12 ns 268.02 ns 270.10 ns]
Found 12 outliers among 100 measurements (12.00%)
  1 (1.00%) low mild
  9 (9.00%) high mild
  2 (2.00%) high severe

Benchmarking ct_eq_hash_varying_data_32b
Benchmarking ct_eq_hash_varying_data_32b: Warming up for 3.0000 s
Benchmarking ct_eq_hash_varying_data_32b: Collecting 100 samples in estimated 5.0006 s (18M iterations)
Benchmarking ct_eq_hash_varying_data_32b: Analyzing
ct_eq_hash_varying_data_32b
                        time:   [266.90 ns 269.37 ns 272.05 ns]
Found 9 outliers among 100 measurements (9.00%)
  1 (1.00%) low mild
  7 (7.00%) high mild
  1 (1.00%) high severe

Benchmarking ct_eq_hash_fixed_data_1kb
Benchmarking ct_eq_hash_fixed_data_1kb: Warming up for 3.0000 s
Benchmarking ct_eq_hash_fixed_data_1kb: Collecting 100 samples in estimated 5.0081 s (2.8M iterations)
Benchmarking ct_eq_hash_fixed_data_1kb: Analyzing
ct_eq_hash_fixed_data_1kb
                        time:   [1.8124 ┬╡s 1.8405 ┬╡s 1.8730 ┬╡s]

Benchmarking ct_eq_hash_varying_data_1kb
Benchmarking ct_eq_hash_varying_data_1kb: Warming up for 3.0000 s
Benchmarking ct_eq_hash_varying_data_1kb: Collecting 100 samples in estimated 5.0052 s (2.5M iterations)
Benchmarking ct_eq_hash_varying_data_1kb: Analyzing
ct_eq_hash_varying_data_1kb
                        time:   [1.9664 ┬╡s 1.9997 ┬╡s 2.0402 ┬╡s]
Found 9 outliers among 100 measurements (9.00%)
  3 (3.00%) high mild
  6 (6.00%) high severe

Benchmarking hash_compute_32b
Benchmarking hash_compute_32b: Warming up for 3.0000 s
Benchmarking hash_compute_32b: Collecting 100 samples in estimated 5.0002 s (89M iterations)
Benchmarking hash_compute_32b: Analyzing
hash_compute_32b        time:   [55.577 ns 55.883 ns 56.238 ns]
Found 15 outliers among 100 measurements (15.00%)
  1 (1.00%) low mild
  8 (8.00%) high mild
  6 (6.00%) high severe

Benchmarking hash_compute_1kb
Benchmarking hash_compute_1kb: Warming up for 3.0000 s
Benchmarking hash_compute_1kb: Collecting 100 samples in estimated 5.0001 s (5.8M iterations)
Benchmarking hash_compute_1kb: Analyzing
hash_compute_1kb        time:   [845.91 ns 852.48 ns 859.83 ns]
Found 13 outliers among 100 measurements (13.00%)
  6 (6.00%) high mild
  7 (7.00%) high severe

Benchmarking hash_compute_100kb
Benchmarking hash_compute_100kb: Warming up for 3.0000 s
Benchmarking hash_compute_100kb: Collecting 100 samples in estimated 5.1177 s (187k iterations)
Benchmarking hash_compute_100kb: Analyzing
hash_compute_100kb      time:   [26.839 ┬╡s 26.949 ┬╡s 27.061 ┬╡s]
Found 5 outliers among 100 measurements (5.00%)
  2 (2.00%) low mild
  3 (3.00%) high mild

Benchmarking hash_compute_1mb
Benchmarking hash_compute_1mb: Warming up for 3.0000 s
Benchmarking hash_compute_1mb: Collecting 100 samples in estimated 7.2476 s (15k iterations)
Benchmarking hash_compute_1mb: Analyzing
hash_compute_1mb        time:   [505.96 ┬╡s 510.48 ┬╡s 515.28 ┬╡s]
Found 8 outliers among 100 measurements (8.00%)
  2 (2.00%) low mild
  4 (4.00%) high mild
  2 (2.00%) high severe

Benchmarking blake3_deterministic_32b
Benchmarking blake3_deterministic_32b: Warming up for 3.0000 s
Benchmarking blake3_deterministic_32b: Collecting 100 samples in estimated 5.0000 s (88M iterations)
Benchmarking blake3_deterministic_32b: Analyzing
blake3_deterministic_32b
                        time:   [56.283 ns 56.942 ns 57.727 ns]
Found 15 outliers among 100 measurements (15.00%)
  4 (4.00%) high mild
  11 (11.00%) high severe

Benchmarking blake3_keyed_32b
Benchmarking blake3_keyed_32b: Warming up for 3.0000 s
Benchmarking blake3_keyed_32b: Collecting 100 samples in estimated 5.0000 s (69M iterations)
Benchmarking blake3_keyed_32b: Analyzing
blake3_keyed_32b        time:   [76.067 ns 78.665 ns 81.431 ns]
Found 17 outliers among 100 measurements (17.00%)
  4 (4.00%) high mild
  13 (13.00%) high severe

Benchmarking blake3_deterministic_1kb
Benchmarking blake3_deterministic_1kb: Warming up for 3.0000 s
Benchmarking blake3_deterministic_1kb: Collecting 100 samples in estimated 5.0030 s (5.7M iterations)
Benchmarking blake3_deterministic_1kb: Analyzing
blake3_deterministic_1kb
                        time:   [857.86 ns 867.90 ns 879.02 ns]
Found 12 outliers among 100 measurements (12.00%)
  6 (6.00%) high mild
  6 (6.00%) high severe

Benchmarking blake3_keyed_1kb
Benchmarking blake3_keyed_1kb: Warming up for 3.0000 s
Benchmarking blake3_keyed_1kb: Collecting 100 samples in estimated 5.0017 s (5.7M iterations)
Benchmarking blake3_keyed_1kb: Analyzing
blake3_keyed_1kb        time:   [865.62 ns 874.06 ns 883.86 ns]
Found 11 outliers among 100 measurements (11.00%)
  4 (4.00%) high mild
  7 (7.00%) high severe

Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end
Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end: Warming up for 3.0000 s
Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end: Collecting 100 samples in estimated 5.0004 s (18M iterations)
Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end: Analyzing
fixed_unequal_end_32b/ct_eq_hash_differ_at_end
                        time:   [276.18 ns 281.92 ns 288.09 ns]
Found 6 outliers among 100 measurements (6.00%)
  5 (5.00%) high mild
  1 (1.00%) high severe
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end: Warming up for 3.0000 s
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end: Collecting 100 samples in estimated 5.0001 s (37M iterations)
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end: Analyzing
fixed_unequal_end_32b/ct_eq_differ_at_end
                        time:   [130.69 ns 132.58 ns 134.70 ns]
Found 7 outliers among 100 measurements (7.00%)
  6 (6.00%) high mild
  1 (1.00%) high severe

## BENCH RUN #2 OF 3
cargo bench --all-features ct_eq_hash_vs_standard
    Finished `bench` profile [optimized] target(s) in 0.23s
     Running benches\ct_eq_hash_vs_standard.rs (target\release\deps\ct_eq_hash_vs_standard-dc5560ce4977ee60.exe)
Benchmarking fixed_ct_eq_hash_32b
Benchmarking fixed_ct_eq_hash_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_hash_32b: Collecting 100 samples in estimated 5.0001 s (19M iterations)
Benchmarking fixed_ct_eq_hash_32b: Analyzing
fixed_ct_eq_hash_32b    time:   [260.54 ns 262.80 ns 265.32 ns]
                        change: [+1.7509% +3.0824% +4.4815%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 10 outliers among 100 measurements (10.00%)
  7 (7.00%) high mild
  3 (3.00%) high severe

Benchmarking fixed_ct_eq_32b
Benchmarking fixed_ct_eq_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_32b: Collecting 100 samples in estimated 5.0007 s (35M iterations)
Benchmarking fixed_ct_eq_32b: Analyzing
fixed_ct_eq_32b         time:   [131.95 ns 132.88 ns 133.90 ns]
                        change: [+5.4169% +6.8194% +8.1603%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

Benchmarking dynamic_ct_eq_hash_1kb
Benchmarking dynamic_ct_eq_hash_1kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_hash_1kb: Collecting 100 samples in estimated 5.0070 s (2.6M iterations)
Benchmarking dynamic_ct_eq_hash_1kb: Analyzing
dynamic_ct_eq_hash_1kb  time:   [1.8207 ┬╡s 1.8318 ┬╡s 1.8431 ┬╡s]
                        change: [+7.3312% +8.7020% +10.085%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking dynamic_ct_eq_1kb
Benchmarking dynamic_ct_eq_1kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_1kb: Collecting 100 samples in estimated 5.0023 s (1.2M iterations)
Benchmarking dynamic_ct_eq_1kb: Analyzing
dynamic_ct_eq_1kb       time:   [4.1437 ┬╡s 4.1677 ┬╡s 4.1933 ┬╡s]
                        change: [+3.8721% +6.2244% +8.4998%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking dynamic_ct_eq_hash_100kb
Benchmarking dynamic_ct_eq_hash_100kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_hash_100kb: Collecting 100 samples in estimated 5.1781 s (86k iterations)
Benchmarking dynamic_ct_eq_hash_100kb: Analyzing
dynamic_ct_eq_hash_100kb
                        time:   [58.460 ┬╡s 58.824 ┬╡s 59.212 ┬╡s]
                        change: [ΓêÆ4.7738% ΓêÆ3.9629% ΓêÆ3.1820%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

Benchmarking dynamic_ct_eq_100kb
Benchmarking dynamic_ct_eq_100kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_100kb: Collecting 100 samples in estimated 6.6187 s (15k iterations)
Benchmarking dynamic_ct_eq_100kb: Analyzing
dynamic_ct_eq_100kb     time:   [422.06 ┬╡s 425.03 ┬╡s 428.37 ┬╡s]
                        change: [+2.1717% +3.7358% +5.3151%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 5 outliers among 100 measurements (5.00%)
  3 (3.00%) high mild
  2 (2.00%) high severe

Benchmarking dynamic_ct_eq_hash_1mb
Benchmarking dynamic_ct_eq_hash_1mb: Warming up for 3.0000 s

Warning: Unable to complete 100 samples in 5.0s. You may wish to increase target time to 5.4s, enable flat sampling, or reduce sample count to 60.
Benchmarking dynamic_ct_eq_hash_1mb: Collecting 100 samples in estimated 5.3606 s (5050 iterations)
Benchmarking dynamic_ct_eq_hash_1mb: Analyzing
dynamic_ct_eq_hash_1mb  time:   [1.0252 ms 1.0325 ms 1.0404 ms]
                        change: [+7.7061% +8.8416% +9.9732%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

Benchmarking dynamic_ct_eq_1mb
Benchmarking dynamic_ct_eq_1mb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_1mb: Collecting 100 samples in estimated 5.2729 s (1000 iterations)
Benchmarking dynamic_ct_eq_1mb: Analyzing
dynamic_ct_eq_1mb       time:   [5.1274 ms 5.1986 ms 5.2771 ms]
                        change: [+11.693% +13.604% +15.639%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 10 outliers among 100 measurements (10.00%)
  6 (6.00%) high mild
  4 (4.00%) high severe

Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end
Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end: Warming up for 3.0000 s
Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end: Collecting 100 samples in estimated 5.0037 s (2.4M iterations)
Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end: Analyzing
dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end
                        time:   [2.1263 ┬╡s 2.1568 ┬╡s 2.1875 ┬╡s]
                        change: [+5.5174% +7.3531% +9.0876%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end: Warming up for 3.0000 s
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end: Collecting 100 samples in estimated 5.0221 s (1.1M iterations)
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end: Analyzing
dynamic_unequal_end_1kb/ct_eq_differ_at_end
                        time:   [4.7300 ┬╡s 4.8434 ┬╡s 4.9486 ┬╡s]
                        change: [+10.744% +12.548% +14.557%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

Benchmarking ct_eq_hash_fixed_data_32b
Benchmarking ct_eq_hash_fixed_data_32b: Warming up for 3.0000 s
Benchmarking ct_eq_hash_fixed_data_32b: Collecting 100 samples in estimated 5.0003 s (16M iterations)
Benchmarking ct_eq_hash_fixed_data_32b: Analyzing
ct_eq_hash_fixed_data_32b
                        time:   [308.06 ns 315.82 ns 322.75 ns]
                        change: [+9.2429% +11.292% +13.466%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

Benchmarking ct_eq_hash_varying_data_32b
Benchmarking ct_eq_hash_varying_data_32b: Warming up for 3.0000 s
Benchmarking ct_eq_hash_varying_data_32b: Collecting 100 samples in estimated 5.0013 s (17M iterations)
Benchmarking ct_eq_hash_varying_data_32b: Analyzing
ct_eq_hash_varying_data_32b
                        time:   [310.36 ns 317.20 ns 323.93 ns]
                        change: [+13.223% +14.958% +16.964%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking ct_eq_hash_fixed_data_1kb
Benchmarking ct_eq_hash_fixed_data_1kb: Warming up for 3.0000 s
Benchmarking ct_eq_hash_fixed_data_1kb: Collecting 100 samples in estimated 5.0080 s (2.6M iterations)
Benchmarking ct_eq_hash_fixed_data_1kb: Analyzing
ct_eq_hash_fixed_data_1kb
                        time:   [1.8652 ┬╡s 1.8840 ┬╡s 1.9032 ┬╡s]
                        change: [ΓêÆ1.3273% +0.4063% +2.1748%] (p = 0.65 > 0.05)
                        No change in performance detected.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

Benchmarking ct_eq_hash_varying_data_1kb
Benchmarking ct_eq_hash_varying_data_1kb: Warming up for 3.0000 s
Benchmarking ct_eq_hash_varying_data_1kb: Collecting 100 samples in estimated 5.0066 s (2.2M iterations)
Benchmarking ct_eq_hash_varying_data_1kb: Analyzing
ct_eq_hash_varying_data_1kb
                        time:   [2.1019 ┬╡s 2.1199 ┬╡s 2.1388 ┬╡s]
                        change: [+5.1478% +7.0425% +8.7928%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking hash_compute_32b
Benchmarking hash_compute_32b: Warming up for 3.0000 s
Benchmarking hash_compute_32b: Collecting 100 samples in estimated 5.0003 s (82M iterations)
Benchmarking hash_compute_32b: Analyzing
hash_compute_32b        time:   [60.327 ns 60.979 ns 61.603 ns]
                        change: [+7.0124% +8.1340% +9.1926%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking hash_compute_1kb
Benchmarking hash_compute_1kb: Warming up for 3.0000 s
Benchmarking hash_compute_1kb: Collecting 100 samples in estimated 5.0031 s (5.3M iterations)
Benchmarking hash_compute_1kb: Analyzing
hash_compute_1kb        time:   [919.87 ns 927.57 ns 935.99 ns]
                        change: [+7.7630% +9.3019% +10.766%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild

Benchmarking hash_compute_100kb
Benchmarking hash_compute_100kb: Warming up for 3.0000 s
Benchmarking hash_compute_100kb: Collecting 100 samples in estimated 5.0534 s (152k iterations)
Benchmarking hash_compute_100kb: Analyzing
hash_compute_100kb      time:   [30.122 ┬╡s 30.725 ┬╡s 31.370 ┬╡s]
                        change: [+10.536% +11.839% +13.298%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 10 outliers among 100 measurements (10.00%)
  7 (7.00%) high mild
  3 (3.00%) high severe

Benchmarking hash_compute_1mb
Benchmarking hash_compute_1mb: Warming up for 3.0000 s
Benchmarking hash_compute_1mb: Collecting 100 samples in estimated 5.9854 s (10k iterations)
Benchmarking hash_compute_1mb: Analyzing
hash_compute_1mb        time:   [522.51 ┬╡s 527.97 ┬╡s 533.98 ┬╡s]
                        change: [+3.5069% +4.9548% +6.3896%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

Benchmarking blake3_deterministic_32b
Benchmarking blake3_deterministic_32b: Warming up for 3.0000 s
Benchmarking blake3_deterministic_32b: Collecting 100 samples in estimated 5.0001 s (83M iterations)
Benchmarking blake3_deterministic_32b: Analyzing
blake3_deterministic_32b
                        time:   [59.708 ns 60.226 ns 60.764 ns]
                        change: [+5.7454% +7.0311% +8.2878%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

Benchmarking blake3_keyed_32b
Benchmarking blake3_keyed_32b: Warming up for 3.0000 s
Benchmarking blake3_keyed_32b: Collecting 100 samples in estimated 5.0003 s (67M iterations)
Benchmarking blake3_keyed_32b: Analyzing
blake3_keyed_32b        time:   [74.069 ns 74.697 ns 75.387 ns]
                        change: [ΓêÆ4.0607% ΓêÆ1.6111% +0.7550%] (p = 0.21 > 0.05)
                        No change in performance detected.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

Benchmarking blake3_deterministic_1kb
Benchmarking blake3_deterministic_1kb: Warming up for 3.0000 s
Benchmarking blake3_deterministic_1kb: Collecting 100 samples in estimated 5.0032 s (5.4M iterations)
Benchmarking blake3_deterministic_1kb: Analyzing
blake3_deterministic_1kb
                        time:   [901.91 ns 908.08 ns 914.56 ns]
                        change: [+3.2582% +4.5585% +5.7761%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking blake3_keyed_1kb
Benchmarking blake3_keyed_1kb: Warming up for 3.0000 s
Benchmarking blake3_keyed_1kb: Collecting 100 samples in estimated 5.0040 s (5.4M iterations)
Benchmarking blake3_keyed_1kb: Analyzing
blake3_keyed_1kb        time:   [908.01 ns 913.73 ns 919.72 ns]
                        change: [+3.5755% +4.7474% +5.8158%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end
Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end: Warming up for 3.0000 s
Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end: Collecting 100 samples in estimated 5.0000 s (17M iterations)
Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end: Analyzing
fixed_unequal_end_32b/ct_eq_hash_differ_at_end
                        time:   [281.49 ns 283.10 ns 284.87 ns]
                        change: [+1.5943% +3.0831% +4.5330%] (p = 0.00 < 0.05)
                        Performance has regressed.
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end: Warming up for 3.0000 s
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end: Collecting 100 samples in estimated 5.0005 s (36M iterations)
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end: Analyzing
fixed_unequal_end_32b/ct_eq_differ_at_end
                        time:   [135.94 ns 137.02 ns 138.14 ns]
                        change: [+1.7255% +3.2556% +4.6909%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

## BENCH RUN #3 OF 3
cargo bench --all-features ct_eq_hash_vs_standard
    Finished `bench` profile [optimized] target(s) in 0.25s
     Running benches\ct_eq_hash_vs_standard.rs (target\release\deps\ct_eq_hash_vs_standard-dc5560ce4977ee60.exe)
Benchmarking fixed_ct_eq_hash_32b
Benchmarking fixed_ct_eq_hash_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_hash_32b: Collecting 100 samples in estimated 5.0004 s (16M iterations)
Benchmarking fixed_ct_eq_hash_32b: Analyzing
fixed_ct_eq_hash_32b    time:   [299.26 ns 303.98 ns 309.23 ns]
                        change: [+20.366% +22.887% +25.515%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking fixed_ct_eq_32b
Benchmarking fixed_ct_eq_32b: Warming up for 3.0000 s
Benchmarking fixed_ct_eq_32b: Collecting 100 samples in estimated 5.0001 s (32M iterations)
Benchmarking fixed_ct_eq_32b: Analyzing
fixed_ct_eq_32b         time:   [160.21 ns 161.46 ns 162.67 ns]
                        change: [+13.006% +15.268% +17.323%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking dynamic_ct_eq_hash_1kb
Benchmarking dynamic_ct_eq_hash_1kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_hash_1kb: Collecting 100 samples in estimated 5.0031 s (2.6M iterations)
Benchmarking dynamic_ct_eq_hash_1kb: Analyzing
dynamic_ct_eq_hash_1kb  time:   [1.9156 ┬╡s 1.9465 ┬╡s 1.9778 ┬╡s]
                        change: [+3.2254% +4.3338% +5.4790%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 7 outliers among 100 measurements (7.00%)
  7 (7.00%) high mild

Benchmarking dynamic_ct_eq_1kb
Benchmarking dynamic_ct_eq_1kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_1kb: Collecting 100 samples in estimated 5.0037 s (1.1M iterations)
Benchmarking dynamic_ct_eq_1kb: Analyzing
dynamic_ct_eq_1kb       time:   [4.2572 ┬╡s 4.3100 ┬╡s 4.3673 ┬╡s]
                        change: [+0.7968% +2.0171% +3.2153%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

Benchmarking dynamic_ct_eq_hash_100kb
Benchmarking dynamic_ct_eq_hash_100kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_hash_100kb: Collecting 100 samples in estimated 5.2172 s (86k iterations)
Benchmarking dynamic_ct_eq_hash_100kb: Analyzing
dynamic_ct_eq_hash_100kb
                        time:   [59.026 ┬╡s 59.751 ┬╡s 60.437 ┬╡s]
                        change: [ΓêÆ1.4039% ΓêÆ0.4074% +0.4978%] (p = 0.40 > 0.05)
                        No change in performance detected.

Benchmarking dynamic_ct_eq_100kb
Benchmarking dynamic_ct_eq_100kb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_100kb: Collecting 100 samples in estimated 7.2305 s (15k iterations)
Benchmarking dynamic_ct_eq_100kb: Analyzing
dynamic_ct_eq_100kb     time:   [425.92 ┬╡s 428.72 ┬╡s 431.54 ┬╡s]
                        change: [ΓêÆ0.9189% +0.1172% +1.1108%] (p = 0.82 > 0.05)
                        No change in performance detected.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

Benchmarking dynamic_ct_eq_hash_1mb
Benchmarking dynamic_ct_eq_hash_1mb: Warming up for 3.0000 s

Warning: Unable to complete 100 samples in 5.0s. You may wish to increase target time to 5.4s, enable flat sampling, or reduce sample count to 60.
Benchmarking dynamic_ct_eq_hash_1mb: Collecting 100 samples in estimated 5.3907 s (5050 iterations)
Benchmarking dynamic_ct_eq_hash_1mb: Analyzing
dynamic_ct_eq_hash_1mb  time:   [1.0608 ms 1.0709 ms 1.0813 ms]
                        change: [+2.8209% +3.9326% +5.0701%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 5 outliers among 100 measurements (5.00%)
  4 (4.00%) high mild
  1 (1.00%) high severe

Benchmarking dynamic_ct_eq_1mb
Benchmarking dynamic_ct_eq_1mb: Warming up for 3.0000 s
Benchmarking dynamic_ct_eq_1mb: Collecting 100 samples in estimated 5.3462 s (1000 iterations)
Benchmarking dynamic_ct_eq_1mb: Analyzing
dynamic_ct_eq_1mb       time:   [4.9981 ms 5.0507 ms 5.1083 ms]
                        change: [ΓêÆ4.6250% ΓêÆ2.8440% ΓêÆ1.0959%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 10 outliers among 100 measurements (10.00%)
  6 (6.00%) high mild
  4 (4.00%) high severe

Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end
Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end: Warming up for 3.0000 s
Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end: Collecting 100 samples in estimated 5.0043 s (2.2M iterations)
Benchmarking dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end: Analyzing
dynamic_unequal_end_1kb/ct_eq_hash_differ_at_end
                        time:   [2.0449 ┬╡s 2.0569 ┬╡s 2.0700 ┬╡s]
                        change: [ΓêÆ2.3856% ΓêÆ1.2122% ΓêÆ0.0586%] (p = 0.04 < 0.05)
                        Change within noise threshold.
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end: Warming up for 3.0000 s
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end: Collecting 100 samples in estimated 5.0175 s (1.1M iterations)
Benchmarking dynamic_unequal_end_1kb/ct_eq_differ_at_end: Analyzing
dynamic_unequal_end_1kb/ct_eq_differ_at_end
                        time:   [4.4373 ┬╡s 4.4718 ┬╡s 4.5094 ┬╡s]
                        change: [ΓêÆ6.4675% ΓêÆ4.9630% ΓêÆ3.4880%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) high mild
  2 (2.00%) high severe

Benchmarking ct_eq_hash_fixed_data_32b
Benchmarking ct_eq_hash_fixed_data_32b: Warming up for 3.0000 s
Benchmarking ct_eq_hash_fixed_data_32b: Collecting 100 samples in estimated 5.0009 s (18M iterations)
Benchmarking ct_eq_hash_fixed_data_32b: Analyzing
ct_eq_hash_fixed_data_32b
                        time:   [282.10 ns 283.97 ns 285.93 ns]
                        change: [ΓêÆ6.6887% ΓêÆ5.0987% ΓêÆ3.5154%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

Benchmarking ct_eq_hash_varying_data_32b
Benchmarking ct_eq_hash_varying_data_32b: Warming up for 3.0000 s
Benchmarking ct_eq_hash_varying_data_32b: Collecting 100 samples in estimated 5.0006 s (17M iterations)
Benchmarking ct_eq_hash_varying_data_32b: Analyzing
ct_eq_hash_varying_data_32b
                        time:   [279.92 ns 281.85 ns 283.97 ns]
                        change: [ΓêÆ8.9811% ΓêÆ7.5287% ΓêÆ6.0298%] (p = 0.00 < 0.05)
                        Performance has improved.

Benchmarking ct_eq_hash_fixed_data_1kb
Benchmarking ct_eq_hash_fixed_data_1kb: Warming up for 3.0000 s
Benchmarking ct_eq_hash_fixed_data_1kb: Collecting 100 samples in estimated 5.0023 s (2.7M iterations)
Benchmarking ct_eq_hash_fixed_data_1kb: Analyzing
ct_eq_hash_fixed_data_1kb
                        time:   [1.8178 ┬╡s 1.8283 ┬╡s 1.8398 ┬╡s]
                        change: [ΓêÆ1.1647% ΓêÆ0.2122% +0.7298%] (p = 0.66 > 0.05)
                        No change in performance detected.

Benchmarking ct_eq_hash_varying_data_1kb
Benchmarking ct_eq_hash_varying_data_1kb: Warming up for 3.0000 s
Benchmarking ct_eq_hash_varying_data_1kb: Collecting 100 samples in estimated 5.0060 s (2.4M iterations)
Benchmarking ct_eq_hash_varying_data_1kb: Analyzing
ct_eq_hash_varying_data_1kb
                        time:   [2.0381 ┬╡s 2.0526 ┬╡s 2.0678 ┬╡s]
                        change: [ΓêÆ4.5304% ΓêÆ3.8215% ΓêÆ3.0351%] (p = 0.00 < 0.05)
                        Performance has improved.

Benchmarking hash_compute_32b
Benchmarking hash_compute_32b: Warming up for 3.0000 s
Benchmarking hash_compute_32b: Collecting 100 samples in estimated 5.0003 s (80M iterations)
Benchmarking hash_compute_32b: Analyzing
hash_compute_32b        time:   [57.448 ns 57.871 ns 58.341 ns]
                        change: [ΓêÆ3.3947% ΓêÆ2.1724% ΓêÆ0.8868%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 8 outliers among 100 measurements (8.00%)
  8 (8.00%) high mild

Benchmarking hash_compute_1kb
Benchmarking hash_compute_1kb: Warming up for 3.0000 s
Benchmarking hash_compute_1kb: Collecting 100 samples in estimated 5.0003 s (5.4M iterations)
Benchmarking hash_compute_1kb: Analyzing
hash_compute_1kb        time:   [892.29 ns 898.18 ns 904.26 ns]
                        change: [ΓêÆ4.8915% ΓêÆ3.7628% ΓêÆ2.6099%] (p = 0.00 < 0.05)
                        Performance has improved.

Benchmarking hash_compute_100kb
Benchmarking hash_compute_100kb: Warming up for 3.0000 s
Benchmarking hash_compute_100kb: Collecting 100 samples in estimated 5.0357 s (177k iterations)
Benchmarking hash_compute_100kb: Analyzing
hash_compute_100kb      time:   [28.148 ┬╡s 28.380 ┬╡s 28.609 ┬╡s]
                        change: [ΓêÆ6.7850% ΓêÆ5.5341% ΓêÆ4.3512%] (p = 0.00 < 0.05)
                        Performance has improved.

Benchmarking hash_compute_1mb
Benchmarking hash_compute_1mb: Warming up for 3.0000 s
Benchmarking hash_compute_1mb: Collecting 100 samples in estimated 5.3079 s (10k iterations)
Benchmarking hash_compute_1mb: Analyzing
hash_compute_1mb        time:   [485.91 ┬╡s 489.53 ┬╡s 493.21 ┬╡s]
                        change: [ΓêÆ9.7118% ΓêÆ8.6376% ΓêÆ7.5590%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

Benchmarking blake3_deterministic_32b
Benchmarking blake3_deterministic_32b: Warming up for 3.0000 s
Benchmarking blake3_deterministic_32b: Collecting 100 samples in estimated 5.0001 s (76M iterations)
Benchmarking blake3_deterministic_32b: Analyzing
blake3_deterministic_32b
                        time:   [57.610 ns 58.016 ns 58.442 ns]
                        change: [ΓêÆ3.9395% ΓêÆ2.7100% ΓêÆ1.4709%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 5 outliers among 100 measurements (5.00%)
  5 (5.00%) high mild

Benchmarking blake3_keyed_32b
Benchmarking blake3_keyed_32b: Warming up for 3.0000 s
Benchmarking blake3_keyed_32b: Collecting 100 samples in estimated 5.0000 s (66M iterations)
Benchmarking blake3_keyed_32b: Analyzing
blake3_keyed_32b        time:   [72.905 ns 73.347 ns 73.807 ns]
                        change: [ΓêÆ2.8449% ΓêÆ1.8846% ΓêÆ0.9636%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild

Benchmarking blake3_deterministic_1kb
Benchmarking blake3_deterministic_1kb: Warming up for 3.0000 s
Benchmarking blake3_deterministic_1kb: Collecting 100 samples in estimated 5.0013 s (5.5M iterations)
Benchmarking blake3_deterministic_1kb: Analyzing
blake3_deterministic_1kb
                        time:   [914.00 ns 927.59 ns 941.70 ns]
                        change: [+0.1310% +1.2044% +2.2860%] (p = 0.03 < 0.05)
                        Change within noise threshold.
Found 7 outliers among 100 measurements (7.00%)
  5 (5.00%) high mild
  2 (2.00%) high severe

Benchmarking blake3_keyed_1kb
Benchmarking blake3_keyed_1kb: Warming up for 3.0000 s
Benchmarking blake3_keyed_1kb: Collecting 100 samples in estimated 5.0033 s (5.4M iterations)
Benchmarking blake3_keyed_1kb: Analyzing
blake3_keyed_1kb        time:   [902.33 ns 907.61 ns 913.36 ns]
                        change: [ΓêÆ1.2552% ΓêÆ0.6087% +0.0726%] (p = 0.07 > 0.05)
                        No change in performance detected.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end
Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end: Warming up for 3.0000 s
Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end: Collecting 100 samples in estimated 5.0003 s (17M iterations)
Benchmarking fixed_unequal_end_32b/ct_eq_hash_differ_at_end: Analyzing
fixed_unequal_end_32b/ct_eq_hash_differ_at_end
                        time:   [284.81 ns 286.78 ns 288.83 ns]
                        change: [ΓêÆ0.8265% ΓêÆ0.0003% +0.7745%] (p = 1.00 > 0.05)
                        No change in performance detected.
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end: Warming up for 3.0000 s
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end: Collecting 100 samples in estimated 5.0001 s (34M iterations)
Benchmarking fixed_unequal_end_32b/ct_eq_differ_at_end: Analyzing
fixed_unequal_end_32b/ct_eq_differ_at_end
                        time:   [136.21 ns 137.82 ns 139.66 ns]
                        change: [ΓêÆ0.4116% +0.9624% +2.3753%] (p = 0.20 > 0.05)
                        No change in performance detected.
Found 8 outliers among 100 measurements (8.00%)
  6 (6.00%) high mild
  2 (2.00%) high severe
