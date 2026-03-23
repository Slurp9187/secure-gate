# Why secure-gate Wrappers?

`Fixed<T>` and `Dynamic<T>` enforce explicit access (`with_secret` / `expose_secret`) with **zero runtime overhead** compared to raw arrays.

Benchmarks show:

- Access & mutation: indistinguishable from raw data (within measurement noise)
- Drop: ~15–25 ns extra (intentional zeroization cost, including spare capacity)

For full raw performance data, [explore benchmark sources](https://github.com/Slurp9187/secure-gate/blob/main/benches/).

This makes every access explicit and auditable while preserving performance. Raw arrays are faster to type but far easier to misuse.

See [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for the full model.
