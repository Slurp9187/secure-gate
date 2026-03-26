//! Secrecy compatibility layer — exhaustive test suite.
//!
//! This suite is the authoritative reference for migrating from `secrecy`
//! (v0.8.x or v0.10.x) to `secure-gate`. All sub-modules are compiled only
//! when the `secrecy-compat` feature is enabled — this is the single
//! authoritative gate; no sub-module needs its own `#![cfg(feature = "secrecy-compat")]`.
//!
//! | Module       | Coverage                                                          |
//! |--------------|-------------------------------------------------------------------|
//! | `v08`        | Drop-in smoke tests for the secrecy 0.8.x API surface            |
//! | `v10`        | Drop-in smoke tests for the secrecy 0.10.x API surface           |
//! | `round_trip` | Cross-type conversions with ct_eq assertions at every hop        |
//! | `edge_cases` | ZSTs, large payloads, panic-in-drop, move / borrow patterns      |
//! | `examples`   | Canonical copy-paste migration patterns (MIGRATING_FROM_SECRECY) |

#![cfg(feature = "secrecy-compat")]
// Helper types shared across sub-modules are not all used in every config.
#![allow(dead_code)]

mod v08;
mod v10;
mod round_trip;
mod edge_cases;
mod examples;
