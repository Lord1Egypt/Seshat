//! Seshat Rust performance core.
//!
//! A drop-in scanning engine that reads the **same** YAML pattern catalog as the
//! Python engine and produces **identical findings** — it only adds speed
//! (parallel, compiled regex). Python stays the ergonomic front-end.

pub mod engine;
pub mod normalize;
pub mod pattern;
