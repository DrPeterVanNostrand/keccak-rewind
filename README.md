# About

A clone of the Rust crate
[`tiny-keccak`](https://github.com/debris/tiny-keccak) with
[loop unwinding](https://en.wikipedia.org/wiki/Loop_unrolling) removed.

This is a deoptimization! I wasn't able to compile the `tiny-keccak` crate
on a fresh EC2 Ubuntu 16 instance running Rust 1.27-nightly. Removing the
loop-unwinding allowed the crate to compile.

