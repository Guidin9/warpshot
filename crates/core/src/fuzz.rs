//! Dependency-free mutation fuzzing for every decoder (security plan item 9;
//! `cargo-fuzz` needs nightly and libFuzzer, which the MSVC toolchain lacks).
//! Each decoder's test module runs a short pass in every `cargo test` and a
//! timed pass, per module, with
//! `WARPSHOT_FUZZ_SECS=600 cargo test -p warpshot-core --release fuzz_long -- --ignored`.
//! Inputs are deterministic: a failure prints its seed and input.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::panic
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

/// xorshift64*.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n) as usize
        }
    }
}

/// Bytes the formats treat specially: CBOR length boundaries, JSON and HTTP
/// delimiters, WebSocket flag bits.
const INTERESTING: [u8; 18] = [
    0x00, 0x01, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x7e, 0x7f, 0x80, 0xff, b'"', b'\\', b'{',
    b'[', b'\r', b'\n',
];

/// One input: random bytes (a quarter of the time) or a seed with 1–4 mutations.
pub(crate) fn input(r: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    if seeds.is_empty() || r.below(4) == 0 {
        let len = r.below(64);
        return (0..len).map(|_| r.next() as u8).collect();
    }
    let mut b = seeds[r.below(seeds.len() as u64)].clone();
    for _ in 0..=r.below(4) {
        let len = b.len() as u64;
        match r.below(8) {
            0 if len > 0 => {
                let i = r.below(len);
                b[i] = r.next() as u8;
            }
            1 if len > 0 => {
                let i = r.below(len);
                b[i] ^= 1 << r.below(8);
            }
            2 if len > 0 => {
                let i = r.below(len);
                b[i] = INTERESTING[r.below(INTERESTING.len() as u64)];
            }
            3 if len > 0 => {
                b.remove(r.below(len));
            }
            4 => b.insert(r.below(len + 1), r.next() as u8),
            // Duplicate a short range somewhere else.
            5 if len > 0 => {
                let i = r.below(len);
                let n = (r.below(16) + 1).min(b.len() - i);
                let chunk = b[i..i + n].to_vec();
                let j = r.below(b.len() as u64 + 1);
                b.splice(j..j, chunk);
            }
            // Cut here and continue with the tail of another seed.
            6 if len > 0 => {
                let o = &seeds[r.below(seeds.len() as u64)];
                let k = r.below(o.len() as u64 + 1);
                b.truncate(r.below(len));
                b.extend_from_slice(&o[k..]);
            }
            _ => b.truncate(r.below(len + 1)),
        }
    }
    b
}

/// Feeds `n` inputs generated from `seed` to `f`, which asserts the target's
/// properties and returns whether a decoder accepted the input. A panic (in
/// the decoder or an assertion) names the input. Returns the accepted count.
pub(crate) fn run(seeds: &[Vec<u8>], n: u64, seed: u64, mut f: impl FnMut(&[u8]) -> bool) -> u64 {
    let mut r = Rng(seed);
    let mut accepted = 0;
    for _ in 0..n {
        let b = input(&mut r, seeds);
        match catch_unwind(AssertUnwindSafe(|| f(&b))) {
            Ok(ok) => accepted += u64::from(ok),
            Err(_) => panic!("fuzz failure (seed {seed:#x}), input {b:02x?}"),
        }
    }
    accepted
}

/// The pass run by every `cargo test`. Some inputs must be accepted, or the
/// mutations never reach past the first checks and the run proves little.
pub(crate) fn short(seeds: &[Vec<u8>], n: u64, f: impl FnMut(&[u8]) -> bool) {
    let accepted = run(seeds, n, 0x5eed, f);
    assert!(
        accepted > 0,
        "no input accepted in {n}: seeds or mutations are broken"
    );
}

/// The timed pass of a `fuzz_long` test: `WARPSHOT_FUZZ_SECS` (default 60).
pub(crate) fn long(seeds: &[Vec<u8>], mut f: impl FnMut(&[u8]) -> bool) {
    let secs: u64 = std::env::var("WARPSHOT_FUZZ_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let start = Instant::now();
    let (mut seed, mut accepted) = (1u64, 0);
    while start.elapsed().as_secs() < secs {
        accepted += run(seeds, 10_000, seed, &mut f);
        seed += 1;
    }
    let name = std::thread::current().name().unwrap_or("fuzz").to_owned();
    eprintln!(
        "{name}: {} inputs, {accepted} accepted",
        (seed - 1) * 10_000
    );
}

/// Text decoders get the input as (lossy) UTF-8.
pub(crate) fn text(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
}
