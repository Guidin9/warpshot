# netwatch 0.19.3, patched for Warpshot

Upstream: <https://github.com/n0-computer/net-tools> (crate `netwatch` 0.19.3,
MIT OR Apache-2.0; license texts in this folder). Used through
`[patch.crates-io]` in the workspace `Cargo.toml`.

## The change

`src/interfaces/linux.rs`, module `android`: the default route's interface
comes from `ConnectivityManager.getLinkProperties(getActiveNetwork())
.getInterfaceName()` through JNI (the context published to `ndk_context`,
which the app already initializes for iroh's DNS resolver). Upstream runs
`ip route show table 0` instead. `Cargo.toml`: the Android target depends on
`jni` 0.22 and `ndk-context` 0.1 (both already in the dependency tree through
iroh) instead of tokio's `process` feature.

## Why

Forking the app process for `ip` sometimes left the child stuck before
`exec` (a `fork` in a multi-threaded ART process), and the spawn then blocked
a tokio worker for good: the iroh endpoint bind never returned, no timeout
could fire, and a woken phone hung at "Connecting…" (7 of 20 cold starts in
the emulator; docs/spikes.md "Android bind hang"). iroh needs the default
route (`has_usable_network`), so the step cannot simply be skipped.

## When upgrading iroh

Check whether the new netwatch still forks `ip` on Android. If upstream reads
the route without a subprocess, drop this folder and the `[patch]` entry;
otherwise re-apply the change to the new version.
