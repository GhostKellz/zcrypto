//! Forces analysis of zcrypto's entropy path on wasm32-freestanding.
//!
//! `src/rand.zig` answers freestanding with `@compileError` rather than a PRNG,
//! because a freestanding module has no host interface and inventing one would
//! hand the caller predictable key material that is indistinguishable from
//! CSPRNG output. That refusal is only worth anything if it is still there, and
//! Zig analyses lazily: nothing checks a function that is never referenced.
//!
//! `zig test src/rand.zig -target wasm32-freestanding` does not do the job. It
//! pulls in `std.testing`, which reaches `std.Io.Threaded` and `std.Thread`, and
//! those fail on freestanding first -- so the build goes red without ever
//! reaching zcrypto's own refusal, and would keep going red if that refusal were
//! deleted tomorrow.
//!
//! This root exists to reference exactly one function, through the same module
//! boundary a consumer would use. dev/wasm/check.sh compiles it and requires the
//! failure to quote zcrypto's message.

const rand = @import("zcrypto_rand");

export fn freestanding_entropy_probe() void {
    var buf: [32]u8 = @splat(0);
    rand.fillChecked(&buf) catch {};
}
