//! The `wasm` feature: a host-side interface for embedding crypto in a WASM VM.
//!
//! This is not "zcrypto compiled to WebAssembly", and the shared word is the
//! only thing the two have in common. The types below run on the *host*, in a
//! runtime that is executing someone else's WASM: they take offsets into a
//! guest's linear memory instead of pointers, bound every access against the
//! guest's declared memory size, and bill each operation against a gas limit.
//! Turning the feature off with `-Dwasm=false` removes that interface. It does
//! not stop zcrypto from being built for wasm32 -- that is a target, chosen
//! with `-Dtarget=`, and it works whatever this flag is set to.
//!
//! Support for wasm32 as a target is checked by dev/wasm/check.sh, which builds
//! and runs the library's whole test suite under Node's WASI preview1. That is
//! the extent of the claim: wasm32-wasi under a WASI host. A browser supplies
//! no WASI, and wasm32-freestanding has no entropy source at all -- `rand`
//! there is a compile error, deliberately, rather than a PRNG that would hand
//! out predictable keys.

pub const wasm_crypto = @import("wasm_crypto.zig");

// Flattened so callers can write `zcrypto.wasm_crypto.WasmCrypto` rather than
// `zcrypto.wasm_crypto.wasm_crypto.WasmCrypto`. The doubled segment is an
// artifact of every feature living behind a `feature_*.zig` namespace; it
// happens to be visible only here, because this is the one feature whose single
// module shares its name with the family. The nested path still resolves, so
// nothing that already spells it out breaks.
pub const WasmCryptoError = wasm_crypto.WasmCryptoError;
pub const GasCosts = wasm_crypto.GasCosts;
pub const GasMeter = wasm_crypto.GasMeter;
pub const WasmMemory = wasm_crypto.WasmMemory;
pub const WasmCrypto = wasm_crypto.WasmCrypto;
pub const WasmStreamCrypto = wasm_crypto.WasmStreamCrypto;
pub const CryptoSandbox = wasm_crypto.CryptoSandbox;

test {
    _ = wasm_crypto;
}
