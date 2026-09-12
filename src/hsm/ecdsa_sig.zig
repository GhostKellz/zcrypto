//! Conversion between the two encodings of an ECDSA P-256 signature.
//!
//! PKCS#11's `CKM_ECDSA` produces the raw concatenation r || s, each half
//! padded to the byte length of the curve order — 64 bytes for P-256. X.509,
//! TLS and OpenSSL use DER `SEQUENCE { INTEGER r, INTEGER s }`. The two are not
//! interchangeable, and the difference is not a matter of adding a header: DER
//! INTEGERs are signed and minimally encoded, so a half whose top bit is set
//! gains a leading zero byte and a half with leading zeros loses them. A
//! `memcpy` of the 64 bytes into a `SEQUENCE` produces a structure that parses
//! on roughly half of all keys and fails on the rest, which is the worst
//! possible failure mode: intermittent, key-dependent and far from its cause.
//!
//! This lives outside both PKCS#11 backends because it touches no Cryptoki
//! type. Both import it, so the real backend and the absent shim cannot drift
//! apart, and the conversion is exercised by the default test build even though
//! the real backend is not compiled there.

const std = @import("std");

/// Bytes in a P-256 field element, and therefore in each half of a raw
/// signature.
pub const scalar_len = 32;

/// Worst-case DER length for a P-256 signature: `SEQUENCE` header (2) plus two
/// INTEGERs of 33 content bytes with their own 2-byte headers.
pub const max_der_len = 2 + 2 * (2 + scalar_len + 1);

/// Deliberately a two-member set rather than a reference to either backend's
/// error type, so this file depends on neither. Both `Pkcs11Error` sets are
/// supersets of it, and Zig error sets are structural, so these values coerce
/// into either without a mapping table.
pub const SignatureError = error{
    BufferTooSmall,
    MalformedResponse,
};

/// Convert a raw r || s signature into DER. Returns the number of bytes
/// written to `out`, which needs `max_der_len` in the worst case.
pub fn derFromRaw(raw: [2 * scalar_len]u8, out: []u8) SignatureError!usize {
    const r = derInteger(raw[0..scalar_len]);
    const s = derInteger(raw[scalar_len..][0..scalar_len]);

    const body_len = 2 + r.len + 2 + s.len;
    // A P-256 signature body never reaches 128 bytes, so the SEQUENCE length is
    // always short form. Asserting it keeps the encoder from silently emitting
    // an invalid long-form length if this is ever reused for a larger curve.
    std.debug.assert(body_len < 0x80);
    if (out.len < 2 + body_len) return SignatureError.BufferTooSmall;

    var i: usize = 0;
    out[i] = 0x30;
    i += 1;
    out[i] = @intCast(body_len);
    i += 1;
    for ([_]DerInt{ r, s }) |v| {
        out[i] = 0x02;
        i += 1;
        out[i] = @intCast(v.len);
        i += 1;
        if (v.pad) {
            out[i] = 0;
            i += 1;
        }
        @memcpy(out[i..][0..v.body.len], v.body);
        i += v.body.len;
    }
    return i;
}

const DerInt = struct {
    /// The scalar with leading zero bytes removed.
    body: []const u8,
    /// Whether a zero byte must precede it to keep the DER value positive.
    pad: bool,
    /// Encoded content length, including any pad byte.
    len: usize,
};

fn derInteger(scalar: []const u8) DerInt {
    // `start + 1 < len` rather than `start < len`: DER has no zero-length
    // INTEGER, so the value zero keeps one 0x00 content byte.
    var start: usize = 0;
    while (start + 1 < scalar.len and scalar[start] == 0) start += 1;
    const body = scalar[start..];
    const pad = (body[0] & 0x80) != 0;
    return .{ .body = body, .pad = pad, .len = body.len + @intFromBool(pad) };
}

/// Recover the raw r || s form from a DER signature.
///
/// Rejects anything that is not exactly one well-formed two-INTEGER SEQUENCE
/// covering the whole input. A scalar too wide for the curve is an error rather
/// than being truncated, because dropping a top byte turns an invalid signature
/// into a plausible one.
pub fn rawFromDer(der: []const u8, out: *[2 * scalar_len]u8) SignatureError!void {
    if (der.len < 8 or der[0] != 0x30) return SignatureError.MalformedResponse;
    if (der[1] != der.len - 2) return SignatureError.MalformedResponse;

    @memset(out, 0);
    var i: usize = 2;
    for (0..2) |half| {
        if (i + 2 > der.len or der[i] != 0x02) return SignatureError.MalformedResponse;
        const len = der[i + 1];
        i += 2;
        if (len == 0 or i + len > der.len) return SignatureError.MalformedResponse;

        var body = der[i..][0..len];
        i += len;
        while (body.len > 1 and body[0] == 0) body = body[1..];
        if (body.len > scalar_len) return SignatureError.MalformedResponse;

        const dst = out[half * scalar_len ..][0..scalar_len];
        @memcpy(dst[scalar_len - body.len ..], body);
    }
    // Trailing bytes after the second INTEGER mean the SEQUENCE length lied.
    if (i != der.len) return SignatureError.MalformedResponse;
}

const testing = std.testing;

test "raw and DER signature encodings round-trip" {
    var raw: [64]u8 = undefined;
    for (&raw, 0..) |*b, i| b.* = @intCast(i + 1);

    var der: [max_der_len]u8 = undefined;
    const n = try derFromRaw(raw, &der);

    var back: [64]u8 = undefined;
    try rawFromDer(der[0..n], &back);
    try testing.expectEqualSlices(u8, &raw, &back);
}

test "a scalar with the high bit set gains a leading zero in DER" {
    // This is the case a memcpy-based encoder gets wrong.
    var raw: [64]u8 = @splat(0x11);
    raw[0] = 0xff;

    var der: [max_der_len]u8 = undefined;
    const n = try derFromRaw(raw, &der);

    try testing.expectEqual(@as(u8, 0x30), der[0]);
    try testing.expectEqual(@as(u8, 0x02), der[2]);
    // 32 content bytes plus the pad byte.
    try testing.expectEqual(@as(u8, 33), der[3]);
    try testing.expectEqual(@as(u8, 0x00), der[4]);
    try testing.expectEqual(@as(u8, 0xff), der[5]);

    var back: [64]u8 = undefined;
    try rawFromDer(der[0..n], &back);
    try testing.expectEqualSlices(u8, &raw, &back);
}

test "a scalar with leading zeros loses them in DER and is restored padded" {
    var raw: [64]u8 = @splat(0x22);
    raw[0] = 0;
    raw[1] = 0;

    var der: [max_der_len]u8 = undefined;
    const n = try derFromRaw(raw, &der);

    // 30 content bytes, no pad: the leading byte is 0x22.
    try testing.expectEqual(@as(u8, 30), der[3]);
    try testing.expectEqual(@as(u8, 0x22), der[4]);

    var back: [64]u8 = undefined;
    try rawFromDer(der[0..n], &back);
    try testing.expectEqualSlices(u8, &raw, &back);
}

test "an all-zero scalar keeps one content byte" {
    const raw: [64]u8 = @splat(0);
    var der: [max_der_len]u8 = undefined;
    const n = try derFromRaw(raw, &der);

    try testing.expectEqual(@as(u8, 1), der[3]);
    try testing.expectEqual(@as(u8, 0), der[4]);

    var back: [64]u8 = undefined;
    try rawFromDer(der[0..n], &back);
    try testing.expectEqualSlices(u8, &raw, &back);
}

test "the worst-case signature fits max_der_len exactly" {
    // Both halves have their high bit set, so both are padded. Nothing larger
    // is possible for P-256, which is what makes the bound a bound.
    const raw: [64]u8 = @splat(0xff);
    var der: [max_der_len]u8 = undefined;
    const n = try derFromRaw(raw, &der);
    try testing.expectEqual(max_der_len, n);
}

test "derFromRaw reports a small buffer instead of truncating" {
    const raw: [64]u8 = @splat(0xff);
    var tiny: [8]u8 = undefined;
    try testing.expectError(SignatureError.BufferTooSmall, derFromRaw(raw, &tiny));
}

test "malformed DER is rejected rather than partially decoded" {
    var out: [64]u8 = undefined;

    // Not a SEQUENCE.
    try testing.expectError(SignatureError.MalformedResponse, rawFromDer(&[_]u8{ 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }, &out));
    // The declared SEQUENCE length disagrees with the buffer.
    try testing.expectError(SignatureError.MalformedResponse, rawFromDer(&[_]u8{ 0x30, 0x20, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }, &out));
    // The second element is an OCTET STRING, not an INTEGER.
    try testing.expectError(SignatureError.MalformedResponse, rawFromDer(&[_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x01 }, &out));
    // Too short to be a signature at all.
    try testing.expectError(SignatureError.MalformedResponse, rawFromDer(&[_]u8{ 0x30, 0x00 }, &out));
    // A zero-length INTEGER, which DER does not permit.
    try testing.expectError(SignatureError.MalformedResponse, rawFromDer(&[_]u8{ 0x30, 0x06, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01 }, &out));
}

test "a scalar wider than the curve is rejected, not truncated" {
    // 33 content bytes with no sign pad does not fit a P-256 scalar.
    var der: [max_der_len]u8 = undefined;
    der[0] = 0x30;
    der[1] = 38;
    der[2] = 0x02;
    der[3] = 33;
    @memset(der[4..][0..33], 0x77);
    der[37] = 0x02;
    der[38] = 1;
    der[39] = 1;

    var out: [64]u8 = undefined;
    try testing.expectError(SignatureError.MalformedResponse, rawFromDer(der[0..40], &out));
}

test "trailing bytes after the signature are rejected" {
    const raw: [64]u8 = @splat(0x33);
    var der: [max_der_len + 1]u8 = undefined;
    const n = try derFromRaw(raw, &der);
    der[n] = 0xaa;

    var out: [64]u8 = undefined;
    try testing.expectError(SignatureError.MalformedResponse, rawFromDer(der[0 .. n + 1], &out));
}

test "a DER signature this module produced verifies as the same signature" {
    // Ties the encoding to something outside this file: the raw form is what
    // std.crypto accepts, so a round-trip that changed the value would make a
    // real signature stop verifying.
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    // Deterministic key and deterministic nonce: a random signature would make
    // this test cover a different pair of scalars on every run, so a padding
    // case it failed on would be unreproducible from the failure alone.
    const seed: [Ecdsa.KeyPair.seed_length]u8 = @splat(0x5a);
    const kp = try Ecdsa.KeyPair.generateDeterministic(seed);
    const msg = "pkcs11 signature encoding";
    const sig = try kp.sign(msg, null);

    var der: [max_der_len]u8 = undefined;
    const n = try derFromRaw(sig.toBytes(), &der);

    var back: [64]u8 = undefined;
    try rawFromDer(der[0..n], &back);
    try Ecdsa.Signature.fromBytes(back).verify(msg, kp.public_key);
}
