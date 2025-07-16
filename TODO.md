# 🚀 TODO: Migrate from tokioZ async to zsync async runtime (Zig v0.15+)

## Why migrate?
- zsync is a modern, colorblind async runtime for Zig v0.15+
- Replaces legacy tokioZ (custom, less compatible)
- Supports std.Io interface, multiple execution models, and better performance

## Migration Steps

### 1. **build.zig - Replace tokioZ dependency (Lines 7-58)**
```zig
// REMOVE:
const tokioZ_dep = b.lazyDependency("tokioZ", .{...});
const zcrypto_imports: []const std.Build.Module.Import = if (tokioZ_dep) |tokioZ| blk: {
    break :blk &.{ .{ .name = "tokioZ", .module = tokioZ.module("TokioZ") }, };
} else &.{};

// REPLACE WITH:
const zsync_dep = b.lazyDependency("zsync", .{...});
const zcrypto_imports: []const std.Build.Module.Import = if (zsync_dep) |zsync| blk: {
    break :blk &.{ .{ .name = "zsync", .module = zsync.module("zsync") }, };
} else &.{};
```

### 2. **src/async_crypto.zig - Complete rewrite (514 lines)**
```zig
// REMOVE placeholder tokioZ code (lines 13-50):
// const tokioZ = @import("tokioZ");
const Runtime = struct { ... }; // All placeholder structs

// REPLACE WITH zsync implementation:
const zsync = @import("zsync");
const Io = zsync.Io;
const Future = zsync.Future;

pub fn encryptAsync(io: Io, data: []const u8, key: [32]u8) ![]u8 {
    var future = io.async(performEncryption, .{ data, key });
    defer future.cancel(io) catch {};
    return try future.await(io);
}
```

### 3. **examples/tokioz_crypto_example.zig → zsync_crypto_example.zig**
- **Rename file**: `examples/tokioz_crypto_example.zig` → `examples/zsync_crypto_example.zig`
- **Replace header comment** (lines 1-4): "TokioZ integration" → "zsync integration"  
- **Replace imports** (line 18): `// const tokioZ = @import("tokioZ");` → `const zsync = @import("zsync");`
- **Update all 383 lines** to use zsync async patterns instead of tokioZ placeholders

### 4. **build.zig - Update example executable (lines 40-58)**
```zig
// REMOVE:
const tokioz_example = b.addExecutable(.{
    .name = "tokioz-crypto-example",
    .root_source_file = b.path("examples/tokioz_crypto_example.zig"),
});

// REPLACE WITH:
const zsync_example = b.addExecutable(.{
    .name = "zsync-crypto-example", 
    .root_source_file = b.path("examples/zsync_crypto_example.zig"),
});
```

### 5. **INTEGRATION.md - Fix 4 tokioZ references**
- Line 43: `// Async crypto with tokioZ` → `// Async crypto with zsync`
- Line 354: `- **tokioZ integration** for Zig async` → `- **zsync integration** for Zig async`
- Line 405-406: Replace tokioZ missing dependency fix with zsync solution

### 6. **Test and verify all changes work**
```bash
zig build                           # Should compile without tokioZ errors
zig build run-zsync                 # Should run zsync example
zig test src/async_crypto.zig       # Should pass all async tests
grep -r "tokio" src/ examples/      # Should return no results
```

## Files to update
- ✅ `build.zig.zon` - Already has zsync dependency
- ✅ `build.zig` - Replace tokioZ with zsync (completed)
- ✅ `src/async_crypto.zig` - Complete rewrite (zsync implementation done)
- ✅ `examples/zsync_crypto_example.zig` - Created with zsync integration
- ✅ `INTEGRATION.md` - Fix 4 tokioZ references to zsync (completed)
- ✅ `examples/async_features.zig` - Update header comments (completed)

## Success criteria
- ✅ All async crypto uses zsync
- ✅ No tokioZ code or docs remain
- 🔄 All tests/examples pass with zsync (pending zsync v0.3.1 API fixes)
- ✅ Documentation reflects new async runtime

## 🚀 Waiting for zsync v0.3.1 Features

**Claude's Recommendations for zsync v0.3.1:**
1. **Zero-Copy Async Operations** - Critical for performance across all async use cases
2. **Hardware-Accelerated Async** - SIMD/AVX operations for better performance
3. **Async Performance Metrics** - Essential for validating zsync's performance claims
4. **Real-time Async Streams** - Core async pattern for networking and data processing

These features will unlock the full potential of zcrypto's async operations and enable the advanced features planned for zcrypto v0.9.0.

## 📋 Next Steps After zsync v0.3.1
Once zsync v0.3.1 is released with the recommended features, zcrypto can implement:
- Zero-copy encryption/decryption operations
- Hardware-accelerated crypto with async SIMD
- Real-time crypto stream processing
- Performance monitoring for async crypto operations

---

**zsync will provide better async performance, simpler code, and future-proofing for Zig async crypto!**
