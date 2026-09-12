//! BBR Crypto Profiling for zcrypto
//!
//! Provides real-time crypto performance metrics to help zquic's BBR congestion
//! control make intelligent decisions about bandwidth and pacing based on
//! cryptographic workload and hardware capabilities.
//!
//! This module measures and advises; it implements no congestion control itself.
//! Every figure it publishes is either a measurement or explicitly absent --
//! there are no defaults standing in for data that was never collected, because
//! a pacing controller cannot tell a conservative guess from an observation.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const hardware = @import("hardware.zig");
const util = @import("util.zig");

/// Sentinel for "no CPU utilisation sample has been supplied".
///
/// Out of band rather than 0 because 0% is a legitimate reading. The field is
/// `u16` purely so a value outside 0..100 exists to spend on this.
const cpu_unknown: u16 = std.math.maxInt(u16);

pub const BBRCryptoProfiler = struct {
    // Performance metrics
    encryption_latency_ns: util.Counter64 = util.Counter64.init(0),
    decryption_latency_ns: util.Counter64 = util.Counter64.init(0),
    /// Kilobits per second, not megabits.
    ///
    /// Finer than the reported unit on purpose: this is a rolling average kept
    /// in integer arithmetic, and storing megabits directly floored every link
    /// slower than 1 Mb/s to zero -- which `calculateOverheadFactor` then read
    /// as "no measurement". Kilobits keep three more digits before that happens.
    throughput_kbps: util.Counter64 = util.Counter64.init(0),
    cpu_utilization: std.atomic.Value(u16) = std.atomic.Value(u16).init(cpu_unknown),

    // Hardware capabilities
    hw_features: hardware.HardwareAcceleration,
    hw_acceleration_available: bool,

    pub fn init(hw_features: hardware.HardwareAcceleration) BBRCryptoProfiler {
        return BBRCryptoProfiler{
            .hw_features = hw_features,
            .hw_acceleration_available = hw_features.aes_ni or hw_features.avx2 or hw_features.arm_crypto,
        };
    }

    /// Supply the current CPU utilisation, 0..100, clamped.
    ///
    /// zcrypto cannot measure this -- it has no view of the process, let alone
    /// the host -- so the embedding stack has to provide it. Until it does, the
    /// CPU-driven advice below stays switched off rather than reading 0%, which
    /// is what previously made this profiler recommend pacing *up* forever.
    pub fn setCpuUtilization(self: *BBRCryptoProfiler, percent: u8) void {
        self.cpu_utilization.store(@min(100, percent), .monotonic);
    }

    /// Record an encryption that took `latency_ns` and covered `bytes_processed`.
    ///
    /// Takes an elapsed duration rather than a start/end pair. The pair form
    /// computed `end - start` on unsigned values, so a backwards or unsynchronised
    /// clock did not skew a statistic -- it panicked on integer overflow. Callers
    /// now produce the duration with `util.Instant.since`, which reports a
    /// backwards clock as an error, so the bad state cannot reach this function.
    pub fn recordEncryption(self: *BBRCryptoProfiler, latency_ns: u64, bytes_processed: usize) void {
        ewmaUpdate(&self.encryption_latency_ns, latency_ns);

        if (latency_ns == 0) return; // No elapsed time means no derivable rate.

        // bytes * 8 bits * 1e9 ns/s / 1e3 bits/kbit collapses to bytes * 8e6.
        const sample_kbps = (@as(u64, bytes_processed) *| 8_000_000) / latency_ns;
        ewmaUpdate(&self.throughput_kbps, sample_kbps);
    }

    /// Record a decryption that took `latency_ns`.
    ///
    /// No byte count: decryption throughput is not tracked, and the parameter
    /// that used to accept one was discarded at the top of the body. A parameter
    /// a caller believes is being used is worse than one that is not offered.
    pub fn recordDecryption(self: *BBRCryptoProfiler, latency_ns: u64) void {
        ewmaUpdate(&self.decryption_latency_ns, latency_ns);
    }

    /// Get current crypto performance metrics for BBR
    pub fn getMetrics(self: *BBRCryptoProfiler) BBRCryptoMetrics {
        const raw_cpu = self.cpu_utilization.load(.monotonic);
        return BBRCryptoMetrics{
            .avg_encryption_latency_us = self.encryption_latency_ns.load() / 1000,
            .avg_decryption_latency_us = self.decryption_latency_ns.load() / 1000,
            .throughput_kbps = self.throughput_kbps.load(),
            .cpu_utilization_percent = if (raw_cpu == cpu_unknown) null else @intCast(raw_cpu),
            .hw_acceleration_active = self.hw_acceleration_available,
            .crypto_overhead_factor = self.calculateOverheadFactor(),
        };
    }

    /// Ratio of the throughput this hardware should reach to what it is reaching.
    ///
    /// Null rather than a "conservative default" when nothing has been measured:
    /// the previous 2.0 was indistinguishable from a genuine 2x shortfall, so a
    /// caller halved its bandwidth estimate on the strength of no data at all.
    fn calculateOverheadFactor(self: *BBRCryptoProfiler) ?f32 {
        const current_kbps = self.throughput_kbps.load();
        if (current_kbps == 0) return null;

        // Order-of-magnitude expectations for AEAD on one core: ~1 GB/s with an
        // AES-NI-class unit, ~500 MB/s without. Expressed in kbit/s to match the
        // measurement. These are reference points for a ratio, not guarantees.
        const base_kbps: f32 = if (self.hw_acceleration_available) 8_000_000.0 else 4_000_000.0;
        return base_kbps / @as(f32, @floatFromInt(current_kbps));
    }

    /// Predict whether the measured crypto throughput can carry a packet rate.
    ///
    /// Null when no throughput sample exists yet. The old version always answered,
    /// deriving a percentage from a latency average that was never normalised per
    /// byte, so the figure had no dimension a caller could act on.
    pub fn predictCryptoCapacity(
        self: *BBRCryptoProfiler,
        packets_per_second: u32,
        avg_packet_size: u32,
    ) ?CryptoCapacityPrediction {
        const measured_kbps = self.throughput_kbps.load();
        if (measured_kbps == 0) return null;

        // Widened before multiplying. As u32 this overflowed at roughly 4.3e9
        // bytes/s, which 800k packets/s of 9000-byte jumbo frames -- an ordinary
        // 10GbE load -- exceeds, panicking rather than reporting saturation.
        const bytes_per_second: u64 = @as(u64, packets_per_second) * @as(u64, avg_packet_size);
        const required_kbps: u64 = bytes_per_second * 8 / 1000;

        const usage_percent: u64 = required_kbps * 100 / measured_kbps;
        const will_bottleneck = usage_percent > 80;

        return CryptoCapacityPrediction{
            .can_handle_load = !will_bottleneck,
            // Clamped before the cast, not after. `@min(100, @intCast(x))`
            // evaluates the cast first, so the clamp that looked like the
            // safeguard ran only once the unsafe cast had already succeeded.
            .expected_cpu_usage = @intCast(@min(@as(u64, 100), usage_percent)),
            .recommended_max_pps = recommendedMaxPps(packets_per_second, usage_percent),
            .crypto_latency_impact_us = self.encryption_latency_ns.load() / 1000,
        };
    }

    /// Suggest optimal cipher suite based on current conditions
    pub fn suggestOptimalCipher(self: *BBRCryptoProfiler, target_throughput_mbps: u32) CipherRecommendation {
        const metrics = self.getMetrics();

        if (self.hw_features.aes_ni and target_throughput_mbps > 500) {
            return CipherRecommendation{
                .cipher = .aes_256_gcm,
                .reason = "AES-NI available, high throughput target",
                .expected_performance_gain = 2.1,
            };
        }

        // Only consults CPU load when there is a reading. Unknown used to compare
        // as 0%, so this branch was unreachable and ChaCha20 was never suggested.
        if (metrics.cpu_utilization_percent) |cpu| {
            if (cpu > 70) {
                return CipherRecommendation{
                    .cipher = .chacha20_poly1305,
                    .reason = "High CPU utilization, ChaCha20 more efficient",
                    .expected_performance_gain = 1.3,
                };
            }
        }

        return CipherRecommendation{
            .cipher = .aes_128_gcm,
            .reason = "Balanced choice for current conditions",
            .expected_performance_gain = 1.0,
        };
    }
};

/// Fold `sample` into a 7/8-to-history rolling average held in `cell`.
///
/// Compare-and-swap rather than load/compute/store. The three-step form looked
/// atomic because the cell was a `std.atomic.Value`, but concurrent recorders
/// interleaved between the load and the store and silently dropped each other's
/// samples -- on a profiler whose whole purpose is to be written from every
/// connection thread at once.
///
/// A zero cell is treated as unseeded and takes the sample whole. Otherwise the
/// first measurement is averaged against an initial zero and lands at one eighth
/// of its true value, which is how a 5us encryption used to be reported as 0us.
fn ewmaUpdate(cell: *util.Counter64, sample: u64) void {
    var current = cell.load();
    while (true) {
        const next = if (current == 0) sample else (current *| 7 +| sample) / 8;
        if (cell.cmpxchgWeak(current, next)) |actual| {
            current = actual;
        } else {
            return;
        }
    }
}

/// Packet rate that would put crypto at 80% of measured capacity.
fn recommendedMaxPps(packets_per_second: u32, usage_percent: u64) u32 {
    // A load too small to register as 1% gives no ratio to scale by, so report
    // the ceiling rather than dividing by zero.
    if (usage_percent == 0) return std.math.maxInt(u32);
    const scaled = @as(u64, packets_per_second) * 80 / usage_percent;
    return @intCast(@min(@as(u64, std.math.maxInt(u32)), scaled));
}

/// Crypto performance metrics for BBR decision making
pub const BBRCryptoMetrics = struct {
    avg_encryption_latency_us: u64,
    avg_decryption_latency_us: u64,
    /// Kilobits per second. Zero means nothing has been measured yet.
    throughput_kbps: u64,
    /// Null until the embedding stack supplies a reading via `setCpuUtilization`.
    cpu_utilization_percent: ?u8,
    hw_acceleration_active: bool,
    /// Null until throughput has been measured at least once.
    crypto_overhead_factor: ?f32,

    /// Check if crypto is currently a bottleneck
    pub fn isCryptoBottleneck(self: BBRCryptoMetrics) bool {
        if (self.cpu_utilization_percent) |cpu| {
            if (cpu > 80) return true;
        }
        return self.avg_encryption_latency_us > 1000; // 1ms threshold
    }

    /// Get recommended pacing rate adjustment for BBR
    pub fn getPacingAdjustment(self: BBRCryptoMetrics) f32 {
        if (self.isCryptoBottleneck()) return 0.7; // Reduce pacing by 30%

        // Pacing *up* requires evidence, so an absent CPU reading declines to
        // adjust instead of assuming an idle core. With utilisation hardwired to
        // 0 this used to be the only reachable outcome, leaving the profiler
        // permanently urging BBR to send faster and never able to ask for less.
        if (self.hw_acceleration_active) {
            if (self.cpu_utilization_percent) |cpu| {
                if (cpu < 50) return 1.2; // Can pace 20% faster
            }
        }
        return 1.0; // No adjustment needed
    }
};

/// Prediction of crypto capacity for future load
pub const CryptoCapacityPrediction = struct {
    can_handle_load: bool,
    expected_cpu_usage: u8,
    recommended_max_pps: u32,
    crypto_latency_impact_us: u64,
};

/// Cipher suite recommendation based on current conditions
pub const CipherRecommendation = struct {
    cipher: CipherType,
    reason: []const u8,
    expected_performance_gain: f32,

    pub const CipherType = enum {
        aes_128_gcm,
        aes_256_gcm,
        chacha20_poly1305,
    };
};

/// BBR integration helper for crypto-aware congestion control
pub const BBRCryptoIntegration = struct {
    profiler: *BBRCryptoProfiler,
    last_metrics: BBRCryptoMetrics,
    metrics_update_interval_ms: u32,
    /// When the metrics were last refreshed; null if the clock was unreadable.
    last_update_time: ?util.Instant,

    pub fn init(profiler: *BBRCryptoProfiler, update_interval_ms: u32) BBRCryptoIntegration {
        return BBRCryptoIntegration{
            .profiler = profiler,
            .last_metrics = profiler.getMetrics(),
            .metrics_update_interval_ms = update_interval_ms,
            .last_update_time = util.getMonotonic(),
        };
    }

    /// Called by BBR to get current crypto-adjusted bandwidth estimate
    pub fn getCryptoAdjustedBandwidth(self: *BBRCryptoIntegration, base_bandwidth_mbps: u32) u32 {
        self.updateMetricsIfNeeded();

        const adjustment = self.last_metrics.getPacingAdjustment();
        const adjusted_bandwidth = @as(f32, @floatFromInt(base_bandwidth_mbps)) * adjustment;

        return @as(u32, @intFromFloat(@max(1.0, adjusted_bandwidth)));
    }

    /// Called by BBR to check if pacing rate should be reduced due to crypto load
    pub fn shouldReducePacing(self: *BBRCryptoIntegration) bool {
        self.updateMetricsIfNeeded();
        return self.last_metrics.isCryptoBottleneck();
    }

    /// Get crypto latency to add to RTT measurements
    pub fn getCryptoLatencyContribution(self: *BBRCryptoIntegration) u64 {
        self.updateMetricsIfNeeded();
        return self.last_metrics.avg_encryption_latency_us + self.last_metrics.avg_decryption_latency_us;
    }

    fn updateMetricsIfNeeded(self: *BBRCryptoIntegration) void {
        const now = util.getMonotonic();

        // Every path that cannot establish an elapsed time refreshes rather than
        // skips. Holding the previous metrics would feed BBR a pacing input that
        // grows more stale the longer the clock stays unreadable, and would do so
        // silently; refreshing costs only the recomputation.
        const due = due: {
            const current = now orelse break :due true;
            const previous = self.last_update_time orelse break :due true;
            const elapsed_ns = current.since(previous) catch break :due true;
            break :due elapsed_ns / std.time.ns_per_ms >= self.metrics_update_interval_ms;
        };

        if (due) {
            self.last_metrics = self.profiler.getMetrics();
            self.last_update_time = now;
        }
    }
};

// =============================================================================
// TESTS
// =============================================================================

const hw_with_aes = hardware.HardwareAcceleration{
    .aes_ni = true,
    .avx2 = false,
    .arm_crypto = false,
    .sha_ext = false,
    .pclmulqdq = false,
    .avx512 = false,
};

const hw_without = hardware.HardwareAcceleration{
    .aes_ni = false,
    .avx2 = false,
    .arm_crypto = false,
    .sha_ext = false,
    .pclmulqdq = false,
    .avx512 = false,
};

test "a single sample is reported at its true value, not an eighth of it" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);

    // One 5us encryption. Averaging this against an unseeded zero yields 625ns,
    // which `getMetrics` floors to 0us -- the profiler reporting no latency for
    // an operation it just measured.
    profiler.recordEncryption(5_000, 1024);

    try testing.expectEqual(@as(u64, 5), profiler.getMetrics().avg_encryption_latency_us);
}

test "a constant stream converges to the constant" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);

    const latency_ns: u64 = 5_000;
    for (0..32) |_| profiler.recordEncryption(latency_ns, 1024);

    const metrics = profiler.getMetrics();
    // An average over a constant stream is that constant. Asserting only `> 0`
    // would pass on any positive number, including one larger than every sample.
    try testing.expectEqual(latency_ns / 1000, metrics.avg_encryption_latency_us);
    try testing.expect(metrics.hw_acceleration_active);
}

test "throughput is reported in the unit its name claims" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);

    // Exactly one mebibyte in exactly one second. That is 8_388_608 bits/s, so
    // 8388 kb/s. Held in megabits it truncated to 0 and read as "unmeasured".
    for (0..64) |_| profiler.recordEncryption(std.time.ns_per_s, 1024 * 1024);

    const kbps = profiler.getMetrics().throughput_kbps;
    try testing.expect(kbps > 8_000 and kbps < 8_800);
}

test "an unmeasured profiler declines to predict rather than inventing a figure" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);

    try testing.expectEqual(@as(?CryptoCapacityPrediction, null), profiler.predictCryptoCapacity(10_000, 1500));
    try testing.expectEqual(@as(?f32, null), profiler.getMetrics().crypto_overhead_factor);
}

test "capacity prediction survives a 10GbE packet rate" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);
    for (0..64) |_| profiler.recordEncryption(200_000, 1500);

    // 800k packets/s of 9000-byte jumbo frames overflows a u32 byte-rate, which
    // used to panic here rather than report that the link cannot be served.
    const prediction = profiler.predictCryptoCapacity(800_000, 9000) orelse return error.TestUnexpectedResult;

    try testing.expect(prediction.expected_cpu_usage <= 100);
    try testing.expect(!prediction.can_handle_load);
    try testing.expect(prediction.recommended_max_pps < 800_000);
}

test "a load far below capacity is reported as servable" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);
    for (0..64) |_| profiler.recordEncryption(200_000, 1500);

    const prediction = profiler.predictCryptoCapacity(10, 64) orelse return error.TestUnexpectedResult;

    // Pairs with the test above: a predictor hardwired to "bottleneck" would
    // satisfy that one while being useless.
    try testing.expect(prediction.can_handle_load);
    try testing.expect(prediction.recommended_max_pps > 10);
}

test "pacing is never advised upward on an unknown CPU load" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);
    for (0..32) |_| profiler.recordEncryption(5_000, 1024);

    const metrics = profiler.getMetrics();
    try testing.expectEqual(@as(?u8, null), metrics.cpu_utilization_percent);
    // The failure this guards is directional. With utilisation stuck at 0 the
    // only reachable answer was 1.2 -- a crypto-aware pacer that could ask BBR
    // to speed up and never to slow down.
    try testing.expectEqual(@as(f32, 1.0), metrics.getPacingAdjustment());
}

test "a supplied CPU load unlocks both directions of advice" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);
    for (0..32) |_| profiler.recordEncryption(5_000, 1024);

    profiler.setCpuUtilization(10);
    try testing.expectEqual(@as(f32, 1.2), profiler.getMetrics().getPacingAdjustment());

    profiler.setCpuUtilization(95);
    const loaded = profiler.getMetrics();
    try testing.expect(loaded.isCryptoBottleneck());
    try testing.expectEqual(@as(f32, 0.7), loaded.getPacingAdjustment());
}

test "cpu utilization is clamped to a percentage" {
    var profiler = BBRCryptoProfiler.init(hw_without);
    profiler.setCpuUtilization(250);
    try testing.expectEqual(@as(?u8, 100), profiler.getMetrics().cpu_utilization_percent);
}

test "cipher recommendation reaches the high-CPU branch" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);

    // AES-NI plus a high target still wins outright.
    try testing.expect(profiler.suggestOptimalCipher(1000).cipher == .aes_256_gcm);

    // Below that target, a loaded CPU should pick ChaCha20. This branch was
    // unreachable while utilisation could not be set.
    profiler.setCpuUtilization(90);
    try testing.expect(profiler.suggestOptimalCipher(100).cipher == .chacha20_poly1305);

    profiler.setCpuUtilization(5);
    try testing.expect(profiler.suggestOptimalCipher(100).cipher == .aes_128_gcm);
}

test "concurrent recorders do not lose samples" {
    // Skipped rather than reworked on a single-threaded target. There is no
    // contention to create on wasm32-wasi, so the property under test does not
    // exist there; a version that ran the workers sequentially would report a
    // pass having exercised nothing.
    if (builtin.single_threaded) return error.SkipZigTest;

    var profiler = BBRCryptoProfiler.init(hw_with_aes);

    // A load/compute/store average drops updates when threads interleave. Every
    // sample here is identical, so a correct rolling average must land exactly
    // on it no matter how the writes are ordered -- any lost update still
    // converges, so what this really exercises is that the CAS loop terminates
    // and stays coherent under contention.
    const Worker = struct {
        fn run(p: *BBRCryptoProfiler) void {
            for (0..2000) |_| p.recordEncryption(4_000, 1024);
        }
    };

    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{&profiler});
    for (threads) |t| t.join();

    try testing.expectEqual(@as(u64, 4), profiler.getMetrics().avg_encryption_latency_us);
}

test "BBR integration" {
    var profiler = BBRCryptoProfiler.init(hw_with_aes);
    var bbr_integration = BBRCryptoIntegration.init(&profiler, 50); // 50ms update interval

    const base_bandwidth = 1000; // 1Gbps
    const adjusted_bandwidth = bbr_integration.getCryptoAdjustedBandwidth(base_bandwidth);

    try testing.expect(adjusted_bandwidth > 0);
    try testing.expect(adjusted_bandwidth <= base_bandwidth * 2); // Reasonable range
}
