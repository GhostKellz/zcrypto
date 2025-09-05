//! BBR Crypto Profiling for zcrypto v0.7.0
//!
//! Provides real-time crypto performance metrics to help zquic's BBR congestion
//! control make intelligent decisions about bandwidth and pacing based on
//! cryptographic workload and hardware capabilities.

const std = @import("std");
const testing = std.testing;
const hardware = @import("hardware.zig");

pub const BBRCryptoProfiler = struct {
    // Performance metrics
    encryption_latency_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    decryption_latency_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    throughput_mbps: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    cpu_utilization: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    // Hardware capabilities
    hw_features: hardware.HardwareAcceleration,
    hw_acceleration_available: bool,

    // Measurement state
    measurement_window_ms: u32,
    last_measurement_time: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(hw_features: hardware.HardwareAcceleration, window_ms: u32) BBRCryptoProfiler {
        return BBRCryptoProfiler{
            .hw_features = hw_features,
            .hw_acceleration_available = hw_features.aes_ni or hw_features.avx2 or hw_features.arm_crypto,
            .measurement_window_ms = window_ms,
        };
    }

    /// Record encryption operation timing
    pub fn recordEncryption(self: *BBRCryptoProfiler, start_time_ns: u64, end_time_ns: u64, bytes_processed: usize) void {
        const latency_ns = end_time_ns - start_time_ns;

        // Update rolling average latency
        const current_latency = self.encryption_latency_ns.load(.unordered);
        const new_latency = (current_latency * 7 + latency_ns) / 8; // 7/8 weight to history
        self.encryption_latency_ns.store(new_latency, .unordered);

        // Update throughput calculation
        if (latency_ns > 0) {
            const throughput_bps = (bytes_processed * 1_000_000_000) / latency_ns;
            const throughput_mbps = @as(u32, @intCast(throughput_bps / (1024 * 1024)));

            const current_throughput = self.throughput_mbps.load(.unordered);
            const new_throughput = (current_throughput * 7 + throughput_mbps) / 8;
            self.throughput_mbps.store(new_throughput, .unordered);
        }
    }

    /// Record decryption operation timing
    pub fn recordDecryption(self: *BBRCryptoProfiler, start_time_ns: u64, end_time_ns: u64, bytes_processed: usize) void {
        const latency_ns = end_time_ns - start_time_ns;

        const current_latency = self.decryption_latency_ns.load(.unordered);
        const new_latency = (current_latency * 7 + latency_ns) / 8;
        self.decryption_latency_ns.store(new_latency, .unordered);

        _ = bytes_processed; // Used for throughput in full implementation
    }

    /// Get current crypto performance metrics for BBR
    pub fn getMetrics(self: *BBRCryptoProfiler) BBRCryptoMetrics {
        return BBRCryptoMetrics{
            .avg_encryption_latency_us = self.encryption_latency_ns.load(.unordered) / 1000,
            .avg_decryption_latency_us = self.decryption_latency_ns.load(.unordered) / 1000,
            .throughput_mbps = self.throughput_mbps.load(.unordered),
            .cpu_utilization_percent = self.cpu_utilization.load(.unordered),
            .hw_acceleration_active = self.hw_acceleration_available,
            .crypto_overhead_factor = self.calculateOverheadFactor(),
        };
    }

    /// Calculate crypto overhead factor for BBR bandwidth estimation
    fn calculateOverheadFactor(self: *BBRCryptoProfiler) f32 {
        const base_throughput: f32 = if (self.hw_acceleration_available) 1000.0 else 500.0; // MB/s
        const current_throughput = @as(f32, @floatFromInt(self.throughput_mbps.load(.unordered)));

        if (current_throughput > 0) {
            return base_throughput / current_throughput;
        }
        return 2.0; // Conservative default
    }

    /// Predict crypto capacity for given packet rate
    pub fn predictCryptoCapacity(self: *BBRCryptoProfiler, packets_per_second: u32, avg_packet_size: u32) CryptoCapacityPrediction {
        const metrics = self.getMetrics();

        // Calculate expected crypto workload
        const bytes_per_second = packets_per_second * avg_packet_size;
        const expected_crypto_time_us = (bytes_per_second * metrics.avg_encryption_latency_us) / (1024 * 1024);

        // Determine if crypto will be a bottleneck
        const crypto_cpu_usage = (expected_crypto_time_us * 100) / 1_000_000; // Rough estimate
        const will_bottleneck = crypto_cpu_usage > 80;

        return CryptoCapacityPrediction{
            .can_handle_load = !will_bottleneck,
            .expected_cpu_usage = @min(100, @as(u8, @intCast(crypto_cpu_usage))),
            .recommended_max_rate = if (will_bottleneck) packets_per_second * 80 / @as(u32, @intCast(crypto_cpu_usage)) else packets_per_second * 2,
            .crypto_latency_impact_us = expected_crypto_time_us,
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
        } else if (metrics.cpu_utilization_percent > 70) {
            return CipherRecommendation{
                .cipher = .chacha20_poly1305,
                .reason = "High CPU utilization, ChaCha20 more efficient",
                .expected_performance_gain = 1.3,
            };
        } else {
            return CipherRecommendation{
                .cipher = .aes_128_gcm,
                .reason = "Balanced choice for current conditions",
                .expected_performance_gain = 1.0,
            };
        }
    }
};

/// Crypto performance metrics for BBR decision making
pub const BBRCryptoMetrics = struct {
    avg_encryption_latency_us: u64,
    avg_decryption_latency_us: u64,
    throughput_mbps: u32,
    cpu_utilization_percent: u8,
    hw_acceleration_active: bool,
    crypto_overhead_factor: f32,

    /// Check if crypto is currently a bottleneck
    pub fn isCryptoBottleneck(self: BBRCryptoMetrics) bool {
        return self.cpu_utilization_percent > 80 or self.avg_encryption_latency_us > 1000; // 1ms threshold
    }

    /// Get recommended pacing rate adjustment for BBR
    pub fn getPacingAdjustment(self: BBRCryptoMetrics) f32 {
        if (self.isCryptoBottleneck()) {
            return 0.7; // Reduce pacing by 30%
        } else if (self.hw_acceleration_active and self.cpu_utilization_percent < 50) {
            return 1.2; // Can pace 20% faster
        }
        return 1.0; // No adjustment needed
    }
};

/// Prediction of crypto capacity for future load
pub const CryptoCapacityPrediction = struct {
    can_handle_load: bool,
    expected_cpu_usage: u8,
    recommended_max_rate: u32,
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
    last_update_time: u64,

    pub fn init(profiler: *BBRCryptoProfiler, update_interval_ms: u32) BBRCryptoIntegration {
        return BBRCryptoIntegration{
            .profiler = profiler,
            .last_metrics = profiler.getMetrics(),
            .metrics_update_interval_ms = update_interval_ms,
            .last_update_time = @intCast(std.time.nanoTimestamp()),
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
        const current_time = std.time.nanoTimestamp();
        const elapsed_ms = @divTrunc((current_time - self.last_update_time), 1_000_000);

        if (elapsed_ms >= self.metrics_update_interval_ms) {
            self.last_metrics = self.profiler.getMetrics();
            self.last_update_time = @intCast(current_time);
        }
    }
};

// =============================================================================
// TESTS
// =============================================================================

test "BBR crypto profiler basic operations" {
    const hw_features = hardware.HardwareAcceleration{
        .aes_ni = true,
        .avx2 = false,
        .arm_crypto = false,
        .sha_ext = false,
        .pclmulqdq = false,
        .avx512 = false,
    };

    var profiler = BBRCryptoProfiler.init(hw_features, 100); // 100ms window

    // Simulate encryption timing
    const start_time = std.time.nanoTimestamp();
    std.Thread.sleep(1000); // 1μs
    const end_time = std.time.nanoTimestamp();

    profiler.recordEncryption(@intCast(start_time), @intCast(end_time), 1024);

    const metrics = profiler.getMetrics();
    try testing.expect(metrics.avg_encryption_latency_us > 0);
    try testing.expect(metrics.hw_acceleration_active);
}

test "crypto capacity prediction" {
    const hw_features = hardware.HardwareAcceleration{
        .aes_ni = false,
        .avx2 = false,
        .arm_crypto = false,
        .sha_ext = false,
        .pclmulqdq = false,
        .avx512 = false,
    };

    var profiler = BBRCryptoProfiler.init(hw_features, 100);

    // Test prediction for high packet rate
    const prediction = profiler.predictCryptoCapacity(10000, 1500); // 10k packets/sec, 1.5KB each

    try testing.expect(prediction.expected_cpu_usage <= 100);
    try testing.expect(prediction.recommended_max_rate > 0);
}

test "BBR integration" {
    const hw_features = hardware.HardwareAcceleration{
        .aes_ni = true,
        .avx2 = true,
        .arm_crypto = false,
        .sha_ext = true,
        .pclmulqdq = true,
        .avx512 = false,
    };

    var profiler = BBRCryptoProfiler.init(hw_features, 100);
    var bbr_integration = BBRCryptoIntegration.init(&profiler, 50); // 50ms update interval

    // Test bandwidth adjustment
    const base_bandwidth = 1000; // 1Gbps
    const adjusted_bandwidth = bbr_integration.getCryptoAdjustedBandwidth(base_bandwidth);

    try testing.expect(adjusted_bandwidth > 0);
    try testing.expect(adjusted_bandwidth <= base_bandwidth * 2); // Reasonable range
}

test "cipher recommendation" {
    const hw_features = hardware.HardwareAcceleration{
        .aes_ni = true,
        .avx2 = false,
        .arm_crypto = false,
    };

    var profiler = BBRCryptoProfiler.init(hw_features, 100);

    // Test high throughput recommendation
    const recommendation = profiler.suggestOptimalCipher(1000); // 1Gbps target

    try testing.expect(recommendation.cipher == .aes_256_gcm); // Should recommend AES-GCM with AES-NI
    try testing.expect(recommendation.expected_performance_gain > 1.0);
}
