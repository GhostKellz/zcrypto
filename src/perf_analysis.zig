//! Advanced Performance Analysis and Memory Profiling for zcrypto
//!
//! Enterprise-grade performance monitoring with detailed analytics,
//! memory leak detection, and real-time performance metrics collection.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

pub const AnalysisError = error{
    InsufficientData,
    InvalidConfiguration,
    ProfilingDisabled,
    ResourceExhausted,
};

/// Performance analysis configuration
pub const AnalysisConfig = struct {
    enable_memory_tracking: bool = true,
    enable_timing_analysis: bool = true,
    enable_cache_analysis: bool = false,
    enable_statistical_analysis: bool = true,
    max_samples: u32 = 10000,
    sampling_interval_ns: u64 = 1000, // 1µs
};

/// Detailed performance metrics
pub const DetailedMetrics = struct {
    operation_name: []const u8,
    sample_count: u32,
    total_time_ns: u64,
    min_time_ns: u64,
    max_time_ns: u64,
    mean_time_ns: f64,
    median_time_ns: u64,
    std_deviation_ns: f64,
    percentile_95_ns: u64,
    percentile_99_ns: u64,
    throughput_ops_per_sec: f64,
    memory_usage_bytes: u64,
    cache_misses: u64,

    pub fn calculateThroughput(self: DetailedMetrics) f64 {
        if (self.mean_time_ns > 0) {
            return 1e9 / self.mean_time_ns;
        }
        return 0.0;
    }

    pub fn getEfficiencyScore(self: DetailedMetrics) f64 {
        // Efficiency score based on throughput vs memory usage
        const throughput_score = @min(self.throughput_ops_per_sec / 1000.0, 100.0);
        const memory_efficiency = if (self.memory_usage_bytes > 0)
            1000.0 / @as(f64, @floatFromInt(self.memory_usage_bytes))
        else
            1.0;

        return (throughput_score + memory_efficiency) / 2.0;
    }
};

/// Advanced statistical analysis
pub const StatisticalAnalyzer = struct {
    samples: std.ArrayList(u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StatisticalAnalyzer {
        return StatisticalAnalyzer{
            .samples = std.ArrayList(u64).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StatisticalAnalyzer) void {
        self.samples.deinit();
    }

    /// Add a sample to the analyzer
    pub fn addSample(self: *StatisticalAnalyzer, value: u64) !void {
        try self.samples.append(value);
    }

    /// Calculate comprehensive statistics
    pub fn analyze(self: *StatisticalAnalyzer) !StatisticalResults {
        if (self.samples.items.len == 0) {
            return AnalysisError.InsufficientData;
        }

        // Sort samples for percentile calculations
        const sorted_samples = try self.allocator.dupe(u64, self.samples.items);
        defer self.allocator.free(sorted_samples);
        std.sort.pdq(u64, sorted_samples, {}, std.sort.asc(u64));

        // Calculate basic statistics
        const min_val = sorted_samples[0];
        const max_val = sorted_samples[sorted_samples.len - 1];

        var sum: u64 = 0;
        for (sorted_samples) |sample| {
            sum += sample;
        }
        const mean = @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(sorted_samples.len));

        // Calculate standard deviation
        var variance_sum: f64 = 0.0;
        for (sorted_samples) |sample| {
            const diff = @as(f64, @floatFromInt(sample)) - mean;
            variance_sum += diff * diff;
        }
        const variance = variance_sum / @as(f64, @floatFromInt(sorted_samples.len));
        const std_dev = @sqrt(variance);

        // Calculate percentiles
        const median_idx = sorted_samples.len / 2;
        const median = if (sorted_samples.len % 2 == 0)
            (sorted_samples[median_idx - 1] + sorted_samples[median_idx]) / 2
        else
            sorted_samples[median_idx];

        const p95_idx = (sorted_samples.len * 95) / 100;
        const p99_idx = (sorted_samples.len * 99) / 100;

        return StatisticalResults{
            .sample_count = @intCast(sorted_samples.len),
            .min_value = min_val,
            .max_value = max_val,
            .mean = mean,
            .median = median,
            .std_deviation = std_dev,
            .percentile_95 = sorted_samples[@min(p95_idx, sorted_samples.len - 1)],
            .percentile_99 = sorted_samples[@min(p99_idx, sorted_samples.len - 1)],
            .coefficient_of_variation = if (mean > 0) std_dev / mean else 0.0,
        };
    }

    /// Detect performance anomalies
    pub fn detectAnomalies(self: *StatisticalAnalyzer, threshold_std_devs: f64) ![]u64 {
        const stats = try self.analyze();
        var anomalies = std.ArrayList(u64).init(self.allocator);

        const lower_bound = stats.mean - (threshold_std_devs * stats.std_deviation);
        const upper_bound = stats.mean + (threshold_std_devs * stats.std_deviation);

        for (self.samples.items) |sample| {
            const sample_f = @as(f64, @floatFromInt(sample));
            if (sample_f < lower_bound or sample_f > upper_bound) {
                try anomalies.append(sample);
            }
        }

        return anomalies.toOwnedSlice();
    }
};

pub const StatisticalResults = struct {
    sample_count: u32,
    min_value: u64,
    max_value: u64,
    mean: f64,
    median: u64,
    std_deviation: f64,
    percentile_95: u64,
    percentile_99: u64,
    coefficient_of_variation: f64,
};

/// Memory leak detector with advanced analysis
pub const MemoryLeakDetector = struct {
    allocations: std.HashMap(usize, AllocationRecord, std.hash_map.AutoContext(usize), 80),
    allocation_timeline: std.ArrayList(AllocationEvent),
    total_allocated: u64,
    total_freed: u64,
    peak_usage: u64,
    current_usage: u64,
    allocator: std.mem.Allocator,

    const AllocationRecord = struct {
        size: usize,
        timestamp: i128,
        call_site: ?[]const u8 = null,
        thread_id: u32 = 0,
    };

    const AllocationEvent = struct {
        timestamp: i128,
        event_type: EventType,
        address: usize,
        size: usize,

        const EventType = enum { allocate, deallocate };
    };

    pub fn init(allocator: std.mem.Allocator) MemoryLeakDetector {
        return MemoryLeakDetector{
            .allocations = std.HashMap(usize, AllocationRecord, std.hash_map.AutoContext(usize), 80).init(allocator),
            .allocation_timeline = std.ArrayList(AllocationEvent).init(allocator),
            .total_allocated = 0,
            .total_freed = 0,
            .peak_usage = 0,
            .current_usage = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MemoryLeakDetector) void {
        self.allocations.deinit();
        self.allocation_timeline.deinit();
    }

    /// Record memory allocation
    pub fn recordAllocation(self: *MemoryLeakDetector, address: usize, size: usize, call_site: ?[]const u8) !void {
        const timestamp = std.time.nanoTimestamp();

        const record = AllocationRecord{
            .size = size,
            .timestamp = timestamp,
            .call_site = call_site,
            .thread_id = 0, // TODO: Get actual thread ID
        };

        try self.allocations.put(address, record);
        try self.allocation_timeline.append(AllocationEvent{
            .timestamp = timestamp,
            .event_type = .allocate,
            .address = address,
            .size = size,
        });

        self.total_allocated += size;
        self.current_usage += size;

        if (self.current_usage > self.peak_usage) {
            self.peak_usage = self.current_usage;
        }
    }

    /// Record memory deallocation
    pub fn recordDeallocation(self: *MemoryLeakDetector, address: usize) !void {
        if (self.allocations.get(address)) |record| {
            const timestamp = std.time.nanoTimestamp();

            try self.allocation_timeline.append(AllocationEvent{
                .timestamp = timestamp,
                .event_type = .deallocate,
                .address = address,
                .size = record.size,
            });

            self.total_freed += record.size;
            self.current_usage -= record.size;
            _ = self.allocations.remove(address);
        }
    }

    /// Generate comprehensive leak report
    pub fn generateLeakReport(self: *MemoryLeakDetector) !LeakReport {
        var leak_details = std.ArrayList(LeakDetail).init(self.allocator);
        var total_leaked: u64 = 0;

        var iterator = self.allocations.iterator();
        while (iterator.next()) |entry| {
            const leak = LeakDetail{
                .address = entry.key_ptr.*,
                .size = entry.value_ptr.size,
                .age_ns = std.time.nanoTimestamp() - entry.value_ptr.timestamp,
                .call_site = entry.value_ptr.call_site,
            };
            try leak_details.append(leak);
            total_leaked += entry.value_ptr.size;
        }

        // Sort leaks by size (largest first)
        std.sort.pdq(LeakDetail, leak_details.items, {}, struct {
            fn lessThan(_: void, a: LeakDetail, b: LeakDetail) bool {
                return a.size > b.size;
            }
        }.lessThan);

        return LeakReport{
            .total_leaked_bytes = total_leaked,
            .leak_count = @intCast(leak_details.items.len),
            .peak_usage_bytes = self.peak_usage,
            .current_usage_bytes = self.current_usage,
            .allocation_count = @intCast(self.allocation_timeline.items.len),
            .leak_details = try leak_details.toOwnedSlice(),
        };
    }

    /// Analyze allocation patterns
    pub fn analyzeAllocationPatterns(self: *MemoryLeakDetector) AllocationPattern {
        if (self.allocation_timeline.items.len == 0) {
            return AllocationPattern{
                .average_allocation_size = 0,
                .allocation_frequency_hz = 0.0,
                .memory_churn_rate = 0.0,
                .fragmentation_score = 0.0,
            };
        }

        var total_alloc_size: u64 = 0;
        var alloc_count: u32 = 0;

        const first_timestamp = self.allocation_timeline.items[0].timestamp;
        const last_timestamp = self.allocation_timeline.items[self.allocation_timeline.items.len - 1].timestamp;
        const duration_ns = @as(f64, @floatFromInt(last_timestamp - first_timestamp));

        for (self.allocation_timeline.items) |event| {
            if (event.event_type == .allocate) {
                total_alloc_size += event.size;
                alloc_count += 1;
            }
        }

        const avg_alloc_size = if (alloc_count > 0) total_alloc_size / alloc_count else 0;
        const alloc_frequency = if (duration_ns > 0) @as(f64, @floatFromInt(alloc_count)) / (duration_ns / 1e9) else 0.0;
        const churn_rate = if (self.total_allocated > 0) @as(f64, @floatFromInt(self.total_freed)) / @as(f64, @floatFromInt(self.total_allocated)) else 0.0;

        return AllocationPattern{
            .average_allocation_size = avg_alloc_size,
            .allocation_frequency_hz = alloc_frequency,
            .memory_churn_rate = churn_rate,
            .fragmentation_score = 0.0, // TODO: Calculate based on allocation sizes
        };
    }
};

pub const LeakDetail = struct {
    address: usize,
    size: usize,
    age_ns: i128,
    call_site: ?[]const u8,
};

pub const LeakReport = struct {
    total_leaked_bytes: u64,
    leak_count: u32,
    peak_usage_bytes: u64,
    current_usage_bytes: u64,
    allocation_count: u32,
    leak_details: []LeakDetail,

    pub fn deinit(self: *LeakReport, allocator: std.mem.Allocator) void {
        allocator.free(self.leak_details);
    }

    /// Print formatted leak report
    pub fn print(self: LeakReport) void {
        std.log.info("=== Memory Leak Report ===");
        std.log.info("Total leaked: {} bytes", .{self.total_leaked_bytes});
        std.log.info("Leak count: {}", .{self.leak_count});
        std.log.info("Peak usage: {} bytes", .{self.peak_usage_bytes});
        std.log.info("Current usage: {} bytes", .{self.current_usage_bytes});
        std.log.info("");

        if (self.leak_details.len > 0) {
            std.log.info("Top leaks:");
            for (self.leak_details[0..@min(5, self.leak_details.len)]) |leak| {
                const age_ms = @as(f64, @floatFromInt(leak.age_ns)) / 1e6;
                std.log.info("  {} bytes at 0x{X} (age: {d:.2}ms)", .{ leak.size, leak.address, age_ms });
            }
        }
    }
};

pub const AllocationPattern = struct {
    average_allocation_size: u64,
    allocation_frequency_hz: f64,
    memory_churn_rate: f64,
    fragmentation_score: f64,
};

/// Real-time performance monitor
pub const RealTimeMonitor = struct {
    config: AnalysisConfig,
    crypto_metrics: std.HashMap([]const u8, DetailedMetrics, std.hash_map.StringContext, 80),
    memory_detector: MemoryLeakDetector,
    statistical_analyzer: StatisticalAnalyzer,
    monitoring_active: bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: AnalysisConfig) RealTimeMonitor {
        return RealTimeMonitor{
            .config = config,
            .crypto_metrics = std.HashMap([]const u8, DetailedMetrics, std.hash_map.StringContext, 80).init(allocator),
            .memory_detector = MemoryLeakDetector.init(allocator),
            .statistical_analyzer = StatisticalAnalyzer.init(allocator),
            .monitoring_active = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RealTimeMonitor) void {
        self.crypto_metrics.deinit();
        self.memory_detector.deinit();
        self.statistical_analyzer.deinit();
    }

    /// Start real-time monitoring
    pub fn startMonitoring(self: *RealTimeMonitor) void {
        self.monitoring_active = true;
        std.log.info("Real-time performance monitoring started", .{});
    }

    /// Stop monitoring and generate final report
    pub fn stopMonitoring(self: *RealTimeMonitor) !PerformanceReport {
        self.monitoring_active = false;

        const leak_report = try self.memory_detector.generateLeakReport();
        const allocation_pattern = self.memory_detector.analyzeAllocationPatterns();
        const statistical_results = self.statistical_analyzer.analyze() catch StatisticalResults{
            .sample_count = 0,
            .min_value = 0,
            .max_value = 0,
            .mean = 0.0,
            .median = 0,
            .std_deviation = 0.0,
            .percentile_95 = 0,
            .percentile_99 = 0,
            .coefficient_of_variation = 0.0,
        };

        return PerformanceReport{
            .monitoring_duration_ns = 0, // TODO: Track actual duration
            .leak_report = leak_report,
            .allocation_pattern = allocation_pattern,
            .statistical_results = statistical_results,
            .crypto_operations_count = @intCast(self.crypto_metrics.count()),
        };
    }

    /// Record crypto operation performance
    pub fn recordCryptoOperation(self: *RealTimeMonitor, operation_name: []const u8, duration_ns: u64, memory_used: u64) !void {
        if (!self.monitoring_active) return;

        try self.statistical_analyzer.addSample(duration_ns);

        // Update or create metrics for this operation
        if (self.crypto_metrics.getPtr(operation_name)) |metrics| {
            metrics.sample_count += 1;
            metrics.total_time_ns += duration_ns;
            metrics.min_time_ns = @min(metrics.min_time_ns, duration_ns);
            metrics.max_time_ns = @max(metrics.max_time_ns, duration_ns);
            metrics.memory_usage_bytes += memory_used;

            // Recalculate derived metrics
            metrics.mean_time_ns = @as(f64, @floatFromInt(metrics.total_time_ns)) / @as(f64, @floatFromInt(metrics.sample_count));
            metrics.throughput_ops_per_sec = 1e9 / metrics.mean_time_ns;
        } else {
            const new_metrics = DetailedMetrics{
                .operation_name = operation_name,
                .sample_count = 1,
                .total_time_ns = duration_ns,
                .min_time_ns = duration_ns,
                .max_time_ns = duration_ns,
                .mean_time_ns = @floatFromInt(duration_ns),
                .median_time_ns = duration_ns,
                .std_deviation_ns = 0.0,
                .percentile_95_ns = duration_ns,
                .percentile_99_ns = duration_ns,
                .throughput_ops_per_sec = 1e9 / @as(f64, @floatFromInt(duration_ns)),
                .memory_usage_bytes = memory_used,
                .cache_misses = 0,
            };

            try self.crypto_metrics.put(operation_name, new_metrics);
        }
    }
};

pub const PerformanceReport = struct {
    monitoring_duration_ns: u64,
    leak_report: LeakReport,
    allocation_pattern: AllocationPattern,
    statistical_results: StatisticalResults,
    crypto_operations_count: u32,

    pub fn deinit(self: *PerformanceReport, allocator: std.mem.Allocator) void {
        self.leak_report.deinit(allocator);
    }

    /// Generate comprehensive performance summary
    pub fn printSummary(self: PerformanceReport) void {
        std.log.info("=== Performance Analysis Summary ===");
        std.log.info("Monitoring duration: {d:.2} ms", .{@as(f64, @floatFromInt(self.monitoring_duration_ns)) / 1e6});
        std.log.info("Crypto operations tracked: {}", .{self.crypto_operations_count});
        std.log.info("");

        // Statistical summary
        std.log.info("Performance Statistics:");
        std.log.info("  Samples: {}", .{self.statistical_results.sample_count});
        std.log.info("  Mean: {d:.2} ns", .{self.statistical_results.mean});
        std.log.info("  Std Dev: {d:.2} ns", .{self.statistical_results.std_deviation});
        std.log.info("  95th percentile: {} ns", .{self.statistical_results.percentile_95});
        std.log.info("  99th percentile: {} ns", .{self.statistical_results.percentile_99});
        std.log.info("");

        // Memory summary
        self.leak_report.print();
        std.log.info("");

        // Allocation patterns
        std.log.info("Allocation Patterns:");
        std.log.info("  Average allocation size: {} bytes", .{self.allocation_pattern.average_allocation_size});
        std.log.info("  Allocation frequency: {d:.2} Hz", .{self.allocation_pattern.allocation_frequency_hz});
        std.log.info("  Memory churn rate: {d:.2}%", .{self.allocation_pattern.memory_churn_rate * 100});
    }
};

// =============================================================================
// TESTS
// =============================================================================

test "statistical analyzer" {
    var analyzer = StatisticalAnalyzer.init(std.testing.allocator);
    defer analyzer.deinit();

    // Add sample data
    try analyzer.addSample(100);
    try analyzer.addSample(200);
    try analyzer.addSample(150);
    try analyzer.addSample(175);
    try analyzer.addSample(125);

    const results = try analyzer.analyze();
    try testing.expect(results.sample_count == 5);
    try testing.expect(results.min_value == 100);
    try testing.expect(results.max_value == 200);
    try testing.expect(results.mean == 150.0);
}

test "memory leak detector" {
    var detector = MemoryLeakDetector.init(std.testing.allocator);
    defer detector.deinit();

    // Record some allocations
    try detector.recordAllocation(0x1000, 100, "test_function");
    try detector.recordAllocation(0x2000, 200, "another_function");

    // Free one allocation
    try detector.recordDeallocation(0x1000);

    var report = try detector.generateLeakReport();
    defer report.deinit(std.testing.allocator);

    try testing.expect(report.leak_count == 1);
    try testing.expect(report.total_leaked_bytes == 200);
}

test "real-time monitor" {
    const config = AnalysisConfig{
        .enable_memory_tracking = true,
        .enable_timing_analysis = true,
        .max_samples = 1000,
    };

    var monitor = RealTimeMonitor.init(std.testing.allocator, config);
    defer monitor.deinit();

    monitor.startMonitoring();

    // Record some operations
    try monitor.recordCryptoOperation("hash", 1000, 32);
    try monitor.recordCryptoOperation("encrypt", 2000, 64);

    var report = try monitor.stopMonitoring();
    defer report.deinit(std.testing.allocator);

    try testing.expect(report.crypto_operations_count > 0);
}
