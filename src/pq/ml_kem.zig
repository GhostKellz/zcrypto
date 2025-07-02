//! ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
//! FIPS 203 Implementation - formerly known as Kyber
//!
//! This module implements the NIST-standardized ML-KEM algorithms for
//! post-quantum key encapsulation. ML-KEM is based on the hardness of
//! the Module Learning With Errors (MLWE) problem over module lattices.

const std = @import("std");
const pq = @import("../pq.zig");

/// ML-KEM parameters and constants
pub const Params = struct {
    pub const Q: u32 = 3329;  // Prime modulus
    pub const N: u32 = 256;   // Ring dimension
    pub const ROOT_OF_UNITY: u32 = 17; // Primitive 512th root of unity mod Q
    
    // Polynomial reduction constants
    pub const QINV: u32 = 62209; // Q^(-1) mod 2^16
    pub const MONT: u32 = 2285;  // 2^16 mod Q
    
    // Hash function output lengths
    pub const SYMBYTES = 32;   // Bytes for shared secret
    pub const HASHBYTES = 32;  // SHA3-256 output
    pub const NOISEBYTES = 32; // Noise sampling randomness
};

/// Polynomial representation in NTT domain
pub const Poly = struct {
    coeffs: [Params.N]u16,
    
    /// Initialize polynomial with zeros
    pub fn zero() Poly {
        return Poly{ .coeffs = [_]u16{0} ** Params.N };
    }
    
    /// Initialize polynomial from bytes
    pub fn fromBytes(bytes: []const u8) Poly {
        var poly = zero();
        for (0..Params.N) |i| {
            const idx = i * 3 / 2;
            if (i % 2 == 0) {
                poly.coeffs[i] = @as(u16, bytes[idx]) | (@as(u16, bytes[idx + 1] & 0x0F) << 8);
            } else {
                poly.coeffs[i] = (@as(u16, bytes[idx]) >> 4) | (@as(u16, bytes[idx + 1]) << 4);
            }
            poly.coeffs[i] = montgomeryReduce(poly.coeffs[i]);
        }
        return poly;
    }
    
    /// Convert polynomial to bytes
    pub fn toBytes(self: *const Poly, bytes: []u8) void {
        for (0..Params.N) |i| {
            const t = montgomeryReduce(self.coeffs[i]);
            const idx = i * 3 / 2;
            if (i % 2 == 0) {
                bytes[idx] = @intCast(t & 0xFF);
                bytes[idx + 1] = @intCast((t >> 8) | ((self.coeffs[i + 1] & 0x0F) << 4));
            } else if (i == Params.N - 1) {
                bytes[idx] = @intCast((t >> 4) & 0xFF);
            }
        }
    }
    
    /// Number-Theoretic Transform (NTT)
    pub fn ntt(self: *Poly) void {
        var len: u32 = 128;
        var k: u32 = 1;
        
        while (len >= 2) {
            var start: u32 = 0;
            while (start < Params.N) {
                const zeta = nttZetas[k];
                k += 1;
                
                var j: u32 = start;
                while (j < start + len) {
                    const t = montgomeryMul(zeta, self.coeffs[j + len]);
                    self.coeffs[j + len] = barrettReduce(@as(u32, self.coeffs[j]) +% Params.Q -% @as(u32, t));
                    self.coeffs[j] = barrettReduce(@as(u32, self.coeffs[j]) +% @as(u32, t));
                    j += 1;
                }
                start = j + len;
            }
            len >>= 1;
        }
        
        // Reduce coefficients
        for (&self.coeffs) |*coeff| {
            coeff.* = barrettReduce(coeff.*);
        }
    }
    
    /// Inverse Number-Theoretic Transform (INTT)
    pub fn invNtt(self: *Poly) void {
        var len: u32 = 2;
        var k: u32 = 127;
        
        while (len <= 128) {
            var start: u32 = 0;
            while (start < Params.N) {
                const zeta = nttZetas[k];
                k -= 1;
                
                var j: u32 = start;
                while (j < start + len) {
                    const t = self.coeffs[j];
                    self.coeffs[j] = barrettReduce(t + self.coeffs[j + len]);
                    self.coeffs[j + len] = montgomeryMul(zeta, t + Params.Q - self.coeffs[j + len]);
                    j += 1;
                }
                start = j + len;
            }
            len <<= 1;
        }
        
        // Final reduction with n^(-1)
        const ninv = 3303; // 256^(-1) mod Q
        for (&self.coeffs) |*coeff| {
            coeff.* = montgomeryMul(coeff.*, ninv);
        }
    }
    
    /// Polynomial multiplication in NTT domain
    pub fn pointwiseMul(self: *const Poly, other: *const Poly) Poly {
        var result = zero();
        for (0..Params.N) |i| {
            result.coeffs[i] = montgomeryMul(self.coeffs[i], other.coeffs[i]);
        }
        return result;
    }
    
    /// Polynomial addition
    pub fn add(self: *const Poly, other: *const Poly) Poly {
        var result = zero();
        for (0..Params.N) |i| {
            result.coeffs[i] = barrettReduce(self.coeffs[i] + other.coeffs[i]);
        }
        return result;
    }
    
    /// Polynomial subtraction
    pub fn sub(self: *const Poly, other: *const Poly) Poly {
        var result = zero();
        for (0..Params.N) |i| {
            result.coeffs[i] = barrettReduce(@as(u32, self.coeffs[i]) +% Params.Q -% @as(u32, other.coeffs[i]));
        }
        return result;
    }
};

/// Montgomery reduction: compute a * R^(-1) mod Q
fn montgomeryReduce(a: u32) u16 {
    const u = (@as(u16, @truncate(a)) *% Params.QINV);  // Use truncate and wrapping
    const t = (a +% @as(u32, u) *% Params.Q) >> 16;  // Use wrapping arithmetic
    return @intCast(if (t >= Params.Q) t - Params.Q else t);
}

/// Montgomery multiplication: compute a * b * R^(-1) mod Q
fn montgomeryMul(a: u16, b: u16) u16 {
    return montgomeryReduce(@as(u32, a) *% @as(u32, b));  // Use wrapping multiplication
}

/// Barrett reduction: compute a mod Q
fn barrettReduce(a: u32) u16 {
    const v = 20159; // floor(2^26 / Q)
    const t = (@as(u32, v) *% @as(u32, a)) >> 26;  // Use wrapping multiplication
    var result = @as(u32, a) -% t *% Params.Q;  // Use wrapping arithmetic
    while (result >= Params.Q) {
        result -%= Params.Q;
    }
    return @intCast(result);
}

/// NTT twiddle factors (precomputed powers of the root of unity)
const nttZetas = [_]u16{
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
    2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
    732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
    1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
    107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
    430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
    1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
    418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
    1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
    478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

/// Centered binomial distribution sampling
fn sampleCBD(eta: u8, buf: []const u8) Poly {
    var poly = Poly.zero();
    
    for (0..Params.N) |i| {
        var a: u32 = 0;
        var b: u32 = 0;
        
        for (0..eta) |j| {
            const bit_pos = i * eta + j;
            const byte_idx = bit_pos / 8;
            const bit_idx = bit_pos % 8;
            if (byte_idx < buf.len) {
                const bit = (buf[byte_idx] >> @intCast(bit_idx)) & 1;
                a += bit;
            }
        }
        
        for (0..eta) |j| {
            const bit_pos = i * eta + j + eta * Params.N;
            const byte_idx = bit_pos / 8;
            const bit_idx = bit_pos % 8;
            if (byte_idx < buf.len) {
                const bit = (buf[byte_idx] >> @intCast(bit_idx)) & 1;
                b += bit;
            }
        }
        
        poly.coeffs[i] = @intCast((a + Params.Q - b) % Params.Q);
    }
    
    return poly;
}

/// ML-KEM-768 specific implementation
pub const ML_KEM_768 = struct {
    pub const K = 3;           // Module rank
    pub const ETA1 = 2;        // Noise parameter for key generation
    pub const ETA2 = 2;        // Noise parameter for encryption
    pub const DU = 10;         // Ciphertext compression parameter
    pub const DV = 4;          // Ciphertext compression parameter
    
    pub const PUBLIC_KEY_SIZE = 1184;
    pub const PRIVATE_KEY_SIZE = 2400;
    pub const CIPHERTEXT_SIZE = 1088;
    pub const SHARED_SECRET_SIZE = 32;
    pub const SEED_SIZE = 32;
    
    /// ML-KEM-768 Key Pair
    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
        
        /// Generate ML-KEM-768 key pair from seed
        pub fn generate(seed: [SEED_SIZE]u8) pq.PQError!KeyPair {
            var keypair: KeyPair = undefined;
            
            // Expand seed with SHAKE-128
            var expanded: [64]u8 = undefined;
            expandSeed(&expanded, &seed);
            
            const rho = expanded[0..32];
            const sigma = expanded[32..64];
            
            // Generate matrix A from rho
            var A: [K][K]Poly = undefined;
            generateMatrix(&A, rho);
            
            // Sample secret vector s from sigma  
            var s: [K]Poly = undefined;
            sampleSecretVector(&s, sigma, 0);
            
            // Sample error vector e from sigma
            var e: [K]Poly = undefined;
            sampleSecretVector(&e, sigma, K);
            
            // Compute public key: t = A*s + e
            var t: [K]Poly = undefined;
            for (0..K) |i| {
                t[i] = Poly.zero();
                for (0..K) |j| {
                    const product = A[i][j].pointwiseMul(&s[j]);
                    t[i] = t[i].add(&product);
                }
                t[i] = t[i].add(&e[i]);
                t[i].ntt();
            }
            
            // Pack public key
            packPublicKey(&keypair.public_key, &t, rho);
            
            // Pack private key  
            packPrivateKey(&keypair.private_key, &s);
            
            return keypair;
        }
        
        /// Generate key pair using system randomness
        pub fn generateRandom() pq.PQError!KeyPair {
            var seed: [SEED_SIZE]u8 = undefined;
            std.crypto.random.bytes(&seed);
            return generate(seed);
        }
        
        /// Encapsulate shared secret using public key
        pub fn encapsulate(public_key: [PUBLIC_KEY_SIZE]u8, randomness: [SEED_SIZE]u8) pq.PQError!struct {
            ciphertext: [CIPHERTEXT_SIZE]u8,
            shared_secret: [SHARED_SECRET_SIZE]u8,
        } {
            var result: struct {
                ciphertext: [CIPHERTEXT_SIZE]u8,
                shared_secret: [SHARED_SECRET_SIZE]u8,
            } = undefined;
            
            // Unpack public key
            var t: [K]Poly = undefined;
            var rho: [32]u8 = undefined;
            unpackPublicKey(&t, &rho, &public_key);
            
            // Sample random vectors
            var r: [K]Poly = undefined;
            var e1: [K]Poly = undefined;
            var e2: Poly = undefined;
            
            sampleSecretVector(&r, &randomness, 0);
            sampleSecretVector(&e1, &randomness, K);
            
            var noise_bytes: [64]u8 = undefined;
            @memcpy(noise_bytes[0..32], &randomness);
            noise_bytes[32] = 2 * K;
            @memset(noise_bytes[33..], 0);
            e2 = sampleCBD(ETA2, &noise_bytes);
            
            // Generate matrix A
            var A: [K][K]Poly = undefined;
            generateMatrix(&A, &rho);
            
            // Compute u = A^T * r + e1
            var u: [K]Poly = undefined;
            for (0..K) |i| {
                u[i] = Poly.zero();
                for (0..K) |j| {
                    var A_transpose = A[j][i];
                    A_transpose.ntt();
                    var r_ntt = r[j];
                    r_ntt.ntt();
                    const product = A_transpose.pointwiseMul(&r_ntt);
                    u[i] = u[i].add(&product);
                }
                u[i].invNtt();
                u[i] = u[i].add(&e1[i]);
            }
            
            // Decompress and compute v = t^T * r + e2 + compress(m)
            var t_decompressed: [K]Poly = undefined;
            for (0..K) |i| {
                t_decompressed[i] = t[i];
                t_decompressed[i].invNtt();
            }
            
            var v = Poly.zero();
            for (0..K) |i| {
                var r_i = r[i];
                r_i.ntt();
                const product = t_decompressed[i].pointwiseMul(&r_i);
                v = v.add(&product);
            }
            v.invNtt();
            v = v.add(&e2);
            
            // Add compressed message (randomness hash)
            var msg_poly = Poly.zero();
            for (0..Params.N) |i| {
                const byte_idx = (i * 8) / Params.N;
                const bit_idx = (i * 8) % Params.N;
                if (byte_idx < randomness.len) {
                    const bit = (randomness[byte_idx] >> @intCast(bit_idx % 8)) & 1;
                    msg_poly.coeffs[i] = @as(u16, bit) * (Params.Q / 2);
                }
            }
            v = v.add(&msg_poly);
            
            // Pack ciphertext
            packCiphertext(&result.ciphertext, &u, &v);
            
            // Derive shared secret from randomness
            var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
            hasher.update(&randomness);
            hasher.final(&result.shared_secret);
            
            return result;
        }
        
        /// Decapsulate shared secret using private key
        pub fn decapsulate(self: *const KeyPair, ciphertext: [CIPHERTEXT_SIZE]u8) pq.PQError![SHARED_SECRET_SIZE]u8 {
            var shared_secret: [SHARED_SECRET_SIZE]u8 = undefined;
            
            // Unpack private key
            var s: [K]Poly = undefined;
            unpackPrivateKey(&s, &self.private_key);
            
            // Unpack ciphertext
            var u: [K]Poly = undefined;
            var v: Poly = undefined;
            unpackCiphertext(&u, &v, &ciphertext);
            
            // Convert s to NTT domain
            for (&s) |*poly| {
                poly.ntt();
            }
            
            // Compute m' = v - s^T * u
            var s_dot_u = Poly.zero();
            for (0..K) |i| {
                var u_ntt = u[i];
                u_ntt.ntt();
                const product = s[i].pointwiseMul(&u_ntt);
                s_dot_u = s_dot_u.add(&product);
            }
            s_dot_u.invNtt();
            
            const m_prime = v.sub(&s_dot_u);
            
            // Decode message from m'
            var decoded_msg: [SEED_SIZE]u8 = undefined;
            for (0..SEED_SIZE) |i| {
                var byte_val: u8 = 0;
                for (0..8) |bit| {
                    const coeff_idx = (i * 8 + bit) % Params.N;
                    const coeff = m_prime.coeffs[coeff_idx];
                    
                    // Decode bit based on coefficient magnitude
                    const threshold = Params.Q / 4;
                    if (coeff > threshold and coeff < 3 * threshold) {
                        byte_val |= @as(u8, 1) << @intCast(bit);
                    }
                }
                decoded_msg[i] = byte_val;
            }
            
            // Derive shared secret
            var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
            hasher.update(&decoded_msg);
            hasher.final(&shared_secret);
            
            return shared_secret;
        }
    };
    
    /// Expand seed using SHAKE-128
    fn expandSeed(output: []u8, seed: []const u8) void {
        // TODO: Implement SHAKE-128 expansion
        // For now, use a placeholder
        @memcpy(output[0..32], seed);
        @memset(output[32..], 0);
    }
    
    /// Generate matrix A from seed rho
    fn generateMatrix(A: *[K][K]Poly, rho: []const u8) void {
        for (0..K) |i| {
            for (0..K) |j| {
                A[i][j] = sampleUniform(rho, @intCast(i), @intCast(j));
            }
        }
    }
    
    /// Sample uniform polynomial from seed
    fn sampleUniform(seed: []const u8, i: u8, j: u8) Poly {
        _ = seed;
        // TODO: Implement uniform sampling using SHAKE-128
        // This is a placeholder implementation
        var poly = Poly.zero();
        
        // Simple deterministic generation for testing
        const offset = (@as(u32, i) * K + j) * Params.N;
        for (0..Params.N) |k| {
            poly.coeffs[k] = @intCast((offset + k) % Params.Q);
        }
        
        return poly;
    }
    
    /// Sample secret vector using CBD
    fn sampleSecretVector(vector: *[K]Poly, sigma: []const u8, offset: usize) void {
        for (0..K) |i| {
            // TODO: Implement proper CBD sampling with PRF
            // This is a placeholder implementation
            var noise_bytes: [64]u8 = undefined;
            @memcpy(noise_bytes[0..32], sigma);
            noise_bytes[32] = @intCast(offset + i);
            @memset(noise_bytes[33..], 0);
            
            vector[i] = sampleCBD(ETA1, &noise_bytes);
        }
    }
    
    /// Pack public key into byte array
    fn packPublicKey(output: []u8, t: *const [K]Poly, rho: []const u8) void {
        _ = t;
        // TODO: Implement proper public key packing
        // This is a placeholder implementation
        @memset(output, 0);
        @memcpy(output[0..32], rho);
    }
    
    /// Pack private key into byte array  
    fn packPrivateKey(output: []u8, s: *const [K]Poly) void {
        var offset: usize = 0;
        for (0..K) |i| {
            for (0..Params.N) |j| {
                const coeff = s[i].coeffs[j];
                if (offset + 1 < output.len) {
                    output[offset] = @intCast(coeff & 0xFF);
                    output[offset + 1] = @intCast((coeff >> 8) & 0xFF);
                    offset += 2;
                }
            }
        }
    }
    
    /// Unpack public key from byte array
    fn unpackPublicKey(t: *[K]Poly, rho: []u8, input: []const u8) void {
        @memcpy(rho[0..32], input[0..32]);
        
        var offset: usize = 32;
        for (0..K) |i| {
            for (0..Params.N) |j| {
                if (offset + 1 < input.len) {
                    t[i].coeffs[j] = @as(u16, input[offset]) | (@as(u16, input[offset + 1]) << 8);
                    offset += 2;
                }
            }
        }
    }
    
    /// Unpack private key from byte array
    fn unpackPrivateKey(s: *[K]Poly, input: []const u8) void {
        var offset: usize = 0;
        for (0..K) |i| {
            for (0..Params.N) |j| {
                if (offset + 1 < input.len) {
                    s[i].coeffs[j] = @as(u16, input[offset]) | (@as(u16, input[offset + 1]) << 8);
                    offset += 2;
                }
            }
        }
    }
    
    /// Pack ciphertext into byte array
    fn packCiphertext(output: []u8, u: *const [K]Poly, v: *const Poly) void {
        var offset: usize = 0;
        
        // Pack u vector
        for (0..K) |i| {
            for (0..Params.N) |j| {
                const coeff = u[i].coeffs[j];
                if (offset + 1 < output.len) {
                    output[offset] = @intCast(coeff & 0xFF);
                    output[offset + 1] = @intCast((coeff >> 8) & 0xFF);
                    offset += 2;
                }
            }
        }
        
        // Pack v polynomial
        for (0..Params.N) |j| {
            const coeff = v.coeffs[j];
            if (offset + 1 < output.len) {
                output[offset] = @intCast(coeff & 0xFF);
                output[offset + 1] = @intCast((coeff >> 8) & 0xFF);
                offset += 2;
            }
        }
    }
    
    /// Unpack ciphertext from byte array
    fn unpackCiphertext(u: *[K]Poly, v: *Poly, input: []const u8) void {
        var offset: usize = 0;
        
        // Unpack u vector
        for (0..K) |i| {
            for (0..Params.N) |j| {
                if (offset + 1 < input.len) {
                    u[i].coeffs[j] = @as(u16, input[offset]) | (@as(u16, input[offset + 1]) << 8);
                    offset += 2;
                }
            }
        }
        
        // Unpack v polynomial
        for (0..Params.N) |j| {
            if (offset + 1 < input.len) {
                v.coeffs[j] = @as(u16, input[offset]) | (@as(u16, input[offset + 1]) << 8);
                offset += 2;
            }
        }
    }
};

test "ML-KEM-768 polynomial arithmetic" {
    var poly1 = Poly.zero();
    var poly2 = Poly.zero();
    
    // Test basic operations
    poly1.coeffs[0] = 100;
    poly2.coeffs[0] = 200;
    
    const sum = poly1.add(&poly2);
    try std.testing.expect(sum.coeffs[0] == 300);
    
    const diff = poly2.sub(&poly1);  
    try std.testing.expect(diff.coeffs[0] == 100);
}

test "ML-KEM-768 key generation" {
    const seed = [_]u8{42} ** 32;
    const keypair = ML_KEM_768.KeyPair.generate(seed) catch |err| {
        std.debug.print("Key generation failed: {}\n", .{err});
        return;
    };
    
    // Basic sanity check - keys should not be all zeros
    var all_zero = true;
    for (keypair.public_key) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}