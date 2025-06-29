# 🔗 ZCRYPTO v0.5.0 INTEGRATION GUIDE

**Complete Integration Guide for GhostChain Services and External Projects**

---

## 📋 **TABLE OF CONTENTS**

1. [Quick Start Integration](#quick-start-integration)
2. [GhostChain Services Integration](#ghostchain-services-integration)
3. [Rust Project Integration](#rust-project-integration)
4. [C/C++ Project Integration](#cc-project-integration)
5. [Build System Integration](#build-system-integration)
6. [Performance Optimization](#performance-optimization)
7. [Security Considerations](#security-considerations)
8. [Testing and Validation](#testing-and-validation)
9. [Migration Strategies](#migration-strategies)
10. [Troubleshooting](#troubleshooting)

---

## ⚡ **QUICK START INTEGRATION**

### **1. Basic Setup**

```bash
# Clone zcrypto
git clone https://github.com/GhostChain/zcrypto.git
cd zcrypto

# Build the library
zig build -Doptimize=ReleaseFast

# Generate C headers for FFI
zig build generate-headers

# Run tests to verify installation
zig test src/root.zig
```

### **2. Basic Usage Example**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    // Hash a message
    const message = "Hello, Post-Quantum World!";
    const hash = zcrypto.hash.sha256(message);
    std.debug.print("SHA-256: {x}\n", .{hash});
    
    // Generate post-quantum keys
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    
    const ml_kem_keypair = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.generate(seed);
    std.debug.print("ML-KEM-768 public key generated successfully\n");
    
    // Hybrid key exchange
    var shared_secret: [64]u8 = undefined;
    try zcrypto.pq.hybrid.x25519_ml_kem_768_kex(
        &shared_secret,
        &classical_share,
        &pq_share,
        entropy
    );
    std.debug.print("Hybrid key exchange completed\n");
}
```

---

## 🏗️ **GHOSTCHAIN SERVICES INTEGRATION**

### **🌉 ghostbridge (gRPC Relay over QUIC)**

#### **Integration Requirements**
- Post-quantum QUIC handshake for relay connections
- High-throughput packet encryption/decryption
- Hybrid classical+PQ security during migration

#### **Key Components**
```rust
// Cargo.toml
[dependencies]
zcrypto-sys = { path = "../zcrypto/bindings/rust" }
tokio = "1.0"
quinn = "0.10"

// src/crypto.rs
use zcrypto_sys::*;

pub struct PQQuicCrypto {
    classical_keys: [u8; 32],
    pq_keys: [u8; 800],
    shared_secret: [u8; 64],
}

impl PQQuicCrypto {
    pub fn new() -> Result<Self, CryptoError> {
        let mut classical_share = [0u8; 32];
        let mut pq_share = [0u8; 800];
        let entropy = generate_entropy();
        
        let result = unsafe {
            zcrypto_quic_pq_keygen(
                classical_share.as_mut_ptr(),
                pq_share.as_mut_ptr(),
                entropy.as_ptr(),
            )
        };
        
        if result.success {
            Ok(Self {
                classical_keys: classical_share,
                pq_keys: pq_share,
                shared_secret: [0u8; 64],
            })
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
    
    pub fn encrypt_packet(&self, packet: &mut [u8], header_len: usize) -> Result<(), CryptoError> {
        let result = unsafe {
            zcrypto_quic_encrypt_packet_inplace(
                packet.as_mut_ptr(),
                packet.len() as u32,
                header_len as u32,
                self.packet_number,
                self.shared_secret.as_ptr(),
            )
        };
        
        if result.success {
            Ok(())
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
}

// Integration with Quinn QUIC
pub struct PQQuicEndpoint {
    crypto: PQQuicCrypto,
    endpoint: quinn::Endpoint,
}

impl PQQuicEndpoint {
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<Connection, Error> {
        // Use zcrypto for post-quantum handshake
        let connection = self.endpoint.connect(addr, "server_name")?
            .await?;
        
        // Upgrade to post-quantum crypto
        self.upgrade_to_pq_crypto(&connection).await?;
        
        Ok(connection)
    }
    
    async fn upgrade_to_pq_crypto(&mut self, conn: &Connection) -> Result<(), Error> {
        // Perform post-quantum key exchange
        let pq_handshake_msg = self.create_pq_handshake()?;
        conn.send_datagram(pq_handshake_msg.into())?;
        
        // Process response and derive shared secret
        let response = conn.read_datagram().await?;
        self.process_pq_response(&response)?;
        
        Ok(())
    }
}
```

#### **Configuration**
```toml
# ghostbridge.toml
[crypto]
enabled_cipher_suites = [
    "TLS_ML_KEM_768_X25519_AES256_GCM_SHA384",
    "TLS_AES_256_GCM_SHA384",  # Fallback
]
enable_0rtt = true
pq_key_update_interval = 3600  # 1 hour
hybrid_mode_required = true

[performance]
max_concurrent_connections = 10000
packet_buffer_size = 65536
enable_batch_processing = true
```

### **⛓️ ghostd (Blockchain Daemon)**

#### **Integration Requirements**
- Post-quantum digital signatures for transactions
- Hybrid consensus mechanisms
- Zero-knowledge proof verification

#### **Key Components**
```rust
// src/consensus/pq_signatures.rs
use zcrypto_sys::*;

pub struct PQValidator {
    classical_keypair: Ed25519KeyPair,
    pq_keypair: MLDSAKeyPair,
}

impl PQValidator {
    pub fn generate_keys() -> Result<Self, CryptoError> {
        let mut classical_public = [0u8; 32];
        let mut classical_private = [0u8; 64];
        let mut pq_public = [0u8; 1952];
        let mut pq_private = [0u8; 4032];
        
        // Generate classical keys
        let result = unsafe {
            zcrypto_ed25519_keygen(
                classical_public.as_mut_ptr(),
                classical_private.as_mut_ptr(),
            )
        };
        require_success(result)?;
        
        // Generate post-quantum keys
        let result = unsafe {
            zcrypto_ml_dsa_65_keygen(
                pq_public.as_mut_ptr(),
                pq_private.as_mut_ptr(),
            )
        };
        require_success(result)?;
        
        Ok(Self {
            classical_keypair: Ed25519KeyPair {
                public_key: classical_public,
                private_key: classical_private,
            },
            pq_keypair: MLDSAKeyPair {
                public_key: pq_public,
                private_key: pq_private,
            },
        })
    }
    
    pub fn sign_block(&self, block: &Block) -> Result<HybridSignature, CryptoError> {
        let block_hash = block.hash();
        
        // Classical signature
        let mut classical_sig = [0u8; 64];
        let result = unsafe {
            zcrypto_ed25519_sign(
                block_hash.as_ptr(),
                block_hash.len() as u32,
                self.classical_keypair.private_key.as_ptr(),
                classical_sig.as_mut_ptr(),
            )
        };
        require_success(result)?;
        
        // Post-quantum signature
        let mut pq_sig = [0u8; 3309];
        let result = unsafe {
            zcrypto_ml_dsa_65_sign(
                block_hash.as_ptr(),
                block_hash.len() as u32,
                self.pq_keypair.private_key.as_ptr(),
                pq_sig.as_mut_ptr(),
            )
        };
        require_success(result)?;
        
        Ok(HybridSignature {
            classical_signature: classical_sig,
            pq_signature: pq_sig,
        })
    }
    
    pub fn verify_block(&self, block: &Block, signature: &HybridSignature) -> Result<bool, CryptoError> {
        let block_hash = block.hash();
        
        // Verify classical signature
        let classical_valid = unsafe {
            zcrypto_ed25519_verify(
                block_hash.as_ptr(),
                block_hash.len() as u32,
                signature.classical_signature.as_ptr(),
                self.classical_keypair.public_key.as_ptr(),
            )
        };
        
        // Verify post-quantum signature
        let pq_result = unsafe {
            zcrypto_ml_dsa_65_verify(
                block_hash.as_ptr(),
                block_hash.len() as u32,
                signature.pq_signature.as_ptr(),
                self.pq_keypair.public_key.as_ptr(),
            )
        };
        
        // Both signatures must be valid
        Ok(classical_valid.success && pq_result.success)
    }
}

// Consensus integration
pub struct PQConsensus {
    validators: Vec<PQValidator>,
    threshold: usize,
}

impl PQConsensus {
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<bool, Error> {
        // Verify transaction signatures using hybrid crypto
        let tx_hash = tx.hash();
        
        let mut valid_signatures = 0;
        for validator in &self.validators {
            if validator.verify_transaction(tx)? {
                valid_signatures += 1;
            }
        }
        
        Ok(valid_signatures >= self.threshold)
    }
}
```

#### **Configuration**
```toml
# ghostd.toml
[consensus]
signature_algorithm = "hybrid_ed25519_ml_dsa_65"
min_validators = 7
consensus_threshold = 5
enable_pq_transition = true

[blockchain]
block_time = 10  # seconds
max_block_size = 2097152  # 2MB
enable_zkp_verification = true

[crypto]
preferred_hash = "sha3_256"
enable_post_quantum = true
migration_mode = "hybrid"
```

### **💰 walletd (Wallet Microservice)**

#### **Integration Requirements**
- Zero-knowledge proof generation for privacy
- Post-quantum key management
- Secure transaction signing

#### **Key Components**
```rust
// src/wallet/zkp.rs
use zcrypto_sys::*;

pub struct PrivacyWallet {
    spending_key: [u8; 32],
    viewing_key: [u8; 64],
    nullifier_key: [u8; 32],
}

impl PrivacyWallet {
    pub fn generate_range_proof(&self, amount: u64, blinding: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let mut proof = vec![0u8; 1024]; // Max proof size
        let mut proof_len = 1024u32;
        
        let result = unsafe {
            zcrypto_bulletproof_prove_range(
                amount,
                blinding.as_ptr(),
                0,     // min value
                u64::MAX, // max value (private)
                proof.as_mut_ptr(),
                &mut proof_len,
            )
        };
        
        if result.success {
            proof.truncate(proof_len as usize);
            Ok(proof)
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
    
    pub fn verify_range_proof(&self, commitment: &[u8], proof: &[u8]) -> Result<bool, CryptoError> {
        let result = unsafe {
            zcrypto_bulletproof_verify_range(
                commitment.as_ptr(),
                proof.as_ptr(),
                proof.len() as u32,
                0,        // min value
                u64::MAX, // max value
            )
        };
        
        Ok(result.success)
    }
    
    pub fn create_private_transaction(&self, amount: u64, recipient: &PublicKey) -> Result<PrivateTransaction, Error> {
        // Generate blinding factor
        let mut blinding = [0u8; 32];
        generate_random_bytes(&mut blinding);
        
        // Create Pedersen commitment
        let commitment = self.create_commitment(amount, &blinding)?;
        
        // Generate range proof
        let range_proof = self.generate_range_proof(amount, &blinding)?;
        
        // Create nullifier to prevent double-spending
        let nullifier = self.create_nullifier(&commitment)?;
        
        Ok(PrivateTransaction {
            commitment,
            range_proof,
            nullifier,
            encrypted_amount: self.encrypt_amount(amount, recipient)?,
        })
    }
}

// Post-quantum key derivation
pub struct PQKeyDerivation {
    master_seed: [u8; 64],
}

impl PQKeyDerivation {
    pub fn derive_spending_key(&self, account: u32, index: u32) -> Result<[u8; 32], CryptoError> {
        let derivation_path = format!("m/44'/1'/{}'/0/{}", account, index);
        
        let mut derived_key = [0u8; 32];
        let result = unsafe {
            zcrypto_kdf_derive_key(
                self.master_seed.as_ptr(),
                self.master_seed.len() as u32,
                derivation_path.as_ptr(),
                derivation_path.len() as u32,
                derived_key.as_mut_ptr(),
                derived_key.len() as u32,
            )
        };
        
        if result.success {
            Ok(derived_key)
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
    
    pub fn derive_pq_keypair(&self, account: u32) -> Result<MLKEMKeyPair, CryptoError> {
        let seed = self.derive_spending_key(account, 0)?;
        
        let mut public_key = [0u8; 1184];
        let mut secret_key = [0u8; 2400];
        
        let result = unsafe {
            zcrypto_ml_kem_768_keygen_from_seed(
                seed.as_ptr(),
                public_key.as_mut_ptr(),
                secret_key.as_mut_ptr(),
            )
        };
        
        if result.success {
            Ok(MLKEMKeyPair {
                public_key,
                secret_key,
            })
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
}
```

#### **Configuration**
```toml
# walletd.toml
[privacy]
enable_zkp_transactions = true
default_proof_system = "bulletproofs"
enable_groth16 = true
max_proof_size = 2048

[keys]
derivation_standard = "bip44_pq"
enable_post_quantum_keys = true
key_rotation_interval = 86400  # 24 hours

[security]
require_hardware_backing = false
enable_secure_enclave = true
constant_time_verification = true
```

### **👻 wraith (QUIC Proxy)**

#### **Integration Requirements**
- High-performance packet processing
- Post-quantum connection upgrades
- Zero-latency crypto operations

#### **Key Components**
```rust
// src/proxy/pq_tunnel.rs
use zcrypto_sys::*;

pub struct PQTunnel {
    upstream_crypto: PQQuicCrypto,
    downstream_crypto: PQQuicCrypto,
    packet_buffer: Vec<u8>,
}

impl PQTunnel {
    pub fn new(upstream_config: &TunnelConfig, downstream_config: &TunnelConfig) -> Result<Self, Error> {
        Ok(Self {
            upstream_crypto: PQQuicCrypto::new_with_config(upstream_config)?,
            downstream_crypto: PQQuicCrypto::new_with_config(downstream_config)?,
            packet_buffer: vec![0u8; 65536], // 64KB buffer
        })
    }
    
    pub fn process_packet(&mut self, packet: &[u8], direction: TunnelDirection) -> Result<Vec<u8>, Error> {
        match direction {
            TunnelDirection::Upstream => {
                // Decrypt from downstream, encrypt for upstream
                self.decrypt_and_reencrypt(packet, &self.downstream_crypto, &self.upstream_crypto)
            },
            TunnelDirection::Downstream => {
                // Decrypt from upstream, encrypt for downstream
                self.decrypt_and_reencrypt(packet, &self.upstream_crypto, &self.downstream_crypto)
            },
        }
    }
    
    fn decrypt_and_reencrypt(
        &mut self,
        packet: &[u8],
        decrypt_crypto: &PQQuicCrypto,
        encrypt_crypto: &PQQuicCrypto,
    ) -> Result<Vec<u8>, Error> {
        // Zero-copy decryption
        self.packet_buffer[..packet.len()].copy_from_slice(packet);
        
        let header_len = extract_header_length(&self.packet_buffer)?;
        let packet_number = extract_packet_number(&self.packet_buffer, header_len)?;
        
        // Decrypt in place
        let result = unsafe {
            zcrypto_quic_decrypt_packet_inplace(
                self.packet_buffer.as_mut_ptr(),
                packet.len() as u32,
                header_len as u32,
                packet_number,
                decrypt_crypto.keys.as_ptr(),
            )
        };
        require_success(result)?;
        
        // Re-encrypt in place with new crypto
        let result = unsafe {
            zcrypto_quic_encrypt_packet_inplace(
                self.packet_buffer.as_mut_ptr(),
                packet.len() as u32,
                header_len as u32,
                packet_number,
                encrypt_crypto.keys.as_ptr(),
            )
        };
        require_success(result)?;
        
        Ok(self.packet_buffer[..packet.len()].to_vec())
    }
    
    // Batch processing for high throughput
    pub fn process_packet_batch(&mut self, packets: &[&[u8]]) -> Result<Vec<Vec<u8>>, Error> {
        let mut results = Vec::with_capacity(packets.len());
        
        for packet in packets {
            results.push(self.process_packet(packet, TunnelDirection::Upstream)?);
        }
        
        Ok(results)
    }
}

// High-performance proxy server
pub struct WraithProxy {
    tunnels: HashMap<ConnectionId, PQTunnel>,
    thread_pool: ThreadPool,
}

impl WraithProxy {
    pub async fn handle_connection(&mut self, conn: Connection) -> Result<(), Error> {
        let conn_id = conn.id();
        
        // Create tunnel with post-quantum crypto
        let tunnel = PQTunnel::new(&conn.upstream_config(), &conn.downstream_config())?;
        self.tunnels.insert(conn_id, tunnel);
        
        // Process packets with zero-copy operations
        while let Some(packet) = conn.read_packet().await? {
            let tunnel = self.tunnels.get_mut(&conn_id).unwrap();
            let processed = tunnel.process_packet(&packet, TunnelDirection::Upstream)?;
            conn.send_packet(&processed).await?;
        }
        
        Ok(())
    }
}
```

### **🌐 CNS/ZNS (Name Resolution Services)**

#### **Integration Requirements**
- DNSSEC with post-quantum signatures
- Secure name resolution over QUIC
- Zero-knowledge domain ownership proofs

#### **Key Components**
```rust
// src/dns/pq_dnssec.rs
use zcrypto_sys::*;

pub struct PQDNSSec {
    zone_signing_key: MLDSAKeyPair,
    key_signing_key: SLHDSAKeyPair,
}

impl PQDNSSec {
    pub fn sign_dns_record(&self, record: &DNSRecord) -> Result<DNSSignature, CryptoError> {
        let record_data = record.canonical_form();
        
        let mut signature = [0u8; 3309];
        let result = unsafe {
            zcrypto_ml_dsa_65_sign(
                record_data.as_ptr(),
                record_data.len() as u32,
                self.zone_signing_key.secret_key.as_ptr(),
                signature.as_mut_ptr(),
            )
        };
        
        if result.success {
            Ok(DNSSignature {
                algorithm: SignatureAlgorithm::MLDSA65,
                signature: signature.to_vec(),
                key_tag: self.calculate_key_tag()?,
            })
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
    
    pub fn verify_dns_chain(&self, records: &[DNSRecord], signatures: &[DNSSignature]) -> Result<bool, CryptoError> {
        if records.len() != signatures.len() {
            return Ok(false);
        }
        
        for (record, signature) in records.iter().zip(signatures.iter()) {
            if !self.verify_dns_record(record, signature)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    pub fn create_domain_ownership_proof(&self, domain: &str, secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Zero-knowledge proof of domain ownership without revealing secret
        let mut proof = vec![0u8; 1024];
        let mut proof_len = 1024u32;
        
        // Create commitment to secret
        let commitment = self.create_commitment(secret)?;
        
        // Generate ZK proof of knowledge
        let result = unsafe {
            zcrypto_zkp_prove_domain_ownership(
                domain.as_ptr(),
                domain.len() as u32,
                secret.as_ptr(),
                secret.len() as u32,
                commitment.as_ptr(),
                proof.as_mut_ptr(),
                &mut proof_len,
            )
        };
        
        if result.success {
            proof.truncate(proof_len as usize);
            Ok(proof)
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
}

// Secure name resolution over post-quantum QUIC
pub struct SecureResolver {
    pq_crypto: PQQuicCrypto,
    dnssec: PQDNSSec,
    cache: LRUCache<String, DNSResponse>,
}

impl SecureResolver {
    pub async fn resolve_secure(&mut self, domain: &str) -> Result<DNSResponse, Error> {
        // Check cache first
        if let Some(cached) = self.cache.get(domain) {
            if !cached.is_expired() {
                return Ok(cached.clone());
            }
        }
        
        // Resolve over post-quantum QUIC
        let query = DNSQuery::new(domain, RecordType::A);
        let encrypted_query = self.encrypt_dns_query(&query)?;
        
        let response = self.send_over_pq_quic(&encrypted_query).await?;
        let decrypted_response = self.decrypt_dns_response(&response)?;
        
        // Verify DNSSEC signatures
        self.verify_dnssec_chain(&decrypted_response)?;
        
        // Cache the result
        self.cache.insert(domain.to_string(), decrypted_response.clone());
        
        Ok(decrypted_response)
    }
}
```

### **🕸️ GhostMesh (P2P Network Layer)**

#### **Integration Requirements**
- Post-quantum secure channels between mesh nodes
- Distributed key management and rotation
- Zero-knowledge network topology proofs
- High-throughput P2P message encryption

#### **Key Components**
```rust
// Cargo.toml
[dependencies]
zcrypto-sys = { path = "../zcrypto/bindings/rust" }
libp2p = "0.53"
tokio = "1.0"
serde = { version = "1.0", features = ["derive"] }

// src/mesh/pq_network.rs
use zcrypto_sys::*;
use libp2p::{NetworkBehaviour, PeerId};

pub struct PQMeshNode {
    node_identity: PQNodeIdentity,
    peer_sessions: HashMap<PeerId, PQPeerSession>,
    mesh_topology: MeshTopology,
    message_router: MessageRouter,
}

#[derive(Clone)]
pub struct PQNodeIdentity {
    node_id: PeerId,
    classical_keypair: Ed25519KeyPair,
    pq_keypair: MLDSAKeyPair,
    hybrid_mode: bool,
}

impl PQNodeIdentity {
    pub fn generate() -> Result<Self, CryptoError> {
        // Generate classical Ed25519 keys
        let mut classical_public = [0u8; 32];
        let mut classical_private = [0u8; 64];
        
        let result = unsafe {
            zcrypto_ed25519_keygen(
                classical_public.as_mut_ptr(),
                classical_private.as_mut_ptr(),
            )
        };
        require_success(result)?;
        
        // Generate post-quantum ML-DSA keys
        let mut pq_public = [0u8; 1952];
        let mut pq_private = [0u8; 4032];
        
        let result = unsafe {
            zcrypto_ml_dsa_65_keygen(
                pq_public.as_mut_ptr(),
                pq_private.as_mut_ptr(),
            )
        };
        require_success(result)?;
        
        // Derive PeerId from combined keys
        let node_id = Self::derive_peer_id(&classical_public, &pq_public);
        
        Ok(Self {
            node_id,
            classical_keypair: Ed25519KeyPair {
                public_key: classical_public,
                private_key: classical_private,
            },
            pq_keypair: MLDSAKeyPair {
                public_key: pq_public,
                private_key: pq_private,
            },
            hybrid_mode: true,
        })
    }
    
    fn derive_peer_id(classical_key: &[u8; 32], pq_key: &[u8; 1952]) -> PeerId {
        // Combine both keys to create unique peer ID
        let mut combined = Vec::with_capacity(32 + 1952);
        combined.extend_from_slice(classical_key);
        combined.extend_from_slice(pq_key);
        
        let mut hash = [0u8; 32];
        let result = unsafe {
            zcrypto_sha256(combined.as_ptr(), combined.len() as u32, hash.as_mut_ptr())
        };
        
        if result.success {
            PeerId::from_bytes(&hash[0..20]).unwrap_or_else(|_| PeerId::random())
        } else {
            PeerId::random()
        }
    }
    
    pub fn sign_mesh_message(&self, message: &[u8]) -> Result<MeshSignature, CryptoError> {
        if self.hybrid_mode {
            // Sign with both classical and post-quantum keys
            let mut classical_sig = [0u8; 64];
            let mut pq_sig = [0u8; 3309];
            
            let classical_result = unsafe {
                zcrypto_ed25519_sign(
                    message.as_ptr(),
                    message.len() as u32,
                    self.classical_keypair.private_key.as_ptr(),
                    classical_sig.as_mut_ptr(),
                )
            };
            
            let pq_result = unsafe {
                zcrypto_ml_dsa_65_sign(
                    message.as_ptr(),
                    message.len() as u32,
                    self.pq_keypair.private_key.as_ptr(),
                    pq_sig.as_mut_ptr(),
                )
            };
            
            if classical_result.success && pq_result.success {
                Ok(MeshSignature::Hybrid {
                    classical: classical_sig,
                    post_quantum: pq_sig,
                })
            } else {
                Err(CryptoError::SigningFailed)
            }
        } else {
            // Pure post-quantum mode
            let mut pq_sig = [0u8; 3309];
            
            let result = unsafe {
                zcrypto_ml_dsa_65_sign(
                    message.as_ptr(),
                    message.len() as u32,
                    self.pq_keypair.private_key.as_ptr(),
                    pq_sig.as_mut_ptr(),
                )
            };
            
            if result.success {
                Ok(MeshSignature::PostQuantum(pq_sig))
            } else {
                Err(CryptoError::SigningFailed)
            }
        }
    }
}

pub struct PQPeerSession {
    peer_id: PeerId,
    session_key: [u8; 32],
    message_counter: AtomicU64,
    established_at: Instant,
    last_activity: AtomicU64,
}

impl PQPeerSession {
    pub fn establish(our_identity: &PQNodeIdentity, peer_public_key: &PeerPublicKey) -> Result<Self, CryptoError> {
        // Perform hybrid key exchange
        let mut shared_secret = [0u8; 64];
        
        let result = unsafe {
            zcrypto_hybrid_x25519_ml_kem_kex(
                shared_secret.as_mut_ptr(),
                peer_public_key.classical.as_ptr(),
                peer_public_key.pq.as_ptr(),
            )
        };
        
        if result.success {
            // Derive session key from shared secret
            let mut session_key = [0u8; 32];
            let result = unsafe {
                zcrypto_kdf_derive_key(
                    shared_secret.as_ptr(),
                    shared_secret.len() as u32,
                    b"mesh_session_key".as_ptr(),
                    17, // length of "mesh_session_key"
                    session_key.as_mut_ptr(),
                    32,
                )
            };
            
            if result.success {
                Ok(Self {
                    peer_id: peer_public_key.peer_id,
                    session_key,
                    message_counter: AtomicU64::new(0),
                    established_at: Instant::now(),
                    last_activity: AtomicU64::new(0),
                })
            } else {
                Err(CryptoError::KeyDerivationFailed)
            }
        } else {
            Err(CryptoError::KeyExchangeFailed)
        }
    }
    
    pub fn encrypt_message(&self, plaintext: &[u8]) -> Result<EncryptedMeshMessage, CryptoError> {
        let counter = self.message_counter.fetch_add(1, Ordering::SeqCst);
        
        // Create nonce from counter
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        
        let result = unsafe {
            zcrypto_chacha20_poly1305_encrypt(
                plaintext.as_ptr(),
                plaintext.len() as u32,
                self.session_key.as_ptr(),
                nonce.as_ptr(),
                ciphertext.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        
        if result.success {
            Ok(EncryptedMeshMessage {
                sender: self.peer_id,
                nonce,
                ciphertext,
                tag,
                timestamp: SystemTime::now(),
            })
        } else {
            Err(CryptoError::EncryptionFailed)
        }
    }
    
    pub fn decrypt_message(&self, encrypted: &EncryptedMeshMessage) -> Result<Vec<u8>, CryptoError> {
        let mut plaintext = vec![0u8; encrypted.ciphertext.len()];
        
        let result = unsafe {
            zcrypto_chacha20_poly1305_decrypt(
                encrypted.ciphertext.as_ptr(),
                encrypted.ciphertext.len() as u32,
                self.session_key.as_ptr(),
                encrypted.nonce.as_ptr(),
                encrypted.tag.as_ptr(),
                plaintext.as_mut_ptr(),
            )
        };
        
        if result.success {
            self.last_activity.store(
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                Ordering::Relaxed,
            );
            Ok(plaintext)
        } else {
            Err(CryptoError::DecryptionFailed)
        }
    }
}

impl PQMeshNode {
    pub fn new(identity: PQNodeIdentity) -> Self {
        Self {
            node_identity: identity,
            peer_sessions: HashMap::new(),
            mesh_topology: MeshTopology::new(),
            message_router: MessageRouter::new(),
        }
    }
    
    pub async fn connect_to_peer(&mut self, peer_addr: &str) -> Result<PeerId, Error> {
        // Establish connection using libp2p
        let connection = self.dial_peer(peer_addr).await?;
        
        // Perform post-quantum handshake
        let peer_public_key = self.exchange_public_keys(&connection).await?;
        let session = PQPeerSession::establish(&self.node_identity, &peer_public_key)?;
        
        let peer_id = peer_public_key.peer_id;
        self.peer_sessions.insert(peer_id, session);
        self.mesh_topology.add_peer(peer_id);
        
        Ok(peer_id)
    }
    
    pub async fn broadcast_message(&self, message: &[u8]) -> Result<usize, Error> {
        let mut successful_sends = 0;
        
        // Sign the message for authenticity
        let signature = self.node_identity.sign_mesh_message(message)?;
        let signed_message = SignedMeshMessage {
            content: message.to_vec(),
            signature,
            sender: self.node_identity.node_id,
            timestamp: SystemTime::now(),
        };
        
        // Serialize signed message
        let serialized = bincode::serialize(&signed_message)?;
        
        // Encrypt and send to all peers
        for (peer_id, session) in &self.peer_sessions {
            match session.encrypt_message(&serialized) {
                Ok(encrypted) => {
                    if let Err(e) = self.send_to_peer(*peer_id, encrypted).await {
                        log::warn!("Failed to send to peer {}: {}", peer_id, e);
                    } else {
                        successful_sends += 1;
                    }
                },
                Err(e) => {
                    log::error!("Failed to encrypt message for peer {}: {}", peer_id, e);
                }
            }
        }
        
        Ok(successful_sends)
    }
    
    pub fn create_zkp_topology_proof(&self) -> Result<Vec<u8>, CryptoError> {
        // Create zero-knowledge proof of network topology without revealing peer identities
        let topology_hash = self.mesh_topology.compute_hash();
        
        let mut proof = vec![0u8; 1024];
        let mut proof_len = 1024u32;
        
        let result = unsafe {
            zcrypto_zkp_prove_topology(
                topology_hash.as_ptr(),
                32,
                self.node_identity.node_id.as_bytes().as_ptr(),
                self.node_identity.node_id.as_bytes().len() as u32,
                proof.as_mut_ptr(),
                &mut proof_len,
            )
        };
        
        if result.success {
            proof.truncate(proof_len as usize);
            Ok(proof)
        } else {
            Err(CryptoError::ProofGenerationFailed)
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SignedMeshMessage {
    pub content: Vec<u8>,
    pub signature: MeshSignature,
    pub sender: PeerId,
    pub timestamp: SystemTime,
}

#[derive(Serialize, Deserialize)]
pub enum MeshSignature {
    Classical([u8; 64]),
    PostQuantum([u8; 3309]),
    Hybrid {
        classical: [u8; 64],
        post_quantum: [u8; 3309],
    },
}

pub struct EncryptedMeshMessage {
    pub sender: PeerId,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub timestamp: SystemTime,
}

pub struct MeshTopology {
    peers: HashSet<PeerId>,
    connections: HashMap<PeerId, Vec<PeerId>>,
    network_hash: [u8; 32],
}

impl MeshTopology {
    fn new() -> Self {
        Self {
            peers: HashSet::new(),
            connections: HashMap::new(),
            network_hash: [0u8; 32],
        }
    }
    
    fn add_peer(&mut self, peer_id: PeerId) {
        self.peers.insert(peer_id);
        self.connections.entry(peer_id).or_insert_with(Vec::new);
        self.update_network_hash();
    }
    
    fn compute_hash(&self) -> [u8; 32] {
        self.network_hash
    }
    
    fn update_network_hash(&mut self) {
        // Update hash based on current topology
        let mut hasher_input = Vec::new();
        for peer in &self.peers {
            hasher_input.extend_from_slice(peer.as_bytes());
        }
        
        let result = unsafe {
            zcrypto_sha256(
                hasher_input.as_ptr(),
                hasher_input.len() as u32,
                self.network_hash.as_mut_ptr(),
            )
        };
        
        if !result.success {
            log::error!("Failed to update network hash");
        }
    }
}
```

#### **Configuration**
```toml
# ghostmesh.toml
[network]
listen_addresses = ["/ip4/0.0.0.0/tcp/4001", "/ip4/0.0.0.0/udp/4001/quic"]
bootstrap_peers = [
    "/ip4/bootstrap1.ghostmesh.network/tcp/4001/p2p/12D3KooW...",
    "/ip4/bootstrap2.ghostmesh.network/tcp/4001/p2p/12D3KooW...",
]
max_peers = 50
connection_timeout = 30

[crypto]
post_quantum_enabled = true
hybrid_mode = true
key_rotation_interval = 3600  # 1 hour
session_timeout = 1800        # 30 minutes

[routing]
enable_dht = true
replication_factor = 3
message_ttl = 300  # 5 minutes
```

---

## 🦀 **RUST PROJECT INTEGRATION**

### **1. FFI Bindings Setup**

#### **Creating Rust Bindings**

```bash
# Create bindings directory
mkdir -p bindings/rust
cd bindings/rust

# Generate bindings
cargo init --lib
```

```toml
# Cargo.toml
[package]
name = "zcrypto-sys"
version = "0.5.0"
edition = "2021"

[dependencies]
libc = "0.2"

[build-dependencies]
bindgen = "0.66"

[lib]
name = "zcrypto_sys"
crate-type = ["rlib", "cdylib"]
```

```rust
// build.rs
use std::env;
use std::path::PathBuf;

fn main() {
    // Build zcrypto library
    let zcrypto_dir = env::var("ZCRYPTO_DIR")
        .unwrap_or_else(|_| "../../".to_string());
    
    println!("cargo:rustc-link-search=native={}/zig-out/lib", zcrypto_dir);
    println!("cargo:rustc-link-lib=static=zcrypto");
    
    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header(format!("{}/zig-out/include/zcrypto.h", zcrypto_dir))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
```

```rust
// src/lib.rs
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidInput = 1,
    CryptoFailed = 2,
    InsufficientBuffer = 3,
    KeyGenerationFailed = 4,
    SignatureFailed = 5,
    VerificationFailed = 6,
    EncryptionFailed = 7,
    DecryptionFailed = 8,
    PostQuantumFailed = 9,
    QuicFailed = 10,
}

impl From<u32> for CryptoError {
    fn from(code: u32) -> Self {
        match code {
            1 => CryptoError::InvalidInput,
            2 => CryptoError::CryptoFailed,
            3 => CryptoError::InsufficientBuffer,
            4 => CryptoError::KeyGenerationFailed,
            5 => CryptoError::SignatureFailed,
            6 => CryptoError::VerificationFailed,
            7 => CryptoError::EncryptionFailed,
            8 => CryptoError::DecryptionFailed,
            9 => CryptoError::PostQuantumFailed,
            10 => CryptoError::QuicFailed,
            _ => CryptoError::CryptoFailed,
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::InvalidInput => write!(f, "Invalid input provided"),
            CryptoError::CryptoFailed => write!(f, "Cryptographic operation failed"),
            CryptoError::InsufficientBuffer => write!(f, "Insufficient buffer size"),
            CryptoError::KeyGenerationFailed => write!(f, "Key generation failed"),
            CryptoError::SignatureFailed => write!(f, "Signature generation failed"),
            CryptoError::VerificationFailed => write!(f, "Signature verification failed"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::PostQuantumFailed => write!(f, "Post-quantum operation failed"),
            CryptoError::QuicFailed => write!(f, "QUIC cryptographic operation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;

// Safe Rust wrappers
pub mod hash {
    use super::*;
    
    pub fn sha256(input: &[u8]) -> Result<[u8; 32]> {
        let mut output = [0u8; 32];
        let result = unsafe {
            zcrypto_sha256(input.as_ptr(), input.len() as u32, output.as_mut_ptr())
        };
        
        if result.success {
            Ok(output)
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
    
    pub fn blake2b(input: &[u8]) -> Result<[u8; 64]> {
        let mut output = [0u8; 64];
        let result = unsafe {
            zcrypto_blake2b(input.as_ptr(), input.len() as u32, output.as_mut_ptr())
        };
        
        if result.success {
            Ok(output)
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
}

pub mod pq {
    use super::*;
    
    pub mod ml_kem {
        use super::*;
        
        pub const PUBLIC_KEY_SIZE: usize = 1184;
        pub const SECRET_KEY_SIZE: usize = 2400;
        pub const CIPHERTEXT_SIZE: usize = 1088;
        pub const SHARED_SECRET_SIZE: usize = 32;
        
        pub struct KeyPair {
            pub public_key: [u8; PUBLIC_KEY_SIZE],
            pub secret_key: [u8; SECRET_KEY_SIZE],
        }
        
        impl KeyPair {
            pub fn generate() -> Result<Self> {
                let mut public_key = [0u8; PUBLIC_KEY_SIZE];
                let mut secret_key = [0u8; SECRET_KEY_SIZE];
                
                let result = unsafe {
                    zcrypto_ml_kem_768_keygen(
                        public_key.as_mut_ptr(),
                        secret_key.as_mut_ptr(),
                    )
                };
                
                if result.success {
                    Ok(Self { public_key, secret_key })
                } else {
                    Err(CryptoError::from(result.error_code))
                }
            }
            
            pub fn encapsulate(public_key: &[u8; PUBLIC_KEY_SIZE]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_SIZE])> {
                let mut ciphertext = vec![0u8; CIPHERTEXT_SIZE];
                let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
                
                let result = unsafe {
                    zcrypto_ml_kem_768_encapsulate(
                        public_key.as_ptr(),
                        ciphertext.as_mut_ptr(),
                        shared_secret.as_mut_ptr(),
                    )
                };
                
                if result.success {
                    Ok((ciphertext, shared_secret))
                } else {
                    Err(CryptoError::from(result.error_code))
                }
            }
            
            pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_SIZE]> {
                if ciphertext.len() != CIPHERTEXT_SIZE {
                    return Err(CryptoError::InvalidInput);
                }
                
                let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
                
                let result = unsafe {
                    zcrypto_ml_kem_768_decapsulate(
                        self.secret_key.as_ptr(),
                        ciphertext.as_ptr(),
                        shared_secret.as_mut_ptr(),
                    )
                };
                
                if result.success {
                    Ok(shared_secret)
                } else {
                    Err(CryptoError::from(result.error_code))
                }
            }
        }
    }
}

pub mod quic {
    use super::*;
    
    pub fn encrypt_packet_inplace(
        packet: &mut [u8],
        header_len: usize,
        packet_number: u64,
        keys: &[u8; 64],
    ) -> Result<()> {
        let result = unsafe {
            zcrypto_quic_encrypt_packet_inplace(
                packet.as_mut_ptr(),
                packet.len() as u32,
                header_len as u32,
                packet_number,
                keys.as_ptr(),
            )
        };
        
        if result.success {
            Ok(())
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
    
    pub fn decrypt_packet_inplace(
        packet: &mut [u8],
        header_len: usize,
        packet_number: u64,
        keys: &[u8; 64],
    ) -> Result<()> {
        let result = unsafe {
            zcrypto_quic_decrypt_packet_inplace(
                packet.as_mut_ptr(),
                packet.len() as u32,
                header_len as u32,
                packet_number,
                keys.as_ptr(),
            )
        };
        
        if result.success {
            Ok(())
        } else {
            Err(CryptoError::from(result.error_code))
        }
    }
}
```

### **2. High-Level Rust Wrapper**

```rust
// Create zcrypto wrapper crate
// Cargo.toml
[package]
name = "zcrypto"
version = "0.5.0"
edition = "2021"

[dependencies]
zcrypto-sys = { path = "../zcrypto-sys" }
tokio = { version = "1.0", optional = true }
serde = { version = "1.0", features = ["derive"], optional = true }

[features]
default = ["async", "serde"]
async = ["tokio"]
serde = ["dep:serde"]
```

```rust
// src/lib.rs
pub use zcrypto_sys as ffi;

pub mod error {
    pub use zcrypto_sys::{CryptoError, Result};
}

pub mod hash {
    use crate::error::Result;
    
    pub fn sha256(input: &[u8]) -> Result<[u8; 32]> {
        zcrypto_sys::hash::sha256(input)
    }
    
    pub fn blake2b(input: &[u8]) -> Result<[u8; 64]> {
        zcrypto_sys::hash::blake2b(input)
    }
}

pub mod pq {
    pub use zcrypto_sys::pq::*;
}

pub mod quic {
    pub use zcrypto_sys::quic::*;
    
    #[cfg(feature = "async")]
    pub mod async_quic {
        use super::*;
        use tokio::net::UdpSocket;
        
        pub struct AsyncQuicCrypto {
            keys: [u8; 64],
        }
        
        impl AsyncQuicCrypto {
            pub async fn encrypt_packet_async(&self, packet: &mut [u8], header_len: usize) -> Result<()> {
                // Offload to thread pool for CPU-intensive operations
                let keys = self.keys;
                tokio::task::spawn_blocking(move || {
                    encrypt_packet_inplace(packet, header_len, 1, &keys)
                }).await.unwrap()
            }
        }
    }
}

#[cfg(feature = "serde")]
pub mod serde_support {
    use serde::{Deserialize, Serialize};
    
    #[derive(Serialize, Deserialize)]
    pub struct SerializableKeyPair {
        pub public_key: Vec<u8>,
        pub secret_key: Vec<u8>,
    }
    
    impl From<crate::pq::ml_kem::KeyPair> for SerializableKeyPair {
        fn from(kp: crate::pq::ml_kem::KeyPair) -> Self {
            Self {
                public_key: kp.public_key.to_vec(),
                secret_key: kp.secret_key.to_vec(),
            }
        }
    }
}
```

### **3. Integration Examples**

#### **Basic Usage**
```rust
// examples/basic_usage.rs
use zcrypto::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Hash data
    let data = b"Hello, zcrypto!";
    let hash = zcrypto::hash::sha256(data)?;
    println!("SHA-256: {}", hex::encode(hash));
    
    // Post-quantum key exchange
    let keypair = zcrypto::pq::ml_kem::KeyPair::generate()?;
    let (ciphertext, shared_secret) = zcrypto::pq::ml_kem::KeyPair::encapsulate(&keypair.public_key)?;
    let recovered_secret = keypair.decapsulate(&ciphertext)?;
    
    assert_eq!(shared_secret, recovered_secret);
    println!("Post-quantum key exchange successful!");
    
    Ok(())
}
```

#### **QUIC Integration**
```rust
// examples/quic_integration.rs
use zcrypto::quic::*;

pub struct QuicConnection {
    crypto: AsyncQuicCrypto,
    socket: UdpSocket,
}

impl QuicConnection {
    pub async fn new(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(addr).await?;
        let crypto = AsyncQuicCrypto::new().await?;
        
        Ok(Self { crypto, socket })
    }
    
    pub async fn send_encrypted(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        // Create QUIC packet
        let mut packet = vec![0u8; 1500];
        let header_len = create_quic_header(&mut packet, data.len())?;
        packet[header_len..header_len + data.len()].copy_from_slice(data);
        
        // Encrypt in place
        self.crypto.encrypt_packet_async(&mut packet, header_len).await?;
        
        // Send over UDP
        self.socket.send(&packet).await?;
        
        Ok(())
    }
}
```

---

## 🔧 **C/C++ PROJECT INTEGRATION**

### **1. Header Generation**

```bash
# Generate C headers
zig build-lib src/ffi.zig -femit-h=zcrypto.h -target=native

# Or using build system
zig build generate-headers
```

### **2. CMake Integration**

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(MyProject)

# Find zcrypto
find_library(ZCRYPTO_LIBRARY 
    NAMES zcrypto libzcrypto
    HINTS ${ZCRYPTO_DIR}/zig-out/lib
)

find_path(ZCRYPTO_INCLUDE_DIR
    NAMES zcrypto.h
    HINTS ${ZCRYPTO_DIR}/zig-out/include
)

if(NOT ZCRYPTO_LIBRARY OR NOT ZCRYPTO_INCLUDE_DIR)
    message(FATAL_ERROR "zcrypto not found. Set ZCRYPTO_DIR to zcrypto installation directory.")
endif()

# Create target
add_executable(myapp main.cpp)
target_include_directories(myapp PRIVATE ${ZCRYPTO_INCLUDE_DIR})
target_link_libraries(myapp ${ZCRYPTO_LIBRARY})

# Link system libraries
if(UNIX)
    target_link_libraries(myapp m pthread)
elseif(WIN32)
    target_link_libraries(myapp ws2_32)
endif()
```

### **3. C++ Wrapper Example**

```cpp
// zcrypto_wrapper.hpp
#pragma once

#include <vector>
#include <memory>
#include <stdexcept>
#include "zcrypto.h"

namespace zcrypto {

class CryptoException : public std::runtime_error {
public:
    CryptoException(uint32_t error_code, const std::string& message)
        : std::runtime_error(message), error_code_(error_code) {}
    
    uint32_t error_code() const { return error_code_; }

private:
    uint32_t error_code_;
};

inline void check_result(CryptoResult result) {
    if (!result.success) {
        throw CryptoException(result.error_code, "Cryptographic operation failed");
    }
}

namespace hash {
    inline std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& input) {
        std::array<uint8_t, 32> output;
        auto result = zcrypto_sha256(input.data(), input.size(), output.data());
        check_result(result);
        return output;
    }
    
    inline std::array<uint8_t, 64> blake2b(const std::vector<uint8_t>& input) {
        std::array<uint8_t, 64> output;
        auto result = zcrypto_blake2b(input.data(), input.size(), output.data());
        check_result(result);
        return output;
    }
}

namespace pq {
    class MLKEMKeyPair {
    public:
        static constexpr size_t PUBLIC_KEY_SIZE = 1184;
        static constexpr size_t SECRET_KEY_SIZE = 2400;
        static constexpr size_t CIPHERTEXT_SIZE = 1088;
        static constexpr size_t SHARED_SECRET_SIZE = 32;
        
        MLKEMKeyPair() {
            auto result = zcrypto_ml_kem_768_keygen(
                public_key_.data(),
                secret_key_.data()
            );
            check_result(result);
        }
        
        const std::array<uint8_t, PUBLIC_KEY_SIZE>& public_key() const {
            return public_key_;
        }
        
        std::pair<std::vector<uint8_t>, std::array<uint8_t, SHARED_SECRET_SIZE>>
        encapsulate() const {
            std::vector<uint8_t> ciphertext(CIPHERTEXT_SIZE);
            std::array<uint8_t, SHARED_SECRET_SIZE> shared_secret;
            
            auto result = zcrypto_ml_kem_768_encapsulate(
                public_key_.data(),
                ciphertext.data(),
                shared_secret.data()
            );
            check_result(result);
            
            return {std::move(ciphertext), shared_secret};
        }
        
        std::array<uint8_t, SHARED_SECRET_SIZE>
        decapsulate(const std::vector<uint8_t>& ciphertext) const {
            if (ciphertext.size() != CIPHERTEXT_SIZE) {
                throw std::invalid_argument("Invalid ciphertext size");
            }
            
            std::array<uint8_t, SHARED_SECRET_SIZE> shared_secret;
            
            auto result = zcrypto_ml_kem_768_decapsulate(
                secret_key_.data(),
                ciphertext.data(),
                shared_secret.data()
            );
            check_result(result);
            
            return shared_secret;
        }
        
    private:
        std::array<uint8_t, PUBLIC_KEY_SIZE> public_key_;
        std::array<uint8_t, SECRET_KEY_SIZE> secret_key_;
    };
}

namespace quic {
    class QuicCrypto {
    public:
        void encrypt_packet_inplace(
            std::vector<uint8_t>& packet,
            size_t header_len,
            uint64_t packet_number,
            const std::array<uint8_t, 64>& keys
        ) {
            auto result = zcrypto_quic_encrypt_packet_inplace(
                packet.data(),
                packet.size(),
                header_len,
                packet_number,
                keys.data()
            );
            check_result(result);
        }
        
        void decrypt_packet_inplace(
            std::vector<uint8_t>& packet,
            size_t header_len,
            uint64_t packet_number,
            const std::array<uint8_t, 64>& keys
        ) {
            auto result = zcrypto_quic_decrypt_packet_inplace(
                packet.data(),
                packet.size(),
                header_len,
                packet_number,
                keys.data()
            );
            check_result(result);
        }
    };
}

} // namespace zcrypto
```

### **4. Usage Example**

```cpp
// main.cpp
#include <iostream>
#include <vector>
#include "zcrypto_wrapper.hpp"

int main() {
    try {
        // Hash some data
        std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
        auto hash = zcrypto::hash::sha256(data);
        
        std::cout << "SHA-256: ";
        for (auto byte : hash) {
            std::cout << std::hex << static_cast<int>(byte);
        }
        std::cout << std::endl;
        
        // Post-quantum key exchange
        zcrypto::pq::MLKEMKeyPair keypair;
        auto [ciphertext, shared_secret1] = keypair.encapsulate();
        auto shared_secret2 = keypair.decapsulate(ciphertext);
        
        if (shared_secret1 == shared_secret2) {
            std::cout << "Post-quantum key exchange successful!" << std::endl;
        }
        
        // QUIC packet encryption
        zcrypto::quic::QuicCrypto quic_crypto;
        std::vector<uint8_t> packet(1500, 0);
        std::array<uint8_t, 64> keys{};
        
        quic_crypto.encrypt_packet_inplace(packet, 50, 1, keys);
        std::cout << "QUIC packet encrypted successfully!" << std::endl;
        
    } catch (const zcrypto::CryptoException& e) {
        std::cerr << "Crypto error: " << e.what() 
                  << " (code: " << e.error_code() << ")" << std::endl;
        return 1;
    }
    
    return 0;
}
```

---

## 🏗️ **BUILD SYSTEM INTEGRATION**

### **1. Zig Build Integration**

```zig
// build.zig for projects using zcrypto
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    
    // Add zcrypto dependency
    const zcrypto_dep = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
        .enable_pq_algorithms = true,
        .enable_zkp = true,
        .enable_asm_optimizations = true,
    });
    
    const exe = b.addExecutable(.{
        .name = "myapp",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    
    exe.root_module.addImport("zcrypto", zcrypto_dep.module("zcrypto"));
    
    b.installArtifact(exe);
}
```

### **2. Cargo Integration**

```toml
# For Rust projects
[dependencies]
zcrypto = { git = "https://github.com/GhostChain/zcrypto", branch = "main" }

# Or with local path
zcrypto = { path = "../zcrypto/bindings/rust" }

# With features
zcrypto = { 
    git = "https://github.com/GhostChain/zcrypto", 
    features = ["async", "serde", "pq-algorithms", "zkp"]
}
```

### **3. npm Integration (for Node.js)**

```json
{
  "name": "my-node-app",
  "dependencies": {
    "zcrypto-node": "file:../zcrypto/bindings/node"
  },
  "scripts": {
    "build": "node-gyp build",
    "test": "node test/test.js"
  }
}
```

### **4. Meson Integration**

```meson
# meson.build
project('myapp', 'c', 'cpp')

# Find zcrypto
zcrypto_dep = dependency('zcrypto', 
  fallback: ['zcrypto', 'zcrypto_dep'],
  required: true
)

executable('myapp', 
  'src/main.cpp',
  dependencies: [zcrypto_dep]
)
```

---

## ⚡ **PERFORMANCE OPTIMIZATION**

### **1. Compilation Optimizations**

```bash
# Maximum performance build
zig build -Doptimize=ReleaseFast -Dstrip=true

# Size-optimized build
zig build -Doptimize=ReleaseSmall

# Profile-guided optimization
zig build -Doptimize=ReleaseFast -Dpgo=true

# Architecture-specific optimizations
zig build -Dtarget=native -Dcpu=native
```

### **2. Runtime Configuration**

```zig
// Configure for maximum performance
const config = zcrypto.Config{
    .use_asm_optimizations = true,
    .preferred_aead = .ChaCha20Poly1305, // Faster than AES on many CPUs
    .preferred_hash = .BLAKE2b,          // Faster than SHA-256
    .constant_time_verification = false,  // Only disable if performance critical
};

zcrypto.setGlobalConfig(config);
```

### **3. Memory Pool Optimization**

```rust
// Rust example with object pools
use zcrypto::memory::CryptoPool;

struct HighThroughputCrypto {
    crypto_pool: CryptoPool,
    packet_buffers: Vec<Vec<u8>>,
}

impl HighThroughputCrypto {
    pub fn new() -> Self {
        Self {
            crypto_pool: CryptoPool::new(1024), // Pre-allocate 1024 contexts
            packet_buffers: (0..1024).map(|_| vec![0u8; 1500]).collect(),
        }
    }
    
    pub async fn process_packets_batch(&mut self, packets: &[&[u8]]) -> Result<Vec<Vec<u8>>, Error> {
        // Use pre-allocated buffers and crypto contexts
        let mut tasks = Vec::new();
        
        for (i, packet) in packets.iter().enumerate() {
            let crypto_ctx = self.crypto_pool.acquire()?;
            let mut buffer = self.packet_buffers[i % self.packet_buffers.len()].clone();
            
            tasks.push(tokio::spawn(async move {
                buffer[..packet.len()].copy_from_slice(packet);
                crypto_ctx.encrypt_inplace(&mut buffer)?;
                Ok(buffer)
            }));
        }
        
        let results = futures::future::try_join_all(tasks).await?;
        Ok(results.into_iter().collect::<Result<Vec<_>, _>>()?)
    }
}
```

### **4. Batch Processing**

```c
// C example with batch operations
typedef struct {
    uint8_t* packets[1024];
    uint32_t packet_lens[1024];
    uint32_t header_lens[1024];
    uint64_t packet_numbers[1024];
    uint32_t count;
} PacketBatch;

int process_packet_batch(PacketBatch* batch, const uint8_t* keys) {
    // Process multiple packets in single call
    CryptoResult result = zcrypto_quic_encrypt_packet_batch(
        batch->packets,
        batch->packet_lens,
        batch->header_lens,
        batch->packet_numbers,
        batch->count,
        keys
    );
    
    return result.success ? 0 : -1;
}
```

---

## 🛡️ **SECURITY CONSIDERATIONS**

### **1. Secure Compilation**

```bash
# Enable security features
zig build -Doptimize=ReleaseSafe \
          -Dstrip=false \
          -Duse_llvm=true \
          -Dstack_check=true

# Enable control flow integrity
zig build -Dcfi=true

# Enable memory sanitizers (for testing)
zig build -Doptimize=Debug -Dsanitize-thread=true
```

### **2. Key Management**

```rust
use zcrypto::memory::SecureMemory;

pub struct SecureKeyManager {
    keys: SecureMemory<[u8; 32]>,
}

impl SecureKeyManager {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            keys: SecureMemory::new()?, // Allocated in secure memory
        })
    }
    
    pub fn rotate_keys(&mut self) -> Result<(), Error> {
        // Generate new keys
        let new_keys = zcrypto::pq::ml_kem::KeyPair::generate()?;
        
        // Securely overwrite old keys
        self.keys.secure_overwrite(&new_keys.secret_key[..32])?;
        
        Ok(())
    }
}

impl Drop for SecureKeyManager {
    fn drop(&mut self) {
        // Keys are automatically zeroed on drop
        self.keys.secure_zero();
    }
}
```

### **3. Side-Channel Protection**

```zig
// Enable constant-time verification
const result = zcrypto.util.constantTimeVerify(
    computed_signature,
    expected_signature,
);

// Use secure comparison
const keys_match = zcrypto.util.constantTimeCompare(
    &key1,
    &key2,
);

// Protect against timing attacks
const protected_result = zcrypto.util.withTimingProtection(struct {
    fn compute() ![]u8 {
        return sensitive_crypto_operation();
    }
}.compute);
```

### **4. Input Validation**

```c
// Always validate inputs
int validate_and_encrypt(const uint8_t* data, uint32_t data_len,
                        const uint8_t* key, uint32_t key_len,
                        uint8_t* output, uint32_t output_len) {
    
    // Validate input lengths
    if (data_len == 0 || data_len > MAX_MESSAGE_SIZE) {
        return -1;
    }
    
    if (key_len != 32) {
        return -1;
    }
    
    if (output_len < data_len + 16) { // data + tag
        return -1;
    }
    
    // Validate pointers
    if (!data || !key || !output) {
        return -1;
    }
    
    // Perform operation
    CryptoResult result = zcrypto_aes256_gcm_encrypt(
        data, data_len, key, nonce, output, tag
    );
    
    return result.success ? 0 : -1;
}
```

---

## 🧪 **TESTING AND VALIDATION**

### **1. Unit Testing**

```zig
// Zig tests
test "post-quantum key exchange" {
    const keypair = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.generate(test_seed);
    
    const encap_result = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(
        keypair.public_key,
        test_randomness
    );
    
    const shared_secret = try keypair.decapsulate(encap_result.ciphertext);
    
    try std.testing.expectEqual(encap_result.shared_secret, shared_secret);
}

test "hybrid key exchange compatibility" {
    var classical_shared: [32]u8 = undefined;
    var pq_shared: [32]u8 = undefined;
    var combined_secret: [64]u8 = undefined;
    
    try zcrypto.pq.hybrid.x25519_ml_kem_768_kex(
        &classical_shared,
        &pq_shared,
        &combined_secret,
        test_entropy
    );
    
    // Verify the combined secret is derived correctly
    var expected: [64]u8 = undefined;
    var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
    hasher.update(&classical_shared);
    hasher.update(&pq_shared);
    hasher.final(&expected);
    
    try std.testing.expectEqual(expected, combined_secret);
}
```

### **2. Integration Testing**

```rust
// Rust integration tests
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_quic_pq_handshake() {
        let mut server = PQQuicEndpoint::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        
        let client = PQQuicEndpoint::new().unwrap();
        
        // Start server
        let server_handle = tokio::spawn(async move {
            let conn = server.accept().await.unwrap();
            // Echo server
            loop {
                let data = conn.read_datagram().await.unwrap();
                conn.send_datagram(data).await.unwrap();
            }
        });
        
        // Connect client
        let conn = client.connect(server_addr).await.unwrap();
        
        // Test post-quantum handshake
        let test_data = b"Hello, PQ-QUIC!";
        conn.send_datagram(test_data.to_vec().into()).await.unwrap();
        
        let received = conn.read_datagram().await.unwrap();
        assert_eq!(received.as_ref(), test_data);
    }
    
    #[test]
    fn test_cross_platform_compatibility() {
        // Test that keys generated on different platforms are compatible
        let keypair1 = zcrypto::pq::ml_kem::KeyPair::generate().unwrap();
        let (ciphertext, secret1) = zcrypto::pq::ml_kem::KeyPair::encapsulate(&keypair1.public_key).unwrap();
        let secret2 = keypair1.decapsulate(&ciphertext).unwrap();
        
        assert_eq!(secret1, secret2);
    }
}
```

### **3. Performance Testing**

```rust
// Benchmark example
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_ml_kem(c: &mut Criterion) {
    let keypair = zcrypto::pq::ml_kem::KeyPair::generate().unwrap();
    
    c.bench_function("ml_kem_768_encapsulate", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret) = zcrypto::pq::ml_kem::KeyPair::encapsulate(
                black_box(&keypair.public_key)
            ).unwrap();
            black_box((ciphertext, shared_secret))
        })
    });
    
    let (ciphertext, _) = zcrypto::pq::ml_kem::KeyPair::encapsulate(&keypair.public_key).unwrap();
    
    c.bench_function("ml_kem_768_decapsulate", |b| {
        b.iter(|| {
            let shared_secret = keypair.decapsulate(black_box(&ciphertext)).unwrap();
            black_box(shared_secret)
        })
    });
}

criterion_group!(benches, benchmark_ml_kem);
criterion_main!(benches);
```

### **4. Security Testing**

```bash
# Static analysis
zig build --check-unused-imports --check-unreachable-code

# Memory safety testing
valgrind --tool=memcheck ./target/debug/myapp

# Fuzzing
cargo fuzz run fuzz_ml_kem_decapsulate

# Side-channel testing
# Use tools like dudect for timing analysis
./timing_analysis_tool --test-constant-time
```

---

## 🔄 **MIGRATION STRATEGIES**

### **1. Gradual Post-Quantum Migration**

```rust
pub enum CryptoMode {
    Classical,
    Hybrid,
    PostQuantum,
}

pub struct MigrationManager {
    current_mode: CryptoMode,
    classical_keys: ClassicalKeys,
    pq_keys: Option<PQKeys>,
}

impl MigrationManager {
    pub fn new() -> Self {
        Self {
            current_mode: CryptoMode::Classical,
            classical_keys: ClassicalKeys::generate(),
            pq_keys: None,
        }
    }
    
    pub fn enable_hybrid_mode(&mut self) -> Result<(), Error> {
        self.pq_keys = Some(PQKeys::generate()?);
        self.current_mode = CryptoMode::Hybrid;
        Ok(())
    }
    
    pub fn upgrade_to_post_quantum(&mut self) -> Result<(), Error> {
        if self.pq_keys.is_none() {
            return Err(Error::NotInHybridMode);
        }
        
        self.current_mode = CryptoMode::PostQuantum;
        Ok(())
    }
    
    pub fn sign(&self, data: &[u8]) -> Result<Signature, Error> {
        match self.current_mode {
            CryptoMode::Classical => {
                Ok(Signature::Classical(self.classical_keys.sign(data)?))
            },
            CryptoMode::Hybrid => {
                let classical_sig = self.classical_keys.sign(data)?;
                let pq_sig = self.pq_keys.as_ref().unwrap().sign(data)?;
                Ok(Signature::Hybrid { classical_sig, pq_sig })
            },
            CryptoMode::PostQuantum => {
                Ok(Signature::PostQuantum(self.pq_keys.as_ref().unwrap().sign(data)?))
            },
        }
    }
    
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<bool, Error> {
        match (signature, &self.current_mode) {
            (Signature::Classical(sig), _) => {
                self.classical_keys.verify(data, sig)
            },
            (Signature::Hybrid { classical_sig, pq_sig }, _) => {
                let classical_valid = self.classical_keys.verify(data, classical_sig)?;
                let pq_valid = self.pq_keys.as_ref().unwrap().verify(data, pq_sig)?;
                Ok(classical_valid && pq_valid)
            },
            (Signature::PostQuantum(sig), CryptoMode::PostQuantum) => {
                self.pq_keys.as_ref().unwrap().verify(data, sig)
            },
            _ => Err(Error::IncompatibleSignature),
        }
    }
}
```

### **2. Database Migration**

```sql
-- Database schema migration for post-quantum keys
-- Step 1: Add PQ columns
ALTER TABLE user_keys ADD COLUMN pq_public_key BYTEA;
ALTER TABLE user_keys ADD COLUMN pq_secret_key_encrypted BYTEA;
ALTER TABLE user_keys ADD COLUMN crypto_mode VARCHAR(20) DEFAULT 'classical';

-- Step 2: Migrate existing users to hybrid mode
UPDATE user_keys 
SET crypto_mode = 'hybrid'
WHERE pq_public_key IS NOT NULL;

-- Step 3: Create indices for performance
CREATE INDEX idx_crypto_mode ON user_keys(crypto_mode);
CREATE INDEX idx_pq_public_key_hash ON user_keys(SHA256(pq_public_key));
```

### **3. Protocol Version Negotiation**

```rust
pub struct ProtocolNegotiator {
    supported_versions: Vec<ProtocolVersion>,
}

#[derive(Debug, Clone, Copy)]
pub enum ProtocolVersion {
    V1Classical,
    V2Hybrid,
    V3PostQuantum,
}

impl ProtocolNegotiator {
    pub fn negotiate(&self, peer_versions: &[ProtocolVersion]) -> Option<ProtocolVersion> {
        // Prefer latest supported version
        for &version in &[ProtocolVersion::V3PostQuantum, ProtocolVersion::V2Hybrid, ProtocolVersion::V1Classical] {
            if self.supported_versions.contains(&version) && peer_versions.contains(&version) {
                return Some(version);
            }
        }
        None
    }
    
    pub fn create_handshake(&self, version: ProtocolVersion) -> Result<HandshakeMessage, Error> {
        match version {
            ProtocolVersion::V1Classical => {
                Ok(HandshakeMessage::Classical(ClassicalHandshake::new()))
            },
            ProtocolVersion::V2Hybrid => {
                Ok(HandshakeMessage::Hybrid(HybridHandshake::new()))
            },
            ProtocolVersion::V3PostQuantum => {
                Ok(HandshakeMessage::PostQuantum(PQHandshake::new()))
            },
        }
    }
}
```

---

## 🔧 **TROUBLESHOOTING**

### **1. Common Build Issues**

#### **Zig Compiler Version Mismatch**
```bash
# Check Zig version
zig version
# Should be 0.11.0 or later

# If wrong version, update
curl -L https://ziglang.org/download/0.11.0/zig-linux-x86_64-0.11.0.tar.xz | tar -xJ
export PATH=$PWD/zig-linux-x86_64-0.11.0:$PATH
```

#### **Missing Dependencies**
```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake

# macOS
xcode-select --install
brew install cmake

# Windows (use vcpkg or pre-built binaries)
vcpkg install cmake
```

#### **Linking Errors**
```bash
# Check if library was built correctly
ls -la zig-out/lib/
# Should contain libzcrypto.a or zcrypto.lib

# Verify symbols
nm zig-out/lib/libzcrypto.a | grep zcrypto_sha256

# For Rust projects, set library path
export LIBRARY_PATH=$PWD/zig-out/lib:$LIBRARY_PATH
export LD_LIBRARY_PATH=$PWD/zig-out/lib:$LD_LIBRARY_PATH
```

### **2. Runtime Issues**

#### **Invalid Key Errors**
```rust
// Validate key sizes before use
pub fn validate_ml_kem_key(public_key: &[u8]) -> Result<(), Error> {
    if public_key.len() != zcrypto::pq::ml_kem::PUBLIC_KEY_SIZE {
        return Err(Error::InvalidKeySize);
    }
    
    // Check key format (first bytes should not be all zeros)
    if public_key[..16].iter().all(|&b| b == 0) {
        return Err(Error::InvalidKeyFormat);
    }
    
    Ok(())
}
```

#### **Memory Allocation Failures**
```c
// Check return values and handle allocation failures
CryptoResult result = zcrypto_groth16_setup(circuit_data, circuit_len, 
                                           &proving_key, &verifying_key);
if (!result.success) {
    if (result.error_code == FFI_ERROR_INSUFFICIENT_BUFFER) {
        // Increase buffer size or use streaming API
        fprintf(stderr, "Insufficient memory for ZKP setup\n");
    }
    return -1;
}
```

### **3. Performance Issues**

#### **Slow Operations**
```rust
// Enable assembly optimizations
std::env::set_var("ZCRYPTO_ENABLE_ASM", "1");

// Use batch processing for multiple operations
let results = zcrypto::batch_encrypt(&plaintexts, &keys, &nonces)?;

// Profile with perf
// perf record -g ./my_app
// perf report
```

#### **High Memory Usage**
```rust
// Use stack allocation for small operations
let result = zcrypto::hash::sha256_stack(data)?;

// Release resources promptly
{
    let circuit = zcrypto::zkp::groth16::Circuit::new()?;
    let proof = circuit.prove(&witness)?;
    // circuit dropped here
}

// Monitor memory usage
println!("Memory usage: {} KB", get_memory_usage());
```

### **4. Compatibility Issues**

#### **Cross-Platform Differences**
```rust
// Handle platform-specific behavior
#[cfg(target_os = "windows")]
fn platform_specific_init() -> Result<(), Error> {
    // Windows-specific initialization
    unsafe { windows_crypto_init() }
}

#[cfg(target_os = "linux")]
fn platform_specific_init() -> Result<(), Error> {
    // Linux-specific initialization
    linux_crypto_init()
}

#[cfg(target_os = "macos")]
fn platform_specific_init() -> Result<(), Error> {
    // macOS-specific initialization
    macos_crypto_init()
}
```

#### **Version Compatibility**
```toml
# Pin specific versions to avoid breaking changes
[dependencies]
zcrypto = "=0.5.0"  # Exact version
```

### **5. Debugging Tools**

#### **Enable Debug Logging**
```bash
# Set environment variable
export ZCRYPTO_LOG_LEVEL=debug

# Or in code
std::env::set_var("ZCRYPTO_LOG_LEVEL", "debug");
```

#### **Memory Debugging**
```bash
# Valgrind
valgrind --leak-check=full --show-leak-kinds=all ./my_app

# AddressSanitizer
gcc -fsanitize=address -g -o my_app_debug my_app.c -lzcrypto
./my_app_debug
```

#### **Timing Analysis**
```rust
use std::time::Instant;

let start = Instant::now();
let result = zcrypto::pq::ml_kem::KeyPair::generate()?;
let duration = start.elapsed();
println!("Key generation took: {:?}", duration);

// Look for timing variations that might indicate side-channels
for _ in 0..1000 {
    let start = Instant::now();
    let _ = zcrypto::pq::ml_kem::KeyPair::encapsulate(&public_key)?;
    println!("{:?}", start.elapsed());
}
```

---

## 📞 **SUPPORT AND RESOURCES**

### **Documentation**
- **API Reference**: See `API.md` for complete function documentation
- **Security Guide**: See `SECURITY_ASSESSMENT.md` for security considerations
- **QUIC Integration**: See `ZQUIC_INTEGRATION.md` for QUIC-specific integration

### **Community**
- **GitHub Issues**: Report bugs and request features
- **Discord**: Join the GhostChain development community
- **Matrix**: #ghostchain-dev:matrix.org

### **Examples Repository**
```bash
git clone https://github.com/GhostChain/zcrypto-examples.git
cd zcrypto-examples
./run_all_examples.sh
```

---

**🚀 zcrypto v0.5.0 Integration Guide - Empowering the post-quantum future across all platforms and languages!**