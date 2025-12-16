#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

// =============================================================================
// MIQROCHAIN PRODUCTION-GRADE CONSTANTS v3.0
// Expert-level tuning for global-scale deployment with millions of users
// Optimized for: Reliability, Performance, Security, Scalability
// =============================================================================
//
// This configuration represents industry best practices derived from:
// - Production-grade blockchain tuning
// - Enterprise-grade distributed systems design
// - Real-world blockchain network operations
//
// =============================================================================

// === RATE LIMITING (Production-tuned for high throughput) ===
#ifndef MIQ_RATE_BLOCK_BPS
#define MIQ_RATE_BLOCK_BPS   (32u * 1024u * 1024u)  // 32 MB/s block rate
#endif
#ifndef MIQ_RATE_BLOCK_BURST
#define MIQ_RATE_BLOCK_BURST (128u * 1024u * 1024u) // 128 MB burst capacity
#endif
#ifndef MIQ_RATE_TX_BPS
#define MIQ_RATE_TX_BPS      (4u * 1024u * 1024u)   // 4 MB/s tx rate
#endif
#ifndef MIQ_RATE_TX_BURST
#define MIQ_RATE_TX_BURST    (16u * 1024u * 1024u)  // 16 MB tx burst
#endif

// === SYNCHRONIZATION TUNING ===
#ifndef MIQ_P2P_STALL_RETRY_MS
#define MIQ_P2P_STALL_RETRY_MS 2000  // CRITICAL FIX: Ultra-fast 2s retry to prevent forks
#endif
#ifndef MIQ_IBD_FALLBACK_AFTER_MS
#define MIQ_IBD_FALLBACK_AFTER_MS (3 * 1000)  // CRITICAL: 3s fallback for near-instant sync
#endif
#ifndef MIQ_OUTBOUND_TARGET
#define MIQ_OUTBOUND_TARGET 12  // More outbound for better connectivity
#endif
#ifndef MIQ_SEED_MODE_OUTBOUND_TARGET
#define MIQ_SEED_MODE_OUTBOUND_TARGET 4  // More seeds for reliability
#endif

// === PRODUCTION PERFORMANCE CONSTANTS ===
#ifndef MIQ_SIGNATURE_CACHE_SIZE
#define MIQ_SIGNATURE_CACHE_SIZE (131072u)  // 128K signature cache entries
#endif
#ifndef MIQ_SCRIPT_EXECUTION_CACHE_SIZE
#define MIQ_SCRIPT_EXECUTION_CACHE_SIZE (65536u)  // 64K script cache entries
#endif
#ifndef MIQ_BLOCK_DOWNLOAD_WINDOW
#define MIQ_BLOCK_DOWNLOAD_WINDOW 1024  // Blocks to download ahead
#endif
#ifndef MIQ_MAX_HEADERS_BATCH
#define MIQ_MAX_HEADERS_BATCH 2000  // Headers per batch
#endif

// === P2P HEADER FLOOD PROTECTION ===
// Per-peer header rate limiting to prevent DoS attacks
#ifndef MIQ_HEADER_RATE_LIMIT_PER_SEC
#define MIQ_HEADER_RATE_LIMIT_PER_SEC 50  // Max headers per second per peer
#endif
#ifndef MIQ_HEADER_RATE_WINDOW_MS
#define MIQ_HEADER_RATE_WINDOW_MS 10000  // Rate window (10 seconds)
#endif
#ifndef MIQ_HEADER_RATE_MAX_BURST
#define MIQ_HEADER_RATE_MAX_BURST 500  // Max burst of headers before rate limiting
#endif
#ifndef MIQ_HEADER_FLOOD_BAN_SCORE
#define MIQ_HEADER_FLOOD_BAN_SCORE 50  // Ban score for header flooding
#endif
#ifndef MIQ_INVALID_HEADER_BAN_SCORE
#define MIQ_INVALID_HEADER_BAN_SCORE 100  // Ban score for invalid headers (immediate ban)
#endif
#ifndef MIQ_PARALLEL_BLOCKS
#define MIQ_PARALLEL_BLOCKS 16  // Parallel block downloads
#endif

//
// ==== P2P/addrman tuning (macros picked up by p2p.cpp) =====================
// These are optional overrides; p2p.cpp only defines its own defaults if these
// are *not* defined here. Adjust as you like without touching code.
//

// Enable the new persistent addrman path
#ifndef MIQ_ENABLE_ADDRMAN
#define MIQ_ENABLE_ADDRMAN 1
#endif

// Addrman persistence file name (distinct from legacy peers.dat)
#ifndef MIQ_ADDRMAN_FILE
#define MIQ_ADDRMAN_FILE "peers2.dat"
#endif

// MIQ_OUTBOUND_TARGET already defined earlier in this file (line ~41) at 12

#ifndef MIQ_INDEX_PIPELINE
#define MIQ_INDEX_PIPELINE 512  // CRITICAL FIX: High pipeline for near-instant sync
#endif

// Outbound dialing cadence (ms) - faster for quicker network formation
#ifndef MIQ_DIAL_INTERVAL_MS
#define MIQ_DIAL_INTERVAL_MS 10000
#endif

// Feeler cadence (ms) for probing NEW addresses
#ifndef MIQ_FEELER_INTERVAL_MS
#define MIQ_FEELER_INTERVAL_MS 45000  // More frequent for better discovery
#endif

// Max outbounds per IPv4 /16 group (anti-eclipse protection)
#ifndef MIQ_GROUP_OUTBOUND_MAX
#define MIQ_GROUP_OUTBOUND_MAX 2
#endif

// Legacy addrset autosave interval & cap (used by current code)
#ifndef MIQ_ADDR_SAVE_INTERVAL_MS
#define MIQ_ADDR_SAVE_INTERVAL_MS 45000  // More frequent saves
#endif
#ifndef MIQ_ADDR_MAX_STORE
#define MIQ_ADDR_MAX_STORE 50000  // Store more addresses for better connectivity
#endif

// === PRODUCTION NETWORK RESILIENCE ===
#ifndef MIQ_MIN_PEERS_FOR_HEALTHY
#define MIQ_MIN_PEERS_FOR_HEALTHY 4  // Minimum peers for healthy state
#endif
#ifndef MIQ_TARGET_PEERS
#define MIQ_TARGET_PEERS 32  // Target total peer count
#endif
#ifndef MIQ_STALE_TIP_AGE_SECS
#define MIQ_STALE_TIP_AGE_SECS 1800  // 30 minutes = stale tip
#endif
// ===========================================================================

// ======= Consensus activation height (grandfather existing chain) ===========
#ifndef MIQ_RULES_ACTIVATE_AT
// Default: effectively "disabled" until you set TIP+1 at build time
// or drop <datadir>/activation.height. This avoids forking past-mined blocks.
#define MIQ_RULES_ACTIVATE_AT 0xFFFFFFFFFFFFFFFFULL
#endif

// Optional: keep low-S enforcement explicitly enabled (chain.cpp also defaults it)
#ifndef MIQ_RULE_ENFORCE_LOW_S
#define MIQ_RULE_ENFORCE_LOW_S 1
#endif

namespace miq {

// ---------------------------------------------------------------------
// Existing identifiers (unchanged)
static constexpr const char* COIN_NAME  = "miq";
static constexpr const char* CHAIN_NAME = "miqrochain";
static constexpr const char* UNIT_NAME  = "miqron";

static constexpr uint64_t COIN = 100000000ULL;
static constexpr uint64_t BLOCK_TIME_SECS = 480; // 8 minutes
static constexpr uint16_t P2P_PORT = 9883;      // (kept as-is per your current config)
static constexpr uint16_t RPC_PORT = 9834;

// MIQ_INDEX_PIPELINE already defined earlier in this file (line ~104) at 128

// Historical 32-bit network tag you already had; we continue to honor it.
static constexpr uint32_t MAGIC = 0xA3FB9E21;

// Canonical **wire** magic bytes (big-endian rendering of MAGIC). Keep stable forever.
static constexpr uint8_t MAGIC_BE[4] = {
    static_cast<uint8_t>((MAGIC >> 24) & 0xFF),
    static_cast<uint8_t>((MAGIC >> 16) & 0xFF),
    static_cast<uint8_t>((MAGIC >>  8) & 0xFF),
    static_cast<uint8_t>((MAGIC >>  0) & 0xFF),
};

// Money / subsidy
static constexpr uint64_t MAX_MONEY        = 26280000ULL * COIN;
static constexpr uint64_t INITIAL_SUBSIDY  = 50ULL * COIN;
static constexpr uint64_t HALVING_INTERVAL = 262800ULL;
static constexpr uint32_t COINBASE_MATURITY = 100;

// Address version bytes : mainnet P2PKH = 0x35 ('5')
static constexpr uint8_t VERSION_P2PKH = 0x35;

// ---------------------------------------------------------------------
// GENESIS (pinned to the currently running network)
// Use these in your init path to build/verify genesis deterministically.
static constexpr int64_t  GENESIS_TIME = 1758890772;     // from dump / matches header bytes
static constexpr uint32_t GENESIS_BITS = 0x1d00ffff;     // compact target (unchanged)
static constexpr uint32_t GENESIS_NONCE = 0xd3dda73c;    // low 32 bits

// Explicit hash & merkle of block 0 (display/big-endian hex as you had)
static constexpr const char* GENESIS_HASH_HEX   = "00000000a5e8a7eb02a83fb9693bc2dccbf14ee69d67315c1f151a25cb43fce8";
static constexpr const char* GENESIS_MERKLE_HEX = "c5d2f3cdb807edcd4b0d9573df33e751ad038797088336c4558e7fd58784a097";

// Bundled genesis private key (leave empty if you don’t embed it)
static constexpr const char* GENESIS_ECDSA_PRIV_HEX = "";

// Who receives the genesis coinbase (your PKH)
static constexpr const char* GENESIS_COINBASE_PKH_HEX = "00c649e06c60278501aad8a3b05d345fe8008836";
static constexpr uint64_t    GENESIS_COINBASE_VALUE   = INITIAL_SUBSIDY;

// Byte-for-byte serialized genesis block for fresh datadirs (exactly 192 bytes)
static constexpr const char* GENESIS_RAW_BLOCK_HEX =
    "01000000f14b2f88c25fb8d87df687a6f5f94be2304a319f1b71209f632d2fffdbfe7856"
    "c5d2f3cdb807edcd4b0d9573df33e751ad038797088336c4558e7fd58784a097"
    "148bd66800000000ffff001d3ca7ddd3f2e65f9e"
    "01000000"  // tx count (4)
    "60000000"  // tx size (96)
    "01000000"  // tx.version
    "01000000"  // #inputs
    "20000000"  // prev.txid size (32)
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000"  // prev.vout
    "00000000"  // sig len
    "00000000"  // pubkey len
    "01000000"  // #outputs (LE)
    "00f2052a01000000"  // value = 50*COIN (u64 LE)
    "14000000"          // pkh len = 20 (LE)
    "00c649e06c60278501aad8a3b05d345fe8008836"  // PKH (20 bytes)
    "00000000";         // lock_time

// ---------------------------------------------------------------------
// Seeds (kept intact)
static const std::string DNS_SEED = "seed.miqrochain.org";

// Multi-seed list (add-only). Your node can try these in order.
static inline const char* const DNS_SEEDS[] = {
    "miqseed1.duckdns.org",
    "miqseed2.freeddns.org"
};
static constexpr size_t DNS_SEEDS_COUNT = sizeof(DNS_SEEDS) / sizeof(DNS_SEEDS[0]);

// ---------------------------------------------------------------------
// DoS/time
static constexpr int64_t MAX_TIME_SKEW = 2*60*60; // 2 hours

// === PRODUCTION SECURITY CAPS ===
// Allow large transactions that can fill the entire block
static constexpr size_t MAX_BLOCK_SIZE = 4 * 1024 * 1024;  // 4 MiB (scalable)
static constexpr size_t MAX_TX_SIZE    = 4 * 1024 * 1024;  // 4 MiB (no tx size limit within block)
static constexpr size_t MAX_MSG_SIZE   = 8 * 1024 * 1024;  // 8 MiB (for large INVs)

// Optional: default RPC token (empty = no token unless MIQ_RPC_TOKEN env set)
static constexpr const char* RPC_TOKEN_DEFAULT = "";

// MIQ_DIAL_INTERVAL_MS already defined earlier in this file (line ~105) at 10000ms

#ifndef MIQ_HEADERS_EMPTY_LIMIT
#define MIQ_HEADERS_EMPTY_LIMIT 3
#endif

// === PRODUCTION MEMPOOL CONFIGURATION ===
#ifndef MIQ_MEMPOOL_MAX_BYTES_PROD
#define MIQ_MEMPOOL_MAX_BYTES_PROD (300u * 1024u * 1024u)  // 300 MiB mempool
#endif
#ifndef MIQ_MEMPOOL_MIN_FEE_RATE
#define MIQ_MEMPOOL_MIN_FEE_RATE 1  // 1 miqron/byte minimum relay fee
#endif
#ifndef MIQ_MEMPOOL_MAX_ANCESTORS_PROD
#define MIQ_MEMPOOL_MAX_ANCESTORS_PROD 50  // Allow deeper chains
#endif
#ifndef MIQ_MEMPOOL_MAX_DESCENDANTS_PROD
#define MIQ_MEMPOOL_MAX_DESCENDANTS_PROD 50
#endif
#ifndef MIQ_MEMPOOL_EXPIRY_HOURS
#define MIQ_MEMPOOL_EXPIRY_HOURS 336  // 14 days
#endif

// === PRODUCTION UTXO OPTIMIZATION ===
#ifndef MIQ_UTXO_CACHE_SIZE_MB
#define MIQ_UTXO_CACHE_SIZE_MB 450  // 450 MB UTXO cache
#endif
#ifndef MIQ_UTXO_FLUSH_INTERVAL
#define MIQ_UTXO_FLUSH_INTERVAL 10000  // Flush every 10k blocks
#endif

// === PRODUCTION MINING DEFAULTS ===
#ifndef MIQ_DEFAULT_MINING_THREADS
#define MIQ_DEFAULT_MINING_THREADS 0  // 0 = auto-detect CPU cores
#endif
#ifndef MIQ_BLOCK_MIN_TX_FEE
#define MIQ_BLOCK_MIN_TX_FEE 1000  // Minimum 1000 miqrons fee for inclusion
#endif

// === PRODUCTION LOGGING & MONITORING ===
#ifndef MIQ_LOG_LEVEL_DEFAULT
#define MIQ_LOG_LEVEL_DEFAULT 1  // 0=debug, 1=info, 2=warn, 3=error
#endif
#ifndef MIQ_METRICS_INTERVAL_MS
#define MIQ_METRICS_INTERVAL_MS 60000  // Log metrics every minute
#endif

// === PRODUCTION SECURITY HARDENING ===
#ifndef MIQ_MAX_ORPHAN_TX_SIZE
#define MIQ_MAX_ORPHAN_TX_SIZE (100u * 1024u)  // 100 KB max orphan tx
#endif
#ifndef MIQ_MAX_ORPHAN_TRANSACTIONS
#define MIQ_MAX_ORPHAN_TRANSACTIONS 10000  // Max orphan tx pool size
#endif
#ifndef MIQ_BAN_SCORE_THRESHOLD
#define MIQ_BAN_SCORE_THRESHOLD 100  // Ban after 100 points
#endif
#ifndef MIQ_BAN_DURATION_SECS
#define MIQ_BAN_DURATION_SECS 86400  // 24 hour ban
#endif

// === PRODUCTION CHECKPOINTS (add actual checkpoints for your chain) ===
// Format: {height, "blockhash"}
// These provide DoS protection during IBD

// === VERSION & PROTOCOL ===
static constexpr uint32_t PROTOCOL_VERSION = 70016;  // Protocol version
static constexpr uint32_t MIN_PEER_PROTO_VERSION = 70015;  // Minimum supported

// === EXPERT-LEVEL PERFORMANCE TUNING ===
// Thread pool sizing for CPU-intensive operations
#ifndef MIQ_VALIDATION_THREADS
#define MIQ_VALIDATION_THREADS 0  // 0 = auto-detect (recommended)
#endif

// Batch processing sizes for optimal throughput
#ifndef MIQ_TX_VALIDATION_BATCH
#define MIQ_TX_VALIDATION_BATCH 100  // Transactions per validation batch
#endif
#ifndef MIQ_BLOCK_VALIDATION_BATCH
#define MIQ_BLOCK_VALIDATION_BATCH 16  // Blocks per validation batch
#endif

// I/O optimization
#ifndef MIQ_DB_WRITE_BUFFER_MB
#define MIQ_DB_WRITE_BUFFER_MB 64  // LevelDB write buffer size
#endif
#ifndef MIQ_DB_CACHE_MB
#define MIQ_DB_CACHE_MB 256  // LevelDB cache size
#endif

// Network optimization for global scale
#ifndef MIQ_MAX_INBOUND_CONNECTIONS
#define MIQ_MAX_INBOUND_CONNECTIONS 125  // Maximum inbound peers
#endif
#ifndef MIQ_MAX_OUTBOUND_CONNECTIONS
#define MIQ_MAX_OUTBOUND_CONNECTIONS 12  // Maximum outbound peers
#endif
#ifndef MIQ_FEELER_CONNECTIONS
#define MIQ_FEELER_CONNECTIONS 2  // Feeler connections for address testing
#endif

// Connection limits for anti-eclipse protection
#ifndef MIQ_MAX_CONNECTIONS_PER_IP
#define MIQ_MAX_CONNECTIONS_PER_IP 3  // Max connections from same IP
#endif
#ifndef MIQ_MAX_CONNECTIONS_PER_SUBNET
#define MIQ_MAX_CONNECTIONS_PER_SUBNET 6  // Max connections from same /16
#endif

// Peer rotation for network health
#ifndef MIQ_PEER_ROTATION_INTERVAL_MS
#define MIQ_PEER_ROTATION_INTERVAL_MS (20 * 60 * 1000)  // 20 minutes
#endif

// Connection backoff (exponential with cap)
#ifndef MIQ_CONNECTION_BACKOFF_BASE_MS
#define MIQ_CONNECTION_BACKOFF_BASE_MS 30000  // 30 second base
#endif
#ifndef MIQ_CONNECTION_BACKOFF_MAX_MS
#define MIQ_CONNECTION_BACKOFF_MAX_MS (12 * 60 * 60 * 1000)  // 12 hour max
#endif

// === P2P BAN AND RATE LIMITING ===
#ifndef MIQ_P2P_MAX_BANSCORE
#define MIQ_P2P_MAX_BANSCORE 100  // Ban threshold score
#endif
#ifndef MIQ_P2P_BAN_MS
#define MIQ_P2P_BAN_MS (24 * 60 * 60 * 1000)  // 24 hour ban duration
#endif
#ifndef MIQ_MAX_SAME_IP_CONNECTIONS
#define MIQ_MAX_SAME_IP_CONNECTIONS 3  // Max connections from same IP
#endif
#ifndef MIQ_MAX_SUBNET24_CONNECTIONS
#define MIQ_MAX_SUBNET24_CONNECTIONS 6  // Max connections from same /24 subnet
#endif
#ifndef MIQ_P2P_INV_WINDOW_MS
#define MIQ_P2P_INV_WINDOW_MS 5000  // INV rate limit window (5 seconds)
#endif
#ifndef MIQ_P2P_INV_WINDOW_CAP
#define MIQ_P2P_INV_WINDOW_CAP 500  // Max INVs per window
#endif
#ifndef MIQ_P2P_MSG_DEADLINE_MS
#define MIQ_P2P_MSG_DEADLINE_MS 30000  // 30 second message deadline
#endif

// === RELIABILITY & FAULT TOLERANCE ===
// Automatic recovery settings
#ifndef MIQ_AUTO_REINDEX_ON_CORRUPTION
#define MIQ_AUTO_REINDEX_ON_CORRUPTION 1  // Auto-repair corrupted indexes
#endif
#ifndef MIQ_MAX_REORG_DEPTH
#define MIQ_MAX_REORG_DEPTH 100  // Maximum chain reorganization depth
#endif

// === IMPROVED IBD STALL DETECTION ===
// Faster peer switching for peers that send headers but no blocks
#ifndef MIQ_HEADERS_ONLY_BAN_SCORE
#define MIQ_HEADERS_ONLY_BAN_SCORE 50  // Ban score for headers-only peer (high penalty)
#endif
#ifndef MIQ_BLOCK_STALL_MAX_COUNT
#define MIQ_BLOCK_STALL_MAX_COUNT 3  // Switch peers after 3 stalls (was 1 - too aggressive, caused rapid connect/disconnect)
#endif
#ifndef MIQ_HEADERS_NO_BLOCKS_TIMEOUT_MS
#define MIQ_HEADERS_NO_BLOCKS_TIMEOUT_MS 30000  // 30s timeout for headers-only stall
#endif
#ifndef MIQ_IBD_PEER_SWITCH_THRESHOLD
#define MIQ_IBD_PEER_SWITCH_THRESHOLD 3  // Switch sync peer after 3 stalls (was 1 - too aggressive)
#endif

// Health monitoring
#ifndef MIQ_HEALTH_CHECK_INTERVAL_MS
#define MIQ_HEALTH_CHECK_INTERVAL_MS 60000  // Health check every minute
#endif
#ifndef MIQ_STALE_PEER_TIMEOUT_MS
#define MIQ_STALE_PEER_TIMEOUT_MS (30 * 60 * 1000)  // 30 minute stale timeout
#endif

// === WALLET TRANSFER LIMITS ===
// No transfer limit - users can send any amount up to their balance
#ifndef MIQ_MAX_TRANSFER_AMOUNT
#define MIQ_MAX_TRANSFER_AMOUNT MAX_MONEY  // No limit - can send up to total supply
#endif

// === RBF (Replace-By-Fee) SUPPORT ===
#ifndef MIQ_RBF_ENABLED
#define MIQ_RBF_ENABLED 1  // Enable replace-by-fee
#endif
#ifndef MIQ_RBF_MIN_FEE_BUMP_PERCENT
#define MIQ_RBF_MIN_FEE_BUMP_PERCENT 10  // Minimum fee bump for RBF
#endif

// === COMPACT BLOCK RELAY (BIP 152) ===
#ifndef MIQ_COMPACT_BLOCKS_ENABLED
#define MIQ_COMPACT_BLOCKS_ENABLED 1  // Enable compact block relay
#endif
#ifndef MIQ_COMPACT_BLOCK_HIGH_BANDWIDTH
#define MIQ_COMPACT_BLOCK_HIGH_BANDWIDTH 3  // High-bandwidth compact block peers
#endif

// === TRANSACTION RELAY OPTIMIZATION (V1 HIGH-THROUGHPUT) ===
#ifndef MIQ_TX_FLOOD_PROTECTION
#define MIQ_TX_FLOOD_PROTECTION 1  // Enable transaction flood protection
#endif
#ifndef MIQ_TX_RELAY_RATE_LIMIT_PER_PEER
#define MIQ_TX_RELAY_RATE_LIMIT_PER_PEER 100  // V1: Increased from 7 to 100 txs per second per peer
#endif
#ifndef MIQ_TX_RELAY_BURST_LIMIT
#define MIQ_TX_RELAY_BURST_LIMIT 500  // V1: Allow burst of up to 500 txs before rate limiting kicks in
#endif

}

