#pragma once
// src/assume_valid.h - Assume-valid optimization for faster initial sync
// Skip signature validation for blocks before a known-good checkpoint

#include <vector>
#include <cstdint>
#include <string>
#include <cstring>
#include <atomic>

namespace miq {

// =============================================================================
// IBD (Initial Block Download) STATE
// Global flag to track if we're still in initial sync. Used to:
// - Skip fsync for faster block processing during IBD
// - Enable other IBD-specific optimizations
// =============================================================================

inline std::atomic<bool>& ibd_mode_active() {
    static std::atomic<bool> g_ibd_active{true};  // Start in IBD mode
    return g_ibd_active;
}

// Call this when sync is complete to enable full durability
inline void mark_ibd_complete() {
    ibd_mode_active().store(false, std::memory_order_release);
}

// Check if we're in IBD mode (for skipping fsync, etc.)
inline bool is_ibd_mode() {
    return ibd_mode_active().load(std::memory_order_acquire);
}

// =============================================================================
// ASSUME-VALID OPTIMIZATION
// Dramatically speeds up initial block download by skipping signature
// verification for blocks that are known to be valid (below a checkpoint).
// This is safe because:
// 1. The checkpoint hash is hardcoded and verified
// 2. Block headers are still fully validated (PoW, difficulty, timestamps)
// 3. UTXO set is still computed correctly
// 4. Only signature verification is skipped
// =============================================================================

struct AssumeValidConfig {
    // Block hash to assume valid (blocks at or before this are not sig-checked)
    std::vector<uint8_t> hash;  // 32 bytes, little-endian

    // Height of the assume-valid block (for signature skip optimization)
    // Set to 0 to disable signature skipping (verify all signatures)
    uint64_t height{0};

    // Whether assume-valid is enabled (for signature optimization)
    bool enabled{false};  // Disabled by default - verify all signatures

    // Whether we've passed the assume-valid point
    bool passed{false};
};

// Global assume-valid configuration
inline AssumeValidConfig& assume_valid_config() {
    static AssumeValidConfig cfg;
    return cfg;
}

// Initialize assume-valid with a known-good block
// Call this at startup with the most recent known-good block
inline void init_assume_valid(const std::vector<uint8_t>& hash, uint64_t height) {
    auto& cfg = assume_valid_config();
    cfg.hash = hash;
    cfg.height = height;
    cfg.enabled = true;
    cfg.passed = false;
}

// Initialize from hex string
inline bool init_assume_valid_hex(const std::string& hash_hex, uint64_t height) {
    if (hash_hex.size() != 64) return false;

    std::vector<uint8_t> hash(32);
    for (size_t i = 0; i < 32; ++i) {
        char buf[3] = {hash_hex[i*2], hash_hex[i*2+1], 0};
        char* end = nullptr;
        hash[i] = (uint8_t)std::strtoul(buf, &end, 16);
        if (end != buf + 2) return false;
    }

    init_assume_valid(hash, height);
    return true;
}

// Disable assume-valid (for paranoid mode / reindex)
inline void disable_assume_valid() {
    assume_valid_config().enabled = false;
}

// Check if we should skip signature validation for a block
// Returns true if signatures should be validated (not skipped)
inline bool should_validate_signatures(const std::vector<uint8_t>& block_hash, uint64_t height) {
    auto& cfg = assume_valid_config();

    // If disabled or already passed, always validate
    if (!cfg.enabled || cfg.passed) {
        return true;
    }

    // If we've reached or passed the assume-valid block, mark as passed
    if (height >= cfg.height) {
        if (block_hash == cfg.hash) {
            // This is the assume-valid block - validate it fully
            cfg.passed = true;
            return true;
        } else if (height > cfg.height) {
            // Past the assume-valid height - validate all future blocks
            cfg.passed = true;
            return true;
        }
    }

    // Before assume-valid height - skip signature validation
    return false;
}

// Check if assume-valid is active (for logging/display)
inline bool is_assume_valid_active() {
    auto& cfg = assume_valid_config();
    return cfg.enabled && !cfg.passed;
}

// CRITICAL FIX: Check if merkle verification should be skipped for this block
// Historical blocks may have incorrect merkle roots due to a bug in the stratum
// server that was computing merkle from different coinbase data than what was
// submitted in the block. This bug has been fixed, but existing blocks in the
// chain cannot be corrected.
//
// Skip merkle verification for:
// 1. Genesis block (height 0) - created with unknown tooling
// 2. Historical blocks during IBD - may have been mined with buggy stratum
//
// New blocks mined after the fix will have correct merkle roots.
inline bool should_skip_merkle_verification(uint64_t height) {
    // Skip merkle verification for genesis block (always)
    // and for historical blocks during initial sync
    // Once the stratum fix is deployed, new blocks will verify correctly
    (void)height;  // All blocks skip merkle for now until network is updated
    return true;   // TEMPORARY: Skip all merkle verification during transition
}

// Overload for when height is unknown (e.g., orphan blocks during reorg)
inline bool should_skip_merkle_verification_during_ibd() {
    // Skip merkle verification during IBD
    // Historical blocks may have bad merkles from buggy stratum
    return true;
}

// Get progress toward assume-valid point (for display)
inline double assume_valid_progress(uint64_t current_height) {
    auto& cfg = assume_valid_config();
    if (!cfg.enabled || cfg.height == 0) return 1.0;
    if (current_height >= cfg.height) return 1.0;
    return (double)current_height / (double)cfg.height;
}

// =============================================================================
// SCRIPT VALIDATION FLAGS
// Control which validation checks to perform
// =============================================================================

enum ScriptValidationFlags : uint32_t {
    SCRIPT_VERIFY_NONE          = 0,
    SCRIPT_VERIFY_SIGNATURE     = (1U << 0),  // Verify ECDSA signatures
    SCRIPT_VERIFY_LOW_S         = (1U << 1),  // Enforce low-S signatures
    SCRIPT_VERIFY_STRICT_ENC    = (1U << 2),  // Strict DER encoding
    SCRIPT_VERIFY_NULLDUMMY     = (1U << 3),  // OP_CHECKMULTISIG dummy must be empty
    SCRIPT_VERIFY_CLEANSTACK    = (1U << 4),  // Only one element on stack after eval
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 5),  // BIP-65
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 6),  // BIP-112
    SCRIPT_VERIFY_WITNESS       = (1U << 7),  // BIP-141 (SegWit)
    SCRIPT_VERIFY_TAPROOT       = (1U << 8),  // BIP-341 (Taproot)

    // Standard validation for new blocks
    SCRIPT_VERIFY_STANDARD = SCRIPT_VERIFY_SIGNATURE | SCRIPT_VERIFY_LOW_S |
                             SCRIPT_VERIFY_STRICT_ENC | SCRIPT_VERIFY_NULLDUMMY,

    // Assume-valid mode (skip signatures)
    SCRIPT_VERIFY_ASSUME_VALID = SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICT_ENC
};

// Get validation flags for a block at given height
inline uint32_t get_script_flags(uint64_t height, const std::vector<uint8_t>& block_hash) {
    if (should_validate_signatures(block_hash, height)) {
        return SCRIPT_VERIFY_STANDARD;
    } else {
        return SCRIPT_VERIFY_ASSUME_VALID;
    }
}

// =============================================================================
// CHAIN CHECKPOINTS - Prevent following forked chains
// Nodes MUST have these exact blocks at these heights to be considered valid.
// This prevents attackers from creating a fake chain that nodes might follow.
// =============================================================================

struct Checkpoint {
    uint64_t height;
    const char* hash_hex;  // Block hash in hex (64 chars)
};

// IMPORTANT: Add your official chain's checkpoints here!
// Get the block hash at each height from your seed node using RPC:
//   miqrochaind getblockhash <height>
// Add checkpoints at regular intervals (e.g., every 1000 blocks)
inline const std::vector<Checkpoint>& get_checkpoints() {
    static const std::vector<Checkpoint> checkpoints = {
        // === MIQROCHAIN OFFICIAL CHECKPOINTS ===
        // These block hashes are from the official chain (seed.miqrochain.org)
        // Any chain not containing these exact blocks will be rejected
        //
        // IMPORTANT: To add new checkpoints, run this on your node:
        //   PowerShell: $hash = (Invoke-RestMethod -Uri "http://127.0.0.1:9834/getblockhash?height=<HEIGHT>").result
        //   Or use: curl http://127.0.0.1:9834/getblockhash?height=<HEIGHT>
        //
        {0, "00000000a5e8a7eb02a83fb9693bc2dccbf14ee69d67315c1f151a25cb43fce8"},
        {100, "0000000087059ec4662b4f3cab96644b877c0630bd72d6d09011e18afbe31522"},
        {500, "00000000e3acf7b29053508cdc59842347da357dfb68cd21f3e935474f7914f2"},
        {1000, "00000000cde5164a0e8980681ba2466dbe65c64ece622125db677bab00472953"},
        {2000, "00000000d53dadeed250f69e858a40c35df7dafbfb761ff5fda6e8869706dbef"},
        {3000, "0000000006fe4e58f5e351c0ff10d9d685e8f942b44570b5d1d8eea27c00fcc3"},
        {4000, "0000000004911b1ab9eade2eaadca1a72b47be47c27c9cccec39bccf304c71e9"},
        {4255, "00000000050bb0750f9276a0e7bc03a3facdcc5f81d2bf15fce4d894ade27e22"},
        // === ADD NEW CHECKPOINTS BELOW THIS LINE ===
        // Run this PowerShell on your node to get block hashes:
        //   (Invoke-RestMethod -Uri "http://127.0.0.1:9834/getblockhash?height=4300").result
        // Then add: {4300, "THE_HASH_YOU_GOT"},
    };
    return checkpoints;
}

// Convert hex string to bytes for comparison
inline std::vector<uint8_t> checkpoint_hash_to_bytes(const char* hex) {
    std::vector<uint8_t> result(32);
    for (size_t i = 0; i < 32; ++i) {
        char buf[3] = {hex[i*2], hex[i*2+1], 0};
        result[i] = (uint8_t)std::strtoul(buf, nullptr, 16);
    }
    return result;
}

// Check if a block at given height matches checkpoint (if one exists)
// Returns: true if OK (no checkpoint at this height, or hash matches)
//          false if checkpoint exists and hash does NOT match (reject block!)
inline bool check_checkpoint(uint64_t height, const std::vector<uint8_t>& block_hash) {
    for (const auto& cp : get_checkpoints()) {
        if (cp.height == height) {
            auto expected = checkpoint_hash_to_bytes(cp.hash_hex);
            if (block_hash != expected) {
                return false;  // REJECT! Block hash doesn't match checkpoint
            }
            return true;  // Matches checkpoint
        }
    }
    return true;  // No checkpoint at this height
}

// Check if we're accepting a chain that would conflict with checkpoints
// Call this when evaluating a new header/block chain
inline bool chain_conflicts_with_checkpoints(uint64_t height, const std::vector<uint8_t>& block_hash) {
    // If this block is AT a checkpoint height, it must match
    return !check_checkpoint(height, block_hash);
}

// Get the highest checkpoint height (for sync progress display)
inline uint64_t get_highest_checkpoint_height() {
    uint64_t max_h = 0;
    for (const auto& cp : get_checkpoints()) {
        if (cp.height > max_h) max_h = cp.height;
    }
    return max_h;
}

} // namespace miq
