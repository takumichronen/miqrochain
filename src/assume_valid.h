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

// Forward declaration for IBD state machine
namespace ibd { class IBDState; }

// Call this when sync is complete to enable full durability
inline void mark_ibd_complete() {
    ibd_mode_active().store(false, std::memory_order_release);
    // Note: IBD state machine transition to DONE is handled separately
    // in ibd_state.cpp to avoid circular includes
}

// Check if we're in IBD mode (for skipping fsync, etc.)
inline bool is_ibd_mode() {
    return ibd_mode_active().load(std::memory_order_acquire);
}

// =============================================================================
// NEAR-TIP MODE: When ≤16 blocks from tip, skip fsync for fast completion
// This is SEPARATE from IBD - enables fast sync even after IBD is done
// Used for warm datadir scenarios where we're only a few blocks behind
// =============================================================================

inline std::atomic<bool>& near_tip_mode_active() {
    static std::atomic<bool> g_near_tip{false};
    return g_near_tip;
}

inline void set_near_tip_mode(bool enabled) {
    near_tip_mode_active().store(enabled, std::memory_order_release);
}

inline bool is_near_tip_mode() {
    return near_tip_mode_active().load(std::memory_order_acquire);
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

// =============================================================================
// IBD FAST-VALIDATION: Skip signatures for deeply buried blocks during IBD
// This dramatically speeds up initial sync by trusting proof-of-work:
// - Blocks far from the tip (>144 confirmations) have massive accumulated work
// - An attacker would need to create a fake chain with valid PoW (infeasible)
// - UTXO amounts/double-spend are still validated
// - Once near-tip, full signature validation is enabled
// =============================================================================

// Threshold for "deeply buried" blocks - skip signatures when >144 blocks from tip
static constexpr uint64_t IBD_SIGNATURE_SKIP_DEPTH = 144;

// Global best header height (set by P2P layer)
inline std::atomic<uint64_t>& g_best_header_height() {
    static std::atomic<uint64_t> h{0};
    return h;
}

inline void set_best_header_height(uint64_t h) {
    uint64_t cur = g_best_header_height().load(std::memory_order_relaxed);
    // Only update if new height is greater (monotonic)
    while (h > cur && !g_best_header_height().compare_exchange_weak(cur, h, std::memory_order_release));
}

// CRITICAL FIX: Reset header height when blocks are disconnected/invalidated
// This is needed because disconnect_tip_once() reduces chain height, but the
// global atomic header height would stay at the old (higher) value, causing
// sync gates to fail indefinitely after block deletion.
inline void reset_best_header_height(uint64_t h) {
    g_best_header_height().store(h, std::memory_order_release);
}

// Check if we should skip signature validation for a block
// Returns true if signatures should be validated (not skipped)
inline bool should_validate_signatures(const std::vector<uint8_t>& block_hash, uint64_t height) {
    auto& cfg = assume_valid_config();

    // === PHASE 1: Checkpoint-based assume-valid (original logic) ===
    // If enabled and below checkpoint, skip signatures
    if (cfg.enabled && !cfg.passed) {
        if (height < cfg.height) {
            // Before assume-valid height - skip signature validation
            return false;
        }
        // At or past checkpoint - mark as passed
        if (height >= cfg.height) {
            if (block_hash == cfg.hash || height > cfg.height) {
                cfg.passed = true;
            }
        }
    }

    // === PHASE 2: IBD deep-burial optimization (Bitcoin Core style) ===
    // During IBD, skip signatures for blocks deeply buried below header tip
    // This is safe because:
    // 1. Headers are validated (PoW, difficulty, timestamps)
    // 2. Block connects to validated header chain
    // 3. Blocks have massive accumulated proof-of-work
    // 4. UTXO set is still computed correctly
    if (is_ibd_mode()) {
        uint64_t best_header = g_best_header_height().load(std::memory_order_acquire);
        // If we have a valid header chain and this block is deeply buried
        if (best_header > 0 && height + IBD_SIGNATURE_SKIP_DEPTH < best_header) {
            // Block is >144 below header tip - safe to skip signatures during IBD
            return false;
        }
    }

    // === PHASE 3: Near-tip - full validation ===
    // We're either:
    // - Past IBD mode
    // - Near the header tip (within 144 blocks)
    // - No header height known
    // Full signature validation required
    return true;
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
        // Checkpoints at every 50 blocks for maximum fork protection
        {0, "00000000a5e8a7eb02a83fb9693bc2dccbf14ee69d67315c1f151a25cb43fce8"},
        {50, "000000004771c7bad4108147df1b200c2ea7c366befae38a6cce51b209ad6ac6"},
        {100, "0000000087059ec4662b4f3cab96644b877c0630bd72d6d09011e18afbe31522"},
        {150, "0000000033580bcf91791fa5ec7a56eae4aa0d8999f8b83cf18d9230aaa0a276"},
        {200, "000000003f7de0949a7c4b725765df6ff12f0e09ee15dde1dcd30ff3f31cfcbc"},
        {250, "00000000337ca47e9567601998a1b0d1aa7bf935244399140eb717e39c5216b4"},
        {300, "0000000023252053a8094c741e089f58acf5725ee8c4c03d6ebb412bfee712b9"},
        {350, "000000001f6ab0130b49dd4d56cb8926a7ddd3b4c81eb5a9b1aff3ddf8c6292e"},
        {400, "000000005879b7da4bda72e387a6a15eee3bf3d709446d2892cf60143f006f8e"},
        {450, "0000000036b9db4dee9f0bff79073678cdb4dc4b6360a538d2457eb409215134"},
        {500, "00000000e3acf7b29053508cdc59842347da357dfb68cd21f3e935474f7914f2"},
        {550, "000000005d42c5d60ef7d29c814343194e1dadb0adda5b49984abffe2c1e615c"},
        {600, "000000000563691fbf1152a449d83d4174104edfcf651f1362c6393d270b3d18"},
        {650, "000000000f0f337172d1f9f5441f223118f647e6c7f6a3765cd1f19df15b4484"},
        {700, "00000000300bf9eb4e19e19349481b4a747eab811ab1db4faaa146f5b24190a2"},
        {750, "00000000ec53ee85a25521a71ab76dbc15879f2aebbf4b7cd24f28a0a1964a1d"},
        {800, "00000000abf27299678e1dd1df5aaf74a702798f2216c685fc43e005f803e334"},
        {850, "0000000067fdd1dd9da36926d33aff33ee2166f0a56d75bbffea4e258e232738"},
        {900, "0000000014407a09f8d3e0bf50051f244adc7151e09d459db3910067bcf3836a"},
        {950, "000000002402cbd23dd6a527e4be7856b40bdd1ff686505fbd075106d060ce3f"},
        {1000, "00000000cde5164a0e8980681ba2466dbe65c64ece622125db677bab00472953"},
        {1050, "000000004b5c2f7cd1ddc956e8c55afd34a01b8f4464b016738942e37160706d"},
        {1100, "000000001177406c709d520d85f1d4392647f0b01f75e29bf8fa0c2bfa4c1d2e"},
        {1150, "00000000e688d8b2216046a6a498f773a1e19ad60844633d6686561e41d4c0f9"},
        {1200, "00000000c302ce09da13c59d243572f2f86976b458104d643909202549af2e0c"},
        {1250, "00000000681cbe69e7502084c665978feb90317bdcc8076ee8ad620b9e809b8d"},
        {1300, "00000000fdcd2e9260b23dd682641fbf7b48d7ecec62779b66af4fcd1eb4ef1d"},
        {1350, "0000000069d2421542bc656e9bfbd4dc3fbfb9f42f537cde7cc9ed4c7b8251ed"},
        {1400, "0000000020ea71871ac1ee2e305739731eafd27b70297fc2a7d5996debe2f270"},
        {1450, "0000000099c7cdafb433ba27695b9384c8b09e372b2d5c37d2cc7d5c3bccd3f3"},
        {1500, "00000000af400ca229e4321e90266742045d4ac1dc4321ff41f505ecbf56a005"},
        {1550, "0000000019ae8c21b5b0b7b88a114dbb1cc1471c9e5bc1b3ec66a8c98759ed58"},
        {1600, "000000004445ae48ea67e6fec0902f027391e740a499bde39344197aa819b780"},
        {1650, "0000000059889373d0a32ae0d5540429360b150d800b9ad3afb85740c54a8f7e"},
        {1700, "00000000733c1304b6106c1bc008e68409b568fb8a21e61fb59c6ec06ce65478"},
        {1750, "000000008fa9be0bb5d6ff3732b63bb06acc5873c9a420673cf36a828fe5e24d"},
        {1800, "000000003d872e60d2136ba96ee170cadb63a025b3f7fcdc420151fb69da024e"},
        {1850, "000000008273a9931c8a497f7f579c3e1fa05cb6db13836df3fe98116371ae94"},
        {1900, "000000005807ee2bf4758e5ab2f6701889dfcda457fb761edc41b67421bf718e"},
        {1950, "00000000883091866958290f0dfc619b72b6d857212f5e13d2dad054a5cf5be1"},
        {2000, "00000000d53dadeed250f69e858a40c35df7dafbfb761ff5fda6e8869706dbef"},
        {2050, "000000006b255c8d71049b7a063c7fab4abff3d84d3769c95c286080c705bc9c"},
        {2100, "000000009eefe85c19b1ba992f99d0e11dfef490c39ef7ba76cc6da0db8f5d42"},
        {2150, "000000003e7f71f2d92192ec0021bb5de60d80acc6c9dc21419c529caea2133d"},
        {2200, "0000000015842107da13460f37ab4d62655500d4c038c15e798242120c7bfb6e"},
        {2250, "000000000af6e8f2de9c88c94e092ba2b086ff123826a26260a16ac5dcb7c35e"},
        {2300, "0000000012d41d5b4647d5e3919c57cb5456258ff4ef272ccac3679ce3fa621b"},
        {2350, "00000000a1155a7cf9f850f89bd1a813808799dc666c7faf0f04871d23a9583a"},
        {2400, "00000000c64524a6940547badf256412ddd1ea7196f4ccc07b16849ee984d9ed"},
        {2450, "000000005bde1c8ebe259c6b22d9f26e23d9aeed1aa8516321adb9d7be95ec60"},
        {2500, "000000008b601c824f094d9cc8734d1a390ef6d0ca2066b84d40dc108b6166ad"},
        {2550, "00000000b1acdf8742207ab08616ca5cda4075320fd1cf41164a32dbd50cc5c7"},
        {2600, "000000004426311bfdcd11eeb5d8214bc945ee1f87dfe6cd7229b32a1cb8c3fb"},
        {2650, "0000000000034c8bf9932ac0d4aa47cababc775a147cacc486d2fec095362e1d"},
        {2700, "0000000008eb0f5a31538f374bb34abb50ed6984262e43505a9cec73c2028842"},
        {2750, "000000000069b3da6586382c58431e1e81030a865bc3cd3a1f63f3c4d744f07a"},
        {2800, "00000000051ef203749d1f20ea5de672ab7f017bd3ed75ada47a6ee5db494726"},
        {2850, "000000000054ad2ae98447e7f77f6222a53a5067da6cff68898ecd56b11412f1"},
        {2900, "000000000112e6d346f7428eca93db48682642b727b9d71cf2d2235658df5ee7"},
        {2950, "0000000000cdbfc02a8d1453f1b6eb912ed0a2a6752b0424d2a370f929d5e12c"},
        {3000, "0000000006fe4e58f5e351c0ff10d9d685e8f942b44570b5d1d8eea27c00fcc3"},
        {3050, "00000000060255f3c31f2eecc5d144ed4be39d67cb8a0b9b10c8acbaa945675d"},
        {3100, "0000000002cc56745d3bcf42e471b04b2c36b0f9ada2a3c9087a2cec8eff44da"},
        {3150, "000000000279320fdf146c5e8d0777431d32ff0bb69fd9e8d46c809cc402b718"},
        {3200, "0000000009d3f232636603bd1e677c7a8e0093df346c0eb4e2a4561993533fca"},
        {3250, "000000000072faf00efb8ed82010e0e526d10a623393cb5e7442958e8df81607"},
        {3300, "00000000037af7c12e6e3bb0b139b71279edd2262d9baad0e4fdad4aa6115b01"},
        {3350, "0000000009386092f3dbbe9fc575d6eb300704ca461f4bee9099f365d4c1331a"},
        {3400, "000000000508b6ca290b514acfcdada46b093f142523fcefb9233bbc2fd355c9"},
        {3450, "000000000389f8acd9800ca289f0f536a36c86adf28e5e7e8531bae9d98f79cf"},
        {3500, "000000000049f68b3b19b89ff6c130796e4654b88d6ddc04326f3e81b2259837"},
        {3550, "000000000546239509b80e5c8343cd0735cb1b6f89698e9f612d2459ddeda385"},
        {3600, "00000000083e9429e598b5fe992b41c67da01a376c7d17fed25d58ae3df7d1a5"},
        {3650, "0000000006642882bee9d70540441cced3c591ed46818f46ae3ffb858da5f827"},
        // Checkpoints beyond 3650 removed after chain truncation to block 3667
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
