#include "difficulty.h"
#include "constants.h"   // for BLOCK_TIME_SECS / GENESIS_BITS if callers pass those
#include "log.h"         // for log_info
#include <cstdint>
#include <cstddef>
#include <vector>
#include <utility>
#include <sstream>

namespace miq {

// =============================================================================
// DIFFICULTY FIX ACTIVATION HEIGHT
// =============================================================================
// The original LWMA algorithm had a bug that prevented difficulty from decreasing
// (target couldn't increase when blocks were slow). This was fixed with proper
// 256-bit arithmetic, but changing the algorithm would invalidate existing blocks.
//
// Solution: Use legacy algorithm for blocks BELOW this height (preserves consensus),
// use fixed algorithm for blocks AT OR ABOVE this height (fixes future difficulty).
//
// Your chain history: Diff 1.0 → 25.5 → 255.5 → stuck
// Current tip: ~7884 (epoch 3 boundary)
// Next epoch: 10512 (epoch 4 boundary)
//
// Set this to the NEXT EPOCH BOUNDARY after your current tip to ensure:
// - All existing blocks validate with legacy algorithm
// - All future epoch calculations use the fixed algorithm
// =============================================================================
static constexpr uint64_t DIFFICULTY_FIX_ACTIVATION_HEIGHT = 10512;

// Convert big-endian 32-byte target -> compact "bits"
static inline uint32_t compact_from_target(const unsigned char* t) {
    int i = 0;
    while (i < 32 && t[i] == 0) ++i;
    if (i == 32) return 0;

    uint32_t exp = 32 - i;
    // Read up to 3 mantissa bytes safely (pad with zeros at the end).
    uint32_t b0 = t[i];
    uint32_t b1 = (i + 1 < 32) ? t[i + 1] : 0;
    uint32_t b2 = (i + 2 < 32) ? t[i + 2] : 0;
    uint32_t mant = (b0 << 16) | (b1 << 8) | b2;

    return (exp << 24) | (mant & 0x007fffff);
}

// Convert compact "bits" -> big-endian 32-byte target
static inline void target_from_compact(uint32_t bits, unsigned char* out) {
    for (int i = 0; i < 32; i++) out[i] = 0;

    uint32_t exp  = bits >> 24;
    uint32_t mant = bits & 0x007fffff;

    if (exp <= 3) {
        uint32_t v = mant >> (8 * (3 - exp));
        out[29] = (unsigned char)((v >> 16) & 0xff);
        out[30] = (unsigned char)((v >> 8)  & 0xff);
        out[31] = (unsigned char)(v & 0xff);
    } else {
        // idx in [0,29] for well-formed inputs; clamp to avoid UB on malformed bits.
        int idx = 32 - (int)exp;
        if (idx < 0)  idx = 0;
        if (idx > 29) idx = 29;
        out[idx + 0] = (unsigned char)((mant >> 16) & 0xff);
        out[idx + 1] = (unsigned char)((mant >> 8)  & 0xff);
        out[idx + 2] = (unsigned char)(mant & 0xff);
    }
}

// =============================================================================
// FIXED: Proper 256-bit multiplication with carry propagation
// =============================================================================
// The original algorithm had a critical bug: each byte was scaled individually
// and capped at 255, with NO carry propagation. This meant:
// - ratio < 1 (fast blocks): target decreases correctly
// - ratio > 1 (slow blocks): target CAN'T increase (bytes cap at 0xFF)
//
// This fix uses proper big-integer arithmetic:
// 1. Multiply entire 256-bit target by numerator
// 2. Divide by denominator with proper long division
// 3. Handle carry/borrow correctly across all bytes
// =============================================================================
static void target_multiply_ratio(unsigned char t[32], uint64_t num, uint64_t denom) {
    if (denom == 0) return;
    if (num == denom) return;  // ratio = 1, no change

    // Step 1: Multiply target by numerator (with carry propagation)
    // Process LSB to MSB for correct carry handling
    uint64_t carry = 0;
    for (int i = 31; i >= 0; --i) {
        uint64_t val = (uint64_t)t[i] * num + carry;
        t[i] = (unsigned char)(val % 256);
        carry = val / 256;
    }

    // Handle overflow (carry left over after MSB)
    // If there's overflow, we need to shift right and adjust
    if (carry > 0) {
        // Overflow occurred - the target is larger than 256 bits
        // Shift right by the number of overflow bytes and fill MSB
        // For simplicity, if we overflow significantly, cap at max target
        // This is safe because max target = easiest difficulty
        for (int i = 0; i < 32; ++i) t[i] = 0xFF;
        return;
    }

    // Step 2: Divide target by denominator (with proper long division)
    // Process MSB to LSB for correct remainder handling
    uint64_t remainder = 0;
    for (int i = 0; i < 32; ++i) {
        uint64_t val = remainder * 256 + t[i];
        t[i] = (unsigned char)(val / denom);
        remainder = val % denom;
    }
}

// =============================================================================
// LEGACY LWMA Algorithm (for blocks < DIFFICULTY_FIX_ACTIVATION_HEIGHT)
// =============================================================================
// This is the original buggy algorithm that was used for blocks 0-10511.
// It has a bug where each byte is scaled individually and capped at 255,
// preventing the target from increasing when blocks are slow.
// We MUST keep this for consensus compatibility with existing blocks.
// =============================================================================
static uint32_t lwma_next_bits_legacy(const std::vector<std::pair<int64_t, uint32_t>>& last,
                                       int64_t target_spacing, uint32_t min_bits) {
    if (last.size() < 2) return min_bits;

    size_t window = (last.size() < 90) ? last.size() : 90;
    int64_t sum = 0;

    for (size_t i = last.size() - window + 1; i < last.size(); ++i) {
        int64_t dt = last[i].first - last[i - 1].first;
        if (dt < 1) dt = 1;
        int64_t cap = target_spacing * 10;
        if (dt > cap) dt = cap;
        sum += dt;
    }

    int64_t avg = sum / (int64_t)(window - 1);

    unsigned char t[32];
    target_from_compact(last.back().second, t);

    // LEGACY: Buggy byte-by-byte scaling with cap at 255 (no carry propagation)
    // This is WRONG but must be kept for consensus with existing blocks
    for (int i = 31; i >= 0; --i) {
        unsigned int v = t[i];
        v = (unsigned int)((uint64_t)v * (uint64_t)avg / (uint64_t)target_spacing);
        if (v > 255U) v = 255U;  // BUG: caps at 255, no carry!
        t[i] = (unsigned char)v;
    }

    return compact_from_target(t);
}

// =============================================================================
// FIXED LWMA Algorithm (for blocks >= DIFFICULTY_FIX_ACTIVATION_HEIGHT)
// =============================================================================
// Uses proper 256-bit arithmetic with carry propagation.
// This correctly handles both increasing AND decreasing difficulty.
// =============================================================================
static uint32_t lwma_next_bits_fixed(const std::vector<std::pair<int64_t, uint32_t>>& last,
                                      int64_t target_spacing, uint32_t min_bits) {
    if (last.size() < 2) return min_bits;

    size_t window = (last.size() < 90) ? last.size() : 90;
    int64_t sum = 0;

    // Sum clamped inter-block times over the window
    for (size_t i = last.size() - window + 1; i < last.size(); ++i) {
        int64_t dt = last[i].first - last[i - 1].first;
        if (dt < 1) dt = 1;
        int64_t cap = target_spacing * 10;
        if (dt > cap) dt = cap;
        sum += dt;
    }

    int64_t avg = sum / (int64_t)(window - 1);

    // Get current target
    unsigned char t[32];
    target_from_compact(last.back().second, t);

    // DEBUG: Log difficulty calculation details
    {
        std::ostringstream oss;
        oss << "LWMA_FIXED: window=" << window << " sum=" << sum << " avg=" << avg
            << " target_spacing=" << target_spacing << " ratio=" << (double)avg/(double)target_spacing
            << " prev_bits=0x" << std::hex << last.back().second;
        log_info(oss.str());
    }

    // FIXED: Use proper 256-bit arithmetic
    target_multiply_ratio(t, (uint64_t)avg, (uint64_t)target_spacing);

    // Ensure target doesn't exceed max (min difficulty)
    unsigned char max_target[32];
    target_from_compact(min_bits, max_target);

    // Compare: if t > max_target, cap at max_target
    for (int i = 0; i < 32; ++i) {
        if (t[i] > max_target[i]) {
            return min_bits;
        } else if (t[i] < max_target[i]) {
            break;
        }
    }

    // Ensure target isn't zero
    bool is_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (t[i] != 0) { is_zero = false; break; }
    }
    if (is_zero) t[31] = 1;

    uint32_t result = compact_from_target(t);

    // DEBUG: Log result
    {
        std::ostringstream oss;
        oss << "LWMA_FIXED: result_bits=0x" << std::hex << result;
        log_info(oss.str());
    }

    return result;
}

// --- Public LWMA function (delegates based on use_fixed flag) ---
uint32_t lwma_next_bits(const std::vector<std::pair<int64_t, uint32_t>>& last,
                        int64_t target_spacing, uint32_t min_bits) {
    // Default to legacy for backward compatibility when called without height context
    return lwma_next_bits_legacy(last, target_spacing, min_bits);
}

// --- Epoch retarget: freeze inside epoch; adjust only at boundary ---
uint32_t epoch_next_bits(const std::vector<std::pair<int64_t, uint32_t>>& last,
                         int64_t target_spacing,
                         uint32_t min_bits,
                         uint64_t next_height,
                         size_t interval) {
    // Determine which algorithm to use based on activation height
    const bool use_fixed = (next_height >= DIFFICULTY_FIX_ACTIVATION_HEIGHT);

    // DEBUG: Log epoch_next_bits call
    {
        std::ostringstream oss;
        oss << "epoch_next_bits: next_height=" << next_height
            << " interval=" << interval
            << " last.size()=" << last.size()
            << " at_boundary=" << ((next_height % interval) == 0 ? "YES" : "no")
            << " algorithm=" << (use_fixed ? "FIXED" : "LEGACY");
        log_info(oss.str());
    }

    // If not at a boundary, keep current bits (freeze difficulty).
    if (!last.empty() && (next_height % interval) != 0) {
        return last.back().second;
    }

    // At boundary: compute new bits using the last `interval` headers
    if (last.size() < 2) {
        // No history? stick with min_bits / genesis
        return last.empty() ? min_bits : last.back().second;
    }

    // Select algorithm based on activation height
    auto compute_bits = use_fixed ? lwma_next_bits_fixed : lwma_next_bits_legacy;

    if (last.size() > interval) {
        // Use only the last `interval` headers to determine the new target
        log_info("epoch_next_bits: using tail of " + std::to_string(interval) + " headers");
        std::vector<std::pair<int64_t, uint32_t>> tail(last.end() - interval, last.end());
        return compute_bits(tail, target_spacing, min_bits);
    } else {
        log_info("epoch_next_bits: using all " + std::to_string(last.size()) + " headers");
        return compute_bits(last, target_spacing, min_bits);
    }
}

}
