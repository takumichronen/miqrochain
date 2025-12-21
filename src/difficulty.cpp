#include "difficulty.h"
#include "constants.h"   // for BLOCK_TIME_SECS / GENESIS_BITS if callers pass those
#include "log.h"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <utility>
#include <sstream>

namespace miq {

// =============================================================================
// DIFFICULTY FIX ACTIVATION HEIGHT
// =============================================================================
// The original LWMA has a bug that prevents difficulty from decreasing.
// At this height, we switch to a fixed algorithm.
// Set to next epoch boundary (10512 = 2628 * 4) to preserve existing chain.
// =============================================================================
static constexpr uint64_t DIFFICULTY_FIX_HEIGHT = 10512;

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
// ORIGINAL LWMA - DO NOT MODIFY! Used for blocks < DIFFICULTY_FIX_HEIGHT
// =============================================================================
// This has a known bug (byte capping) but must be kept for consensus.
// =============================================================================
uint32_t lwma_next_bits(const std::vector<std::pair<int64_t, uint32_t>>& last,
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

    // Scale target by avg/target_spacing in big-endian space
    unsigned char t[32];
    target_from_compact(last.back().second, t);

    for (int i = 31; i >= 0; --i) {
        unsigned int v = t[i];
        v = (unsigned int)((uint64_t)v * (uint64_t)avg / (uint64_t)target_spacing);
        if (v > 255U) v = 255U;
        t[i] = (unsigned char)v;
    }
    return compact_from_target(t);
}

// =============================================================================
// FIXED: Proper 256-bit target scaling (for blocks >= DIFFICULTY_FIX_HEIGHT)
// =============================================================================
static void target_scale_256bit(unsigned char t[32], uint64_t num, uint64_t denom) {
    if (denom == 0 || num == denom) return;

    // Multiply with carry (LSB to MSB)
    uint64_t carry = 0;
    for (int i = 31; i >= 0; --i) {
        uint64_t v = (uint64_t)t[i] * num + carry;
        t[i] = (unsigned char)(v & 0xFF);
        carry = v >> 8;
    }
    // Handle overflow
    if (carry > 0) {
        for (int i = 0; i < 32; ++i) t[i] = 0xFF;
        return;
    }

    // Divide with remainder (MSB to LSB)
    uint64_t rem = 0;
    for (int i = 0; i < 32; ++i) {
        uint64_t v = (rem << 8) | t[i];
        t[i] = (unsigned char)(v / denom);
        rem = v % denom;
    }
}

// =============================================================================
// FIXED LWMA - Uses proper 256-bit arithmetic (for blocks >= DIFFICULTY_FIX_HEIGHT)
// =============================================================================
static uint32_t lwma_next_bits_fixed(const std::vector<std::pair<int64_t, uint32_t>>& last,
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

    // FIXED: Proper 256-bit scaling
    target_scale_256bit(t, (uint64_t)avg, (uint64_t)target_spacing);

    // Cap at max target (min difficulty)
    unsigned char max_t[32];
    target_from_compact(min_bits, max_t);
    for (int i = 0; i < 32; ++i) {
        if (t[i] > max_t[i]) return min_bits;
        if (t[i] < max_t[i]) break;
    }

    // Don't allow zero target
    bool zero = true;
    for (int i = 0; i < 32; ++i) if (t[i]) { zero = false; break; }
    if (zero) t[31] = 1;

    return compact_from_target(t);
}

// =============================================================================
// Epoch retarget: adjust every `interval` blocks
// =============================================================================
uint32_t epoch_next_bits(const std::vector<std::pair<int64_t, uint32_t>>& last,
                         int64_t target_spacing,
                         uint32_t min_bits,
                         uint64_t next_height,
                         size_t interval) {
    // Not at boundary: keep current bits
    if (!last.empty() && (next_height % interval) != 0) {
        return last.back().second;
    }

    // At boundary: compute new difficulty
    if (last.size() < 2) {
        return last.empty() ? min_bits : last.back().second;
    }

    // Get the headers for this epoch
    std::vector<std::pair<int64_t, uint32_t>> headers;
    if (last.size() > interval) {
        headers.assign(last.end() - interval, last.end());
    } else {
        headers = last;
    }

    // Use fixed algorithm for blocks >= DIFFICULTY_FIX_HEIGHT
    if (next_height >= DIFFICULTY_FIX_HEIGHT) {
        log_info("Epoch retarget at height " + std::to_string(next_height) + " using FIXED algorithm");
        return lwma_next_bits_fixed(headers, target_spacing, min_bits);
    } else {
        // Use original (buggy) algorithm for consensus with existing blocks
        return lwma_next_bits(headers, target_spacing, min_bits);
    }
}

}
