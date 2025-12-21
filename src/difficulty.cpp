#include "difficulty.h"
#include "constants.h"   // for BLOCK_TIME_SECS / GENESIS_BITS if callers pass those
#include <cstdint>
#include <cstddef>
#include <vector>
#include <utility>

namespace miq {

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

// --- LWMA (kept; window implied by size of `last`) ---
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

// Helper: multiply 256-bit big-endian number by uint64, then divide by uint64
// Handles carry propagation correctly for full 256-bit arithmetic
static void bignum_mul_div(unsigned char t[32], uint64_t mul, uint64_t div) {
    if (div == 0 || mul == 0) return;

    // Multiply: process from LSB (byte 31) to MSB (byte 0)
    uint64_t carry = 0;
    for (int i = 31; i >= 0; --i) {
        uint64_t val = (uint64_t)t[i] * mul + carry;
        t[i] = (unsigned char)(val % 256);
        carry = val / 256;
    }

    // Handle overflow from multiplication (shift right if needed)
    if (carry > 0) {
        // Overflow - set to max target
        for (int i = 0; i < 32; ++i) t[i] = 0xFF;
        return;
    }

    // Divide: process from MSB (byte 0) to LSB (byte 31)
    uint64_t remainder = 0;
    for (int i = 0; i < 32; ++i) {
        uint64_t val = remainder * 256 + t[i];
        t[i] = (unsigned char)(val / div);
        remainder = val % div;
    }
}

// --- Epoch retarget: Bitcoin-style with full epoch timespan ---
uint32_t epoch_next_bits(const std::vector<std::pair<int64_t, uint32_t>>& last,
                         int64_t target_spacing,
                         uint32_t min_bits,
                         uint64_t next_height,
                         size_t interval) {
    // If not at a boundary, keep current bits (freeze difficulty).
    if (!last.empty() && (next_height % interval) != 0) {
        return last.back().second;
    }

    // At boundary: compute new bits using FULL EPOCH timespan (Bitcoin-style)
    if (last.size() < 2) {
        // No history? stick with min_bits / genesis
        return last.empty() ? min_bits : last.back().second;
    }

    // Determine epoch window size
    size_t epoch_size = (last.size() > interval) ? interval : last.size();

    // Get first and last block times for the epoch
    // last[] is ordered oldest to newest
    size_t first_idx = last.size() - epoch_size;
    size_t last_idx = last.size() - 1;

    int64_t first_time = last[first_idx].first;
    int64_t last_time = last[last_idx].first;

    // Calculate actual timespan of the epoch
    int64_t actual_timespan = last_time - first_time;
    if (actual_timespan < 1) actual_timespan = 1;

    // Expected timespan = (epoch_size - 1) * target_spacing
    // (N blocks have N-1 intervals between them)
    int64_t expected_timespan = (int64_t)(epoch_size - 1) * target_spacing;
    if (expected_timespan < 1) expected_timespan = target_spacing;

    // Clamp to max 4x adjustment per epoch (Bitcoin-style protection)
    if (actual_timespan < expected_timespan / 4) {
        actual_timespan = expected_timespan / 4;
    }
    if (actual_timespan > expected_timespan * 4) {
        actual_timespan = expected_timespan * 4;
    }

    // Get current target from last block's bits
    unsigned char target[32];
    target_from_compact(last.back().second, target);

    // new_target = old_target * actual_timespan / expected_timespan
    bignum_mul_div(target, (uint64_t)actual_timespan, (uint64_t)expected_timespan);

    // Ensure we don't exceed minimum difficulty (max target)
    unsigned char max_target[32];
    target_from_compact(min_bits, max_target);

    // Compare: if target > max_target, cap at max
    for (int i = 0; i < 32; ++i) {
        if (target[i] > max_target[i]) {
            return min_bits;  // Target too high, use minimum difficulty
        } else if (target[i] < max_target[i]) {
            break;  // Target is lower (harder), that's fine
        }
    }

    // Ensure target isn't zero
    bool is_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (target[i] != 0) { is_zero = false; break; }
    }
    if (is_zero) target[31] = 1;

    return compact_from_target(target);
}

}
