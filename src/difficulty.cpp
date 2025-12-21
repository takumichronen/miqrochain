#include "difficulty.h"
#include "constants.h"   // for BLOCK_TIME_SECS / GENESIS_BITS if callers pass those
#include "log.h"         // for logging
#include <cstdint>
#include <cstddef>
#include <vector>
#include <utility>
#include <cstring>

#if defined(_MSC_VER)
#include <intrin.h>      // For _umul128, _udiv128 on Windows
#endif

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

// ============================================================================
// 256-bit arithmetic for proper difficulty scaling
// ============================================================================

// Portable 64x64->128 multiplication (works on MSVC and GCC/Clang)
static inline void mul64(uint64_t a, uint64_t b, uint64_t& hi, uint64_t& lo) {
#if defined(_MSC_VER) && defined(_M_X64)
    lo = _umul128(a, b, &hi);
#elif defined(__SIZEOF_INT128__)
    __uint128_t r = (__uint128_t)a * b;
    lo = (uint64_t)r;
    hi = (uint64_t)(r >> 64);
#else
    // Portable fallback: split into 32-bit parts
    uint64_t a_lo = (uint32_t)a;
    uint64_t a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b;
    uint64_t b_hi = b >> 32;

    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_lo * b_hi;
    uint64_t p2 = a_hi * b_lo;
    uint64_t p3 = a_hi * b_hi;

    uint64_t mid = p1 + (p0 >> 32);
    mid += p2;
    if (mid < p2) p3 += (1ULL << 32);  // carry

    lo = (p0 & 0xFFFFFFFF) | (mid << 32);
    hi = p3 + (mid >> 32);
#endif
}

// Portable 128/64->64 division with remainder
static inline uint64_t div128by64(uint64_t hi, uint64_t lo, uint64_t divisor, uint64_t& remainder) {
#if defined(_MSC_VER) && defined(_M_X64)
    return _udiv128(hi, lo, divisor, &remainder);
#elif defined(__SIZEOF_INT128__)
    __uint128_t n = ((__uint128_t)hi << 64) | lo;
    remainder = (uint64_t)(n % divisor);
    return (uint64_t)(n / divisor);
#else
    // Portable fallback using binary long division
    if (hi == 0) {
        remainder = lo % divisor;
        return lo / divisor;
    }

    // Full 128-bit division needed
    uint64_t quotient = 0;
    uint64_t rem = 0;

    for (int i = 127; i >= 0; --i) {
        rem <<= 1;
        if (i >= 64) {
            rem |= (hi >> (i - 64)) & 1;
        } else {
            rem |= (lo >> i) & 1;
        }
        if (rem >= divisor) {
            rem -= divisor;
            if (i < 64) quotient |= (1ULL << i);
        }
    }
    remainder = rem;
    return quotient;
#endif
}

// Multiply 256-bit target (big-endian) by numerator, divide by denominator
// Uses proper carry propagation to avoid truncation bugs
static void scale_target_256(unsigned char* t, uint64_t num, uint64_t denom) {
    if (denom == 0) return;  // Safety check
    if (num == denom) return; // No scaling needed

    // Convert big-endian bytes to 4x uint64_t (little-endian word order for easier math)
    // t[0..7] -> words[3], t[8..15] -> words[2], t[16..23] -> words[1], t[24..31] -> words[0]
    uint64_t words[4] = {0, 0, 0, 0};
    for (int w = 0; w < 4; ++w) {
        int base = (3 - w) * 8;  // t[0..7] for w=3, t[8..15] for w=2, etc.
        for (int b = 0; b < 8; ++b) {
            words[w] = (words[w] << 8) | t[base + b];
        }
    }

    // Multiply by num: result is 320-bit (5 words) to handle overflow
    // We multiply each word by num, propagate carry
    uint64_t carry_hi = 0, carry_lo = 0;
    uint64_t result[5] = {0, 0, 0, 0, 0};
    for (int w = 0; w < 4; ++w) {
        uint64_t prod_hi, prod_lo;
        mul64(words[w], num, prod_hi, prod_lo);

        // Add carry from previous iteration
        prod_lo += carry_lo;
        if (prod_lo < carry_lo) prod_hi++;  // overflow
        prod_hi += carry_hi;

        result[w] = prod_lo;
        carry_lo = prod_hi;
        carry_hi = 0;
    }
    result[4] = carry_lo;

    // Divide by denom: long division from most significant word down
    uint64_t remainder = 0;
    for (int w = 4; w >= 0; --w) {
        result[w] = div128by64(remainder, result[w], denom, remainder);
    }

    // Check if result overflows 256 bits (words[4] != 0)
    // If so, clamp to max target (all 0xFF)
    if (result[4] != 0) {
        for (int i = 0; i < 32; i++) t[i] = 0xFF;
        return;
    }

    // Convert back to big-endian bytes
    for (int w = 0; w < 4; ++w) {
        int base = (3 - w) * 8;
        uint64_t word = result[w];
        for (int b = 7; b >= 0; --b) {
            t[base + b] = (unsigned char)(word & 0xFF);
            word >>= 8;
        }
    }
}

// Check if target is all zeros
static bool is_target_zero(const unsigned char* t) {
    for (int i = 0; i < 32; i++) {
        if (t[i] != 0) return false;
    }
    return true;
}

// ============================================================================
// Activation height for difficulty fix - blocks before this use legacy algorithm
// ============================================================================
static constexpr uint64_t DIFFICULTY_FIX_ACTIVATION_HEIGHT = 7884;

// --- Legacy LWMA (original broken algorithm - for consensus with old blocks) ---
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

    // LEGACY: byte-by-byte scaling with capping (has underflow bug at high difficulty)
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

// --- Fixed LWMA with proper 256-bit arithmetic ---
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

    // Clamp avg to reasonable bounds to prevent extreme adjustments
    // Min: 1/4 of target (4x difficulty increase max per epoch)
    // Max: 4x of target (4x difficulty decrease max per epoch)
    int64_t min_avg = target_spacing / 4;
    int64_t max_avg = target_spacing * 4;
    if (avg < min_avg) avg = min_avg;
    if (avg > max_avg) avg = max_avg;

    // Scale target by avg/target_spacing using proper 256-bit arithmetic
    unsigned char t[32];
    target_from_compact(last.back().second, t);

    // Use 256-bit multiplication and division for accurate scaling
    scale_target_256(t, (uint64_t)avg, (uint64_t)target_spacing);

    // Safety: if result is all zeros (would happen with extreme difficulty),
    // return the previous bits to avoid breaking consensus
    if (is_target_zero(t)) {
        log_warn("lwma_next_bits_fixed: target underflow, keeping previous bits");
        return last.back().second;
    }

    uint32_t result = compact_from_target(t);

    // Safety: if compact conversion failed, return previous bits
    if (result == 0) {
        log_warn("lwma_next_bits_fixed: compact conversion failed, keeping previous bits");
        return last.back().second;
    }

    return result;
}

// --- Public API: automatically selects legacy or fixed based on height ---
uint32_t lwma_next_bits(const std::vector<std::pair<int64_t, uint32_t>>& last,
                        int64_t target_spacing, uint32_t min_bits) {
    // For backwards compatibility, use fixed version by default
    // (callers that care about height should use epoch_next_bits instead)
    return lwma_next_bits_fixed(last, target_spacing, min_bits);
}

// --- Epoch retarget: freeze inside epoch; adjust only at boundary ---
uint32_t epoch_next_bits(const std::vector<std::pair<int64_t, uint32_t>>& last,
                         int64_t target_spacing,
                         uint32_t min_bits,
                         uint64_t next_height,
                         size_t interval) {
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
    // Blocks before activation use legacy algorithm for consensus compatibility
    // Blocks at/after activation use fixed 256-bit arithmetic
    bool use_fixed = (next_height >= DIFFICULTY_FIX_ACTIVATION_HEIGHT);

    std::vector<std::pair<int64_t, uint32_t>> window_data;
    if (last.size() > interval) {
        window_data.assign(last.end() - interval, last.end());
    } else {
        window_data = last;
    }

    if (use_fixed) {
        return lwma_next_bits_fixed(window_data, target_spacing, min_bits);
    } else {
        return lwma_next_bits_legacy(window_data, target_spacing, min_bits);
    }
}

}
