#include "difficulty.h"
#include "constants.h"   // for BLOCK_TIME_SECS / GENESIS_BITS if callers pass those
#include "log.h"         // for log_info
#include <cstdint>
#include <cstddef>
#include <vector>
#include <utility>
#include <sstream>

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

    // DEBUG: Log difficulty calculation details
    {
        std::ostringstream oss;
        oss << "LWMA: window=" << window << " sum=" << sum << " avg=" << avg
            << " target_spacing=" << target_spacing << " ratio=" << (double)avg/(double)target_spacing
            << " prev_bits=0x" << std::hex << last.back().second;
        log_info(oss.str());
    }

    for (int i = 31; i >= 0; --i) {
        unsigned int v = t[i];
        v = (unsigned int)((uint64_t)v * (uint64_t)avg / (uint64_t)target_spacing);
        if (v > 255U) v = 255U;
        t[i] = (unsigned char)v;
    }

    uint32_t result = compact_from_target(t);

    // DEBUG: Log result
    {
        std::ostringstream oss;
        oss << "LWMA: result_bits=0x" << std::hex << result;
        log_info(oss.str());
    }

    return result;
}

// --- Epoch retarget: freeze inside epoch; adjust only at boundary ---
uint32_t epoch_next_bits(const std::vector<std::pair<int64_t, uint32_t>>& last,
                         int64_t target_spacing,
                         uint32_t min_bits,
                         uint64_t next_height,
                         size_t interval) {
    // DEBUG: Log epoch_next_bits call
    {
        std::ostringstream oss;
        oss << "epoch_next_bits: next_height=" << next_height
            << " interval=" << interval
            << " last.size()=" << last.size()
            << " at_boundary=" << ((next_height % interval) == 0 ? "YES" : "no");
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

    if (last.size() > interval) {
        // Use only the last `interval` headers to determine the new target
        log_info("epoch_next_bits: using tail of " + std::to_string(interval) + " headers");
        std::vector<std::pair<int64_t, uint32_t>> tail(last.end() - interval, last.end());
        return lwma_next_bits(tail, target_spacing, min_bits);
    } else {
        log_info("epoch_next_bits: using all " + std::to_string(last.size()) + " headers");
        return lwma_next_bits(last, target_spacing, min_bits);
    }
}

}
