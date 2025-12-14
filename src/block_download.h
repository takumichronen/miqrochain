// =============================================================================
// BLOCK DOWNLOAD MANAGER - Bitcoin Core-Aligned Architecture
// =============================================================================
// This replaces the fragmented inflight tracking with a single authoritative
// source of truth for block downloads during IBD.
//
// Key principles (Bitcoin Core reference: src/net_processing.cpp):
// 1. HASH-BASED ONLY: Never request blocks by index (getbi)
// 2. HEADERS-FIRST: Blocks only requested after headers known
// 3. MONOTONIC PROGRESS: Chain height must advance within bounded time
// 4. AGGRESSIVE GAP RESOLUTION: Missing blocks detected immediately
// 5. SINGLE SOURCE OF TRUTH: One data structure for all inflight tracking
// =============================================================================

#ifndef MIQ_BLOCK_DOWNLOAD_H
#define MIQ_BLOCK_DOWNLOAD_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace miq {
namespace sync {

// =============================================================================
// CONFIGURATION CONSTANTS
// =============================================================================

// Maximum blocks in flight per peer (Bitcoin Core: 16, we use 64 for faster sync)
constexpr size_t MAX_BLOCKS_IN_FLIGHT_PER_PEER = 64;

// Maximum total blocks in flight (all peers combined)
constexpr size_t MAX_BLOCKS_IN_FLIGHT_TOTAL = 1024;

// Timeout before re-requesting from different peer (ms)
constexpr int64_t BLOCK_STALLING_TIMEOUT_MS = 2000;

// Minimum time before marking a peer as stalling (ms)
constexpr int64_t BLOCK_DOWNLOAD_WINDOW_MS = 1000;

// Maximum pending blocks in memory before eviction
constexpr size_t MAX_PENDING_BLOCKS = 2048;

// Gap detection interval (ms) - much faster than before
constexpr int64_t GAP_DETECTION_INTERVAL_MS = 100;

// =============================================================================
// SYNC STATE - Single authoritative state machine
// =============================================================================

enum class SyncPhase : uint8_t {
    CONNECTING = 0,    // Finding peers, handshaking
    HEADERS = 1,       // Downloading headers (headers-first)
    BLOCKS = 2,        // Downloading blocks (have all headers)
    NEAR_TIP = 3,      // Within 16 blocks of tip
    SYNCED = 4         // Fully synced
};

inline const char* sync_phase_name(SyncPhase p) {
    switch (p) {
        case SyncPhase::CONNECTING: return "CONNECTING";
        case SyncPhase::HEADERS: return "HEADERS";
        case SyncPhase::BLOCKS: return "BLOCKS";
        case SyncPhase::NEAR_TIP: return "NEAR_TIP";
        case SyncPhase::SYNCED: return "SYNCED";
        default: return "UNKNOWN";
    }
}

// =============================================================================
// BLOCK REQUEST - Tracks a single block request
// =============================================================================

struct BlockRequest {
    std::vector<uint8_t> hash;    // Block hash (32 bytes)
    uint64_t height;              // Expected height (from headers)
    uint64_t peer_id;             // Peer we requested from
    int64_t request_time_ms;      // When we sent the request
    int64_t first_request_ms;     // First ever request (for total time tracking)
    uint8_t attempts;             // Number of request attempts
    bool stalling;                // Marked as stalling (will retry with different peer)
};

// =============================================================================
// PEER DOWNLOAD STATE - Per-peer tracking
// =============================================================================

struct PeerDownloadState {
    uint64_t peer_id;
    size_t blocks_in_flight;      // Current count
    size_t blocks_delivered;      // Total delivered
    size_t blocks_failed;         // Failed/timed out
    int64_t last_block_time_ms;   // Last successful receive
    int64_t avg_latency_ms;       // EMA of delivery times
    bool is_stalling;             // Currently stalling
    bool is_preferred;            // High-bandwidth, reliable

    PeerDownloadState() : peer_id(0), blocks_in_flight(0), blocks_delivered(0),
                          blocks_failed(0), last_block_time_ms(0), avg_latency_ms(0),
                          is_stalling(false), is_preferred(false) {}
};

// =============================================================================
// BLOCK DOWNLOAD MANAGER - Single source of truth
// =============================================================================

class BlockDownloadManager {
public:
    static BlockDownloadManager& instance() {
        static BlockDownloadManager mgr;
        return mgr;
    }

    // =========================================================================
    // SYNC STATE MANAGEMENT
    // =========================================================================

    SyncPhase current_phase() const {
        return phase_.load(std::memory_order_acquire);
    }

    void set_phase(SyncPhase new_phase) {
        SyncPhase old = phase_.load(std::memory_order_acquire);
        // Monotonic: only forward transitions (except SYNCED can go back to BLOCKS on reorg)
        if (static_cast<uint8_t>(new_phase) > static_cast<uint8_t>(old) ||
            (old == SyncPhase::SYNCED && new_phase == SyncPhase::BLOCKS)) {
            phase_.store(new_phase, std::memory_order_release);
        }
    }

    // =========================================================================
    // HEADER HEIGHT TRACKING
    // =========================================================================

    void set_header_height(uint64_t h) {
        uint64_t old = header_height_.load(std::memory_order_acquire);
        if (h > old) {
            header_height_.store(h, std::memory_order_release);
        }
    }

    uint64_t header_height() const {
        return header_height_.load(std::memory_order_acquire);
    }

    void set_chain_height(uint64_t h) {
        uint64_t old = chain_height_.load(std::memory_order_acquire);
        if (h > old) {
            chain_height_.store(h, std::memory_order_release);
            last_height_change_ms_.store(now_ms(), std::memory_order_release);
        }
    }

    uint64_t chain_height() const {
        return chain_height_.load(std::memory_order_acquire);
    }

    // =========================================================================
    // BLOCK REQUEST MANAGEMENT (Hash-based ONLY)
    // =========================================================================

    // Request a block by hash. Returns false if already inflight or already have it.
    bool request_block(const std::vector<uint8_t>& hash, uint64_t height, uint64_t peer_id) {
        std::lock_guard<std::mutex> lk(mu_);

        // Already have this block?
        if (height <= chain_height_.load(std::memory_order_acquire)) {
            return false;
        }

        // Already inflight?
        std::string hash_key(hash.begin(), hash.end());
        if (inflight_by_hash_.count(hash_key)) {
            return false;
        }

        // Peer at capacity?
        auto& peer_state = peer_states_[peer_id];
        if (peer_state.blocks_in_flight >= MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
            return false;
        }

        // Total capacity?
        if (inflight_by_hash_.size() >= MAX_BLOCKS_IN_FLIGHT_TOTAL) {
            return false;
        }

        // Create request
        BlockRequest req;
        req.hash = hash;
        req.height = height;
        req.peer_id = peer_id;
        req.request_time_ms = now_ms();
        req.first_request_ms = req.request_time_ms;
        req.attempts = 1;
        req.stalling = false;

        inflight_by_hash_[hash_key] = req;
        inflight_by_height_[height] = hash_key;
        peer_state.blocks_in_flight++;
        peer_state.peer_id = peer_id;

        total_requested_.fetch_add(1, std::memory_order_relaxed);

        return true;
    }

    // Block received. Returns height or 0 if wasn't expected.
    uint64_t block_received(const std::vector<uint8_t>& hash, uint64_t peer_id) {
        std::lock_guard<std::mutex> lk(mu_);

        std::string hash_key(hash.begin(), hash.end());
        auto it = inflight_by_hash_.find(hash_key);
        if (it == inflight_by_hash_.end()) {
            // Unsolicited block - still might be useful
            return 0;
        }

        BlockRequest req = it->second;
        uint64_t height = req.height;

        // Update peer stats
        auto& peer_state = peer_states_[req.peer_id];
        if (peer_state.blocks_in_flight > 0) {
            peer_state.blocks_in_flight--;
        }
        peer_state.blocks_delivered++;
        peer_state.last_block_time_ms = now_ms();
        peer_state.is_stalling = false;

        // Update latency EMA (0.2 weight for new sample)
        int64_t latency = now_ms() - req.request_time_ms;
        if (peer_state.avg_latency_ms == 0) {
            peer_state.avg_latency_ms = latency;
        } else {
            peer_state.avg_latency_ms = (peer_state.avg_latency_ms * 8 + latency * 2) / 10;
        }

        // Remove from tracking
        inflight_by_hash_.erase(it);
        inflight_by_height_.erase(height);

        total_received_.fetch_add(1, std::memory_order_relaxed);
        last_recv_ms_.store(now_ms(), std::memory_order_release);

        return height;
    }

    // Block failed (timeout, invalid, etc). Returns hash for retry.
    std::vector<uint8_t> block_failed(uint64_t height, uint64_t peer_id) {
        std::lock_guard<std::mutex> lk(mu_);

        auto hit = inflight_by_height_.find(height);
        if (hit == inflight_by_height_.end()) {
            return {};
        }

        std::string hash_key = hit->second;
        auto it = inflight_by_hash_.find(hash_key);
        if (it == inflight_by_hash_.end()) {
            inflight_by_height_.erase(hit);
            return {};
        }

        BlockRequest req = it->second;

        // Update peer stats
        auto& peer_state = peer_states_[req.peer_id];
        if (peer_state.blocks_in_flight > 0) {
            peer_state.blocks_in_flight--;
        }
        peer_state.blocks_failed++;

        // Remove from tracking
        std::vector<uint8_t> hash = req.hash;
        inflight_by_hash_.erase(it);
        inflight_by_height_.erase(hit);

        return hash;
    }

    // =========================================================================
    // GAP DETECTION - Find missing blocks that should be requested
    // =========================================================================

    struct Gap {
        uint64_t height;
        std::vector<uint8_t> hash;  // From header index
    };

    // Get blocks that need to be requested (gaps in the chain).
    // Caller provides a function to look up block hash from header at height.
    template<typename HashLookup>
    std::vector<Gap> get_gaps(size_t max_count, HashLookup get_hash_at_height) {
        std::lock_guard<std::mutex> lk(mu_);

        std::vector<Gap> gaps;
        uint64_t current = chain_height_.load(std::memory_order_acquire) + 1;
        uint64_t target = header_height_.load(std::memory_order_acquire);

        while (gaps.size() < max_count && current <= target) {
            // Skip if already inflight
            if (!inflight_by_height_.count(current)) {
                std::vector<uint8_t> hash = get_hash_at_height(current);
                if (!hash.empty()) {
                    gaps.push_back({current, hash});
                }
            }
            current++;
        }

        return gaps;
    }

    // Get stalling requests that need retry from different peer
    std::vector<BlockRequest> get_stalling_requests() {
        std::lock_guard<std::mutex> lk(mu_);

        std::vector<BlockRequest> stalling;
        int64_t now = now_ms();

        for (auto& kv : inflight_by_hash_) {
            BlockRequest& req = kv.second;
            int64_t elapsed = now - req.request_time_ms;

            if (elapsed > BLOCK_STALLING_TIMEOUT_MS && !req.stalling) {
                req.stalling = true;
                stalling.push_back(req);

                // Mark peer as stalling
                auto& peer_state = peer_states_[req.peer_id];
                peer_state.is_stalling = true;
            }
        }

        return stalling;
    }

    // Retry a stalling request with a new peer
    void retry_with_peer(const std::vector<uint8_t>& hash, uint64_t new_peer_id) {
        std::lock_guard<std::mutex> lk(mu_);

        std::string hash_key(hash.begin(), hash.end());
        auto it = inflight_by_hash_.find(hash_key);
        if (it == inflight_by_hash_.end()) {
            return;
        }

        BlockRequest& req = it->second;

        // Decrement old peer's inflight count
        auto& old_peer = peer_states_[req.peer_id];
        if (old_peer.blocks_in_flight > 0) {
            old_peer.blocks_in_flight--;
        }

        // Update to new peer
        req.peer_id = new_peer_id;
        req.request_time_ms = now_ms();
        req.attempts++;
        req.stalling = false;

        // Increment new peer's inflight count
        auto& new_peer = peer_states_[new_peer_id];
        new_peer.blocks_in_flight++;
    }

    // =========================================================================
    // PEER MANAGEMENT
    // =========================================================================

    void peer_disconnected(uint64_t peer_id) {
        std::lock_guard<std::mutex> lk(mu_);

        // Find all blocks from this peer and clear them
        std::vector<std::string> to_remove;
        for (auto& kv : inflight_by_hash_) {
            if (kv.second.peer_id == peer_id) {
                to_remove.push_back(kv.first);
                inflight_by_height_.erase(kv.second.height);
            }
        }

        for (const auto& key : to_remove) {
            inflight_by_hash_.erase(key);
        }

        peer_states_.erase(peer_id);
    }

    const PeerDownloadState* get_peer_state(uint64_t peer_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = peer_states_.find(peer_id);
        if (it == peer_states_.end()) return nullptr;
        return &it->second;
    }

    // Get best peer for requesting a block (lowest latency, not stalling)
    uint64_t get_best_peer() const {
        std::lock_guard<std::mutex> lk(mu_);

        uint64_t best = 0;
        int64_t best_score = INT64_MAX;

        for (const auto& kv : peer_states_) {
            if (kv.second.is_stalling) continue;
            if (kv.second.blocks_in_flight >= MAX_BLOCKS_IN_FLIGHT_PER_PEER) continue;

            // Score: latency + penalty for inflight
            int64_t score = kv.second.avg_latency_ms + kv.second.blocks_in_flight * 10;
            if (score < best_score) {
                best_score = score;
                best = kv.first;
            }
        }

        return best;
    }

    // =========================================================================
    // STATISTICS
    // =========================================================================

    size_t inflight_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return inflight_by_hash_.size();
    }

    size_t peer_inflight_count(uint64_t peer_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = peer_states_.find(peer_id);
        if (it == peer_states_.end()) return 0;
        return it->second.blocks_in_flight;
    }

    uint64_t total_requested() const {
        return total_requested_.load(std::memory_order_relaxed);
    }

    uint64_t total_received() const {
        return total_received_.load(std::memory_order_relaxed);
    }

    bool has_recent_progress(int64_t threshold_ms = 5000) const {
        int64_t last = last_height_change_ms_.load(std::memory_order_acquire);
        return (now_ms() - last) < threshold_ms;
    }

    // =========================================================================
    // INVARIANT CHECKS
    // =========================================================================

    bool check_invariants() const {
        std::lock_guard<std::mutex> lk(mu_);

        // Invariant 1: inflight_by_hash and inflight_by_height must be consistent
        if (inflight_by_hash_.size() != inflight_by_height_.size()) {
            return false;
        }

        // Invariant 2: chain_height <= header_height
        if (chain_height_.load() > header_height_.load()) {
            return false;
        }

        // Invariant 3: All inflight heights > chain_height
        uint64_t chain_h = chain_height_.load();
        for (const auto& kv : inflight_by_height_) {
            if (kv.first <= chain_h) {
                return false;
            }
        }

        return true;
    }

    // Debug dump
    std::string debug_status() const {
        std::lock_guard<std::mutex> lk(mu_);

        std::string s = "BlockDownloadManager: phase=" + std::string(sync_phase_name(phase_.load()));
        s += " chain=" + std::to_string(chain_height_.load());
        s += " headers=" + std::to_string(header_height_.load());
        s += " inflight=" + std::to_string(inflight_by_hash_.size());
        s += " peers=" + std::to_string(peer_states_.size());
        s += " requested=" + std::to_string(total_requested_.load());
        s += " received=" + std::to_string(total_received_.load());
        return s;
    }

private:
    BlockDownloadManager() = default;

    static int64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    // Sync state
    std::atomic<SyncPhase> phase_{SyncPhase::CONNECTING};
    std::atomic<uint64_t> header_height_{0};
    std::atomic<uint64_t> chain_height_{0};
    std::atomic<int64_t> last_height_change_ms_{0};
    std::atomic<int64_t> last_recv_ms_{0};

    // Inflight tracking - SINGLE SOURCE OF TRUTH
    mutable std::mutex mu_;
    std::unordered_map<std::string, BlockRequest> inflight_by_hash_;  // hash -> request
    std::unordered_map<uint64_t, std::string> inflight_by_height_;    // height -> hash
    std::unordered_map<uint64_t, PeerDownloadState> peer_states_;     // peer_id -> state

    // Statistics
    std::atomic<uint64_t> total_requested_{0};
    std::atomic<uint64_t> total_received_{0};
};

// =============================================================================
// CONVENIENCE ACCESSORS
// =============================================================================

inline BlockDownloadManager& block_download() {
    return BlockDownloadManager::instance();
}

} // namespace sync
} // namespace miq

#endif // MIQ_BLOCK_DOWNLOAD_H
