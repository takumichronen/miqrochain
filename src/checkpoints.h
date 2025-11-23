// checkpoints.h - Production-grade checkpoint system for fast sync
// Bitcoin Core-level reliability with assume-valid and assume-UTXO support
#ifndef MIQ_CHECKPOINTS_H
#define MIQ_CHECKPOINTS_H

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <cstdint>

namespace miq {

// =============================================================================
// Checkpoint Data Structures
// =============================================================================

struct Checkpoint {
    uint64_t height;
    std::string hash;         // Block hash (hex)
    uint64_t timestamp;       // Block timestamp
    uint64_t total_supply;    // Total issued supply at this height
    std::string utxo_hash;    // UTXO set hash (for assume-UTXO)

    Checkpoint() : height(0), timestamp(0), total_supply(0) {}
    Checkpoint(uint64_t h, const std::string& hsh, uint64_t ts = 0,
               uint64_t supply = 0, const std::string& utxo = "")
        : height(h), hash(hsh), timestamp(ts), total_supply(supply), utxo_hash(utxo) {}
};

struct AssumeValidData {
    std::string block_hash;
    uint64_t height;
    uint64_t timestamp;
    std::string minimum_chain_work;  // Hex string of minimum work

    AssumeValidData() : height(0), timestamp(0) {}
};

struct AssumeUTXOData {
    uint64_t height;
    std::string utxo_hash;          // Hash of UTXO set
    uint64_t utxo_count;            // Number of UTXOs
    uint64_t total_value;           // Total value in UTXOs
    std::string block_hash;         // Block hash at this height

    AssumeUTXOData() : height(0), utxo_count(0), total_value(0) {}
};

// =============================================================================
// Checkpoint Manager
// =============================================================================

class CheckpointManager {
public:
    CheckpointManager();
    ~CheckpointManager() = default;

    // Initialize with built-in checkpoints
    void Initialize();

    // Add a checkpoint
    void AddCheckpoint(const Checkpoint& cp);
    void AddCheckpoint(uint64_t height, const std::string& hash);

    // Query checkpoints
    bool IsCheckpoint(uint64_t height) const;
    bool ValidateCheckpoint(uint64_t height, const std::string& hash) const;
    bool ValidateCheckpoint(uint64_t height, const std::vector<uint8_t>& hash) const;

    // Get checkpoint data
    std::optional<Checkpoint> GetCheckpoint(uint64_t height) const;
    std::optional<Checkpoint> GetLastCheckpoint() const;
    uint64_t GetLastCheckpointHeight() const;

    // Get all checkpoints in range
    std::vector<Checkpoint> GetCheckpointsInRange(uint64_t start, uint64_t end) const;

    // Block locator helpers
    std::vector<uint64_t> GetCheckpointHeights() const;
    uint64_t GetHighestCheckpointBelow(uint64_t height) const;

    // Assume-valid support
    void SetAssumeValid(const AssumeValidData& data);
    bool IsAssumeValidBlock(const std::string& hash) const;
    bool IsAssumeValidHeight(uint64_t height) const;
    const AssumeValidData& GetAssumeValidData() const { return assume_valid_; }

    // Assume-UTXO support
    void AddAssumeUTXO(const AssumeUTXOData& data);
    bool HasAssumeUTXO(uint64_t height) const;
    std::optional<AssumeUTXOData> GetAssumeUTXO(uint64_t height) const;
    std::vector<uint64_t> GetAssumeUTXOHeights() const;

    // Validation helpers
    bool ShouldSkipScriptValidation(uint64_t height) const;
    bool CanAssumeBlockValid(const std::string& hash) const;

    // Statistics
    size_t GetCheckpointCount() const;
    uint64_t GetTotalVerifiedHeight() const;

    // Serialization
    std::vector<uint8_t> Serialize() const;
    bool Deserialize(const std::vector<uint8_t>& data);

private:
    void LoadBuiltInCheckpoints();
    void LoadBuiltInAssumeUTXO();

    std::map<uint64_t, Checkpoint> checkpoints_;
    std::map<uint64_t, AssumeUTXOData> assume_utxo_;
    AssumeValidData assume_valid_;

    mutable std::mutex mutex_;
};

// =============================================================================
// Built-in Checkpoints for Miqrochain
// =============================================================================

inline void CheckpointManager::LoadBuiltInCheckpoints() {
    // Genesis checkpoint
    AddCheckpoint(0,
        "0000000000000000000000000000000000000000000000000000000000000000",
        1700000000, 0);

    // These would be filled in as the chain grows
    // Format: height, hash, timestamp, supply, utxo_hash

    // Example future checkpoints:
    // AddCheckpoint(10000, "...", timestamp, supply);
    // AddCheckpoint(50000, "...", timestamp, supply);
    // AddCheckpoint(100000, "...", timestamp, supply);
}

inline void CheckpointManager::LoadBuiltInAssumeUTXO() {
    // Assume-UTXO snapshots for fast initial sync
    // These allow nodes to sync from a UTXO snapshot instead of full history

    // Example:
    // AssumeUTXOData data;
    // data.height = 50000;
    // data.utxo_hash = "...";
    // data.utxo_count = 100000;
    // data.total_value = 2500000 * COIN;
    // data.block_hash = "...";
    // AddAssumeUTXO(data);
}

// =============================================================================
// Checkpoint Manager Implementation
// =============================================================================

inline CheckpointManager::CheckpointManager() {
    // Initialize will be called explicitly
}

inline void CheckpointManager::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    LoadBuiltInCheckpoints();
    LoadBuiltInAssumeUTXO();
}

inline void CheckpointManager::AddCheckpoint(const Checkpoint& cp) {
    std::lock_guard<std::mutex> lock(mutex_);
    checkpoints_[cp.height] = cp;
}

inline void CheckpointManager::AddCheckpoint(uint64_t height, const std::string& hash) {
    Checkpoint cp;
    cp.height = height;
    cp.hash = hash;
    AddCheckpoint(cp);
}

inline bool CheckpointManager::IsCheckpoint(uint64_t height) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return checkpoints_.find(height) != checkpoints_.end();
}

inline bool CheckpointManager::ValidateCheckpoint(uint64_t height, const std::string& hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = checkpoints_.find(height);
    if (it == checkpoints_.end()) return true; // Not a checkpoint, always valid
    return it->second.hash == hash;
}

inline bool CheckpointManager::ValidateCheckpoint(uint64_t height, const std::vector<uint8_t>& hash) const {
    // Convert vector to hex string
    static const char* hex = "0123456789abcdef";
    std::string hash_str;
    hash_str.reserve(hash.size() * 2);
    for (uint8_t b : hash) {
        hash_str += hex[b >> 4];
        hash_str += hex[b & 0xF];
    }
    return ValidateCheckpoint(height, hash_str);
}

inline std::optional<Checkpoint> CheckpointManager::GetCheckpoint(uint64_t height) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = checkpoints_.find(height);
    if (it == checkpoints_.end()) return std::nullopt;
    return it->second;
}

inline std::optional<Checkpoint> CheckpointManager::GetLastCheckpoint() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (checkpoints_.empty()) return std::nullopt;
    return checkpoints_.rbegin()->second;
}

inline uint64_t CheckpointManager::GetLastCheckpointHeight() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (checkpoints_.empty()) return 0;
    return checkpoints_.rbegin()->first;
}

inline std::vector<Checkpoint> CheckpointManager::GetCheckpointsInRange(
    uint64_t start, uint64_t end) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Checkpoint> result;

    for (const auto& [height, cp] : checkpoints_) {
        if (height >= start && height <= end) {
            result.push_back(cp);
        }
    }
    return result;
}

inline std::vector<uint64_t> CheckpointManager::GetCheckpointHeights() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint64_t> heights;
    heights.reserve(checkpoints_.size());
    for (const auto& [h, _] : checkpoints_) {
        heights.push_back(h);
    }
    return heights;
}

inline uint64_t CheckpointManager::GetHighestCheckpointBelow(uint64_t height) const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t result = 0;
    for (const auto& [h, _] : checkpoints_) {
        if (h < height && h > result) {
            result = h;
        }
    }
    return result;
}

inline void CheckpointManager::SetAssumeValid(const AssumeValidData& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    assume_valid_ = data;
}

inline bool CheckpointManager::IsAssumeValidBlock(const std::string& hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return assume_valid_.block_hash == hash;
}

inline bool CheckpointManager::IsAssumeValidHeight(uint64_t height) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return height <= assume_valid_.height;
}

inline void CheckpointManager::AddAssumeUTXO(const AssumeUTXOData& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    assume_utxo_[data.height] = data;
}

inline bool CheckpointManager::HasAssumeUTXO(uint64_t height) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return assume_utxo_.find(height) != assume_utxo_.end();
}

inline std::optional<AssumeUTXOData> CheckpointManager::GetAssumeUTXO(uint64_t height) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = assume_utxo_.find(height);
    if (it == assume_utxo_.end()) return std::nullopt;
    return it->second;
}

inline std::vector<uint64_t> CheckpointManager::GetAssumeUTXOHeights() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint64_t> heights;
    heights.reserve(assume_utxo_.size());
    for (const auto& [h, _] : assume_utxo_) {
        heights.push_back(h);
    }
    return heights;
}

inline bool CheckpointManager::ShouldSkipScriptValidation(uint64_t height) const {
    std::lock_guard<std::mutex> lock(mutex_);
    // Skip script validation for blocks before assume-valid height
    return height < assume_valid_.height && !assume_valid_.block_hash.empty();
}

inline bool CheckpointManager::CanAssumeBlockValid(const std::string& hash) const {
    return IsAssumeValidBlock(hash);
}

inline size_t CheckpointManager::GetCheckpointCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return checkpoints_.size();
}

inline uint64_t CheckpointManager::GetTotalVerifiedHeight() const {
    return GetLastCheckpointHeight();
}

// =============================================================================
// Fee Estimation System
// =============================================================================

struct FeeEstimate {
    uint64_t fee_rate;          // Satoshis per vKB
    uint64_t median_fee_rate;
    uint64_t high_priority;     // For next block
    uint64_t medium_priority;   // Within 6 blocks
    uint64_t low_priority;      // Within 25 blocks
    double decay;               // Decay factor
    uint64_t total_txs;
    uint64_t timestamp;
};

class FeeEstimator {
public:
    FeeEstimator();
    ~FeeEstimator() = default;

    // Process confirmed transactions
    void ProcessBlock(uint64_t height, const std::vector<std::pair<uint64_t, uint64_t>>& fee_sizes);

    // Get estimates
    uint64_t EstimateFee(int confirm_target) const;
    uint64_t EstimateSmartFee(int confirm_target, double* decay = nullptr) const;
    FeeEstimate GetCurrentEstimate() const;

    // Configuration
    void SetMinimumFeeRate(uint64_t rate) { min_fee_rate_ = rate; }
    void SetDecayFactor(double decay) { decay_factor_ = decay; }

    // Statistics
    uint64_t GetMedianFeeRate() const;
    uint64_t GetMempoolMinFee() const { return mempool_min_fee_; }
    void SetMempoolMinFee(uint64_t fee) { mempool_min_fee_ = fee; }

private:
    struct FeeHistory {
        std::vector<uint64_t> fee_rates;
        uint64_t height;
    };

    std::vector<FeeHistory> history_;
    uint64_t min_fee_rate_;
    uint64_t mempool_min_fee_;
    double decay_factor_;

    static constexpr size_t MAX_HISTORY_BLOCKS = 1008; // 1 week
    static constexpr int CONFIRM_TARGET_1 = 1;
    static constexpr int CONFIRM_TARGET_6 = 6;
    static constexpr int CONFIRM_TARGET_25 = 25;

    mutable std::mutex mutex_;
};

inline FeeEstimator::FeeEstimator()
    : min_fee_rate_(1000), mempool_min_fee_(1000), decay_factor_(0.998) {
}

inline void FeeEstimator::ProcessBlock(
    uint64_t height,
    const std::vector<std::pair<uint64_t, uint64_t>>& fee_sizes) {

    std::lock_guard<std::mutex> lock(mutex_);

    FeeHistory entry;
    entry.height = height;

    for (const auto& [fee, size] : fee_sizes) {
        if (size > 0) {
            uint64_t rate = (fee * 1000) / size; // per kB
            entry.fee_rates.push_back(rate);
        }
    }

    if (!entry.fee_rates.empty()) {
        history_.push_back(std::move(entry));

        // Keep only recent history
        while (history_.size() > MAX_HISTORY_BLOCKS) {
            history_.erase(history_.begin());
        }
    }
}

inline uint64_t FeeEstimator::EstimateFee(int confirm_target) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (history_.empty()) return min_fee_rate_;

    // Collect fee rates from recent blocks
    std::vector<uint64_t> all_rates;
    size_t blocks_to_check = std::min((size_t)confirm_target * 3, history_.size());

    for (size_t i = history_.size() - blocks_to_check; i < history_.size(); ++i) {
        for (uint64_t rate : history_[i].fee_rates) {
            all_rates.push_back(rate);
        }
    }

    if (all_rates.empty()) return min_fee_rate_;

    // Sort and get percentile based on target
    std::sort(all_rates.begin(), all_rates.end());

    double percentile;
    if (confirm_target <= 1) {
        percentile = 0.9; // 90th percentile for next block
    } else if (confirm_target <= 6) {
        percentile = 0.6; // 60th percentile for 6 blocks
    } else {
        percentile = 0.3; // 30th percentile for 25+ blocks
    }

    size_t idx = (size_t)(all_rates.size() * percentile);
    if (idx >= all_rates.size()) idx = all_rates.size() - 1;

    return std::max(all_rates[idx], min_fee_rate_);
}

inline uint64_t FeeEstimator::EstimateSmartFee(int confirm_target, double* decay) const {
    uint64_t estimate = EstimateFee(confirm_target);

    if (decay) {
        *decay = decay_factor_;
    }

    // Apply mempool minimum
    return std::max(estimate, mempool_min_fee_);
}

inline FeeEstimate FeeEstimator::GetCurrentEstimate() const {
    FeeEstimate est;
    est.high_priority = EstimateFee(CONFIRM_TARGET_1);
    est.medium_priority = EstimateFee(CONFIRM_TARGET_6);
    est.low_priority = EstimateFee(CONFIRM_TARGET_25);
    est.median_fee_rate = GetMedianFeeRate();
    est.fee_rate = est.medium_priority;
    est.decay = decay_factor_;
    est.total_txs = history_.size();
    est.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return est;
}

inline uint64_t FeeEstimator::GetMedianFeeRate() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (history_.empty()) return min_fee_rate_;

    std::vector<uint64_t> all_rates;
    for (const auto& h : history_) {
        for (uint64_t rate : h.fee_rates) {
            all_rates.push_back(rate);
        }
    }

    if (all_rates.empty()) return min_fee_rate_;

    std::sort(all_rates.begin(), all_rates.end());
    return all_rates[all_rates.size() / 2];
}

// =============================================================================
// Global Checkpoint Manager Instance
// =============================================================================

CheckpointManager& GetCheckpointManager();

} // namespace miq

#endif // MIQ_CHECKPOINTS_H
