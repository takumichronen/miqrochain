// validation_engine.h - Production-grade transaction and block validation
// Bitcoin Core-level validation with comprehensive error handling
#ifndef MIQ_VALIDATION_ENGINE_H
#define MIQ_VALIDATION_ENGINE_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <optional>

#include "block.h"
#include "tx.h"
#include "utxo.h"
#include "constants.h"

namespace miq {

// =============================================================================
// Validation Result Types
// =============================================================================

enum class ValidationState {
    VALID,
    INVALID,
    MISSING_INPUTS,
    PREMATURE_SPEND,
    DUPLICATE,
    CONSENSUS_ERROR,
    NETWORK_ERROR
};

struct ValidationResult {
    ValidationState state = ValidationState::VALID;
    std::string error;
    std::string debug_message;
    int reject_code = 0;
    bool dos_protected = false;
    int ban_score = 0;

    bool IsValid() const { return state == ValidationState::VALID; }
    bool IsInvalid() const { return state == ValidationState::INVALID; }
    bool IsMissingInputs() const { return state == ValidationState::MISSING_INPUTS; }

    void Invalid(const std::string& err, int code = 0, int dos = 0) {
        state = ValidationState::INVALID;
        error = err;
        reject_code = code;
        ban_score = dos;
    }

    void MissingInputs(const std::string& err) {
        state = ValidationState::MISSING_INPUTS;
        error = err;
    }
};

// =============================================================================
// Script Verification Flags (Bitcoin Core compatible)
// =============================================================================

enum ScriptVerifyFlags : uint32_t {
    SCRIPT_VERIFY_NONE                       = 0,
    SCRIPT_VERIFY_P2SH                       = (1U << 0),
    SCRIPT_VERIFY_STRICTENC                  = (1U << 1),
    SCRIPT_VERIFY_DERSIG                     = (1U << 2),
    SCRIPT_VERIFY_LOW_S                      = (1U << 3),
    SCRIPT_VERIFY_NULLDUMMY                  = (1U << 4),
    SCRIPT_VERIFY_SIGPUSHONLY                = (1U << 5),
    SCRIPT_VERIFY_MINIMALDATA                = (1U << 6),
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7),
    SCRIPT_VERIFY_CLEANSTACK                 = (1U << 8),
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY        = (1U << 9),
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY        = (1U << 10),
    SCRIPT_VERIFY_WITNESS                    = (1U << 11),
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1U << 12),
    SCRIPT_VERIFY_MINIMALIF                  = (1U << 13),
    SCRIPT_VERIFY_NULLFAIL                   = (1U << 14),
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE         = (1U << 15),
    SCRIPT_VERIFY_CONST_SCRIPTCODE           = (1U << 16),
    SCRIPT_VERIFY_TAPROOT                    = (1U << 17),
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = (1U << 18),
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS      = (1U << 19),
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = (1U << 20),
};

// Standard script flags for mainnet
constexpr uint32_t STANDARD_SCRIPT_VERIFY_FLAGS =
    SCRIPT_VERIFY_P2SH |
    SCRIPT_VERIFY_DERSIG |
    SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_VERIFY_NULLDUMMY |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_MINIMALIF |
    SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
    SCRIPT_VERIFY_LOW_S |
    SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
    SCRIPT_VERIFY_CONST_SCRIPTCODE |
    SCRIPT_VERIFY_TAPROOT |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE;

// Mandatory script flags
constexpr uint32_t MANDATORY_SCRIPT_VERIFY_FLAGS =
    SCRIPT_VERIFY_P2SH |
    SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_DERSIG |
    SCRIPT_VERIFY_LOW_S |
    SCRIPT_VERIFY_NULLDUMMY;

// =============================================================================
// Transaction Policy Limits
// =============================================================================

struct TxPolicy {
    // Size limits
    static constexpr size_t MAX_STANDARD_TX_WEIGHT = 400000;
    static constexpr size_t MAX_STANDARD_TX_SIGOPS_COST = 16000;
    static constexpr size_t MAX_P2SH_SIGOPS = 15;
    static constexpr size_t MAX_STANDARD_P2WSH_STACK_ITEMS = 100;
    static constexpr size_t MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80;
    static constexpr size_t MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80;
    static constexpr size_t MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;
    static constexpr size_t MAX_STANDARD_SCRIPTSIG_SIZE = 1650;

    // Output limits
    static constexpr uint64_t DUST_RELAY_TX_FEE = 3000; // satoshis per kB
    static constexpr size_t MAX_OP_RETURN_RELAY = 83;

    // Input limits
    static constexpr size_t MAX_TX_IN_WITNESS_ITEMS = 500;
    static constexpr size_t MAX_PUBKEYS_PER_MULTISIG = 20;

    // Fee limits
    static constexpr uint64_t DEFAULT_MIN_RELAY_TX_FEE = 1000; // per kB
    static constexpr uint64_t DEFAULT_INCREMENTAL_RELAY_FEE = 1000;
    static constexpr uint64_t MAX_MONEY_LOCAL = MAX_MONEY;

    // Time locks
    static constexpr uint32_t LOCKTIME_THRESHOLD = 500000000;
    static constexpr int64_t MAX_TIME_ADJUSTMENT = 70 * 60; // 70 minutes
};

// =============================================================================
// Input/Output Tracking
// =============================================================================

struct COutPoint {
    std::vector<uint8_t> txid;
    uint32_t n;

    COutPoint() : n(0) { txid.assign(32, 0); }
    COutPoint(const std::vector<uint8_t>& tx, uint32_t idx) : txid(tx), n(idx) {}

    bool operator==(const COutPoint& other) const {
        return n == other.n && txid == other.txid;
    }

    bool operator<(const COutPoint& other) const {
        if (txid != other.txid) return txid < other.txid;
        return n < other.n;
    }

    bool IsNull() const {
        return n == 0 && std::all_of(txid.begin(), txid.end(), [](uint8_t b) { return b == 0; });
    }
};

struct COutPointHash {
    size_t operator()(const COutPoint& op) const {
        size_t h = op.n * 1315423911u;
        if (!op.txid.empty()) {
            h ^= (size_t)op.txid[0] * 2654435761u;
            h ^= (size_t)op.txid[op.txid.size() - 1] * 2246822519u;
        }
        return h;
    }
};

// =============================================================================
// Coin/UTXO Representation
// =============================================================================

struct Coin {
    uint64_t value;
    std::vector<uint8_t> pkh;
    uint32_t height;
    bool coinbase;
    bool spent;

    Coin() : value(0), height(0), coinbase(false), spent(false) {}

    bool IsSpent() const { return spent; }
    bool IsAvailable() const { return !spent && value > 0; }
};

// =============================================================================
// UTXO View Interface
// =============================================================================

class CoinsView {
public:
    virtual ~CoinsView() = default;

    virtual bool GetCoin(const COutPoint& outpoint, Coin& coin) const = 0;
    virtual bool HaveCoin(const COutPoint& outpoint) const = 0;
    virtual uint64_t GetBestBlock() const = 0;
    virtual std::vector<uint8_t> GetBestBlockHash() const = 0;
};

// =============================================================================
// Cached UTXO View
// =============================================================================

class CachedCoinsView : public CoinsView {
public:
    explicit CachedCoinsView(const CoinsView* base) : base_(base) {}

    bool GetCoin(const COutPoint& outpoint, Coin& coin) const override {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cache_.find(outpoint);
        if (it != cache_.end()) {
            coin = it->second;
            return !coin.IsSpent();
        }

        if (base_) {
            bool found = base_->GetCoin(outpoint, coin);
            cache_[outpoint] = coin;
            return found;
        }
        return false;
    }

    bool HaveCoin(const COutPoint& outpoint) const override {
        Coin coin;
        return GetCoin(outpoint, coin);
    }

    uint64_t GetBestBlock() const override {
        return base_ ? base_->GetBestBlock() : 0;
    }

    std::vector<uint8_t> GetBestBlockHash() const override {
        return base_ ? base_->GetBestBlockHash() : std::vector<uint8_t>(32, 0);
    }

    void AddCoin(const COutPoint& outpoint, const Coin& coin) {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_[outpoint] = coin;
    }

    void SpendCoin(const COutPoint& outpoint) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(outpoint);
        if (it != cache_.end()) {
            it->second.spent = true;
        } else {
            Coin coin;
            coin.spent = true;
            cache_[outpoint] = coin;
        }
    }

    void Flush() {
        std::lock_guard<std::mutex> lock(mutex_);
        // Flush changes to base (if writable)
        cache_.clear();
    }

    size_t GetCacheSize() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_.size();
    }

    uint64_t GetCacheUsage() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_.size() * (sizeof(COutPoint) + sizeof(Coin) + 64);
    }

private:
    const CoinsView* base_;
    mutable std::unordered_map<COutPoint, Coin, COutPointHash> cache_;
    mutable std::mutex mutex_;
};

// =============================================================================
// Validation Engine
// =============================================================================

class ValidationEngine {
public:
    ValidationEngine();
    ~ValidationEngine();

    // Transaction validation
    ValidationResult CheckTransaction(const Transaction& tx) const;
    ValidationResult CheckTransactionContextual(
        const Transaction& tx,
        const CoinsView& view,
        uint32_t height,
        int64_t median_time_past,
        uint32_t flags = MANDATORY_SCRIPT_VERIFY_FLAGS) const;

    // Block validation
    ValidationResult CheckBlock(const Block& block) const;
    ValidationResult CheckBlockHeader(const BlockHeader& header, uint64_t height) const;
    ValidationResult ContextualCheckBlock(
        const Block& block,
        const CoinsView& view,
        uint64_t height) const;

    // Input validation
    ValidationResult CheckInputs(
        const Transaction& tx,
        const CoinsView& view,
        uint32_t flags,
        bool cache_store = false) const;

    // Signature validation
    bool VerifySignature(
        const std::vector<uint8_t>& pubkey,
        const std::vector<uint8_t>& hash,
        const std::vector<uint8_t>& signature) const;

    // Fee calculation
    uint64_t GetTransactionFee(const Transaction& tx, const CoinsView& view) const;
    uint64_t GetTransactionWeight(const Transaction& tx) const;
    uint64_t GetTransactionVirtualSize(const Transaction& tx) const;

    // Policy checks
    bool IsStandardTransaction(const Transaction& tx, std::string& reason) const;
    bool AreInputsStandard(const Transaction& tx, const CoinsView& view) const;
    uint64_t GetDustThreshold(const TxOut& txout, uint64_t dust_relay_fee) const;
    bool IsDust(const TxOut& txout, uint64_t dust_relay_fee) const;

    // Script validation
    bool VerifyScript(
        const std::vector<uint8_t>& scriptSig,
        const std::vector<uint8_t>& scriptPubKey,
        uint32_t flags,
        const Transaction& tx,
        size_t input_index) const;

    // Statistics
    uint64_t GetValidationCount() const { return validation_count_.load(); }
    uint64_t GetCacheHits() const { return cache_hits_.load(); }
    uint64_t GetCacheMisses() const { return cache_misses_.load(); }
    double GetCacheHitRate() const;

    // Configuration
    void SetMaxSigOps(uint32_t max) { max_sigops_ = max; }
    void SetMaxTxSize(size_t max) { max_tx_size_ = max; }
    void EnableStrictMode(bool enable) { strict_mode_ = enable; }

private:
    // Internal validation helpers
    ValidationResult CheckTransactionBasic(const Transaction& tx) const;
    ValidationResult CheckCoinbase(const Transaction& tx, uint64_t height) const;
    ValidationResult CheckSequenceLocks(
        const Transaction& tx,
        const CoinsView& view,
        int64_t median_time_past) const;

    bool CheckLockTime(const Transaction& tx, int64_t time, uint64_t height) const;
    bool CheckSequence(uint32_t sequence, int64_t time_diff, uint32_t height_diff) const;

    // Signature cache for performance
    struct SigCacheEntry {
        std::vector<uint8_t> pubkey;
        std::vector<uint8_t> hash;
        std::vector<uint8_t> signature;
        bool valid;
    };

    bool CheckSignatureCache(
        const std::vector<uint8_t>& pubkey,
        const std::vector<uint8_t>& hash,
        const std::vector<uint8_t>& signature) const;

    void AddToSignatureCache(
        const std::vector<uint8_t>& pubkey,
        const std::vector<uint8_t>& hash,
        const std::vector<uint8_t>& signature,
        bool valid) const;

    // Member variables
    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, bool> sig_cache_;
    mutable std::atomic<uint64_t> validation_count_{0};
    mutable std::atomic<uint64_t> cache_hits_{0};
    mutable std::atomic<uint64_t> cache_misses_{0};

    uint32_t max_sigops_ = 80000;
    size_t max_tx_size_ = 4 * 1024 * 1024; // 4 MiB
    bool strict_mode_ = true;

    // Constants
    static constexpr size_t MAX_BLOCK_WEIGHT = 4000000;
    static constexpr size_t MAX_BLOCK_SERIALIZED_SIZE = 4000000;
    static constexpr size_t MAX_BLOCK_SIGOPS_COST = 80000;
    static constexpr size_t SIG_CACHE_MAX_SIZE = 32 * 1024;
};

// =============================================================================
// Block Validator
// =============================================================================

class BlockValidator {
public:
    BlockValidator(ValidationEngine& engine, const CoinsView& view);

    ValidationResult ValidateBlock(const Block& block, uint64_t height);
    ValidationResult ValidateBlockHeader(const BlockHeader& header, uint64_t height);

    // Contextual validation
    ValidationResult CheckMerkleRoot(const Block& block);
    ValidationResult CheckWitnessMerkleRoot(const Block& block);
    ValidationResult CheckBlockTime(const BlockHeader& header, int64_t median_time);
    ValidationResult CheckProofOfWork(const BlockHeader& header);
    ValidationResult CheckCoinbaseSubsidy(const Block& block, uint64_t height);

    // Statistics
    double GetAverageValidationTime() const;
    uint64_t GetBlocksValidated() const { return blocks_validated_.load(); }

private:
    ValidationEngine& engine_;
    const CoinsView& view_;

    std::atomic<uint64_t> blocks_validated_{0};
    std::atomic<uint64_t> total_validation_time_us_{0};
};

// =============================================================================
// Parallel Validation Support
// =============================================================================

class ParallelValidationState {
public:
    ParallelValidationState(size_t num_threads = 0);
    ~ParallelValidationState();

    // Queue transactions for parallel validation
    void QueueTransaction(const Transaction& tx, uint64_t priority = 0);
    void QueueTransactions(const std::vector<Transaction>& txs);

    // Get results
    std::vector<ValidationResult> GetResults();
    bool AllValid() const;

    // Control
    void Start();
    void Stop();
    void Wait();

    // Statistics
    size_t GetPendingCount() const;
    size_t GetCompletedCount() const;

private:
    struct ValidationTask {
        Transaction tx;
        uint64_t priority;
        std::chrono::steady_clock::time_point queued_at;
    };

    void WorkerThread();

    std::vector<std::thread> workers_;
    std::queue<ValidationTask> task_queue_;
    std::vector<ValidationResult> results_;

    std::mutex queue_mutex_;
    std::mutex results_mutex_;
    std::condition_variable queue_cv_;
    std::condition_variable results_cv_;

    std::atomic<bool> running_{false};
    std::atomic<size_t> completed_{0};
};

// =============================================================================
// Utility Functions
// =============================================================================

// Calculate transaction weight (for SegWit compatibility)
inline uint64_t GetTransactionWeight(const Transaction& tx) {
    // Base weight: non-witness data * 4
    // Witness weight: witness data * 1
    // Total weight = base + witness
    auto raw = ser_tx(tx);
    return raw.size() * 4; // No SegWit yet, so just 4x size
}

// Calculate virtual size (weight / 4)
inline uint64_t GetVirtualTransactionSize(const Transaction& tx) {
    return (GetTransactionWeight(tx) + 3) / 4;
}

// Get minimum fee for transaction
inline uint64_t GetMinimumFee(const Transaction& tx, uint64_t fee_rate_per_kvb) {
    uint64_t vsize = GetVirtualTransactionSize(tx);
    return (vsize * fee_rate_per_kvb + 999) / 1000;
}

// Check if transaction is final
inline bool IsFinalTransaction(const Transaction& tx, uint64_t height, int64_t time) {
    if (tx.lock_time == 0) return true;

    if (tx.lock_time < TxPolicy::LOCKTIME_THRESHOLD) {
        if (tx.lock_time < height) return true;
    } else {
        if ((int64_t)tx.lock_time < time) return true;
    }

    for (const auto& in : tx.vin) {
        if (in.prev.vout != 0xFFFFFFFF) {
            // TODO: Check sequence numbers properly
            return false;
        }
    }
    return true;
}

} // namespace miq

#endif // MIQ_VALIDATION_ENGINE_H
