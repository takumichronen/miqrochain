// src/tools/miq_chain_doctor.cpp
// Chain Doctor - Production chain recovery and diagnostic tool
//
// Features:
// - scan:      Validate all blocks, find first invalid/corrupted block
// - truncate:  Remove blocks after a specific height (keeps blocks.dat valid)
// - info:      Show detailed info about a specific block
// - verify:    Full chain verification with UTXO rebuilding
//
// Usage:
//   miq-chain-doctor --datadir=/path/to/data scan
//   miq-chain-doctor --datadir=/path/to/data truncate --height=1000
//   miq-chain-doctor --datadir=/path/to/data info --height=500
//   miq-chain-doctor --datadir=/path/to/data verify

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <iomanip>
#include <chrono>

#include "serialize.h"
#include "block.h"
#include "tx.h"
#include "hex.h"
#include "sha256.h"
#include "constants.h"
#include "utxo.h"

namespace fs = std::filesystem;

// ============================================================================
// Utility Functions
// ============================================================================

static void print_usage() {
    std::cerr << R"(
miq-chain-doctor - Chain Recovery & Diagnostic Tool

USAGE:
  miq-chain-doctor --datadir=<path> <command> [options]

COMMANDS:
  scan              Scan blocks.dat and find first invalid block
  truncate          Remove blocks after specified height
  info              Show detailed block information
  verify            Full chain verification with UTXO rebuild
  export-valid      Export only valid blocks to new blocks.dat

OPTIONS:
  --datadir=<path>  Path to data directory (required)
  --height=<n>      Block height for truncate/info commands
  --hash=<hex>      Block hash for info command
  --verbose         Show detailed output
  --dry-run         For truncate: show what would be done without doing it
  --force           Skip confirmation prompts

EXAMPLES:
  # Scan for corruption
  miq-chain-doctor --datadir=./data scan

  # Find info about block 100
  miq-chain-doctor --datadir=./data info --height=100

  # Truncate chain to height 500 (remove blocks 501+)
  miq-chain-doctor --datadir=./data truncate --height=500

  # Full verification with UTXO rebuild
  miq-chain-doctor --datadir=./data verify --verbose

)";
}

static std::string format_time(int64_t timestamp) {
    time_t t = static_cast<time_t>(timestamp);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", std::gmtime(&t));
    return std::string(buf);
}

static std::string format_size(uint64_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    if (bytes < 1024*1024) return std::to_string(bytes/1024) + " KB";
    return std::to_string(bytes/(1024*1024)) + " MB";
}

// ============================================================================
// Low-level Block Storage Access
// ============================================================================

struct BlockLocation {
    uint64_t offset;
    uint32_t size;
    std::vector<uint8_t> hash;
};

class RawBlockReader {
public:
    bool open(const std::string& datadir) {
        datadir_ = datadir;
        path_blocks_ = datadir + "/blocks.dat";
        path_index_ = datadir + "/blocks.idx";
        path_hashmap_ = datadir + "/hash.map";

        if (!fs::exists(path_blocks_)) {
            std::cerr << "ERROR: blocks.dat not found at " << path_blocks_ << "\n";
            return false;
        }

        // Load offsets from blocks.idx
        offsets_.clear();
        if (fs::exists(path_index_)) {
            std::ifstream idx(path_index_, std::ios::binary);
            while (idx) {
                uint64_t off = 0;
                if (!idx.read(reinterpret_cast<char*>(&off), sizeof(off))) break;
                offsets_.push_back(off);
            }
        }

        // If no index, build from blocks.dat
        if (offsets_.empty()) {
            std::cerr << "INFO: blocks.idx missing or empty, scanning blocks.dat...\n";
            if (!rebuild_offsets()) return false;
        }

        // Load hash map
        hash_to_index_.clear();
        if (fs::exists(path_hashmap_)) {
            std::ifstream hm(path_hashmap_, std::ios::binary);
            while (hm) {
                uint32_t ksz = 0;
                if (!hm.read(reinterpret_cast<char*>(&ksz), sizeof(ksz))) break;
                if (ksz == 0 || ksz > 1024) break;
                std::string k(ksz, '\0');
                if (!hm.read(&k[0], ksz)) break;
                uint32_t vi = 0;
                if (!hm.read(reinterpret_cast<char*>(&vi), sizeof(vi))) break;
                hash_to_index_[k] = vi;
            }
        }

        return true;
    }

    size_t count() const { return offsets_.size(); }

    bool read_block_raw(size_t index, std::vector<uint8_t>& out) const {
        if (index >= offsets_.size()) return false;

        std::ifstream f(path_blocks_, std::ios::binary);
        if (!f) return false;

        f.seekg(static_cast<std::streamoff>(offsets_[index]));
        uint32_t sz = 0;
        if (!f.read(reinterpret_cast<char*>(&sz), sizeof(sz))) return false;

        // Sanity check
        if (sz == 0 || sz > 32 * 1024 * 1024) {
            std::cerr << "WARNING: Block " << index << " has invalid size: " << sz << "\n";
            return false;
        }

        out.resize(sz);
        return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), sz));
    }

    bool read_block(size_t index, miq::Block& out) const {
        std::vector<uint8_t> raw;
        if (!read_block_raw(index, raw)) return false;
        return miq::deser_block(raw, out);
    }

    uint64_t get_offset(size_t index) const {
        if (index >= offsets_.size()) return 0;
        return offsets_[index];
    }

    // Get the byte offset where block N+1 would start (end of block N)
    uint64_t get_end_offset(size_t index) const {
        if (index >= offsets_.size()) return 0;

        std::ifstream f(path_blocks_, std::ios::binary);
        if (!f) return 0;

        f.seekg(static_cast<std::streamoff>(offsets_[index]));
        uint32_t sz = 0;
        if (!f.read(reinterpret_cast<char*>(&sz), sizeof(sz))) return 0;

        return offsets_[index] + sizeof(sz) + sz;
    }

    const std::string& datadir() const { return datadir_; }

    // Truncate files to keep only blocks 0..height (inclusive)
    bool truncate_to_height(size_t height, bool dry_run) {
        if (height >= offsets_.size()) {
            std::cerr << "ERROR: Height " << height << " >= current block count " << offsets_.size() << "\n";
            return false;
        }

        // Calculate where to truncate blocks.dat
        uint64_t truncate_offset = get_end_offset(height);
        if (truncate_offset == 0) {
            std::cerr << "ERROR: Could not determine truncate offset\n";
            return false;
        }

        // Calculate new blocks.idx size
        uint64_t new_idx_size = (height + 1) * sizeof(uint64_t);

        std::cout << "\n=== TRUNCATION PLAN ===\n";
        std::cout << "Keep blocks: 0 to " << height << " (" << (height + 1) << " blocks)\n";
        std::cout << "Remove blocks: " << (height + 1) << " to " << (offsets_.size() - 1)
                  << " (" << (offsets_.size() - height - 1) << " blocks)\n";
        std::cout << "blocks.dat: truncate to " << format_size(truncate_offset) << "\n";
        std::cout << "blocks.idx: truncate to " << format_size(new_idx_size) << "\n";
        std::cout << "hash.map: will be deleted (rebuilt on next start)\n";
        std::cout << "state.dat: will be deleted (rebuilt on next start)\n";
        std::cout << "chainstate/: will be deleted (rebuilt on next start)\n";

        if (dry_run) {
            std::cout << "\n[DRY RUN - no changes made]\n";
            return true;
        }

        std::cout << "\nProceeding with truncation...\n";

        // Truncate blocks.dat
        {
            std::error_code ec;
            fs::resize_file(path_blocks_, truncate_offset, ec);
            if (ec) {
                std::cerr << "ERROR: Failed to truncate blocks.dat: " << ec.message() << "\n";
                return false;
            }
            std::cout << "  [OK] blocks.dat truncated\n";
        }

        // Truncate blocks.idx
        {
            std::error_code ec;
            fs::resize_file(path_index_, new_idx_size, ec);
            if (ec) {
                std::cerr << "ERROR: Failed to truncate blocks.idx: " << ec.message() << "\n";
                return false;
            }
            std::cout << "  [OK] blocks.idx truncated\n";
        }

        // Delete hash.map (will be rebuilt)
        if (fs::exists(path_hashmap_)) {
            std::error_code ec;
            fs::remove(path_hashmap_, ec);
            if (!ec) std::cout << "  [OK] hash.map deleted\n";
        }

        // Delete state.dat
        std::string state_path = datadir_ + "/state.dat";
        if (fs::exists(state_path)) {
            std::error_code ec;
            fs::remove(state_path, ec);
            if (!ec) std::cout << "  [OK] state.dat deleted\n";
        }

        // Delete chainstate directory
        std::string chainstate_path = datadir_ + "/chainstate";
        if (fs::exists(chainstate_path)) {
            std::error_code ec;
            fs::remove_all(chainstate_path, ec);
            if (!ec) std::cout << "  [OK] chainstate/ deleted\n";
        }

        // Delete undo directory (optional, will be rebuilt)
        std::string undo_path = datadir_ + "/undo";
        if (fs::exists(undo_path)) {
            std::error_code ec;
            fs::remove_all(undo_path, ec);
            if (!ec) std::cout << "  [OK] undo/ deleted\n";
        }

        std::cout << "\nTruncation complete. Restart the node to rebuild chainstate.\n";
        return true;
    }

private:
    bool rebuild_offsets() {
        std::ifstream f(path_blocks_, std::ios::binary);
        if (!f) return false;

        offsets_.clear();
        uint64_t off = 0;

        while (true) {
            uint32_t sz = 0;
            if (!f.read(reinterpret_cast<char*>(&sz), sizeof(sz))) break;

            if (sz == 0 || sz > 32 * 1024 * 1024) {
                std::cerr << "WARNING: Corrupt block at offset " << off << " (size=" << sz << ")\n";
                break;
            }

            offsets_.push_back(off);
            f.seekg(sz, std::ios::cur);
            if (!f) break;
            off = static_cast<uint64_t>(f.tellg());
        }

        return !offsets_.empty();
    }

    std::string datadir_;
    std::string path_blocks_;
    std::string path_index_;
    std::string path_hashmap_;
    std::vector<uint64_t> offsets_;
    std::unordered_map<std::string, uint32_t> hash_to_index_;
};

// ============================================================================
// UTXO Tracking for Validation
// ============================================================================

struct SimpleUTXO {
    uint64_t value;
    std::vector<uint8_t> pkh;
    uint64_t height;
    bool coinbase;
};

class SimpleUTXOSet {
public:
    void add(const std::vector<uint8_t>& txid, uint32_t vout, const SimpleUTXO& entry) {
        std::string k = make_key(txid, vout);
        map_[k] = entry;
    }

    bool get(const std::vector<uint8_t>& txid, uint32_t vout, SimpleUTXO& out) const {
        std::string k = make_key(txid, vout);
        auto it = map_.find(k);
        if (it == map_.end()) return false;
        out = it->second;
        return true;
    }

    bool spend(const std::vector<uint8_t>& txid, uint32_t vout) {
        std::string k = make_key(txid, vout);
        return map_.erase(k) > 0;
    }

    size_t size() const { return map_.size(); }
    void clear() { map_.clear(); }

private:
    static std::string make_key(const std::vector<uint8_t>& txid, uint32_t vout) {
        std::string k;
        k.reserve(txid.size() + 4);
        k.append(reinterpret_cast<const char*>(txid.data()), txid.size());
        k.append(reinterpret_cast<const char*>(&vout), sizeof(vout));
        return k;
    }

    std::unordered_map<std::string, SimpleUTXO> map_;
};

// ============================================================================
// Block Validation
// ============================================================================

struct ValidationResult {
    bool valid = true;
    size_t first_invalid_height = 0;
    std::string error;
    std::vector<uint8_t> block_hash;

    // For detailed reporting
    size_t tx_index = 0;
    size_t input_index = 0;
    std::vector<uint8_t> missing_txid;
    uint32_t missing_vout = 0;
};

class ChainValidator {
public:
    ChainValidator(bool verbose = false) : verbose_(verbose) {}

    // Validate a single block against current UTXO state
    ValidationResult validate_block(const miq::Block& block, uint64_t height) {
        ValidationResult result;
        result.block_hash = block.block_hash();

        // Track outputs created in this block (for chained txs)
        struct TxOutKey {
            std::vector<uint8_t> txid;
            uint32_t vout;
            bool operator==(const TxOutKey& o) const { return txid == o.txid && vout == o.vout; }
        };
        struct TxOutKeyHash {
            size_t operator()(const TxOutKey& k) const {
                size_t h = k.vout;
                if (!k.txid.empty()) h ^= std::hash<uint8_t>()(k.txid[0]) << 8;
                return h;
            }
        };
        std::unordered_map<TxOutKey, SimpleUTXO, TxOutKeyHash> created_in_block;
        std::unordered_set<std::string> spent_in_block;

        // Process coinbase first (add outputs)
        if (!block.txs.empty()) {
            const auto& cb = block.txs[0];
            auto cb_txid = cb.txid();
            for (uint32_t i = 0; i < cb.vout.size(); ++i) {
                SimpleUTXO entry;
                entry.value = cb.vout[i].value;
                entry.pkh = cb.vout[i].pkh;
                entry.height = height;
                entry.coinbase = true;
                created_in_block[{cb_txid, i}] = entry;
            }
        }

        // Validate non-coinbase transactions
        for (size_t ti = 1; ti < block.txs.size(); ++ti) {
            const auto& tx = block.txs[ti];
            auto txid = tx.txid();

            // Check inputs
            for (size_t ii = 0; ii < tx.vin.size(); ++ii) {
                const auto& in = tx.vin[ii];

                // Check for double-spend within block
                std::string spend_key;
                spend_key.append(reinterpret_cast<const char*>(in.prev.txid.data()), in.prev.txid.size());
                spend_key.append(reinterpret_cast<const char*>(&in.prev.vout), sizeof(in.prev.vout));

                if (spent_in_block.count(spend_key)) {
                    result.valid = false;
                    result.first_invalid_height = height;
                    result.error = "in-block double-spend";
                    result.tx_index = ti;
                    result.input_index = ii;
                    return result;
                }
                spent_in_block.insert(spend_key);

                // Check if UTXO exists
                SimpleUTXO utxo;
                TxOutKey key{in.prev.txid, in.prev.vout};

                auto cib_it = created_in_block.find(key);
                if (cib_it != created_in_block.end()) {
                    // Chained tx - output created earlier in this block
                    utxo = cib_it->second;
                } else if (!utxo_set_.get(in.prev.txid, in.prev.vout, utxo)) {
                    result.valid = false;
                    result.first_invalid_height = height;
                    result.error = "missing UTXO";
                    result.tx_index = ti;
                    result.input_index = ii;
                    result.missing_txid = in.prev.txid;
                    result.missing_vout = in.prev.vout;
                    return result;
                }

                // Check coinbase maturity
                if (utxo.coinbase && height < utxo.height + miq::COINBASE_MATURITY) {
                    result.valid = false;
                    result.first_invalid_height = height;
                    result.error = "immature coinbase spend";
                    result.tx_index = ti;
                    result.input_index = ii;
                    return result;
                }
            }

            // Add outputs to created_in_block
            for (uint32_t i = 0; i < tx.vout.size(); ++i) {
                SimpleUTXO entry;
                entry.value = tx.vout[i].value;
                entry.pkh = tx.vout[i].pkh;
                entry.height = height;
                entry.coinbase = false;
                created_in_block[{txid, i}] = entry;
            }
        }

        // Commit changes to UTXO set
        // First spend inputs
        for (size_t ti = 1; ti < block.txs.size(); ++ti) {
            const auto& tx = block.txs[ti];
            for (const auto& in : tx.vin) {
                utxo_set_.spend(in.prev.txid, in.prev.vout);
            }
        }

        // Then add all outputs
        for (const auto& [key, utxo] : created_in_block) {
            utxo_set_.add(key.txid, key.vout, utxo);
        }

        return result;
    }

    // Full chain scan
    ValidationResult scan_chain(RawBlockReader& reader) {
        ValidationResult result;
        size_t total = reader.count();

        std::cout << "Scanning " << total << " blocks...\n\n";

        auto start_time = std::chrono::steady_clock::now();
        size_t last_report = 0;

        for (size_t i = 0; i < total; ++i) {
            miq::Block block;
            if (!reader.read_block(i, block)) {
                result.valid = false;
                result.first_invalid_height = i;
                result.error = "failed to deserialize block";
                std::cerr << "\n[CORRUPTION] Block " << i << ": " << result.error << "\n";
                return result;
            }

            // Validate block structure
            if (i > 0) {
                // Check prev_hash links
                miq::Block prev_block;
                if (reader.read_block(i - 1, prev_block)) {
                    if (block.header.prev_hash != prev_block.block_hash()) {
                        result.valid = false;
                        result.first_invalid_height = i;
                        result.error = "prev_hash mismatch (chain broken)";
                        result.block_hash = block.block_hash();
                        std::cerr << "\n[CORRUPTION] Block " << i << ": " << result.error << "\n";
                        std::cerr << "  Expected prev: " << miq::to_hex(prev_block.block_hash()) << "\n";
                        std::cerr << "  Got prev:      " << miq::to_hex(block.header.prev_hash) << "\n";
                        return result;
                    }
                }
            }

            // Validate UTXO integrity
            result = validate_block(block, i);
            if (!result.valid) {
                std::cerr << "\n[CORRUPTION] Block " << i << ": " << result.error << "\n";
                std::cerr << "  Block hash: " << miq::to_hex(block.block_hash()) << "\n";
                if (!result.missing_txid.empty()) {
                    std::cerr << "  Missing UTXO: " << miq::to_hex(result.missing_txid)
                              << ":" << result.missing_vout << "\n";
                }
                std::cerr << "  Transaction index: " << result.tx_index << "\n";
                std::cerr << "  Input index: " << result.input_index << "\n";
                return result;
            }

            // Progress reporting
            if (i - last_report >= 1000 || i == total - 1) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
                double rate = elapsed > 0 ? static_cast<double>(i + 1) / elapsed : 0;

                std::cout << "\r  Block " << (i + 1) << "/" << total
                          << " (" << std::fixed << std::setprecision(1)
                          << (100.0 * (i + 1) / total) << "%) "
                          << "[" << static_cast<int>(rate) << " blocks/sec] "
                          << "[UTXO set: " << utxo_set_.size() << "]   " << std::flush;
                last_report = i;
            }
        }

        std::cout << "\n\n[OK] All " << total << " blocks validated successfully!\n";
        std::cout << "Final UTXO set size: " << utxo_set_.size() << "\n";
        return result;
    }

    void reset() { utxo_set_.clear(); }

private:
    SimpleUTXOSet utxo_set_;
    bool verbose_;
};

// ============================================================================
// Commands
// ============================================================================

int cmd_scan(RawBlockReader& reader, bool verbose) {
    std::cout << "=== CHAIN SCAN ===\n";
    std::cout << "Data directory: " << reader.datadir() << "\n";
    std::cout << "Total blocks in storage: " << reader.count() << "\n\n";

    ChainValidator validator(verbose);
    auto result = validator.scan_chain(reader);

    if (!result.valid) {
        std::cout << "\n=== CORRUPTION DETECTED ===\n";
        std::cout << "First invalid block: " << result.first_invalid_height << "\n";
        std::cout << "Error: " << result.error << "\n";
        std::cout << "\nTo fix, run:\n";
        std::cout << "  miq-chain-doctor --datadir=" << reader.datadir()
                  << " truncate --height=" << (result.first_invalid_height - 1) << "\n";
        return 1;
    }

    return 0;
}

int cmd_info(RawBlockReader& reader, int64_t height, const std::string& hash_hex) {
    std::cout << "=== BLOCK INFO ===\n\n";

    size_t target_height = 0;

    if (height >= 0) {
        target_height = static_cast<size_t>(height);
    } else if (!hash_hex.empty()) {
        // Find by hash
        std::vector<uint8_t> target_hash;
        try {
            target_hash = miq::from_hex(hash_hex);
        } catch (...) {
            std::cerr << "ERROR: Invalid hash hex\n";
            return 1;
        }

        bool found = false;
        for (size_t i = 0; i < reader.count(); ++i) {
            miq::Block block;
            if (reader.read_block(i, block)) {
                if (block.block_hash() == target_hash) {
                    target_height = i;
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            std::cerr << "ERROR: Block not found with hash " << hash_hex << "\n";
            return 1;
        }
    } else {
        std::cerr << "ERROR: Specify --height or --hash\n";
        return 1;
    }

    if (target_height >= reader.count()) {
        std::cerr << "ERROR: Height " << target_height << " out of range (max: " << (reader.count() - 1) << ")\n";
        return 1;
    }

    miq::Block block;
    if (!reader.read_block(target_height, block)) {
        std::cerr << "ERROR: Failed to read block at height " << target_height << "\n";
        return 1;
    }

    std::vector<uint8_t> raw;
    reader.read_block_raw(target_height, raw);

    std::cout << "Height:       " << target_height << "\n";
    std::cout << "Hash:         " << miq::to_hex(block.block_hash()) << "\n";
    std::cout << "Prev Hash:    " << miq::to_hex(block.header.prev_hash) << "\n";
    std::cout << "Merkle Root:  " << miq::to_hex(block.header.merkle_root) << "\n";
    std::cout << "Time:         " << format_time(block.header.time) << " (" << block.header.time << ")\n";
    std::cout << "Bits:         0x" << std::hex << block.header.bits << std::dec << "\n";
    std::cout << "Nonce:        " << block.header.nonce << "\n";
    std::cout << "Transactions: " << block.txs.size() << "\n";
    std::cout << "Raw Size:     " << format_size(raw.size()) << "\n";
    std::cout << "File Offset:  " << reader.get_offset(target_height) << "\n";

    // Coinbase info
    if (!block.txs.empty()) {
        const auto& cb = block.txs[0];
        uint64_t cb_total = 0;
        for (const auto& out : cb.vout) cb_total += out.value;
        std::cout << "\nCoinbase:\n";
        std::cout << "  TXID:   " << miq::to_hex(cb.txid()) << "\n";
        std::cout << "  Value:  " << (cb_total / miq::COIN) << "."
                  << std::setw(8) << std::setfill('0') << (cb_total % miq::COIN) << " MIQ\n";
        if (!cb.vout.empty()) {
            std::cout << "  Recipient PKH: " << miq::to_hex(cb.vout[0].pkh) << "\n";
        }
    }

    // Show all transactions if verbose
    if (block.txs.size() > 1) {
        std::cout << "\nTransactions:\n";
        for (size_t i = 1; i < block.txs.size(); ++i) {
            const auto& tx = block.txs[i];
            uint64_t out_total = 0;
            for (const auto& out : tx.vout) out_total += out.value;
            std::cout << "  [" << i << "] " << miq::to_hex(tx.txid()).substr(0, 16) << "... "
                      << tx.vin.size() << " in, " << tx.vout.size() << " out, "
                      << (out_total / miq::COIN) << "." << std::setw(8) << std::setfill('0')
                      << (out_total % miq::COIN) << " MIQ\n";
        }
    }

    return 0;
}

int cmd_truncate(RawBlockReader& reader, size_t height, bool dry_run, bool force) {
    std::cout << "=== CHAIN TRUNCATION ===\n\n";
    std::cout << "Current block count: " << reader.count() << "\n";
    std::cout << "Target height: " << height << "\n";

    if (height >= reader.count()) {
        std::cerr << "ERROR: Target height must be less than current block count\n";
        return 1;
    }

    size_t blocks_to_remove = reader.count() - height - 1;
    std::cout << "Blocks to remove: " << blocks_to_remove << "\n";

    if (!force && !dry_run) {
        std::cout << "\nWARNING: This operation will permanently remove " << blocks_to_remove << " blocks!\n";
        std::cout << "Type 'yes' to confirm: ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "yes") {
            std::cout << "Aborted.\n";
            return 1;
        }
    }

    if (!reader.truncate_to_height(height, dry_run)) {
        return 1;
    }

    return 0;
}

int cmd_verify(RawBlockReader& reader, bool verbose) {
    std::cout << "=== FULL CHAIN VERIFICATION ===\n";
    std::cout << "Data directory: " << reader.datadir() << "\n";
    std::cout << "Total blocks: " << reader.count() << "\n\n";

    std::cout << "This performs a complete chain validation including:\n";
    std::cout << "  - Block structure validation\n";
    std::cout << "  - Chain connectivity (prev_hash links)\n";
    std::cout << "  - UTXO existence for all inputs\n";
    std::cout << "  - Coinbase maturity rules\n";
    std::cout << "  - Double-spend detection\n\n";

    ChainValidator validator(verbose);
    auto result = validator.scan_chain(reader);

    if (!result.valid) {
        return 1;
    }

    return 0;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    std::string datadir;
    std::string command;
    int64_t height = -1;
    std::string hash_hex;
    bool verbose = false;
    bool dry_run = false;
    bool force = false;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg.rfind("--datadir=", 0) == 0) {
            datadir = arg.substr(10);
        } else if (arg.rfind("--height=", 0) == 0) {
            height = std::stoll(arg.substr(9));
        } else if (arg.rfind("--hash=", 0) == 0) {
            hash_hex = arg.substr(7);
        } else if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        } else if (arg == "--dry-run") {
            dry_run = true;
        } else if (arg == "--force" || arg == "-f") {
            force = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg[0] != '-') {
            command = arg;
        }
    }

    if (datadir.empty()) {
        std::cerr << "ERROR: --datadir is required\n";
        print_usage();
        return 1;
    }

    if (command.empty()) {
        std::cerr << "ERROR: No command specified\n";
        print_usage();
        return 1;
    }

    // Open block storage
    RawBlockReader reader;
    if (!reader.open(datadir)) {
        std::cerr << "ERROR: Failed to open data directory\n";
        return 1;
    }

    // Execute command
    if (command == "scan") {
        return cmd_scan(reader, verbose);
    } else if (command == "info") {
        return cmd_info(reader, height, hash_hex);
    } else if (command == "truncate") {
        if (height < 0) {
            std::cerr << "ERROR: --height is required for truncate command\n";
            return 1;
        }
        return cmd_truncate(reader, static_cast<size_t>(height), dry_run, force);
    } else if (command == "verify") {
        return cmd_verify(reader, verbose);
    } else {
        std::cerr << "ERROR: Unknown command: " << command << "\n";
        print_usage();
        return 1;
    }
}
