#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <tuple>
#include <mutex>           // CRITICAL FIX: Thread safety

namespace miq {

struct UTXOEntry {
    uint64_t value;
    std::vector<uint8_t> pkh;
    uint64_t height;
    bool coinbase;
};

class UTXOSet {
public:
    bool open(const std::string& dir);
    bool add(const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry& e);
    bool spend(const std::vector<uint8_t>& txid, uint32_t vout);
    bool get(const std::vector<uint8_t>& txid, uint32_t vout, UTXOEntry& out) const;
    size_t size() const { return map_.size(); }
    void clear();  // Clear UTXO set and log for rebuild

    // CRITICAL FIX: Flush entire in-memory map to disk
    // Must be called after IBD completes to persist UTXOs that were skipped during fast sync
    bool flush_to_disk();

    // Enumerate live UTXOs for a given PKH. Returns (txid, vout, entry).
    std::vector<std::tuple<std::vector<uint8_t>, uint32_t, UTXOEntry>>
    list_for_pkh(const std::vector<uint8_t>& pkh) const;

private:
    // CRITICAL FIX: Thread safety - protect all mutable state
    mutable std::mutex mtx_;

    std::string log_path_;
    std::unordered_map<std::string, UTXOEntry> map_; // key = hex(txid)+":"+vout

    bool append_log(char op, const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry* e);
    std::string key(const std::vector<uint8_t>& txid, uint32_t vout) const;
    bool load_log();
};

} // namespace miq
