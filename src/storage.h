#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace miq {
class Storage {
public:
    bool open(const std::string& dir);
    bool append_block(const std::vector<uint8_t>& raw, const std::vector<uint8_t>& hash);
    bool read_block_by_index(size_t index, std::vector<uint8_t>& out) const;
    bool read_block_by_hash(const std::vector<uint8_t>& hash, std::vector<uint8_t>& out) const;
    // CRITICAL PERFORMANCE: Check if block exists WITHOUT reading it from disk
    // This is O(1) hash lookup instead of O(block_size) disk read
    bool has_block(const std::vector<uint8_t>& hash) const;
    size_t count() const { return offsets_.size(); }
    bool write_state(const std::vector<uint8_t>& b);
    bool read_state(std::vector<uint8_t>& b) const;

    // RECOVERY: Remove a block hash from the index so it can be re-requested
    // This is used when a block is found to be corrupted - removes from hash.map only
    // The block data stays in blocks.dat but becomes "orphaned" and will be overwritten
    bool invalidate_block(const std::vector<uint8_t>& hash);

    // DIAGNOSTICS: Check if a block at a given index can be read and deserialized
    bool validate_block_at_index(size_t index) const;

    // Get the number of indexed blocks
    size_t indexed_count() const { return hash_to_index_.size(); }
private:
    std::string path_blocks_, path_state_, path_index_, path_hashmap_;
    mutable std::vector<uint64_t> offsets_;
    mutable std::unordered_map<std::string, uint32_t> hash_to_index_;
};
}
