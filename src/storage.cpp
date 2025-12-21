#include "storage.h"
#include "hex.h"
#include "log.h"  // For log_warn
#include "assume_valid.h"  // For is_ibd_mode()
#include "serialize.h"  // For deser_block
#include "block.h"      // For Block::block_hash()
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <unordered_set>

#if defined(_WIN32)
  #include <windows.h>
  static inline void flush_path(const std::string& p){
      // CRITICAL FIX: Aggressive retry for Windows file locks
      // Windows antivirus (Defender), indexing services, and cloud sync (OneDrive)
      // can hold file locks for 500ms+ - must retry aggressively!
      // Increased from 3 retries (150ms max) to 10 retries (1000ms max)
      HANDLE h = INVALID_HANDLE_VALUE;
      static constexpr int MAX_RETRIES = 10;        // Was 3
      static constexpr int RETRY_DELAY_MS = 100;    // Was 50ms

      for (int retry = 0; retry < MAX_RETRIES && h == INVALID_HANDLE_VALUE; ++retry) {
          h = CreateFileA(p.c_str(), GENERIC_WRITE,
                          FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
          if (h == INVALID_HANDLE_VALUE && retry < MAX_RETRIES - 1) {
              // Use SleepEx with alertable=FALSE to avoid APC issues
              // Exponential backoff: 100ms, 100ms, 100ms... (capped at RETRY_DELAY_MS)
              Sleep(RETRY_DELAY_MS);
          }
      }
      if (h != INVALID_HANDLE_VALUE) {
          if (!FlushFileBuffers(h)) {
              // Log flush failure - data may not be persisted to disk
              DWORD err = GetLastError();
              miq::log_warn("Storage: FlushFileBuffers failed for " + p +
                      " error=" + std::to_string(err));
          }
          CloseHandle(h);
      } else {
          // WINDOWS FIX: Reduced logging frequency - file lock failures are common
          // during IBD on Windows and flooding the log makes debugging harder
          static std::atomic<int64_t> last_log_ms{0};
          static std::atomic<int> suppressed_count{0};
          DWORD err = GetLastError();
          int64_t now = GetTickCount64();
          if (now - last_log_ms.load() > 30000) { // Log at most every 30 seconds
              int suppressed = suppressed_count.exchange(0);
              if (suppressed > 0) {
                  miq::log_warn("Storage: CreateFileA failed for flush " + p +
                          " error=" + std::to_string(err) +
                          " (suppressed " + std::to_string(suppressed) + " similar)");
              } else {
                  miq::log_warn("Storage: CreateFileA failed for flush " + p +
                          " error=" + std::to_string(err));
              }
              last_log_ms.store(now);
          } else {
              suppressed_count.fetch_add(1);
          }
      }
  }
#else
  #include <unistd.h>
  #include <fcntl.h>
  static inline void flush_path(const std::string& p){
      int fd = ::open(p.c_str(), O_RDWR | O_CLOEXEC);
      if (fd >= 0) { ::fsync(fd); ::close(fd); }
  }
#endif

namespace fs = std::filesystem;
namespace miq {

// PERFORMANCE: Skip fsync during IBD or near-tip for fast block processing
// CRITICAL FIX: Also check near-tip mode for <1s warm datadir completion
static bool fast_sync_enabled() {
    // Always skip fsync during IBD for 10-100x faster sync
    if (miq::is_ibd_mode()) return true;
    // CRITICAL: Also skip fsync in near-tip mode for sub-second warm datadir sync
    if (miq::is_near_tip_mode()) return true;
    // Manual override via environment variable
    const char* e = std::getenv("MIQ_FAST_SYNC");
    return e && (e[0]=='1' || e[0]=='t' || e[0]=='T' || e[0]=='y' || e[0]=='Y');
}
[[maybe_unused]] static inline int64_t now_ms_steady(){
    using clock = std::chrono::steady_clock;
    return std::chrono::duration_cast<std::chrono::milliseconds>(clock::now().time_since_epoch()).count();
}

bool Storage::open(const std::string& dir){
    fs::create_directories(dir);
    path_blocks_ = dir + "/blocks.dat";
    path_state_  = dir + "/state.dat";
    path_index_  = dir + "/blocks.idx";
    path_hashmap_ = dir + "/hash.map";
    offsets_.clear(); hash_to_index_.clear();
    std::ofstream ensure(path_blocks_, std::ios::app|std::ios::binary); ensure.close();
    std::ifstream f(path_blocks_, std::ios::binary);
    uint64_t off=0; [[maybe_unused]] uint32_t idx=0;

    // STABILITY FIX: Limit maximum block size to prevent corrupt file hangs
    static constexpr uint32_t STORAGE_MAX_BLOCK_SIZE = 32 * 1024 * 1024; // 32 MB max block
    static constexpr uint32_t MAX_KEY_SIZE = 1024; // Max hash key size

    while(true){
        uint32_t sz=0; f.read((char*)&sz,sizeof(sz)); if(!f) break;
        // STABILITY FIX: Validate block size to prevent corrupt file issues
        if (sz == 0 || sz > STORAGE_MAX_BLOCK_SIZE) {
            log_warn("Storage: corrupt blocks.dat detected at offset " + std::to_string(off));
            break;
        }
        offsets_.push_back(off);
        f.seekg(sz, std::ios::cur);
        if (!f) break; // Check seek succeeded
        off = (uint64_t)f.tellg(); idx++;
    }
    // load hashmap
    std::ifstream hm(path_hashmap_, std::ios::binary);
    while(hm){
        uint32_t ksz=0; hm.read((char*)&ksz,sizeof(ksz)); if(!hm) break;
        // STABILITY FIX: Validate key size
        if (ksz == 0 || ksz > MAX_KEY_SIZE) {
            log_warn("Storage: corrupt hash.map detected");
            break;
        }
        std::string k(ksz,'\0'); hm.read(&k[0], ksz); uint32_t vi=0; hm.read((char*)&vi,sizeof(vi)); hash_to_index_[k]=vi;
    }

    // CRITICAL FIX: Rebuild hash.map if it has fewer entries than blocks.dat
    // This can happen after a crash during IBD when hash.map wasn't fsynced.
    // Without this fix, blocks exist in storage but can't be looked up by hash,
    // causing "possible index corruption" errors and sync failures.
    if (hash_to_index_.size() < offsets_.size()) {
        size_t missing_count = offsets_.size() - hash_to_index_.size();
        log_warn("Storage: hash.map has " + std::to_string(hash_to_index_.size()) +
                 " entries but blocks.dat has " + std::to_string(offsets_.size()) +
                 " blocks - rebuilding " + std::to_string(missing_count) + " missing entries...");

        // Build a set of indices we already have in hash_to_index_
        std::unordered_set<uint32_t> known_indices;
        for (const auto& kv : hash_to_index_) {
            known_indices.insert(kv.second);
        }

        // Scan all blocks and add missing ones to hash_to_index_
        size_t rebuilt = 0;
        std::ofstream hm_append(path_hashmap_, std::ios::app|std::ios::binary);

        for (size_t i = 0; i < offsets_.size(); ++i) {
            if (known_indices.count((uint32_t)i)) {
                continue;  // Already have this index
            }

            // Read the block and compute its hash
            std::vector<uint8_t> raw;
            if (!read_block_by_index(i, raw)) {
                log_warn("Storage: failed to read block at index " + std::to_string(i) + " during hash.map rebuild");
                continue;
            }

            Block blk;
            if (!deser_block(raw, blk)) {
                log_warn("Storage: failed to deserialize block at index " + std::to_string(i) + " during hash.map rebuild");
                continue;
            }

            // Compute hash and add to index
            std::vector<uint8_t> hash = blk.block_hash();
            std::string hexh = to_hex(hash);
            hash_to_index_[hexh] = (uint32_t)i;

            // Persist to hash.map file
            if (hm_append) {
                uint32_t ksz = (uint32_t)hexh.size();
                uint32_t idx_val = (uint32_t)i;
                hm_append.write((const char*)&ksz, sizeof(ksz));
                hm_append.write(hexh.c_str(), ksz);
                hm_append.write((const char*)&idx_val, sizeof(idx_val));
            }

            rebuilt++;
        }

        if (hm_append) {
            hm_append.flush();
            flush_path(path_hashmap_);
        }

        log_info("Storage: rebuilt " + std::to_string(rebuilt) + " missing hash.map entries");
    }

    return true;
}
// Append a block, update offsets and hash->index, then fsync all files.
bool miq::Storage::append_block(const std::vector<uint8_t>& raw,
                                const std::vector<uint8_t>& hash){
    std::ofstream f(path_blocks_, std::ios::app|std::ios::binary);
    if(!f) return false;

    // STABILITY FIX: Handle file_size() exception gracefully
    uint64_t off = 0;
    try {
        off = (uint64_t)std::filesystem::file_size(path_blocks_);
    } catch (const std::exception& e) {
        log_warn("Storage: failed to get file size: " + std::string(e.what()));
        return false;
    }
    uint32_t sz  = (uint32_t)raw.size();
    f.write((const char*)&sz, sizeof(sz));
    f.write((const char*)raw.data(), sz);
    f.flush();
    if (!fast_sync_enabled()) { flush_path(path_blocks_); }

    offsets_.push_back(off);
    uint32_t idx = (uint32_t)offsets_.size()-1;
    const std::string hexh = miq::to_hex(hash);
    hash_to_index_[hexh] = idx;

    // persist index and hashmap append-only (with flush)
    {
        std::ofstream idxf(path_index_, std::ios::app|std::ios::binary);
        idxf.write((const char*)&off, sizeof(off));
        idxf.flush();
        // CRITICAL FIX: Skip fsync during IBD - was causing 2x slowdown!
        if (!fast_sync_enabled()) { flush_path(path_index_); }
    }
    {
        std::ofstream hm(path_hashmap_, std::ios::app|std::ios::binary);
        uint32_t ksz = (uint32_t)hexh.size();
        hm.write((const char*)&ksz, sizeof(ksz));
        hm.write(hexh.c_str(), ksz);
        hm.write((const char*)&idx, sizeof(idx));
        hm.flush(); if (!fast_sync_enabled()) { flush_path(path_hashmap_); }
    }
    return true;
}

bool miq::Storage::read_block_by_index(size_t index, std::vector<uint8_t>& out) const{
    if(index >= offsets_.size()) return false;
    std::ifstream f(path_blocks_, std::ios::binary);
    if(!f) return false;

    f.seekg((std::streamoff)offsets_[index], std::ios::beg);
    uint32_t sz = 0;
    if(!f.read((char*)&sz, sizeof(sz))) return false;

    // CRITICAL FIX: Validate block size to prevent segfault on corrupted blocks.dat
    // Without this check, a corrupted file could cause out.resize() to allocate
    // gigabytes of memory, leading to std::bad_alloc or OOM crash
    static constexpr uint32_t STORAGE_MAX_BLOCK_SIZE = 32 * 1024 * 1024; // 32 MB max
    if (sz == 0 || sz > STORAGE_MAX_BLOCK_SIZE) {
        log_warn("Storage: block at index " + std::to_string(index) +
                 " has invalid size (" + std::to_string(sz) + " bytes), skipping");
        return false;  // Corrupted or invalid block size - caller will handle recovery
    }

    out.resize(sz);
    return (bool)f.read((char*)out.data(), sz);
}

bool miq::Storage::read_block_by_hash(const std::vector<uint8_t>& hash,
                                      std::vector<uint8_t>& out) const{
    auto it = hash_to_index_.find(miq::to_hex(hash));
    if(it == hash_to_index_.end()) return false;
    return read_block_by_index(it->second, out);
}

// CRITICAL PERFORMANCE FIX: Check block existence without disk I/O
// The old have_block() was reading entire blocks from disk just to check existence!
// This caused massive slowdown during sync - 5000+ disk reads per sync!
bool miq::Storage::has_block(const std::vector<uint8_t>& hash) const {
    return hash_to_index_.find(miq::to_hex(hash)) != hash_to_index_.end();
}

bool miq::Storage::write_state(const std::vector<uint8_t>& b){
    // DURABILITY: Atomic write - write to .tmp then rename
    // This prevents corruption if crash occurs during write
    std::string temp_path = path_state_ + ".tmp";
    std::ofstream f(temp_path, std::ios::binary|std::ios::trunc);
    if(!f) return false;
    f.write((const char*)b.data(), b.size());
    f.flush();
    f.close();
    // CRITICAL FIX: Skip fsync during IBD for much faster sync
    // State can be rebuilt from blocks if crash during IBD
    if (!fast_sync_enabled()) { flush_path(temp_path); }
    // Atomic rename - either old state or new state, never partial
    try {
        std::filesystem::rename(temp_path, path_state_);
    } catch (...) {
        return false;
    }
    return true;
}

bool miq::Storage::read_state(std::vector<uint8_t>& out) const {
    std::ifstream f(path_state_, std::ios::binary);
    if (!f) return false;                 // no state file → caller may treat as "fresh"
    f.seekg(0, std::ios::end);
    std::streamoff end = f.tellg();
    if (end < 0) return false;
    size_t sz = static_cast<size_t>(end);

    // CRITICAL FIX: Validate state file size to prevent issues with corrupted files
    // State file should be small (~100 bytes), reject anything unreasonably large
    static constexpr size_t MAX_STATE_SIZE = 1024 * 1024; // 1 MB max (way more than needed)
    if (sz > MAX_STATE_SIZE) {
        log_warn("Storage: state.dat is corrupted (size " + std::to_string(sz) +
                 " bytes), will rebuild from blocks");
        return false;
    }

    f.seekg(0, std::ios::beg);
    out.resize(sz);
    if (sz == 0) return true;             // empty state is valid
    return (bool)f.read(reinterpret_cast<char*>(out.data()), sz);
}

// RECOVERY: Remove a block hash from the index so it can be re-requested
// This is used when a block is found to be corrupted
bool miq::Storage::invalidate_block(const std::vector<uint8_t>& hash) {
    std::string hexh = miq::to_hex(hash);
    auto it = hash_to_index_.find(hexh);
    if (it == hash_to_index_.end()) {
        log_warn("Storage::invalidate_block: hash " + hexh + " not found in index");
        return false;
    }

    uint32_t index = it->second;
    log_warn("Storage::invalidate_block: removing block at index " + std::to_string(index) +
             " (hash " + hexh + ") from index - will be re-requested from peers");

    // Remove from in-memory index
    hash_to_index_.erase(it);

    // Rewrite hash.map file without this block
    std::ofstream hf(path_hashmap_, std::ios::binary | std::ios::trunc);
    if (!hf) {
        log_warn("Storage::invalidate_block: failed to rewrite hash.map");
        return false;
    }

    for (const auto& kv : hash_to_index_) {
        // Key format: [uint32_t key_size][key_data][uint32_t index]
        uint32_t ksz = (uint32_t)kv.first.size();
        hf.write((const char*)&ksz, sizeof(ksz));
        hf.write(kv.first.c_str(), ksz);
        hf.write((const char*)&kv.second, sizeof(kv.second));
    }
    hf.close();

    log_info("Storage::invalidate_block: block " + hexh + " removed from index, will be re-synced");
    return true;
}

// DIAGNOSTICS: Check if a block at a given index can be read and deserialized
bool miq::Storage::validate_block_at_index(size_t index) const {
    if (index >= offsets_.size()) {
        log_error("Storage::validate_block_at_index(" + std::to_string(index) +
                 "): index out of range (max " + std::to_string(offsets_.size()) + ")");
        return false;
    }

    std::ifstream f(path_blocks_, std::ios::binary);
    if (!f) {
        log_error("Storage::validate_block_at_index: cannot open blocks.dat");
        return false;
    }

    f.seekg((std::streamoff)offsets_[index], std::ios::beg);
    uint32_t sz = 0;
    if (!f.read((char*)&sz, sizeof(sz))) {
        log_error("Storage::validate_block_at_index(" + std::to_string(index) +
                 "): cannot read size field at offset " + std::to_string(offsets_[index]));
        return false;
    }

    static constexpr uint32_t STORAGE_MAX_BLOCK_SIZE = 32 * 1024 * 1024;
    if (sz == 0 || sz > STORAGE_MAX_BLOCK_SIZE) {
        log_error("Storage::validate_block_at_index(" + std::to_string(index) +
                 "): invalid block size " + std::to_string(sz) + " bytes");
        return false;
    }

    std::vector<uint8_t> raw(sz);
    if (!f.read((char*)raw.data(), sz)) {
        log_error("Storage::validate_block_at_index(" + std::to_string(index) +
                 "): cannot read " + std::to_string(sz) + " bytes of block data");
        return false;
    }

    // Try to deserialize
    miq::Block blk;
    if (!miq::deser_block(raw, blk)) {
        log_error("Storage::validate_block_at_index(" + std::to_string(index) +
                 "): deser_block failed - block data is corrupted");
        return false;
    }

    // Validate block has at least one transaction (coinbase)
    if (blk.txs.empty()) {
        log_error("Storage::validate_block_at_index(" + std::to_string(index) +
                 "): block has no transactions");
        return false;
    }

    log_info("Storage::validate_block_at_index(" + std::to_string(index) +
             "): block is valid (" + std::to_string(blk.txs.size()) + " txs, " +
             std::to_string(sz) + " bytes)");
    return true;
}

} // namespace miq
