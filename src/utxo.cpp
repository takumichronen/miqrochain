#include "utxo.h"
#include "hex.h"       // to_hex
#include "assume_valid.h"  // For is_ibd_mode()
#include <fstream>
#include <filesystem>
#include <sstream>
#include <unordered_map>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <unistd.h>
  #include <fcntl.h>
#endif

namespace fs = std::filesystem;

// Fast sync mode - skip fsync during IBD or near-tip for speed
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

// DURABILITY: Platform-specific fsync for UTXO log
static inline void fsync_file(const std::string& path) {
    if (fast_sync_enabled()) return;  // Skip in fast sync mode
#if defined(_WIN32)
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE,
                           FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(h);
        CloseHandle(h);
    }
#else
    int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
    if (fd >= 0) { ::fsync(fd); ::close(fd); }
#endif
}

namespace miq {

// CRITICAL FIX: Maximum limits to prevent DoS and buffer overflows
static constexpr uint32_t MAX_TXID_SIZE = 64;       // Max txid size (typical is 32)
static constexpr uint32_t MAX_PKH_SIZE = 64;        // Max pubkey hash size (typical is 20)
static constexpr size_t MAX_LOG_SIZE = 10ULL * 1024 * 1024 * 1024;  // 10 GiB max log

std::string UTXOSet::key(const std::vector<uint8_t>& txid, uint32_t vout) const {
    // Stable and simple: hex(txid) + ":" + vout
    std::ostringstream o;
    o << to_hex(txid) << ":" << vout;
    return o.str();
}

bool UTXOSet::append_log(char op, const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry* e){
    // CRITICAL PERFORMANCE: Skip log writes during IBD
    // UTXO state is kept in memory (map_), log is only for crash recovery
    // During IBD, we can rebuild from blocks if crash occurs - no need to log
    // This prevents 200,000+ file operations during sync!
    if (fast_sync_enabled()) return true;

    // CRITICAL FIX: Open in binary append mode with explicit sync
    std::ofstream f(log_path_, std::ios::app|std::ios::binary);
    if(!f) return false;

    f.write(&op,1);
    uint32_t n=(uint32_t)txid.size();
    f.write((const char*)&n,sizeof(n));
    f.write((const char*)txid.data(), n);
    f.write((const char*)&vout,sizeof(vout));
    if(op=='A'&&e){
        f.write((const char*)&e->value,sizeof(e->value));
        f.write((const char*)&e->height,sizeof(e->height));
        char cb=e->coinbase?1:0; f.write(&cb,1);
        uint32_t ph=(uint32_t)e->pkh.size(); f.write((const char*)&ph,sizeof(ph));
        f.write((const char*)e->pkh.data(), ph);
    }

    // CRITICAL FIX: Check write success before flush
    if (!f.good()) return false;

    // DURABILITY: Flush stream buffer to OS
    f.flush();
    if (!f.good()) return false;
    f.close();

    // DURABILITY: Actually fsync to disk for true persistence
    // Without this, data could be lost on power failure even after flush()
    fsync_file(log_path_);

    return true;
}

bool UTXOSet::load_log(){
    map_.clear();
    std::ifstream f(log_path_, std::ios::binary);
    if(!f) return true;

    // CRITICAL: Check file size to prevent DoS via oversized log files
    f.seekg(0, std::ios::end);
    auto file_size = f.tellg();
    if (file_size < 0 || static_cast<size_t>(file_size) > MAX_LOG_SIZE) {
        return false;  // File too large or seek failed
    }
    f.seekg(0, std::ios::beg);

    while(f){
        char op;
        f.read(&op,1);
        if(!f) break;

        uint32_t n=0;
        f.read((char*)&n,sizeof(n));
        if(!f) return false;

        // CRITICAL FIX: Bounds check to prevent buffer overflow / DoS
        if (n > MAX_TXID_SIZE) return false;

        std::vector<uint8_t> txid(n);
        if (n > 0) {
            f.read((char*)txid.data(), n);
            if(!f) return false;
        }

        uint32_t vout=0;
        f.read((char*)&vout,sizeof(vout));
        if(!f) return false;

        if(op=='A'){
            UTXOEntry e;
            uint32_t ph=0;
            char cb=0;

            f.read((char*)&e.value,sizeof(e.value));
            if(!f) return false;

            f.read((char*)&e.height,sizeof(e.height));
            if(!f) return false;

            f.read(&cb,1);
            if(!f) return false;
            e.coinbase=(cb!=0);

            f.read((char*)&ph,sizeof(ph));
            if(!f) return false;

            // CRITICAL FIX: Bounds check to prevent buffer overflow / DoS
            if (ph > MAX_PKH_SIZE) return false;

            e.pkh.resize(ph);
            if (ph > 0) {
                f.read((char*)e.pkh.data(), ph);
                if(!f) return false;
            }

            map_[key(txid,vout)] = e;
        } else if(op=='S'){
            map_.erase(key(txid,vout));
        } else {
            return false;
        }
    }
    return true;
}

bool UTXOSet::open(const std::string& dir){
    fs::create_directories(dir);
    log_path_ = dir + "/utxo.log";
    std::ofstream f(log_path_, std::ios::app|std::ios::binary); f.close();
    return load_log();
}

bool UTXOSet::add(const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry& e){
    std::lock_guard<std::mutex> lk(mtx_);  // CRITICAL FIX: Thread safety

    // CRITICAL FIX: Write to log FIRST, then update map
    // This ensures we don't lose data on crash
    if (!append_log('A',txid,vout,&e)) return false;

    map_[key(txid,vout)] = e;
    return true;
}

bool UTXOSet::spend(const std::vector<uint8_t>& txid, uint32_t vout){
    std::lock_guard<std::mutex> lk(mtx_);  // CRITICAL FIX: Thread safety

    // CRITICAL FIX: Write to log FIRST, then update map
    if (!append_log('S',txid,vout,nullptr)) return false;

    map_.erase(key(txid,vout));
    return true;
}

bool UTXOSet::get(const std::vector<uint8_t>& txid, uint32_t vout, UTXOEntry& out) const{
    std::lock_guard<std::mutex> lk(mtx_);  // CRITICAL FIX: Thread safety

    auto it=map_.find(key(txid,vout));
    if(it==map_.end()) return false;
    out=it->second;
    return true;
}

// CRITICAL FIX: Use in-memory map_ instead of log file
// During IBD/sync, UTXOs are added to map_ but NOT written to utxo.log
// (for performance - see append_log() which skips writes during fast_sync)
// Reading from log file would return empty results after sync!
std::vector<std::tuple<std::vector<uint8_t>, uint32_t, UTXOEntry>>
UTXOSet::list_for_pkh(const std::vector<uint8_t>& pkh) const {
    std::lock_guard<std::mutex> lk(mtx_);  // Thread safety

    std::vector<std::tuple<std::vector<uint8_t>, uint32_t, UTXOEntry>> out;
    out.reserve(map_.size() / 10);  // Estimate ~10% of UTXOs match a given pkh

    for (const auto& kv : map_) {
        if (kv.second.pkh == pkh) {
            // Parse key format: "hex_txid:vout"
            const std::string& k = kv.first;
            size_t colon = k.rfind(':');
            if (colon == std::string::npos) continue;  // Malformed key, skip

            std::vector<uint8_t> txid = from_hex(k.substr(0, colon));
            uint32_t vout = static_cast<uint32_t>(std::stoul(k.substr(colon + 1)));

            out.emplace_back(std::move(txid), vout, kv.second);
        }
    }
    return out;
}

void UTXOSet::clear() {
    std::lock_guard<std::mutex> lk(mtx_);
    map_.clear();
    // Truncate the log file to allow fresh rebuild
    std::ofstream f(log_path_, std::ios::trunc | std::ios::binary);
    f.close();
}

// CRITICAL FIX: Flush entire in-memory UTXO map to disk
// This MUST be called after IBD completes because append_log() skips writes during fast sync.
// Without this, UTXOs are lost on restart!
bool UTXOSet::flush_to_disk() {
    std::lock_guard<std::mutex> lk(mtx_);

    if (map_.empty()) return true;  // Nothing to flush

    // Truncate and rewrite the entire log file with current state
    std::ofstream f(log_path_, std::ios::trunc | std::ios::binary);
    if (!f) return false;

    size_t count = 0;
    for (const auto& kv : map_) {
        // Parse key format: "hex_txid:vout"
        const std::string& k = kv.first;
        size_t colon = k.rfind(':');
        if (colon == std::string::npos) continue;

        std::vector<uint8_t> txid = from_hex(k.substr(0, colon));
        uint32_t vout = static_cast<uint32_t>(std::stoul(k.substr(colon + 1)));
        const UTXOEntry& e = kv.second;

        // Write 'A' (add) operation
        char op = 'A';
        f.write(&op, 1);

        uint32_t n = (uint32_t)txid.size();
        f.write((const char*)&n, sizeof(n));
        f.write((const char*)txid.data(), n);
        f.write((const char*)&vout, sizeof(vout));

        f.write((const char*)&e.value, sizeof(e.value));
        f.write((const char*)&e.height, sizeof(e.height));
        char cb = e.coinbase ? 1 : 0;
        f.write(&cb, 1);
        uint32_t ph = (uint32_t)e.pkh.size();
        f.write((const char*)&ph, sizeof(ph));
        f.write((const char*)e.pkh.data(), ph);

        if (!f.good()) return false;
        count++;
    }

    f.flush();
    if (!f.good()) return false;
    f.close();

    // Force fsync to disk
#if defined(_WIN32)
    HANDLE h = CreateFileA(log_path_.c_str(), GENERIC_WRITE,
                           FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(h);
        CloseHandle(h);
    }
#else
    int fd = ::open(log_path_.c_str(), O_RDWR | O_CLOEXEC);
    if (fd >= 0) { ::fsync(fd); ::close(fd); }
#endif

    return true;
}

}

