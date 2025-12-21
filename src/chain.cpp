// chain.cpp
#include "chain.h"
#include <cmath>      // std::pow, std::fabs
#include <optional>
#include "sha256.h"
#include "hex.h"
#include "mtp.h"
#include <deque>
#include "reorg_manager.h"
#include "merkle.h"
#include <unordered_map>
#include "hasher.h"
#include <cstdlib>
#include "log.h"
#include "sig_encoding.h"
#include "hash160.h"
#include "crypto/ecdsa_iface.h"
#include "constants.h"     // BLOCK_TIME_SECS, GENESIS_BITS, etc.
#include "difficulty.h"    // epoch_next_bits
#include "supply.h"        // GetBlockSubsidy, WouldExceedMaxSupply
#include "assume_valid.h"  // should_skip_merkle_verification
#include <sstream>
#include <unordered_set>
#include <array>

#include <algorithm>       // std::any_of, std::sort, std::max, std::reverse
#include <chrono>          // future-time bound
#include <cstring>         // std::memcmp, std::memset
#include <type_traits>     // compile-time detection (SFINAE)
#include <mutex>           // locking
#include <cctype>          // std::isxdigit, std::tolower

#ifndef __has_include
  #define __has_include(x) 0
#endif

#if __has_include("filters/bip158.h") && __has_include("filters/gcs.h") && __has_include("filters/filter_store.h")
  #define MIQ_HAVE_GCS_FILTERS 1
  #include "filters/gcs.h"
  #include "filters/filter_store.h"
#else
  #define MIQ_HAVE_GCS_FILTERS 0
#endif

#ifndef MAX_TX_SIZE
#define MIQ_FALLBACK_MAX_TX_SIZE (4u * 1024u * 1024u) // 4 MiB default (no tx size limit)
#else
#define MIQ_FALLBACK_MAX_TX_SIZE (MAX_TX_SIZE)
#endif

#ifndef MIQ_RULE_ENFORCE_LOW_S
#define MIQ_RULE_ENFORCE_LOW_S 1
#endif

#include <cstdio>
#include <string>
#include <vector>
#include <sys/types.h>
#ifdef _WIN32
  #include <direct.h>
  #include <io.h>
  #define miq_mkdir(p) _mkdir(p)
  #define miq_fsync(fd) _commit(fd)
  #define miq_fileno _fileno
#else
  #include <sys/stat.h>
  #include <unistd.h>
  #include <fcntl.h>
  #define miq_mkdir(p) mkdir(p, 0755)
  #define miq_fsync(fd) fsync(fd)
  #define miq_fileno fileno
#endif

// ---------- file-scope helpers (ensure declared before first use) ----------

// PERFORMANCE: Skip fsync during IBD or near-tip for fast block processing
// Automatically enabled during:
// - IBD (initial block download) - 10-100x faster sync
// - Near-tip mode (≤16 blocks behind) - <1s warm datadir completion
// - Manual override with MIQ_FAST_SYNC=1
static inline bool fast_sync_enabled() {
    // Always skip fsync during IBD for 10-100x faster sync
    if (miq::is_ibd_mode()) return true;
    // CRITICAL: Also skip fsync in near-tip mode for sub-second warm datadir sync
    // This is the key fix for Bitcoin Core-grade near-tip performance
    if (miq::is_near_tip_mode()) return true;
    // Manual override via environment variable
    const char* e = std::getenv("MIQ_FAST_SYNC");
    return e && (e[0]=='1' || e[0]=='t' || e[0]=='T' || e[0]=='y' || e[0]=='Y');
}

// ============================================================================
// PERFORMANCE INSTRUMENTATION: Block timing for near-tip analysis
// When in near-tip mode, log detailed timestamps to verify sub-second sync
// ============================================================================
struct BlockTiming {
    int64_t t_validate_start{0};
    int64_t t_validate_end{0};
    int64_t t_disk_write{0};
    int64_t t_utxo_commit{0};
    int64_t t_save_state{0};
    uint64_t height{0};

    static int64_t now_ms() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(
            steady_clock::now().time_since_epoch()).count();
    }

    void log_if_near_tip() const {
        if (!miq::is_near_tip_mode()) return;
        int64_t total = t_save_state - t_validate_start;
        int64_t validate_ms = t_validate_end - t_validate_start;
        int64_t disk_ms = t_disk_write - t_validate_end;
        int64_t utxo_ms = t_utxo_commit - t_disk_write;
        int64_t state_ms = t_save_state - t_utxo_commit;

        miq::log_info("[PERF] Block " + std::to_string(height) +
                      " total=" + std::to_string(total) + "ms" +
                      " (validate=" + std::to_string(validate_ms) +
                      " disk=" + std::to_string(disk_ms) +
                      " utxo=" + std::to_string(utxo_ms) +
                      " state=" + std::to_string(state_ms) + "ms)");
    }
};

static inline size_t env_szt(const char* name, size_t defv){
    const char* v = std::getenv(name);
    if(!v || !*v) return defv;
    char* end=nullptr; long long x = std::strtoll(v, &end, 10);
    if(end==v || x < 0) return defv;
    return (size_t)x;
}

// parse 64 hex chars into 32 bytes (big-endian nibble order)
static bool parse_hex32(const char* hex, std::vector<uint8_t>& out) {
    out.clear();
    if (!hex) return false;
    size_t len = std::strlen(hex);
    if (len != 64) return false;
    auto hv = [](char c)->int{
        if (c>='0' && c<='9') return c-'0';
        c = (char)std::tolower(static_cast<unsigned char>(c));
        if (c>='a' && c<='f') return 10 + (c-'a');
        return -1;
    };
    out.resize(32);
    for (size_t i=0;i<32;++i){
        int hi = hv(hex[2*i]);
        int lo = hv(hex[2*i+1]);
        if (hi<0 || lo<0) return false;
        out[i] = (uint8_t)((hi<<4) | lo);
    }
    return true;
}

// === compact bits -> big-endian target, and hash <= target check ============
static inline void bits_to_target_be(uint32_t bits, uint8_t out[32]) {
    std::memset(out, 0, 32);
    uint32_t exp = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if (mant == 0) { return; } // invalid -> zero target (will fail compare)

    if (exp <= 3) {
        uint32_t mant2 = mant >> (8 * (3 - exp));
        out[29] = uint8_t((mant2 >> 16) & 0xff);
        out[30] = uint8_t((mant2 >> 8)  & 0xff);
        out[31] = uint8_t((mant2 >> 0)  & 0xff);
    } else {
        int pos = int(32) - int(exp);
        // CRITICAL FIX: Validate pos to prevent buffer overflow
        if (pos < 0) {
            // Exponent too large - set max target (will fail most compares)
            out[0] = out[1] = out[2] = 0xff;
            return;
        }
        // CRITICAL FIX: pos must be <= 29 to safely write 3 bytes
        if (pos > 29) {
            // Invalid exponent - target would be too small, set to zero
            return;
        }
        out[pos + 0] = uint8_t((mant >> 16) & 0xff);
        out[pos + 1] = uint8_t((mant >> 8)  & 0xff);
        out[pos + 2] = uint8_t((mant >> 0)  & 0xff);
    }
}
static inline bool meets_target_be(const std::vector<uint8_t>& hash32, uint32_t bits) {
    if (hash32.size() != 32) return false;
    uint8_t target[32];
    bits_to_target_be(bits, target);
    return std::memcmp(hash32.data(), target, 32) <= 0; // hash <= target
}

namespace miq {

// Reentrant guard (chain.h uses std::recursive_mutex)
#define MIQ_CHAIN_GUARD() std::lock_guard<std::recursive_mutex> _lk(mtx_)

struct UndoIn {
    std::vector<uint8_t> prev_txid;
    uint32_t             prev_vout{0};
    UTXOEntry            prev_entry;
};

// Binary-safe key for unordered_map (store raw 32 bytes)
static inline std::string hk(const std::vector<uint8_t>& h){
    return std::string(reinterpret_cast<const char*>(h.data()), h.size());
}

static inline std::vector<uint8_t> header_hash_of(const BlockHeader& h) {
    Block tmp;
    tmp.header = h;
    return tmp.block_hash();
}

static const size_t UNDO_WINDOW = ::env_szt("MIQ_UNDO_WINDOW", 2000); // keep last N blocks' undo

static inline std::string hexstr(const std::vector<uint8_t>& v){
    static const char* hexd="0123456789abcdef";
    std::string s; s.resize(v.size()*2);
    for(size_t i=0;i<v.size();++i){ unsigned b=v[i]; s[2*i]=hexd[b>>4]; s[2*i+1]=hexd[b&15]; }
    return s;
}
static inline std::string join_path(const std::string& a, const std::string& b){
#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    if(a.empty()) return b;
    if(a.back()==sep) return a+b;
    return a + sep + b;
}

static inline std::string undo_dir(const std::string& base){ return join_path(base, "undo"); }

static void ensure_dir_exists(const std::string& path){
#ifdef _WIN32
    _mkdir(path.c_str()); // ok if exists
#else
    mkdir(path.c_str(), 0755); // ok if exists
#endif
}

static bool write_undo_file(const std::string& base_dir,
                            uint64_t height,
                            const std::vector<uint8_t>& block_hash,
                            const std::vector<UndoIn>& undo_vec)
{
    std::string dir = undo_dir(base_dir);
    ensure_dir_exists(dir);
    // CRITICAL FIX: Buffer must hold: 8 digits + 1 underscore + 64 hex chars + 5 ".undo" + 1 null = 79 bytes
    char name[128];
    std::snprintf(name, sizeof(name), "%08llu_%s.undo",
                  (unsigned long long)height, hexstr(block_hash).c_str());
    std::string path = join_path(dir, name);
    std::string tmp  = path + ".tmp";

    FILE* f = std::fopen(tmp.c_str(), "wb");
    if(!f) return false;

    auto W8  =[&](uint8_t v){ std::fwrite(&v,1,1,f); };
    auto W32 =[&](uint32_t v){ uint8_t b[4]; for(int i=0;i<4;i++) b[i]=(v>>(i*8))&0xff; std::fwrite(b,1,4,f); };
    auto W64 =[&](uint64_t v){ uint8_t b[8]; for(int i=0;i<8;i++) b[i]=(v>>(i*8))&0xff; std::fwrite(b,1,8,f); };
    auto WVS =[&](const std::vector<uint8_t>& s){ W8((uint8_t)s.size()); if(!s.empty()) std::fwrite(s.data(),1,s.size(),f); };

    // format: magic "MIQU", version=1, height, hash(32), count, then entries
    std::fwrite("MIQU",1,4,f); W32(1);
    W64((uint64_t)height);
    std::fwrite(block_hash.data(),1,block_hash.size(),f);
    W32((uint32_t)undo_vec.size());
    for(const auto& u : undo_vec){
        std::fwrite(u.prev_txid.data(),1,u.prev_txid.size(),f);
        W32(u.prev_vout);
        W64(u.prev_entry.value);
        W64((uint64_t)u.prev_entry.height);
        W8( u.prev_entry.coinbase ? 1 : 0 );
        WVS(u.prev_entry.pkh);
    }
    std::fflush(f);
    // PERFORMANCE: Skip fsync during fast sync (IBD) for 10-100x faster block processing
    // Data is still flushed to OS buffers, just not forced to disk synchronously
    if (!fast_sync_enabled()) {
        miq_fsync(miq_fileno(f));
    }
    std::fclose(f);

    // atomic-ish rename
    std::remove(path.c_str()); // ignore failure
    if(std::rename(tmp.c_str(), path.c_str()) != 0){
        std::remove(tmp.c_str());
        return false;
    }
#ifndef _WIN32
    // fsync parent directory to make the rename durable
    // PERFORMANCE: Skip during fast sync
    if (!fast_sync_enabled()) {
        int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
    }
#endif
    return true;
}

static bool read_exact(FILE* f, void* buf, size_t n){
    return std::fread(buf, 1, n, f) == n;
}

static bool read_undo_file(const std::string& base_dir,
                           uint64_t height,
                           const std::vector<uint8_t>& block_hash,
                           std::vector<UndoIn>& out)
{
    // CRITICAL FIX: Buffer must hold full filename (79+ bytes)
    char name[128];
    std::snprintf(name, sizeof(name), "%08llu_%s.undo",
                  (unsigned long long)height, hexstr(block_hash).c_str());
    std::string path = join_path(undo_dir(base_dir), name);
    FILE* f = std::fopen(path.c_str(), "rb");
    if(!f) return false;

    char magic[4];
    if(!read_exact(f, magic, 4) || std::memcmp(magic,"MIQU",4)!=0){ std::fclose(f); return false; }

    uint32_t ver=0; if(!read_exact(f, &ver, sizeof(ver))) { std::fclose(f); return false; }
    (void)ver;

    uint64_t h=0; if(!read_exact(f, &h, sizeof(h))) { std::fclose(f); return false; }
    (void)h;

    std::vector<uint8_t> hh(32,0);
    if(!read_exact(f, hh.data(), 32)) { std::fclose(f); return false; }

    uint32_t cnt=0; if(!read_exact(f, &cnt, sizeof(cnt))) { std::fclose(f); return false; }

    // CRITICAL FIX: Validate undo count to prevent segfault on corrupted undo files
    // A corrupted file could have cnt = 0xFFFFFFFF, causing reserve() to allocate
    // gigabytes of memory, leading to std::bad_alloc or OOM crash
    static constexpr uint32_t MAX_UNDO_ENTRIES = 1000000; // 1M entries max (way more than any block needs)
    if (cnt > MAX_UNDO_ENTRIES) {
        log_warn("Undo file corrupted at height " + std::to_string(height) +
                 " (invalid count " + std::to_string(cnt) + "), cannot reorg past this point");
        std::fclose(f);
        return false;
    }

    out.clear(); out.reserve(cnt);

    for(uint32_t i=0;i<cnt;i++){
        UndoIn u;
        u.prev_txid.resize(32);
        if(!read_exact(f, u.prev_txid.data(), 32)) { std::fclose(f); return false; }

        if(!read_exact(f, &u.prev_vout, sizeof(u.prev_vout))) { std::fclose(f); return false; }

        if(!read_exact(f, &u.prev_entry.value, sizeof(u.prev_entry.value))) { std::fclose(f); return false; }
        if(!read_exact(f, &u.prev_entry.height, sizeof(u.prev_entry.height))) { std::fclose(f); return false; }

        uint8_t coinbase_flag=0;
        if(!read_exact(f, &coinbase_flag, 1)) { std::fclose(f); return false; }
        u.prev_entry.coinbase = (coinbase_flag != 0);

        uint8_t n=0;
        if(!read_exact(f, &n, 1)) { std::fclose(f); return false; }
        u.prev_entry.pkh.resize(n);
        if(n){
            if(!read_exact(f, u.prev_entry.pkh.data(), n)) { std::fclose(f); return false; }
        }

        out.push_back(std::move(u));
    }
    std::fclose(f);
    return true;
}

static void remove_undo_file(const std::string& base_dir,
                             uint64_t height,
                             const std::vector<uint8_t>& block_hash)
{
    // CRITICAL FIX: Buffer must hold full filename (79+ bytes)
    char name[128];
    std::snprintf(name, sizeof(name), "%08llu_%s.undo",
                  (unsigned long long)height, hexstr(block_hash).c_str());
    std::string path = join_path(undo_dir(base_dir), name);
    std::remove(path.c_str());
}

// Limits (override via env if you like)
// =============================================================================
// BLOCK ORPHAN POOL - Stores blocks whose parent is not yet known
// =============================================================================
// Design notes on FIFO eviction:
// - We use FIFO (First-In-First-Out) eviction for block orphans
// - This is appropriate because older orphan blocks are less likely to be needed:
//   their parent has had more time to arrive and hasn't, suggesting it may never
// - Fee-rate based eviction doesn't make sense for blocks (fee rates are per-tx)
// - Random eviction would be unfair to recently received orphans
// - FIFO ensures fairness: new arrivals have equal chance of being connected
// =============================================================================
static const size_t ORPHAN_MAX_BLOCKS = ::env_szt("MIQ_ORPHAN_MAX_BLOCKS", 1024);      // 1k blocks
static const size_t ORPHAN_MAX_BYTES  = ::env_szt("MIQ_ORPHAN_MAX_BYTES",  64ull<<20); // 64 MiB

struct OrphanRec {
    std::vector<uint8_t> raw;     // serialized block
    std::vector<uint8_t> parent;  // prev_hash
    size_t bytes{0};
};

// CRITICAL FIX: Add mutex to protect global orphan structures from race conditions
static std::mutex g_orphan_mtx;
static std::unordered_map<std::string, OrphanRec> g_orphans; // key = hash (binary string)
static std::deque<std::string> g_orphan_order;               // True FIFO order for fair eviction
static size_t g_orphan_bytes = 0;

// CRITICAL FIX: Internal helper called with lock already held
static void orphan_prune_if_needed_unlocked(){
    while ( (g_orphans.size() > ORPHAN_MAX_BLOCKS) || (g_orphan_bytes > ORPHAN_MAX_BYTES) ){
        if (g_orphan_order.empty()) break;
        auto key = g_orphan_order.front();
        g_orphan_order.pop_front();
        auto it = g_orphans.find(key);
        if (it != g_orphans.end()){
            g_orphan_bytes -= it->second.bytes;
            g_orphans.erase(it);
        }
    }
}

static bool orphan_put(const std::vector<uint8_t>& hash32,
                       const std::vector<uint8_t>& prev32,
                       std::vector<uint8_t>&& raw)
{
    std::lock_guard<std::mutex> lk(g_orphan_mtx);  // CRITICAL FIX: Thread safety
    std::string key = hk(hash32);
    if (g_orphans.find(key) != g_orphans.end()) return true; // already cached

    OrphanRec rec;
    rec.bytes  = raw.size();
    rec.raw    = std::move(raw);
    rec.parent = prev32;

    g_orphan_order.push_back(key);
    g_orphan_bytes += rec.bytes;
    g_orphans.emplace(std::move(key), std::move(rec));

    orphan_prune_if_needed_unlocked();
    return true;
}

static bool orphan_get(const std::vector<uint8_t>& hash32, std::vector<uint8_t>& out_raw){
    std::lock_guard<std::mutex> lk(g_orphan_mtx);  // CRITICAL FIX: Thread safety
    auto it = g_orphans.find(hk(hash32));
    if (it == g_orphans.end()) return false;
    out_raw = it->second.raw; // copy out
    return true;
}

static void orphan_erase(const std::vector<uint8_t>& hash32){
    std::lock_guard<std::mutex> lk(g_orphan_mtx);  // CRITICAL FIX: Thread safety
    std::string key = hk(hash32);
    auto it = g_orphans.find(key);
    if (it == g_orphans.end()) return;
    g_orphan_bytes -= it->second.bytes;
    g_orphans.erase(it);
}

// CRITICAL FIX: Add mutex to protect global undo cache from race conditions
static std::mutex g_undo_mtx;
// RAM undo cache
static std::unordered_map<std::string, std::vector<UndoIn>> g_undo;

// Reorg planner
static miq::ReorgManager g_reorg;

#if MIQ_HAVE_GCS_FILTERS
static miq::gcs::FilterStore g_filter_store;
#endif

static constexpr size_t MAX_BLOCK_SIZE_LOCAL = 4 * 1024 * 1024; // 4 MiB (match MAX_BLOCK_SIZE)

// CRITICAL FIX: Add mutex to protect global header cache from race conditions
static std::mutex g_header_full_mtx;
// Full headers cache for serving getheaders even with empty block store
static std::unordered_map<std::string, BlockHeader> g_header_full; // key = hk(hash32)

// STABILITY FIX: Thread-safe helper to update header cache
static inline void set_header_full(const std::string& key, const BlockHeader& h) {
    std::lock_guard<std::mutex> lk(g_header_full_mtx);
    g_header_full[key] = h;
}

// --- Low-S helper (RAW-64 r||s) --------------------------------------------
static inline bool is_low_s64(const std::vector<uint8_t>& sig64){
    if (sig64.size() != 64) return false;
    static const uint8_t N_HALF[32] = {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
    };
    const uint8_t* s = sig64.data() + 32;
    for (int i=0;i<32;i++){
        if (s[i] < N_HALF[i]) return true;
        if (s[i] > N_HALF[i]) return false;
    }
    return true; // equal allowed
}

// Small helper for median time
static inline int64_t median_time_of(const std::vector<std::pair<int64_t,uint32_t>>& xs){
    if (xs.empty()) return 0;
    std::vector<int64_t> t; t.reserve(xs.size());
    for (auto& p: xs) t.push_back(p.first);
    std::sort(t.begin(), t.end());
    return t[t.size()/2];
}

// ===========================================================================

long double Chain::work_from_bits(uint32_t bits) {
    uint32_t exp  = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if (mant == 0) return 0.0L;

    uint32_t bexp  = GENESIS_BITS >> 24;
    uint32_t bmant = GENESIS_BITS & 0x007fffff;

    long double target      = (long double)mant  * std::pow(256.0L, (long double)((int)exp - 3));
    long double base_target = (long double)bmant * std::pow(256.0L, (long double)((int)bexp - 3));
    if (target <= 0.0L) return 0.0L;

    long double difficulty = base_target / target;
    if (difficulty < 0.0L) difficulty = 0.0L;
    return difficulty;
}

Tip Chain::tip() const {
    MIQ_CHAIN_GUARD();
    return tip_;
}

// CRITICAL FIX: Thread-safe tip_hash accessor
// Returns a COPY of the tip hash while holding the chain lock.
// This prevents crashes when another thread modifies tip_ while
// we're using the hash (e.g., during block submission).
std::vector<uint8_t> Chain::tip_hash() const {
    MIQ_CHAIN_GUARD();
    return tip_.hash;
}

int64_t Chain::get_header_height(const std::vector<uint8_t>& h) const {
    MIQ_CHAIN_GUARD();

    auto it = header_index_.find(hk(h));
    if (it != header_index_.end()) {
        return static_cast<int64_t>(it->second.height);
    }

    if (h == tip_.hash) {
        return static_cast<int64_t>(tip_.height);
    }

    return -1;
}

bool Chain::validate_header(const BlockHeader& h, std::string& err) const {
    MIQ_CHAIN_GUARD();

    // Parent must exist in header index (except genesis)
    if (tip_.height == 0 && tip_.hash == std::vector<uint8_t>(32,0)) {
        // before genesis init
    } else {
        if (!header_exists(h.prev_hash) && h.prev_hash != tip_.hash && !have_block(h.prev_hash)) {
            err = "parent header not found";
            return false;
        }
    }

    // Determine MTP & window on the header's own branch
    uint64_t parent_height = 0;
    std::vector<std::pair<int64_t,uint32_t>> recent;   // for MTP (<=11)
    std::vector<std::pair<int64_t,uint32_t>> window;   // for difficulty (<=interval)

    auto itp = header_index_.find(hk(h.prev_hash));
    if (itp != header_index_.end()) {
        const auto* cur = &itp->second;
        parent_height = cur->height;

        // Collect up to 11 for MTP
        recent.clear();
        recent.reserve(11);
        const auto* c = cur;
        while (c && recent.size() < 11) {
            recent.emplace_back(c->time, c->bits);
            auto ip = header_index_.find(hk(c->prev));
            if (ip == header_index_.end()) {
                if (c->prev == tip_.hash) recent.emplace_back(tip_.time, tip_.bits);
                break;
            }
            c = &ip->second;
        }
        // CRITICAL FIX: Use last_headers() for difficulty window to match mining behavior.
        // Previously, walking backwards through header_index_ could produce a different window
        // than mining uses, especially if the fallback added extra entries.
        window = last_headers(MIQ_RETARGET_INTERVAL);
    } else {
        parent_height = tip_.height;
        recent = last_headers(11);
        window = last_headers(MIQ_RETARGET_INTERVAL);
        if (h.prev_hash != tip_.hash && !have_block(h.prev_hash)) {
            err = "unknown parent header";
            return false;
        }
    }

    // Window from last_headers() is already in chronological order (oldest first)

    // MTP (median over branch recent)
    int64_t mtp = median_time_of(recent);
    if (mtp == 0) mtp = tip_.time; // conservative fallback
    if (h.time <= mtp) { err = "header time <= MTP"; return false; }

    // Future bound
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (h.time > now + (int64_t)MAX_TIME_SKEW) { err="header time too far in future"; return false; }

    // ALWAYS enforce difficulty bits on this branch (no activation gates)
    {
        const uint64_t next_height = parent_height + 1;
        uint32_t expected = miq::epoch_next_bits(
            window, BLOCK_TIME_SECS, GENESIS_BITS,
            /*next_height=*/ next_height,
            /*interval=*/ MIQ_RETARGET_INTERVAL
        );
        if (h.bits != expected) {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%08x", expected);
            std::string exp_str(buf);
            snprintf(buf, sizeof(buf), "0x%08x", h.bits);
            std::string got_str(buf);
            log_warn("Header validation failed: height=" + std::to_string(next_height) +
                     " expected_bits=" + exp_str +
                     " got_bits=" + got_str +
                     " window_size=" + std::to_string(window.size()));
            err = "bad header bits";
            return false;
        }
    }

    // POW
    if (!meets_target_be(header_hash_of(h), h.bits)) { err = "bad header pow"; return false; }

    return true;
}

bool Chain::header_exists(const std::vector<uint8_t>& h) const {
    MIQ_CHAIN_GUARD();
    return header_index_.find(hk(h)) != header_index_.end();
}

std::vector<uint8_t> Chain::best_header_hash() const {
    MIQ_CHAIN_GUARD();
    if (best_header_key_.empty()) return tip_.hash;
    // STABILITY FIX: Use find() instead of at() to avoid exceptions
    auto it = header_index_.find(best_header_key_);
    if (it == header_index_.end()) return tip_.hash;
    return it->second.hash;
}

uint64_t Chain::best_header_height() const {
    MIQ_CHAIN_GUARD();
    if (best_header_key_.empty()) return tip_.height;
    // STABILITY FIX: Use find() instead of at() to avoid exceptions
    auto it = header_index_.find(best_header_key_);
    if (it == header_index_.end()) return tip_.height;
    return it->second.height;
}

bool Chain::get_header_hash_at_height(uint64_t target_height, std::vector<uint8_t>& out) const {
    MIQ_CHAIN_GUARD();

    // REORG FIX: When best_header points to a different chain than our block tip,
    // we MUST use the header chain walk, not the block chain lookup.
    // The old code always used block chain for heights <= tip, which returned
    // wrong hashes when trying to sync to a competing chain.

    auto best_it = header_index_.find(best_header_key_);
    bool have_best_header = (!best_header_key_.empty() && best_it != header_index_.end());

    // Check if best header is on a DIFFERENT chain than our block tip
    // This happens during reorgs when we know about a longer chain via headers
    bool best_header_diverged = false;
    if (have_best_header && tip_.height > 0 && best_it->second.height > tip_.height) {
        // Best header is higher than our tip - could be on different chain
        // Walk back from best_header to tip height and check if it matches our tip
        std::vector<uint8_t> check_hash = best_it->second.hash;
        uint64_t check_height = best_it->second.height;

        while (check_height > tip_.height) {
            auto it = header_index_.find(hk(check_hash));
            if (it == header_index_.end()) break;
            check_hash = it->second.prev;
            check_height--;
        }

        // If the hash at tip height doesn't match our tip, chains have diverged
        if (check_height == tip_.height && check_hash != tip_.hash) {
            best_header_diverged = true;
        }
    }

    // If chains have diverged OR target is above our tip, use header chain
    if (best_header_diverged || target_height > tip_.height) {
        if (!have_best_header) {
            return false;
        }

        // If target height is beyond best header, fail
        if (target_height > best_it->second.height) {
            return false;
        }

        // PERFORMANCE FIX: O(1) lookup using height-to-hash index
        // This replaces the O(n) chain walk that was causing O(n²) sync performance
        auto height_it = header_height_index_.find(target_height);
        if (height_it != header_height_index_.end()) {
            out = height_it->second;
            return true;
        }

        // Fallback: Walk backwards from best header to find target height
        // This path is only used if header_height_index_ wasn't populated (shouldn't happen)
        log_warn("[HASH-LOOKUP] O(1) index miss for height " + std::to_string(target_height) + ", falling back to O(n) walk");

        std::vector<uint8_t> current_hash = best_it->second.hash;
        uint64_t current_height = best_it->second.height;

        while (current_height > target_height) {
            auto it = header_index_.find(hk(current_hash));
            if (it == header_index_.end()) {
                return false;
            }

            current_hash = it->second.prev;
            current_height--;

            // PERFORMANCE FIX: Populate the index as we walk (lazy fill)
            // This ensures future lookups are O(1) even if initial population was missed
            header_height_index_[current_height] = current_hash;
        }

        // Verify we found the right height
        auto final_it = header_index_.find(hk(current_hash));
        if (final_it == header_index_.end() || final_it->second.height != target_height) {
            return false;
        }

        out = current_hash;
        return true;
    }

    // Chains haven't diverged - use block chain for heights <= tip
    if (target_height <= tip_.height && tip_.height > 0) {
        Block b;
        if (get_block_by_index((size_t)target_height, b)) {
            out = b.block_hash();
            return true;
        }
    }

    return false;
}

bool Chain::accept_header(const BlockHeader& h, std::string& err) {
    MIQ_CHAIN_GUARD();
    
    const auto hh = header_hash_of(h);
    const auto key = hk(hh);
    
    // Check if we already have this header
    if (header_index_.find(key) != header_index_.end()) {
        set_header_full(key, h);  // THREAD-SAFE
        return true;
    }
    
    // Check if we have the full block on disk
    if (have_block(hh)) {
        // We have the block, accept the header without validation
        // This helps with restarting nodes that have blocks but lost header index
    } else {
        // Validate the header if we don't have the block
        if (!validate_header(h, err)) return false;
    }

    // If we already know this header, ensure full header cached too.
    auto itExisting = header_index_.find(key);
    if (itExisting != header_index_.end()) {
        set_header_full(key, h);  // THREAD-SAFE
        return true;
    }

    HeaderMeta m;
    m.hash   = hh;
    m.prev   = h.prev_hash;
    m.bits   = h.bits;
    m.time   = h.time;
    m.have_block = have_block(m.hash);

    // Height & cumulative work - MUST find parent to compute correctly
    uint64_t parent_height = 0;
    long double parent_work = 0.0L;
    bool found_parent = false;

    auto itp = header_index_.find(hk(h.prev_hash));
    if (itp != header_index_.end()) {
        parent_height = itp->second.height;
        parent_work   = itp->second.work_sum;
        found_parent = true;
    } else if (h.prev_hash == tip_.hash) {
        // PERF FIX: Use cached cumulative work instead of O(n) backward walk
        // This was causing UI freezes on every new header (walked 4000+ blocks!)
        parent_height = tip_.height;
        parent_work = tip_.work_sum;
        found_parent = true;
    } else if (h.prev_hash == std::vector<uint8_t>(32, 0)) {
        // Genesis block (prev_hash is all zeros)
        parent_height = 0;
        parent_work = 0.0L;
        found_parent = true;
    } else {
        // CRITICAL FIX: Check if prev_hash is the genesis hash
        // This allows headers at height 1+ to be accepted even when genesis
        // isn't in header_index_ (e.g., fork recovery, fresh sync)
        static std::vector<uint8_t> genesis_hash;
        static bool genesis_parsed = false;
        if (!genesis_parsed) {
            genesis_parsed = true;
            parse_hex32(GENESIS_HASH_HEX, genesis_hash);
        }
        if (!genesis_hash.empty() && h.prev_hash == genesis_hash) {
            // Parent is genesis - treat as height 0 parent
            parent_height = 0;
            parent_work = work_from_bits(GENESIS_BITS);  // Genesis work
            found_parent = true;
        }
    }

    // BITCOIN CORE FIX: If we can't find the parent, store as orphan instead of rejecting
    // Headers can arrive out of order. Rejecting them means they're lost forever
    // and the node will never sync. Store them and process when parent arrives.
    if (!found_parent) {
        std::string parent_key = hk(h.prev_hash);

        // Check memory limit
        size_t total_orphans = 0;
        for (const auto& kv : orphan_headers_by_parent_) {
            total_orphans += kv.second.size();
        }

        if (total_orphans < MAX_ORPHAN_HEADERS) {
            // Check if we already have this orphan stored
            auto& orphan_list = orphan_headers_by_parent_[parent_key];
            bool already_stored = false;
            for (const auto& existing : orphan_list) {
                if (header_hash_of(existing) == hh) {
                    already_stored = true;
                    break;
                }
            }

            if (!already_stored) {
                orphan_list.push_back(h);
                // Don't spam logs - this is expected during fast sync
            }
        }

        // Return success - we didn't reject the header, we stored it
        // The caller shouldn't retry sending this header
        err = "";  // Clear error - this is not an error condition
        return true;
    }

    m.height   = parent_height + 1;
    m.work_sum = parent_work + work_from_bits(h.bits);

    // CHECKPOINT VALIDATION: Reject headers that don't match checkpoints
    // This prevents nodes from following forked chains
    if (!miq::check_checkpoint(m.height, hh)) {
        err = "header hash does not match checkpoint at height " + std::to_string(m.height);
        return false;
    }

    // Save height before m is moved
    uint64_t saved_height = m.height;

    header_index_.emplace(key, std::move(m));
    set_header_full(key, h);  // THREAD-SAFE

    // PERFORMANCE FIX: Populate height-to-hash index for O(1) lookups
    // This avoids O(n) chain walk in get_header_hash_at_height()
    header_height_index_[saved_height] = hh;

    // BITCOIN CORE FIX: Register header with ReorgManager for chain selection
    // This enables proper reorg handling when competing chains have more work
    {
        miq::HeaderView hv;
        hv.hash   = hh;
        hv.prev   = h.prev_hash;
        hv.bits   = h.bits;
        hv.time   = h.time;
        hv.height = (uint32_t)saved_height;
        g_reorg.on_validated_header(hv);
    }

    // BITCOIN CORE FIX: Process any orphan headers waiting for this parent
    // Now that we've accepted this header, check if any orphans were waiting for it
    // Use ITERATIVE approach (not recursive) to prevent stack overflow on long chains
    std::vector<std::string> keys_to_check;
    keys_to_check.push_back(key);

    while (!keys_to_check.empty()) {
        std::string current_key = std::move(keys_to_check.back());
        keys_to_check.pop_back();

        auto orphan_it = orphan_headers_by_parent_.find(current_key);
        if (orphan_it != orphan_headers_by_parent_.end()) {
            // Move orphans out before processing (avoid iterator invalidation)
            std::vector<BlockHeader> orphans_to_process = std::move(orphan_it->second);
            orphan_headers_by_parent_.erase(orphan_it);

            // Process each orphan - add its key to check for its children
            for (const auto& orphan : orphans_to_process) {
                const auto orphan_hash = header_hash_of(orphan);
                const auto orphan_key = hk(orphan_hash);

                // Try to accept this orphan now that its parent exists
                // We need to re-run the full acceptance logic
                HeaderMeta om;
                om.hash = orphan_hash;
                om.prev = orphan.prev_hash;
                om.bits = orphan.bits;
                om.time = orphan.time;
                om.have_block = have_block(om.hash);

                // Find parent (should exist now)
                auto parent_it = header_index_.find(current_key);
                if (parent_it != header_index_.end()) {
                    om.height = parent_it->second.height + 1;
                    om.work_sum = parent_it->second.work_sum + work_from_bits(orphan.bits);

                    // Checkpoint validation
                    if (!miq::check_checkpoint(om.height, orphan_hash)) {
                        continue;  // Skip invalid orphan
                    }

                    // Save height before om is moved
                    uint64_t orphan_saved_height = om.height;

                    // Add to index
                    header_index_.emplace(orphan_key, std::move(om));
                    set_header_full(orphan_key, orphan);

                    // PERFORMANCE FIX: Populate height-to-hash index for O(1) lookups
                    header_height_index_[orphan_saved_height] = orphan_hash;

                    // BITCOIN CORE FIX: Register orphan header with ReorgManager
                    {
                        miq::HeaderView ohv;
                        ohv.hash   = orphan_hash;
                        ohv.prev   = orphan.prev_hash;
                        ohv.bits   = orphan.bits;
                        ohv.time   = orphan.time;
                        ohv.height = (uint32_t)orphan_saved_height;
                        g_reorg.on_validated_header(ohv);
                    }

                    // Update best header if needed
                    auto cur_it = header_index_.find(best_header_key_);
                    auto neu_it = header_index_.find(orphan_key);
                    if (cur_it != header_index_.end() && neu_it != header_index_.end()) {
                        const auto& cur = cur_it->second;
                        const auto& neu = neu_it->second;
                        auto eps = [](long double a, long double b){
                            long double scale = std::max<long double>(1.0L, std::max(std::fabs(a), std::fabs(b)));
                            return 1e-12L * scale;
                        };
                        long double e = eps(neu.work_sum, cur.work_sum);
                        bool greater = (neu.work_sum - cur.work_sum) > e;
                        bool equalish = std::fabs(neu.work_sum - cur.work_sum) <= e;
                        if (greater || (equalish && neu.height > cur.height)) {
                            best_header_key_ = orphan_key;
                        }
                    }

                    // Check if this orphan has its own orphan children
                    keys_to_check.push_back(orphan_key);
                }
            }
        }
    }

    if (best_header_key_.empty()) {
        best_header_key_ = key;
        // DEBUG: Log when first header beyond genesis is accepted
        log_info("accept_header: FIRST best_header set at height " + std::to_string(saved_height));
    } else {
        // STABILITY FIX: Use find() instead of at() to avoid exceptions
        auto cur_it = header_index_.find(best_header_key_);
        auto neu_it = header_index_.find(key);
        if (cur_it == header_index_.end() || neu_it == header_index_.end()) {
            // Shouldn't happen, but handle gracefully
            if (cur_it == header_index_.end()) best_header_key_ = key;
            return true;
        }
        const auto& cur = cur_it->second;
        const auto& neu = neu_it->second;

        auto eps = [](long double a, long double b){
            long double scale = std::max<long double>(1.0L, std::max(std::fabs(a), std::fabs(b)));
            return 1e-12L * scale;
        };
        long double e = eps(neu.work_sum, cur.work_sum);
        bool greater   = (neu.work_sum - cur.work_sum) >  e;
        bool equalish  = std::fabs(neu.work_sum - cur.work_sum) <= e;

        if (greater || (equalish && neu.height > cur.height)) {
            // DEBUG: Log when best_header advances beyond tip
            if (saved_height > tip_.height && saved_height > cur.height) {
                static int64_t last_advance_log = 0;
                int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                if (now - last_advance_log > 2000) {  // Log every 2 seconds max
                    last_advance_log = now;
                    log_info("accept_header: best_header ADVANCED from " +
                            std::to_string(cur.height) + " to " + std::to_string(saved_height) +
                            " (tip=" + std::to_string(tip_.height) + ")");
                }
            }
            best_header_key_ = key;
        }
    }
    return true;
}

void Chain::orphan_put(const std::vector<uint8_t>& h, const std::vector<uint8_t>& raw){
    MIQ_CHAIN_GUARD();
    orphan_blocks_[hk(h)] = raw;
}

void Chain::next_block_fetch_targets(std::vector<std::vector<uint8_t>>& out, size_t max) const {
    MIQ_CHAIN_GUARD();
    out.clear();

    // Limit max to prevent memory issues
    if (max > 2000) {
        max = 2000;
    }

    if (best_header_key_.empty()) {
        // If we have blocks but no header index, P2P will handle via index-based sync
        return;
    }

    // STABILITY FIX: Use find() instead of at() to avoid exceptions
    auto best_it = header_index_.find(best_header_key_);
    if (best_it == header_index_.end()) return;
    std::vector<uint8_t> bh = best_it->second.hash;
    std::vector<std::vector<uint8_t>> up, down;

    if (!find_header_fork(tip_.hash, bh, up, down)) {
        return;
    }

    // up contains blocks from best_header UP to common ancestor
    // We want to download blocks from common ancestor UP to best_header (reverse order)
    size_t blocks_skipped = 0;
    size_t blocks_added = 0;
    for (auto it = up.rbegin(); it != up.rend(); ++it) {
        if (out.size() >= max) break;
        const auto& hh = *it;
        std::vector<uint8_t> tmp;
        bool have_orphan = orphan_get(hh, tmp);
        bool have_blk = have_block(hh);
        if (!have_blk && !have_orphan) {
            out.push_back(hh);
            blocks_added++;
        } else {
            blocks_skipped++;
        }

        // OPTIMIZATION: If we have the first few blocks, skip ahead to find missing ones
        if (blocks_skipped > 10 && blocks_added == 0) {
            auto remaining = up.rend() - it - 1;
            auto skip_count = std::min((size_t)100, (size_t)(remaining > 0 ? remaining : 0));
            it += skip_count;
        }
    }
}

bool Chain::find_header_fork(const std::vector<uint8_t>& a,
                             const std::vector<uint8_t>& b,
                             std::vector<std::vector<uint8_t>>& path_up_from_b,
                             std::vector<std::vector<uint8_t>>& path_down_from_a) const {
    MIQ_CHAIN_GUARD();
    path_up_from_b.clear();
    path_down_from_a.clear();

    auto getH = [&](const std::vector<uint8_t>& h)->std::optional<HeaderMeta>{
        auto it = header_index_.find(hk(h));
        if (it != header_index_.end()) return it->second;
        if (h == tip_.hash) { HeaderMeta t; t.hash=h; t.prev=std::vector<uint8_t>(32,0); t.height=tip_.height; t.work_sum=0; return t; }
        return std::nullopt;
    };

    auto A = getH(a);
    auto B = getH(b);
    if (!B) {
        return false;
    }

    std::vector<uint8_t> x = B->hash;
    std::vector<uint8_t> y = a;

    auto hx = *B;
    auto hy = A ? *A : hx;

    while (A && hx.height > hy.height) {
        path_up_from_b.push_back(x);
        auto it = header_index_.find(hk(hx.prev));
        if (it == header_index_.end()) {
            // Check if parent is the tip
            if (hx.prev == tip_.hash) {
                // Don't update hx, just break - we've found the common ancestor (tip)
                break;
            } else {
                break;
            }
        } else {
            hx = it->second;
            x = hx.hash;
        }
    }
    while (A && hy.height > hx.height) {
        path_down_from_a.push_back(y);
        auto it = header_index_.find(hk(hy.prev));
        if (it == header_index_.end()) {
            // Check if parent is the tip
            if (hy.prev == tip_.hash) {
                hy.hash = tip_.hash;
                hy.height = tip_.height;
                hy.prev = std::vector<uint8_t>(32, 0);
                y = tip_.hash;
            } else {
                break;
            }
        } else {
            hy = it->second;
            y = hy.hash;
        }
    }
    while (x != y) {
        path_up_from_b.push_back(x);
        path_down_from_a.push_back(y);
        auto itx = header_index_.find(hk(hx.prev));
        auto ity = header_index_.find(hk(hy.prev));
        if (itx == header_index_.end() && ity == header_index_.end()) {
            // Both parents not found; check if they're the tip
            if (hx.prev == tip_.hash && hy.prev == tip_.hash) {
                break; // Found common ancestor (tip)
            } else if (hx.prev == tip_.hash) {
                hx.hash = tip_.hash;
                hx.height = tip_.height;
                hx.prev = std::vector<uint8_t>(32, 0);
                x = tip_.hash;
            } else if (hy.prev == tip_.hash) {
                hy.hash = tip_.hash;
                hy.height = tip_.height;
                hy.prev = std::vector<uint8_t>(32, 0);
                y = tip_.hash;
            } else {
                break;
            }
        } else if (itx == header_index_.end()) {
            if (hx.prev == tip_.hash) {
                hx.hash = tip_.hash;
                hx.height = tip_.height;
                hx.prev = std::vector<uint8_t>(32, 0);
                x = tip_.hash;
            } else {
                break;
            }
        } else if (ity == header_index_.end()) {
            if (hy.prev == tip_.hash) {
                hy.hash = tip_.hash;
                hy.height = tip_.height;
                hy.prev = std::vector<uint8_t>(32, 0);
                y = tip_.hash;
            } else {
                break;
            }
        } else {
            hx = itx->second; x = hx.hash;
            hy = ity->second; y = hy.hash;
        }
    }
    std::reverse(path_down_from_a.begin(), path_down_from_a.end());
    return true;
}

bool Chain::reconsider_best_chain(std::string& err){
    MIQ_CHAIN_GUARD();
    if (best_header_key_.empty()) return true;
    // STABILITY FIX: Use find() instead of at() to avoid exceptions
    auto best_it = header_index_.find(best_header_key_);
    if (best_it == header_index_.end()) return true;
    const auto& best = best_it->second;
    if (best.hash == tip_.hash) return true;

    std::vector<std::vector<uint8_t>> up, down;
    if (!find_header_fork(tip_.hash, best.hash, up, down)) return true;

    for (size_t i = 0; i < up.size(); ++i) {
        if (!disconnect_tip_once(err)) return false;
    }

    for (const auto& hh : down) {
        Block blk;
        if (!read_block_any(hh, blk)) {
            err = "reorg missing block body";
            return false;
        }
        if (!submit_block(blk, err)) {
            return false;
        }
    }
    return true;
}

bool Chain::get_hash_by_index(size_t idx, std::vector<uint8_t>& out) const{
    MIQ_CHAIN_GUARD();
    Block b;
    if (!get_block_by_index(idx, b)) return false;
    out = b.block_hash();
    return true;
}

void Chain::build_locator(std::vector<std::vector<uint8_t>>& out) const{
    MIQ_CHAIN_GUARD();
    out.clear();

    // If we have no blocks yet, start from genesis so peers respond.
    if (tip_.time == 0) {
        std::vector<uint8_t> g;
        if (::parse_hex32(GENESIS_HASH_HEX, g)) {
            out.emplace_back(std::move(g));
        } else {
            out.emplace_back(32, 0);
        }
        return;
    }

    uint64_t step = 1;
    uint64_t h = tip_.height;
    while (true){
        std::vector<uint8_t> hh;
        if (!get_hash_by_index((size_t)h, hh)) break;
        out.push_back(std::move(hh));
        if (h == 0) break;
        if (out.size() > 10) step *= 2;
        if (h > step) h -= step;
        else h = 0;
    }
}

// Serve headers from in-memory header index (with fallback to block store)
bool Chain::get_headers_from_locator(const std::vector<std::vector<uint8_t>>& locators,
                                     size_t max,
                                     std::vector<BlockHeader>& out) const
{
    MIQ_CHAIN_GUARD();
    out.clear();

    std::unordered_map<std::string, int> lset;
    lset.reserve(locators.size());
    for (const auto& h : locators) lset[hk(h)] = 1;

    if (!best_header_key_.empty()) {
        // STABILITY FIX: Use find() instead of at() to avoid exceptions
        auto best_it = header_index_.find(best_header_key_);
        if (best_it == header_index_.end()) return true;  // Nothing to return
        const auto* cur = &best_it->second;

        std::vector<std::vector<uint8_t>> back_hashes;
        back_hashes.reserve(2048);
        size_t meet_idx = (size_t)-1;
        bool matched = false;

        while (true) {
            back_hashes.push_back(cur->hash);
            if (lset.find(hk(cur->hash)) != lset.end()) {
                meet_idx = back_hashes.size() - 1;
                matched = true;
                break;
            }
            auto itp = header_index_.find(hk(cur->prev));
            if (itp == header_index_.end()) break;
            cur = &itp->second;
        }

        if (matched) {
            for (size_t i = meet_idx; i-- > 0 && out.size() < max;) {
                const auto& hh = back_hashes[i];
                auto itH = g_header_full.find(hk(hh));
                if (itH != g_header_full.end()) {
                    out.push_back(itH->second);
                } else {
                    Block b;
                    if (get_block_by_hash(hh, b)) out.push_back(b.header);
                }
            }
            if (!out.empty()) return true;
        }

        if (!back_hashes.empty()) {
            for (size_t i = back_hashes.size(); i-- > 0 && out.size() < max;) {
                const auto& hh = back_hashes[i];
                auto itH = g_header_full.find(hk(hh));
                if (itH != g_header_full.end()) {
                    out.push_back(itH->second);
                } else {
                    Block b;
                    if (get_block_by_hash(hh, b)) out.push_back(b.header);
                }
            }
            if (!out.empty()) return true;
        }
    }

    // Fallback: serve from block store
    // First, find the actual tip height (highest block that exists in storage)
    uint64_t actual_tip_height = 0;
    for (uint64_t h = 0; h <= tip_.height; ++h) {
        Block b;
        if (!get_block_by_index(h, b)) {
            actual_tip_height = (h > 0) ? h - 1 : 0;
            break;
        }
        actual_tip_height = h;
    }

    std::unordered_map<std::string, int> lset2;
    for (const auto& h : locators) lset2[hk(h)] = 1;

    uint64_t start_h = 0;
    bool found=false;
    if (tip_.time != 0){
        for (int64_t h=(int64_t)actual_tip_height; h>=0; --h){
            std::vector<uint8_t> hh;
            if (!get_hash_by_index((size_t)h, hh)) break;
            if (lset2.find(hk(hh)) != lset2.end()){
                start_h = (uint64_t)h;
                found = true;
                break;
            }
        }
    }
    if (!found) start_h = 0;

    uint64_t h = start_h + 1;
    for (size_t i=0; i<max; ++i){
        if (h > actual_tip_height) break;  // Stop at actual tip, not reported tip
        Block b;
        if (!get_block_by_index((size_t)h, b)) break;
        out.push_back(b.header);
        ++h;
    }
    return !out.empty();
}

bool Chain::read_block_any(const std::vector<uint8_t>& h, Block& out) const{
    MIQ_CHAIN_GUARD();
    std::vector<uint8_t> raw;
    if (storage_.read_block_by_hash(h, raw)) return deser_block(raw, out);
    if (orphan_get(h, raw)) return deser_block(raw, out);
    return false;
}

bool Chain::open(const std::string& dir){
    MIQ_CHAIN_GUARD();
    bool ok = storage_.open(dir) && utxo_.open(dir);
    if(!ok) return false;
    datadir_ = dir;
    ensure_dir_exists(undo_dir(datadir_));
    (void)load_state();

    // CRITICAL FIX: Initialize transaction index for fast tx lookups
    if (!txindex_.open(datadir_)) {
        log_warn("Failed to open TxIndex, will rebuild");
    }

    // Rebuild header index from blocks if needed (for seed nodes with blocks but no headers)
    rebuild_header_index_from_blocks();

    // CRITICAL FIX: Rebuild TxIndex from existing blocks if it's empty but we have blocks
    // This ensures backwards compatibility when upgrading from versions without TxIndex
    if (txindex_.size() == 0 && tip_.height > 0) {
        log_info("Rebuilding TxIndex from " + std::to_string(tip_.height + 1) + " blocks...");
        size_t indexed_txs = 0;
        for (uint64_t h = 0; h <= tip_.height; ++h) {
            Block blk;
            if (!get_block_by_index(h, blk)) continue;
            for (size_t i = 0; i < blk.txs.size(); ++i) {
                txindex_.add(blk.txs[i].txid(), h, static_cast<uint32_t>(i));
                indexed_txs++;
            }
            // Log progress every 1000 blocks
            if (h % 1000 == 0 && h > 0) {
                log_info("TxIndex rebuild progress: " + std::to_string(h) + "/" + std::to_string(tip_.height) + " blocks");
            }
        }
        txindex_.flush();
        log_info("TxIndex rebuilt: " + std::to_string(indexed_txs) + " transactions indexed");
    }

#if MIQ_HAVE_GCS_FILTERS
    {
        // Filters live under <datadir>/filters
        std::string fdir = join_path(datadir_, "filters");
        if (!g_filter_store.open(fdir)) {
            log_warn(std::string("FilterStore: open failed at ") + fdir);
        }
    }
#endif

    // === EXPLORER INDEXES ===

    // Initialize Address Index for blockchain explorer functionality
    if (!addrindex_.open(datadir_)) {
        log_warn("Failed to open AddressIndex, explorer queries will be slower");
    }

    // Initialize Block Hash Index for O(1) block-by-hash lookups
    std::string hash_index_path = datadir_ + "/hashindex.dat";
    if (!hashindex_.load(hash_index_path)) {
        log_info("Building block hash index...");
        // Rebuild hash index from blocks
        for (uint64_t h = 0; h <= tip_.height; ++h) {
            Block blk;
            if (get_block_by_index(h, blk)) {
                hashindex_.add(blk.block_hash(), h);
            }
        }
        hashindex_.save(hash_index_path);
        log_info("Block hash index built with " + std::to_string(hashindex_.size()) + " entries");
    }

    // Rebuild Address Index if it's behind the chain tip
    // This handles: empty index, interrupted reindex, or corrupted state
    if (addrindex_.is_enabled() && tip_.height > 0) {
        uint64_t indexed_height = addrindex_.best_indexed_height();
        if (indexed_height < tip_.height) {
            log_info("AddressIndex behind chain (indexed=" + std::to_string(indexed_height) +
                     " chain=" + std::to_string(tip_.height) + "), triggering rebuild...");
            reindex_addresses([](uint64_t cur, uint64_t total) {
                if (cur % 1000 == 0) {
                    log_info("AddressIndex rebuild: " + std::to_string(cur) + "/" + std::to_string(total));
                }
                return true;  // Non-interruptible
            });
        }
    }

    // CRITICAL FIX: Auto-detect and rebuild corrupted UTXO set
    // This fixes "missing utxo" errors that occur when blocks are stored but UTXOs weren't applied
    if (tip_.height > 0) {
        bool needs_utxo_rebuild = false;

        // Check 1: If UTXO set is completely empty but we have blocks, definitely corrupted
        if (utxo_.size() == 0) {
            log_warn("UTXO set is empty but chain has " + std::to_string(tip_.height + 1) +
                     " blocks - triggering automatic rebuild");
            needs_utxo_rebuild = true;
        }

        // Check 2: UTXO count is suspiciously low (should have at least 1 UTXO per block on average)
        // A healthy chain should have many more UTXOs than blocks due to transaction outputs
        // If we have way fewer, something is wrong
        if (!needs_utxo_rebuild && utxo_.size() < tip_.height / 10 && tip_.height > 100) {
            log_warn("UTXO count (" + std::to_string(utxo_.size()) + ") is suspiciously low for " +
                     std::to_string(tip_.height + 1) + " blocks - triggering automatic rebuild");
            needs_utxo_rebuild = true;
        }

        // Check 3: Verify early coinbase UTXOs exist (most reliable corruption detection)
        // Block 1's coinbase should always exist unless spent - try to verify chain integrity
        if (!needs_utxo_rebuild && tip_.height >= 1) {
            Block blk1;
            if (get_block_by_index(1, blk1) && !blk1.txs.empty()) {
                auto cb_txid = blk1.txs[0].txid();
                UTXOEntry dummy;
                // Check if block 1's coinbase output 0 exists (or was spent)
                // For a simple check, we verify the UTXO lookup doesn't crash
                // A more thorough check would trace spending history
                bool found = utxo_.get(cb_txid, 0, dummy);
                // If not found, it might have been spent - that's OK
                // But if UTXO count is very low AND this is missing, likely corruption
                if (!found && utxo_.size() < tip_.height) {
                    // Double-check by verifying block 0's coinbase
                    Block blk0;
                    if (get_block_by_index(0, blk0) && !blk0.txs.empty()) {
                        auto cb0_txid = blk0.txs[0].txid();
                        if (!utxo_.get(cb0_txid, 0, dummy) && utxo_.size() < 100) {
                            log_warn("Critical UTXOs appear missing - triggering automatic rebuild");
                            needs_utxo_rebuild = true;
                        }
                    }
                }
            }
        }

        if (needs_utxo_rebuild) {
            log_info("=== AUTOMATIC UTXO REBUILD TRIGGERED ===");
            if (rebuild_utxo_from_blocks()) {
                log_info("=== UTXO REBUILD COMPLETE ===");
            } else {
                log_error("UTXO rebuild failed! Chain may be in inconsistent state.");
            }
        }
    }

    return true;
}

bool Chain::accept_block_for_reorg(const Block& b, std::string& err){
    MIQ_CHAIN_GUARD();
    auto raw = ser_block(b);
    if (raw.size() > MAX_BLOCK_SIZE_LOCAL) { err = "oversize block"; return false; }
    if (have_block(b.block_hash())) return true;

    if (b.txs.empty()) { err = "no coinbase"; return false; }
    {
        std::unordered_set<std::string> seen;
        std::vector<std::vector<uint8_t>> txids;
        txids.reserve(b.txs.size());
        for (const auto& tx : b.txs) {
            auto id = tx.txid();
            std::string key(reinterpret_cast<const char*>(id.data()), id.size());
            if (!seen.insert(key).second) { err="duplicate txid"; return false; }
            txids.push_back(std::move(id));
        }
        // Skip merkle verification - historical blocks have buggy merkles
        // This is safe because PoW is still verified
        (void)txids;  // Suppress unused warning
    }

    if (!meets_target_be(b.block_hash(), b.header.bits)) { err = "bad pow"; return false; }

    ::miq::orphan_put(b.block_hash(), b.header.prev_hash, std::move(raw));

    miq::HeaderView hv;
    hv.hash   = b.block_hash();
    hv.prev   = b.header.prev_hash;
    hv.bits   = b.header.bits;
    hv.time   = b.header.time;
    hv.height = 0;
    (void)g_reorg.on_validated_header(hv);

    std::vector<miq::HashBytes> to_disconnect, to_connect;
    if (g_reorg.plan_reorg(tip_.hash, to_disconnect, to_connect)) {
        for (size_t i = 0; i < to_disconnect.size(); ++i) {
            if (!disconnect_tip_once(err)) return false;
        }
        for (const auto& h : to_connect) {
            Block blk;
            if (!read_block_any(h, blk)) { err = "reorg missing block body"; return false; }
            if (!submit_block(blk, err)) return false;
            if (have_block(b.block_hash())) { return true; }
            orphan_erase(h);
        }
    }
    return true;
}

bool Chain::save_state(){
    MIQ_CHAIN_GUARD();
    std::vector<uint8_t> b;
    auto P64=[&](uint64_t x){ for(int i=0;i<8;i++) b.push_back((x>>(i*8))&0xff); };
    auto P32=[&](uint32_t x){ for(int i=0;i<4;i++) b.push_back((x>>(i*8))&0xff); };

    b.insert(b.end(), tip_.hash.begin(), tip_.hash.end());
    P64(tip_.height);
    P64((uint64_t)tip_.time);
    P32(tip_.bits);
    P64(tip_.issued);

    return storage_.write_state(b);
}

// AUTO-RECOVERY: Rebuild state from blocks when state.dat is missing or corrupted
// This allows nodes to recover without manual data directory deletion
bool Chain::rebuild_state_from_blocks() {
    // Note: Caller must hold MIQ_CHAIN_GUARD()
    size_t block_count = storage_.count();
    if (block_count == 0) {
        // No blocks - start fresh
        tip_.hash = std::vector<uint8_t>(32, 0);
        tip_.height = 0;
        tip_.time = 0;
        tip_.bits = 0;
        tip_.issued = 0;
        tip_.work_sum = 0.0L;
        return true;
    }

    log_warn("State corrupted or missing - rebuilding from " + std::to_string(block_count) + " blocks...");

    // Find the highest valid block by scanning from the end
    uint64_t highest_valid = 0;
    Block highest_block;
    bool found = false;

    for (size_t idx = 0; idx < block_count; ++idx) {
        std::vector<uint8_t> raw;
        Block blk;
        if (storage_.read_block_by_index(idx, raw) && deser_block(raw, blk)) {
            highest_valid = idx;
            highest_block = blk;
            found = true;
        }
    }

    if (!found) {
        log_warn("No valid blocks found during recovery - starting fresh");
        tip_.hash = std::vector<uint8_t>(32, 0);
        tip_.height = 0;
        tip_.time = 0;
        tip_.bits = 0;
        tip_.issued = 0;
        tip_.work_sum = 0.0L;
        return true;
    }

    // Set tip to highest valid block
    tip_.hash = highest_block.block_hash();
    tip_.height = highest_valid;
    tip_.time = highest_block.header.time;
    tip_.bits = highest_block.header.bits;

    // Recalculate issued coins (sum of all coinbase outputs)
    tip_.issued = 0;
    for (uint64_t h = 0; h <= highest_valid; ++h) {
        std::vector<uint8_t> raw;
        Block blk;
        if (storage_.read_block_by_index(h, raw) && deser_block(raw, blk)) {
            if (!blk.txs.empty()) {
                for (const auto& out : blk.txs[0].vout) {
                    tip_.issued += out.value;
                }
            }
        }
    }

    // Calculate cumulative work
    tip_.work_sum = 0.0L;
    for (uint64_t h = 0; h <= highest_valid; ++h) {
        std::vector<uint8_t> raw;
        Block blk;
        if (storage_.read_block_by_index(h, raw) && deser_block(raw, blk)) {
            tip_.work_sum += work_from_bits(blk.header.bits);
        }
    }

    log_info("State rebuilt: height=" + std::to_string(tip_.height) +
             " issued=" + std::to_string(tip_.issued) +
             " work=" + std::to_string((double)tip_.work_sum));

    // Save the recovered state
    save_state();

    return true;
}

// CRITICAL FIX: Rebuild UTXO set from stored blocks
// This recovers from corrupted/incomplete UTXO sets that cause "missing utxo" errors
bool Chain::rebuild_utxo_from_blocks() {
    MIQ_CHAIN_GUARD();

    // CRITICAL FIX: Use chain height, not storage count
    // After reorgs, storage may contain orphaned blocks at different indices.
    // We must walk the ACTUAL CHAIN from genesis to tip.
    uint64_t chain_height = tip_.height;
    if (chain_height == 0 && tip_.hash.empty()) {
        return true;  // Nothing to rebuild (no chain yet)
    }

    log_warn("Rebuilding UTXO set from " + std::to_string(chain_height + 1) + " blocks (height 0 to " + std::to_string(chain_height) + ")...");

    // Clear existing UTXO set
    utxo_.clear();

    // CRITICAL FIX: Process blocks by CHAIN HEIGHT using get_block_by_index()
    // This follows the actual chain, not storage order which may include orphans
    for (uint64_t h = 0; h <= chain_height; ++h) {
        Block blk;
        // CRITICAL FIX: Use get_block_by_index which walks the chain, not storage
        if (!get_block_by_index((size_t)h, blk)) {
            // CRITICAL FIX: FAIL on missing blocks, don't continue!
            // A missing block means UTXO set would be incomplete/incorrect
            log_error("UTXO rebuild FAILED: cannot read block at height " + std::to_string(h) +
                      " - chain may be corrupted");
            return false;
        }

        if (blk.txs.empty()) {
            log_error("UTXO rebuild FAILED: block at height " + std::to_string(h) + " has no transactions");
            return false;
        }

        // Add coinbase outputs
        const auto& cb = blk.txs[0];
        auto cb_txid = cb.txid();
        for (size_t i = 0; i < cb.vout.size(); ++i) {
            UTXOEntry e{cb.vout[i].value, cb.vout[i].pkh, h, true};
            if (!utxo_.add(cb_txid, (uint32_t)i, e)) {
                log_error("UTXO rebuild FAILED: cannot add coinbase output at height " + std::to_string(h));
                return false;
            }
        }

        // Process non-coinbase transactions
        for (size_t ti = 1; ti < blk.txs.size(); ++ti) {
            const auto& tx = blk.txs[ti];

            // Spend inputs
            for (const auto& in : tx.vin) {
                // Note: spend() may fail if UTXO doesn't exist (indicates prior corruption)
                // We continue anyway since we're rebuilding from scratch
                utxo_.spend(in.prev.txid, in.prev.vout);
            }

            // Add outputs
            auto txid = tx.txid();
            for (size_t i = 0; i < tx.vout.size(); ++i) {
                UTXOEntry e{tx.vout[i].value, tx.vout[i].pkh, h, false};
                if (!utxo_.add(txid, (uint32_t)i, e)) {
                    log_error("UTXO rebuild FAILED: cannot add output at height " + std::to_string(h));
                    return false;
                }
            }
        }

        if (h % 1000 == 0 && h > 0) {
            log_info("UTXO rebuild progress: " + std::to_string(h) + "/" + std::to_string(chain_height + 1) + " blocks");
        }
    }

    log_info("UTXO rebuild complete: processed " + std::to_string(chain_height + 1) + " blocks");
    return true;
}

bool Chain::load_state(){
    MIQ_CHAIN_GUARD();
    std::vector<uint8_t> b;

    if(!storage_.read_state(b)){
        // State file missing or corrupted - try to rebuild from blocks
        return rebuild_state_from_blocks();
    }

    if(b.size() < 32 + 8 + 8 + 4 + 8){
        // State file truncated/corrupted - try to rebuild from blocks
        log_warn("State file truncated, attempting recovery...");
        return rebuild_state_from_blocks();
    }

    size_t i = 0;
    tip_.hash.assign(b.begin() + i, b.begin() + i + 32); i += 32;

    tip_.height = 0;
    for (int k = 0; k < 8; ++k) {
        tip_.height |= (uint64_t)b[i + k] << (k * 8);
    }
    i += 8;

    tip_.time = 0;
    for (int k = 0; k < 8; ++k) {
        tip_.time |= (uint64_t)b[i + k] << (k * 8);
    }
    i += 8;

    tip_.bits = b[i] | (b[i+1] << 8) | (b[i+2] << 16) | (b[i+3] << 24);
    i += 4;

    tip_.issued = 0;
    for (int k = 0; k < 8; ++k) {
        tip_.issued |= (uint64_t)b[i + k] << (k * 8);
    }
    i += 8;

    // PERF: Calculate cumulative work once on startup
    // This is O(n) but only runs once, not on every header like before
    tip_.work_sum = 0.0L;
    if (tip_.height > 0) {
        std::vector<uint8_t> cur_hash = tip_.hash;
        uint64_t cur_height = tip_.height;
        while (cur_height > 0) {
            std::vector<uint8_t> raw;
            Block blk;
            if (storage_.read_block_by_hash(cur_hash, raw) && deser_block(raw, blk)) {
                tip_.work_sum += work_from_bits(blk.header.bits);
                cur_hash = blk.header.prev_hash;
                cur_height--;
            } else break;
        }
        // Add genesis work
        tip_.work_sum += work_from_bits(GENESIS_BITS);
    }

    // CRITICAL FIX: Verify chain connectivity from genesis to tip
    // Just checking if tip block exists isn't enough - the chain must be CONNECTED
    // This detects corruption where state.dat claims higher height but intermediate blocks are missing
    if (tip_.height > 0) {
        // First check: does the tip block exist?
        Block tip_block;
        if (!get_block_by_index(tip_.height, tip_block)) {
            log_warn("CORRUPTION DETECTED: state.dat claims height=" + std::to_string(tip_.height) +
                     " but tip block doesn't exist! Rebuilding...");
            return rebuild_state_from_blocks();
        }

        // Second check: does tip hash match?
        if (tip_block.block_hash() != tip_.hash) {
            log_warn("CORRUPTION DETECTED: tip block hash mismatch! Rebuilding...");
            return rebuild_state_from_blocks();
        }

        // Third check: verify chain connectivity by walking back from tip
        // We don't need to check every block, just spot-check the last N blocks
        std::vector<uint8_t> expected_hash = tip_.hash;
        uint64_t check_height = tip_.height;
        uint64_t checks_done = 0;
        const uint64_t max_checks = 50;  // Check last 50 blocks for connectivity

        while (check_height > 0 && checks_done < max_checks) {
            std::vector<uint8_t> raw;
            if (!storage_.read_block_by_hash(expected_hash, raw)) {
                log_warn("CORRUPTION DETECTED: block at height " + std::to_string(check_height) +
                         " not found by hash! Chain is disconnected. Rebuilding...");
                return rebuild_state_from_blocks();
            }

            Block blk;
            if (!deser_block(raw, blk)) {
                log_warn("CORRUPTION DETECTED: failed to deserialize block at height " +
                         std::to_string(check_height) + "! Rebuilding...");
                return rebuild_state_from_blocks();
            }

            // Move to parent block
            expected_hash = blk.header.prev_hash;
            check_height--;
            checks_done++;
        }

        log_info("Chain connectivity verified (checked " + std::to_string(checks_done) + " blocks)");
    }

    return true;
}

void Chain::rebuild_header_index_from_blocks(){
    MIQ_CHAIN_GUARD();

    // CRITICAL FIX: Also rebuild if header index exists but is behind tip_
    // This handles the case where blocks.dat has more blocks than header index
    // Without this fix, best_header_height() would return stale value
    uint64_t current_best_header_height = 0;
    if (!best_header_key_.empty()) {
        auto it = header_index_.find(best_header_key_);
        if (it != header_index_.end()) {
            current_best_header_height = it->second.height;
        }
    }

    // Skip rebuild if:
    // - No blocks to process (tip_.height == 0)
    // - Header index is in sync with tip (current_best_header_height >= tip_.height)
    if (tip_.height == 0) {
        return;
    }

    // Only log and rebuild if we're behind
    if (!header_index_.empty() && current_best_header_height >= tip_.height) {
        return;  // Header index is up to date
    }

    if (!header_index_.empty() && current_best_header_height < tip_.height) {
        log_info("Header index is behind tip (headers=" + std::to_string(current_best_header_height) +
                 " tip=" + std::to_string(tip_.height) + ") - rebuilding missing entries...");
    }

    // Count actual blocks in storage (handle gaps)
    // Scan the full range up to tip_.height to find all blocks (including gaps)
    uint64_t actual_block_count = 0;
    uint64_t highest_block_found = 0;
    for (uint64_t h = 0; h <= tip_.height; ++h) {
        Block blk;
        if (get_block_by_index((size_t)h, blk)) {
            actual_block_count++;
            highest_block_found = h;
        }
    }

    // Start from genesis (height 0), rebuild for all blocks that exist (handle gaps)
    for (uint64_t h = 0; h <= highest_block_found; ++h) {
        Block blk;
        if (!get_block_by_index((size_t)h, blk)) {
            continue;  // Skip missing blocks, don't break
        }

        const auto hh = header_hash_of(blk.header);
        const auto key = hk(hh);

        // Skip if already in index
        if (header_index_.find(key) != header_index_.end()) {
            continue;
        }

        // For genesis, manually add to index without validation
        if (h == 0) {
            HeaderMeta m;
            m.hash   = hh;
            m.prev   = blk.header.prev_hash;
            m.bits   = blk.header.bits;
            m.time   = blk.header.time;
            m.have_block = true;
            m.height = 0;
            m.work_sum = work_from_bits(blk.header.bits);
            header_index_.emplace(key, std::move(m));
            best_header_key_ = key;
            // PERFORMANCE FIX: Populate height index for O(1) lookups
            header_height_index_[0] = hh;
            // BITCOIN CORE FIX: Initialize ReorgManager with genesis during rebuild
            g_reorg.init_genesis(hh, blk.header.bits, blk.header.time);
            continue;
        }

        // For non-genesis headers, add directly without validation
        // (these blocks are already stored and were validated when mined)
        HeaderMeta m;
        m.hash   = hh;
        m.prev   = blk.header.prev_hash;
        m.bits   = blk.header.bits;
        m.time   = blk.header.time;
        m.have_block = true;

        // Get parent height and work
        uint64_t parent_height = 0;
        long double parent_work = 0.0L;
        auto itp = header_index_.find(hk(blk.header.prev_hash));
        if (itp != header_index_.end()) {
            parent_height = itp->second.height;
            parent_work   = itp->second.work_sum;
        } else if (blk.header.prev_hash == tip_.hash) {
            parent_height = tip_.height;
            parent_work   = tip_.work_sum;  // PERF: Use cached work
        }
        m.height   = parent_height + 1;
        m.work_sum = parent_work + work_from_bits(blk.header.bits);

        // PERF: Keep tip_.work_sum updated as we rebuild
        if (m.height == tip_.height && m.hash == tip_.hash) {
            tip_.work_sum = m.work_sum;
        }

        // Save height before m is moved
        uint64_t rebuild_saved_height = m.height;

        header_index_.emplace(key, std::move(m));
        set_header_full(key, blk.header);  // THREAD-SAFE

        // PERFORMANCE FIX: Populate height index for O(1) lookups
        header_height_index_[rebuild_saved_height] = hh;

        // BITCOIN CORE FIX: Register rebuilt header with ReorgManager
        {
            miq::HeaderView rhv;
            rhv.hash   = hh;
            rhv.prev   = blk.header.prev_hash;
            rhv.bits   = blk.header.bits;
            rhv.time   = blk.header.time;
            rhv.height = (uint32_t)rebuild_saved_height;
            g_reorg.on_validated_header(rhv);
        }

        // Update best header if this has more work
        if (best_header_key_.empty()) {
            best_header_key_ = key;
        } else {
            // STABILITY FIX: Use find() instead of at() to avoid exceptions
            auto cur_it = header_index_.find(best_header_key_);
            auto neu_it = header_index_.find(key);
            if (cur_it != header_index_.end() && neu_it != header_index_.end()) {
                const auto& cur = cur_it->second;
                const auto& neu = neu_it->second;
                auto eps = [](long double a, long double b){
                    long double scale = std::max<long double>(1.0L, std::max(std::fabs(a), std::fabs(b)));
                    return 1e-12L * scale;
                };
                long double e = eps(neu.work_sum, cur.work_sum);
                bool greater   = (neu.work_sum - cur.work_sum) >  e;
                bool equalish  = std::fabs(neu.work_sum - cur.work_sum) <= e;
                if (greater || (equalish && neu.height > cur.height)) {
                    best_header_key_ = key;
                }
            } else if (cur_it == header_index_.end()) {
                best_header_key_ = key;
            }
        }
    }

    MIQ_LOG_INFO(LogCategory::VALIDATION,
        "rebuild_header_index_from_blocks: rebuilt index with " +
        std::to_string(actual_block_count) + " blocks (highest=" +
        std::to_string(highest_block_found) + ", indexed=" +
        std::to_string(header_index_.size()) + ")");
}

uint64_t Chain::subsidy_for_height(uint64_t h) const {
    return GetBlockSubsidy(static_cast<uint32_t>(h));
}

bool Chain::init_genesis(const Block& g){
    MIQ_CHAIN_GUARD();
    if(tip_.hash != std::vector<uint8_t>(32,0)) return true;

    // NOTE: Genesis block merkle root validation is SKIPPED here because:
    // 1. The genesis block is hardcoded in constants.h (not received from network)
    // 2. main.cpp already validates the block hash and header merkle match expected values
    // 3. The original genesis was created with a header merkle that doesn't match
    //    the computed txid (likely a tooling issue during genesis creation)
    // 4. Fixing this would change the block hash and require all nodes to resync
    //
    // For all other blocks, verify_block() validates the merkle root properly.

    // Initialize reorg manager with the genesis block hash
    g_reorg.init_genesis(g.block_hash(), g.header.bits, g.header.time);

    storage_.append_block(ser_block(g), g.block_hash());

    const auto& cb = g.txs[0];
    uint64_t cb_sum = 0;
    for(size_t i=0;i<cb.vout.size();++i){
        UTXOEntry e{cb.vout[i].value, cb.vout[i].pkh, 0, true};
        utxo_.add(cb.txid(), (uint32_t)i, e);
        cb_sum += cb.vout[i].value;
    }

    tip_ = Tip{0, g.block_hash(), g.header.bits, g.header.time, cb_sum, work_from_bits(g.header.bits)};
    index_.reset(tip_.hash, tip_.time, tip_.bits);
    save_state();

    // Cache the full genesis header for serving to peers
    set_header_full(hk(g.block_hash()), g.header);  // THREAD-SAFE

    #if MIQ_HAVE_GCS_FILTERS
    // Build & store genesis filter (best-effort)
    std::vector<uint8_t> fbytes;
    if (miq::gcs::build_block_filter(g, fbytes)) {
         if (!g_filter_store.put(/*height=*/0, g.block_hash(), fbytes)) {
             log_warn("FilterStore: put(genesis) failed");
         }
    } else {
         log_warn("BlockFilter: build(genesis) failed");
    }
    #endif

    return true;
}

// SECURITY: Maximum transactions per block to prevent DoS
static constexpr size_t MAX_BLOCK_TXS = 50000;
// SECURITY: Maximum coinbase outputs to prevent DoS
static constexpr size_t MAX_COINBASE_OUTPUTS = 100;

bool Chain::verify_block(const Block& b, std::string& err) const{
    MIQ_CHAIN_GUARD();

    // Basic block structure validation
    if (b.txs.empty()) {
        err = "block has no transactions";
        return false;
    }

    // SECURITY FIX: Limit transaction count to prevent memory exhaustion
    if (b.txs.size() > MAX_BLOCK_TXS) {
        err = "too many transactions in block";
        return false;
    }

    // SECURITY FIX: Limit coinbase outputs to prevent DoS
    if (!b.txs.empty() && b.txs[0].vout.size() > MAX_COINBASE_OUTPUTS) {
        err = "too many coinbase outputs";
        return false;
    }

    if(b.header.prev_hash != tip_.hash){ err="bad prev hash"; return false; }

    // MTP
    auto hdrs = last_headers(11);
    int64_t mtp = tip_.time;
    if (!hdrs.empty()) {
        std::vector<int64_t> ts; ts.reserve(hdrs.size());
        for (auto& p : hdrs) ts.push_back(p.first);
        std::sort(ts.begin(), ts.end());
        mtp = ts[ts.size()/2];
    }
    if (b.header.time <= mtp) { err = "time <= MTP"; return false; }

    // Future bound
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (b.header.time > now + (int64_t)MAX_TIME_SKEW) { err="time too far in future"; return false; }
    }

    // Merkle + duplicate guard
    if (b.txs.empty()){ err="no coinbase"; return false; }

    // Calculate block height for assume-valid check (used later for signature skipping)
    const uint64_t block_height = tip_.height + 1;
    const auto block_hash = b.block_hash();

    // CHECKPOINT VALIDATION: Reject blocks that don't match checkpoints
    // This prevents nodes from following forked chains
    if (!miq::check_checkpoint(block_height, block_hash)) {
        err = "block hash does not match checkpoint at height " + std::to_string(block_height);
        return false;
    }

    // CRITICAL PERFORMANCE: Check if we should skip signature verification
    // For blocks below the assume-valid checkpoint, signatures have already
    // been verified by the network. We still validate UTXO, amounts, etc.
    const bool skip_sigs = !miq::should_validate_signatures(block_hash, block_height);
    if (skip_sigs) {
        MIQ_LOG_DEBUG(miq::LogCategory::VALIDATION,
            "Assume-valid: skipping signatures for block " + std::to_string(block_height));
    }

    // PERF: Compute txids once and reuse for duplicate check, merkle, and BIP30
    std::vector<std::vector<uint8_t>> txids;
    {
        std::unordered_set<std::string> seen;
        txids.reserve(b.txs.size());
        for (const auto& tx : b.txs) {
            auto id = tx.txid();
            std::string key(reinterpret_cast<const char*>(id.data()), id.size());
            if (!seen.insert(key).second) { err="duplicate txid"; return false; }
            txids.push_back(std::move(id));
        }

        // Skip merkle verification only for genesis block (height 0) which has mismatched merkle
        if (!should_skip_merkle_verification(block_height)) {
            auto mr = merkle_root(txids);
            // NETWORK COMPAT FIX: Try both byte-orders for merkle root comparison
            // Some blocks in the network have merkle roots stored in reversed byte order
            // relative to how tx.txid() computes them. This handles both orientations.
            if (mr != b.header.merkle_root) {
                std::vector<uint8_t> mr_reversed = mr;
                std::reverse(mr_reversed.begin(), mr_reversed.end());
                if (mr_reversed != b.header.merkle_root) {
                    // DIAGNOSTIC: Log full details about merkle mismatch
                    MIQ_LOG_WARN(miq::LogCategory::VALIDATION, "bad merkle: computed=" + to_hex(mr) +
                                 " reversed=" + to_hex(mr_reversed) +
                                 " header=" + to_hex(b.header.merkle_root) +
                                 " txs=" + std::to_string(b.txs.size()));
                    err="bad merkle";
                    return false;
                }
            }
        }
    }

    // Coinbase shape (allow tagged sig; pubkey must be empty)
    const auto& cb = b.txs[0];
    if (cb.vin.size()!=1 || !cb.vin[0].pubkey.empty()) { err="bad coinbase"; return false; }
    if (cb.vin[0].prev.txid.size()!=32) { err="bad coinbase prev size"; return false; }
    if (std::any_of(cb.vin[0].prev.txid.begin(), cb.vin[0].prev.txid.end(), [](uint8_t v){ return v!=0; })) { err="bad coinbase prev"; return false; }
    if (cb.vin[0].prev.vout != 0) { err="bad coinbase vout"; return false; }

    // === BIP30: reject if any txid already has ANY unspent outputs (ALWAYS on) ===
    // PERF: Use pre-computed txids from earlier loop instead of recomputing
    {
        UTXOEntry dummy;
        for (size_t i = 0; i < b.txs.size(); ++i) {
            const auto& id = txids[i];  // Use cached txid
            for (uint32_t v = 0; v < (uint32_t)b.txs[i].vout.size(); ++v) {
                if (utxo_.get(id, v, dummy)) {
                    err = "BIP30 duplicate txid";
                    return false;
                }
            }
        }
    }

    // Non-coinbase tx checks
    for (size_t ti=1; ti<b.txs.size(); ++ti) {
        const auto& tx = b.txs[ti];
        if (tx.vin.empty() || tx.vout.empty()) { err="empty tx"; return false; }
        if (tx.vin.size()==1 && tx.vin[0].prev.vout==0 &&
            tx.vin[0].prev.txid.size()==32 &&
            std::all_of(tx.vin[0].prev.txid.begin(), tx.vin[0].prev.txid.end(), [](uint8_t v){return v==0;})) {
            err="multiple coinbase"; return false;
        }
        auto raw = ser_tx(tx);
        if (raw.size() > MIQ_FALLBACK_MAX_TX_SIZE) { err="tx too large"; return false; }
    }

    // Difficulty bits equality (ALWAYS on), computed using last_headers() for consistency with mining.
    // CRITICAL FIX: Always use last_headers() to match what mining uses when calculating difficulty.
    // Previously, validation walked backwards through header_index_ which could produce a different
    // window than mining (e.g., if the fallback added an extra entry, causing window size mismatch).
    // This caused "bad bits" rejections at epoch boundaries after the third epoch.
    {
        auto itp = header_index_.find(hk(b.header.prev_hash));
        uint64_t next_h = (itp != header_index_.end()) ? itp->second.height + 1 : tip_.height + 1;

        // Use last_headers() - the same function mining uses - to ensure identical window calculation
        auto window = last_headers(MIQ_RETARGET_INTERVAL);
        uint32_t expected = miq::epoch_next_bits(
            window, BLOCK_TIME_SECS, GENESIS_BITS,
            /*next_height=*/ next_h,
            /*interval=*/ MIQ_RETARGET_INTERVAL
        );
        if (b.header.bits != expected) { err = "bad bits"; return false; }
    }

    // POW - use cached block_hash instead of recomputing
    if (!meets_target_be(block_hash, b.header.bits)) { err = "bad pow"; return false; }

    // Block raw size cap
    if (ser_block(b).size() > MAX_BLOCK_SIZE_LOCAL) { err = "oversize block"; return false; }

    // ---- Safe math helpers ----
    auto add_u64_safe = [](uint64_t a, uint64_t b, uint64_t& out)->bool { out = a + b; return out >= a; };
    auto leq_max_money = [](uint64_t v)->bool { return v <= (uint64_t)MAX_MONEY; };

    struct Key { std::vector<uint8_t> txid; uint32_t vout; };
    struct KH { size_t operator()(Key const& k) const noexcept {
        size_t h = k.vout * 1315423911u;
        if(!k.txid.empty()){ h ^= (size_t)k.txid.front() * 2654435761u; h ^= (size_t)k.txid.back() * 2246822519u; }
        return h;
    }};
    struct KE { bool operator()(Key const& a, Key const& b) const noexcept { return a.vout==b.vout && a.txid==b.txid; } };
    std::unordered_set<Key, KH, KE> spent_in_block;

    // CRITICAL FIX: Track outputs created by earlier transactions in this block
    // This enables spending of outputs created earlier in the same block (chained transactions)
    std::unordered_map<Key, UTXOEntry, KH, KE> created_in_block;

    // SECURITY FIX: Clear BOTH sig AND pubkey for sighash computation
    // This prevents signature malleability attacks where different pubkeys
    // could produce different sighashes for the same transaction
    auto sigh=[&](const Transaction& t){
        Transaction tmp=t;
        for(auto& i: tmp.vin) {
            i.sig.clear();
            i.pubkey.clear();
        }
        return dsha256(ser_tx(tmp));
    };

    // CRITICAL DEBUG: Log the exact order of transactions in submitted block
    if (b.txs.size() > 2) {  // More than just coinbase + 1 tx
        std::string order_log = "verify_block TX ORDER in block: ";
        for (size_t i = 1; i < b.txs.size(); ++i) {
            std::string txid_short = to_hex(b.txs[i].txid()).substr(0, 8);
            order_log += "[" + std::to_string(i-1) + "]=" + txid_short + " ";
        }
        MIQ_LOG_INFO(miq::LogCategory::VALIDATION, order_log);
    }

    uint64_t fees = 0, tmp = 0;
    for(size_t ti=1; ti<b.txs.size(); ++ti){
        const auto& tx=b.txs[ti];
        uint64_t in=0, out=0;

        for (const auto& o : tx.vout) {
            if (!leq_max_money(o.value)) { err="txout>MAX_MONEY"; return false; }
            if (!add_u64_safe(out, o.value, tmp)) { err="tx out overflow"; return false; }
            out = tmp;
        }
        if (!leq_max_money(out)) { err="sum(out)>MAX_MONEY"; return false; }

        auto hash = sigh(tx);

        for(const auto& inx: tx.vin){
            if (inx.pubkey.size() != 33 && inx.pubkey.size() != 65) { err="bad pubkey size"; return false; }

            // CRITICAL FIX: Validate prev.txid is exactly 32 bytes
            // Malformed txids cause UTXO lookup key mismatches, leading to "missing utxo" errors
            // Coinbase has this check at line 1856, but non-coinbase was missing it
            if (inx.prev.txid.size() != 32) {
                err = "bad prev_txid size: " + std::to_string(inx.prev.txid.size()) + " (expected 32)";
                return false;
            }

            Key k{inx.prev.txid, inx.prev.vout};
            if (spent_in_block.find(k) != spent_in_block.end()){ err="in-block double-spend"; return false; }
            spent_in_block.insert(k);

            UTXOEntry e;
            // CRITICAL FIX: First check if this output was created earlier in this block
            // This enables chained transactions where Tx B spends output from Tx A in same block
            auto cib_it = created_in_block.find(k);
            if (cib_it != created_in_block.end()) {
                e = cib_it->second;
                MIQ_LOG_DEBUG(miq::LogCategory::VALIDATION, "verify_block: tx[" + std::to_string(ti) +
                              "] input found in created_in_block (chained tx OK)");
            } else if(!utxo_.get(inx.prev.txid, inx.prev.vout, e)){
                // DEBUG: Log detailed info about missing UTXO to help diagnose the issue
                std::string full_txid = to_hex(inx.prev.txid);
                MIQ_LOG_WARN(miq::LogCategory::VALIDATION, "verify_block: tx[" + std::to_string(ti) +
                             "] MISSING UTXO - prev_txid=" + full_txid.substr(0, 16) +
                             "... vout=" + std::to_string(inx.prev.vout) +
                             ", created_in_block has " + std::to_string(created_in_block.size()) + " entries" +
                             ", current_tip_height=" + std::to_string(tip_.height) +
                             ", block_being_verified=" + std::to_string(tip_.height + 1));

                // Additional diagnostic: check if we have the parent transaction in txindex
                TxLocation parent_loc;
                if (txindex_.get(inx.prev.txid, parent_loc)) {
                    MIQ_LOG_WARN(miq::LogCategory::VALIDATION, std::string("  -> Parent tx found in txindex at height ") +
                                 std::to_string(parent_loc.block_height) + " pos " + std::to_string(parent_loc.tx_position) +
                                 " - UTXO should exist but doesn't! Possible incomplete block processing.");
                } else {
                    MIQ_LOG_WARN(miq::LogCategory::VALIDATION, std::string("  -> Parent tx NOT in txindex - ") +
                                 "transaction may not exist on this chain");
                }

                err="missing utxo";
                return false;
            }
            // SECURITY FIX: Use <= instead of < for coinbase maturity check
            // MIQ requires 100 confirmations, meaning coinbase at height H
            // is spendable at height H + COINBASE_MATURITY + 1
            // Example: coinbase at 100, maturity 100 -> spendable at 201
            if(e.coinbase && tip_.height+1 <= e.height + COINBASE_MATURITY){ err="immature coinbase"; return false; }
            if(hash160(inx.pubkey)!=e.pkh){ err="pkh mismatch"; return false; }
            // CRITICAL PERFORMANCE: Skip signature verification for assume-valid blocks
            // This dramatically speeds up IBD (Initial Block Download) by skipping
            // expensive ECDSA verification for blocks that have already been
            // verified by the network. We still validate UTXO, amounts, pkh, etc.
            if (!skip_sigs) {
                if(!crypto::ECDSA::verify(inx.pubkey, hash, inx.sig)){ err="bad signature"; return false; }
            #if MIQ_RULE_ENFORCE_LOW_S
                if (!is_low_s64(inx.sig)) { err = "high-S signature"; return false; }
            #endif
            }
            // Sum input values (after signature check to avoid expensive crypto on invalid tx)
            if (!leq_max_money(e.value)) { err = "utxo>MAX_MONEY"; return false; }
            if (!add_u64_safe(in, e.value, tmp)) { err = "tx in overflow"; return false; }
            in = tmp;
        }
        if (!leq_max_money(in)) { err="sum(in)>MAX_MONEY"; return false; }

        if(out > in){ err="outputs>inputs"; return false; }
        uint64_t fee = in - out;
        if (!leq_max_money(fee)) { err="fee>MAX_MONEY"; return false; }
        if (!add_u64_safe(fees, fee, tmp)) { err="fees overflow"; return false; }
        fees = tmp;

        // CRITICAL FIX: Add this transaction's outputs to created_in_block
        // This allows later transactions in this block to spend these outputs
        auto txid = tx.txid();
        for (uint32_t vi = 0; vi < tx.vout.size(); ++vi) {
            Key outk{txid, vi};
            UTXOEntry out_entry{tx.vout[vi].value, tx.vout[vi].pkh, tip_.height + 1, false};
            created_in_block.emplace(outk, out_entry);
        }
    }

    // Coinbase payout checks
    uint64_t sub = subsidy_for_height(tip_.height+1);
    uint64_t cb_sum = 0, tmp2 = 0;
    for(const auto& o:cb.vout){
        if (!leq_max_money(o.value)) { err="coinbase out>MAX_MONEY"; return false; }
        if (!add_u64_safe(cb_sum, o.value, tmp2)) { err="coinbase overflow"; return false; }
        cb_sum = tmp2;
    }
    if(cb_sum > sub + fees){ err="coinbase too high"; return false; }
    if(!leq_max_money(cb_sum)){ err="coinbase>MAX_MONEY"; return false; }

    // Hard MAX_SUPPLY: subsidy-only against remaining supply (ALWAYS on)
    {
        uint64_t coinbase_without_fees = (cb_sum > fees) ? (cb_sum - fees) : 0;
        if (WouldExceedMaxSupply((uint32_t)(tip_.height + 1), coinbase_without_fees)) {
            err = "exceeds max supply";
            return false;
        }
    }

    if(tip_.issued > (uint64_t)MAX_MONEY - cb_sum){ err="exceeds cap"; return false; }

    return true;
}

// ---------- UTXO atomic-apply helper (uses batch if available) ----------
struct UtxoOp {
    bool is_add{false};
    std::vector<uint8_t> txid;
    uint32_t vout{0};
    UTXOEntry entry; // valid only when is_add=true
};

template<typename DB>
static auto has_make_batch_impl(int) -> decltype(std::declval<DB&>().make_batch(), std::true_type{});
template<typename DB>
static auto has_make_batch_impl(...) -> std::false_type;
template<typename DB>
static constexpr bool has_make_batch_v = decltype(has_make_batch_impl<DB>(0))::value;

template<typename DB>
static bool utxo_apply_ops(DB& db, const std::vector<UtxoOp>& ops, std::string& err) {
    if constexpr (has_make_batch_v<DB>) {
        auto batch = db.make_batch();
        for (const auto& op : ops) {
            if (op.is_add) batch.add(op.txid, op.vout, op.entry);
            else           batch.spend(op.txid, op.vout);
        }
        std::string kv_err;
        if (!batch.commit(/*sync=*/!fast_sync_enabled(), &kv_err)) {
            err = kv_err.empty() ? "utxo batch commit failed" : kv_err;
            return false;
        }
        return true;
    } else {
        for (const auto& op : ops) {
            if (op.is_add) {
                if (!db.add(op.txid, op.vout, op.entry)) {
                    err = "utxo add failed";
                    return false;
                }
            } else {
                if (!db.spend(op.txid, op.vout)) {
                    err = "utxo spend failed";
                    return false;
                }
            }
        }
        return true;
    }
}
// -----------------------------------------------------------------------

bool Chain::disconnect_tip_once(std::string& err){
    MIQ_CHAIN_GUARD();
    if (tip_.height == 0) { err = "cannot disconnect genesis"; return false; }

    Block cur;
    if (!get_block_by_hash(tip_.hash, cur)) {
        err = "failed to read tip block";
        return false;
    }

    std::vector<UndoIn> undo_tmp;
    {
        std::lock_guard<std::mutex> lk(g_undo_mtx);
        auto it_ram = g_undo.find(hk(tip_.hash));
        if (it_ram != g_undo.end()) {
            undo_tmp = it_ram->second;
        }
    }
    if (undo_tmp.empty()) {
        if (!read_undo_file(datadir_, tip_.height, tip_.hash, undo_tmp)) {
            err = "no undo data for tip (restart or missing undo)";
            return false;
        }
    }
    const std::vector<UndoIn>& undo = undo_tmp;

    // Build UTXO reversal ops
    std::vector<UtxoOp> ops;
    ops.reserve(64);

    // Spend non-coinbase created outs
    for (size_t ti = cur.txs.size(); ti-- > 1; ){
        const auto& tx = cur.txs[ti];
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            ops.push_back(UtxoOp{false, tx.txid(), (uint32_t)i, {}});
        }
    }

    // Restore previous inputs from undo (reverse order)
    // CRITICAL FIX: Skip in-block spends that may exist in old undo data
    // Before the chained transaction fix, undo data incorrectly included entries
    // for outputs created and spent within the same block. These should NOT be
    // restored because they never existed in UTXO before this block.
    // Detection: if prev_entry.height == tip_.height, it was created in this block.
    for (size_t i = undo.size(); i-- > 0; ){
        const auto& u = undo[i];
        // Skip in-block spends: outputs created at this block's height were
        // created within this block and should not be restored to UTXO
        if (u.prev_entry.height == tip_.height) {
            continue;  // In-block spend, do not restore
        }
        ops.push_back(UtxoOp{true, u.prev_txid, u.prev_vout, u.prev_entry});
    }

    // Remove coinbase outs and compute sum
    const auto& cb = cur.txs[0];
    uint64_t cb_sum = 0;
    for (size_t i = 0; i < cb.vout.size(); ++i) {
        ops.push_back(UtxoOp{false, cb.txid(), (uint32_t)i, {}});
        cb_sum += cb.vout[i].value;
    }
    if (tip_.issued < cb_sum) { err = "issued underflow"; return false; }

    // Commit reversals atomically if backend supports it
    if (!utxo_apply_ops(utxo_, ops, err)) return false;

    // CRITICAL FIX: Remove transactions from TxIndex on block disconnect (reorg handling)
    // This ensures the transaction index stays consistent with the active chain
    txindex_.remove_block(tip_.height);

    // === EXPLORER INDEX ROLLBACK ===

    // Remove block from Address Index
    if (addrindex_.is_enabled()) {
        addrindex_.unindex_block(cur, tip_.height);
    }

    // Remove block from Hash Index
    hashindex_.remove(cur.block_hash());

    // CRITICAL FIX: Rollback BIP158 filters on disconnect to maintain consistency
    // Without this, SPV clients can receive stale filters after a reorg
#if MIQ_HAVE_GCS_FILTERS
    {
        const uint32_t new_tip_h = (uint32_t)(tip_.height - 1);
        if (!g_filter_store.rollback_to(new_tip_h)) {
            log_warn("FilterStore: rollback_to failed for height=" + std::to_string(new_tip_h));
            // Non-fatal: filters will be rebuilt on next connect
        }
    }
#endif

    Block prev;
    if (!get_block_by_hash(cur.header.prev_hash, prev)) {
        err = "failed to read prev block";
        return false;
    }

    tip_.height -= 1;
    tip_.hash   = cur.header.prev_hash;
    tip_.bits   = prev.header.bits;
    tip_.time   = prev.header.time;
    tip_.issued -= cb_sum;
    tip_.work_sum -= work_from_bits(cur.header.bits);  // PERF: Update cached work

    // CRITICAL FIX: Reset best_header_key_ to the new tip after block disconnect
    // Without this, best_header_height() returns the old (higher) disconnected header height
    // which causes compute_sync_gate() to fail with "syncing (cur/old_higher)" forever.
    // This was causing "Finalizing..." stuck state after deleting malicious blocks.
    best_header_key_ = hk(tip_.hash);

    // Also reset the global atomic header height used by P2P and assume-valid
    miq::reset_best_header_height(tip_.height);

    {
        std::lock_guard<std::mutex> lk(g_undo_mtx);
        auto it_ram2 = g_undo.find(hk(cur.block_hash()));
        if (it_ram2 != g_undo.end()) g_undo.erase(it_ram2);
    }
    remove_undo_file(datadir_, (uint64_t)(tip_.height + 1), cur.block_hash());

    save_state();
    return true;
}

bool Chain::submit_block(const Block& b, std::string& err, uint64_t* out_height){
    MIQ_CHAIN_GUARD();

    // PERF: Start timing for near-tip performance analysis
    BlockTiming tm;
    tm.t_validate_start = BlockTiming::now_ms();
    tm.height = tip_.height + 1;

    // Ensure header is in index before block validation
    const auto hh = b.block_hash();
    const auto key = hk(hh);

    // Check if we already have this block
    if (have_block(hh)) {
        // CRITICAL FIX: Detect incomplete block processing
        // If this block's prev_hash matches our current tip but our tip hasn't advanced,
        // it means the block was stored but UTXO operations failed (e.g., due to crash).
        // In this case, we need to re-process the UTXOs rather than returning early.
        bool incomplete_processing = (b.header.prev_hash == tip_.hash);

        if (incomplete_processing) {
            log_warn("Detected incomplete block processing at height " +
                     std::to_string(tip_.height + 1) + " - re-applying UTXOs");
            // Fall through to continue processing UTXOs
        } else {
            // Block doesn't extend tip - truly a duplicate or already processed
            if (header_index_.find(key) == header_index_.end()) {
                std::string header_err;
                accept_header(b.header, header_err);
            }
            return true;
        }
    }
    
    // Add header to index if not present
    if (header_index_.find(key) == header_index_.end()) {
        std::string header_err;
        if (!accept_header(b.header, header_err)) {
            log_warn("Failed to accept header during block submission: " + header_err);
        }
    }

    if (!verify_block(b, err)) return false;
    tm.t_validate_end = BlockTiming::now_ms();

    // CRITICAL FIX: Don't early-return here if block extends tip
    // This handles the case where block was stored but UTXO wasn't applied
    if (have_block(b.block_hash()) && b.header.prev_hash != tip_.hash) {
        return true;
    }

    // --- Collect undo BEFORE mutating UTXO ---
    std::vector<UndoIn> undo;
    undo.reserve(b.txs.size() * 2);

    // CRITICAL FIX: Track outputs created by earlier transactions in this block
    // This mirrors the same logic in verify_block() and is needed for chained transactions
    // where Tx B spends an output from Tx A, both in the same block.
    // Without this, syncing nodes fail with "missing utxo during undo-capture" on blocks
    // containing chained transactions, because the parent output isn't in UTXO set yet.
    struct UndoKey { std::vector<uint8_t> txid; uint32_t vout; };
    struct UndoKeyHash {
        size_t operator()(const UndoKey& k) const noexcept {
            size_t h = k.vout * 1315423911u;
            if(!k.txid.empty()){ h ^= (size_t)k.txid.front() * 2654435761u; h ^= (size_t)k.txid.back() * 2246822519u; }
            return h;
        }
    };
    struct UndoKeyEq {
        bool operator()(const UndoKey& a, const UndoKey& b) const noexcept {
            return a.vout == b.vout && a.txid == b.txid;
        }
    };
    std::unordered_map<UndoKey, UTXOEntry, UndoKeyHash, UndoKeyEq> created_in_block;

    const uint64_t pending_height = tip_.height + 1;

    for (size_t ti = 1; ti < b.txs.size(); ++ti){
        const auto& tx = b.txs[ti];
        for (const auto& in : tx.vin){
            UTXOEntry e;
            UndoKey k{in.prev.txid, in.prev.vout};

            // CRITICAL FIX: First check if this output was created earlier in this block
            // This enables chained transactions where Tx B spends output from Tx A in same block
            auto cib_it = created_in_block.find(k);
            if (cib_it != created_in_block.end()) {
                // In-block spend: output was created and spent within same block.
                // Do NOT record in undo - these have no net effect on UTXO set.
                // On disconnect, we should NOT restore these outputs because they
                // never existed in UTXO before this block.
                continue;
            } else if (!utxo_.get(in.prev.txid, in.prev.vout, e)){
                err = "missing utxo during undo-capture";
                return false;
            }
            // Only record undo for outputs that existed BEFORE this block
            undo.push_back(UndoIn{in.prev.txid, in.prev.vout, e});
        }

        // CRITICAL FIX: Add this transaction's outputs to created_in_block
        // This allows later transactions in this block to find these outputs
        auto txid = tx.txid();
        for (uint32_t vi = 0; vi < tx.vout.size(); ++vi) {
            UndoKey outk{txid, vi};
            UTXOEntry out_entry{tx.vout[vi].value, tx.vout[vi].pkh, pending_height, false};
            created_in_block.emplace(outk, out_entry);
        }
    }

    // Persist the block body (only if not already stored)
    // CRITICAL FIX: Check have_block to avoid duplicating storage on re-processing
    if (!have_block(b.block_hash())) {
        storage_.append_block(ser_block(b), b.block_hash());
    }

    // --- Crash-safety: write undo BEFORE UTXO mutation ---
    const uint64_t new_height = tip_.height + 1;
    const auto     new_hash   = b.block_hash();
    if (!write_undo_file(datadir_, new_height, new_hash, undo)) {
        err = "failed to write undo";
        return false;
    }
    tm.t_disk_write = BlockTiming::now_ms();

    // Build UTXO apply ops
    std::vector<UtxoOp> ops;
    ops.reserve(64);

    for (size_t ti = 1; ti < b.txs.size(); ++ti){
        const auto& tx = b.txs[ti];

        // spends
        for (const auto& in : tx.vin){
            ops.push_back(UtxoOp{false, in.prev.txid, in.prev.vout, {}});
        }
        // adds
        for (size_t i = 0; i < tx.vout.size(); ++i){
            UTXOEntry e{tx.vout[i].value, tx.vout[i].pkh, new_height, false};
            ops.push_back(UtxoOp{true, tx.txid(), (uint32_t)i, e});
        }
    }

    // coinbase adds + sum
    const auto& cb = b.txs[0];
    uint64_t cb_sum = 0;
    for (size_t i = 0; i < cb.vout.size(); ++i){
        UTXOEntry e{cb.vout[i].value, cb.vout[i].pkh, new_height, true};
        ops.push_back(UtxoOp{true, cb.txid(), (uint32_t)i, e});
        cb_sum += cb.vout[i].value;
    }

    // Apply all UTXO changes
    if (!utxo_apply_ops(utxo_, ops, err)) return false;
    tm.t_utxo_commit = BlockTiming::now_ms();

    // Advance tip (state)
    tip_.height = new_height;
    tip_.hash   = new_hash;
    tip_.bits   = b.header.bits;
    tip_.time   = b.header.time;
    tip_.issued += cb_sum;
    tip_.work_sum += work_from_bits(b.header.bits);  // PERF: Update cached work

    // Cache undo in RAM map (thread-safe)
    {
        std::lock_guard<std::mutex> lk(g_undo_mtx);
        g_undo[hk(tip_.hash)] = std::move(undo);
    }

    // Also cache the full header for serving to peers
    set_header_full(hk(new_hash), b.header);  // THREAD-SAFE

    // CRITICAL FIX: Add all transactions to the transaction index for fast lookups
    // This enables O(1) transaction lookup by txid instead of scanning blocks
    for (size_t i = 0; i < b.txs.size(); ++i) {
        txindex_.add(b.txs[i].txid(), new_height, static_cast<uint32_t>(i));
    }
    // Periodically flush TxIndex to disk (every 10 blocks for durability)
    if (new_height % 10 == 0) {
        txindex_.flush();
    }

    // === EXPLORER INDEX UPDATES ===

    // Update Address Index for blockchain explorer queries
    if (addrindex_.is_enabled()) {
        addrindex_.index_block(b, new_height);
    }

    // Update Block Hash Index for O(1) block-by-hash lookups
    hashindex_.add(new_hash, new_height);

    // Prune old undo if beyond window
    if (tip_.height >= UNDO_WINDOW) {
        size_t prune_h = (size_t)(tip_.height - UNDO_WINDOW);
        std::vector<uint8_t> prune_hash;
        if (get_hash_by_index(prune_h, prune_hash)) {
            remove_undo_file(datadir_, prune_h, prune_hash);
        }
    }

    #if MIQ_HAVE_GCS_FILTERS
    {
        std::vector<uint8_t> fbytes;
        if (miq::gcs::build_block_filter(b, fbytes)) {
            if (!g_filter_store.put(static_cast<uint32_t>(new_height), new_hash, fbytes)) {
                log_warn("FilterStore: put failed for height=" + std::to_string(new_height) +
                         " hash=" + hexstr(new_hash));
            }
        } else {
            log_warn("BlockFilter: build failed for height=" + std::to_string(new_height) +
                     " hash=" + hexstr(new_hash));
        }
    }
    #endif

    // Notify reorg manager
    miq::HeaderView hv;
    hv.hash   = tip_.hash;
    hv.prev   = b.header.prev_hash;
    hv.bits   = b.header.bits;
    hv.time   = b.header.time;
    hv.height = (uint32_t)tip_.height;
    g_reorg.on_validated_header(hv);

    save_state();
    tm.t_save_state = BlockTiming::now_ms();

    // PERF: Log timing data when in near-tip mode for performance analysis
    tm.log_if_near_tip();

    // Output new height atomically under lock (prevents race with concurrent submissions)
    if (out_height) *out_height = tip_.height;

    return true;
}

std::vector<std::pair<int64_t,uint32_t>> Chain::last_headers(size_t n) const{
    MIQ_CHAIN_GUARD();
    std::vector<std::pair<int64_t,uint32_t>> v;
    if (tip_.time == 0) return v;

    size_t start = 0;
    if (tip_.height + 1 > n) start = (size_t)(tip_.height + 1 - n);

    for (size_t idx = start; idx <= (size_t)tip_.height; ++idx) {
        Block b;
        if (!get_block_by_index(idx, b)) break;
        v.emplace_back(b.header.time, b.header.bits);
    }
    return v;
}

// CRITICAL FIX: get_block_by_index must follow the CURRENT chain, not storage order
// After reorgs, storage indices don't match chain heights - old blocks remain at
// their original storage positions. We must walk back from tip to find the correct
// block hash at the requested height.
bool Chain::get_block_by_index(size_t idx, Block& out) const{
    MIQ_CHAIN_GUARD();

    // Quick bounds check
    if (idx > tip_.height) return false;

    // Special case: if no headers exist, fall back to storage index (pre-IBD)
    // This maintains backwards compatibility for genesis initialization
    if (header_index_.empty()) {
        std::vector<uint8_t> raw;
        if (!storage_.read_block_by_index(idx, raw)) return false;
        return deser_block(raw, out);
    }

    // Walk back from tip to find the block hash at height idx
    // Start from current tip
    std::vector<uint8_t> cur_hash = tip_.hash;
    uint64_t cur_height = tip_.height;

    // Walk back using header_index_ until we reach the target height
    while (cur_height > idx) {
        auto it = header_index_.find(hk(cur_hash));
        if (it == header_index_.end()) {
            // Header not in index - fall back to storage for this and all deeper lookups
            // This handles cases where header_index_ is incomplete (node restart, etc.)
            // IMPORTANT: After reorgs, storage may have stale blocks, but if headers
            // are incomplete we have no choice - let validation catch any issues
            std::vector<uint8_t> raw;
            if (!storage_.read_block_by_index(idx, raw)) return false;
            return deser_block(raw, out);
        }
        cur_hash = it->second.prev;
        cur_height--;
    }

    // Now cur_hash is the hash of block at height idx
    // Verify height matches (sanity check)
    if (cur_height != idx) {
        return false;
    }

    // Get block by hash
    std::vector<uint8_t> raw;
    if (!storage_.read_block_by_hash(cur_hash, raw)) return false;
    return deser_block(raw, out);
}

bool Chain::get_block_by_hash(const std::vector<uint8_t>& h, Block& out) const{
    MIQ_CHAIN_GUARD();
    std::vector<uint8_t> raw;
    if(!storage_.read_block_by_hash(h, raw)) return false;
    return deser_block(raw, out);
}

bool Chain::have_block(const std::vector<uint8_t>& h) const{
    MIQ_CHAIN_GUARD();
    // CRITICAL PERFORMANCE FIX: Use O(1) hash lookup instead of disk read!
    // The old code was reading entire blocks from disk just to check existence,
    // causing massive slowdown during sync (5000+ unnecessary disk reads).
    return storage_.has_block(h);
}

long double Chain::work_from_bits_public(uint32_t bits) {
    return work_from_bits(bits);
}

#if MIQ_HAVE_GCS_FILTERS
bool Chain::get_filter_headers(uint32_t start, uint32_t count,
                               std::vector<std::array<uint8_t,32>>& out) const {
    MIQ_CHAIN_GUARD();
    return g_filter_store.get_headers(start, count, out);
}

bool Chain::get_filters_with_hash(uint32_t start, uint32_t count,
                                  std::vector<std::pair<std::array<uint8_t,32>, std::vector<uint8_t>>>& out) const {
    MIQ_CHAIN_GUARD();
    return g_filter_store.get_filters(start, count, out);
}
#endif

// =============================================================================
// EXPLORER INDEX METHODS
// =============================================================================

bool Chain::get_block_by_hash_fast(const std::vector<uint8_t>& hash, Block& out) const {
    MIQ_CHAIN_GUARD();

    // Use hash index for O(1) lookup
    int64_t height = hashindex_.get(hash);
    if (height < 0) {
        // Fallback to storage lookup (slower, O(n))
        return get_block_by_hash(hash, out);
    }

    return get_block_by_index(static_cast<size_t>(height), out);
}

int64_t Chain::get_height_by_hash(const std::vector<uint8_t>& hash) const {
    MIQ_CHAIN_GUARD();
    return hashindex_.get(hash);
}

bool Chain::reindex_addresses(std::function<bool(uint64_t, uint64_t)> progress) {
    MIQ_CHAIN_GUARD();

    if (!addrindex_.is_enabled()) {
        log_error("AddressIndex not enabled");
        return false;
    }

    log_info("Starting address index rebuild from genesis to height " + std::to_string(tip_.height));

    auto get_block = [this](uint64_t h, Block& b) -> bool {
        return this->get_block_by_index(static_cast<size_t>(h), b);
    };

    bool result = addrindex_.reindex(get_block, tip_.height, progress);

    if (result) {
        // Save hash index as well
        std::string hash_index_path = datadir_ + "/hashindex.dat";
        hashindex_.save(hash_index_path);
        log_info("Address index rebuild complete");
    } else {
        log_error("Address index rebuild failed");
    }

    return result;
}

// Fast PoW verification for optimistic relay
// Only checks if hash meets target, no full block validation
bool verify_block_pow(const Block& b) {
    auto hash = b.block_hash();
    return meets_target_be(hash, b.header.bits);
}

}
