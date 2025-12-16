// src/p2p.cpp  (strict-filter profile, Windows SOCKET-safe)
#include "p2p.h"

// Define global network statistics
namespace p2p_stats {
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_recv{0};
}

#include <cmath>
#include "nat.h"
#include "seeds.h"
#include "log.h"
#include "netmsg.h"
#include "serialize.h"
#include "chain.h"
#include "constants.h"
#include "utxo.h"           // fee calc (UTXOEntry)
#include "base58check.h"    // Base58Check address display (miner logs)
#include "sha256.h"         // dsha256 for compact block hash calculation
#include "stratum/stratum_server.h"  // For stratum block notifications
#include "compact_blocks.h" // BIP152 compact block relay
#include "mempool.h"        // For compact block reconstruction
#include "assume_valid.h"   // Checkpoint verification for fork detection
#include "ibd_state.h"      // Bitcoin Core-aligned IBD state machine
#include "block_download.h" // Bitcoin Core-aligned block download manager

#include <chrono>
#include <deque>
#include <tuple>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <algorithm>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <cstdio>
#include <random>
#include <cstdlib>  // getenv
#include <mutex>
#include <type_traits>
#include <thread>
#include <future>
#include <memory>
#include <cerrno>
#include <cstdint>
#include <climits>
#include <atomic>
#include <cassert>

// ============================================================================
// DEBUG ASSERTIONS FOR BITCOIN CORE-GRADE SCHEDULING INVARIANTS
// ============================================================================
// These assertions verify the level-triggered scheduling invariants:
// 1. When force_mode enables, ALL index-capable peers must be triggered
// 2. When peer disconnects in force_mode, remaining peers must be triggered
// 3. When tip increases in force_mode, all peers must be triggered
//
// Enable with: -DMIQ_DEBUG_SCHEDULING=1
// ============================================================================
#ifndef MIQ_DEBUG_SCHEDULING
#define MIQ_DEBUG_SCHEDULING 0
#endif

#if MIQ_DEBUG_SCHEDULING
#define MIQ_SCHED_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        miq::log_error("[SCHED_ASSERT FAILED] " msg); \
        assert(cond && msg); \
    } \
} while(0)
#define MIQ_SCHED_LOG(msg) miq::log_info("[SCHED_DEBUG] " + std::string(msg))
#else
#define MIQ_SCHED_ASSERT(cond, msg) ((void)0)
#define MIQ_SCHED_LOG(msg) ((void)0)
#endif

// ============================================================================
// TIMING INSTRUMENTATION FOR SCHEDULING LATENCY ANALYSIS
// ============================================================================
// Enable with: -DMIQ_TIMING_INSTRUMENTATION=1
// Tracks key scheduling event latencies to prove <1s warm datadir sync:
// - Force-mode enable → first block request (should be <10ms)
// - Block receive → relay to stratum (should be <50ms)
// - State change → scheduling trigger (should be <1ms)
// ============================================================================
#ifndef MIQ_TIMING_INSTRUMENTATION
#define MIQ_TIMING_INSTRUMENTATION 1  // Enabled by default for performance proof
#endif

#if MIQ_TIMING_INSTRUMENTATION
static std::atomic<int64_t> g_timing_force_mode_enabled_ms{0};
static std::atomic<int64_t> g_timing_last_block_recv_ms{0};
static std::atomic<int64_t> g_timing_last_relay_ms{0};
static std::atomic<int64_t> g_timing_peers_triggered_count{0};

#define MIQ_TIMING_RECORD(var) do { \
    var.store(now_ms(), std::memory_order_relaxed); \
} while(0)

#define MIQ_TIMING_LOG_LATENCY(event, start_var) do { \
    int64_t start = start_var.load(std::memory_order_relaxed); \
    if (start > 0) { \
        int64_t latency = now_ms() - start; \
        miq::log_info("[TIMING] " event " latency: " + std::to_string(latency) + "ms"); \
    } \
} while(0)
#else
#define MIQ_TIMING_RECORD(var) ((void)0)
#define MIQ_TIMING_LOG_LATENCY(event, start_var) ((void)0)
#endif

#ifndef _WIN32
#include <netinet/tcp.h>
#endif

#ifdef _MSC_VER
#include <intrin.h>  // _mm_pause() for MSVC
#endif

#ifndef _WIN32
#include <signal.h>
#endif

// ----- lightweight trace toggle ------------------------------------------------
#ifndef MIQ_DEBUG_TRACE_NAMES
#define MIQ_DEBUG_TRACE_NAMES 0
#endif

// Extern declaration for stratum server (defined in main.cpp)
namespace miq {
    extern std::atomic<StratumServer*> g_stratum_server;
}

#ifndef MIQ_SEED_MODE_ENV
#define MIQ_SEED_MODE_ENV "MIQ_IS_SEED"
#endif
// CRITICAL FIX: Removed MIQ_SEED_MODE_OUTBOUND_TARGET override here
// It was set to 1, overriding constants.h value of 4, causing seed nodes
// to only have 1 outbound connection and stalling when that peer was slow.
// Now using constants.h value (4) for more reliable seed node syncing.
#ifndef MIQ_SEED_MODE_OUTBOUND_TARGET
#define MIQ_SEED_MODE_OUTBOUND_TARGET 4  // Match constants.h
#endif
// CRITICAL: Use FAST fallback - if headers stall for 1s, switch to index sync
// Headers should arrive almost instantly for small chains
#ifndef MIQ_IBD_FALLBACK_AFTER_MS
#define MIQ_IBD_FALLBACK_AFTER_MS (1 * 1000)  // 1 second - aggressive fallback
#endif
// ============================================================================
// PERFORMANCE OPTIMIZATION: P2P Trace disabled by default
// The previous MIQ_P2P_TRACE=1 caused severe lag due to:
// 1. String concatenation overhead on EVERY P2P message
// 2. Mutex contention in the logging system
// 3. I/O blocking on every trace call
// Enable with -DMIQ_P2P_TRACE=1 only for debugging
// ============================================================================
#ifndef MIQ_P2P_TRACE
#define MIQ_P2P_TRACE 0
#endif

// Rate-limited trace: only logs every N calls (for hot paths)
#ifndef MIQ_TRACE_RATE_LIMIT
#define MIQ_TRACE_RATE_LIMIT 1000
#endif

#if MIQ_P2P_TRACE
  // Full tracing enabled - use sparingly, causes severe performance degradation
  #define P2P_TRACE(msg) do { ::miq::log_info(std::string("[TRACE] ") + (msg)); } while(0)
  // Rate-limited trace for hot paths
  #define P2P_TRACE_RATE(msg) do { \
    static std::atomic<uint64_t> _trace_cnt{0}; \
    if (++_trace_cnt % MIQ_TRACE_RATE_LIMIT == 0) { \
      ::miq::log_info(std::string("[TRACE-SAMPLED] ") + (msg)); \
    } \
  } while(0)
#else
  // Tracing disabled - zero overhead (macros expand to nothing)
  #define P2P_TRACE(msg) do {} while(0)
  #define P2P_TRACE_RATE(msg) do {} while(0)
#endif

// Conditional trace that checks a runtime flag (for selective debugging)
#ifndef MIQ_RUNTIME_TRACE
#define MIQ_RUNTIME_TRACE 0
#endif
static std::atomic<bool> g_runtime_trace_enabled{MIQ_RUNTIME_TRACE != 0};
#define P2P_TRACE_IF(cond, msg) do { \
  if ((cond) && g_runtime_trace_enabled.load(std::memory_order_relaxed)) { \
    ::miq::log_info(std::string("[TRACE-COND] ") + (msg)); \
  } \
} while(0)

#if !defined(MIQ_MAYBE_UNUSED)
  #if defined(__GNUC__) || defined(__clang__)
    #define MIQ_MAYBE_UNUSED __attribute__((unused))
  #elif defined(_MSC_VER)
    #define MIQ_MAYBE_UNUSED [[maybe_unused]]
  #else
    #define MIQ_MAYBE_UNUSED
  #endif
#endif

// === Optional persisted addrman =============================================
#if defined(__has_include)
#  if __has_include("addrman.h")
#    include "addrman.h"
#    ifndef MIQ_ENABLE_ADDRMAN
#      define MIQ_ENABLE_ADDRMAN 1
#    endif
#  else
#    ifndef MIQ_ENABLE_ADDRMAN
#      define MIQ_ENABLE_ADDRMAN 0
#    endif
#  endif
#else
#  ifndef MIQ_ENABLE_ADDRMAN
#    define MIQ_ENABLE_ADDRMAN 0
#  endif
#endif

#ifndef MIQ_TRY_HEADERS_ANYWAY
#define MIQ_TRY_HEADERS_ANYWAY 1
#endif

#ifndef MIQ_FEAT_HEADERS_FIRST
#define MIQ_FEAT_HEADERS_FIRST      (1ull<<0)
#endif
#ifndef MIQ_FEAT_TX_RELAY
#define MIQ_FEAT_TX_RELAY           (1ull<<1)
#endif
#ifndef MIQ_FEAT_INDEX_BY_HEIGHT
#define MIQ_FEAT_INDEX_BY_HEIGHT    (1ull<<2)
#endif

// ===== STRICT FILTER PROFILE (central knobs) ================================
#ifndef MIQ_FILTER_PROFILE_STRICT
#define MIQ_FILTER_PROFILE_STRICT 1
#endif

// Handshake & pacing
#if MIQ_FILTER_PROFILE_STRICT
  #ifndef MIQ_P2P_VERACK_TIMEOUT_MS
  #define MIQ_P2P_VERACK_TIMEOUT_MS 15000
  #endif
  #ifndef MIQ_P2P_PING_EVERY_MS
  #define MIQ_P2P_PING_EVERY_MS     20000
  #endif
  #ifndef MIQ_P2P_PONG_TIMEOUT_MS
  #define MIQ_P2P_PONG_TIMEOUT_MS   25000
  #endif
  #ifndef MIQ_PREVERACK_QUEUE_MAX
  #define MIQ_PREVERACK_QUEUE_MAX   6
  #endif
#else
  #ifndef MIQ_P2P_VERACK_TIMEOUT_MS
  #define MIQ_P2P_VERACK_TIMEOUT_MS 10000
  #endif
  #ifndef MIQ_P2P_PING_EVERY_MS
  #define MIQ_P2P_PING_EVERY_MS     30000
  #endif
  #ifndef MIQ_P2P_PONG_TIMEOUT_MS
  #define MIQ_P2P_PONG_TIMEOUT_MS   15000
  #endif
  #ifndef MIQ_PREVERACK_QUEUE_MAX
  #define MIQ_PREVERACK_QUEUE_MAX   8
  #endif
#endif

#ifndef MIQ_ADDRMAN_FILE
#define MIQ_ADDRMAN_FILE "peers2.dat"
#endif
#ifndef MIQ_FEELER_INTERVAL_MS
#define MIQ_FEELER_INTERVAL_MS 60000
#endif
#ifndef MIQ_GROUP_OUTBOUND_MAX
#define MIQ_GROUP_OUTBOUND_MAX 2
#endif

#ifndef MIQ_ENABLE_HEADERS_FIRST
  #ifdef MIQ_ENABLE_HEADERS_FIRST_WIP
    #define MIQ_ENABLE_HEADERS_FIRST MIQ_ENABLE_HEADERS_FIRST_WIP
  #else
    #define MIQ_ENABLE_HEADERS_FIRST 1
  #endif
#endif

#ifdef __has_include
#  if __has_include("constants.h")
#    include "constants.h"
#  endif
#endif

#ifdef MIQ_FALLBACK_MAX_MSG_SIZE
#undef MIQ_FALLBACK_MAX_MSG_SIZE
#endif
#ifndef MAX_MSG_SIZE
#define MIQ_FALLBACK_MAX_MSG_SIZE (64u * 1024u * 1024u)
#else
#define MIQ_FALLBACK_MAX_MSG_SIZE (MAX_MSG_SIZE)
#endif

#ifdef __has_include
#  if __has_include("constants.h")
#    include "constants.h"
#  endif
#endif

#ifndef MIQ_INDEX_PIPELINE
#define MIQ_INDEX_PIPELINE 512  // AGGRESSIVE: Maximum parallel block requests
#endif

// CRITICAL: Header pipeline size - how many header requests in flight
// For small chains, headers should download almost instantly
#ifndef MIQ_HDR_PIPELINE
#define MIQ_HDR_PIPELINE 16  // Allow many header batches in flight
#endif
#ifndef MIQ_SYNC_SEQUENTIAL_DEFAULT
#define MIQ_SYNC_SEQUENTIAL_DEFAULT 0
#endif
#ifndef MIQ_CONTINUATION_BATCH
#define MIQ_CONTINUATION_BATCH 1
#endif
#ifndef MIQ_SEED_DOMAIN
#define MIQ_SEED_DOMAIN "seed.miqrochain.org"
#endif

#ifndef MAX_BLOCK_SIZE
#define MIQ_FALLBACK_MAX_BLOCK_SZ (32u * 1024u * 1024u)
#else
#define MIQ_FALLBACK_MAX_BLOCK_SZ (MAX_BLOCK_SIZE)
#endif

#ifndef MIQ_P2P_MAX_BUFSZ
#define MIQ_P2P_MAX_BUFSZ (MIQ_FALLBACK_MAX_MSG_SIZE + (2u * 1024u * 1024u))
#endif

#ifndef MIQ_MSG_HARD_MAX
#define MIQ_MSG_HARD_MAX (MIQ_FALLBACK_MAX_BLOCK_SZ + (2u * 1024u * 1024u))
#endif
#ifndef MIQ_PARSE_DEADLINE_MS
#define MIQ_PARSE_DEADLINE_MS 45000             /* per-frame parse deadline (ms) */
#endif
#ifndef MIQ_PARSE_STUCK_MS
#define MIQ_PARSE_STUCK_MS (MIQ_PARSE_DEADLINE_MS + 10000) /* extra slack before remediation */
#endif
#ifndef MIQ_RX_TRIM_CHUNK
#define MIQ_RX_TRIM_CHUNK (64u * 1024u)         /* trim in 64 KiB slices when stuck */
#endif
#ifndef MIQ_P2P_BAD_PEER_MAX_STALLS
// CRITICAL FIX: Reduced from 3 to 1 for faster peer switching during IBD
// When a peer stalls (sends headers but no blocks), switch immediately
#define MIQ_P2P_BAD_PEER_MAX_STALLS MIQ_BLOCK_STALL_MAX_COUNT
#endif
// CRITICAL: Fast fallback on empty headers - 3 batches, not 8!
// 8 empty batches was causing massive delays
#ifndef MIQ_HEADERS_EMPTY_LIMIT
#define MIQ_HEADERS_EMPTY_LIMIT 3  // Matches constants.h
#endif

// ULTRA-FAST PROPAGATION: Increased rate limits for sub-second block relay
// Block rate: 10MB/s (was 1MB/s) - allows instant block push to all peers
// Burst: 20MB (was 2MB) - handles block storms without throttling
#ifndef MIQ_RATE_BLOCK_BPS
#define MIQ_RATE_BLOCK_BPS (10u * 1024u * 1024u)
#endif
#ifndef MIQ_RATE_TX_BPS
#define MIQ_RATE_TX_BPS    (1024u * 1024u)
#endif
#ifndef MIQ_RATE_BLOCK_BURST
#define MIQ_RATE_BLOCK_BURST (MIQ_RATE_BLOCK_BPS * 2u)
#endif
#ifndef MIQ_RATE_TX_BURST
#define MIQ_RATE_TX_BURST    (MIQ_RATE_TX_BPS * 2u)
#endif

#if MIQ_FILTER_PROFILE_STRICT
  #ifndef MIQ_ADDR_MAX_BATCH
  #define MIQ_ADDR_MAX_BATCH 800
  #endif
  #ifndef MIQ_ADDR_MIN_INTERVAL_MS
  #define MIQ_ADDR_MIN_INTERVAL_MS 150000
  #endif
  #ifndef MIQ_ADDR_RESPONSE_MAX
  #define MIQ_ADDR_RESPONSE_MAX 150
  #endif
#else
  #ifndef MIQ_ADDR_MAX_BATCH
  #define MIQ_ADDR_MAX_BATCH 1000
  #endif
  #ifndef MIQ_ADDR_MIN_INTERVAL_MS
  #define MIQ_ADDR_MIN_INTERVAL_MS 120000
  #endif
  #ifndef MIQ_ADDR_RESPONSE_MAX
  #define MIQ_ADDR_RESPONSE_MAX 200
  #endif
#endif

#ifndef MIQ_ADDR_SAVE_INTERVAL_MS
#define MIQ_ADDR_SAVE_INTERVAL_MS 60000
#endif
#ifndef MIQ_ADDR_MAX_STORE
#define MIQ_ADDR_MAX_STORE 10000
#endif

#ifndef MIQ_OUTBOUND_TARGET
#define MIQ_OUTBOUND_TARGET 8
#endif
// Dial interval for new connections
// During IBD: aggressive reconnection is needed to maintain sync
// After IBD: more conservative to prevent rapid cycling
#ifndef MIQ_DIAL_INTERVAL_MS
#define MIQ_DIAL_INTERVAL_MS 5000  // 5 seconds - faster during IBD
#endif
#ifndef MIQ_DIAL_INTERVAL_STEADY_MS
#define MIQ_DIAL_INTERVAL_STEADY_MS 15000  // 15 seconds after sync complete
#endif

#ifndef MIQ_ORPHAN_MAX_BYTES
#define MIQ_ORPHAN_MAX_BYTES (32u * 1024u * 1024u)
#endif
#ifndef MIQ_ORPHAN_MAX_COUNT
#define MIQ_ORPHAN_MAX_COUNT (4096u)
#endif

#ifndef MIQ_TX_STORE_MAX
#define MIQ_TX_STORE_MAX 10000
#endif

// =============================================================================
// P2P ANNOUNCE QUEUE CONFIGURATION (FIX: Increased limits for high-volume networks)
// =============================================================================
// The announce queue holds transaction IDs waiting to be broadcast to peers.
// Previous limit of 8192 caused transaction loss during high-volume periods.
// New design: larger queue with priority-based eviction.
#ifndef MIQ_TX_ANNOUNCE_QUEUE_MAX
#define MIQ_TX_ANNOUNCE_QUEUE_MAX 32768  // 32K entries (was 8192)
#endif
#ifndef MIQ_TX_ANNOUNCE_QUEUE_EVICT_BATCH
#define MIQ_TX_ANNOUNCE_QUEUE_EVICT_BATCH 1024  // Evict oldest 1K when full
#endif

#ifndef MIQ_P2P_GETADDR_INTERVAL_MS
#define MIQ_P2P_GETADDR_INTERVAL_MS 120000
#endif
#if MIQ_FILTER_PROFILE_STRICT
  #ifndef MIQ_P2P_NEW_INBOUND_CAP_PER_MIN
  #define MIQ_P2P_NEW_INBOUND_CAP_PER_MIN 200
  #endif
  #ifndef MIQ_P2P_INV_WINDOW_MS
  #define MIQ_P2P_INV_WINDOW_MS 10000
  #endif
  #ifndef MIQ_P2P_INV_WINDOW_CAP
  #define MIQ_P2P_INV_WINDOW_CAP 300
  #endif
  // CRITICAL FIX: Reduced trickle delay from 250ms to 50ms for faster propagation
  #ifndef MIQ_P2P_TRICKLE_MS
  #define MIQ_P2P_TRICKLE_MS 50   // Was 250ms - each 250ms added to propagation time
  #endif
  #ifndef MIQ_P2P_TRICKLE_BATCH
  #define MIQ_P2P_TRICKLE_BATCH 48
  #endif
  #ifndef MIQ_P2P_STALL_RETRY_MS
  #define MIQ_P2P_STALL_RETRY_MS 2000   // CRITICAL FIX: Fast retry (2s) to prevent forks
  #endif
#else
  #ifndef MIQ_P2P_NEW_INBOUND_CAP_PER_MIN
  #define MIQ_P2P_NEW_INBOUND_CAP_PER_MIN 60
  #endif
  #ifndef MIQ_P2P_INV_WINDOW_MS
  #define MIQ_P2P_INV_WINDOW_MS 10000
  #endif
  #ifndef MIQ_P2P_INV_WINDOW_CAP
  #define MIQ_P2P_INV_WINDOW_CAP 500
  #endif
  // CRITICAL FIX: Reduced trickle delay from 200ms to 50ms for faster propagation
  #ifndef MIQ_P2P_TRICKLE_MS
  #define MIQ_P2P_TRICKLE_MS 50   // Was 200ms - each 200ms added to propagation time
  #endif
  #ifndef MIQ_P2P_TRICKLE_BATCH
  #define MIQ_P2P_TRICKLE_BATCH 64
  #endif
#endif

#ifndef MIQ_STRICT_HANDSHAKE
#define MIQ_STRICT_HANDSHAKE 1
#endif

// ----- banscore (compile fix for mixed uses) --------------------------------
#ifndef MIQ_P2P_MAX_BANSCORE
#define MIQ_P2P_MAX_BANSCORE 100
#endif

// ===== Platform networking glue: socket/close/poll types ====================
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #ifdef min
  #undef min
  #endif
  #ifdef max
  #undef max
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <mstcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using Sock   = SOCKET;
  using PollFD = WSAPOLLFD;
  static const short POLL_RD = POLLRDNORM;
  #define MIQ_INVALID_SOCK INVALID_SOCKET
  #define CLOSESOCK(s) closesocket(s)
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <poll.h>
  using Sock   = int;
  using PollFD = pollfd;
  static const short POLL_RD = POLLIN;
  #define MIQ_INVALID_SOCK (-1)
  #define CLOSESOCK(s) close(s)
#endif

std::atomic<bool> g_sync_wants_active{false};

namespace {
    static std::mutex g_peer_stalls_mu;
    static std::unordered_map<std::uintptr_t, int> g_peer_stalls;

    // Per-IP reconnection backoff - adaptive based on sync state
    // During IBD: short backoff to maintain sync progress
    // After IBD: longer backoff to prevent rapid cycling
    static std::mutex g_reconnect_backoff_mu;
    static std::unordered_map<std::string, int64_t> g_reconnect_backoff_until;  // IP -> earliest reconnect time
    static constexpr int64_t RECONNECT_BACKOFF_IBD_MS = 5000;    // 5 second backoff during IBD
    static constexpr int64_t RECONNECT_BACKOFF_STEADY_MS = 30000; // 30 second backoff after sync

    // Single authoritative monotonic ms clock used by rate limiters / stall guards / snapshots.
    static inline int64_t now_ms() {
        using namespace std::chrono;
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

static inline void miq_set_cloexec(Sock s) {
#ifndef _WIN32
    int flags = fcntl(s, F_GETFD, 0);
    if (flags >= 0) (void)fcntl(s, F_SETFD, flags | FD_CLOEXEC);
#else
    (void)s; // no CLOEXEC on winsock
#endif
}

// ============================================================================
// OPTIMIZED SOCKET CONFIGURATION
// ============================================================================
// Performance-critical socket settings for P2P networking:
// - Large recv/send buffers for block transfers (256KB each)
// - TCP_NODELAY to disable Nagle's algorithm for lower latency
// - SO_KEEPALIVE with aggressive timeouts for connection health
// ============================================================================

// Optimal buffer sizes for blockchain P2P (256KB handles large blocks)
#ifndef MIQ_SOCK_RCVBUF
#define MIQ_SOCK_RCVBUF (256 * 1024)
#endif
#ifndef MIQ_SOCK_SNDBUF
#define MIQ_SOCK_SNDBUF (256 * 1024)
#endif

static inline void miq_optimize_socket(Sock s) {
    // Set larger socket buffers for high-throughput block transfers
    int rcvbuf = MIQ_SOCK_RCVBUF;
    int sndbuf = MIQ_SOCK_SNDBUF;
    (void)setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                     reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
    (void)setsockopt(s, SOL_SOCKET, SO_SNDBUF,
                     reinterpret_cast<const char*>(&sndbuf), sizeof(sndbuf));

    // Disable Nagle's algorithm for lower latency
    int nodelay = 1;
    (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

#ifdef SO_REUSEADDR
    int reuse = 1;
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#endif

#ifdef TCP_QUICKACK
    // Enable TCP_QUICKACK for faster ACKs (Linux-specific)
    int quickack = 1;
    (void)setsockopt(s, IPPROTO_TCP, TCP_QUICKACK,
                     reinterpret_cast<const char*>(&quickack), sizeof(quickack));
#endif
}

static inline void miq_set_keepalive(Sock s) {
    int one = 1;
    (void)setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                     reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef _WIN32
    // 60s idle, then 15s interval, 4 probes
    tcp_keepalive ka;
    ka.onoff = 1;
    ka.keepalivetime = 60 * 1000;
    ka.keepaliveinterval = 15 * 1000;
    DWORD ret = 0;
    (void)WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &ret, nullptr, nullptr);
#else
    // Linux: TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT ; macOS/BSD: TCP_KEEPALIVE seconds
    int v;
#  if defined(TCP_KEEPIDLE)
    v = 60;  (void)setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE,  &v, sizeof(v));
#  endif
#  if defined(TCP_KEEPINTVL)
    v = 15;  (void)setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &v, sizeof(v));
#  endif
#  if defined(TCP_KEEPCNT)
    v = 4;   (void)setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT,   &v, sizeof(v));
#  endif
#  if defined(__APPLE__) && defined(TCP_KEEPALIVE)
    v = 60;  (void)setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE, &v, sizeof(v));
#  endif
#endif
}

// ----- IPv6/IPv4 literal + hostname resolver (drop-in, no new files) -------
struct MiqEndpoint {
    sockaddr_storage ss{};
#ifdef _WIN32
    int len = 0;
#else
    socklen_t len = 0;
#endif
};

static inline std::string miq_trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (unsigned char)s[a] <= ' ') ++a;
    while (b > a && (unsigned char)s[b-1] <= ' ') --b;
    return s.substr(a, b - a);
}

// Parse host[:port], [v6]:port, [v6], v6, v4, hostname → (host,port)
static bool miq_parse_host_port(const std::string& in_raw, std::string& host, uint16_t& port_out, uint16_t default_port) {
    std::string in = miq_trim(in_raw);
    host.clear(); port_out = default_port;
    if (in.empty()) return false;

    if (in.front() == '[') { // [v6] or [v6]:port
        auto rb = in.find(']');
        if (rb == std::string::npos) return false;
        host = in.substr(1, rb - 1);
        if (rb + 1 < in.size() && in[rb + 1] == ':') {
            std::string p = in.substr(rb + 2);
            if (!p.empty()) {
                char* end=nullptr;
                unsigned long v = std::strtoul(p.c_str(), &end, 10);
                if (end && *end == '\0' && v <= 65535UL) {
                    port_out = static_cast<uint16_t>(v);
                } /* else: keep default_port */
            }

        }
        return true;
    }

    // More than one ':' => bare IPv6 literal (no port)
    size_t colons = std::count(in.begin(), in.end(), ':');
    if (colons > 1) { host = in; return true; }

    // hostname/v4 or host:port
    auto pos = in.rfind(':');
    if (pos != std::string::npos) {
        host = in.substr(0, pos);
        std::string p = in.substr(pos + 1);
        if (!p.empty()) {
            char* end=nullptr;
            unsigned long v = std::strtoul(p.c_str(), &end, 10);
            if (end && *end == '\0' && v <= 65535UL) {
                port_out = static_cast<uint16_t>(v);
            }
        }
    } else {
        host = in;
    }
    return true;
}

static bool miq_try_numeric_v6(const std::string& h, uint16_t port, MiqEndpoint& out) {
    sockaddr_in6 a6{}; a6.sin6_family = AF_INET6; a6.sin6_port = htons(port);
    if (inet_pton(AF_INET6, h.c_str(), &a6.sin6_addr) == 1) {
        memcpy(&out.ss, &a6, sizeof(a6)); out.len =
#ifdef _WIN32
            (int)
#endif
            sizeof(a6);
        return true;
    }
    return false;
}
static bool miq_try_numeric_v4(const std::string& h, uint16_t port, MiqEndpoint& out) {
    sockaddr_in a4{}; a4.sin_family = AF_INET; a4.sin_port = htons(port);
    if (inet_pton(AF_INET, h.c_str(), &a4.sin_addr) == 1) {
        memcpy(&out.ss, &a4, sizeof(a4)); out.len =
#ifdef _WIN32
            (int)
#endif
            sizeof(a4);
        return true;
    }
    return false;
}

static std::string miq_ntop_sockaddr(const sockaddr_storage& ss) {
    char buf[128] = {0};
    if (ss.ss_family == AF_INET6) {
        const sockaddr_in6* a6 = reinterpret_cast<const sockaddr_in6*>(&ss);
    #ifdef _WIN32
        InetNtopA(AF_INET6, (void*)&a6->sin6_addr, buf, (int)sizeof(buf));
    #else
        inet_ntop(AF_INET6, (void*)&a6->sin6_addr, buf, (socklen_t)sizeof(buf));
    #endif
    } else if (ss.ss_family == AF_INET) {
        const sockaddr_in* a4 = reinterpret_cast<const sockaddr_in*>(&ss);
    #ifdef _WIN32
        InetNtopA(AF_INET, (void*)&a4->sin_addr, buf, (int)sizeof(buf));
    #else
        inet_ntop(AF_INET, (void*)&a4->sin_addr, buf, (socklen_t)sizeof(buf));
    #endif
    }
    return std::string(buf[0] ? buf : "unknown");
}

static bool miq_resolve_endpoints_from_string(const std::string& input, uint16_t default_port,
                                              std::vector<MiqEndpoint>& out_eps)
{
    out_eps.clear();
    std::string host; uint16_t port = default_port;
    if (!miq_parse_host_port(input, host, port, default_port)) return false;

    // Fast-path numeric literals
    MiqEndpoint ep{};
    if (miq_try_numeric_v6(host, port, ep)) { out_eps.push_back(ep); return true; }
    if (miq_try_numeric_v4(host, port, ep)) { out_eps.push_back(ep); return true; }

#ifdef _WIN32
    ADDRINFOA hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_ADDRCONFIG;
    PADDRINFOA res = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) return false;
    for (auto p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET6 && p->ai_addrlen >= (int)sizeof(sockaddr_in6)) {
            sockaddr_in6 a6{}; memcpy(&a6, p->ai_addr, sizeof(a6)); a6.sin6_port = htons(port);
            MiqEndpoint ne{}; memcpy(&ne.ss, &a6, sizeof(a6)); ne.len = (int)sizeof(a6); out_eps.push_back(ne);
        } else if (p->ai_family == AF_INET && p->ai_addrlen >= (int)sizeof(sockaddr_in)) {
            sockaddr_in a4{}; memcpy(&a4, p->ai_addr, sizeof(a4)); a4.sin_port = htons(port);
            MiqEndpoint ne{}; memcpy(&ne.ss, &a4, sizeof(a4)); ne.len = (int)sizeof(a4); out_eps.push_back(ne);
        }
    }
    freeaddrinfo(res);
#else
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET6 && p->ai_addrlen >= (socklen_t)sizeof(sockaddr_in6)) {
            sockaddr_in6 a6{}; memcpy(&a6, p->ai_addr, sizeof(a6)); a6.sin6_port = htons(port);
            MiqEndpoint ne{}; memcpy(&ne.ss, &a6, sizeof(a6)); ne.len = (socklen_t)sizeof(a6); out_eps.push_back(ne);
        } else if (p->ai_family == AF_INET && p->ai_addrlen >= (socklen_t)sizeof(sockaddr_in)) {
            sockaddr_in a4{}; memcpy(&a4, p->ai_addr, sizeof(a4)); a4.sin_port = htons(port);
            MiqEndpoint ne{}; memcpy(&ne.ss, &a4, sizeof(a4)); ne.len = (socklen_t)sizeof(a4); out_eps.push_back(ne);
        }
    }
    freeaddrinfo(res);
#endif

    return !out_eps.empty();
}

// p2p.h uses int for PeerState::sock and for map keys; we cast to Sock
// where needed on Windows to avoid narrowing and keep WSAPOLLFD happy.

namespace {
// === lightweight handshake/size gate ========================================
using Clock = std::chrono::steady_clock;

struct PeerGate {
    bool sent_verack{false};
    bool got_version{false};
    bool got_verack{false};
    // Timestamp when TCP connect succeeds (steady clock, ms)
    int64_t t_conn_ms{0};
    bool is_loopback{false};   // mark if this fd belongs to 127.0.0.1 peer
    int  banscore{0};
    size_t rx_bytes{0};
    Clock::time_point t_conn{Clock::now()};
    Clock::time_point t_last{Clock::now()};
    int64_t hs_last_ms{0};
};

// Keyed by per-connection socket fd/handle
static std::unordered_map<Sock, PeerGate> g_gate;

// Tunables (local to this TU)
static const size_t MAX_MSG_BYTES = 2 * 1024 * 1024; // 2 MiB per message (soft)
static const int    MAX_BANSCORE  = MIQ_P2P_MAX_BANSCORE;
static const int    HANDSHAKE_MS  = MIQ_P2P_VERACK_TIMEOUT_MS;

// IBD phase logging flags
static bool g_logged_headers_started = false;
static bool g_logged_headers_done    = false;
static int64_t g_ibd_headers_started_ms = 0;

// Global listen port for outbound dials (set in start())
static uint16_t g_listen_port = 0;

// Stall/progress trackers (atomic for thread safety)
static std::atomic<int64_t> g_last_progress_ms{0};
static std::atomic<size_t>  g_last_progress_height{0};
static std::atomic<int64_t> g_next_stall_probe_ms{0};

// Simple trickle queues per-peer (sock -> txid queue and last flush ms)
// CRITICAL FIX: Added mutex to protect trickle queue from concurrent access
static std::mutex g_trickle_mu;
static std::unordered_map<Sock, std::vector<std::vector<uint8_t>>> g_trickle_q;
static std::unordered_map<Sock, int64_t> g_trickle_last_ms;

static std::unordered_map<Sock,int64_t> g_last_hdr_req_ms;

// CRITICAL FIX: Periodic header polling after IBD completes
// This ensures nodes discover new blocks mined by peers during/after sync
static std::atomic<int64_t> g_last_header_poll_ms{0};
static constexpr int64_t MIQ_HEADER_POLL_INTERVAL_MS = 10000; // Poll every 10 seconds for faster block discovery

// Per-peer sliding-window message counters
static std::unordered_map<Sock,
    std::unordered_map<std::string, std::pair<int64_t,uint32_t>>> g_cmd_rl;

// Per-socket parse deadlines for partial frames
static std::unordered_map<uint64_t,int64_t> g_last_idx_probe_ms;
static std::unordered_map<uint64_t,int64_t> g_last_wait_log_ms;
static std::unordered_map<Sock, int64_t> g_rx_started_ms;
namespace { static inline void schedule_close(Sock s); }
static inline void rx_track_start(Sock fd){
    if (g_rx_started_ms.find(fd)==g_rx_started_ms.end())
        g_rx_started_ms[fd] = [](){
            using namespace std::chrono;
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        }();
}
static inline void rx_clear_start(Sock fd){
    g_rx_started_ms.erase(fd);
}

static inline int64_t now_ms();

static inline void enforce_rx_parse_deadline(miq::PeerState& ps, Sock s){
    auto it = g_rx_started_ms.find(s);
    if (it == g_rx_started_ms.end()) return;
    const int64_t t0 = it->second;
    const int64_t now = now_ms();
    if (now - t0 < (int64_t)MIQ_PARSE_STUCK_MS) return;

    // We are stuck parsing this buffer for too long.
    if (!ps.rx.empty()) {
        if (!ps.verack_ok || !g_logged_headers_done) {
            // During handshake/IBD be lenient: trim a chunk from the front, keep session.
            const size_t trim = std::min<size_t>(ps.rx.size(), (size_t)MIQ_RX_TRIM_CHUNK);
            if (trim > 0) {
                ps.rx.erase(ps.rx.begin(), ps.rx.begin() + (ptrdiff_t)trim);
                rx_track_start(s); // restart the timer from now
                miq::log_warn("P2P: trimmed stuck RX buffer during sync from " + ps.ip +
                              " bytes=" + std::to_string(trim) +
                              " remain=" + std::to_string(ps.rx.size()));
                return;
            }
        }
        // Steady-state or nothing to trim: count a stall and potentially drop.
        std::lock_guard<std::mutex> lk(g_peer_stalls_mu);
        int &st = g_peer_stalls[s];
        st++;
        // During IBD, never drop for parse stalls; trim and forgive.
        const bool syncing = ps.syncing || !g_logged_headers_done;
        if (syncing && st >= MIQ_P2P_BAD_PEER_MAX_STALLS) {
            miq::log_warn("P2P: parse stall during IBD from " + ps.ip + " — trimming & forgiving (no drop)");
            // Aggressive trim to shake loose a bad frame; keep the session alive.
            if (!ps.rx.empty()) {
                const size_t trim = std::min<size_t>(ps.rx.size(), (size_t)MIQ_RX_TRIM_CHUNK);
                ps.rx.erase(ps.rx.begin(), ps.rx.begin() + (ptrdiff_t)trim);
            }
            st = 0;               // reset stall counter since we forgave this
            rx_track_start(s);    // restart deadline timer
            return;
        }
        rx_clear_start(s);
        if (st >= MIQ_P2P_BAD_PEER_MAX_STALLS) {
            miq::log_warn("P2P: closing stalled peer (parse deadline) " + ps.ip);
            schedule_close(s);
        } else {
            miq::log_warn("P2P: parse deadline hit (stall " + std::to_string(st) + "/"
                          + std::to_string(MIQ_P2P_BAD_PEER_MAX_STALLS) + ") from " + ps.ip);
        }
    }
}

namespace {
  static inline void schedule_close(Sock s);
}
// --- small Windows-safe send/recv helpers -----------------------------------
// Hardened: loop on partial sends
static inline bool miq_send(Sock s, const uint8_t* data, size_t len) {
    if (!data || len == 0) return true;
    // WINDOWS FIX: Enable TCP_NODELAY on ALL platforms including Windows
    // This was only being set on non-Windows, causing send delays on Windows nodes
    {
        int flag = 1;
#ifdef _WIN32
        (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&flag, sizeof(flag));
#else
        (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#endif
    }
    size_t sent = 0;
    // WINDOWS FIX: Increased from 200ms to 500ms for Windows
    // Windows antivirus scanning, Defender, and higher syscall overhead means
    // 200ms is often not enough - peers timeout prematurely on Windows seeds
    // 500ms is still fast enough for sub-second propagation (most sends complete in <50ms)
#ifdef _WIN32
    const int kMaxSpinMs = 500;   // Windows: more generous timeout
#else
    const int kMaxSpinMs = 200;   // Linux/macOS: keep fast timeout
#endif
    int waited_ms = 0;



    while (sent < len) {
#ifdef _WIN32
        int n = send(s, reinterpret_cast<const char*>(data + sent), (int)std::min<size_t>(INT32_MAX, len - sent), 0);
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEWOULDBLOCK) {
                // WINDOWS FIX: Use 15ms poll timeout to align with Windows timer granularity
                // Using 10ms results in actual ~15ms sleeps, causing timing drift
                WSAPOLLFD pfd{}; pfd.fd = s; pfd.events = POLLWRNORM; pfd.revents = 0;
                int rc = WSAPoll(&pfd, 1, 15);
                if (rc <= 0 && (waited_ms += 15) >= kMaxSpinMs) return false;
                continue;
            }
            // CRITICAL FIX: Rate-limit error logging to prevent log flooding
            // WSAE=10053 (connection aborted) and 10054 (connection reset) are common
            // and happen naturally when peers disconnect - don't spam logs
            static std::atomic<int64_t> last_wsae_log_ms{0};
            static std::atomic<int> wsae_suppressed_count{0};
            int64_t tnow = now_ms();
            if (tnow - last_wsae_log_ms.load(std::memory_order_relaxed) > 10000) { // Log at most every 10 sec
                int suppressed = wsae_suppressed_count.exchange(0, std::memory_order_relaxed);
                if (suppressed > 0) {
                    miq::log_warn("P2P: send() failed WSAE=" + std::to_string(e) +
                        " (suppressed " + std::to_string(suppressed) + " similar errors)");
                } else {
                    miq::log_warn("P2P: send() failed WSAE=" + std::to_string(e));
                }
                last_wsae_log_ms.store(tnow, std::memory_order_relaxed);
            } else {
                wsae_suppressed_count.fetch_add(1, std::memory_order_relaxed);
            }
            return false;
        }
        if (n == 0) return false;
        sent += (size_t)n;
#else
        ssize_t n = ::send(s, data + sent, (len - sent), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd{ s, POLLOUT, 0 };
                int rc = ::poll(&pfd, 1, 10);
                if (rc <= 0 && (waited_ms += 10) >= kMaxSpinMs) return false;
                continue;
            }
            miq::log_warn("P2P: send() failed");
            return false;
        }
        if (n == 0) return false;
        sent += (size_t)n;
#endif
    }

    // Track total bytes sent for network stats
    p2p_stats::bytes_sent.fetch_add(len, std::memory_order_relaxed);
    return true;
}
static inline bool miq_send(Sock s, const std::vector<uint8_t>& v){
    if (v.empty()) return true;
    return miq_send(s, v.data(), v.size());
}

static inline bool send_or_close(Sock s, const std::vector<uint8_t>& v){
  if (miq_send(s, v)) {
    return true;
  }
  schedule_close(s);
  return false;
}

// =============================================================================
// PARALLEL BLOCK BROADCAST - TRUE CONCURRENT SENDS TO ALL PEERS
// This is critical for sub-1-second propagation: sends happen simultaneously
// instead of sequentially. With 20 peers, this reduces latency from 20*100ms
// to just ~100ms (the slowest single peer).
//
// THREAD SAFETY:
// - Message is copied via shared_ptr to ensure lifetime extends beyond async tasks
// - schedule_close() is protected by g_force_close_mu mutex
// - All futures are waited on before return to prevent dangling references
// =============================================================================
static inline int parallel_send_to_peers(
    const std::vector<Sock>& sockets,
    const std::vector<uint8_t>& message,
    int max_parallel = 32)  // Limit concurrent threads to avoid resource exhaustion
{
    if (sockets.empty() || message.empty()) return 0;

    // CRITICAL: Copy message to shared_ptr to extend lifetime beyond this function
    // This prevents use-after-free when async tasks outlive the caller's local variable
    auto msg_ptr = std::make_shared<std::vector<uint8_t>>(message);

    // For small peer counts, use std::async for true parallelism
    // For large peer counts, batch to avoid thread explosion
    const size_t batch_size = std::min<size_t>(sockets.size(), (size_t)max_parallel);

    std::vector<std::future<bool>> futures;
    futures.reserve(batch_size);

    int total_sent = 0;
    size_t idx = 0;

    // Track start time for cumulative timeout
    // WINDOWS FIX: Increased timeout for Windows due to higher syscall overhead
    // Windows antivirus, Defender, and WSAPoll overhead requires more time
    const auto batch_start = std::chrono::steady_clock::now();
#ifdef _WIN32
    // Windows: 250ms allows for antivirus delays while still being fast
    const auto max_total_time = std::chrono::milliseconds(250);
#else
    // Linux/macOS: Keep aggressive 100ms for fast propagation
    const auto max_total_time = std::chrono::milliseconds(100);
#endif

    while (idx < sockets.size()) {
        futures.clear();

        // Check if we've exceeded total time budget
        auto elapsed = std::chrono::steady_clock::now() - batch_start;
        if (elapsed > max_total_time) {
            // PROPAGATION FIX: Time's up - but DON'T close connections!
            // INVARIANT P3 VIOLATION: "Block relay MUST NOT be blocked by peer scoring"
            // Closing slow peers during broadcast is a form of backpressure that
            // prevents block relay to those peers entirely.
            //
            // Instead, just skip remaining peers for this broadcast.
            // They will receive the block through:
            // 1. Normal inv/getdata cycle
            // 2. Subsequent relay from other peers
            // 3. Next broadcast attempt
            //
            // OLD BUG: schedule_close(sockets[i]) - disconnected slow peers
            // FIX: Just break - let them stay connected
            break;
        }

        // Launch parallel sends for this batch
        size_t batch_end = std::min(idx + batch_size, sockets.size());
        for (size_t i = idx; i < batch_end; ++i) {
            Sock s = sockets[i];
            // CRITICAL: Capture msg_ptr BY VALUE (shared_ptr copy) - extends lifetime!
            futures.push_back(std::async(std::launch::async, [s, msg_ptr]() {
                return miq_send(s, *msg_ptr);
            }));
        }

        // Calculate remaining time for this batch
        elapsed = std::chrono::steady_clock::now() - batch_start;
        auto remaining = max_total_time - elapsed;
        if (remaining < std::chrono::milliseconds(50)) {
            remaining = std::chrono::milliseconds(50);  // Minimum 50ms per batch
        }

        // Wait for all sends in this batch with remaining time budget
        auto per_future_timeout = remaining / futures.size();
        if (per_future_timeout < std::chrono::milliseconds(50)) {
            per_future_timeout = std::chrono::milliseconds(50);
        }

        for (size_t i = 0; i < futures.size(); ++i) {
            try {
                // Wait with timeout - don't let slow peers delay everything
                auto status = futures[i].wait_for(per_future_timeout);
                if (status == std::future_status::ready) {
                    if (futures[i].get()) {
                        total_sent++;
                    } else {
                        // Send failed - schedule close (thread-safe)
                        schedule_close(sockets[idx + i]);
                    }
                } else {
                    // Timeout - peer too slow
                    // PROPAGATION FIX: DON'T close slow peers!
                    // INVARIANT P3: "Block relay MUST NOT be blocked by peer scoring"
                    // The peer is just slow - it will receive blocks through normal
                    // inv/getdata cycle. Closing disconnects them from the network.
                    //
                    // OLD BUG: schedule_close(sockets[idx + i]) - disconnected slow peers
                    // FIX: Just skip - the async task will complete, msg_ptr keeps message alive
                    //
                    // Note: The send may still succeed eventually - we just won't count it
                }
            } catch (...) {
                // Exception in async task - close socket
                schedule_close(sockets[idx + i]);
            }
        }

        idx = batch_end;
    }

    // CRITICAL: All futures MUST be waited on before we return
    // The shared_ptr ensures message stays alive, but we want clean shutdown
    // futures.clear() will call destructors which wait for completion
    futures.clear();

    return total_sent;
}

// Return values:
//   >0 = bytes read
//   0  = EOF (peer closed connection gracefully)
//  -1  = error
//  -2  = would block (EAGAIN/EWOULDBLOCK) - no data available yet
static inline int miq_recv(Sock s, uint8_t* buf, size_t bufsz) {
#ifdef _WIN32
    int n = recv(s, reinterpret_cast<char*>(buf), (int)bufsz, 0);
    if (n == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK) return -2;  // would block, not an error
        // CRITICAL FIX: Rate-limit recv error logging to prevent log flooding
        // Connection errors are common and expected - don't spam logs
        static std::atomic<int64_t> last_recv_log_ms{0};
        static std::atomic<int> recv_suppressed_count{0};
        int64_t tnow = now_ms();
        if (tnow - last_recv_log_ms.load(std::memory_order_relaxed) > 10000) { // Log at most every 10 sec
            int suppressed = recv_suppressed_count.exchange(0, std::memory_order_relaxed);
            if (suppressed > 0) {
                miq::log_warn("P2P: recv() failed WSAE=" + std::to_string(e) +
                    " (suppressed " + std::to_string(suppressed) + " similar errors)");
            } else {
                miq::log_warn("P2P: recv() failed WSAE=" + std::to_string(e));
            }
            last_recv_log_ms.store(tnow, std::memory_order_relaxed);
        } else {
            recv_suppressed_count.fetch_add(1, std::memory_order_relaxed);
        }
        return -1;
    }
    return n;  // 0 = EOF, >0 = data
#else
    for (;;) {
        ssize_t n = ::recv(s, buf, bufsz, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -2;  // would block, not an error
            return -1;  // actual error
        }
        return (int)n;  // 0 = EOF (peer closed), >0 = data
    }
#endif
}

// --- helper to send gettx using existing encode_msg path ----------
static inline void send_gettx(Sock sock, const std::vector<uint8_t>& txid) {
    if (txid.size() != 32) return;
    auto m = miq::encode_msg("gettx", txid);
    (void)send_or_close(sock, m);
}

static inline uint64_t env_u64(const char* name, uint64_t defv){
    const char* v = std::getenv(name);
    if(!v || !*v) return defv;
    char* end=nullptr; unsigned long long x = std::strtoull(v, &end, 10);
    if(end==v) return defv;
    return (uint64_t)x;
}

// ---- Fee filter state (miqron/kB) ------------------------------------------
static inline uint64_t local_min_relay_kb(){
    static uint64_t v = env_u64("MIQ_MIN_RELAY_FEE_RATE", 1000ULL);
    return v;
}
static std::unordered_map<Sock, uint64_t> g_peer_minrelay_kb;
static std::unordered_map<Sock, int64_t>  g_peer_last_ff_ms;

static inline void set_peer_feefilter(Sock fd, uint64_t kb){
    g_peer_minrelay_kb[fd] = kb;
    g_peer_last_ff_ms[fd]  = std::chrono::duration_cast<std::chrono::milliseconds>(
                                Clock::now().time_since_epoch()).count();
}
static inline uint64_t peer_feefilter_kb(Sock fd){
    auto it = g_peer_minrelay_kb.find(fd);
    return (it==g_peer_minrelay_kb.end()) ? 0ULL : it->second;
}

#ifndef MIQ_FEEFILTER_INTERVAL_MS
#define MIQ_FEEFILTER_INTERVAL_MS (10 * 60 * 1000)
#endif
static inline void maybe_send_feefilter(miq::PeerState& ps){
    if (!ps.verack_ok) return;
    const int64_t now = now_ms();
    const int64_t last = (g_peer_last_ff_ms.count((Sock)ps.sock) ? g_peer_last_ff_ms[(Sock)ps.sock] : 0);
    if (last != 0 && (now - last) < (int64_t)MIQ_FEEFILTER_INTERVAL_MS) return;
    const uint64_t mrf = local_min_relay_kb();
    std::vector<uint8_t> pl(8);
    for (int i=0;i<8;i++) pl[i] = (uint8_t)((mrf >> (8*i)) & 0xFF);
    auto msg = miq::encode_msg("feefilter", pl);
    if (send_or_close(ps.sock, msg)) {
        // CRITICAL FIX: Only update the timestamp, NOT the peer's feefilter value!
        // The peer's feefilter should only be set when we RECEIVE their feefilter message.
        // Previously this was setting our own value as the peer's, which was incorrect.
        g_peer_last_ff_ms[(Sock)ps.sock] = now;
    }
}

// ---- DNS seed backoff (per-host) -------------------------------------------
static std::unordered_map<std::string, std::pair<int64_t,int64_t>> g_seed_backoff;

// ---- Header zero-progress tracker (socket -> consecutive empty batches) ----
static std::unordered_map<Sock,int> g_zero_hdr_batches;
static std::unordered_map<Sock,bool> g_hdr_flip;

static miq::Chain* g_chain_ptr = nullptr;

static std::unordered_map<Sock,int64_t> g_last_hdr_ok_ms; // time of last accepted headers

static std::unordered_map<Sock,int64_t> g_peer_last_fetch_ms;    // last time peer sent us headers/blocks
static std::unordered_map<Sock,int64_t> g_peer_last_request_ms;  // last time peer requested headers/blocks from us
static inline bool ibd_or_fetch_active(const miq::PeerState& ps, int64_t nowms) {
    const Sock s = (Sock)ps.sock;
    const bool inflight =
        ps.syncing ||
        !ps.inflight_blocks.empty() ||
        ps.inflight_index > 0 ||
        ps.inflight_hdr_batches > 0 ||
        ps.sent_getheaders;
    // CRITICAL FIX: Use find() instead of count()/at() pattern to avoid TOCTOU race
    // The old pattern could crash if another thread erased the key between count() and at()
    auto it_f = g_peer_last_fetch_ms.find(s);
    auto it_r = g_peer_last_request_ms.find(s);
    const int64_t f = (it_f != g_peer_last_fetch_ms.end()) ? it_f->second : 0;
    const int64_t r = (it_r != g_peer_last_request_ms.end()) ? it_r->second : 0;
    const int64_t kWindow = 5 * 60 * 1000; // 5 minutes grace
    // Also grant grace while global headers IBD hasn't finished.
    return inflight || (f && (nowms - f) < kWindow) || (r && (nowms - r) < kWindow)
           || !g_logged_headers_done || g_sync_wants_active.load();
}

static bool g_seed_mode = false;
static std::atomic<bool> g_sequential_sync{(MIQ_SYNC_SEQUENTIAL_DEFAULT != 0)};
static inline int miq_outbound_target(){
    return g_seed_mode ? MIQ_SEED_MODE_OUTBOUND_TARGET : MIQ_OUTBOUND_TARGET;
}
// Adaptive dial interval - faster during IBD for quick recovery
static inline int64_t miq_dial_interval_ms() {
    return g_logged_headers_done ? MIQ_DIAL_INTERVAL_STEADY_MS : MIQ_DIAL_INTERVAL_MS;
}

static inline bool hostname_is_seed(){
    const char* env_host = std::getenv("MIQ_PUBLIC_HOSTNAME");
    if (env_host && *env_host) return std::string(env_host) == MIQ_SEED_DOMAIN;
    return false;
}

// NOTE: g_global_inflight_blocks is now defined in the optimized inflight tracking section below

static std::unordered_map<Sock, bool> g_peer_index_capable; // default true; false => headers-only

static int g_headers_tip_confirmed = 0;   // consecutive confirmations of "at tip"

// Flag to trigger immediate block sync when headers complete
static std::atomic<bool> g_headers_just_done{false};

// Global max peer tip - updated whenever we learn of higher tips
static std::atomic<uint64_t> g_max_known_peer_tip{0};

// FORCE-COMPLETION MODE: When we're ≤16 blocks from tip, enable aggressive completion
// In this mode: allow duplicate requests, relax limits, ignore peer penalties
static std::atomic<bool> g_force_completion_mode{false};
constexpr uint64_t FORCE_COMPLETION_THRESHOLD = 16;  // Enable when ≤16 blocks behind

static inline void maybe_mark_headers_done(bool at_tip) {
    if (g_logged_headers_done) return;
    if (!g_logged_headers_started) {
        g_headers_tip_confirmed = 0;
        return;
    }

    // CRITICAL FIX: Don't mark headers done just because ONE peer sent empty headers!
    // We must verify our header height is >= the maximum known peer tip.
    // Otherwise we'll prematurely think we're synced and show wrong progress.
    if (at_tip) {
        // Double-check: is our header height actually >= max peer tip?
        uint64_t hdr_height = g_chain_ptr ? g_chain_ptr->best_header_height() : 0;
        uint64_t max_peer_tip = g_max_known_peer_tip.load();

        // Only consider headers done if we actually have headers up to max peer tip
        // (or very close - allow 10 block margin for timing)
        if (max_peer_tip > 0 && hdr_height + 10 < max_peer_tip) {
            // NOT at real tip - peers know of higher chain!
            // Don't increment confirmation counter, and reset to avoid false positives
            g_headers_tip_confirmed = 0;
            return;
        }

        if (++g_headers_tip_confirmed >= 3) {
            g_logged_headers_done = true;
            g_headers_just_done.store(true);  // Signal to start block downloads NOW
            // IBD PERF: Set header height for signature skip optimization
            miq::set_best_header_height(hdr_height);

            // State machine transition: HEADERS → BLOCKS
            // Bitcoin Core principle: once headers complete, NEVER restart headers phase
            miq::ibd::IBDState::instance().set_header_height(hdr_height);
            miq::ibd::IBDState::instance().transition_to(miq::ibd::SyncState::BLOCKS);

            miq::log_info("[IBD] headers phase COMPLETE (height=" + std::to_string(hdr_height) +
                         ", max_peer_tip=" + std::to_string(max_peer_tip) +
                         ") — IMMEDIATELY starting block downloads!");
        }
    } else {
        // Not at tip - reset confirmation counter
        g_headers_tip_confirmed = 0;
    }
}

static bool g_sync_green_logged = false;

// Thread-safe global inflight tracking at file scope
// (separate from the more sophisticated SpinLock-based system in the anonymous namespace below)
static std::mutex g_file_scope_inflight_mu;
static std::unordered_set<std::string> g_file_scope_inflight_blocks;

[[maybe_unused]] static bool is_block_inflight(const std::string& hash) {
    std::lock_guard<std::mutex> lk(g_file_scope_inflight_mu);
    return g_file_scope_inflight_blocks.find(hash) != g_file_scope_inflight_blocks.end();
}

static void add_file_scope_inflight(const std::string& hash) {
    std::lock_guard<std::mutex> lk(g_file_scope_inflight_mu);
    g_file_scope_inflight_blocks.insert(hash);
}

static void remove_file_scope_inflight(const std::string& hash) {
    std::lock_guard<std::mutex> lk(g_file_scope_inflight_mu);
    g_file_scope_inflight_blocks.erase(hash);
}

static std::unordered_map<Sock,int> g_index_timeouts;

// ============================================================================
// IP REPUTATION HISTORY - Persists across reconnections
// ============================================================================
// Problem: Bad peers disconnect and reconnect with fresh health=100%, wasting slots.
// Solution: Track per-IP history that survives reconnections.
struct IPReputationHistory {
    int64_t  total_blocks_delivered{0};    // Lifetime blocks from this IP
    int64_t  total_blocks_failed{0};       // Lifetime failures from this IP
    int64_t  total_connections{0};         // How many times this IP connected
    int64_t  last_disconnect_ms{0};        // When they last disconnected
    double   last_reputation{1.0};         // Last known reputation score
    bool     proven_good{false};           // Has this IP ever delivered >100 blocks?
};
static std::unordered_map<std::string, IPReputationHistory> g_ip_history;
static std::mutex g_ip_history_mutex;

// Get starting batch size for an IP based on history
static inline uint32_t get_ip_starting_batch(const std::string& ip) {
    std::lock_guard<std::mutex> lk(g_ip_history_mutex);
    auto it = g_ip_history.find(ip);
    if (it == g_ip_history.end()) {
        // Never seen this IP before - start VERY conservatively
        return 32;  // Start with small batch
    }
    const auto& hist = it->second;
    if (hist.proven_good) {
        // This IP has delivered >100 blocks in the past - trust it
        return 128;
    }
    if (hist.total_blocks_delivered == 0 && hist.total_connections > 0) {
        // Has connected before but NEVER delivered anything - very suspicious
        return 16;
    }
    // Has some history - scale based on past success rate
    int64_t total = hist.total_blocks_delivered + hist.total_blocks_failed;
    if (total == 0) return 32;
    double success_rate = (double)hist.total_blocks_delivered / (double)total;
    if (success_rate > 0.9) return 128;
    if (success_rate > 0.7) return 64;
    if (success_rate > 0.5) return 32;
    return 16;  // Poor history
}

// Record that a peer from this IP is connecting
static inline void record_ip_connect(const std::string& ip) {
    std::lock_guard<std::mutex> lk(g_ip_history_mutex);
    g_ip_history[ip].total_connections++;
}

// Record block delivery success/failure for IP history
static inline void record_ip_block_result(const std::string& ip, bool success) {
    std::lock_guard<std::mutex> lk(g_ip_history_mutex);
    auto& hist = g_ip_history[ip];
    if (success) {
        hist.total_blocks_delivered++;
        if (hist.total_blocks_delivered >= 100) {
            hist.proven_good = true;
        }
    } else {
        hist.total_blocks_failed++;
    }
}

// Record peer disconnect and save final reputation
static inline void record_ip_disconnect(const std::string& ip, double final_reputation) {
    std::lock_guard<std::mutex> lk(g_ip_history_mutex);
    auto& hist = g_ip_history[ip];
    hist.last_disconnect_ms = now_ms();
    hist.last_reputation = final_reputation;
}

static inline void mark_index_timeout(Sock s){
    // CRITICAL FIX: Only increment the counter here, don't set g_peer_index_capable!
    // The demotion should happen ONLY in the dedicated demotion loop (line ~5305)
    // where ALL state (syncing, inflight_index, etc.) is updated atomically.
    // Setting g_peer_index_capable here caused race conditions where:
    //   - g_peer_index_capable = false (set here)
    //   - syncing = true (not updated yet)
    //   - has_active_index_sync returns true but no requests sent!
    g_index_timeouts[s]++;
}

// ---- NEW: pre-verack safe allow-list & counters ----------------------------
static std::unordered_map<Sock,int> g_preverack_counts;  // socket -> early safe msg count
static inline bool miq_safe_preverack_cmd(const std::string& cmd) {
    static const char* k[] = {
        "verack","ping","pong","getheaders","headers",
        "addr","getaddr","invb","getb","getbi","invtx","gettx","tx","feefilter"
    };
    for (auto* s : k) if (cmd == s) return true;
    return false;
}

static inline bool env_truthy(const char* name){
    const char* v = std::getenv(name); return v && *v && (v[0]=='1'||v[0]=='y'||v[0]=='Y'||v[0]=='t'||v[0]=='T');
}

static inline int64_t wall_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

#ifndef MIQ_CONNECT_TIMEOUT_MS
#define MIQ_CONNECT_TIMEOUT_MS 5000
#endif

#if 0
static inline int64_t now_ms() {
    using namespace std::chrono;
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
#endif

namespace {
  static std::unordered_set<Sock> g_force_close;
  static std::mutex g_force_close_mu;  // CRITICAL: Thread-safe access for parallel broadcast
  static inline void schedule_close(Sock s){
    if (s!=MIQ_INVALID_SOCK) {
      std::lock_guard<std::mutex> lk(g_force_close_mu);
      g_force_close.insert(s);
    }
  }
  static std::unordered_set<Sock> g_outbounds;
  static inline size_t outbound_count(){ return g_outbounds.size(); }
}


// ============================================================================
// OPTIMIZED INFLIGHT TRACKING SYSTEM
// ============================================================================
// Thread-safe tracking of in-flight block and index requests.
// Uses a lightweight spinlock for minimal contention in the P2P hot path.
// ============================================================================

namespace {

// Lightweight spinlock for inflight data (lower overhead than std::mutex)
class SpinLock {
    std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
public:
    void lock() noexcept {
        while (flag_.test_and_set(std::memory_order_acquire)) {
            // Spin with pause instruction hint for better CPU efficiency
            #if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
                _mm_pause();
            #elif defined(__x86_64__) || defined(__i386__)
                __builtin_ia32_pause();
            #elif defined(_MSC_VER) && defined(_M_ARM64)
                __yield();
            #elif defined(__aarch64__)
                __asm__ volatile("yield");
            #else
                std::this_thread::yield();
            #endif
        }
    }
    void unlock() noexcept {
        flag_.clear(std::memory_order_release);
    }
};

// Global spinlock protecting all inflight state
static SpinLock g_inflight_lock;

// Track inflight block request timestamps without touching PeerState layout
static std::unordered_map<Sock, std::unordered_map<std::string,int64_t>> g_inflight_block_ts;

// Global set of all requested block hashes (across all peers)
static std::unordered_set<std::string> g_global_inflight_blocks;

// Track inflight index-based requests
static std::unordered_map<Sock, std::unordered_map<uint64_t,int64_t>> g_inflight_index_ts;
static std::unordered_map<Sock, std::deque<uint64_t>> g_inflight_index_order;
static int64_t g_stall_retry_ms = MIQ_P2P_STALL_RETRY_MS;

// BULLETPROOF SYNC: Global deduplication for index-based block requests
// Prevents multiple peers from requesting the same block height simultaneously,
// which wastes bandwidth and can create duplicate orphans causing sync issues.
// STALL FIX: Now tracks timestamp so we can allow parallel requests after delay
static std::unordered_set<uint64_t> g_global_requested_indices;
static std::unordered_map<uint64_t, int64_t> g_global_requested_indices_ts;  // index -> request timestamp
static constexpr int64_t SPECULATIVE_REQUEST_DELAY_MS = 2000;  // Allow 2nd peer after 2s

// Helper: Clear index from both tracking maps (must be called with lock held)
static inline void clear_global_requested_index(uint64_t idx) {
    g_global_requested_indices.erase(idx);
    g_global_requested_indices_ts.erase(idx);
}

// ============================================================================
// SYNC DIAGNOSTICS: Track exactly what's happening during block sync
// ============================================================================
static std::atomic<uint64_t> g_diag_blocks_requested{0};    // Total blocks requested
static std::atomic<uint64_t> g_diag_blocks_received{0};     // Total blocks received
static std::atomic<uint64_t> g_diag_blocks_processed{0};    // Total blocks processed
static std::atomic<int64_t>  g_diag_last_log_ms{0};         // Last diagnostic log time
static std::atomic<uint64_t> g_diag_last_height{0};         // Height at last log
static std::atomic<uint64_t> g_diag_fill_blocked_not_capable{0};
static std::atomic<uint64_t> g_diag_fill_blocked_fork{0};
static std::atomic<uint64_t> g_diag_fill_blocked_pending_verify{0};
static std::atomic<uint64_t> g_diag_fill_blocked_max_index{0};
static std::atomic<uint64_t> g_diag_fill_blocked_already_requested{0};
static std::atomic<uint64_t> g_diag_fill_blocked_pipe_full{0};

// CRITICAL FIX: Track inflight tx request timestamps for timeout cleanup
// Without this, inflight_tx can grow forever, eventually blocking all new tx requests
static std::unordered_map<Sock, std::unordered_map<std::string,int64_t>> g_inflight_tx_ts;
static constexpr int64_t INFLIGHT_TX_TIMEOUT_MS = 30000;  // 30 second timeout for tx requests

// RAII lock guard for inflight data
class InflightLock {
    SpinLock& lock_;
public:
    explicit InflightLock(SpinLock& l) noexcept : lock_(l) { lock_.lock(); }
    ~InflightLock() noexcept { lock_.unlock(); }
    InflightLock(const InflightLock&) = delete;
    InflightLock& operator=(const InflightLock&) = delete;
};

// Note: is_block_inflight is defined at file scope, outside this namespace,
// so it can be forward-declared and used by unsolicited_drop above.

static inline void mark_block_inflight(const std::string& hash, Sock sock) {
    InflightLock lk(g_inflight_lock);
    g_global_inflight_blocks.insert(hash);
    g_inflight_block_ts[sock][hash] = now_ms();
    // Also update file-scope set for unsolicited_drop()
    add_file_scope_inflight(hash);
}

static inline void clear_block_inflight(const std::string& hash, Sock sock) {
    InflightLock lk(g_inflight_lock);
    g_global_inflight_blocks.erase(hash);
    auto it = g_inflight_block_ts.find(sock);
    if (it != g_inflight_block_ts.end()) {
        it->second.erase(hash);
    }
    // Also update file-scope set
    remove_file_scope_inflight(hash);
}

static inline void clear_all_inflight_for_sock(Sock sock) {
    InflightLock lk(g_inflight_lock);
    auto it = g_inflight_block_ts.find(sock);
    if (it != g_inflight_block_ts.end()) {
        for (const auto& kv : it->second) {
            g_global_inflight_blocks.erase(kv.first);
            // Also update file-scope set
            remove_file_scope_inflight(kv.first);
        }
        g_inflight_block_ts.erase(it);
    }

    // BULLETPROOF SYNC: Clear global index tracking when peer disconnects
    // This allows other peers to request these indices again
    auto idx_it = g_inflight_index_ts.find(sock);
    if (idx_it != g_inflight_index_ts.end()) {
        for (const auto& kv : idx_it->second) {
            g_global_requested_indices.erase(kv.first);
        }
    }
    g_inflight_index_ts.erase(sock);
    g_inflight_index_order.erase(sock);

    // CRITICAL FIX: Also clear inflight tx tracking
    g_inflight_tx_ts.erase(sock);
}

} // namespace

static inline bool peer_is_index_capable(Sock s) {
    auto it = g_peer_index_capable.find(s);
    // PROPER HEADERS-FIRST: Default to FALSE
    // Peers must explicitly be marked as index-capable via:
    // 1. MIQ_FEAT_INDEX_BY_HEIGHT feature bit in version message
    // 2. Being set by start_sync_with_peer when it starts block sync
    // This ensures headers-first completes before block downloads
    if (it == g_peer_index_capable.end()) return false;
    return it->second;
}

static inline int64_t adaptive_index_timeout_ms(const miq::PeerState& ps){
    // PROPAGATION FIX: Balanced timeouts for both IBD and near-tip performance
    //
    // IBD: Need longer timeouts to avoid premature re-requests that waste bandwidth
    //      and slow down sync when seeds are under load
    // Near-tip: Need shorter timeouts for sub-second block propagation
    //
    // Base on observed block delivery; halve it for indices (headers+lookup are lighter).
    int64_t base = std::max<int64_t>(500, ps.avg_block_delivery_ms / 4);

    // Healthier peers get tighter timeouts, weaker peers looser.
    double health = std::min(1.0, std::max(0.0, ps.health_score)); // clamp
    double health_mul = 1.5 - (health * 0.5); // 1.0..1.5

    // IBD vs near-tip: very different timeout needs
    int64_t max_t;
    double ibd_mul;
    if (!g_logged_headers_done) {
        // IBD mode: Be patient - seeds may be under load, avoid duplicate requests
        ibd_mul = 3.0;  // More slack during IBD
        max_t = 10000;  // 10s max during IBD - avoid re-request storms
    } else if (ps.syncing) {
        // Active sync but past headers: moderate timeout
        ibd_mul = 2.0;
        max_t = 5000;  // 5s max during active sync
    } else {
        // Near-tip steady state: aggressive timeout for fast propagation
        ibd_mul = 1.0;
        max_t = 2000;  // 2s max near tip
    }

    int64_t t = (int64_t)(base * health_mul * ibd_mul);
    return std::max<int64_t>(500, std::min<int64_t>(t, max_t));
}

// ============================================================================
// Peer Reputation & Adaptive Batching System
// ============================================================================

// Calculate reputation score based on delivery success rate and speed
static inline void update_peer_reputation(miq::PeerState& ps) {
    int64_t total_deliveries = ps.blocks_delivered_successfully + ps.blocks_failed_delivery;
    if (total_deliveries == 0) {
        ps.reputation_score = 1.0;  // New peers start with perfect score
        return;
    }

    // Success rate component (0.0 to 1.0)
    double success_rate = (double)ps.blocks_delivered_successfully / (double)total_deliveries;

    // Speed component: compare against baseline (30s)
    double speed_factor = 1.0;
    if (ps.total_blocks_received > 0) {
        int64_t avg_delivery = ps.total_block_delivery_time_ms / ps.total_blocks_received;
        // Peers faster than 10s get bonus, slower than 60s get penalty
        if (avg_delivery < 10000) {
            speed_factor = 1.2;  // 20% bonus for fast peers
        } else if (avg_delivery > 60000) {
            speed_factor = 0.7;  // 30% penalty for slow peers
        } else {
            // Linear interpolation between 10s and 60s
            speed_factor = 1.0 - ((avg_delivery - 10000) / 50000.0) * 0.3;
        }
    }

    // Combine: 70% success rate, 30% speed
    ps.reputation_score = (success_rate * 0.7 + speed_factor * 0.3);
    ps.reputation_score = std::max(0.0, std::min(1.0, ps.reputation_score));
}

// Calculate adaptive batch size based on peer reputation and network conditions
static inline uint32_t calculate_adaptive_batch_size(const miq::PeerState& ps) {
    // CRITICAL FIX: Don't blindly trust new peers with huge batches!
    // Problem: New peers get rep=1.0, get 256 requests, never deliver, waste slots.
    // Solution: Start with IP-based limit, only ramp up AFTER peer proves itself.

    double rep = ps.reputation_score;
    uint32_t batch_size;

    // STEP 1: Check if peer has proven itself THIS SESSION
    // A peer is "proven" if they've delivered at least 10 blocks
    bool peer_proven_this_session = (ps.blocks_delivered_successfully >= 10);

    // STEP 2: Get IP-based starting limit (survives reconnects)
    uint32_t ip_limit = get_ip_starting_batch(ps.ip);

    // During IBD: adaptive based on proven status
    if (!g_logged_headers_done) {
        if (peer_proven_this_session) {
            // Peer has proven themselves this session - allow large batches
            if (rep >= 0.5) {
                batch_size = 256;
            } else {
                batch_size = 128;
            }
        } else {
            // Peer has NOT proven themselves yet - use IP history limit
            // This prevents reconnecting bad peers from immediately getting 256 requests
            batch_size = ip_limit;

            // Allow gradual ramp up based on current session delivery
            if (ps.blocks_delivered_successfully >= 5) {
                batch_size = std::min(batch_size * 2, (uint32_t)128);
            }
        }
    } else {
        // Post-IBD: normal operation with reasonable batches
        if (rep >= 0.9) {
            batch_size = 64;
        } else if (rep >= 0.7) {
            batch_size = 48;
        } else if (rep >= 0.5) {
            batch_size = 32;
        } else {
            batch_size = 16;
        }
    }

    return batch_size;
}

// Update adaptive batch size for a peer
static inline void update_adaptive_batch_size(miq::PeerState& ps) {
    uint32_t new_batch = calculate_adaptive_batch_size(ps);
    if (new_batch != ps.adaptive_batch_size) {
        P2P_TRACE("DEBUG: Adaptive batch size for " + ps.ip + " changed from " +
                  std::to_string(ps.adaptive_batch_size) + " to " + std::to_string(new_batch) +
                  " (reputation=" + std::to_string(ps.reputation_score) + ")");
        ps.adaptive_batch_size = new_batch;
    }
}

static inline void clear_fulfilled_indices_up_to_height(size_t new_h, uint64_t header_height = 0){
    // BULLETPROOF SYNC: Clear completed indices from global tracking
    // This ensures indices below the current chain height are removed,
    // allowing the sync to progress without getting stuck on old indices.
    // Also clear any corrupted indices beyond header height.

    // PERFORMANCE FIX: Throttle cleanup to reduce lock contention
    // With many connections, this function was being called 50+ times/sec
    // Each call iterated the entire global_requested_indices set while holding lock
    // This caused severe lock contention and slowdowns
    static int64_t last_cleanup_ms = 0;
    static size_t last_cleanup_height = 0;
    int64_t now = now_ms();

    // Only run full cleanup every 100ms OR if height advanced significantly
    bool should_run = (now - last_cleanup_ms > 100) ||
                      (new_h > last_cleanup_height + 10);
    if (!should_run) {
        return;
    }
    last_cleanup_ms = now;
    last_cleanup_height = new_h;

    {
        InflightLock lk(g_inflight_lock);
        // Use erase_if pattern with iterator for efficiency
        for (auto it = g_global_requested_indices.begin(); it != g_global_requested_indices.end(); ) {
            uint64_t idx = *it;
            if (idx <= (uint64_t)new_h || (header_height > 0 && idx > header_height)) {
                it = g_global_requested_indices.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Per-peer cleanup - also needs lock protection
    {
        InflightLock lk(g_inflight_lock);
        for (auto &kv : g_inflight_index_ts){
            Sock s = kv.first;
            auto &byidx = kv.second;
            auto &dq = g_inflight_index_order[s];

            // Remove from timestamp map any indices we must already have received
            // OR any corrupted indices beyond header height
            for (auto it = byidx.begin(); it != byidx.end(); ){
                if (it->first <= (uint64_t)new_h) {
                    it = byidx.erase(it);
                } else if (header_height > 0 && it->first > header_height) {
                    it = byidx.erase(it);
                } else {
                    ++it;
                }
            }

            // Trim the front of the oldest-first deque
            while (!dq.empty() && (dq.front() <= (uint64_t)new_h ||
                   (header_height > 0 && dq.front() > header_height))) {
                dq.pop_front();
            }
        }
    }
}

namespace {
  // key: 64-hex block hash  -> next index into a snapshot of candidate peers
  static std::unordered_map<std::string, size_t> g_rr_next_idx;

  // Pick the next peer for a given key from a stable snapshot of candidates.
  // Advances the cursor so future lookups rotate fairly.
  static inline Sock rr_pick_peer_for_key(const std::string& keyHex,
                                          const std::vector<Sock>& candidates)
  {
      if (candidates.empty()) return MIQ_INVALID_SOCK;
      size_t &i = g_rr_next_idx[keyHex];
      if (i >= candidates.size()) {
          i %= candidates.size();
      }
      Sock chosen = candidates[i];
      i = (i + 1) % candidates.size();
      return chosen;
  }
}
// Light-touch guard for peers_ against snapshot_peers() racing the loop
// FIXED: Use recursive_mutex to prevent deadlock when same thread re-acquires lock
namespace {
  static std::recursive_mutex g_peers_mu;
}


// --- socket helpers: non-blocking + nodelay + timed connect -----------------
static inline void miq_set_nodelay(Sock s) {
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&one), sizeof(one));
}

static inline void miq_set_sockbufs(Sock s) {
    // Optimized buffer sizes - use larger buffers for faster block transfers
    // but not too large to avoid memory bloat with many peers
    int sz = MIQ_SOCK_RCVBUF; // Use the optimized value defined above
#if defined(_WIN32)
    (void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&sz, sizeof(sz));
    sz = MIQ_SOCK_SNDBUF;
    (void)setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char*)&sz, sizeof(sz));
#else
    (void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    sz = MIQ_SOCK_SNDBUF;
    (void)setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
#endif

#ifdef TCP_QUICKACK
    // Enable TCP_QUICKACK for faster ACKs on Linux
    int quickack = 1;
    (void)setsockopt(s, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack));
#endif
}

static inline bool miq_set_nonblock(Sock s) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

// Create a socket, set non-blocking, connect with timeout, return the socket or MIQ_INVALID_SOCK.
static Sock miq_connect_nb(const sockaddr* sa, socklen_t slen, int timeout_ms) {
#ifdef _WIN32
    Sock s = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
#else
    Sock s = socket(sa->sa_family, SOCK_STREAM, 0);
#endif
    if (s == MIQ_INVALID_SOCK) return MIQ_INVALID_SOCK;
    miq_set_cloexec(s);
    (void)miq_set_nonblock(s);
    miq_optimize_socket(s);  // Comprehensive socket optimization

#ifdef _WIN32
    int rc = ::connect(s, sa, (int)slen);
    if (rc == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS) {
            CLOSESOCK(s);
            return MIQ_INVALID_SOCK;
        }
        WSAPOLLFD pfd{}; pfd.fd = s; pfd.events = POLLWRNORM; pfd.revents = 0;
        rc = WSAPoll(&pfd, 1, timeout_ms);
        if (rc <= 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
        // verify connect result
        int soerr = 0; int sl = sizeof(soerr);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &sl);
        if (soerr != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    }
#else
    int rc = ::connect(s, sa, slen);
    if (rc != 0) {
        if (errno != EINPROGRESS) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
        struct pollfd pfd{ s, POLLOUT, 0 };
        rc = ::poll(&pfd, 1, timeout_ms);
        if (rc <= 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
        int soerr = 0; socklen_t sl = sizeof(soerr);
        getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if (soerr != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    }
#endif
    miq_set_keepalive(s);
    return s;
}
static inline int64_t seed_backoff_base_ms(){
    return (int64_t)env_u64("MIQ_SEED_BACKOFF_MS_BASE", 15000ULL);
}
static inline int64_t seed_backoff_max_ms(){
    return (int64_t)env_u64("MIQ_SEED_BACKOFF_MS_MAX", 300000ULL);
}
static inline int64_t jitter_ms(int64_t max_jitter){
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<int64_t> d(0, max_jitter);
    return d(gen);
}

static inline void gate_on_connect(Sock fd){
    PeerGate pg;
    pg.t_conn = Clock::now();
    pg.t_last = pg.t_conn;
    pg.t_conn_ms = now_ms();
    pg.is_loopback = false; // default; set after we learn the IP
    pg.hs_last_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();
    g_gate[fd] = pg;
    g_trickle_last_ms[fd] = 0;
    g_peer_index_capable[fd] = false;
}
// NEW: mark the fd as loopback once we know the peer's IP.
static inline void gate_set_loopback(Sock fd, bool is_lb){
    auto it = g_gate.find(fd);
    if (it != g_gate.end()) it->second.is_loopback = is_lb;
}

static inline void gate_on_close(Sock fd){
    // Thread-safe cleanup of all inflight tracking for this socket
    clear_all_inflight_for_sock(fd);
    g_gate.erase(fd);
    g_trickle_q.erase(fd);
    g_trickle_last_ms.erase(fd);
    g_last_hdr_req_ms.erase(fd);
    g_peer_minrelay_kb.erase(fd);
    g_peer_last_ff_ms.erase(fd);
    rx_clear_start(fd);
    g_zero_hdr_batches.erase(fd);
    g_preverack_counts.erase(fd);
    g_cmd_rl.erase(fd); // NEW: clean up per-socket rate-limiter windows
    g_hdr_flip.erase(fd);
    g_peer_last_fetch_ms.erase(fd);
    g_peer_last_request_ms.erase(fd);
    g_peer_index_capable.erase(fd);
    g_index_timeouts.erase(fd);  // CRITICAL FIX: Clean up timeout counter to prevent socket reuse issues
    g_last_hdr_ok_ms.erase(fd);  // Clean up header tracking to prevent stale state
}
[[maybe_unused]] static inline bool gate_on_bytes(Sock fd, size_t add){
    auto it = g_gate.find(fd);
    if (it == g_gate.end()) return false;
    it->second.rx_bytes += add;
    it->second.t_last = Clock::now();
    // trip the gate if a single peer accumulates too much pending RX
    if (it->second.rx_bytes > MAX_MSG_BYTES) return true;
    return false;
}
static inline bool gate_on_command(Sock fd, const std::string& cmd,
                                   /*out*/ bool& should_send_verack,
                                   /*out*/ int& close_code)
{
    should_send_verack = false;
    close_code = 0;

    auto it = g_gate.find(fd);
    if (it == g_gate.end()) {
        miq::log_warn("P2P: gate_on_command - no gate entry for fd=" + std::to_string((uintptr_t)fd) + " cmd=" + cmd);
        return false;
    }
    auto& g = it->second;

    // CRITICAL FIX: Process handshake commands (version/verack) FIRST before timeout check
    // This ensures that receiving a valid handshake message extends the deadline
    if (!cmd.empty()) {
        if (cmd == "version") {
            // Receiving version message - update timestamp immediately to prevent timeout
            g.hs_last_ms = now_ms();
            if (!g.got_version) {
                miq::log_info("P2P: received version from peer fd=" + std::to_string((uintptr_t)fd));
                g.got_version = true;
                should_send_verack = true;
                g_preverack_counts.erase(fd);
            }
            // Don't apply timeout logic - we just got a valid handshake message
            if (g.banscore >= MAX_BANSCORE) { close_code = 400; return true; }
            return false;
        } else if (cmd == "verack") {
            // Receiving verack message - update timestamp immediately to prevent timeout
            g.hs_last_ms = now_ms();
            miq::log_info("P2P: received verack from peer fd=" + std::to_string((uintptr_t)fd));
            g.got_verack = true;
            g_preverack_counts.erase(fd);
            // Don't apply timeout logic - we just got a valid handshake message
            if (g.banscore >= MAX_BANSCORE) { close_code = 400; return true; }
            return false;
        }
    }

    // For non-handshake commands, check timeout
    if (!g.got_verack) {
        int64_t idle = now_ms() - g.hs_last_ms;
        if (idle > HANDSHAKE_MS) {
            if (g.is_loopback) {
                g.hs_last_ms = now_ms();
            } else {
                close_code = 408;
                miq::log_warn("P2P: handshake timeout fd=" + std::to_string((uintptr_t)fd) +
                         " idle=" + std::to_string(idle) + "ms got_version=" +
                         (g.got_version ? "true" : "false") + " got_verack=" +
                         (g.got_verack ? "true" : "false") + " sent_verack=" +
                         (g.sent_verack ? "true" : "false"));
                return true;
            }
        }
    }

    // Handle other pre-handshake commands
    if (!cmd.empty()) {
        if (!g.got_version) {
            if (miq_safe_preverack_cmd(cmd)) {
                g.hs_last_ms = now_ms();
                return false;
            } else {
                g.banscore += 10;
                if (g.banscore >= MAX_BANSCORE) { close_code = 400; P2P_TRACE("close fd="+std::to_string((uintptr_t)fd)+" reason=pre-version-bad"); return true; }
                return false;
            }
        }
        if (!g.got_verack) {
            if (!miq_safe_preverack_cmd(cmd)) { return false; }
            g.hs_last_ms = now_ms();
            if (!g.is_loopback && cmd != "getheaders" && cmd != "headers") {
                int &cnt = g_preverack_counts[fd];
                if (++cnt > MIQ_PREVERACK_QUEUE_MAX) {
                    return false;
                }
            }
        }
    }

    if (g.banscore >= MAX_BANSCORE){ close_code = 400; P2P_TRACE("close fd="+std::to_string((uintptr_t)fd)+" reason=banscore"); return true; }
    return false;
}

// === legacy persisted IPv4 addr set (kept for backward compat) ==============
static void save_addrs_to_disk(const std::string& datadir,
                               const std::unordered_set<uint32_t>& addrv4){
    std::string path = datadir + "/peers.dat";
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if(!f) return;
    f.write("MIQA", 4);
    uint32_t cnt = (uint32_t)std::min<size_t>(addrv4.size(), MIQ_ADDR_MAX_STORE);
    f.write(reinterpret_cast<const char*>(&cnt), sizeof(cnt));
    size_t written = 0;
    for (uint32_t ip : addrv4){
        if (written >= MIQ_ADDR_MAX_STORE) break;
        f.write(reinterpret_cast<const char*>(&ip), sizeof(uint32_t));
        ++written;
    }
}

static bool is_private_be(uint32_t be_ip){
    uint8_t A = uint8_t(be_ip>>24), B = uint8_t(be_ip>>16);
    if (A == 0 || A == 10 || A == 127) return true;
    if (A == 169 && B == 254) return true;
    if (A == 192 && B == 168) return true;
    /* 172.16.0.0/12 == 172.(16..31).x.x */
    if (A == 172 && B >= 16 && B <= 31) return true;
    if (A >= 224) return true;
    return false;
}

static void load_addrs_from_disk(const std::string& datadir,
                                 std::unordered_set<uint32_t>& addrv4){
    std::string path = datadir + "/peers.dat";
    std::ifstream f(path, std::ios::binary);
    if(!f) return;
    char magic[4]; if(!f.read(magic,4)) return;
    if(std::memcmp(magic,"MIQA",4)!=0) return;
    uint32_t cnt=0;
    if(!f.read(reinterpret_cast<char*>(&cnt), sizeof(cnt))) return;
    for (uint32_t i=0; i<cnt; ++i){
        uint32_t ip=0;
        if(!f.read(reinterpret_cast<char*>(&ip), sizeof(ip))) break;
        if (!is_private_be(ip)) addrv4.insert(ip);
    }
}

static std::string be_ip_to_string(uint32_t be_ip){
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = be_ip;
    char buf[64] = {0};
#ifdef _WIN32
    InetNtopA(AF_INET, &a.sin_addr, buf, (int)sizeof(buf));
#else
    inet_ntop(AF_INET, &a.sin_addr, buf, (socklen_t)sizeof(buf));
#endif
    return std::string(buf[0]?buf:"0.0.0.0");
}

// ---- NEVER DIAL LOOPBACK/SELF: guard state & helpers -----------------------
static std::unordered_set<uint32_t> g_self_v4; // network byte order (BE)

static bool parse_ipv4_dotted(const std::string& dotted, uint32_t& be_ip){
    sockaddr_in tmp{};
#ifdef _WIN32
    if (InetPtonA(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#else
    if (inet_pton(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#endif
    be_ip = tmp.sin_addr.s_addr;
    return true;
}

static inline void gate_mark_sent_verack(Sock fd){
    auto it = g_gate.find(fd);
    if (it != g_gate.end()){
        it->second.sent_verack = true;
        it->second.hs_last_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now().time_since_epoch()).count();
    }
}

static inline bool is_loopback_be(uint32_t be_ip){
    return (uint8_t)(be_ip >> 24) == 127;
}
static inline bool is_self_be(uint32_t be_ip){
    return g_self_v4.find(be_ip) != g_self_v4.end();
}
static void self_add_dotted(const std::string& ip){
    uint32_t be_ip=0;
    if (parse_ipv4_dotted(ip, be_ip)) g_self_v4.insert(be_ip);
}
static void gather_self_ipv4_basic(){
    char host[256] = {0};
#ifdef _WIN32
    if (gethostname(host, (int)sizeof(host)) != 0) return;
    ADDRINFOA hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    PADDRINFOA res = nullptr;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res) return;
    for (auto p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        auto sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        if (!sa) continue;
        uint32_t be_ip = sa->sin_addr.s_addr;
        if (be_ip) g_self_v4.insert(be_ip);
    }
    freeaddrinfo(res);
#else
    if (gethostname(host, sizeof(host)) != 0) return;
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res) return;
    for (auto p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        auto sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        if (!sa) continue;
        uint32_t be_ip = sa->sin_addr.s_addr;
        if (be_ip) g_self_v4.insert(be_ip);
    }
    freeaddrinfo(res);
#endif
}
static void gather_self_from_env(){
    const char* a = std::getenv("MIQ_SELF_IP");
    const char* b = std::getenv("MIQ_SELF_IPV4");
    auto take = [&](const char* s){
        if (!s || !*s) return;
        std::string v(s);
        size_t i=0;
        while (i < v.size()) {
            while (i < v.size() && (v[i]==' '||v[i]==','||v[i]==';'||v[i]=='\t')) ++i;
            size_t j=i;
            while (j < v.size() && v[j]!=',' && v[j]!=';' && v[j]!=' ' && v[j]!='\t') ++j;
            if (j>i) self_add_dotted(v.substr(i,j-i));
            i=j;
        }
    };
    take(a); take(b);
}
static std::string self_list_for_log(){
    std::string out;
    bool first = true;
    for (uint32_t be_ip : g_self_v4){
        if (!first) out += ",";
        out += be_ip_to_string(be_ip);
        first = false;
    }
    if (out.empty()) out = "(none)";
    return out;
}

[[maybe_unused]] static inline uint16_t v4_group16(uint32_t be_ip){
    uint8_t A = uint8_t(be_ip>>24), B = uint8_t(be_ip>>16);
    return (uint16_t(A) << 8) | uint16_t(B);
}

// Dial a single IPv4 (be order) at supplied port; returns socket or MIQ_INVALID_SOCK
static Sock dial_be_ipv4(uint32_t be_ip, uint16_t port){
    // Allow loopback connections when MIQ_FORCE_CLIENT=1 (for local testing)
    bool allow_loopback = std::getenv("MIQ_FORCE_CLIENT") != nullptr;
    if (!allow_loopback && (is_loopback_be(be_ip) || is_self_be(be_ip))) {
        return MIQ_INVALID_SOCK;
    }
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = be_ip; a.sin_port = htons(port);
    Sock s = miq_connect_nb((sockaddr*)&a, (socklen_t)sizeof(a), MIQ_CONNECT_TIMEOUT_MS);
    return s;
}

// v6 loopback helper
static inline bool is_loopback_v6(const in6_addr& a) {
    static const uint8_t loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}; // ::1
    return std::memcmp(&a, loop, 16) == 0;
}

// Detect if an accepted fd is a clear self-hairpin (we dialed ourselves).
static bool is_self_endpoint(Sock fd, uint16_t listen_port){
    sockaddr_storage peer{}, local{};
#ifdef _WIN32
    int alen = (int)sizeof(peer), blen = (int)sizeof(local);
#else
    socklen_t alen = sizeof(peer), blen = sizeof(local);
#endif
    if (getpeername(fd, (sockaddr*)&peer, &alen) != 0) return false;
    if (getsockname(fd, (sockaddr*)&local, &blen) != 0) return false;

    if (peer.ss_family == AF_INET && local.ss_family == AF_INET) {
        auto* p = (sockaddr_in*)&peer;
        auto* l = (sockaddr_in*)&local;

        const uint32_t peer_be = p->sin_addr.s_addr;
        const uint16_t peer_port = ntohs(p->sin_port);
        const uint16_t local_port = ntohs(l->sin_port);
        (void)local_port; // Used by P2P_TRACE when enabled

        // DEBUG: Log the hairpin check details
        char peer_ip_str[INET_ADDRSTRLEN] = {0};
        char local_ip_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &p->sin_addr, peer_ip_str, sizeof(peer_ip_str));
        inet_ntop(AF_INET, &l->sin_addr, local_ip_str, sizeof(local_ip_str));
        P2P_TRACE("is_self_endpoint: peer=" + std::string(peer_ip_str) + ":" + std::to_string(peer_port) +
                  " local=" + std::string(local_ip_str) + ":" + std::to_string(local_port) +
                  " listen_port=" + std::to_string(listen_port));

        // explicit: loopback inbound is allowed; only reject if hairpin on same port
        if (is_loopback_be(peer_be)) {
            if (peer_port == listen_port) {
                P2P_TRACE("is_self_endpoint: HAIRPIN DETECTED (loopback + same port)");
                return true;
            }
            return false;
        }
        if (is_self_be(peer_be)) {
            if (peer_port == listen_port) {
                P2P_TRACE("is_self_endpoint: HAIRPIN DETECTED (self IP + same port)");
                return true;
            }
            return false;
        }
    } else if (peer.ss_family == AF_INET6 && local.ss_family == AF_INET6) {
        auto* p6 = (sockaddr_in6*)&peer;
        auto* l6 = (sockaddr_in6*)&local;
        if (is_loopback_v6(p6->sin6_addr)) {
            if (ntohs(p6->sin6_port) == listen_port) return true;
            return false;
        }
        // Conservative hairpin detect: same v6 address AND same port as our listener.
        if (std::memcmp(&p6->sin6_addr, &l6->sin6_addr, sizeof(in6_addr)) == 0 &&
            ntohs(p6->sin6_port) == listen_port) {
            return true;
        }
    }
    return false;
}

static std::string miq_addr_from_pkh(const std::vector<uint8_t>& pkh) {
    if (pkh.size() != 20) return "(unknown)";
    return miq::base58check_encode(miq::VERSION_P2PKH, pkh);
}
static std::string miq_miner_from_block(const miq::Block& b) {
    if (b.txs.empty()) return "(unknown)";
    const miq::Transaction& cb = b.txs[0];
    if (cb.vout.empty()) return "(unknown)";
    return miq_addr_from_pkh(cb.vout[0].pkh);
}

// --- NEW: version payload helper (send a real version+services) -------------
static inline void miq_put_u32le(std::vector<uint8_t>& v, uint32_t x){
    v.push_back((uint8_t)((x>>0)&0xff));
    v.push_back((uint8_t)((x>>8)&0xff));
    v.push_back((uint8_t)((x>>16)&0xff));
    v.push_back((uint8_t)((x>>24)&0xff));
}

// Helper function to create a vector with a single uint32_t in little-endian format
static inline MIQ_MAYBE_UNUSED std::vector<uint8_t> miq_put_u32le_vec(uint32_t x) {
    std::vector<uint8_t> v;
    v.reserve(4);
    miq_put_u32le(v, x);
    return v;
}

// Helper function to create a vector with a single uint64_t in little-endian format (for getbi)
static inline MIQ_MAYBE_UNUSED std::vector<uint8_t> miq_put_u64le_vec(uint64_t x) {
    std::vector<uint8_t> v;
    v.reserve(8);
    v.push_back((uint8_t)((x>>0)&0xff));
    v.push_back((uint8_t)((x>>8)&0xff));
    v.push_back((uint8_t)((x>>16)&0xff));
    v.push_back((uint8_t)((x>>24)&0xff));
    v.push_back((uint8_t)((x>>32)&0xff));
    v.push_back((uint8_t)((x>>40)&0xff));
    v.push_back((uint8_t)((x>>48)&0xff));
    v.push_back((uint8_t)((x>>56)&0xff));
    return v;
}
static inline void miq_put_u64le(std::vector<uint8_t>& v, uint64_t x){
    for (int i=0;i<8;i++) v.push_back((uint8_t)((x>>(8*i))&0xff));
}
static inline std::vector<uint8_t> miq_build_version_payload(uint32_t start_height) {
    std::vector<uint8_t> v; v.reserve(128);

    // Use a compatible protocol version for P2P communication
    const uint32_t version = 70015;
    miq_put_u32le(v, version);

    uint64_t svc = 0;
    svc |= MIQ_FEAT_HEADERS_FIRST;        // headers-first supported
    svc |= MIQ_FEAT_TX_RELAY;             // transaction relay supported
    svc |= MIQ_FEAT_INDEX_BY_HEIGHT;      // by-index fetch supported
    miq_put_u64le(v, svc);

    // Timestamp
    int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    miq_put_u64le(v, (uint64_t)timestamp);

    // Remote address (addr_recv) - 26 bytes: services(8) + ip(16) + port(2)
    miq_put_u64le(v, 0); // remote services
    // IPv4-mapped IPv6 address (::ffff:0.0.0.0)
    for (int i = 0; i < 10; i++) v.push_back(0x00);
    v.push_back(0xff); v.push_back(0xff);
    for (int i = 0; i < 4; i++) v.push_back(0x00); // 0.0.0.0
    v.push_back(0x26); v.push_back(0x9b); // port 9883 in big-endian

    // Local address (addr_from) - 26 bytes: services(8) + ip(16) + port(2)
    miq_put_u64le(v, svc); // local services
    // IPv4-mapped IPv6 address (::ffff:0.0.0.0)
    for (int i = 0; i < 10; i++) v.push_back(0x00);
    v.push_back(0xff); v.push_back(0xff);
    for (int i = 0; i < 4; i++) v.push_back(0x00); // 0.0.0.0
    v.push_back(0x26); v.push_back(0x9b); // port 9883 in big-endian

    // Nonce (8 bytes)
    static uint64_t nonce_counter = 0;
    uint64_t nonce = (uint64_t)timestamp ^ (++nonce_counter);
    miq_put_u64le(v, nonce);

    std::string user_agent = "/miqrochain:0.7.0/";
    if (user_agent.size() < 0xFD) {
        // varstr: length (1 byte) + bytes
        v.push_back((uint8_t)user_agent.size());
        v.insert(v.end(), user_agent.begin(), user_agent.end());
    } else {
        // varstr: 0xFD + uint16 length (LE) + bytes
        v.push_back(0xFD);
        v.push_back((uint8_t)(user_agent.size() & 0xFF));
        v.push_back((uint8_t)((user_agent.size() >> 8) & 0xFF));
        v.insert(v.end(), user_agent.begin(), user_agent.end());
    }

    miq_put_u32le(v, start_height);

    // Relay flag (1 byte)
    v.push_back(1); // true: receive tx announcements
    return v;
}

// Small helper to throttle header pipelining safely.
[[maybe_unused]] static inline bool can_accept_hdr_batch(miq::PeerState& ps, int64_t now) {
    // AGGRESSIVE: Use MIQ_HDR_PIPELINE for consistency
    const int      kMaxInflight = MIQ_HDR_PIPELINE;
    // CRITICAL FIX: During IBD, no gap between requests - blast them all!
    const int64_t  kMinGapMs    = g_logged_headers_done ? 10 : 0;
    if (static_cast<uint32_t>(ps.inflight_hdr_batches) >= static_cast<uint32_t>(kMaxInflight)) return false;
    if (kMinGapMs > 0) {
        auto it = g_last_hdr_req_ms.find((Sock)ps.sock);
        int64_t last_req = (it == g_last_hdr_req_ms.end()) ? 0 : it->second;
        if (last_req && (now - last_req) < kMinGapMs) return false;
    }
    return true;
}
static inline std::string miq_idx_key(uint64_t idx) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "IDX_%016llx", (unsigned long long)idx);
    return std::string(buf);
}
}

namespace miq {

bool P2P::check_rate(PeerState& ps, const char* key) {
    if (!key) return true;

    struct Map { const char* key; const char* family; };
    static const Map kTable[] = {
        {"invb",       "inv"},
        {"invtx",      "inv"},
        {"getb",       "get"},
        {"getbi",      "get"},
        {"gettx",      "get"},
        {"gethdr",     "hdr"},     // legacy alias
        {"getheaders", "hdr"},     // actual command name
        {"addr",       "addr"},
        {"getaddr",    "addr"},
    };

    for (const auto& e : kTable) {
        if (std::strcmp(e.key, key) == 0) {
            return check_rate(ps, e.family, 1.0, now_ms());
        }
    }
    return check_rate(ps, "misc", 1.0, now_ms());
}

// === Per-family token bucket (cost tokens per event) ========================
bool P2P::check_rate(PeerState& ps, const char* family, double cost, int64_t tnow)
{
    if (!family) family = "misc";
    if (cost < 0) cost = 0;
    const std::string fam(family);

    // CRITICAL FIX: During IBD, don't rate-limit headers or blocks!
    // Rate limiting during sync causes extremely slow downloads
    if (!g_logged_headers_done) {
        if (fam == "hdr" || fam == "get" || fam == "blk") {
            return true;  // Allow unlimited during IBD
        }
    }

    // Look up per-family config: default if missing.
    double per_sec = 10.0;
    double burst   = 20.0;
    auto it_cfg = rate_cfg_.find(fam);
    if (it_cfg != rate_cfg_.end()) {
        per_sec = it_cfg->second.per_sec;
        burst   = it_cfg->second.burst;
    }

    // Refill and charge tokens.
    auto& rc = ps.rate;
    if (rc.last_ms == 0) rc.last_ms = tnow;
    const double elapsed = (tnow - rc.last_ms) / 1000.0;
    double tokens = rc.buckets[fam]; // 0 if missing

    if (elapsed > 0) {
        tokens = std::min(burst, tokens + per_sec * elapsed);
    }
    rc.last_ms = tnow;

    if (tokens + 1e-9 < cost) {
        if (!ps.whitelisted && !ibd_or_fetch_active(ps, tnow)) {
            if (ps.banscore < MIQ_P2P_MAX_BANSCORE) ps.banscore += 1;
        }
        rc.buckets[fam] = tokens;
        return false;
    }

    tokens -= cost;
    rc.buckets[fam] = tokens;
    return true;
}


bool P2P::check_rate(PeerState& ps,
                     const char* family,
                     const char* name,
                     uint32_t burst,
                     uint32_t window_ms)
{
    const char* fam = family ? family : "misc";
    const char* nam = name   ? name   : "";

    std::string k;
    k.reserve(std::strlen(fam) + 1 + std::strlen(nam));
    k.append(fam);
    k.push_back(':');
    k.append(nam);

    const int64_t t = now_ms();

    static_assert(std::is_same<decltype(g_cmd_rl),
        std::unordered_map<Sock, std::unordered_map<std::string, std::pair<int64_t,uint32_t>>>>::value,
        "g_cmd_rl type changed");

    auto& perPeer = g_cmd_rl[(Sock)ps.sock];
    auto& slot    = perPeer[k];
    int64_t&  win_start = slot.first;
    uint32_t& count     = slot.second;

    if (win_start == 0 || (t - win_start) >= (int64_t)window_ms) {
        win_start = t;
        count = 0;
    }

    if (count >= burst) {
        if (!ps.whitelisted && !ibd_or_fetch_active(ps, now_ms())) {
            if (ps.banscore < MIQ_P2P_MAX_BANSCORE) ps.banscore += 1;
        }
        return false;
    }

    ++count;
    return true;
}

#if MIQ_ENABLE_HEADERS_FIRST
namespace {
    static constexpr size_t HEADER_WIRE_BYTES = 88;

    static inline void put_u32le(std::vector<uint8_t>& v, uint32_t x){
        v.push_back((uint8_t)((x>>0)&0xff));
        v.push_back((uint8_t)((x>>8)&0xff));
        v.push_back((uint8_t)((x>>16)&0xff));
        v.push_back((uint8_t)((x>>24)&0xff));
    }
    static inline void put_u64le(std::vector<uint8_t>& v, uint64_t x){
        for(int i=0;i<8;i++) v.push_back((uint8_t)((x>>(8*i))&0xff));
    }
    static inline void put_i64le(std::vector<uint8_t>& v, int64_t x){
        put_u64le(v, (uint64_t)x);
    }
    static inline uint32_t get_u32le(const uint8_t* p){ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
    static inline uint64_t get_u64le(const uint8_t* p){ uint64_t z=0; for(int i=0;i<8;i++) z|=((uint64_t)p[i])<<(8*i); return z; }
    static inline int64_t  get_i64le(const uint8_t* p){ return (int64_t)get_u64le(p); }

    static std::vector<uint8_t> ser_header(const BlockHeader& h){
        std::vector<uint8_t> v; v.reserve(HEADER_WIRE_BYTES);
        put_u32le(v, h.version);
        v.insert(v.end(), h.prev_hash.begin(),   h.prev_hash.end());
        v.insert(v.end(), h.merkle_root.begin(), h.merkle_root.end());
        put_i64le(v, h.time);
        put_u32le(v, h.bits);
        put_u64le(v, h.nonce);
        return v;
    }
    static bool deser_header(const uint8_t* p, size_t n, BlockHeader& h){
        if (n < HEADER_WIRE_BYTES) return false;
        h.version = get_u32le(p+0);
        h.prev_hash.assign(p+4,   p+4+32);
        h.merkle_root.assign(p+36, p+36+32);
        h.time = get_i64le(p+68);
        h.bits = get_u32le(p+76);
        h.nonce= get_u64le(p+80);
        return true;
    }

    static std::vector<uint8_t> build_getheaders_payload(const std::vector<std::vector<uint8_t>>& locator,
                                                         const std::vector<uint8_t>& stop){
        const uint8_t n = (uint8_t)std::min<size_t>(locator.size(), 64);
        std::vector<uint8_t> v; v.reserve(1 + n*32 + 32);
        v.push_back(n);
        for (size_t i=0;i<n;i++) v.insert(v.end(), locator[i].begin(), locator[i].end());
        if (stop.size()==32) v.insert(v.end(), stop.begin(), stop.end());
        else v.insert(v.end(), 32, 0);
        return v;
    }
    static bool parse_getheaders_payload(const std::vector<uint8_t>& p,
                                         std::vector<std::vector<uint8_t>>& locator,
                                         std::vector<uint8_t>& stop){
        if (p.size() < 1+32) return false;
        uint8_t n = p[0];
        size_t need = 1 + (size_t)n*32 + 32;
        if (p.size() < need) return false;
        locator.clear();
        size_t off = 1;
        for (uint8_t i=0;i<n;i++){ locator.emplace_back(p.begin()+off, p.begin()+off+32); off+=32; }
        stop.assign(p.begin()+off, p.begin()+off+32);
        return true;
    }

    static std::vector<uint8_t> build_headers_payload(const std::vector<BlockHeader>& hs){
        const uint16_t n = (uint16_t)std::min<size_t>(hs.size(), 2000);
        std::vector<uint8_t> v; v.reserve(2 + (size_t)n*HEADER_WIRE_BYTES);
        v.push_back((uint8_t)(n & 0xff));
        v.push_back((uint8_t)((n >> 8) & 0xff));
        for (size_t i=0;i<n;i++){
            auto h = ser_header(hs[i]);
            v.insert(v.end(), h.begin(), h.end());
        }
        return v;
    }
    static bool parse_headers_payload(const std::vector<uint8_t>& p, std::vector<BlockHeader>& out){
        if (p.size() < 2) return false;
        uint16_t n = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        size_t need = 2 + (size_t)n*HEADER_WIRE_BYTES;
        if (p.size() < need) return false;
        out.clear(); out.reserve(n);
        size_t off = 2;
        for (uint16_t i=0;i<n;i++){
            BlockHeader h;
            if (!deser_header(p.data()+off, p.size()-off, h)) return false;
            out.push_back(std::move(h));
            off += HEADER_WIRE_BYTES;
        }
        return true;
    }
}
#endif

#if MIQ_ENABLE_ADDRMAN
namespace {
    static miq::AddrMan g_addrman;
    static std::string  g_addrman_path;
    static int64_t      g_last_addrman_save = 0;
    static int64_t      g_next_feeler_ms    = 0;
    static miq::FastRand g_am_rng{0xC0FFEEULL};
}
#endif

// ---- server creation: IPv4 and IPv6 ----------------------------------------
static Sock create_server(uint16_t port){
#ifdef _WIN32
    Sock s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    Sock s = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if (s == MIQ_INVALID_SOCK) return MIQ_INVALID_SOCK;
    miq_set_cloexec(s);
    miq_optimize_socket(s);  // Comprehensive socket optimization
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons(port);
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
#ifdef _WIN32
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&yes, sizeof(yes));
#endif
    if (bind(s, (sockaddr*)&a, sizeof(a)) != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    if (listen(s, SOMAXCONN) != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    (void)miq_set_nonblock(s);
    return s;
}
static Sock create_server_v6(uint16_t port){
#ifdef _WIN32
    Sock s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#else
    Sock s = socket(AF_INET6, SOCK_STREAM, 0);
#endif
    if (s == MIQ_INVALID_SOCK) return MIQ_INVALID_SOCK;
    miq_set_cloexec(s);
    miq_optimize_socket(s);  // Comprehensive socket optimization
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
#ifdef _WIN32
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&yes, sizeof(yes));
#endif
#ifdef IPV6_V6ONLY
    int v6only = 1;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6only, sizeof(v6only));
#endif
    sockaddr_in6 a6{}; a6.sin6_family = AF_INET6; a6.sin6_addr = in6addr_any; a6.sin6_port = htons(port);
    if (bind(s, (sockaddr*)&a6, sizeof(a6)) != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    if (listen(s, SOMAXCONN) != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    (void)miq_set_nonblock(s);
    (void)miq_set_nodelay(s);
    return s;
}

std::string P2P::hexkey(const std::vector<uint8_t>& h) {
    static const char* kHex = "0123456789abcdef";
    std::string s; s.resize(h.size()*2);
    for (size_t i=0;i<h.size();++i) {
        s[2*i+0] = kHex[(h[i]>>4) & 0xF];
        s[2*i+1] = kHex[(h[i]    ) & 0xF];
    }
    return s;
}

// IPv4 helpers
bool P2P::parse_ipv4(const std::string& dotted, uint32_t& be_ip){
    sockaddr_in tmp{};
#ifdef _WIN32
    if (InetPtonA(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#else
    if (inet_pton(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#endif
    be_ip = tmp.sin_addr.s_addr;
    return true;
}
[[maybe_unused]] static inline uint32_t be(uint8_t a, uint8_t b, uint8_t c, uint8_t d){
    return (uint32_t(a)<<24)|(uint32_t(b)<<16)|(uint32_t(c)<<8)|uint32_t(d);
}
bool P2P::ipv4_is_public(uint32_t be_ip){
    uint8_t A = uint8_t(be_ip>>24), B = uint8_t(be_ip>>16);
    uint8_t C = uint8_t(be_ip>>8);
    MIQ_MAYBE_UNUSED uint8_t D = uint8_t(be_ip>>0);
    (void)D;
    if (A == 0 || A == 10 || A == 127) return false;
    if (A == 169 && B == 254) return false;
    if (A == 192 && B == 168) return false;
    if (A == 172 && B >= 16 && B <= 31) return false; // correct 172.16/12 check
    if (A == 100 && (B >= 64 && B <= 127)) return false;
    if (A == 192 && B == 0 && C == 0) return false;
    if (A == 192 && B == 0 && C == 2) return false;
    if (A == 192 && B == 88 && C == 99) return false;
    if (A == 198 && (B == 18 || B == 19)) return false;
    if (A == 198 && B == 51 && C == 100) return false;
    if (A == 203 && B == 0 && C == 113) return false;
    if (A >= 224) return false;
    return true;
}

P2P::P2P(Chain& c) : chain_(c) {
    orphan_bytes_limit_  = (size_t)MIQ_ORPHAN_MAX_BYTES;
    orphan_count_limit_  = (size_t)MIQ_ORPHAN_MAX_COUNT;
    msg_deadline_ms_     = (int64_t)MIQ_PARSE_DEADLINE_MS;
}
P2P::~P2P(){ stop(); }

void P2P::load_bans(){
    std::ifstream f(datadir_ + "/bans.txt");
    if (!f) return;
    std::string line;
    const int64_t now_wall   = wall_ms();
    const int64_t now_steady = now_ms();
   while (std::getline(f, line)) {
        // strip comments and whitespace
        size_t hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        auto trim = [](std::string &s){
            size_t a=0,b=s.size();
            while (a<b && (unsigned char)s[a] <= ' ') ++a;
            while (b>a && (unsigned char)s[b-1] <= ' ') --b;
            s = s.substr(a,b-a);
        };
        trim(line);
        if (line.empty()) continue;

        // Supported formats:
        //   "1.2.3.4"                           -> permanent ban
        //   "1.2.3.4 UNTIL=1700000000000"       -> timed ban until epoch-ms
        std::string ip = line;
        int64_t until = 0;
        auto p = line.find("UNTIL=");
        if (p != std::string::npos) {
            ip = miq_trim(line.substr(0, p));
            const std::string val = line.substr(p + 6);
            char *end = nullptr;
            long long ms = std::strtoll(val.c_str(), &end, 10);
            if (end && (*end == 0 || *end == ' ')) until = (int64_t)ms;
        }
        if (until > now_wall) {
            timed_bans_[ip] = now_steady + (until - now_wall);
        } else {
            banned_.insert(ip);       // permanent (or expired timed ban → ignore timing)
        }
    }
}

void P2P::save_bans(){
    std::ofstream f(datadir_ + "/bans.txt", std::ios::trunc);
    if (!f) return;
    // Persist permanent bans only. Timed bans are in-memory and will expire.
    for (const auto& ip : banned_) {
        auto it = timed_bans_.find(ip);
        if (it == timed_bans_.end()) {
            f << ip << "\n";
        }
    }
}

void P2P::bump_ban(PeerState& ps, const std::string& ip, const char* reason, int64_t now_ms)
{
    // Do not ban localhost or whitelisted peers (never hairpin-ban loopback).
    if (is_loopback(ip) || is_whitelisted_ip(ip)) {
        P2P_TRACE(std::string("skip-ban loopback/whitelist ip=") + ip + " reason=" + (reason?reason:""));
        return;
    }

    if (ibd_or_fetch_active(ps, now_ms)) {
        P2P_TRACE(std::string("no-ban (sync-active) ip=") + ip + " reason=" + (reason?reason:""));
        // Still disconnect bad peers during sync, just don't ban them
        if (reason && (std::strstr(reason, "bad") || std::strstr(reason, "invalid"))) {
            schedule_close((Sock)ps.sock);
        }
        return;
    }
    
    timed_bans_[ip] = now_ms + default_ban_ms_;
    P2P_TRACE(std::string("ban set (timed) ip=") + ip +
              " ms_left=" + std::to_string((timed_bans_[ip] > now_ms) ? (timed_bans_[ip] - now_ms) : 0) +
              " reason=" + (reason?reason:""));
    // Defer close so the main loop handles unified close/erase
    schedule_close((Sock)ps.sock);
    (void)reason;
}

// Global IPv6 server socket for this TU (keeps p2p.h untouched)
static Sock g_srv6_ = MIQ_INVALID_SOCK;

bool P2P::start(uint16_t port){
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    
    g_chain_ptr = &chain_;
    
    g_logged_headers_started = false;
    g_logged_headers_done    = false;
    g_max_known_peer_tip.store(0);  // Reset max peer tip on start
    g_headers_tip_confirmed = 0;
    g_global_inflight_blocks.clear();
    g_inflight_block_ts.clear();
    g_rr_next_idx.clear();
    g_last_hdr_req_ms.clear();

    // BULLETPROOF SYNC: Clear global index tracking on start
    {
        InflightLock lk(g_inflight_lock);
        g_global_requested_indices.clear();
    }
    g_inflight_index_ts.clear();
    g_inflight_index_order.clear();

#ifdef MIQ_DEFAULT_PORT
    (void)MIQ_DEFAULT_PORT;
#endif

    load_bans();
    load_addrs_from_disk(datadir_, addrv4_);

#if MIQ_ENABLE_ADDRMAN
    g_addrman_path = datadir_ + "/" + std::string(MIQ_ADDRMAN_FILE);
    {
        std::string err;
        if (g_addrman.load(g_addrman_path, err)) {
            log_info("P2P: addrman loaded (" + std::to_string(g_addrman.size()) + " addrs)");
        } else {
            log_info("P2P: addrman load: " + err);
        }
        
        // Initialize with seed nodes if addrman is empty
        if (g_addrman.size() == 0) {
            log_info("P2P: addrman empty, adding hardcoded seeds");
            std::vector<miq::SeedEndpoint> seeds;
            if (miq::resolve_dns_seeds(seeds, P2P_PORT, true)) {
                for (const auto& s : seeds) {
                    uint32_t be_ip;
                    if (parse_ipv4(s.ip, be_ip) && ipv4_is_public(be_ip)) {
                        miq::NetAddr na;
                        na.host = s.ip;
                        na.port = s.port > 0 ? s.port : P2P_PORT;
                        na.is_ipv6 = false;
                        na.tried = false;
                        g_addrman.add(na, true);
                    }
                }
                log_info("P2P: added " + std::to_string(g_addrman.size()) + " seed addresses");
            }
        }
        
        g_last_addrman_save = now_ms();
        g_next_feeler_ms    = now_ms() + MIQ_FEELER_INTERVAL_MS;
    }
#endif

    // NOTE: srv_ is Sock; Windows-safe
    srv_ = create_server(port);
    if (srv_ == MIQ_INVALID_SOCK) {
        // CRITICAL FIX: Don't return early - continue so the loop thread starts.
        // This allows outbound connections even when we can't accept inbound connections.
        // Common when another instance is already running or port is in use.
        log_error("P2P: failed to create IPv4 server (port " + std::to_string(port) + " may be in use)");
        log_warn("P2P: continuing without inbound - outbound connections will still work");
    }
    // New: IPv6 server as well
    g_srv6_ = create_server_v6(port);
    if (g_srv6_ == MIQ_INVALID_SOCK) {
        log_warn("P2P: IPv6 server not created (continuing with IPv4 only)");
    }
    g_listen_port = port;

    g_last_progress_ms = now_ms();
    g_last_progress_height = chain_.height();
    g_stall_retry_ms = (int64_t)env_u64("MIQ_P2P_STALL_RETRY_MS", (uint64_t)MIQ_P2P_STALL_RETRY_MS);
    g_next_stall_probe_ms = g_last_progress_ms + g_stall_retry_ms;

    std::string ext_ip;
    {
        miq::TryOpenP2PPort(port, &ext_ip);
        if (!ext_ip.empty()) log_info("P2P: external IP (UPnP): " + ext_ip);
    }

    gather_self_ipv4_basic();
    if (!ext_ip.empty()) self_add_dotted(ext_ip);
    gather_self_from_env();
    if (!g_self_v4.empty()) {
        log_info("P2P: self-ip guard active: " + self_list_for_log());
      }
    if (!g_seed_mode) {
        g_seed_mode = env_truthy(MIQ_SEED_MODE_ENV);
    if (const char* seq = std::getenv("MIQ_SEQUENTIAL_SYNC")) {
        g_sequential_sync = (seq[0]=='1'||seq[0]=='y'||seq[0]=='Y'||seq[0]=='t'||seq[0]=='T');
    }
    if (!g_seed_mode && hostname_is_seed()) g_seed_mode = true;
    }

    {
        size_t dropped = 0;
        for (auto it = addrv4_.begin(); it != addrv4_.end(); ) {
            uint32_t be_ip = *it;
            if (!ipv4_is_public(be_ip) || is_loopback_be(be_ip) || is_self_be(be_ip)) {
                it = addrv4_.erase(it);
                ++dropped;
            } else {
                ++it;
            }
        }
        if (dropped) {
            log_warn("P2P: pruned " + std::to_string(dropped) +
                     " non-public/loopback/self addrs from legacy store");
        }
    }

    {
        std::vector<miq::SeedEndpoint> seeds;
        // NOTE: resolve_dns_seeds uses P2P_PORT (9883) as the default seed port, not our listen port
        if (miq::resolve_dns_seeds(seeds, P2P_PORT, /*include_single_dns_seed=*/true)) {
            size_t added = 0;
            for (const auto& s : seeds) {
                uint32_t be_ip;
                if (parse_ipv4(s.ip, be_ip) && ipv4_is_public(be_ip) && !is_self_be(be_ip)) {
                    added += addrv4_.insert(be_ip).second ? 1 : 0;
#if MIQ_ENABLE_ADDRMAN
                    miq::NetAddr na;
                    na.host = s.ip; na.port = P2P_PORT; na.is_ipv6 = false; na.tried = false;
                    g_addrman.add(na, /*from_dns=*/true);
#endif
                }
            }
            if (added) log_info("P2P: loaded " + std::to_string(added) + " seed addrs");
            size_t boots = std::min<size_t>(seeds.size(), 3);
            for (size_t i = 0; i < boots; ++i) {
                (void)connect_seed(seeds[i].ip, P2P_PORT);
            }
        } else {
            log_warn("P2P: no seeds resolved");
        }
    }

    running_ = true;

    th_ = std::thread([this]{
        for(;;){
            try {
                loop();
                break;
            } catch (const std::exception& e) {
                log_error(std::string("P2P: loop exception: ") + e.what());
            } catch (...) {
                log_error("P2P: loop exception (unknown)");
            }
            if(!running_) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });

    return true;
}

void P2P::stop(){
    if (!running_) return;
    running_ = false;

    // Close server sockets first to wake up poll() if it's blocking
    if (srv_ != MIQ_INVALID_SOCK) { CLOSESOCK(srv_); srv_ = MIQ_INVALID_SOCK; }
    if (g_srv6_ != MIQ_INVALID_SOCK) { CLOSESOCK(g_srv6_); g_srv6_ = MIQ_INVALID_SOCK; }

    // CRITICAL FIX: Join thread BEFORE modifying peers_ to prevent race condition
    // The main loop may still be accessing peers_ until it exits
    if (th_.joinable()) th_.join();

    // Now safe to modify peers_ since the thread has exited
    {
        std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
        for (auto& kv : peers_) {
            if (kv.first != MIQ_INVALID_SOCK) {
                gate_on_close(kv.first);
                CLOSESOCK(kv.first);
            }
        }
        peers_.clear();
    }
#ifdef _WIN32
    WSACleanup();
#endif
    save_bans();
    save_addrs_to_disk(datadir_, addrv4_);
#if MIQ_ENABLE_ADDRMAN
    {
        std::string err;
        if (!g_addrman.save(g_addrman_path, err)) {
            log_warn("P2P: addrman save failed: " + err);
        }
    }
#endif
}

static inline void reset_runtime_queues() {
    g_outbounds.clear();
    {
        std::lock_guard<std::mutex> lk(g_force_close_mu);
        g_force_close.clear();
    }
    g_rr_next_idx.clear();
    g_inflight_block_ts.clear();
    g_global_inflight_blocks.clear();
    g_trickle_q.clear();
    g_trickle_last_ms.clear();
    g_last_hdr_req_ms.clear();
    g_zero_hdr_batches.clear();
    g_hdr_flip.clear();
    g_peer_stalls.clear();
    g_last_hdr_ok_ms.clear();
    g_inflight_index_ts.clear();
    g_inflight_index_order.clear();
}

// === outbound connect helpers ===============================================

// REVISED: dual-stack + literal-safe resolver (non-blocking connect + timeout)
bool P2P::connect_seed(const std::string& host, uint16_t port){
    {
        int64_t now = now_ms();
        auto it = g_seed_backoff.find(host);
        if (it != g_seed_backoff.end() && it->second.first > now) {
            return false;
        }
    }

    // Check if we already have a connection to this host (prevent connection storm)
    std::vector<MiqEndpoint> eps;
    if (!miq_resolve_endpoints_from_string(host, port, eps)) {
        int64_t now = now_ms();
        auto &st = g_seed_backoff[host];
        int64_t cur = st.second > 0 ? st.second : seed_backoff_base_ms();
        cur = std::min<int64_t>(cur * 2, seed_backoff_max_ms());
        cur += jitter_ms(5000);
        st = { now + cur, cur };
        log_warn(std::string("P2P: DNS resolve failed: ") + host + " (backoff " + std::to_string(cur) + "ms)");
        return false;
    }

    // Check if we already have connections to any of the resolved IPs
    {
        std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
        for (const auto& ne : eps) {
            if (ne.ss.ss_family == AF_INET) {
                const sockaddr_in* a4 = reinterpret_cast<const sockaddr_in*>(&ne.ss);
                std::string resolved_ip = be_ip_to_string(a4->sin_addr.s_addr);

                // Check existing connections to this IP
                for (const auto& kv : peers_) {
                    if (kv.second.ip == resolved_ip) {
                        // Already connected to this IP, skip
                        return false;
                    }
                }
            }
        }
    }

    Sock s = MIQ_INVALID_SOCK;
    std::string peer_ip = "unknown";

    for (const auto& ne : eps) {
        // Skip obvious self/hairpin for IPv4 candidates (unless MIQ_FORCE_CLIENT=1 for testing)
        if (ne.ss.ss_family == AF_INET) {
            const sockaddr_in* a4 = reinterpret_cast<const sockaddr_in*>(&ne.ss);
            uint32_t be_ip = a4->sin_addr.s_addr;
            bool allow_loopback = std::getenv("MIQ_FORCE_CLIENT") != nullptr;
            if (!allow_loopback && (is_loopback_be(be_ip) || is_self_be(be_ip))) continue;
            if (banned_.count(be_ip_to_string(be_ip))) continue;
        }

        Sock ts = miq_connect_nb((const sockaddr*)&ne.ss, ne.len, MIQ_CONNECT_TIMEOUT_MS);
        if (ts == MIQ_INVALID_SOCK) {
            continue;
        }

        // Connected
        s = ts;
        peer_ip = miq_ntop_sockaddr(ne.ss);
        if (banned_.count(peer_ip) || is_ip_banned(peer_ip, now_ms())) {
            CLOSESOCK(s);
            s = MIQ_INVALID_SOCK;
            continue;
        }

        // Reject obvious hairpin on same port
        if (is_self_endpoint(s, g_listen_port)) {
            P2P_TRACE("reject hairpin outbound (seed)");
            CLOSESOCK(s);
            s = MIQ_INVALID_SOCK;
            continue;
        }
        break;
    }

    if (s == MIQ_INVALID_SOCK) {
        int64_t now = now_ms();
        auto &st = g_seed_backoff[host];
        int64_t cur = st.second > 0 ? st.second : seed_backoff_base_ms();
        cur = std::min<int64_t>(cur * 2, seed_backoff_max_ms());
        cur += jitter_ms(5000);
        st = { now + cur, cur };
        return false;
    }

    g_seed_backoff.erase(host);

    PeerState ps;
    ps.sock = s;
    ps.ip   = peer_ip;
    ps.mis  = 0;
    ps.last_ms = now_ms();
    ps.blk_tokens = MIQ_RATE_BLOCK_BURST;
    ps.tx_tokens  = MIQ_RATE_TX_BURST;
    ps.last_refill_ms = ps.last_ms;
    ps.inflight_hdr_batches = 0;
    ps.last_hdr_batch_done_ms = 0;
    ps.sent_getheaders = false;
    ps.rate.last_ms = ps.last_ms;
    ps.banscore = 0;
    ps.version = 0;
    ps.features = 0;
    ps.whitelisted = false;
    ps.total_blocks_received = 0;
    ps.total_block_delivery_time_ms = 0;
    ps.avg_block_delivery_ms = 30000; // sane initial expectation (30s)
    ps.blocks_delivered_successfully = 0;
    ps.blocks_failed_delivery = 0;
    ps.health_score = 1.0;
    ps.last_block_received_ms = 0;

    // CRITICAL: Hold g_peers_mu while modifying peers_ to prevent data race with loop thread
    {
        std::lock_guard<std::recursive_mutex> lk(g_peers_mu);

        // CRITICAL FIX: Check for duplicate IP AGAIN before adding
        // This prevents TOCTOU race where multiple threads pass the initial check,
        // connect in parallel, and both try to add the same IP
        for (const auto& kv : peers_) {
            if (kv.second.ip == peer_ip) {
                log_info("P2P: rejecting duplicate outbound connection to " + peer_ip);
                CLOSESOCK(s);
                return false;
            }
        }

        peers_[s] = ps;
        g_peer_index_capable[s] = false;
        g_trickle_last_ms[s] = 0;
        // mark as outbound for gating/diversity
        g_outbounds.insert(s);
    }

    uint32_t be_ip;
    if (parse_ipv4(ps.ip, be_ip) && ipv4_is_public(be_ip) && !is_self_be(be_ip)) {
        addrv4_.insert(be_ip);
#if MIQ_ENABLE_ADDRMAN
        miq::NetAddr na; na.host = ps.ip; na.port = port; na.tried = true; na.is_ipv6=false;
        g_addrman.mark_good(na);
        g_addrman.add_anchor(na);
#endif
    }

    log_info("Peer: connected → " + ps.ip);

    // CRITICAL: Track IP connection for reputation history
    record_ip_connect(ps.ip);

    // Gate first, then mark loopback (so flag actually sticks)
    gate_on_connect(s);
    if (parse_ipv4(ps.ip, be_ip)) {
        gate_set_loopback(s, is_loopback_be(be_ip));
    }

    miq_set_keepalive(s);
    auto version_payload = miq_build_version_payload((uint32_t)chain_.height());
    P2P_TRACE("TX " + ps.ip + " cmd=version len=" + std::to_string(version_payload.size()));
    auto msg = encode_msg("version", version_payload);
    bool sent = send_or_close(s, msg);
    if (sent) {
        log_info("P2P: sent version to " + ps.ip + " (payload=" + std::to_string(version_payload.size()) + " bytes)");
    } else {
        log_warn("P2P: FAILED to send version to " + ps.ip);
    }
    P2P_TRACE("TX " + ps.ip + " version send result=" + (sent ? "OK" : "FAILED"));

    return true;
}

static std::mt19937& rng(){
    static thread_local std::mt19937 gen{std::random_device{}()};
    return gen;
}

static bool violates_group_diversity(const std::unordered_map<Sock, miq::PeerState>& peers,
                                     uint32_t candidate_be_ip)
{
    // Count per /16 among current peers; cap outbounds per group to reduce eclipse risk.
    std::unordered_map<uint16_t,int> group_counts;

    auto parse_be_ipv4 = [](const std::string& dotted, uint32_t& be_ip)->bool{
        sockaddr_in tmp{};
    #ifdef _WIN32
        if (InetPtonA(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
    #else
        if (inet_pton(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
    #endif
        be_ip = tmp.sin_addr.s_addr; // network byte order
        return true;
    };

    for (const auto& kv : peers){
        if (!g_outbounds.count(kv.first)) continue;
        const auto& ps = kv.second;
        uint32_t be_ip2 = 0;
        if (!parse_be_ipv4(ps.ip, be_ip2)) continue;
        uint16_t g = (uint16_t(uint8_t(be_ip2>>24)) << 8) | uint16_t(uint8_t(be_ip2>>16));
        group_counts[g]++;
    }

    uint16_t cg = (uint16_t(uint8_t(candidate_be_ip>>24)) << 8) | uint16_t(uint8_t(candidate_be_ip>>16));
    auto it = group_counts.find(cg);
    return (it != group_counts.end() && it->second >= MIQ_GROUP_OUTBOUND_MAX);
}

void P2P::handle_new_peer(Sock c, const std::string& ip){
    // Check for duplicate IP to prevent same peer appearing twice
    {
        std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
        for (const auto& kv : peers_) {
            if (kv.second.ip == ip) {
                log_info("P2P: rejecting duplicate inbound connection from " + ip);
                CLOSESOCK(c);
                return;
            }
        }
    }

    PeerState ps{};
    ps.sock = c;
    ps.ip   = ip;
    ps.mis  = 0;
    ps.last_ms = now_ms();
    ps.blk_tokens = MIQ_RATE_BLOCK_BURST;
    ps.tx_tokens  = MIQ_RATE_TX_BURST;
    ps.last_refill_ms = ps.last_ms;
    ps.inflight_hdr_batches = 0;
    ps.last_hdr_batch_done_ms = 0;
    ps.sent_getheaders = false;
    ps.rate.last_ms = ps.last_ms;
    ps.banscore = 0;
    ps.version = 0;
    ps.features = 0;
    ps.whitelisted = false;
    ps.total_blocks_received = 0;
    ps.total_block_delivery_time_ms = 0;
    ps.avg_block_delivery_ms = 30000;
    ps.blocks_delivered_successfully = 0;
    ps.blocks_failed_delivery = 0;
    ps.health_score = 1.0;
    ps.last_block_received_ms = 0;

    // CRITICAL: Hold g_peers_mu while modifying peers_ to prevent data race with loop thread
    {
        std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
        peers_[c] = ps;
        g_peer_index_capable[c] = false;
        g_trickle_last_ms[c] = 0;
    }

    uint32_t be_ip;
    if (parse_ipv4(ip, be_ip) && ipv4_is_public(be_ip)) {
        addrv4_.insert(be_ip);
    #if MIQ_ENABLE_ADDRMAN
        miq::NetAddr na; na.host=ip; na.port=g_listen_port; na.is_ipv6=false; na.tried=false;
        g_addrman.add(na, /*from_dns=*/false);
    #endif
    }

    log_info("P2P: inbound peer " + ip);

    // CRITICAL: Track IP connection for reputation history
    record_ip_connect(ip);

    // Gate first, then mark loopback (critical for localhost wallet)
    gate_on_connect(c);
    if (parse_ipv4(ip, be_ip)) {
        gate_set_loopback(c, is_loopback_be(be_ip));
    }

    auto payload = miq_build_version_payload((uint32_t)chain_.height());
    auto msg = encode_msg("version", payload);
    if (msg.empty()) {
        log_warn("P2P: failed to encode version message for " + ip + " (payload size=" + std::to_string(payload.size()) + ")");
        schedule_close(c);
        return;
    }
    bool sent = send_or_close(c, msg);
    if (!sent) {
        log_warn("P2P: failed to send version to " + ip);
    } else {
        log_info("P2P: sent version to inbound peer " + ip);
    }
}

void P2P::broadcast_inv_block(const std::vector<uint8_t>& h){
    // ULTRA-FAST BLOCK PROPAGATION with BIP152 COMPACT BLOCKS
    // Goal: Sub-1-second network-wide propagation
    // Strategy:
    //   1. FIRST: Broadcast header (88 bytes) to ALL peers instantly
    //   2. THEN: Send compact block to BIP152 peers, full block to legacy
    //   - Header-first lets peers verify PoW and relay immediately
    //   - All sends happen in parallel outside locks

    // TIMING: Record relay time and log latency from block receive
    // PERF FIX: Only log timing when near-tip, not during IBD bulk download
    #if MIQ_TIMING_INSTRUMENTATION
    if (!miq::is_ibd_mode()) {
        g_timing_last_relay_ms.store(now_ms(), std::memory_order_relaxed);
        int64_t recv_time = g_timing_last_block_recv_ms.load(std::memory_order_relaxed);
        if (recv_time > 0) {
            int64_t relay_latency = now_ms() - recv_time;
            if (relay_latency < 5000) {  // Only log reasonable latencies
                log_info("[TIMING] Block recv→relay latency: " + std::to_string(relay_latency) + "ms");
            }
        }
    }
    #endif

    if (h.size() != 32) return;

    // Read the block from chain (outside lock)
    Block blk;
    std::vector<uint8_t> raw_block;
    bool have_block = false;
    {
        if (chain_.read_block_any(h, blk)) {
            raw_block = ser_block(blk);
            have_block = true;
        }
    }

    if (!have_block) {
        MIQ_LOG_WARN(miq::LogCategory::NET, "broadcast_inv_block: block not found");
        return;
    }

    // Collect ALL peer sockets under lock (fast)
    std::vector<Sock> all_sockets;
    std::vector<Sock> compact_sockets;
    std::vector<Sock> legacy_sockets;
    {
        std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
        all_sockets.reserve(peers_.size());
        compact_sockets.reserve(peers_.size());
        legacy_sockets.reserve(peers_.size());
        for (auto& kv : peers_) {
            if (kv.second.verack_ok) {
                all_sockets.push_back(kv.first);
                if (kv.second.compact_blocks_enabled && kv.second.compact_high_bandwidth) {
                    compact_sockets.push_back(kv.first);
                } else {
                    legacy_sockets.push_back(kv.first);
                }
            }
        }
    }

    // PHASE 1: INSTANT HEADER BROADCAST (88 bytes - fastest possible)
    // This lets ALL peers verify PoW and start relaying immediately
    // Serialize just the header
    std::vector<uint8_t> header_data;
    header_data.reserve(88);
    // Version (4 bytes LE)
    uint32_t ver = blk.header.version;
    header_data.push_back(ver & 0xff);
    header_data.push_back((ver >> 8) & 0xff);
    header_data.push_back((ver >> 16) & 0xff);
    header_data.push_back((ver >> 24) & 0xff);
    // Prev hash (32 bytes)
    header_data.insert(header_data.end(), blk.header.prev_hash.begin(), blk.header.prev_hash.end());
    // Merkle root (32 bytes)
    header_data.insert(header_data.end(), blk.header.merkle_root.begin(), blk.header.merkle_root.end());
    // Time (8 bytes LE)
    for (int i = 0; i < 8; ++i) header_data.push_back((blk.header.time >> (i * 8)) & 0xff);
    // Bits (4 bytes LE)
    header_data.push_back(blk.header.bits & 0xff);
    header_data.push_back((blk.header.bits >> 8) & 0xff);
    header_data.push_back((blk.header.bits >> 16) & 0xff);
    header_data.push_back((blk.header.bits >> 24) & 0xff);
    // Nonce (8 bytes LE)
    for (int i = 0; i < 8; ++i) header_data.push_back((blk.header.nonce >> (i * 8)) & 0xff);

    auto headers_msg = encode_msg("headers", header_data);
    int headers_sent = parallel_send_to_peers(all_sockets, headers_msg);

    // PHASE 2: Build and send full block data
    // Build compact block for BIP152 peers (dramatically smaller)
    std::vector<uint8_t> compact_msg;
    if (mempool_) {
        miq::CompactBlock cb = miq::CompactBlockBuilder::create(blk, *mempool_);
        auto compact_payload = miq::serialize_compact_block(cb);
        compact_msg = encode_msg("cmpctblock", compact_payload);
    }

    // Prepare full block message for legacy peers
    auto invb_msg = encode_msg("invb", h);
    std::vector<uint8_t> block_msg;
    if (!raw_block.empty() && raw_block.size() < 4 * 1024 * 1024) {
        block_msg = encode_msg("block", raw_block);
    }

    // PARALLEL BROADCAST to both groups simultaneously
    int compact_sent = 0;
    int legacy_sent = 0;

    // Send compact blocks to BIP152 high-bandwidth peers (tiny payload, very fast)
    if (!compact_msg.empty() && !compact_sockets.empty()) {
        compact_sent = parallel_send_to_peers(compact_sockets, compact_msg);
    }

    // Send full blocks to legacy peers
    if (!block_msg.empty() && !legacy_sockets.empty()) {
        legacy_sent = parallel_send_to_peers(legacy_sockets, block_msg);
    } else if (!legacy_sockets.empty()) {
        // Fallback to invb only if block too large
        legacy_sent = parallel_send_to_peers(legacy_sockets, invb_msg);
    }

    // PERF FIX: Only log relay stats when near-tip and we actually relayed to someone
    if (!miq::is_ibd_mode() && (headers_sent + compact_sent + legacy_sent) > 0) {
        MIQ_LOG_INFO(miq::LogCategory::NET, "ULTRA-FAST broadcast: headers=" +
            std::to_string(headers_sent) + " compact=" + std::to_string(compact_sent) +
            " legacy=" + std::to_string(legacy_sent) + " peers");
    }

    // Also queue for async processing (handles late-connecting peers)
    announce_block_async(h);
}

void P2P::announce_block_async(const std::vector<uint8_t>& h) {
    if (h.size() != 32) return;
    std::lock_guard<std::mutex> lk(announce_mu_);
    if (announce_blocks_q_.size() < 1024) {
        announce_blocks_q_.push_back(h);
    }
}

// =================== helpers for sync / serving ===================

// V1: Increased trickle queue from 4096 to 32768 for high-throughput tx relay
static constexpr size_t MIQ_TRICKLE_QUEUE_MAX = 32768;

static inline void trickle_enqueue(Sock sock, const std::vector<uint8_t>& txid){
    if (txid.size()!=32) return;
    // CRITICAL FIX: Acquire mutex to protect g_trickle_q from concurrent access
    std::lock_guard<std::mutex> lk(g_trickle_mu);
    auto& q = g_trickle_q[sock];
    if (q.size() < MIQ_TRICKLE_QUEUE_MAX) {
        q.push_back(txid);
    } else {
        // Log when trickle queue is full - this can cause transactions
        // to not propagate to specific peers
        MIQ_LOG_WARN(miq::LogCategory::NET, "trickle_enqueue: peer queue full (" +
                     std::to_string(MIQ_TRICKLE_QUEUE_MAX) + "), dropping tx announcement for sock=" + std::to_string(sock));
    }
}

void P2P::broadcast_inv_tx(const std::vector<uint8_t>& txid){
    if (txid.size()!=32) {
        MIQ_LOG_WARN(miq::LogCategory::NET, "broadcast_inv_tx: invalid txid size " + std::to_string(txid.size()));
        return;
    }

    // CRITICAL FIX: Get the raw tx data from tx_store_ for direct sending
    // This must be done BEFORE acquiring g_peers_mu to avoid lock order issues
    std::vector<uint8_t> raw_tx;
    std::string key = hexkey(txid);
    {
        std::lock_guard<std::mutex> tx_lk(tx_store_mu_);
        auto itx = tx_store_.find(key);
        if (itx != tx_store_.end()) {
            raw_tx = itx->second;
        }
    }

    // CRITICAL FIX: Send BOTH invtx AND full tx directly to all connected peers
    // This ensures immediate propagation without waiting for the gettx round-trip
    // The receiving peer will:
    // - Process invtx first (if it arrives first): mark as known, request via gettx
    // - Process tx first (if it arrives first): validate and accept to mempool
    // - If tx arrives after invtx request: accept and add to mempool
    // Either way, the transaction will be received and processed
    {
        std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
        auto invtx_msg = encode_msg("invtx", txid);
        std::vector<uint8_t> tx_msg;
        if (!raw_tx.empty()) {
            tx_msg = encode_msg("tx", raw_tx);
        }

        int inv_sent = 0;
        int tx_sent = 0;
        for (auto& kv : peers_) {
            if (kv.second.verack_ok) {
                // Send invtx announcement
                if (send_or_close(kv.first, invtx_msg)) {
                    inv_sent++;
                }
                // CRITICAL: Also send the full transaction directly
                // This bypasses the invtx→gettx→tx round-trip entirely
                if (!tx_msg.empty()) {
                    if (send_or_close(kv.first, tx_msg)) {
                        tx_sent++;
                    }
                }
            }
        }
        if (inv_sent > 0 || tx_sent > 0) {
            MIQ_LOG_DEBUG(miq::LogCategory::NET, "broadcast_inv_tx: sent invtx to " +
                std::to_string(inv_sent) + " peers, tx directly to " + std::to_string(tx_sent) + " peers");
        }
    }

    // Also queue for trickle broadcast (handles peers that connect later, rebroadcast, etc.)
    {
        std::lock_guard<std::mutex> lk(tx_store_mu_);

        // FIX: Increased queue limit with FIFO eviction instead of dropping
        if (announce_tx_q_.size() >= MIQ_TX_ANNOUNCE_QUEUE_MAX) {
            size_t to_evict = MIQ_TX_ANNOUNCE_QUEUE_EVICT_BATCH;
            if (to_evict > announce_tx_q_.size()) to_evict = announce_tx_q_.size();
            announce_tx_q_.erase(announce_tx_q_.begin(), announce_tx_q_.begin() + to_evict);
        }

        announce_tx_q_.push_back(txid);
    }
}

// =============================================================================
// V1.0 CRITICAL FIX: Thread-safe transaction storage for relay
// =============================================================================
// This function is called from RPC threads (sendrawtransaction, sendtoaddress)
// to store raw transaction data so it can be served to peers when they request
// it via gettx after receiving our invtx announcement.
//
// THREAD SAFETY: Uses tx_store_mu_ to protect ALL transaction data structures.
// The P2P loop also acquires this lock when accessing these structures.
//
// REBROADCAST: Adds transaction to pending_txids_ for automatic rebroadcast
// if it doesn't get confirmed within REBROADCAST_DELAY_MS.
// =============================================================================
void P2P::store_tx_for_relay(const std::vector<uint8_t>& txid, const std::vector<uint8_t>& raw_tx){
    if (txid.size() != 32 || raw_tx.empty()) {
        MIQ_LOG_WARN(miq::LogCategory::NET, "store_tx_for_relay: invalid params, txid_size=" +
            std::to_string(txid.size()) + " raw_tx_size=" + std::to_string(raw_tx.size()));
        return;
    }

    std::string key;
    key.reserve(64);
    static const char hex[] = "0123456789abcdef";
    for (uint8_t b : txid) {
        key.push_back(hex[b >> 4]);
        key.push_back(hex[b & 0xf]);
    }

    // V1.0 CRITICAL FIX: Use unified tx_store_mu_ for thread safety
    // This lock protects: announce_tx_q_, seen_txids_, tx_store_, tx_order_, pending_txids_
    std::lock_guard<std::mutex> lk(tx_store_mu_);

    // Store raw transaction for serving to peers via gettx
    bool is_new = (tx_store_.find(key) == tx_store_.end());
    if (is_new) {
        tx_store_[key] = raw_tx;
        tx_order_.push_back(key);
        MIQ_LOG_DEBUG(miq::LogCategory::NET, "store_tx_for_relay: stored tx " + key.substr(0, 16) +
            "... size=" + std::to_string(raw_tx.size()) + " store_count=" + std::to_string(tx_store_.size()));
        // Enforce LRU eviction
        if (tx_store_.size() > MIQ_TX_STORE_MAX) {
            auto victim = tx_order_.front();
            tx_order_.pop_front();
            tx_store_.erase(victim);
            // Also remove from pending if evicted
            pending_txids_.erase(victim);
            MIQ_LOG_DEBUG(miq::LogCategory::NET, "store_tx_for_relay: evicted old tx " + victim.substr(0, 16) + "...");
        }
    }

    // Mark as seen so we don't process it again if a peer relays it back
    seen_txids_.insert(key);

    // V1.0 ENHANCEMENT: Add to pending for rebroadcast tracking
    // This ensures transactions get rebroadcast if they don't propagate
    if (pending_txids_.find(key) == pending_txids_.end() && pending_txids_.size() < MAX_PENDING_TXS) {
        PendingTxInfo info;
        info.txid = txid;
        info.raw_tx = raw_tx;
        info.first_broadcast_ms = now_ms();
        info.last_broadcast_ms = now_ms();
        info.broadcast_count = 1;
        pending_txids_[key] = std::move(info);
        MIQ_LOG_DEBUG(miq::LogCategory::NET, "store_tx_for_relay: added tx to rebroadcast pending, pending_count=" +
            std::to_string(pending_txids_.size()));
    }
}

static void trickle_flush(){
    int64_t tnow = now_ms();
    // CRITICAL FIX: Acquire mutex to protect g_trickle_q from concurrent access
    std::lock_guard<std::mutex> lk(g_trickle_mu);
    for (auto& kv : g_trickle_q) {
        Sock s = kv.first;
        auto& q = kv.second;

        // CRITICAL FIX: Skip empty queues entirely - don't update timestamp
        // This prevents delays when new items are added after an empty flush
        if (q.empty()) continue;

        int64_t last = 0;
        auto it_last = g_trickle_last_ms.find(s);
        if (it_last != g_trickle_last_ms.end()) last = it_last->second;

        if (tnow - last < MIQ_P2P_TRICKLE_MS) continue;

        size_t n_send = 0;
        while (!q.empty() && n_send < MIQ_P2P_TRICKLE_BATCH) {
            const auto& txid = q.back();
            auto m = miq::encode_msg("invtx", txid);
            if (send_or_close(s, m)) {
                q.pop_back();
                ++n_send;
            } else {
                break; // scheduled for close; stop emitting
            }
        }
        // CRITICAL FIX: Only update timestamp if we actually sent something
        if (n_send > 0) {
            g_trickle_last_ms[s] = tnow;
        }
    }
}

// CRITICAL FIX: request_tx now returns bool to indicate success
// This allows callers to know if the gettx was actually sent
bool P2P::request_tx(PeerState& ps, const std::vector<uint8_t>& txid){
    if (txid.size()!=32) {
        MIQ_LOG_WARN(miq::LogCategory::NET, "request_tx: invalid txid size " + std::to_string(txid.size()));
        return false;
    }
    if (!check_rate(ps, "get", 1.0, now_ms())) {
        MIQ_LOG_DEBUG(miq::LogCategory::NET, "request_tx: rate limited for peer " + ps.ip);
        return false;
    }
    const size_t max_inflight_tx = caps_.max_txs ? caps_.max_txs : (size_t)128;
    if (ps.inflight_tx.size() >= max_inflight_tx) {
        MIQ_LOG_DEBUG(miq::LogCategory::NET, "request_tx: max inflight (" + std::to_string(max_inflight_tx) +
            ") reached for peer " + ps.ip + ", cannot request tx");
        return false;
    }
    auto m = encode_msg("gettx", txid);
    if (send_or_close(ps.sock, m)) {
        std::string key = hexkey(txid);
        ps.inflight_tx.insert(key);
        // CRITICAL FIX: Track request timestamp for timeout cleanup
        g_inflight_tx_ts[(Sock)ps.sock][key] = now_ms();
        return true;
    }
    return false;
}

void P2P::send_tx(Sock sock, const std::vector<uint8_t>& raw){
    if (raw.empty()) return;
    auto m = encode_msg("tx", raw);
    (void)send_or_close(sock, m);
}

void P2P::start_sync_with_peer(PeerState& ps){
    // FAST PARALLEL SYNC with header-height safety
    //
    // Strategy: Headers AND blocks download in PARALLEL for speed
    // 1. Request headers to build the header chain
    // 2. ALSO start block sync immediately (limited by header height)
    // 3. fill_index_pipeline caps at best_header_height for safety
    //
    // This gives us SPEED (parallel) + SAFETY (header-limited blocks)

#if MIQ_ENABLE_HEADERS_FIRST
    if (!g_logged_headers_done) {
        // Request headers from peer
        std::vector<std::vector<uint8_t>> locator;
        chain_.build_locator(locator);
        if (g_hdr_flip[(Sock)ps.sock]) {
            for (auto& h : locator) std::reverse(h.begin(), h.end());
        }
        std::vector<uint8_t> stop(32, 0);
        auto pl2 = build_getheaders_payload(locator, stop);
        auto m2  = encode_msg("getheaders", pl2);
        int pushed = 0;
        // AGGRESSIVE: No rate limiting on headers during IBD - blast them all!
        while (can_accept_hdr_batch(ps, now_ms()) &&
               pushed < MIQ_HDR_PIPELINE) {
            ps.sent_getheaders = true;
            (void)send_or_close(ps.sock, m2);
            ps.inflight_hdr_batches++;
            g_last_hdr_req_ms[(Sock)ps.sock] = now_ms();
            ps.last_hdr_batch_done_ms        = now_ms();
            ++pushed;
        }
        if (!g_logged_headers_started) {
            g_logged_headers_started = true;
            log_info("[IBD] headers phase started - blocks downloading in parallel");
            if (!g_ibd_headers_started_ms) g_ibd_headers_started_ms = now_ms();

            // State machine transition: CONNECTING → HEADERS
            miq::ibd::IBDState::instance().transition_to(miq::ibd::SyncState::HEADERS);
        }
        // DON'T return - fall through to also start block sync!
    }
#endif

    // Start block sync (runs in parallel with headers)
    // fill_index_pipeline will cap at best_header_height for safety
    g_peer_index_capable[(Sock)ps.sock] = true;
    ps.syncing = true;
    if (ps.inflight_index == 0) {
        ps.next_index = chain_.height() + 1;
    }
    fill_index_pipeline(ps);
}

void P2P::fill_index_pipeline(PeerState& ps){
    // BULLETPROOF SYNC: Fast parallel block downloads
    // Security is maintained through block hash validation in handle_incoming_block()

    // IBD DIAGNOSTICS: Track early gate returns
    static int64_t last_diag_ms = 0;
    static uint64_t fill_calls = 0;
    static uint64_t requests_sent = 0;
    fill_calls++;

    // Use adaptive pipeline size based on peer reputation
    uint32_t pipe;
    if (g_sequential_sync) {
        pipe = 1u;
    } else {
        // Update reputation and adaptive batch size
        update_peer_reputation(ps);
        update_adaptive_batch_size(ps);

        // Use adaptive batch size, but cap at MIQ_INDEX_PIPELINE
        pipe = std::min(ps.adaptive_batch_size, (uint32_t)MIQ_INDEX_PIPELINE);
    }

    // peer_is_index_capable is set by start_sync_with_peer
    if (!peer_is_index_capable((Sock)ps.sock)) {
        g_diag_fill_blocked_not_capable++;
        return;
    }

    // FORK HANDLING: If peer has a different chain, check if theirs is LONGER
    // If they have more blocks, we should sync from them to enable reorg
    // Only skip if they have fewer/equal blocks (truly on inferior fork)
    if (ps.fork_detected) {
        // Check if peer has longer chain (more work)
        uint64_t our_height = chain_.height();
        uint64_t peer_height = ps.peer_tip_height;
        if (peer_height <= our_height) {
            g_diag_fill_blocked_fork++;
            return;
        }
        // Peer has longer chain - continue syncing for potential reorg
        P2P_TRACE("Forked peer " + ps.ip + " has longer chain (" +
                  std::to_string(peer_height) + " > " + std::to_string(our_height) +
                  ") - continuing sync for reorg");
    }

    // CRITICAL: Don't sync from peers pending fork verification!
    // We must verify they're on the same chain before downloading blocks
    if (ps.fork_verification_pending) {
        g_diag_fill_blocked_pending_verify++;
        return;
    }

    // NON-RESPONSIVE PEER DETECTION: Skip peers that have high inflight but 0 delivered
    // This prevents wasting request slots on dead peers that accept connections but never respond
    // Give new peers a chance (first 64 requests) before applying this filter
    if (ps.inflight_index >= 64 && ps.blocks_delivered_successfully == 0) {
        // Peer has 64+ requests pending but hasn't delivered a single block
        // Likely a dead or misbehaving peer - skip sending more requests
        return;
    }

    // QUALITY-BASED THROTTLING: Limit inflight to low-quality peers
    // If a peer has delivered some blocks but has poor success rate, reduce pipeline
    if (ps.blocks_delivered_successfully > 0 && ps.blocks_failed_delivery > ps.blocks_delivered_successfully) {
        // More failures than successes - limit pipeline to 32 to prevent wasting slots
        if (ps.inflight_index >= 32) {
            return;
        }
    }

    // SYNC STATE FIX: Ensure next_index is consistent with current chain height
    const uint64_t current_height = chain_.height();
    if (ps.next_index <= current_height) {
        ps.next_index = current_height + 1;
        P2P_TRACE("DEBUG: Sync state corrected - next_index updated from " +
                  std::to_string(ps.next_index - 1) + " to " + std::to_string(ps.next_index) +
                  " (chain height=" + std::to_string(current_height) + ")");
    }

    // Backpressure - don't request too far ahead of current tip
    // This prevents orphan pool overflow when blocks arrive out of order.
    const uint64_t max_ahead = orphan_count_limit_ / 2;
    uint64_t max_index = current_height + max_ahead;

    // Determine the limit for block requests from this peer
    // CRITICAL FIX: Use the MAXIMUM of ALL known chain heights!
    // This prevents stalls when any single source has a low/wrong value
    const uint64_t best_hdr = chain_.best_header_height();
    const uint64_t max_peer = g_max_known_peer_tip.load();
    uint64_t peer_limit;

    // Use MAX of: header height, this peer's tip, global max peer tip
    // This ensures we NEVER artificially limit requests due to one bad value
    peer_limit = best_hdr;
    if (ps.peer_tip_height > peer_limit) {
        peer_limit = ps.peer_tip_height;
    }
    if (max_peer > peer_limit) {
        peer_limit = max_peer;
    }

    // Fallback if all sources are 0 - use aggressive window
    if (peer_limit == 0) {
        peer_limit = current_height + max_ahead;
    }

    // Don't request from peers that are clearly behind us
    // But use a generous margin - peer might still have some blocks
    if (peer_limit + 100 < current_height) {
        P2P_TRACE("DEBUG: Skipping block requests from " + ps.ip +
                  " - peer_limit=" + std::to_string(peer_limit) +
                  " our_height=" + std::to_string(current_height));
        return;
    }

    max_index = std::min(max_index, peer_limit);

    // IBD DIAG: Track fill loop stats
    uint32_t loop_requests = 0;

    while (ps.inflight_index < pipe) {
        uint64_t idx = ps.next_index;

        // Backpressure: Stop if we're too far ahead of the tip or beyond header height
        if (idx > max_index) {
            if (loop_requests == 0) g_diag_fill_blocked_max_index++;
            break;
        }

        // BULLETPROOF SYNC: Skip if this index is already being requested by another peer
        // This prevents duplicate requests that waste bandwidth and create duplicate orphans
        // FORCE-COMPLETION: In force mode, allow duplicate requests for faster completion
        // STALL FIX: Allow speculative parallel requests after SPECULATIVE_REQUEST_DELAY_MS
        // This prevents stalls when one peer is slow - another peer can start helping
        {
            InflightLock lk(g_inflight_lock);
            const bool force_mode = g_force_completion_mode.load(std::memory_order_relaxed);

            if (!force_mode && g_global_requested_indices.count(idx)) {
                // Check if the original request is stale (taking too long)
                auto ts_it = g_global_requested_indices_ts.find(idx);
                bool allow_speculative = false;
                if (ts_it != g_global_requested_indices_ts.end()) {
                    int64_t age_ms = now_ms() - ts_it->second;
                    if (age_ms >= SPECULATIVE_REQUEST_DELAY_MS) {
                        // Original request is stale - allow speculative parallel request
                        allow_speculative = true;
                    }
                }

                if (!allow_speculative) {
                    g_diag_fill_blocked_already_requested++;
                    // Another peer is already fetching this index, skip to next
                    ps.next_index++;
                    continue;
                }
                // Allow speculative request - don't increment next_index, send the request
            }
        }

        // Check if we should skip this index (already have it or exceeds limits)
        // These are NOT errors - just skip to next index
        // CRITICAL FIX: Only stop at header height if we're TRULY done with headers
        // Use g_max_known_peer_tip as a sanity check to avoid stopping too early
        const uint64_t hdr_height = chain_.best_header_height();
        const uint64_t max_tip = g_max_known_peer_tip.load();
        if (g_logged_headers_done && hdr_height > 0 && idx > hdr_height) {
            // Only stop if header height >= max peer tip (we're truly at the tip)
            // Otherwise, headers might not have fully synced yet
            if (max_tip == 0 || hdr_height >= max_tip) {
                break;
            }
            // Headers not fully synced - continue requesting up to max_tip
        }
        if (idx <= chain_.height()) {
            // Already have this block - skip to next
            ps.next_index++;
            continue;
        }

        // Actually send the request
        if (request_block_index(ps, idx)) {
            ps.next_index++;
            ps.inflight_index++;
            g_diag_blocks_requested++;
            loop_requests++;
        } else {
            // Send failed - stop requesting from this peer (socket issue)
            break;
        }
    }

    // Track if we exited because pipe was full (couldn't request anything)
    if (loop_requests == 0 && ps.inflight_index >= pipe) {
        g_diag_fill_blocked_pipe_full++;
    }
}

bool P2P::request_block_index(PeerState& ps, uint64_t index){
    // PERFORMANCE: During IBD, allow requesting beyond header height for parallel sync
    // Blocks will be validated when headers catch up - they wait in orphan pool
    // Only enforce header cap AFTER headers phase is complete
    const uint64_t hdr_height = chain_.best_header_height();
    const uint64_t max_tip = g_max_known_peer_tip.load();
    if (g_logged_headers_done && hdr_height > 0 && index > hdr_height) {
        // CRITICAL FIX: Only block if headers are truly complete
        // If max_peer_tip > hdr_height, headers haven't fully synced yet
        if (max_tip == 0 || hdr_height >= max_tip) {
            P2P_TRACE("BLOCKED: request_block_index(" + std::to_string(index) +
                      ") exceeds header height " + std::to_string(hdr_height));
            return false;
        }
        // Allow request - headers are incomplete
    }

    // Also don't request blocks we already have
    if (index <= chain_.height()) {
        P2P_TRACE("SKIP: request_block_index(" + std::to_string(index) +
                  ") - already have this block");
        return false;
    }

    // ================================================================
    // INVARIANT D: PREFER HASH-BASED REQUESTS
    // ================================================================
    // When we have the header for this index, use hash-based request (getb)
    // instead of index-based request (getbi). Hash-based is more reliable:
    // - Works across forks (same hash = same block)
    // - Peer can't lie about having a block at an index
    // - Falls back to getbi ONLY when header is unavailable
    // ================================================================
    if (index <= hdr_height && hdr_height > 0) {
        // We have the header - get the block hash and use hash-based request
        std::vector<uint8_t> block_hash;
        if (chain_.get_header_hash_at_height(index, block_hash)) {
            // Use hash-based request - much more reliable
            const std::string key = hexkey(block_hash);
            const bool force_mode = g_force_completion_mode.load(std::memory_order_relaxed);

            // Track as global request (by index for dedup)
            {
                InflightLock lk(g_inflight_lock);
                if (!force_mode && g_global_requested_indices.count(index)) {
                    // Check if we should allow speculative request (stale original)
                    auto ts_it = g_global_requested_indices_ts.find(index);
                    if (ts_it == g_global_requested_indices_ts.end() ||
                        (now_ms() - ts_it->second) < SPECULATIVE_REQUEST_DELAY_MS) {
                        return false;  // Already being requested and not stale
                    }
                    // Stale - allow speculative request (don't insert again, just update ts)
                }
                g_global_requested_indices.insert(index);
                g_global_requested_indices_ts[index] = now_ms();  // STALL FIX: Track request time
            }

            // Use hash-based request
            auto msg = encode_msg("getb", block_hash);
            if (send_or_close(ps.sock, msg)) {
                ps.inflight_blocks.insert(key);
                g_global_inflight_blocks.insert(key);
                g_inflight_index_ts[(Sock)ps.sock][index] = now_ms();
                g_inflight_index_order[(Sock)ps.sock].push_back(index);
                P2P_TRACE("TX " + ps.ip + " getb (hash-based) for index " + std::to_string(index));
                return true;
            }
            // Send failed - remove from tracking
            {
                InflightLock lk(g_inflight_lock);
                clear_global_requested_index(index);
            }
            return false;
        }
    }

    // ================================================================
    // BITCOIN CORE ALIGNMENT: NO getbi FALLBACK
    // ================================================================
    // We NEVER request blocks by index. If we don't have the header,
    // we wait for the headers phase to complete. This ensures:
    // 1. All block requests are hash-based (deterministic)
    // 2. We can verify received blocks match expected hash
    // 3. Fork detection works correctly
    // 4. Sync behavior is identical across runs
    // ================================================================
    static int64_t last_header_wait_log_ms = 0;
    int64_t now = now_ms();
    if (now - last_header_wait_log_ms > 5000) {
        last_header_wait_log_ms = now;
        log_info("[SYNC] Waiting for headers at height " + std::to_string(index) +
                 " (current header_height=" + std::to_string(hdr_height) +
                 ") - hash-based requests only");
    }
    return false;
}

void P2P::request_block_hash(PeerState& ps, const std::vector<uint8_t>& h){
    if (h.size()!=32) return;

    const std::string key = hexkey(h);
    const bool force_mode = g_force_completion_mode.load(std::memory_order_relaxed);

    // FORCE-COMPLETION: In force mode, allow duplicate requests to multiple peers
    // Otherwise, skip if already being fetched globally
    if (!force_mode && g_global_inflight_blocks.count(key)) return;

    // FORCE-COMPLETION: In force mode, double the inflight limit
    size_t base_default = g_sequential_sync ? (size_t)1 : (size_t)256;
    size_t max_inflight_blocks = caps_.max_blocks ? caps_.max_blocks : base_default;
    if (force_mode) max_inflight_blocks *= 2;

    // CRITICAL FIX: If this peer's queue is full, try another peer instead of dropping
    if (ps.inflight_blocks.size() >= max_inflight_blocks) {
        // Find another peer with available capacity
        for (auto& kvp : peers_) {
            if (kvp.first == (Sock)ps.sock) continue;
            if (!kvp.second.verack_ok) continue;
            // FORCE-COMPLETION: In force mode, request even from peers at capacity
            if (!force_mode && kvp.second.inflight_blocks.size() >= max_inflight_blocks) continue;
            // Found a peer - request from them
            auto msg = encode_msg("getb", h);
            if (send_or_close(kvp.first, msg)) {
                kvp.second.inflight_blocks.insert(key);
                mark_block_inflight(key, kvp.first);
                P2P_TRACE_IF(true, "Requested block " + key.substr(0, 16) + "... from alternate peer" +
                            (force_mode ? " (force-completion)" : " (original full)"));
                return;
            }
        }
        // FORCE-COMPLETION: In force mode, proceed anyway even if peer is at capacity
        if (force_mode) {
            auto msg = encode_msg("getb", h);
            if (send_or_close(ps.sock, msg)) {
                ps.inflight_blocks.insert(key);
                mark_block_inflight(key, (Sock)ps.sock);
                P2P_TRACE("FORCE-COMPLETION: Requested block " + key.substr(0, 16) + "... despite capacity");
                return;
            }
        }
        // No peer available - block request is dropped (unavoidable)
        P2P_TRACE("WARNING: Block request dropped - all peers at capacity: " + key.substr(0, 16));
        return;
    }

    auto msg = encode_msg("getb", h);
    if (send_or_close(ps.sock, msg)) {
        ps.inflight_blocks.insert(key);
        mark_block_inflight(key, (Sock)ps.sock);
        P2P_TRACE_IF(true, "Requested block " + key.substr(0, 16) + "... from peer");
    }
}

void P2P::send_block(Sock s, const std::vector<uint8_t>& raw){
    if (raw.empty()) {
        P2P_TRACE("DEBUG: send_block called with empty raw data");
        return;
    }
    auto msg = encode_msg("block", raw);
    P2P_TRACE("DEBUG: Sending block message, raw_size=" + std::to_string(raw.size()) + " encoded_size=" + std::to_string(msg.size()));
    bool result = send_or_close(s, msg);
    (void)result; // Used by P2P_TRACE when enabled
    P2P_TRACE("DEBUG: send_block result=" + std::string(result ? "OK" : "FAILED"));
}

// Send "notfound by index" response when we cannot serve a requested block
// This allows the requesting peer to immediately retry with another peer
// instead of waiting for timeout.
void P2P::send_notfound_index(Sock s, uint64_t idx) {
    uint8_t p[8];
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((idx >> (8 * i)) & 0xFF);
    }
    auto msg = encode_msg("nfbi", std::vector<uint8_t>(p, p + 8));
    P2P_TRACE("DEBUG: Sending notfound for index " + std::to_string(idx));
    (void)send_or_close(s, msg);
}

// === rate-limit helpers ======================================================

void P2P::rate_refill(PeerState& ps, int64_t now){
    int64_t dt = now - ps.last_refill_ms;
    if (dt <= 0) return;
    uint64_t add_blk = (uint64_t)((MIQ_RATE_BLOCK_BPS * (uint64_t)dt) / 1000ull);
    uint64_t add_tx  = (uint64_t)((MIQ_RATE_TX_BPS    * (uint64_t)dt) / 1000ull);
    ps.blk_tokens = std::min<uint64_t>(MIQ_RATE_BLOCK_BURST, ps.blk_tokens + add_blk);
    ps.tx_tokens  = std::min<uint64_t>(MIQ_RATE_TX_BURST,   ps.tx_tokens  + add_tx);
    ps.last_refill_ms = now;
}

bool P2P::rate_consume_block(PeerState& ps, size_t nbytes){
    int64_t n = now_ms();
    rate_refill(ps, n);
    if (ps.blk_tokens < nbytes) {
        ps.blk_tokens = 0; // clamp to zero (soft debt); do not reject the block
        return true;
    } else {
        ps.blk_tokens -= (uint64_t)nbytes;
        return true;
    }
}
bool P2P::rate_consume_tx(PeerState& ps, size_t nbytes){
    int64_t n = now_ms();
    rate_refill(ps, n);
    // v10.0 FIX: Be more lenient with transaction rate limiting
    // Instead of rejecting transactions when out of tokens, allow "soft debt"
    // This matches the block rate limiter behavior and prevents transaction drops
    // from legitimate high-volume wallets
    if (ps.tx_tokens < nbytes) {
        ps.tx_tokens = 0;  // Allow soft debt like blocks
        return true;       // Don't reject the transaction
    }
    ps.tx_tokens -= (uint64_t)nbytes;
    return true;
}

// === addr handling ===========================================================

void P2P::maybe_send_getaddr(PeerState& ps){
    int64_t t = now_ms();
    // Allow first ever send immediately; then rate-limit
    if (ps.last_getaddr_ms != 0 &&
        (t - ps.last_getaddr_ms) < (int64_t)MIQ_P2P_GETADDR_INTERVAL_MS) return;
    auto msg = encode_msg("getaddr", {});
    if (check_rate(ps, "get", 1.0, t)) {
        (void)send_or_close(ps.sock, msg);
        ps.last_getaddr_ms = t;
    }
}

void P2P::send_addr_snapshot(PeerState& ps){
    if (!check_rate(ps, "addr", 1.0, now_ms())) return;
    std::vector<uint8_t> payload;
    payload.reserve(MIQ_ADDR_RESPONSE_MAX * 4);
    size_t cnt = 0;

#if MIQ_ENABLE_ADDRMAN
    {
        std::unordered_set<uint32_t> emitted;
        for (int tries = 0; tries < (int)(MIQ_ADDR_RESPONSE_MAX * 3) && cnt < MIQ_ADDR_RESPONSE_MAX; ++tries) {
            auto cand = g_addrman.select_for_outbound(g_am_rng, /*prefer_tried=*/true);
            if (!cand) break;
            uint32_t be_ip;
            if (!parse_ipv4(cand->host, be_ip) || !ipv4_is_public(be_ip)) continue;

            if (!emitted.insert(be_ip).second) continue;

            payload.push_back((uint8_t)(be_ip >> 24));
            payload.push_back((uint8_t)(be_ip >> 16));
            payload.push_back((uint8_t)(be_ip >> 8));
            payload.push_back((uint8_t)(be_ip >> 0));
            ++cnt;
        }
    }
#endif

    for (uint32_t be_ip : addrv4_) {
        if (cnt >= MIQ_ADDR_RESPONSE_MAX) break;
        if (!ipv4_is_public(be_ip)) continue;
        payload.push_back((uint8_t)(be_ip >> 24));
        payload.push_back((uint8_t)(be_ip >> 16));
        payload.push_back((uint8_t)(be_ip >> 8));
        payload.push_back((uint8_t)(be_ip >> 0));
        ++cnt;
    }
    auto msg = encode_msg("addr", payload);
    (void)send_or_close(ps.sock, msg);
}
void P2P::handle_addr_msg(PeerState& ps, const std::vector<uint8_t>& payload){
    int64_t t = now_ms();
    if (ps.last_addr_ms != 0 &&
        (t - ps.last_addr_ms) < (int64_t)MIQ_ADDR_MIN_INTERVAL_MS) {
        if (++ps.mis > 20) { bump_ban(ps, ps.ip, "addr-interval", t); }
        return;
    }
    ps.last_addr_ms = t;

    if (!check_rate(ps, "addr", std::max(1.0, (double)(payload.size()/64u)), t)) {
        if (!ibd_or_fetch_active(ps, t)) {
            bump_ban(ps, ps.ip, "addr-flood", t);
        }
        return;
    }

    if (payload.size() % 4 != 0) return;
    size_t n = payload.size() / 4;
    if (n > MIQ_ADDR_MAX_BATCH) n = MIQ_ADDR_MAX_BATCH;

    size_t accepted = 0;
    for (size_t i=0;i<n;i++){
        uint32_t be_ip =
            (uint32_t(payload[4*i+0])<<24) |
            (uint32_t(payload[4*i+1])<<16) |
            (uint32_t(payload[4*i+2])<<8 ) |
            (uint32_t(payload[4*i+3])<<0 );
        if (!ipv4_is_public(be_ip)) continue;
        addrv4_.insert(be_ip);
#if MIQ_ENABLE_ADDRMAN
        char buf[64]={0};
        sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=be_ip;
#ifdef _WIN32
        InetNtopA(AF_INET, &a.sin_addr, buf, (int)sizeof(buf));
#else
        inet_ntop(AF_INET, &a.sin_addr, buf, (socklen_t)sizeof(buf));
#endif
        miq::NetAddr na; na.host=buf; na.port=g_listen_port; na.is_ipv6=false; na.tried=false;
        g_addrman.add(na, /*from_dns=*/false);
#endif
        ++accepted;
    }
    if (accepted == 0) {
        if (!ibd_or_fetch_active(ps, now_ms())) {
            if (++ps.mis > 30) bump_ban(ps, ps.ip, "addr-empty", now_ms());
        } else {
            ++ps.mis;
        }
    }
}

// =================== Orphan manager =========================================

void P2P::evict_orphans_if_needed(){
    // CRITICAL FIX: Protect orphans that are part of the active sync chain
    // An orphan is "protected" if its parent is:
    //   1. The current chain tip (next block to be accepted)
    //   2. Another orphan in the pool (forms a chain)
    // Evicting protected orphans would cause permanent sync stalls.

    const std::string tip_hex = hexkey(chain_.tip_hash());

    while ( (orphan_bytes_ > orphan_bytes_limit_) ||
            (orphans_.size() > orphan_count_limit_) ) {
        if (orphan_order_.empty()) break;

        // Find a victim that is NOT protected
        std::string victim;
        bool found_victim = false;

        // Try to find an evictable orphan (not part of active chain)
        // Use while loop with manual iterator management to safely handle erasure
        auto order_it = orphan_order_.begin();
        while (order_it != orphan_order_.end()) {
            const std::string& candidate = *order_it;
            auto it = orphans_.find(candidate);
            if (it == orphans_.end()) {
                // Already removed, clean up order list
                order_it = orphan_order_.erase(order_it);  // Returns next valid iterator
                continue;  // Don't increment - erase already moved us forward
            }

            const std::string parent_hex = hexkey(it->second.prev);

            // PROTECTION: Don't evict if parent is chain tip
            if (parent_hex == tip_hex) {
                ++order_it;
                continue;  // This orphan is next in line - protect it
            }

            // PROTECTION: Don't evict if parent is also an orphan (chain of orphans)
            if (orphans_.find(parent_hex) != orphans_.end()) {
                ++order_it;
                continue;  // Part of orphan chain - protect it
            }

            // PROTECTION: Don't evict if parent is currently inflight (being requested)
            // This is CRITICAL for sync - if block 1 is slow and blocks 2,3,4... arrive first,
            // we must NOT evict block 2 just because block 1 hasn't arrived yet.
            // Without this check, entire orphan chains can be wrongly evicted causing sync stalls.
            {
                InflightLock lk(g_inflight_lock);
                if (g_global_inflight_blocks.count(parent_hex)) {
                    ++order_it;
                    continue;  // Parent is being fetched - protect this orphan
                }
            }

            // This orphan is safe to evict (its parent is neither tip, orphan, nor inflight)
            victim = candidate;
            orphan_order_.erase(order_it);
            found_victim = true;
            break;
        }

        if (!found_victim) {
            // All orphans are protected - we're at capacity with active sync chain
            // This is okay - it means we're making progress on a large reorg or IBD
            // Log once and stop trying to evict
            static int64_t last_protection_log_ms = 0;
            int64_t now = now_ms();
            if (now - last_protection_log_ms > 30000) {  // Log every 30s max
                last_protection_log_ms = now;
                log_info("P2P: orphan pool at capacity with protected blocks (size=" +
                         std::to_string(orphans_.size()) + ") - sync chain intact");
            }
            break;
        }

        auto it = orphans_.find(victim);
        if (it == orphans_.end()) continue;

        const std::string parent_hex = hexkey(it->second.prev);
        orphan_bytes_ -= it->second.raw.size();
        orphans_.erase(it);

        auto pit = orphan_children_.find(parent_hex);
        if (pit != orphan_children_.end()){
            auto& vec = pit->second;
            vec.erase(std::remove(vec.begin(), vec.end(), victim), vec.end());
            if (vec.empty()) orphan_children_.erase(pit);
        }
        log_warn("P2P: evicted orphan " + victim);
    }
}

void P2P::remove_orphan_by_hex(const std::string& child_hex){
    auto it = orphans_.find(child_hex);
    if (it == orphans_.end()) return;
    const std::string parent_hex = hexkey(it->second.prev);
    if (orphan_bytes_ >= it->second.raw.size())
        orphan_bytes_ -= it->second.raw.size();
    else
        orphan_bytes_ = 0;

    orphans_.erase(it);

    auto pit = orphan_children_.find(parent_hex);
    if (pit != orphan_children_.end()){
        auto& vec = pit->second;
        vec.erase(std::remove(vec.begin(), vec.end(), child_hex), vec.end());
        if (vec.empty()) orphan_children_.erase(pit);
    }

    auto dit = std::find(orphan_order_.begin(), orphan_order_.end(), child_hex);
    if (dit != orphan_order_.end()) orphan_order_.erase(dit);
}

// ============================================================================
// HEIGHT-ORDERED BLOCK QUEUE
// Blocks are downloaded in parallel for speed, but processed strictly by height.
// This prevents "missing utxo" errors from out-of-order block processing.
// ============================================================================

void P2P::queue_block_by_height(uint64_t height, const std::vector<uint8_t>& hash,
                                 const std::vector<uint8_t>& raw) {
    // Don't queue if we already have it
    if (pending_blocks_.count(height)) return;

    g_diag_blocks_received++;

    PendingBlock pb;
    pb.hash = hash;
    pb.raw = raw;
    pb.received_ms = now_ms();

    pending_blocks_[height] = std::move(pb);
    pending_blocks_bytes_ += raw.size();

    // Evict old blocks if queue is too large
    evict_pending_blocks_if_needed();
}

void P2P::evict_pending_blocks_if_needed() {
    // Remove blocks that are already in chain or too far behind
    uint64_t current_height = chain_.height();
    int64_t now = now_ms();

    // CRITICAL FIX: Also remove blocks that have been waiting too long (2 minutes)
    // If a block has been pending for 2 min, its predecessor likely failed to arrive.
    // Clear it from pending AND global so it can be re-requested.
    static constexpr int64_t PENDING_BLOCK_TIMEOUT_MS = 120000;

    // Remove blocks at or below current height (already processed)
    // Also remove blocks that have timed out waiting for predecessors
    auto it = pending_blocks_.begin();
    while (it != pending_blocks_.end()) {
        bool should_remove = false;
        bool timed_out = false;

        if (it->first <= current_height) {
            should_remove = true;
        } else if ((now - it->second.received_ms) > PENDING_BLOCK_TIMEOUT_MS) {
            // Block has been waiting too long - predecessor never arrived
            should_remove = true;
            timed_out = true;
        }

        if (should_remove) {
            uint64_t removed_height = it->first;
            pending_blocks_bytes_ -= it->second.raw.size();
            it = pending_blocks_.erase(it);

            // If timed out, clear from global tracking so it can be re-requested
            if (timed_out) {
                InflightLock lk(g_inflight_lock);
                g_global_requested_indices.erase(removed_height);
            }
        } else {
            ++it;
        }
    }

    // If still too large, remove the highest blocks first (furthest from being processable)
    while (pending_blocks_bytes_ > MAX_PENDING_BLOCKS_BYTES && !pending_blocks_.empty()) {
        auto last = std::prev(pending_blocks_.end());
        uint64_t evicted_height = last->first;
        pending_blocks_bytes_ -= last->second.raw.size();
        pending_blocks_.erase(last);

        // CRITICAL FIX: Clear evicted index from global tracking!
        // Without this, the index stays in g_global_requested_indices forever,
        // and will NEVER be re-requested when the node catches up to that height.
        // This was the ROOT CAUSE of random stall heights (1100, 3054, etc.)
        {
            InflightLock lk(g_inflight_lock);
            g_global_requested_indices.erase(evicted_height);
        }
    }
}

void P2P::process_pending_blocks() {
    uint64_t current_height = chain_.height();
    uint64_t next_height = current_height + 1;
    int blocks_processed = 0;
    static int64_t last_pending_log_ms = 0;

    // ========================================================================
    // SYNC DIAGNOSTICS: Log complete sync state every 3 seconds
    // ========================================================================
    int64_t diag_now = now_ms();
    if (diag_now - g_diag_last_log_ms.load() > 3000) {
        uint64_t prev_height = g_diag_last_height.load();
        int64_t prev_time = g_diag_last_log_ms.load();
        g_diag_last_log_ms.store(diag_now);
        g_diag_last_height.store(current_height);

        // Calculate blocks/sec
        double elapsed_sec = (prev_time > 0) ? (diag_now - prev_time) / 1000.0 : 1.0;
        double blocks_per_sec = (prev_height > 0 && elapsed_sec > 0)
            ? (current_height - prev_height) / elapsed_sec : 0;

        // Count total inflight across all peers
        size_t total_inflight = 0;
        size_t syncing_peers = 0;
        size_t capable_peers = 0;
        size_t pending_verify = 0;
        {
            std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
            for (auto& kvp : peers_) {
                total_inflight += kvp.second.inflight_index;
                if (kvp.second.syncing) syncing_peers++;
                if (peer_is_index_capable(kvp.first)) capable_peers++;
                if (kvp.second.fork_verification_pending) pending_verify++;
            }
        }

        // Get global requested size
        size_t global_requested = 0;
        {
            InflightLock lk(g_inflight_lock);
            global_requested = g_global_requested_indices.size();
        }

        log_info("[SYNC-DIAG] height=" + std::to_string(current_height) +
                " hdr=" + std::to_string(chain_.best_header_height()) +
                " target=" + std::to_string(g_max_known_peer_tip.load()) +
                " rate=" + std::to_string((int)blocks_per_sec) + "/s" +
                " pending=" + std::to_string(pending_blocks_.size()) +
                " inflight=" + std::to_string(total_inflight) +
                " global_req=" + std::to_string(global_requested) +
                " peers=" + std::to_string(capable_peers) + "/" + std::to_string(syncing_peers) +
                " verify=" + std::to_string(pending_verify));

        // Log blocking reasons if any are high
        uint64_t blk_not_cap = g_diag_fill_blocked_not_capable.exchange(0);
        uint64_t blk_fork = g_diag_fill_blocked_fork.exchange(0);
        uint64_t blk_verify = g_diag_fill_blocked_pending_verify.exchange(0);
        uint64_t blk_max_idx = g_diag_fill_blocked_max_index.exchange(0);
        uint64_t blk_already = g_diag_fill_blocked_already_requested.exchange(0);
        uint64_t blk_pipe = g_diag_fill_blocked_pipe_full.exchange(0);

        if (blk_not_cap + blk_fork + blk_verify + blk_max_idx + blk_already + blk_pipe > 0) {
            log_info("[SYNC-DIAG] blocked: not_capable=" + std::to_string(blk_not_cap) +
                    " fork=" + std::to_string(blk_fork) +
                    " pending_verify=" + std::to_string(blk_verify) +
                    " max_index=" + std::to_string(blk_max_idx) +
                    " already_req=" + std::to_string(blk_already) +
                    " pipe_full=" + std::to_string(blk_pipe));
        }

        // Log request/receive stats
        uint64_t req = g_diag_blocks_requested.load();
        uint64_t recv = g_diag_blocks_received.load();
        uint64_t proc = g_diag_blocks_processed.load();
        log_info("[SYNC-DIAG] totals: requested=" + std::to_string(req) +
                " received=" + std::to_string(recv) +
                " processed=" + std::to_string(proc));
    }

    // Process blocks in strict height order
    while (true) {
        auto it = pending_blocks_.find(next_height);
        if (it == pending_blocks_.end()) {
            // No block at next height yet - stop processing
            break;
        }

        // Deserialize and validate the block
        Block b;
        if (!deser_block(it->second.raw, b)) {
            log_warn("P2P: failed to deserialize pending block at height " + std::to_string(next_height));
            pending_blocks_bytes_ -= it->second.raw.size();
            pending_blocks_.erase(it);
            // CRITICAL FIX: Clear from global tracking so we can re-request from another peer
            {
                InflightLock lk(g_inflight_lock);
                g_global_requested_indices.erase(next_height);
            }
            continue;
        }

        // Verify this block extends current tip
        const auto current_tip = chain_.tip_hash();
        if (b.header.prev_hash != current_tip) {
            // Block doesn't extend tip - might be competing chain that needs reorg
            // CRITICAL FIX: Try accept_block_for_reorg to handle potential chain reorganization
            // This was previously just discarding the block, causing nodes to get stuck
            std::string reorg_err;
            if (chain_.accept_block_for_reorg(b, reorg_err)) {
                // Reorg manager accepted the block - it may trigger a reorg if this chain has more work
                log_info("P2P: pending block at height " + std::to_string(next_height) +
                         " submitted for reorg evaluation");

                // Check if a reorg happened and this block is now on the main chain
                if (chain_.have_block(b.block_hash())) {
                    blocks_processed++;
                    if (mempool_) {
                        // CRITICAL FIX: Use overload that promotes orphan TXs
                        mempool_->on_block_connect(b, chain_.utxo(), (uint32_t)chain_.height());
                    }
                    // CRITICAL FIX: Notify stratum server immediately on new block
                    if (auto* ss = miq::g_stratum_server.load()) {
                        ss->notify_new_block();
                    }
                    broadcast_inv_block(it->second.hash);
                    g_last_progress_ms = now_ms();
                    g_last_progress_height = chain_.height();

                    // CRITICAL FIX: Clear from global tracking after successful reorg
                    {
                        InflightLock lk(g_inflight_lock);
                        g_global_requested_indices.erase(next_height);
                    }

                    // Update heights for next iteration
                    current_height = chain_.height();
                    next_height = current_height + 1;
                }
            } else {
                int64_t now_log = now_ms();
                if (now_log - last_pending_log_ms > 5000) {
                    last_pending_log_ms = now_log;
                    log_warn("P2P: pending block at height " + std::to_string(next_height) +
                             " rejected for reorg: " + reorg_err);
                }
                // CRITICAL FIX: Allow re-request from alternate peers on reorg failure
                // The block might be from a different chain - try getting it from elsewhere
                {
                    InflightLock lk(g_inflight_lock);
                    g_global_requested_indices.erase(next_height);
                }
            }
            pending_blocks_bytes_ -= it->second.raw.size();
            pending_blocks_.erase(it);
            // Don't break - continue checking other pending blocks
            continue;
        }

        // Submit the block
        std::string err;
        uint64_t new_height = 0;
        // RACE FIX: Capture height atomically during submit (under chain lock)
        bool accepted = chain_.submit_block(b, err, &new_height);

        if (accepted) {
            blocks_processed++;
            g_diag_blocks_processed++;

            // TIMING: Record block receive time for recv→relay latency calculation
            #if MIQ_TIMING_INSTRUMENTATION
            g_timing_last_block_recv_ms.store(now_ms(), std::memory_order_relaxed);
            g_timing_peers_triggered_count.fetch_add(1, std::memory_order_relaxed);
            #endif

            // Notify mempool
            if (mempool_) {
                // CRITICAL FIX: Use overload that promotes orphan TXs
                // RACE FIX: Use captured height, not chain_.height() which could race
                mempool_->on_block_connect(b, chain_.utxo(), (uint32_t)new_height);
            }

            // CRITICAL FIX: Notify stratum server immediately on new block
            if (auto* ss = miq::g_stratum_server.load()) {
                ss->notify_new_block();
            }

            // Broadcast to peers
            broadcast_inv_block(it->second.hash);

            // PERF: Log end-to-end timing when in near-tip mode
            if (miq::is_near_tip_mode()) {
                int64_t t_relay = now_ms();
                int64_t total_ms = t_relay - it->second.received_ms;
                log_info("[PERF] Block " + std::to_string(new_height) +
                         " recv->relay total=" + std::to_string(total_ms) + "ms");
            }

            // Update tracking
            g_last_progress_ms = now_ms();
            g_last_progress_height = new_height;

            // TELEMETRY: Notify main.cpp about received blocks for UI display
            if (block_callback_) {
                P2PBlockInfo info;
                info.height = chain_.height();
                info.hash_hex = hexkey(it->second.hash);
                info.tx_count = static_cast<uint32_t>(b.txs.size());
                info.miner = miq_miner_from_block(b);
                // Calculate fees from coinbase
                if (!b.txs.empty()) {
                    uint64_t coinbase_total = 0;
                    for (const auto& out : b.txs[0].vout) coinbase_total += out.value;
                    uint64_t subsidy = chain_.subsidy_for_height(info.height);
                    if (coinbase_total >= subsidy) {
                        info.fees = coinbase_total - subsidy;
                        info.fees_known = true;
                    }
                }
                block_callback_(info);

                // Also notify about transactions in this block
                if (txids_callback_ && b.txs.size() > 1) {
                    std::vector<std::string> txids;
                    txids.reserve(b.txs.size() - 1);
                    for (size_t i = 1; i < b.txs.size(); ++i) {
                        txids.push_back(hexkey(b.txs[i].txid()));
                    }
                    txids_callback_(txids);
                }
            }

            // Also try to connect any orphans that were waiting for this block
            try_connect_orphans(hexkey(it->second.hash));

            // CRITICAL FIX: Clear from global tracking after successful processing!
            // Without this, the index stays in g_global_requested_indices forever,
            // causing fill_index_pipeline to skip it and stall sync.
            {
                InflightLock lk(g_inflight_lock);
                g_global_requested_indices.erase(next_height);
            }

            // Remove from pending queue
            pending_blocks_bytes_ -= it->second.raw.size();
            pending_blocks_.erase(it);

            // Update heights for next iteration
            current_height = chain_.height();
            next_height = current_height + 1;
        } else {
            // Block rejected - log and remove
            log_warn("P2P: pending block at height " + std::to_string(next_height) +
                     " rejected: " + err);
            pending_blocks_bytes_ -= it->second.raw.size();
            pending_blocks_.erase(it);

            // CRITICAL FIX: Immediately re-request this block from alternate peers
            // Don't just stop - the rejection might be due to a transient error
            {
                InflightLock lk(g_inflight_lock);
                g_global_requested_indices.erase(next_height);  // Allow re-request
            }
            // Continue to check if there are later blocks that might work after reorg
            break;
        }
    }

    // Log progress periodically
    if (blocks_processed > 0) {
        static int64_t last_queue_log_ms = 0;
        static uint64_t total_blocks_processed = 0;
        total_blocks_processed += blocks_processed;
        int64_t now_queue = now_ms();
        if (now_queue - last_queue_log_ms > 5000) {
            last_queue_log_ms = now_queue;
            log_warn("Chain: +" + std::to_string(total_blocks_processed) + " blocks → height " +
                     std::to_string(chain_.height()) + " (pending=" + std::to_string(pending_blocks_.size()) + ")");
            total_blocks_processed = 0;
        }
    }
}

// Helper: Update peer performance metrics when a block is successfully received
static void update_peer_performance(PeerState& ps, const std::string& block_hex,
                                     const std::unordered_map<Sock, std::unordered_map<std::string, int64_t>>& inflight_ts,
                                     int64_t now_ms) {
    // Find when this block was requested
    auto sock_it = inflight_ts.find(ps.sock);
    if (sock_it != inflight_ts.end()) {
        auto block_it = sock_it->second.find(block_hex);
        if (block_it != sock_it->second.end()) {
            int64_t request_time = block_it->second;
            int64_t delivery_time = now_ms - request_time;

            // Update statistics
            ps.total_blocks_received++;
            ps.total_block_delivery_time_ms += delivery_time;
            ps.last_block_received_ms = now_ms;
            ps.blocks_delivered_successfully++;

            // CRITICAL: Record block success in IP history (survives reconnects)
            record_ip_block_result(ps.ip, true);

            // Calculate exponential moving average (EMA) with alpha=0.2
            // This gives more weight to recent deliveries
            if (ps.total_blocks_received == 1) {
                ps.avg_block_delivery_ms = delivery_time;
            } else {
                ps.avg_block_delivery_ms = (int64_t)(0.8 * ps.avg_block_delivery_ms + 0.2 * delivery_time);
            }

            // Update health score (0.0 = bad, 1.0 = good)
            // Based on success rate and delivery speed
            double success_rate = (double)ps.blocks_delivered_successfully /
                                 (ps.blocks_delivered_successfully + ps.blocks_failed_delivery + 1);
            double speed_factor = std::min(1.0, 30000.0 / std::max(1000.0, (double)ps.avg_block_delivery_ms));
            ps.health_score = 0.7 * success_rate + 0.3 * speed_factor;
        }
    }
}

void P2P::handle_incoming_block(Sock sock, const std::vector<uint8_t>& raw){
    if (raw.empty() || raw.size() > MIQ_FALLBACK_MAX_BLOCK_SZ) return;

    Block b;
    if (!deser_block(raw, b)) return;

    const auto bh = b.block_hash();

    // ULTRA-FAST OPTIMISTIC RELAY: Push to ALL peers after PoW check only
    // Goal: Sub-1-second network propagation before full validation
    // Strategy: Collect sockets under lock, send outside lock for parallelism
    //
    // IBD FIX: SKIP relay entirely during IBD - focus 100% on downloading blocks
    // Relaying during IBD wastes bandwidth and CPU that should be used for sync
    static std::unordered_map<std::string, int64_t> recently_relayed;  // block hash -> timestamp
    static std::mutex relay_mu;
    std::string bh_key = hexkey(bh);
    const int64_t tnow = now_ms();

    // IBD FIX: Don't relay blocks during initial sync
    bool should_relay = false;
    if (!miq::is_ibd_mode()) {
        std::lock_guard<std::mutex> lk(relay_mu);
        if (recently_relayed.find(bh_key) == recently_relayed.end()) {
            // Fast PoW check - only hash comparison, no full validation
            if (miq::verify_block_pow(b)) {
                recently_relayed[bh_key] = tnow;
                should_relay = true;

                // Time-based cleanup: remove entries older than 60 seconds
                if (recently_relayed.size() > 50) {
                    for (auto it = recently_relayed.begin(); it != recently_relayed.end(); ) {
                        if (tnow - it->second > 60000) {
                            it = recently_relayed.erase(it);
                        } else {
                            ++it;
                        }
                    }
                }
            }
        }
    }

    if (should_relay) {
        // Prepare message once (outside all locks)
        auto block_msg = encode_msg("block", raw);

        // Collect peer sockets under lock (fast)
        std::vector<Sock> relay_sockets;
        {
            std::lock_guard<std::recursive_mutex> peers_lk(g_peers_mu);
            relay_sockets.reserve(peers_.size());
            for (auto& kv : peers_) {
                if (kv.first != sock && kv.second.verack_ok) {
                    relay_sockets.push_back(kv.first);
                }
            }
        }

        // PARALLEL OPTIMISTIC RELAY: Send to ALL peers simultaneously
        // This is the fastest possible path - PoW verified, now blast to everyone
        int relayed = parallel_send_to_peers(relay_sockets, block_msg);

        MIQ_LOG_INFO(miq::LogCategory::NET, "PARALLEL optimistic relay: block " + bh_key.substr(0, 16) +
                     " pushed to " + std::to_string(relayed) + "/" +
                     std::to_string(relay_sockets.size()) + " peers SIMULTANEOUSLY");
    }

    // CRITICAL FIX: Don't skip blocks that might have incomplete processing
    // If block body is stored but UTXO operations failed (crash/disk error),
    // we need to let submit_block() handle re-processing via its incomplete
    // processing detection logic (checks if block extends current tip).
    // Only skip if we truly have a fully processed block that doesn't extend tip.
    if (chain_.have_block(bh)) {
        // Check if this block extends the current tip - if so, might be incomplete
        const auto tip_hash = chain_.tip_hash();
        if (b.header.prev_hash == tip_hash) {
            // Block extends tip but we already have it - possible incomplete processing!
            // Let it through to submit_block() which will detect and recover
            log_warn("P2P: have block that extends tip - checking for incomplete processing");
        } else {
            // CRITICAL FIX: Even if we have this block, it might be part of a competing
            // chain with more work. Try accept_block_for_reorg to evaluate reorg potential.
            std::string reorg_err;
            if (!chain_.accept_block_for_reorg(b, reorg_err)) {
                // Failed to process for reorg - likely truly duplicate or invalid
            }
            return;
        }
    }

    // =========================================================================
    // HEIGHT-ORDERED QUEUE: Parallel download, sequential processing
    // Blocks are downloaded in parallel for speed, but processed strictly by height.
    // This prevents "missing utxo" errors from out-of-order block processing.
    // =========================================================================

    // Determine block height from parent
    int64_t parent_height = chain_.get_header_height(b.header.prev_hash);
    uint64_t block_height = 0;

    // DIAG: Log parent lookup for early blocks
    if (parent_height < 0 && chain_.height() < 10) {
        log_warn("[BLOCK-DIAG] Block with unknown parent! prev=" + hexkey(b.header.prev_hash).substr(0,16) +
                "... (parent_height=-1, our_height=" + std::to_string(chain_.height()) + ")");
    }

    if (parent_height >= 0) {
        block_height = static_cast<uint64_t>(parent_height) + 1;

        // DIAG: Log block 2 specifically
        if (block_height == 2) {
            log_info("[BLOCK-DIAG] Received block 2! hash=" + hexkey(bh).substr(0,16) +
                    "... parent=" + hexkey(b.header.prev_hash).substr(0,16) + "...");
        }

        // Validate block hash against header index (if we have headers)
        std::vector<uint8_t> expected_hash;
        if (chain_.get_hash_by_index(block_height, expected_hash)) {
            if (bh != expected_hash) {
                log_warn("P2P: block hash mismatch at height " + std::to_string(block_height) +
                         " - expected " + hexkey(expected_hash).substr(0, 16) +
                         " got " + hexkey(bh).substr(0, 16) + " - rejecting");
                auto pit = peers_.find(sock);
                if (pit != peers_.end()) {
                    pit->second.mis++;
                    if (pit->second.mis > 5) {
                        log_warn("P2P: disconnecting peer " + pit->second.ip + " for repeated hash mismatches");
                        schedule_close(sock);
                    }
                }
                return;
            }
        }

        // Queue block by height for ordered processing
        queue_block_by_height(block_height, bh, raw);

        // Update peer performance metrics
        auto pit = peers_.find(sock);
        if (pit != peers_.end()) {
            update_peer_performance(pit->second, hexkey(bh), g_inflight_block_ts, now_ms());

            // CRITICAL FIX: Decrement inflight_index when hash-based block arrives!
            // CRITICAL FIX: Clear this block from ALL peers' inflight tracking!
            // With speculative parallel requests, multiple peers may have requested
            // the same block. When it arrives, ALL peers need their inflight_index
            // decremented, not just the delivering peer.
            {
                InflightLock lk(g_inflight_lock);
                // Clear from ALL peers' tracking (not just delivering peer)
                for (auto& idx_kv : g_inflight_index_ts) {
                    Sock peer_sock = idx_kv.first;
                    auto& peer_indices = idx_kv.second;
                    if (peer_indices.erase(block_height) > 0) {
                        // This peer had this block inflight - decrement their counter
                        auto peer_it = peers_.find(peer_sock);
                        if (peer_it != peers_.end() && peer_it->second.inflight_index > 0) {
                            peer_it->second.inflight_index--;
                        }
                    }
                }
                // Clear from global requested indices
                clear_global_requested_index(block_height);
            }
        }
        g_rr_next_idx.erase(hexkey(bh));

    } else {
        // Parent height unknown - store as orphan (will be rare with height queue)
        OrphanRec rec{ bh, b.header.prev_hash, raw };
        const std::string child_hex  = hexkey(bh);
        const std::string parent_hex = hexkey(b.header.prev_hash);

        if (orphans_.find(child_hex) == orphans_.end()) {
            orphans_.emplace(child_hex, std::move(rec));
            orphan_children_[parent_hex].push_back(child_hex);
            orphan_order_.push_back(child_hex);
            orphan_bytes_ += raw.size();
            evict_orphans_if_needed();
        }

        // Request parent block
        bool have_parent = chain_.have_block(b.header.prev_hash);
        if (!have_parent) {
            auto pit = peers_.find(sock);
            if (pit != peers_.end()) {
                request_block_hash(pit->second, b.header.prev_hash);
            }
        }
        return;
    }

    // Process pending blocks in height order
    process_pending_blocks();

    // Request more blocks from peers
    for (auto& kvp : peers_) {
        auto& pps = kvp.second;
        if (!pps.verack_ok) continue;
        if (!peer_is_index_capable((Sock)pps.sock)) continue;
        fill_index_pipeline(pps);
    }

    // Update sync state
    uint64_t new_height = chain_.height();
    for (auto& kvp : peers_) {
        PeerState& peer = kvp.second;
        if (peer.next_index <= new_height) {
            peer.next_index = new_height + 1;
        }
        if (peer.syncing && peer.next_index <= new_height) {
            peer.next_index = new_height + 1;
        }
    }

    g_last_progress_ms = now_ms();
    g_last_progress_height = chain_.height();

    // Clear fulfilled indices
    clear_fulfilled_indices_up_to_height(chain_.height(), chain_.best_header_height());

#if MIQ_ENABLE_HEADERS_FIRST
    {
        std::vector<std::vector<uint8_t>> want_tmp;
        chain_.next_block_fetch_targets(want_tmp, (size_t)32);
        uint64_t max_peer_tip = chain_.height();
        for (auto &kvp : peers_) {
            const auto &pps = kvp.second;
            if (!pps.verack_ok) continue;
            if (pps.peer_tip_height > max_peer_tip) max_peer_tip = pps.peer_tip_height;
        }

        // CRITICAL FIX: Never consider ourselves "at tip" if the tip is stale
        // Reduced from 5 min to 60 sec to prevent forks
        uint64_t tip_age_sec = 0;
        {
            auto tip = chain_.tip();
            uint64_t now_sec = (uint64_t)std::time(nullptr);
            uint64_t tip_time = (tip.time > 0) ? (uint64_t)tip.time : now_sec;
            tip_age_sec = (now_sec > tip_time) ? (now_sec - tip_time) : 0;
        }
        bool tip_is_stale = (tip_age_sec > 60);  // 60 seconds (was 5 minutes)

        bool at_tip = want_tmp.empty() && (chain_.height() >= max_peer_tip) && !tip_is_stale;
        maybe_mark_headers_done(at_tip);
    }
#endif
}

void P2P::try_connect_orphans(const std::string& parent_hex){
    std::vector<std::string> q;
    auto it = orphan_children_.find(parent_hex);
    if (it != orphan_children_.end()) {
        q.assign(it->second.begin(), it->second.end());
        orphan_children_.erase(it);
        // Found orphan children waiting for this parent - process them
    }
    // Note: During normal sequential sync, no orphans are expected

    while (!q.empty()){
        std::string child_hex = q.back();
        q.pop_back();

        auto oit = orphans_.find(child_hex);
        if (oit == orphans_.end()) {
            // Orphan was already processed or evicted
            continue;
        }

        Block ob;
        if (!deser_block(oit->second.raw, ob)) {
            log_warn("P2P: failed to deserialize orphan " + child_hex + ", dropping");
            remove_orphan_by_hex(child_hex);
            continue;
        }

        if (chain_.have_block(oit->second.hash)) {
            // Chain already has this block, remove from orphans
            remove_orphan_by_hex(child_hex);
            continue;
        }

        // CRITICAL FIX: Enforce sequential processing in orphan handling
        // If this orphan doesn't extend the current tip (e.g., competing chain),
        // keep it in the orphan pool instead of processing and dropping it.
        // This prevents losing valid blocks from alternate chains during reorgs.
        const auto current_tip = chain_.tip_hash();
        if (ob.header.prev_hash != current_tip) {
            // Re-register this orphan under its actual parent for later processing
            const std::string actual_parent_hex = hexkey(ob.header.prev_hash);
            orphan_children_[actual_parent_hex].push_back(child_hex);
            continue;  // Don't remove from orphans_, try again when parent becomes tip
        }

        std::string err;
        uint64_t orphan_height = 0;
        // RACE FIX: Capture height atomically during submit (under chain lock)
        if (chain_.submit_block(ob, err, &orphan_height)) {
            // CRITICAL FIX: Notify mempool and promote orphan TXs
            // RACE FIX: Use captured height, not chain_.height() which could race
            if (mempool_) {
                mempool_->on_block_connect(ob, chain_.utxo(), (uint32_t)orphan_height);
            }
            // CRITICAL FIX: Notify stratum server immediately on new block
            if (auto* ss = miq::g_stratum_server.load()) {
                ss->notify_new_block();
            }
            const std::string miner = miq_miner_from_block(ob);
            log_info("P2P: accepted orphan as block height=" + std::to_string(orphan_height)
                     + " miner=" + miner
                     + " (remaining_orphans=" + std::to_string(orphans_.size() - 1) + ")");

            broadcast_inv_block(oit->second.hash);
            const std::string new_parent_hex = child_hex;
            remove_orphan_by_hex(child_hex);

            // Check for grandchildren (orphans waiting for this orphan)
            auto cit = orphan_children_.find(new_parent_hex);
            if (cit != orphan_children_.end()) {
                for (const auto& g : cit->second) q.push_back(g);
                orphan_children_.erase(cit);
            }
            g_last_progress_ms = now_ms();
            g_last_progress_height = orphan_height;

            // After connecting orphan, try to process pending blocks that may now be ready
            process_pending_blocks();
        } else {
            log_warn("P2P: orphan child rejected (" + err + "), dropping orphan " + child_hex);
            remove_orphan_by_hex(child_hex);
        }
    }
}

// ============================================================================

void P2P::loop(){
    reset_runtime_queues();
    int64_t last_addr_save_ms = now_ms();
    int64_t last_ban_purge_ms = last_addr_save_ms;
    int64_t last_dial_ms = now_ms();

    while (running_) {
        if ((int)outbound_count() < miq_outbound_target() && g_listen_port != 0) {
            int64_t tnow = now_ms();
            if (tnow - last_dial_ms > miq_dial_interval_ms()) {
                last_dial_ms = tnow;

#if MIQ_ENABLE_ADDRMAN
                 bool dialed = false;
                 for (int attempts=0; attempts<8 && !dialed; ++attempts){
                     auto cand = g_addrman.select_for_outbound(g_am_rng, /*prefer_tried=*/true);
                     if (!cand) break;
                     uint32_t be_ip;
                     bool is_v4 = parse_ipv4(cand->host, be_ip);
                     if (is_v4 && !ipv4_is_public(be_ip)) { g_addrman.mark_attempt(*cand); continue; }
                     if (is_v4 && is_self_be(be_ip)) { g_addrman.mark_attempt(*cand); continue; }
                     // CRITICAL FIX: Hold g_peers_mu while accessing peers_ to prevent segfault
                     {
                         std::lock_guard<std::recursive_mutex> lk_check(g_peers_mu);
                         if (is_v4 && outbound_count() >= (size_t)MIQ_OUTBOUND_TARGET && violates_group_diversity(peers_, be_ip)) {
                             g_addrman.mark_attempt(*cand); continue;
                         }
                     }
                     std::string dotted = is_v4 ? be_ip_to_string(be_ip) : cand->host;
                     if (banned_.count(dotted)) { g_addrman.mark_attempt(*cand); continue; }
                     // CRITICAL FIX: Hold g_peers_mu while accessing peers_
                     bool connected = false;
                     {
                         std::lock_guard<std::recursive_mutex> lk_check(g_peers_mu);
                         for (auto& kv : peers_) if (kv.second.ip == dotted) { connected = true; break; }
                     }
                     if (connected) { g_addrman.mark_attempt(*cand); continue; }

                     // CRITICAL FIX: Check reconnection backoff to prevent rapid connect/disconnect
                     {
                         std::lock_guard<std::mutex> lk_backoff(g_reconnect_backoff_mu);
                         auto it = g_reconnect_backoff_until.find(dotted);
                         if (it != g_reconnect_backoff_until.end() && tnow < it->second) {
                             // Still in backoff period, skip this IP
                             continue;
                         }
                         // Clean up expired backoffs while we're here
                         if (it != g_reconnect_backoff_until.end()) {
                             g_reconnect_backoff_until.erase(it);
                         }
                     }

                     Sock s = MIQ_INVALID_SOCK;
                     std::string ip_txt;
                     bool allow_loopback = std::getenv("MIQ_FORCE_CLIENT") != nullptr;
                     if (is_v4) {
                         if (allow_loopback || !is_loopback_be(be_ip)) s = dial_be_ipv4(be_ip, cand->port);
                         ip_txt = dotted;
                     } else {
                         // Try resolving/dialing IPv6 or hostnames
                         std::vector<MiqEndpoint> eps;
                         if (miq_resolve_endpoints_from_string(cand->host, cand->port, eps)) {
                             for (const auto& ne : eps) {
                                 if (ne.ss.ss_family == AF_INET) {
                                     const sockaddr_in* a4 = reinterpret_cast<const sockaddr_in*>(&ne.ss);
                                     if (!allow_loopback && (is_loopback_be(a4->sin_addr.s_addr) || is_self_be(a4->sin_addr.s_addr))) continue;
                                 }
                                 Sock ts = miq_connect_nb((const sockaddr*)&ne.ss, ne.len, MIQ_CONNECT_TIMEOUT_MS);
                                 if (ts != MIQ_INVALID_SOCK) { s = ts; ip_txt = miq_ntop_sockaddr(ne.ss); break; }
                             }
                         }
                     }
                     if (s != MIQ_INVALID_SOCK) {
                         PeerState ps; ps.sock = s; ps.ip = ip_txt; ps.mis=0; ps.last_ms=now_ms();
                         ps.blk_tokens = MIQ_RATE_BLOCK_BURST; ps.tx_tokens=MIQ_RATE_TX_BURST; ps.last_refill_ms=ps.last_ms;
                         ps.inflight_hdr_batches = 0; ps.last_hdr_batch_done_ms = 0; ps.sent_getheaders = false;
                         ps.rate.last_ms=ps.last_ms; ps.banscore=0; ps.version=0; ps.features=0; ps.whitelisted=false;
                         ps.total_blocks_received = 0;
                         ps.total_block_delivery_time_ms = 0;
                         ps.avg_block_delivery_ms = 30000;
                         ps.blocks_delivered_successfully = 0;
                         ps.blocks_failed_delivery = 0;
                         ps.health_score = 1.0;
                         ps.last_block_received_ms = 0;
                         {
                             std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
                             // CRITICAL FIX: Check for duplicate IP before adding (TOCTOU prevention)
                             bool is_dup = false;
                             for (const auto& kv : peers_) {
                                 if (kv.second.ip == ip_txt) { is_dup = true; break; }
                             }
                             if (is_dup) {
                                 log_info("P2P: rejecting duplicate addrman outbound to " + ip_txt);
                                 CLOSESOCK(s);
                                 g_addrman.mark_attempt(*cand);
                                 continue;
                             }
                             peers_[s] = ps;
                             g_outbounds.insert(s);
                         }
                         g_peer_index_capable[s] = false;
                         g_trickle_last_ms[s] = 0;
                         log_info("P2P: outbound (addrman) " + ps.ip);
                         // CRITICAL: Track IP connection for reputation history
                         record_ip_connect(ps.ip);
                         miq_set_keepalive(s);
                         gate_on_connect(s);
                         if (is_v4) gate_set_loopback(s, is_loopback_be(be_ip));
                         auto msg = encode_msg("version", miq_build_version_payload((uint32_t)chain_.height()));
                         (void)send_or_close(s, msg);
                         dialed = true;
                     } else {
                         g_addrman.mark_attempt(*cand);
                     }
                 }
 
                 if (!dialed && !addrv4_.empty()) {
 #endif
                    std::vector<uint32_t> candidates;
                    candidates.reserve(addrv4_.size());
                    // CRITICAL FIX: Hold g_peers_mu while accessing peers_
                    std::lock_guard<std::recursive_mutex> lk_cand(g_peers_mu);
                    for (uint32_t ip : addrv4_) {
                        if (is_self_be(ip)) continue;
                        if (is_loopback_be(ip)) continue;
                        std::string dotted = be_ip_to_string(ip);
                        if (banned_.count(dotted)) continue;
                        bool connected = false;
                        for (auto& kv : peers_) {
                            if (kv.second.ip == dotted) { connected = true; break; }
                        }
                        if (connected) continue;
                        if (violates_group_diversity(peers_, ip)) continue;
                        candidates.push_back(ip);
                    }
                    if (!candidates.empty()) {
                        std::uniform_int_distribution<size_t> dist(0, candidates.size()-1);
                        uint32_t pick = candidates[dist(rng())];

                        if (!is_loopback_be(pick)) {
                            Sock s = dial_be_ipv4(pick, g_listen_port);
                            if (s != MIQ_INVALID_SOCK) {
                                PeerState ps;
                                ps.sock = s;
                                ps.ip   = be_ip_to_string(pick);
                                ps.mis  = 0;
                                ps.last_ms = now_ms();
                                ps.blk_tokens = MIQ_RATE_BLOCK_BURST;
                                ps.tx_tokens  = MIQ_RATE_TX_BURST;
                                ps.last_refill_ms = ps.last_ms;
                                ps.inflight_hdr_batches = 0; ps.last_hdr_batch_done_ms = 0; ps.sent_getheaders = false;
                                ps.rate.last_ms=ps.last_ms; ps.banscore=0; ps.version=0; ps.features=0; ps.whitelisted=false;
                                ps.total_blocks_received = 0;
                                ps.total_block_delivery_time_ms = 0;
                                ps.avg_block_delivery_ms = 30000;
                                ps.blocks_delivered_successfully = 0;
                                ps.blocks_failed_delivery = 0;
                                ps.health_score = 1.0;
                                ps.last_block_received_ms = 0;
                                {
                                    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
                                    // CRITICAL FIX: Check for duplicate IP before adding (TOCTOU prevention)
                                    bool is_dup = false;
                                    for (const auto& kv : peers_) {
                                        if (kv.second.ip == ps.ip) { is_dup = true; break; }
                                    }
                                    if (is_dup) {
                                        log_info("P2P: rejecting duplicate outbound to " + ps.ip);
                                        CLOSESOCK(s);
                                        continue;
                                    }
                                    peers_[s] = ps;
                                    g_outbounds.insert(s);
                                }
                                g_peer_index_capable[s] = false;
                                g_trickle_last_ms[s] = 0;

                                log_info("P2P: outbound to known " + ps.ip);
                                // CRITICAL: Track IP connection for reputation history
                                record_ip_connect(ps.ip);
                                gate_on_connect(s);
                                miq_set_keepalive(s);
                                gate_set_loopback(s, is_loopback_be(pick));
                                auto msg = encode_msg("version", miq_build_version_payload((uint32_t)chain_.height()));
                                (void)send_or_close(s, msg);
                            }
                        }
                    }
#if MIQ_ENABLE_ADDRMAN
                }
#endif
            }
        }

#if MIQ_ENABLE_ADDRMAN
        {
            int64_t tnow = now_ms();
            if (tnow >= g_next_feeler_ms) {
                g_next_feeler_ms = tnow + MIQ_FEELER_INTERVAL_MS + (int)(g_am_rng.next()%5000);
                auto cand = g_addrman.select_feeler(g_am_rng);
                if (cand) {
                    uint32_t be_ip;
                    // CRITICAL FIX: Hold g_peers_mu while accessing peers_
                    bool skip_cand = false;
                    bool connected = false;
                    std::string dotted;
                    {
                        std::lock_guard<std::recursive_mutex> lk_feeler(g_peers_mu);
                        if (parse_ipv4(cand->host, be_ip) && ipv4_is_public(be_ip) && !is_self_be(be_ip) && !violates_group_diversity(peers_, be_ip)) {
                            dotted = be_ip_to_string(be_ip);
                            if (!banned_.count(dotted)) {
                                for (auto& kv:peers_) if (kv.second.ip==dotted) { connected=true; break; }
                            } else {
                                skip_cand = true;
                            }
                        } else {
                            skip_cand = true;
                        }
                    }
                    if (!skip_cand && !connected) {
                        Sock s = dial_be_ipv4(be_ip, g_listen_port);
                        if (s != MIQ_INVALID_SOCK) {
                            PeerState ps; ps.sock=s; ps.ip=dotted; ps.mis=0; ps.last_ms=now_ms();
                            ps.blk_tokens = MIQ_RATE_BLOCK_BURST; ps.tx_tokens=MIQ_RATE_TX_BURST; ps.last_refill_ms=ps.last_ms;
                            ps.inflight_hdr_batches = 0; ps.last_hdr_batch_done_ms = 0; ps.sent_getheaders = false;
                            ps.rate.last_ms=ps.last_ms; ps.banscore=0; ps.version=0; ps.features=0; ps.whitelisted=false;
                            ps.total_blocks_received = 0;
                            ps.total_block_delivery_time_ms = 0;
                            ps.avg_block_delivery_ms = 30000;
                            ps.blocks_delivered_successfully = 0;
                            ps.blocks_failed_delivery = 0;
                            ps.health_score = 1.0;
                            ps.last_block_received_ms = 0;
                            {
                                std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
                                // CRITICAL FIX: Check for duplicate IP before adding (TOCTOU prevention)
                                bool is_dup = false;
                                for (const auto& kv : peers_) {
                                    if (kv.second.ip == dotted) { is_dup = true; break; }
                                }
                                if (is_dup) {
                                    log_info("P2P: rejecting duplicate feeler to " + dotted);
                                    CLOSESOCK(s);
                                    continue;
                                }
                                peers_[s] = ps;
                                g_outbounds.insert(s);
                            }
                            g_peer_index_capable[s] = false;
                            g_trickle_last_ms[s] = 0;
                            log_info("P2P: feeler " + dotted);
                            gate_on_connect(s);
                            miq_set_keepalive(s);
                            gate_set_loopback(s, is_loopback_be(be_ip));
                            auto msg = encode_msg("version", miq_build_version_payload((uint32_t)chain_.height()));
                            (void)send_or_close(s, msg);
                        }
                    }
                }
            }
        }
#endif

        {
            int64_t tnow = now_ms();
            size_t h = chain_.height();

            // ================================================================
            // FORK VERIFICATION TIMEOUT
            // PROPAGATION FIX: Reduced from 10s to 1s for sub-second guarantee
            // INVARIANT P5: "There must exist NO valid execution exceeding 1 second"
            // INVARIANT P1: "relay MUST be attempted on EVERY main loop iteration"
            //
            // OLD BUG: 10-second timeout + disconnect on timeout
            // FIX: 1-second timeout + just clear pending flag and proceed
            // Peer may just be slow - don't disconnect, just stop waiting
            // ================================================================
            constexpr int64_t FORK_VERIFY_TIMEOUT_MS = 1000;  // 1 second timeout
            for (auto& kv : peers_) {
                auto& pps = kv.second;
                if (pps.fork_verification_pending &&
                    pps.fork_verification_sent_ms > 0 &&
                    (tnow - pps.fork_verification_sent_ms) > FORK_VERIFY_TIMEOUT_MS) {
                    log_warn("P2P: FORK VERIFICATION TIMEOUT - peer " + pps.ip +
                            " did not respond within 1s - proceeding anyway");
                    // PROPAGATION FIX: DON'T mark as forked or disconnect!
                    // Just clear the pending flag so sync can proceed.
                    // If peer is on a fork, we'll detect it when blocks don't validate.
                    pps.fork_verification_pending = false;
                    // Optimistically allow sync - validation will catch bad blocks
                    pps.fork_verified = true;  // Assume good until proven otherwise
                    pps.syncing = true;
                    g_peer_index_capable[kv.first] = true;
                    fill_index_pipeline(pps);
                }
            }

            if (h > g_last_progress_height) {
                g_last_progress_height = h;
                g_last_progress_ms = tnow;
                g_next_stall_probe_ms = tnow + g_stall_retry_ms;
            } else if (tnow >= g_next_stall_probe_ms &&
                       std::any_of(peers_.begin(), peers_.end(),
                                   [](const auto& kv){ return kv.second.verack_ok; })) {
                // Stall detected: height hasn't increased for MIQ_P2P_STALL_RETRY_MS
                int64_t stall_duration_ms = tnow - g_last_progress_ms;
                log_info("P2P: stall detected - no height progress for " + std::to_string(stall_duration_ms / 1000) + "s (height=" + std::to_string(h) + ", peers=" + std::to_string(peers_.size()) + ")");

                // STALL DIAGNOSTIC: Log detailed state to find WHY we're stalled
                {
                    InflightLock lk(g_inflight_lock);
                    size_t global_inflight = g_global_requested_indices.size();
                    int64_t oldest_age_ms = 0;
                    uint64_t oldest_idx = 0;
                    for (const auto& kv : g_global_requested_indices_ts) {
                        int64_t age = tnow - kv.second;
                        if (age > oldest_age_ms) {
                            oldest_age_ms = age;
                            oldest_idx = kv.first;
                        }
                    }
                    log_info("P2P: STALL DIAGNOSTIC: global_inflight=" + std::to_string(global_inflight) +
                             " oldest_request_age=" + std::to_string(oldest_age_ms) + "ms" +
                             " oldest_idx=" + std::to_string(oldest_idx) +
                             " next_needed=" + std::to_string(h + 1) +
                             " header_height=" + std::to_string(chain_.best_header_height()));
                }

                // Log peer health during stalls (helps diagnose slow peers)
                if (!g_logged_headers_done) {
                    std::string health_summary;
                    for (const auto& kv : peers_) {
                        if (!kv.second.verack_ok) continue;
                        // CRITICAL FIX: Show inflight_index during IBD (that's what matters), not inflight_blocks
                        health_summary += "\n  " + kv.second.ip +
                                        ": health=" + std::to_string((int)(kv.second.health_score * 100)) + "%" +
                                        " avg_delivery=" + std::to_string(kv.second.avg_block_delivery_ms / 1000) + "s" +
                                        " blocks=" + std::to_string(kv.second.blocks_delivered_successfully) +
                                        " inflight=" + std::to_string(kv.second.inflight_index);
                    }
                    if (!health_summary.empty()) {
                        log_info("P2P: peer health summary:" + health_summary);
                    }

                    // CRITICAL FIX: Proactively decay health for peers with high inflight but not delivering
                    // This catches peers that are holding onto requests but not responding.
                    // BUG: Previously, only timeouts decayed health, but a peer could have many
                    // inflight requests that haven't timed out yet, maintaining artificially high health
                    // while blocking sync progress.
                    for (auto& kv : peers_) {
                        auto& ps = kv.second;
                        if (!ps.verack_ok) continue;
                        // If peer has 64+ inflight_index requests but hasn't delivered anything recently,
                        // decay their health. This prevents "phantom healthy" peers from hogging requests.
                        // The stall itself indicates the peer isn't delivering.
                        if (ps.inflight_index >= 64 && stall_duration_ms > 5000) {
                            // Decay health proportionally to how much they're hogging
                            // More inflight = more aggressive decay
                            double decay = 0.95 - (0.1 * (ps.inflight_index / 256.0)); // 0.85-0.95
                            decay = std::max(0.8, std::min(0.95, decay));
                            ps.health_score = std::max(0.1, ps.health_score * decay);
                        }
                    }

                    // DISCONNECT NON-RESPONSIVE PEERS
                    // If a peer has low health, 0 blocks delivered, and high inflight,
                    // they're wasting our request slots - disconnect and try other peers
                    std::vector<std::string> dead_peer_ips;
                    for (const auto& kv : peers_) {
                        const auto& ps = kv.second;
                        if (!ps.verack_ok) continue;
                        // CRITICAL FIX: Include inflight_index in non-responsive check
                        // Peer has health < 20%, never delivered a block, but has 64+ inflight
                        size_t total_inflight = ps.inflight_blocks.size() + ps.inflight_index;
                        bool is_non_responsive = (ps.health_score < 0.20) &&
                                                 (ps.blocks_delivered_successfully == 0) &&
                                                 (total_inflight >= 64);
                        if (is_non_responsive) {
                            log_warn("P2P: disconnecting non-responsive peer " + ps.ip +
                                    " (health=" + std::to_string((int)(ps.health_score * 100)) + "%" +
                                    " blocks=" + std::to_string(ps.blocks_delivered_successfully) +
                                    " inflight=" + std::to_string(total_inflight) + ")");
                            dead_peer_ips.push_back(ps.ip);
                        }
                    }
                    for (const auto& ip : dead_peer_ips) {
                        disconnect_peer(ip);
                    }
                }
#if MIQ_ENABLE_HEADERS_FIRST
                if (g_logged_headers_started && !g_logged_headers_done &&
                    g_ibd_headers_started_ms > 0 &&
                    (tnow - g_ibd_headers_started_ms) > (int64_t)MIQ_IBD_FALLBACK_AFTER_MS)
                {
                    // Rate-limit this message to once per 60 seconds
                    static int64_t last_ibd_fallback_log = 0;
                    if (tnow - last_ibd_fallback_log > 60000) {
                        last_ibd_fallback_log = tnow;
                        log_info("[IBD] headers phase exceeded fallback threshold; enabling index-by-height pipeline on capable peers");
                    }
                    for (auto &kvp : peers_) {
                        auto &pps = kvp.second;
                        if (!pps.verack_ok) continue;
                        if (!peer_is_index_capable((Sock)pps.sock)) continue;
                        pps.syncing = true;
                        // BITCOIN CORE FIX: Do NOT reset inflight_index - may have outstanding requests
                        pps.next_index = chain_.height() + 1;
                        fill_index_pipeline(pps);
                    }
                    // Don’t stop headers; we run both until completion.
                    g_ibd_headers_started_ms = tnow; // reset timer to avoid spamming
                }
                std::vector<std::vector<uint8_t>> locator;
                chain_.build_locator(locator);
                std::vector<std::vector<uint8_t>> loc_rev = locator;
                for (auto& hash : loc_rev) std::reverse(hash.begin(), hash.end());
                std::vector<uint8_t> stop(32, 0);
                auto pl_n = build_getheaders_payload(locator, stop);
                auto pl_f = build_getheaders_payload(loc_rev, stop);
                auto m_n  = encode_msg("getheaders", pl_n);
                auto m_f  = encode_msg("getheaders", pl_f);
                int probes = 0;
                // Snapshot just the sockets; update real PeerState under lock.
                std::vector<Sock> snapshot;
                {
                    std::lock_guard<std::recursive_mutex> lk2(g_peers_mu);
                    snapshot.reserve(peers_.size());
                    for (auto& kv : peers_) snapshot.push_back(kv.first);
                }
                for (Sock sd : snapshot) {
                    bool do_send = false;
                    bool flip = false;
                    {
                        std::lock_guard<std::recursive_mutex> lk2(g_peers_mu);
                        auto itp = peers_.find(sd);
                        if (itp != peers_.end() &&
                            itp->second.verack_ok &&
                            can_accept_hdr_batch(itp->second, now_ms()) &&
                            check_rate(itp->second, "hdr", 1.0, now_ms())) {
                            itp->second.sent_getheaders = true;
                            itp->second.inflight_hdr_batches++;
                            g_last_hdr_req_ms[sd] = now_ms();
                            flip = g_hdr_flip[sd];
                            do_send = true;
                        }
                    }
                    if (do_send) {
                        (void)send_or_close(sd, flip ? m_f : m_n);
                        if (++probes >= 2) break;
                    }
                }
#endif
                // CRITICAL FIX: Periodic header polling AFTER IBD completes
                // Without this, nodes cannot discover new blocks mined during/after their sync.
                // The seed announces its height at connection time, but may mine more blocks
                // while the node is syncing. Once IBD completes, header requests stop completely,
                // leaving the node stuck at the announced height (e.g., 3668 instead of actual tip).
                // This fix polls for new headers every 30 seconds to discover any new blocks.
                if (g_logged_headers_done) {
                    int64_t poll_now = now_ms();
                    int64_t last_poll = g_last_header_poll_ms.load();
                    if (poll_now - last_poll >= MIQ_HEADER_POLL_INTERVAL_MS) {
                        g_last_header_poll_ms.store(poll_now);

                        std::vector<std::vector<uint8_t>> poll_locator;
                        chain_.build_locator(poll_locator);
                        std::vector<uint8_t> poll_stop(32, 0);
                        auto pl = build_getheaders_payload(poll_locator, poll_stop);
                        auto msg = encode_msg("getheaders", pl);

                        // Send to one or two peers to discover new blocks
                        int sent = 0;
                        std::lock_guard<std::recursive_mutex> lk_poll(g_peers_mu);
                        for (auto& kvp : peers_) {
                            if (!kvp.second.verack_ok) continue;
                            if (sent >= 2) break;
                            Sock s = kvp.first;
                            if (can_accept_hdr_batch(kvp.second, poll_now) &&
                                check_rate(kvp.second, "hdr", 1.0, poll_now)) {
                                kvp.second.sent_getheaders = true;
                                kvp.second.inflight_hdr_batches++;
                                g_last_hdr_req_ms[s] = poll_now;
                                (void)send_or_close(s, msg);
                                sent++;
                                P2P_TRACE("POST-IBD header poll sent to " + kvp.second.ip);
                            }
                        }
                    }
                }

                    {
                    std::vector<std::vector<uint8_t>> want3;
                    chain_.next_block_fetch_targets(want3, (size_t)128);
                    if (!want3.empty()) {
                        // CRITICAL FIX: Hold g_peers_mu while iterating peers_ to prevent
                        // race condition with connect_seed() called from main thread during IBD
                        std::lock_guard<std::recursive_mutex> lk_fetch(g_peers_mu);
                        std::vector<std::pair<Sock,double>> scored;
                        for (auto& kvp : peers_) if (kvp.second.verack_ok)
                            scored.emplace_back(kvp.first, kvp.second.health_score);
                        std::sort(scored.begin(), scored.end(),
                            [](const auto&a,const auto&b){ return a.second > b.second; });
                        std::vector<Sock> cands;
                        for (auto& p : scored) cands.push_back(p.first);
                        if (cands.empty()) {
                            for (auto& kvp : peers_) cands.push_back(kvp.first);
                        }
                        for (const auto& h2 : want3) {
                        const std::string key2 = hexkey(h2);
                          if (g_global_inflight_blocks.count(key2) || orphans_.count(key2))
                          continue;
                        int64_t hdr_height2 = chain_.get_header_height(h2);
                        std::vector<Sock> filtered;
                          if (hdr_height2 >= 0) {
                            for (Sock cs : cands) {
                            auto pit = peers_.find(cs);
                            if (pit == peers_.end()) continue;
                            uint64_t peer_height = pit->second.peer_tip_height;
                          if (peer_height > 0 && peer_height < (uint64_t)hdr_height2) {
                             continue;
                           }
                           filtered.push_back(cs);

                          }
                        } else {
                          filtered = cands;
                          }
                          if (filtered.empty()) filtered = cands;
                          Sock t = rr_pick_peer_for_key(key2, filtered);
                          auto itT = peers_.find(t);
                          if (itT != peers_.end()) {
                          request_block_hash(itT->second, h2);
                        }
                      }
                    }
                }
                g_next_stall_probe_ms = tnow + g_stall_retry_ms;
            } else if (tnow >= g_next_stall_probe_ms && peers_.empty()) {
                // No peers connected - CRITICAL: actually retry DNS seeds!
                static int64_t s_last_no_peers_log_ms = 0;
                static int64_t s_last_seed_retry_ms = 0;

                if (tnow - s_last_no_peers_log_ms > 60000) {
                    s_last_no_peers_log_ms = tnow;
                    log_info("P2P: no peers connected (height=" + std::to_string(h) + ") - retrying DNS seeds");
                }

                // Retry DNS seeds every 30 seconds when we have no peers
                if (tnow - s_last_seed_retry_ms > 30000) {
                    s_last_seed_retry_ms = tnow;

                    // Clear backoff for all seeds when we're desperate for connections
                    g_seed_backoff.clear();

                    // Re-resolve and connect to DNS seeds
                    std::vector<miq::SeedEndpoint> seeds;
                    if (miq::resolve_dns_seeds(seeds, P2P_PORT, /*include_single_dns_seed=*/true)) {
                        log_info("P2P: resolved " + std::to_string(seeds.size()) + " seed(s), attempting connections...");
                        size_t boots = std::min<size_t>(seeds.size(), 3);
                        for (size_t i = 0; i < boots; ++i) {
                            if (connect_seed(seeds[i].ip, P2P_PORT)) {
                                log_info("P2P: seed connection initiated to " + seeds[i].ip);
                            }
                        }
                    } else {
                        log_warn("P2P: DNS seed resolution failed - check network connectivity");
                    }
                }
                g_next_stall_probe_ms = tnow + g_stall_retry_ms;
            }

            // CRITICAL FIX: If we have peers but they can't serve blocks we need, connect to seeds
            // This handles the case where a node is only connected to peers that are behind
            // (e.g., connected to a node that's still syncing itself)
            // Use 10 seconds instead of 30 - faster detection of incapable peers
            if (!peers_.empty() && tnow - g_last_progress_ms > 10000) {
                // Check if any peer can serve the blocks we need
                uint64_t our_height = chain_.height();
                bool found_capable_peer = false;
                for (const auto& kvp : peers_) {
                    if (!kvp.second.verack_ok) continue;
                    // Peer is capable if their announced tip is ahead of us
                    if (kvp.second.peer_tip_height > our_height) {
                        found_capable_peer = true;
                        break;
                    }
                }

                if (!found_capable_peer) {
                    static int64_t s_last_no_capable_log_ms = 0;
                    static int64_t s_last_no_capable_seed_ms = 0;

                    if (tnow - s_last_no_capable_log_ms > 30000) {
                        s_last_no_capable_log_ms = tnow;
                        log_warn("P2P: No peers can serve blocks above height " + std::to_string(our_height) +
                                 " - connecting to seeds");
                    }

                    // Try seeds every 10 seconds when stuck (faster than before)
                    if (tnow - s_last_no_capable_seed_ms > 10000) {
                        s_last_no_capable_seed_ms = tnow;
                        std::vector<miq::SeedEndpoint> seeds;
                        if (miq::resolve_dns_seeds(seeds, P2P_PORT, /*include_single_dns_seed=*/true)) {
                            size_t boots = std::min<size_t>(seeds.size(), 3);
                            for (size_t i = 0; i < boots; ++i) {
                                // Check if we're not already connected to this seed
                                bool already_connected = false;
                                for (const auto& kvp : peers_) {
                                    if (kvp.second.ip == seeds[i].ip) {
                                        already_connected = true;
                                        break;
                                    }
                                }
                                if (!already_connected) {
                                    if (connect_seed(seeds[i].ip, P2P_PORT)) {
                                        log_info("P2P: Connected to seed " + seeds[i].ip + " for additional sync capacity");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // === NEW: Adaptive timeout & retry for inflight blocks =======================
        {
          // CRITICAL FIX: Hold g_peers_mu to prevent race with connect_seed() from main thread
          std::lock_guard<std::recursive_mutex> lk_timeout(g_peers_mu);
          const int64_t tnow = now_ms();
          std::vector<std::pair<Sock,std::string>> expired;

          // Use adaptive timeout based on peer performance
          for (auto& bySock : g_inflight_block_ts) {
            auto pit = peers_.find(bySock.first);
            if (pit == peers_.end()) continue;

            PeerState& ps = pit->second;

            // Calculate adaptive timeout for this peer
            // Base timeout: use peer's average delivery time + 3 standard deviations (generous)
            // During IBD: multiply by 3 to be extra lenient with slow seeds
            // After IBD: use 2x for faster response
            int64_t base_timeout = ps.avg_block_delivery_ms;

            // Add buffer based on peer health (unhealthy peers get more time)
            double health_multiplier = 2.0 - ps.health_score; // 1.0 (healthy) to 2.0 (unhealthy)

            // IBD multiplier: 3x during sync, 1.5x after
            double ibd_multiplier = !g_logged_headers_done ? 3.0 : 1.5;

            // Final adaptive timeout
            int64_t adaptive_timeout = (int64_t)(base_timeout * health_multiplier * ibd_multiplier);

            // CRITICAL FIX: Aggressive timeouts to prevent forks
            // min 5s (fast retry), max 30s during IBD, max 15s after
            int64_t min_timeout = 5000;   // Was 30000 - way too slow
            int64_t max_timeout = !g_logged_headers_done ? 30000 : 15000;  // Was 180000/60000
            adaptive_timeout = std::max(min_timeout, std::min(max_timeout, adaptive_timeout));

            // Check each inflight block for this peer
            for (auto& kv : bySock.second) {
              if (tnow - kv.second > adaptive_timeout) {
                expired.emplace_back(bySock.first, kv.first);
                // Track failed delivery for health score
                ps.blocks_failed_delivery++;
                ps.health_score = std::max(0.1, ps.health_score * 0.9); // Decay health on timeout
                // CRITICAL: Record block failure in IP history (survives reconnects)
                record_ip_block_result(ps.ip, false);
              }
            }
          }

          if (!expired.empty()) {
            log_info("P2P: " + std::to_string(expired.size()) + " inflight block(s) timed out (adaptive) - retrying from other peers");
          }
          for (auto& e : expired) {
            Sock s_exp = e.first; const std::string& k = e.second;
            auto itp = peers_.find(s_exp);
            if (itp != peers_.end()) itp->second.inflight_blocks.erase(k);
            g_inflight_block_ts[s_exp].erase(k);
            g_global_inflight_blocks.erase(k);
            // hex -> raw 32 bytes
            std::vector<uint8_t> h(32);
            auto hexv = [](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return 10+(c-'a'); if(c>='A'&&c<='F')return 10+(c-'A'); return 0; };
            for (size_t i=0;i<32;i++) {
              h[i] = (uint8_t)((hexv(k[2*i])<<4) | hexv(k[2*i+1]));
            }
            // Build candidate list sorted by health score (best peers first)
            std::vector<std::pair<Sock, double>> cands_with_score;
            cands_with_score.reserve(peers_.size());
            for (auto& kv2 : peers_) {
              if (kv2.first == s_exp) continue;
              if (!kv2.second.verack_ok) continue;
              cands_with_score.emplace_back(kv2.first, kv2.second.health_score);
            }
            // If no verack_ok yet (rare early), fall back to anyone but s_exp
            if (cands_with_score.empty()) {
              for (auto& kv2 : peers_) {
                if (kv2.first == s_exp) continue;
                cands_with_score.emplace_back(kv2.first, kv2.second.health_score);
              }
            }

            // Sort by health score (descending) - prioritize healthy peers
            std::sort(cands_with_score.begin(), cands_with_score.end(),
                     [](const auto& a, const auto& b) { return a.second > b.second; });

            // Extract just the sockets for round-robin
            std::vector<Sock> cands;
            cands.reserve(cands_with_score.size());
            for (const auto& p : cands_with_score) {
              cands.push_back(p.first);
            }

            // Round-robin pick per-hash; try a few candidates until one accepts
            // Prioritize healthier peers by trying them first
            if (!cands.empty()) {
              size_t attempts = std::min<size_t>(cands.size(), 4);
              for (size_t tries = 0; tries < attempts; ++tries) {
                Sock target = rr_pick_peer_for_key(k, cands);
                if (target == MIQ_INVALID_SOCK) break;
                auto itpeer = peers_.find(target);
                if (itpeer == peers_.end()) continue;
                size_t before = itpeer->second.inflight_blocks.size();
                request_block_hash(itpeer->second, h);
                if (itpeer->second.inflight_blocks.size() > before) {
                  break; // successfully queued with this peer
                }
              }
            }
          }
        }

          {
          // CRITICAL FIX: Hold g_peers_mu to prevent race with connect_seed() from main thread
          std::lock_guard<std::recursive_mutex> lk_idx_timeout(g_peers_mu);
          const int64_t tnow = now_ms();
          // Oldest-first per-peer: check deque front(s) only each tick, bounded effort
          struct Exp { Sock s; uint64_t idx; int64_t ts; };
          std::vector<Exp> expired_idx;
          expired_idx.reserve(64);

          for (auto &kv : g_inflight_index_order){
            Sock s = kv.first;
            auto &dq = kv.second;
            if (dq.empty()) continue;
            auto pit = peers_.find(s);
            if (pit == peers_.end()) continue;
            miq::PeerState &ps = pit->second;

            int checked = 0;
            while (!dq.empty() && checked < 8){
              uint64_t idx = dq.front();
              auto itts = g_inflight_index_ts[s].find(idx);
              if (itts == g_inflight_index_ts[s].end()){
                dq.pop_front();
                continue;
              }
              int64_t ts = itts->second;
              if (tnow - ts > adaptive_index_timeout_ms(ps)){
                expired_idx.push_back({s, idx, ts});
                dq.pop_front();
                g_inflight_index_ts[s].erase(idx);
                // Clear from global tracking immediately on timeout - allows other peers to try
                {
                    InflightLock lk(g_inflight_lock);
                    g_global_requested_indices.erase(idx);
                }
                if (ps.inflight_index > 0) ps.inflight_index--; // free a slot on original peer
                // CRITICAL FIX: Decay health on index-based timeout (same as hash-based)
                // BUG: Previously only hash-based timeouts decayed health (line 5657)
                // Index-based timeouts didn't decay health, causing peers that don't respond
                // to index requests to keep high health while actively-delivering peers got punished
                ps.blocks_failed_delivery++;
                ps.health_score = std::max(0.1, ps.health_score * 0.9);
                // CRITICAL: Record block failure in IP history (survives reconnects)
                record_ip_block_result(ps.ip, false);
              } else {
                break; // front is still within timeout window
              }
              ++checked;
              if ((int)expired_idx.size() >= 64) break;
            }
            if ((int)expired_idx.size() >= 64) break;
          }

          // Re-issue timed-out indices to healthier peers, round-robin by index
          for (const auto &e : expired_idx){
            // Build candidate set excluding original socket
            std::vector<std::pair<Sock,double>> scored;
            mark_index_timeout(e.s);
            for (auto &kvp : peers_){
              if (kvp.first == e.s) continue;
              if (!kvp.second.verack_ok) continue;
              scored.emplace_back(kvp.first, kvp.second.health_score);
            }
            Sock target = MIQ_INVALID_SOCK;
            if (!scored.empty()){
              std::sort(scored.begin(), scored.end(),
                        [](const auto&a,const auto&b){ return a.second > b.second; });
              std::vector<Sock> socks; socks.reserve(scored.size());
              for (auto &p: scored) socks.push_back(p.first);
              target = rr_pick_peer_for_key(miq_idx_key(e.idx), socks);
            } else {
              target = e.s; // fallback: retry same peer if no alternatives
            }
            auto itT = peers_.find(target);
            if (itT == peers_.end()) continue;
            uint8_t p8[8]; for (int i=0;i<8;i++) p8[i] = (uint8_t)((e.idx>>(8*i))&0xFF);
            auto msg = encode_msg("getbi", std::vector<uint8_t>(p8,p8+8));
            if (send_or_close(target, msg)){
              g_inflight_index_ts[target][e.idx] = now_ms();
              g_inflight_index_order[target].push_back(e.idx);
              // Re-add to global tracking for the new peer
              {
                  InflightLock lk(g_inflight_lock);
                  g_global_requested_indices.insert(e.idx);
              }
              itT->second.inflight_index++;
            }
          }

          // CRITICAL FIX: Track if ANY peer gets demoted this tick
          // If so, we MUST refill remaining peers after demotion completes
          bool any_peer_demoted = false;

          for (auto &kvp : peers_){
            Sock s = kvp.first;
            // CRITICAL FIX: Use same threshold as mark_index_timeout()
            // 3 was way too aggressive - caused stop-start sync behavior
            // 10 was still too aggressive after headers - increased to 30
            int threshold = !g_logged_headers_done ? 50 : 30;
            if (g_index_timeouts[s] >= threshold && g_peer_index_capable[s]) {
              // demote
              any_peer_demoted = true;
              g_peer_index_capable[s] = false;
              auto &ps = kvp.second;
              ps.syncing = false;

              // BULLETPROOF SYNC: Clear global index tracking when peer is demoted
              // This prevents indices from getting stuck in the global set
              {
                  InflightLock lk(g_inflight_lock);
                  auto idx_it = g_inflight_index_ts.find(s);
                  if (idx_it != g_inflight_index_ts.end()) {
                      for (const auto& kv : idx_it->second) {
                          g_global_requested_indices.erase(kv.first);
                      }
                  }
              }
              g_inflight_index_ts.erase(s);
              g_inflight_index_order.erase(s);
              // BITCOIN CORE FIX: Reset inflight_index AFTER clearing tracking
              ps.inflight_index = 0;

              // CRITICAL FIX: Reset peer_tip_height when peer is demoted due to timeouts
              // This prevents peer_tip_height from being stuck at incorrect values
              // after speculative requests timeout (peer doesn't have those blocks)
              // Reset to 0 to force re-discovery from next version message
              // This handles both:
              // 1. Values above current height (speculative inflation)
              // 2. Stale values below current height (outdated peer info)
              ps.peer_tip_height = 0;
              // Send getheaders immediately to re-bootstrap
#if MIQ_ENABLE_HEADERS_FIRST
              std::vector<std::vector<uint8_t>> locator;
              chain_.build_locator(locator);
              if (g_hdr_flip[s]) { for (auto &h : locator) std::reverse(h.begin(), h.end()); }
              std::vector<uint8_t> stop(32, 0);
              auto pl  = build_getheaders_payload(locator, stop);
              auto msg = encode_msg("getheaders", pl);
              if (can_accept_hdr_batch(ps, now_ms()) && check_rate(ps, "hdr", 1.0, now_ms())) {
                  ps.sent_getheaders = true;
                  (void)send_or_close(s, msg);
                  ps.inflight_hdr_batches++;
              }
#endif
            }
          }

          // CRITICAL FIX: Recovery mechanism when all peers are demoted
          // If no peers are index-capable, re-enable them to prevent sync from getting stuck
          // This handles the case where temporary network issues caused all peers to be demoted
          {
              size_t index_capable_count = 0;
              size_t verack_peers = 0;
              for (const auto& kvp : peers_) {
                  if (kvp.second.verack_ok) {
                      verack_peers++;
                      if (g_peer_index_capable[(Sock)kvp.first]) {
                          index_capable_count++;
                      }
                  }
              }
              // If we have verified peers but none are index-capable, re-enable them
              if (verack_peers > 0 && index_capable_count == 0) {
                  log_warn("P2P: All peers demoted from index sync - re-enabling for recovery");
                  for (auto& kvp : peers_) {
                      if (kvp.second.verack_ok) {
                          Sock s = kvp.first;
                          g_peer_index_capable[s] = true;
                          g_index_timeouts[s] = 0;  // Reset timeout counter
                          kvp.second.syncing = true;
                          // BITCOIN CORE FIX: Do NOT reset inflight_index - may have outstanding requests
                          kvp.second.next_index = chain_.height() + 1;
                          // CRITICAL FIX: Actually start requesting blocks after re-enabling
                          // Without this, the peer is marked as syncing but no requests are made
                          fill_index_pipeline(kvp.second);
                      }
                  }
                  any_peer_demoted = false;  // Already handled all peers
              }
          }

          // ========================================================================
          // LIVENESS INVARIANT A: DEMAND-DRIVEN SYNC (UNCONDITIONAL LEVEL CHECK)
          // If local_tip < best_known_tip, we MUST have requests in flight.
          // This runs EVERY iteration with NO time gates.
          // ========================================================================
          {
              const uint64_t chain_height = chain_.height();
              const uint64_t header_height = chain_.best_header_height();
              const uint64_t max_peer_tip = g_max_known_peer_tip.load();
              const uint64_t target_height = std::max(header_height, max_peer_tip);

              // INVARIANT CHECK: Are we behind?
              const bool behind = (target_height > 0 && chain_height < target_height);

              if (behind) {
                  // Count total inflight requests across ALL peers
                  size_t total_inflight = 0;
                  size_t capable_peers = 0;
                  size_t syncing_peers = 0;
                  for (const auto& kvp : peers_) {
                      if (!kvp.second.verack_ok) continue;
                      capable_peers++;
                      if (kvp.second.syncing) syncing_peers++;
                      total_inflight += kvp.second.inflight_index;
                  }

                  // INVARIANT ENFORCEMENT: If behind with capable peers but insufficient requests
                  // This is the CORE liveness fix - unconditional, no time gates
                  // syncing_peers is used to verify invariant: if behind, at least one peer should be syncing
                  const size_t min_inflight_threshold = std::max((size_t)1, capable_peers);
                  const bool sync_invariant_violated = (syncing_peers == 0 && capable_peers > 0);

                  if (capable_peers > 0 && (total_inflight < min_inflight_threshold || sync_invariant_violated)) {
                      // VIOLATION: We're behind but not requesting enough
                      // Force re-enable ALL peers and fill their pipelines
                      for (auto& kvp : peers_) {
                          if (!kvp.second.verack_ok) continue;
                          Sock s = kvp.first;

                          // Re-enable peer if it was demoted (regardless of timeout count)
                          if (!g_peer_index_capable[s]) {
                              g_peer_index_capable[s] = true;
                              g_index_timeouts[s] = 0;
                          }

                          // Ensure peer is syncing
                          if (!kvp.second.syncing) {
                              kvp.second.syncing = true;
                              // BITCOIN CORE FIX: Do NOT reset inflight_index
                              kvp.second.next_index = chain_height + 1;
                          }

                          // Fill pipeline (this is idempotent if already full)
                          fill_index_pipeline(kvp.second);
                      }
                  }
              }
          }

          // Refill pipelines for ALL syncing peers (complements the invariant check above)
          for (auto &kvp : peers_) {
              if (!kvp.second.syncing) continue;
              if (!peer_is_index_capable(kvp.first)) continue;
              fill_index_pipeline(kvp.second);
          }

          // CRITICAL FIX: If any peer was demoted but not all, we need to ensure remaining
          // peers actually pick up the slack. The indices were cleared from global tracking,
          // so remaining peers can now request them. Force another refill pass.
          if (any_peer_demoted) {
              for (auto &kvp : peers_) {
                  if (!kvp.second.verack_ok) continue;
                  if (!peer_is_index_capable(kvp.first)) continue;
                  // Force activate and refill for all capable peers
                  if (!kvp.second.syncing) {
                      kvp.second.syncing = true;
                      // BITCOIN CORE FIX: Do NOT reset inflight_index
                      kvp.second.next_index = chain_.height() + 1;
                  }
                  fill_index_pipeline(kvp.second);
              }
          }

          // CRITICAL FIX: Stall recovery - if no progress for N seconds, force re-enable ALL peers
          // This handles cases where all peers got demoted or stuck in invalid states
          //
          // IBD FIX: The original 500ms/2s recovery was WAY too aggressive!
          // It caused constant "NUCLEAR RECOVERY" which cancelled inflight requests
          // and created a chaotic feedback loop. IBD needs PATIENCE:
          // - Blocks download in parallel and arrive out of order
          // - A single missing block can stall the chain for seconds while it arrives
          // - Aggressive recovery makes things WORSE by cancelling good requests
          //
          // Near-tip: Keep aggressive 2s recovery for fast propagation
          // During IBD: Use 30s recovery - let the pipeline work!
          {
              const int64_t tnow = now_ms();
              const uint64_t chain_height = chain_.height();
              // CRITICAL FIX: Use MAX of header height and known peer tip
              // During IBD, header height may be 0 or incomplete
              const uint64_t header_height = chain_.best_header_height();
              const uint64_t max_peer = g_max_known_peer_tip.load();
              const uint64_t target_height = std::max(header_height, max_peer);

              // IBD FIX: Use different recovery thresholds for IBD vs near-tip
              // IBD: 30 seconds - be patient, blocks are downloading in parallel
              // Near-tip: 2 seconds - fast recovery for propagation latency
              const int64_t STALL_RECOVERY_MS = miq::is_ibd_mode() ? 30000 : 2000;

              // Check if we're stalled: no progress, not fully synced, have peers
              if (!peers_.empty() &&
                  target_height > 0 &&
                  chain_height < target_height &&
                  (tnow - g_last_progress_ms) > STALL_RECOVERY_MS) {

                  log_warn("P2P: Sync stalled for " + std::to_string(STALL_RECOVERY_MS/1000) +
                           "s at height " + std::to_string(chain_height) +
                           "/" + std::to_string(target_height) + " - forcing recovery");

                  // CRITICAL FIX: Clear ALL global requested indices above current height
                  // This handles orphaned indices that got stuck without per-peer tracking
                  // Without this, fill_index_pipeline skips them forever!
                  {
                      InflightLock lk(g_inflight_lock);
                      size_t cleared = 0;
                      for (auto it = g_global_requested_indices.begin(); it != g_global_requested_indices.end(); ) {
                          if (*it > chain_height) {
                              it = g_global_requested_indices.erase(it);
                              cleared++;
                          } else {
                              ++it;
                          }
                      }
                      if (cleared > 0) {
                          log_info("P2P: Cleared " + std::to_string(cleared) + " orphaned indices from global tracking");
                      }
                  }

                  // Force re-enable ALL peers for sync
                  for (auto& kvp : peers_) {
                      if (!kvp.second.verack_ok) continue;
                      Sock s = kvp.first;

                      // Re-enable index capability
                      g_peer_index_capable[s] = true;
                      g_index_timeouts[s] = 0;

                      // Reset sync state
                      kvp.second.syncing = true;
                      // BITCOIN CORE FIX: Do NOT reset inflight_index
                      kvp.second.next_index = chain_height + 1;

                      // Clear per-peer inflight tracking
                      g_inflight_index_ts.erase(s);
                      g_inflight_index_order.erase(s);

                      // Fill pipeline
                      fill_index_pipeline(kvp.second);
                  }

                  // Reset progress timer to avoid immediate re-trigger
                  g_last_progress_ms = tnow;
              }
          }

          // CRITICAL FIX: Recovery mechanism for transient notfound errors
          // If peer_tip_height was reduced due to notfound but peer originally announced
          // higher, periodically reset to allow retry (peer may have had transient issue)
          {
              const int64_t tnow = now_ms();
              // PROPAGATION FIX: Reduced from 5000ms to 1000ms for sub-second guarantee
              // INVARIANT P5: "There must exist NO valid execution exceeding 1 second"
              const int64_t PEER_TIP_RECOVERY_MS = 1000;  // 1 second - TRUE fast recovery
              for (auto& kvp : peers_) {
                  PeerState& ps = kvp.second;
                  if (!ps.verack_ok) continue;
                  // If peer_tip was reduced and enough time has passed, restore it
                  if (ps.peer_tip_reduced_ms > 0 &&
                      ps.peer_tip_height < ps.announced_tip_height &&
                      (tnow - ps.peer_tip_reduced_ms > PEER_TIP_RECOVERY_MS)) {
                      log_info("P2P: Recovering peer_tip_height for " + ps.ip +
                               " from " + std::to_string(ps.peer_tip_height) +
                               " to " + std::to_string(ps.announced_tip_height) +
                               " (retry after transient failure)");
                      ps.peer_tip_height = ps.announced_tip_height;
                      ps.peer_tip_reduced_ms = 0;  // Reset recovery timer
                      // Trigger immediate pipeline refill to retry the blocks
                      if (ps.syncing && peer_is_index_capable((Sock)ps.sock)) {
                          fill_index_pipeline(ps);
                      }
                  }
              }
          }

          // ========================================================================
          // PEER ACCOUNTABILITY: Disconnect non-delivering peers quickly
          // ========================================================================
          // Peers that occupy inflight slots but deliver zero blocks waste resources.
          // AGGRESSIVE: Only give them 30s to prove they can deliver.
          // Also penalize peers that request impossible blocks from us.
          // ========================================================================
          if (miq::is_ibd_mode()) {
              static int64_t last_non_deliver_check_ms = 0;
              const int64_t tnow = now_ms();
              const int64_t NON_DELIVER_TIMEOUT_MS = 30000;  // 30 seconds (was 60s)

              if (tnow - last_non_deliver_check_ms > 5000) {  // Check every 5s (was 10s)
                  last_non_deliver_check_ms = tnow;

                  for (auto& kvp : peers_) {
                      PeerState& ps = kvp.second;
                      if (!ps.verack_ok) continue;

                      // Check if peer has had time to deliver but hasn't
                      int64_t connection_duration = (ps.connected_ms > 0) ? (tnow - ps.connected_ms) : 0;
                      if (connection_duration > NON_DELIVER_TIMEOUT_MS &&
                          ps.total_blocks_received == 0 &&
                          ps.peer_tip_height > 0) {
                          // Peer claims to have blocks but delivered zero
                          log_warn("P2P: Disconnecting non-delivering peer " + ps.ip +
                                   " (connected " + std::to_string(connection_duration/1000) + "s" +
                                   ", claims tip=" + std::to_string(ps.peer_tip_height) +
                                   ", delivered=0 blocks)");

                          // Clear inflight tracking for this peer
                          Sock s = kvp.first;
                          {
                              InflightLock lk(g_inflight_lock);
                              auto idx_it = g_inflight_index_ts.find(s);
                              if (idx_it != g_inflight_index_ts.end()) {
                                  for (const auto& kv : idx_it->second) {
                                      g_global_requested_indices.erase(kv.first);
                                  }
                              }
                          }
                          g_inflight_index_ts.erase(s);
                          g_inflight_index_order.erase(s);
                          g_peer_index_capable.erase(s);

                          // Mark for disconnection
                          schedule_close(s);
                      }
                  }
              }
          }

          // ========================================================================
          // CRITICAL: Clean up ALL stale state when no peers connected
          // This prevents stale global indices from blocking new connections
          // ========================================================================
          {
              static int64_t last_empty_cleanup_ms = 0;
              const int64_t tnow = now_ms();

              // Count verack_ok peers
              size_t active_peers = 0;
              for (const auto& kvp : peers_) {
                  if (kvp.second.verack_ok) active_peers++;
              }

              // If no active peers, clean up all stale state
              if (active_peers == 0 && tnow - last_empty_cleanup_ms > 1000) {
                  last_empty_cleanup_ms = tnow;

                  // Clear all global request tracking
                  {
                      InflightLock lk(g_inflight_lock);
                      if (!g_global_requested_indices.empty()) {
                          log_warn("P2P: Clearing " + std::to_string(g_global_requested_indices.size()) +
                                   " stale global indices (no active peers)");
                          g_global_requested_indices.clear();
                      }
                  }

                  // Clear per-peer tracking maps
                  g_inflight_index_ts.clear();
                  g_inflight_index_order.clear();
                  g_inflight_block_ts.clear();
                  g_global_inflight_blocks.clear();
              }
          }

          // ========================================================================
          // NUCLEAR SAFETY NET: Unconditional sync recovery
          // ========================================================================
          // This is the ultimate failsafe when sync is completely stuck.
          // PATIENT during IBD: Only trigger after 10 seconds of no activity
          // Near-tip: 200ms for fast propagation (sub-second guarantee)
          // ========================================================================
          {
              static int64_t last_nuclear_check_ms = 0;
              const int64_t tnow = now_ms();
              const uint64_t chain_height = chain_.height();
              const uint64_t max_peer = g_max_known_peer_tip.load();
              const uint64_t header_height = chain_.best_header_height();
              const uint64_t target_height = std::max(header_height, max_peer);

              // PATIENT during IBD: Check every 10s (not 200ms!) to avoid chaotic recovery
              // Near-tip: Check every 200ms for sub-second block propagation
              const int64_t nuclear_interval = miq::is_ibd_mode() ? 10000 : 200;

              if ((tnow - last_nuclear_check_ms > nuclear_interval) &&
                  !peers_.empty() &&
                  target_height > 0 &&
                  chain_height < target_height) {

                  last_nuclear_check_ms = tnow;

                  // Check if ANY peer is actively making progress
                  bool any_active = false;
                  size_t total_inflight = 0;
                  for (const auto& kvp : peers_) {
                      if (kvp.second.syncing && kvp.second.inflight_index > 0) {
                          any_active = true;
                      }
                      total_inflight += kvp.second.inflight_index;
                  }

                  // Also check global requested indices
                  size_t global_inflight = 0;
                  {
                      InflightLock lk(g_inflight_lock);
                      global_inflight = g_global_requested_indices.size();
                  }

                  // NUCLEAR RECOVERY: Only trigger if we've made ZERO progress for extended period
                  // AND we have peers that should be sending us blocks
                  // COOLDOWN FIX: Track last trigger time and last height to prevent thrashing
                  static int64_t last_nuclear_trigger_ms = 0;
                  static uint64_t last_nuclear_height = 0;
                  const int64_t nuclear_cooldown_ms = 30000;  // 30 second cooldown between nuclear events

                  bool needs_recovery = false;
                  if (!any_active && total_inflight == 0 && global_inflight == 0) {
                      // Additional checks: Only fire if we haven't made progress AND haven't fired recently
                      bool cooldown_passed = (tnow - last_nuclear_trigger_ms > nuclear_cooldown_ms);
                      bool no_progress = (chain_height == last_nuclear_height || last_nuclear_height == 0);

                      if (cooldown_passed && no_progress) {
                          needs_recovery = true;
                      }
                  }

                  // Also recover if we have global indices but no peer tracking them
                  // (indicates stale state from disconnected peers)
                  // Apply same cooldown to stale indices recovery
                  if (!needs_recovery && global_inflight > 0) {
                      bool cooldown_passed = (tnow - last_nuclear_trigger_ms > nuclear_cooldown_ms);
                      if (cooldown_passed) {
                          size_t tracked_by_peers = 0;
                          for (const auto& kv : g_inflight_index_ts) {
                              tracked_by_peers += kv.second.size();
                          }
                          if (tracked_by_peers == 0) {
                              needs_recovery = true;
                              log_warn("P2P: Stale global indices detected (" +
                                       std::to_string(global_inflight) + " global, 0 tracked)");
                          }
                      }
                  }

                  if (needs_recovery) {
                      // Update cooldown tracking
                      last_nuclear_trigger_ms = tnow;
                      last_nuclear_height = chain_height;

                      log_warn("P2P: NUCLEAR RECOVERY - no active sync, forcing all peers to restart");

                      // Clear stale global state first
                      {
                          InflightLock lk(g_inflight_lock);
                          g_global_requested_indices.clear();
                      }
                      g_inflight_index_ts.clear();
                      g_inflight_index_order.clear();

                      for (auto& kvp : peers_) {
                          if (!kvp.second.verack_ok) continue;
                          Sock s = kvp.first;
                          // Force re-enable EVERYTHING
                          g_peer_index_capable[s] = true;
                          g_index_timeouts[s] = 0;
                          kvp.second.syncing = true;
                          // BITCOIN CORE FIX: Do NOT reset inflight_index
                          kvp.second.next_index = chain_height + 1;
                          // Fill pipeline
                          fill_index_pipeline(kvp.second);
                      }
                  }
              }
          }

          // ========================================================================
          // RUNTIME PROOF: Scheduling Invariant Assertions (STEP 6)
          // These assertions verify that the level-triggered scheduling invariants
          // hold at runtime. They log warnings (not crashes) to prove correctness.
          // ========================================================================
          #if MIQ_TIMING_INSTRUMENTATION
          {
              static int64_t last_invariant_check_ms = 0;
              const int64_t tnow = now_ms();

              // Check every 100ms
              if (tnow - last_invariant_check_ms > 100) {
                  last_invariant_check_ms = tnow;

                  const uint64_t chain_height = chain_.height();
                  const uint64_t max_peer = g_max_known_peer_tip.load();
                  const uint64_t header_height = chain_.best_header_height();
                  const uint64_t target_height = std::max(header_height, max_peer);
                  const bool force_mode = g_force_completion_mode.load(std::memory_order_relaxed);

                  // INVARIANT 1: If behind AND force_mode AND peers available → must have inflight
                  if (chain_height < target_height && force_mode) {
                      size_t total_inflight = 0;
                      size_t capable_peers = 0;
                      for (const auto& kvp : peers_) {
                          if (!kvp.second.verack_ok) continue;
                          if (!g_peer_index_capable[(Sock)kvp.first]) continue;
                          capable_peers++;
                          total_inflight += kvp.second.inflight_index;
                      }

                      if (capable_peers > 0 && total_inflight == 0) {
                          log_warn("[INVARIANT VIOLATION] Behind tip with force_mode and " +
                                  std::to_string(capable_peers) + " capable peers but 0 inflight");
                      }
                  }

                  // INVARIANT 2: If force_mode → at least 2 peers should be requesting same indices
                  // (This is the whole point of force_mode - duplicate requests)
                  if (force_mode && chain_height < target_height) {
                      size_t requesting_peers = 0;
                      for (const auto& kvp : peers_) {
                          if (!kvp.second.verack_ok) continue;
                          if (kvp.second.inflight_index > 0) requesting_peers++;
                      }

                      if (requesting_peers < 2 && peers_.size() >= 2) {
                          // Only warn if we have multiple peers but only one is requesting
                          size_t verack_peers = 0;
                          for (const auto& kvp : peers_) {
                              if (kvp.second.verack_ok) verack_peers++;
                          }
                          if (verack_peers >= 2) {
                              static int64_t last_dup_warn = 0;
                              if (tnow - last_dup_warn > 1000) {
                                  last_dup_warn = tnow;
                                  log_warn("[INVARIANT SOFT] force_mode but only " +
                                          std::to_string(requesting_peers) + " of " +
                                          std::to_string(verack_peers) + " peers requesting");
                              }
                          }
                      }
                  }
              }
          }
          #endif

          // ========================================================================
          // CRITICAL FIX: Orphaned Index Cleanup
          // Indices can get "orphaned" in g_global_requested_indices when:
          // 1. Peer disconnects without cleanup
          // 2. Race condition between timeout and disconnect
          // 3. Index removed from peer tracking but not global tracking
          // This causes sync to stall because fill_index_pipeline skips these indices
          // Run every 200ms for INSTANT recovery from stalls!
          // ========================================================================
          {
              static int64_t last_orphan_cleanup_ms = 0;
              const int64_t tnow = now_ms();
              if (tnow - last_orphan_cleanup_ms > 200) {  // Every 200ms - INSTANT RECOVERY
                  last_orphan_cleanup_ms = tnow;

                  // Build set of ALL indices currently tracked by ANY peer
                  std::unordered_set<uint64_t> peer_tracked_indices;
                  for (const auto& kv : g_inflight_index_ts) {
                      for (const auto& idx_kv : kv.second) {
                          peer_tracked_indices.insert(idx_kv.first);
                      }
                  }

                  // Find orphaned indices (in global but not tracked by any peer)
                  std::vector<uint64_t> orphaned;
                  {
                      InflightLock lk(g_inflight_lock);
                      for (uint64_t idx : g_global_requested_indices) {
                          if (peer_tracked_indices.find(idx) == peer_tracked_indices.end()) {
                              orphaned.push_back(idx);
                          }
                      }
                      // Remove orphaned indices from global tracking
                      for (uint64_t idx : orphaned) {
                          g_global_requested_indices.erase(idx);
                      }
                  }

                  if (!orphaned.empty()) {
                      log_warn("P2P: Cleaned " + std::to_string(orphaned.size()) +
                               " orphaned indices from global tracking (first: " +
                               std::to_string(orphaned[0]) + ")");

                      // Re-request orphaned indices from available peers
                      for (uint64_t idx : orphaned) {
                          // Find best peer to request from
                          Sock target = MIQ_INVALID_SOCK;
                          double best_score = -1.0;
                          for (auto& kvp : peers_) {
                              if (!kvp.second.verack_ok) continue;
                              if (!peer_is_index_capable(kvp.first)) continue;
                              if (kvp.second.health_score > best_score) {
                                  best_score = kvp.second.health_score;
                                  target = kvp.first;
                              }
                          }
                          if (target != MIQ_INVALID_SOCK) {
                              auto itT = peers_.find(target);
                              if (itT != peers_.end()) {
                                  uint8_t p8[8];
                                  for (int i = 0; i < 8; i++) p8[i] = (uint8_t)((idx >> (8 * i)) & 0xFF);
                                  auto msg = encode_msg("getbi", std::vector<uint8_t>(p8, p8 + 8));
                                  if (send_or_close(target, msg)) {
                                      g_inflight_index_ts[target][idx] = tnow;
                                      g_inflight_index_order[target].push_back(idx);
                                      {
                                          InflightLock lk(g_inflight_lock);
                                          g_global_requested_indices.insert(idx);
                                      }
                                      itT->second.inflight_index++;
                                  }
                              }
                          }
                      }
                  }
              }
          }

          // ========================================================================
          // GAP DETECTION WITH HASH-BASED FALLBACK
          // ========================================================================
          // If we have blocks at height N+2, N+3 but not N+1, detect and re-request N+1
          // Uses hash-based requests (getb) when headers are available, falls back to getbi
          // PATIENT: Run every 2s during IBD to avoid chaotic recovery loops
          // ========================================================================
          {
              static int64_t last_gap_check_ms = 0;
              static uint64_t last_gap_index = 0;
              static int gap_request_count = 0;
              static int64_t last_pending_evict_ms = 0;
              const int64_t tnow = now_ms();

              // CRITICAL FIX: Periodically evict timed-out pending blocks
              // Previously this was only called when new blocks arrived, which
              // caused sync to completely stall - pending blocks would never
              // timeout because no new blocks could arrive.
              if (tnow - last_pending_evict_ms > 5000) {
                  last_pending_evict_ms = tnow;
                  evict_pending_blocks_if_needed();
              }

              // AGGRESSIVE: Check every 100ms to detect gaps immediately
              // Bitcoin Core-aligned: missing blocks must be detected within bounded time
              const int64_t gap_check_interval = 100;

              if (tnow - last_gap_check_ms > gap_check_interval) {
                  last_gap_check_ms = tnow;

                  const uint64_t current_height = chain_.height();
                  const uint64_t next_needed = current_height + 1;
                  const uint64_t header_height = chain_.best_header_height();

                  // Only check for gaps if we're behind header tip
                  if (header_height > 0 && current_height < header_height) {
                      // Check if we're missing the next block
                      bool have_next = pending_blocks_.find(next_needed) != pending_blocks_.end();

                      if (!have_next) {
                          // Reset counter if gap index changed (progress was made)
                          if (next_needed != last_gap_index) {
                              last_gap_index = next_needed;
                              gap_request_count = 0;
                          }

                          gap_request_count++;

                          // Clear from global tracking to allow fresh request
                          {
                              InflightLock lk(g_inflight_lock);
                              g_global_requested_indices.erase(next_needed);
                          }

                          // Also clear from all peer tracking
                          for (auto& kv : g_inflight_index_ts) {
                              kv.second.erase(next_needed);
                          }
                          for (auto& kv : g_inflight_index_order) {
                              auto& dq = kv.second;
                              dq.erase(std::remove(dq.begin(), dq.end(), next_needed), dq.end());
                          }

                          // ============================================================
                          // HASH-BASED FALLBACK: Prefer getb (by hash) over getbi
                          // ============================================================
                          // Try to get the block hash from our header chain
                          std::vector<uint8_t> block_hash;
                          bool have_hash = chain_.get_header_hash_at_height(next_needed, block_hash);

                          // DIAG: Log what hash we're requesting for missing blocks
                          if (gap_request_count == 1 && have_hash) {
                              log_info("[GAP-DIAG] Missing block " + std::to_string(next_needed) +
                                      " hash=" + hexkey(block_hash).substr(0,16) + "...");
                          } else if (gap_request_count == 1 && !have_hash) {
                              log_warn("[GAP-DIAG] Missing block " + std::to_string(next_needed) +
                                      " - NO HASH AVAILABLE from header chain!");
                          }

                          // Find best peer
                          Sock target = MIQ_INVALID_SOCK;
                          double best_score = -1.0;
                          for (auto& kvp : peers_) {
                              if (!kvp.second.verack_ok) continue;
                              if (kvp.second.health_score > best_score) {
                                  best_score = kvp.second.health_score;
                                  target = kvp.first;
                              }
                          }

                          if (gap_request_count <= 10) {
                              // First 10 attempts (20 seconds): request from best peer
                              if (gap_request_count == 1 || gap_request_count == 5 || gap_request_count == 10) {
                                  log_info("P2P: Gap at index " + std::to_string(next_needed) +
                                           " (attempt " + std::to_string(gap_request_count) + "/10)" +
                                           (have_hash ? " [using hash]" : " [using index]"));
                              }

                              if (target != MIQ_INVALID_SOCK) {
                                  auto itT = peers_.find(target);
                                  if (itT != peers_.end()) {
                                      bool sent = false;

                                      // PREFER hash-based request when we have the hash
                                      if (have_hash) {
                                          auto msg = encode_msg("getb", block_hash);
                                          if (send_or_close(target, msg)) {
                                              const std::string key = hexkey(block_hash);
                                              itT->second.inflight_blocks.insert(key);
                                              g_global_inflight_blocks.insert(key);
                                              sent = true;
                                          }
                                      }

                                      // NO getbi fallback - wait for headers
                                      // If we don't have the hash, log and continue
                                      if (!sent && !have_hash) {
                                          static int64_t last_no_hash_log = 0;
                                          if (tnow - last_no_hash_log > 5000) {
                                              last_no_hash_log = tnow;
                                              log_info("[SYNC] Gap at " + std::to_string(next_needed) +
                                                      " - waiting for header (no getbi)");
                                          }
                                      }
                                  }
                              }
                          } else if (gap_request_count <= 15) {
                              // After 10 attempts (20s): try other peers one at a time
                              static size_t peer_round_robin = 0;
                              std::vector<Sock> peers_to_try;
                              for (auto& kvp : peers_) {
                                  if (!kvp.second.verack_ok) continue;
                                  peers_to_try.push_back(kvp.first);
                              }
                              if (!peers_to_try.empty() && have_hash) {
                                  // HASH-BASED ONLY: Skip if we don't have header
                                  peer_round_robin = (peer_round_robin + 1) % peers_to_try.size();
                                  Sock try_peer = peers_to_try[peer_round_robin];
                                  auto itT = peers_.find(try_peer);
                                  if (itT != peers_.end()) {
                                      auto msg = encode_msg("getb", block_hash);
                                      send_or_close(try_peer, msg);
                                      log_info("P2P: Gap retry " + std::to_string(next_needed) +
                                               " from peer " + itT->second.ip + " [hash-based]");
                                  }
                              }
                          } else {
                              // After 15 attempts (30s): Broadcast to ALL peers
                              // But only do this ONCE per gap, then give up and wait
                              if (gap_request_count == 16 && have_hash) {
                                  // HASH-BASED BROADCAST: Only if we have the header
                                  log_warn("P2P: Gap at index " + std::to_string(next_needed) +
                                           " - broadcasting to ALL peers (final attempt) [hash-based]");

                                  int sent_count = 0;
                                  for (auto& kvp : peers_) {
                                      if (!kvp.second.verack_ok) continue;
                                      auto msg = encode_msg("getb", block_hash);
                                      if (send_or_close(kvp.first, msg)) sent_count++;
                                  }
                                  log_info("P2P: Broadcast gap " + std::to_string(next_needed) +
                                           " to " + std::to_string(sent_count) + " peers [hash-based]");
                              }
                              // After broadcast, wait 30 more seconds before trying again
                              // gap_request_count will keep incrementing but we won't spam
                          }
                      }
                  }
              }
          }
        }

        // CRITICAL FIX: Inflight transaction request timeout cleanup
        // Without this, inflight_tx can grow forever and block new transaction requests
        {
            // CRITICAL FIX: Hold g_peers_mu to prevent race with connect_seed() from main thread
            std::lock_guard<std::recursive_mutex> lk_tx_timeout(g_peers_mu);
            const int64_t tnow = now_ms();
            std::vector<std::pair<Sock, std::string>> expired_tx;
            for (auto& kv : g_inflight_tx_ts) {
                Sock sock = kv.first;
                for (auto& txkv : kv.second) {
                    if (tnow - txkv.second > INFLIGHT_TX_TIMEOUT_MS) {
                        expired_tx.emplace_back(sock, txkv.first);
                    }
                }
            }
            for (const auto& e : expired_tx) {
                g_inflight_tx_ts[e.first].erase(e.second);
                auto pit = peers_.find(e.first);
                if (pit != peers_.end()) {
                    pit->second.inflight_tx.erase(e.second);
                    // CRITICAL FIX: Also clear from recent_inv_keys so the peer can re-announce
                    // Without this, if a request times out, the peer would never be able to
                    // successfully announce this tx to us again (we'd skip it in invtx handler)
                    pit->second.recent_inv_keys.erase(e.second);
                }
            }
            if (!expired_tx.empty()) {
                MIQ_LOG_DEBUG(miq::LogCategory::NET, "inflight_tx cleanup: timed out " +
                    std::to_string(expired_tx.size()) + " stale tx requests");
            }
        }

            {
            // CRITICAL FIX: Hold g_peers_mu to prevent race with connect_seed() from main thread
            std::lock_guard<std::recursive_mutex> lk_ping(g_peers_mu);
            const int64_t tnow = now_ms();
            std::vector<Sock> to_close;
            for (auto &kv : peers_) {
                auto &ps = kv.second;
                maybe_send_feefilter(ps);
                // send ping periodically
                if (!ps.awaiting_pong && (tnow - ps.last_ping_ms) >= (int64_t)MIQ_P2P_PING_EVERY_MS) {
                    uint8_t rnd[8]; for (int i=0;i<8;i++) rnd[i] = (uint8_t)(std::rand() & 0xFF);
                    auto m = encode_msg("ping", std::vector<uint8_t>(rnd, rnd+8));
                    if (send_or_close(ps.sock, m)) {
                        ps.awaiting_pong = true;
                        ps.last_ping_ms = tnow;
                    } else {
                        to_close.push_back(ps.sock);
                    }
                }
                int64_t hard_timeout = (int64_t)MIQ_P2P_PONG_TIMEOUT_MS;
                const bool sync_active = ibd_or_fetch_active(ps, tnow);
                // CRITICAL FIX: Use 6x multiplier consistently (was 4x here, 6x elsewhere - race condition)
                if (sync_active) hard_timeout *= 6; // 6x window while syncing

                if (ps.awaiting_pong) {
                    const int64_t waited = tnow - ps.last_ping_ms;
                    if (waited > hard_timeout) {
                        log_warn(std::string("P2P: ping timeout from ")+ps.ip + (sync_active?" (IBD)":""));
                        to_close.push_back(ps.sock);
                    } else if (waited > (int64_t)MIQ_P2P_PONG_TIMEOUT_MS) {
                        // Gentle nudge while within extended IBD window: resend ping
                        uint8_t rnd2[8]; for (int i=0;i<8;i++) rnd2[i] = (uint8_t)(std::rand() & 0xFF);
                        auto m2 = encode_msg("ping", std::vector<uint8_t>(rnd2, rnd2+8));
                        if (send_or_close(ps.sock, m2)) {
                            ps.last_ping_ms = tnow;
                        }
                    }
                }
            }
            for (Sock s : to_close) {
                schedule_close(s);
            }
        }

        {
            std::vector<std::vector<uint8_t>> want;
            // During IBD keep a fatter queue; after IBD smaller.
            const size_t cap = 256;
            chain_.next_block_fetch_targets(want, cap);
            g_sync_wants_active.store(!want.empty());
            
            // Request genesis block if we're completely empty
            if (want.empty() && chain_.height() == 0 && chain_.best_header_height() == 0) {
                // Request genesis from peers using the actual genesis hash from constants
                // Helper to parse GENESIS_HASH_HEX (64 hex chars -> 32 bytes)
                static std::vector<uint8_t> s_genesis_hash;
                static bool s_genesis_parsed = false;
                if (!s_genesis_parsed) {
                    s_genesis_parsed = true;
                    const char* hex = GENESIS_HASH_HEX;
                    if (hex && std::strlen(hex) == 64) {
                        s_genesis_hash.resize(32);
                        auto hv = [](char c)->int {
                            if (c >= '0' && c <= '9') return c - '0';
                            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
                            return 0;
                        };
                        for (size_t i = 0; i < 32; i++) {
                            s_genesis_hash[i] = (uint8_t)((hv(hex[2*i]) << 4) | hv(hex[2*i + 1]));
                        }
                    }
                }
                if (!s_genesis_hash.empty() && !chain_.have_block(s_genesis_hash)) {
                    want.push_back(s_genesis_hash);
                    log_info("[SYNC] Requesting genesis block for initial sync");
                }
            }

            // ========================================================================
            // LIVENESS INVARIANT: TRIPLE-LEVEL-TRIGGERED HEADER SYNC
            // Like Bitcoin Core's header-first sync:
            //   1. behind → request (level check: if behind and no inflight, request)
            //   2. stalled → rotate (level check: if request outstanding too long, try another peer)
            //   3. peer regress → re-evaluate (level check: if peer tip went backward, re-assess)
            // No single condition may block progress.
            // ========================================================================
            if (!g_logged_headers_done) {
                const uint64_t hdr_height = chain_.best_header_height();
                const uint64_t max_peer = g_max_known_peer_tip.load();
                const int64_t current_ms = now_ms();
                constexpr int64_t HDR_STALL_TIMEOUT_MS = 10000; // 10 seconds

                // LEVEL 2: Stall detection and peer rotation
                // If a peer has had headers inflight for too long, clear that peer's inflight
                // count and mark them as stalled so we try another peer
                for (auto& kv : peers_) {
                    auto& ps = kv.second;
                    if (ps.inflight_hdr_batches > 0) {
                        auto it = g_last_hdr_req_ms.find((Sock)ps.sock);
                        if (it != g_last_hdr_req_ms.end()) {
                            int64_t elapsed = current_ms - it->second;
                            if (elapsed > HDR_STALL_TIMEOUT_MS) {
                                // STALL DETECTED: Rotate away from this peer
                                log_info("[SYNC] Header stall on peer " + ps.ip +
                                         " (waited " + std::to_string(elapsed) + "ms) - rotating");
                                ps.inflight_hdr_batches = 0;
                                ps.hdr_stall_count++;
                                // Reduce reputation slightly for slow response
                                ps.reputation_score = std::max(0.1, ps.reputation_score - 0.1);
                            }
                        }
                    }
                }

                // LEVEL 3: Peer tip regression detection
                // Track each peer's announced height; if it regresses, force re-evaluation
                // (handled via g_max_known_peer_tip atomic - if max decreases, we still re-check)

                // Check if ANY peer has headers in flight (after stall rotation)
                size_t total_hdr_inflight = 0;
                for (const auto& kvp : peers_) {
                    total_hdr_inflight += kvp.second.inflight_hdr_batches;
                }

                // LEVEL 1: Behind → request (unconditional)
                // INVARIANT: If we're behind on headers and nothing in flight, request now
                if (max_peer > 0 && hdr_height < max_peer && total_hdr_inflight == 0) {
                    // Sort peers by reputation (best first) and stall count (fewest first)
                    std::vector<std::pair<Sock, std::pair<double, size_t>>> candidates;
                    for (auto& kv : peers_) {
                        auto& ps = kv.second;
                        if (!ps.verack_ok) continue;
                        if (!can_accept_hdr_batch(ps, current_ms)) continue;
                        // Penalize peers that have stalled before
                        double adj_rep = ps.reputation_score / (1.0 + ps.hdr_stall_count * 0.5);
                        candidates.push_back({kv.first, {adj_rep, ps.hdr_stall_count}});
                    }
                    // Sort by adjusted reputation descending
                    std::sort(candidates.begin(), candidates.end(),
                              [](const auto& a, const auto& b) { return a.second.first > b.second.first; });

                    // Request from best candidate
                    for (auto& cand : candidates) {
                        auto it = peers_.find(cand.first);
                        if (it == peers_.end()) continue;
                        auto& ps = it->second;

                        std::vector<std::vector<uint8_t>> locator;
                        chain_.build_locator(locator);
                        if (g_hdr_flip[(Sock)ps.sock]) {
                            for (auto& h : locator) std::reverse(h.begin(), h.end());
                        }
                        std::vector<uint8_t> stop(32, 0);
                        auto pl = build_getheaders_payload(locator, stop);
                        auto msg = encode_msg("getheaders", pl);
                        if (send_or_close(ps.sock, msg)) {
                            ps.sent_getheaders = true;
                            ps.inflight_hdr_batches++;
                            g_last_hdr_req_ms[(Sock)ps.sock] = current_ms;
                            break; // Request from one peer at a time
                        }
                    }
                }
            }

            // Debug logging for sync issues
            if (want.empty() && !g_logged_headers_done) {
                static int64_t last_fallback_activation = 0;
                int64_t now = now_ms();

                // For seed nodes with existing blocks, this is normal - reduce log spam
                bool we_are_seed = std::getenv("MIQ_FORCE_SEED") != nullptr;

                // Enhanced fallback: request headers from all connected peers (TIME-GATED BACKUP)
                if (!we_are_seed && now - last_fallback_activation > MIQ_IBD_FALLBACK_AFTER_MS) {
                    last_fallback_activation = now;
                    log_info("[SYNC] Activating enhanced synchronization fallback");
                    
                    // Request headers from all connected peers
                    for (auto& kv : peers_) {
                        auto& ps = kv.second;
                        if (!ps.verack_ok) continue;
                        
                        // Request headers
                        std::vector<std::vector<uint8_t>> locator;
                        chain_.build_locator(locator);
                        std::vector<uint8_t> stop(32, 0);
                        auto pl = build_getheaders_payload(locator, stop);
                        auto msg = encode_msg("getheaders", pl);
                        if (send_or_close(ps.sock, msg)) {
                            ps.sent_getheaders = true;
                            log_info("[SYNC] Requested headers from " + ps.ip);
                        }
                    }
                    
                    // ================================================================
                    // INVARIANT D FIX: Hash-Based Fetch Preferred
                    // ================================================================
                    // Hash-based fetch is PREFERRED because getbi is unreliable.
                    // However, we need a TIME-GATED FALLBACK for bootstrap:
                    // - If headers haven't arrived after 30s, enable getbi as last resort
                    // - This allows cold-start bootstrap while preferring hash-based
                    // ================================================================
                    static int64_t last_empty_targets_log = 0;
                    static int64_t headers_wait_start_ms = 0;
                    const int64_t HEADERS_FALLBACK_TIMEOUT_MS = 30000;  // 30 seconds

                    // Track when we started waiting for headers
                    if (headers_wait_start_ms == 0) {
                        headers_wait_start_ms = now;
                    }

                    // Log progress
                    if (now - last_empty_targets_log > 5000) {
                        last_empty_targets_log = now;
                        int64_t waiting_ms = now - headers_wait_start_ms;
                        log_info("[IBD] Waiting for headers (hash-based fetch preferred) - "
                                "chain_height=" + std::to_string(chain_.height()) +
                                " header_height=" + std::to_string(chain_.best_header_height()) +
                                " waited=" + std::to_string(waiting_ms/1000) + "s");
                    }

                    // Request headers aggressively
                    static int64_t last_aggressive_headers_ms = 0;
                    if (now - last_aggressive_headers_ms > 1000) {
                        last_aggressive_headers_ms = now;
                        for (auto& kvp : peers_) {
                            auto& pps = kvp.second;
                            if (!pps.verack_ok) continue;

                            std::vector<std::vector<uint8_t>> locator;
                            chain_.build_locator(locator);
                            std::vector<uint8_t> stop(32, 0);
                            auto pl = build_getheaders_payload(locator, stop);
                            auto msg = encode_msg("getheaders", pl);
                            if (send_or_close(pps.sock, msg)) {
                                pps.sent_getheaders = true;
                            }
                        }
                    }

                    // TIME-GATED FALLBACK: After 30s with no header PROGRESS, enable fallback
                    // CRITICAL FIX: Check for header STALL, not just header_height == 0
                    // BUG: Previously only triggered when header_height == 0, so partial headers
                    // (e.g., 2000 of 6000) would block fallback forever → inconsistent sync
                    int64_t waiting_ms = now - headers_wait_start_ms;
                    const uint64_t current_hdr_height = chain_.best_header_height();
                    const uint64_t target_height = g_max_known_peer_tip.load();
                    bool headers_stalled = (waiting_ms > HEADERS_FALLBACK_TIMEOUT_MS);
                    bool need_more_headers = (target_height > 0 && current_hdr_height < target_height);

                    if (headers_stalled && need_more_headers) {
                        static int64_t last_fallback_log_ms = 0;
                        if (now - last_fallback_log_ms > 10000) {
                            last_fallback_log_ms = now;
                            log_warn("[IBD] Headers stalled at " + std::to_string(current_hdr_height) +
                                    "/" + std::to_string(target_height) + " for " +
                                    std::to_string(waiting_ms/1000) + "s - activating sync fallback");
                        }

                        // Activate sync for peers
                        for (auto& kvp : peers_) {
                            auto& pps = kvp.second;
                            if (!pps.verack_ok) continue;
                            if (pps.syncing && pps.inflight_index > 0) continue;

                            g_peer_index_capable[(Sock)pps.sock] = true;
                            pps.syncing = true;
                            // BITCOIN CORE FIX: Do NOT reset inflight_index
                            pps.next_index = chain_.height() + 1;
                            fill_index_pipeline(pps);
                        }
                    }

                    g_sync_wants_active.store(true);

                    // Reset wait timer when headers ADVANCE (not just when > 0)
                    static uint64_t last_reset_header_height = 0;
                    if (current_hdr_height > last_reset_header_height) {
                        last_reset_header_height = current_hdr_height;
                        headers_wait_start_ms = now;  // Reset timer - headers are progressing
                    }
                }
            }

            if (!want.empty() && !peers_.empty()) {
                // Build candidate peer list, sorted by reputation score (best first)
                std::vector<std::pair<Sock,double>> scored;
                scored.reserve(peers_.size());
                for (auto& kvp : peers_) {
                    if (!kvp.second.verack_ok) continue;
                    // Use reputation_score for smarter peer selection
                    scored.emplace_back(kvp.first, kvp.second.reputation_score);
                }
                if (scored.empty()) {
                    for (auto& kvp : peers_) scored.emplace_back(kvp.first, kvp.second.reputation_score);
                }
                std::sort(scored.begin(), scored.end(),
                          [](const auto& a, const auto& b){ return a.second > b.second; });
                std::vector<Sock> cands; cands.reserve(scored.size());
                for (auto& p : scored) cands.push_back(p.first);

                for (const auto& h : want) {
                    const std::string key = hexkey(h);
                    // Skip if already globally in-flight (reserved by any peer)
                    if (g_global_inflight_blocks.count(key)) continue;
                    Sock t = rr_pick_peer_for_key(key, cands);
                    if (t == MIQ_INVALID_SOCK) break;
                    auto itp = peers_.find(t);
                    if (itp == peers_.end()) continue;
                    // Request from chosen peer; request_block_hash will mark globals/inflight.
                    request_block_hash(itp->second, h);
                }
            }
        }

        {
            bool any_want = false;
            {
                std::vector<std::vector<uint8_t>> want_chk;
                chain_.next_block_fetch_targets(want_chk, (size_t)1);
                any_want = !want_chk.empty();
            }
            // CRITICAL FIX: Check ALL inflight sources, including g_global_requested_indices!
            // Without this, sync was marked complete when index-based requests were pending
            bool any_inflight = !g_global_inflight_blocks.empty();
            if (!any_inflight) {
                // Check index-based requests
                InflightLock lk(g_inflight_lock);
                any_inflight = !g_global_requested_indices.empty();
            }
            if (!any_inflight) {
                for (auto &kvp : peers_) {
                    if (!kvp.second.inflight_blocks.empty()) { any_inflight = true; break; }
                    if (kvp.second.inflight_index > 0)      { any_inflight = true; break; }
                    if (kvp.second.inflight_hdr_batches > 0){ any_inflight = true; break; }
                    // Also check if peer is actively syncing
                    if (kvp.second.syncing && kvp.second.verack_ok) { any_inflight = true; break; }
                }
            }
            const bool headers_done = g_logged_headers_done;

            // CRITICAL: When headers JUST completed, immediately start block downloads
            // This ensures zero delay between headers-done and block-sync start
            if (g_headers_just_done.exchange(false)) {
                log_info("[IBD] Headers complete - activating block sync on ALL peers NOW!");
                for (auto& kvp : peers_) {
                    auto& pps = kvp.second;
                    if (!pps.verack_ok) continue;
                    // Mark peer as index-capable and start block sync
                    g_peer_index_capable[(Sock)pps.sock] = true;
                    pps.syncing = true;
                    // BITCOIN CORE FIX: Do NOT reset inflight_index
                    pps.next_index = chain_.height() + 1;
                    fill_index_pipeline(pps);
                    log_info("[IBD] Started block sync with " + pps.ip +
                             " from height " + std::to_string(pps.next_index));
                }
            }

            // Debug logging for sync completion - only executes once per session
            #if MIQ_P2P_TRACE
            static bool debug_logged = false;
            if (!any_want && !any_inflight && headers_done && !debug_logged) {
                 P2P_TRACE("Sync completion check: any_want=" + std::string(any_want ? "true" : "false") +
                          " any_inflight=" + std::string(any_inflight ? "true" : "false") +
                          " headers_done=" + std::string(headers_done ? "true" : "false") +
                          " height=" + std::to_string(chain_.height()));
                 debug_logged = true;
            }
            #endif
            // CRITICAL FIX: Don't mark sync complete or stop peers here!
            // This aggressive check caused premature sync completion and stalls.
            // The more thorough check below (truly_complete) handles sync completion properly
            // with height_too_low protection and other safety checks.
            // REMOVED: The old code stopped ALL peers when any_want was empty, which was wrong!
            // Improved sync completion logic: check if we have exhausted all sync methods
            const size_t current_height = chain_.height();
            bool can_try_index_sync = false;
            bool has_active_index_sync = false;

            // FORCE-COMPLETION MODE: Enable when ≤16 blocks from known tip
            // This ensures warm datadir sync completes in <1 second
            // CRITICAL: Also enables near-tip mode to skip fsync for fast block processing
            {
                const uint64_t target = g_max_known_peer_tip.load(std::memory_order_relaxed);
                const uint64_t best_hdr = chain_.best_header_height();
                const uint64_t sync_target = std::max(target, best_hdr);
                const bool should_force = (sync_target > current_height) &&
                                         ((sync_target - current_height) <= FORCE_COMPLETION_THRESHOLD);
                const bool was_force = g_force_completion_mode.load(std::memory_order_relaxed);
                if (should_force != was_force) {
                    g_force_completion_mode.store(should_force, std::memory_order_release);
                    // CRITICAL FIX: Also set near-tip mode to skip fsync during fast sync
                    // This is the key enabler for <1s warm datadir completion
                    miq::set_near_tip_mode(should_force);
                    if (should_force) {
                        log_info("[SYNC] FORCE-COMPLETION MODE ENABLED: " + std::to_string(sync_target - current_height) +
                                " blocks remaining - relaxing limits, skipping fsync for fast sync");

                        // ================================================================
                        // STATE-TRIGGERED FIX: Immediately refill ALL peer pipelines
                        // ================================================================
                        // When force-completion mode is enabled, duplicate requests are now
                        // allowed. Immediately re-evaluate all pipelines to allow ALL peers
                        // to request the same blocks for faster completion.
                        // This is level-triggered: state changed → immediate re-evaluation
                        // ================================================================
                        for (auto& kvp : peers_) {
                            auto& pps = kvp.second;
                            if (!pps.verack_ok) continue;

                            // Re-enable peer if it was demoted
                            Sock s = (Sock)pps.sock;
                            if (!g_peer_index_capable[s]) {
                                g_peer_index_capable[s] = true;
                                g_index_timeouts[s] = 0;
                            }

                            // Force activate and refill pipeline
                            if (!pps.syncing) {
                                pps.syncing = true;
                                // BITCOIN CORE FIX: Do NOT reset inflight_index
                                pps.next_index = current_height + 1;
                            }
                            fill_index_pipeline(pps);
                        }
                    } else {
                        log_info("[SYNC] Force-completion mode disabled - full durability restored");
                    }
                }
            }

            // Check if we have index-capable peers that could provide more blocks
            for (auto &kvp : peers_) {
                auto &pps = kvp.second;
                if (!pps.verack_ok) continue;
                if (!peer_is_index_capable((Sock)pps.sock)) continue;

                can_try_index_sync = true;
                // CRITICAL FIX: Don't require inflight_index > 0!
                // inflight_index can be 0 temporarily while still actively syncing
                // (e.g., just processed a block, about to request more)
                if (pps.syncing) {
                    has_active_index_sync = true;
                    break;
                }
            }

            // Enhanced sync completion logic with aggressive refetch mechanism
            // Track stall detection for continuous sync
            static uint64_t last_height_check = 0;
            static int64_t last_height_time = now_ms();
            static int64_t last_refetch_time = 0;
            int64_t now = now_ms();

            // Check for height progress stall - be more aggressive after headers phase
            // IBD FIX: Increased stall thresholds to prevent chaotic recovery loops
            // IBD: 30s - let blocks arrive, they're downloading in parallel
            // Near-tip: 2s - fast recovery for propagation latency
            bool height_stalled = false;
            int64_t stall_threshold = miq::is_ibd_mode() ? 30000 : 2000;

            if (current_height != last_height_check) {
                last_height_check = current_height;
                last_height_time = now;
                {
                    bool have_peer=false;
                    for (auto& kv : peers_) {
                        if (kv.second.verack_ok) { have_peer=true; break; }
                    }
                    if (!have_peer) continue;
                }
            } else if (current_height > 0) {
                int64_t stall_duration = now - last_height_time;
                if (stall_duration > stall_threshold) {
                    height_stalled = true;
                }
            }

            // Implement aggressive refetch when stalled OR proactive pipeline during IBD
            int64_t refetch_interval = headers_done ? 1000 : 3000;  // 1s after headers, 3s before - INSTANT recovery

            // CRITICAL FIX: Aggressive stale tip detection to prevent forks
            uint64_t tip_age_sec = 0;
            {
                auto tip = chain_.tip();
                uint64_t now_sec = (uint64_t)std::time(nullptr);
                uint64_t tip_time = (tip.time > 0) ? (uint64_t)tip.time : now_sec;
                tip_age_sec = (now_sec > tip_time) ? (now_sec - tip_time) : 0;
            }
            // CRITICAL FIX: Stale threshold reduced from 5 min to 60 sec for instant sync
            bool tip_is_stale = (tip_age_sec > 60);  // 60 seconds (was 5 minutes)

            // Use continuous batch pipeline: request next blocks every 200ms
            // This works both before AND after headers phase
            bool should_refetch = false;
            static int64_t last_proactive_log = 0;
            static int64_t last_stall_log = 0;
            static int64_t last_stale_tip_request = 0;

            // CRITICAL FIX: Force block requests when tip is stale - every 2 seconds (was 10s)
            if (tip_is_stale && (now - last_stale_tip_request > 2000)) {
                should_refetch = true;
                last_stale_tip_request = now;
                static int64_t last_stale_log = 0;
                if (now - last_stale_log > 30000) {
                    last_stale_log = now;
                    log_warn("[SYNC] Tip is stale (" + std::to_string(tip_age_sec/60) + "m old) - forcing block requests from all peers");
                }
            } else if ((now - last_refetch_time > 200) && (g_sequential_sync || !headers_done || current_height < chain_.best_header_height() || current_height < g_max_known_peer_tip.load())) {
                // CRITICAL FIX: Proactive pipeline during IBD - always run when behind ANY known tip
                // This ensures continuous block downloads without waiting for stall detection
                // LIVENESS FIX: Also check g_max_known_peer_tip - peers may know higher tip than headers
                should_refetch = true;
                // Rate-limit log to once per 30 seconds
                if (now - last_proactive_log > 30000) {
                    last_proactive_log = now;
                    log_info("[SYNC] Proactive pipeline active (height=" + std::to_string(current_height) + ")");
                }
            } else if (height_stalled && (now - last_refetch_time > refetch_interval)) {
                // Stall-based refetch (fallback) - this is normal during sync, not a warning
                should_refetch = true;
                // Rate-limit log to once per 60 seconds (reduced from 30s)
                if (now - last_stall_log > 60000) {
                    last_stall_log = now;
                    log_info("[SYNC] refetching blocks (height=" + std::to_string(current_height) + ")");
                }
            }

            if (should_refetch) {
                last_refetch_time = now;

                // CRITICAL: Process any pending blocks in the height-ordered queue
                // This ensures blocks waiting in queue get processed even during stalls
                process_pending_blocks();

                if (g_logged_headers_done && current_height < chain_.best_header_height()) {
                    for (auto& kvp : peers_) {
                        auto& pps = kvp.second;
                        if (!pps.verack_ok) continue;

                        // LIVENESS FIX: Re-enable demoted peers instead of skipping
                        Sock s = (Sock)pps.sock;
                        if (!g_peer_index_capable[s]) {
                            g_peer_index_capable[s] = true;
                            g_index_timeouts[s] = 0;
                        }

                        if (!pps.syncing) {
                            pps.syncing = true;
                            // BITCOIN CORE FIX: Do NOT reset inflight_index
                            pps.next_index = current_height + 1;
                            fill_index_pipeline(pps);
                        }
                    }
                }

                // Check if we're in a headers-only state
                static int64_t last_headers_only_warning = 0;
                if (headers_done && current_height < 100 && (now - last_headers_only_warning > 30000)) {
                    last_headers_only_warning = now;
                    miq::log_warn("[SYNC] ⚠️  Possible headers-only state detected:");
                    miq::log_warn("  📊 Headers phase completed (indicating ~2000+ blocks exist)");
                    miq::log_warn("  🔢 But only " + std::to_string(current_height) + " blocks synced");
                    miq::log_warn("  💾 Seed node may have headers but not block data for higher blocks");
                    miq::log_warn("  🔄 Will continue retrying periodically...");
                }

                // Force refetch next blocks from all capable peers with adaptive batching
                bool refetch_sent = false;
                for (auto& kvp : peers_) {
                    auto& pps = kvp.second;
                    if (!pps.verack_ok) continue;

                    // LIVENESS FIX: Re-enable demoted peers in refetch path
                    // This ensures demoted peers get another chance during catch-up
                    Sock peer_sock = (Sock)pps.sock;
                    if (!g_peer_index_capable[peer_sock]) {
                        g_peer_index_capable[peer_sock] = true;
                        g_index_timeouts[peer_sock] = 0;
                    }

                    // For peers that support index-based sync, use getbi
                    if (peer_is_index_capable(peer_sock)) {
                        // CRITICAL FIX: Just call fill_index_pipeline instead of manually requesting
                        // The old code called request_block_index directly without tracking inflight_index,
                        // causing the stop-start sync pattern
                        if (!pps.syncing) {
                            pps.syncing = true;
                            // BITCOIN CORE FIX: Do NOT reset inflight_index
                            pps.next_index = current_height + 1;
                        }
                        fill_index_pipeline(pps);
                        refetch_sent = true;
                    } else {
                        // For peers that don't support index-based sync, use hash-based sync (getb)
                        // Request the next block by hash from headers
                        std::vector<std::vector<uint8_t>> want;
                        chain_.next_block_fetch_targets(want, g_sequential_sync ? 1 : 10);
                        if (!want.empty()) {
                            for (const auto& h : want) {
                                request_block_hash(pps, h);
                                log_info("TX " + pps.ip + " cmd=getb hash=" + hexkey(h).substr(0, 16) + "... (hash-based sync)");
                            }
                            refetch_sent = true;
                        }
                    }
                }

                if (refetch_sent) {
                    // Reset stall timer to give refetch a chance
                    last_height_time = now;
                }
            }

            // More conservative sync completion criteria
            // Don't declare complete if we're at a suspiciously low height
            bool height_too_low = (current_height < 10000);  // Assume blockchain has more than 10k blocks

            // Only declare sync complete if:
            // 1. Headers are done AND
            // 2. No blocks wanted by hash-based sync AND
            // 3. Nothing in flight AND
            // 4. Either we have no index-capable peers OR all index-capable peers have tried and failed AND
            // 5. We're not at a suspiciously low height AND
            // 6. We haven't stalled recently
            bool truly_complete = headers_done && !any_want && !any_inflight &&
                                 (!can_try_index_sync || (current_height > 0 && !has_active_index_sync)) &&
                                 !height_too_low && !height_stalled;

            if (truly_complete) {
                if (!g_sync_green_logged) {
                    log_info(std::string("[SYNC] ✅ Node is in sync with the network at height=")
                             + std::to_string(chain_.height()));
                    g_sync_green_logged = true;
                }
            } else {
                g_sync_green_logged = false;
                #if MIQ_P2P_TRACE
                debug_logged = false; // Reset debug flag when not in sync
                #endif

                // LIVENESS: If we think we're done but could still try index sync, activate it
                // CRITICAL FIX: No time gate - this is level-triggered!
                // Also re-enable demoted peers since they might have recovered
                if (!any_want && !any_inflight && headers_done && can_try_index_sync && !has_active_index_sync) {
                    // Activate index sync on ALL peers (re-enable demoted ones too)
                    int activated_peers = 0;
                    for (auto &kvp : peers_) {
                        auto &pps = kvp.second;
                        if (!pps.verack_ok) continue;

                        // LIVENESS FIX: Re-enable demoted peers instead of skipping them
                        Sock s = kvp.first;
                        if (!g_peer_index_capable[s]) {
                            g_peer_index_capable[s] = true;
                            g_index_timeouts[s] = 0;
                        }

                        // Always reset and reactivate to ensure fresh sync
                        pps.syncing = true;
                        // BITCOIN CORE FIX: Do NOT reset inflight_index
                        pps.next_index = chain_.height() + 1;
                        fill_index_pipeline(pps);
                        activated_peers++;
                    }

                    if (activated_peers > 0) {
                        g_sync_wants_active.store(true);
                    }
                }
            }
        }

        trickle_flush();

        // --- build pollfd list (SNAPSHOT of peers_) ---
        // CRITICAL FIX: Use unique_lock so we can release before I/O operations
        // Bitcoin Core NEVER holds cs_vNodes during socket writes
        std::unique_lock<std::recursive_mutex> lk(g_peers_mu);
        std::vector<PollFD> fds;
        std::vector<Sock>   peer_fd_order;
        size_t srv_idx_v4 = (size_t)-1, srv_idx_v6 = (size_t)-1;
        size_t base = 0;

        if (srv_ != MIQ_INVALID_SOCK) {
#ifdef _WIN32
            WSAPOLLFD pf{}; pf.fd = srv_; pf.events = POLL_RD; pf.revents = 0;
            fds.push_back(pf);
#else
            fds.push_back(pollfd{ (int)srv_, POLL_RD, 0 });
#endif
            srv_idx_v4 = fds.size() - 1;
        }
        if (g_srv6_ != MIQ_INVALID_SOCK) {
#ifdef _WIN32
            WSAPOLLFD pf{}; pf.fd = g_srv6_; pf.events = POLL_RD; pf.revents = 0;
            fds.push_back(pf);
#else
            fds.push_back(pollfd{ (int)g_srv6_, POLL_RD, 0 });
#endif
            srv_idx_v6 = fds.size() - 1;
        }

        base = fds.size();
        for (auto& kv : peers_) {
            Sock fd = kv.first;
            peer_fd_order.push_back(fd);
#ifdef _WIN32
            WSAPOLLFD pf{};
            pf.fd = fd;
            pf.events = POLL_RD;
            pf.revents = 0;
            fds.push_back(pf);
#else
            fds.push_back(pollfd{ (int)fd, POLL_RD, 0 });
#endif
        }

        // OPTIMIZATION: Poll timeout tuned for platform
        // Windows has higher timer resolution overhead (~15ms min), so use larger timeout
        // to reduce unnecessary wakeups while still maintaining good responsiveness
#ifdef _WIN32
        // WINDOWS FIX: Use 15ms timeout to match Windows timer granularity
        // Using 10ms on Windows results in actual ~15ms sleeps due to scheduler quantum
        // This wastes CPU as the poll returns immediately but sleep adds ~15ms anyway
        int rc = WSAPoll(fds.data(), (ULONG)fds.size(), 15);
#else
        // Linux/macOS: Keep aggressive 10ms for sub-second propagation
        int rc = poll(fds.data(), (nfds_t)fds.size(), 10);
#endif

        // WINDOWS FIX: Improved tight loop detection with platform-specific thresholds
        // Windows has ~15ms minimum sleep granularity, so we need larger sleeps to be effective
        static int64_t last_poll_time = 0;
        static int tight_loop_count = 0;
        int64_t poll_now = now_ms();
        if (poll_now - last_poll_time < 5 && rc == 0) {
            // Poll returned immediately with no events - potential CPU burn
            tight_loop_count++;

            // Only sleep if we've been spinning for a while with no work
            // Increased threshold to 500 iterations to avoid hurting legitimate traffic
            if (tight_loop_count > 500) {
#ifdef _WIN32
                // WINDOWS FIX: Use 15ms to align with Windows timer quantum
                // 10ms sleep on Windows actually sleeps ~15ms anyway due to scheduler
                std::this_thread::sleep_for(std::chrono::milliseconds(15));
#else
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
#endif
                tight_loop_count = 0;
            }
        } else {
            // Reset counter when we have actual work to do
            tight_loop_count = 0;
        }
        last_poll_time = poll_now;

        if (rc < 0) continue;
        {
            int64_t tnow = now_ms();
            if (tnow - last_ban_purge_ms > 60000) {
                for (auto it = timed_bans_.begin(); it != timed_bans_.end(); ) {
                    if (it->second <= tnow) it = timed_bans_.erase(it);
                    else ++it;
                }
                last_ban_purge_ms = tnow;
            }
        }

        if (now_ms() - last_addr_save_ms >= (int64_t)MIQ_ADDR_SAVE_INTERVAL_MS) {
            save_addrs_to_disk(datadir_, addrv4_);
#if MIQ_ENABLE_ADDRMAN
            std::string err;
            (void)g_addrman.save(g_addrman_path, err);
#endif
            last_addr_save_ms = now_ms();
        }

        // Accept new peers (with soft inbound rate cap) - IPv4
        if (srv_ != MIQ_INVALID_SOCK && srv_idx_v4 < fds.size() && (fds[srv_idx_v4].revents & POLL_RD)) {
            sockaddr_in ca{};
#ifdef _WIN32
            int clen = (int)sizeof(ca);
#else
            socklen_t clen = sizeof(ca);
#endif
            Sock c = accept(srv_, (sockaddr*)&ca, &clen);
            P2P_TRACE("accept() returned socket=" + std::to_string((uintptr_t)c));
            if (c != MIQ_INVALID_SOCK) {
                if (is_self_endpoint(c, g_listen_port)) {
                    P2P_TRACE("reject hairpin inbound");
                    CLOSESOCK(c);
                } else {
                    (void)miq_set_nonblock(c);
                    (void)miq_set_nodelay(c);
                    miq_set_sockbufs(c);
                    miq_set_cloexec(c);
                    miq_set_keepalive(c);
                    int64_t tnow = now_ms();
                    if (tnow - inbound_win_start_ms_ > 60000) {
                        inbound_win_start_ms_ = tnow;
                        inbound_accepts_in_window_ = 0;
                    }

                    char ipbuf[64] = {0};
#ifdef _WIN32
                    InetNtopA(AF_INET, &ca.sin_addr, ipbuf, (int)sizeof(ipbuf));
#else
                    inet_ntop(AF_INET, &ca.sin_addr, ipbuf, (socklen_t)sizeof(ipbuf));
#endif

                    // For localhost testing, be more lenient with rate limits
                    uint32_t rate_limit = MIQ_P2P_NEW_INBOUND_CAP_PER_MIN;
                    if (std::string(ipbuf) == "127.0.0.1") {
                        rate_limit = 1000; // Allow 1000 connections per minute for localhost
                    }
                    if (inbound_accepts_in_window_ >= rate_limit) {
                        P2P_TRACE("reject inbound: per-minute cap (limit=" + std::to_string(rate_limit) + ")");
                        CLOSESOCK(c);
                    } else {
                        inbound_accepts_in_window_++;
                        const int64_t now = now_ms();
                        if (banned_.count(ipbuf)) {
                            P2P_TRACE(std::string("reject inbound banned(permanent) ip=") + ipbuf);
                            CLOSESOCK(c);
                        } else if (is_ip_banned(ipbuf, now)) {
                            [[maybe_unused]] int64_t ban_ms_left = 0;
                            auto itb = timed_bans_.find(std::string(ipbuf));
                            if (itb != timed_bans_.end() && itb->second > now) ban_ms_left = itb->second - now;
                            P2P_TRACE(std::string("reject inbound banned(timed) ip=") + ipbuf +
                                      " ms_left=" + std::to_string(ban_ms_left));
                            CLOSESOCK(c);
                        } else {
                            P2P_TRACE("calling handle_new_peer for " + std::string(ipbuf) + " socket=" + std::to_string((uintptr_t)c));
                            handle_new_peer(c, ipbuf);
                        }
                    }
                }
            }
        }

        // Accept new peers (with soft inbound rate cap) - IPv6
        if (g_srv6_ != MIQ_INVALID_SOCK && srv_idx_v6 < fds.size() && (fds[srv_idx_v6].revents & POLL_RD)) {
            sockaddr_in6 ca6{};
#ifdef _WIN32
            int clen6 = (int)sizeof(ca6);
#else
            socklen_t clen6 = sizeof(ca6);
#endif
            Sock c = accept(g_srv6_, (sockaddr*)&ca6, &clen6);
            if (c != MIQ_INVALID_SOCK) {
                if (is_self_endpoint(c, g_listen_port)) {
                    P2P_TRACE("reject hairpin inbound v6");
                    CLOSESOCK(c);
                } else {
                    (void)miq_set_nonblock(c);
                    (void)miq_set_nodelay(c);
                    miq_set_sockbufs(c);
                    miq_set_cloexec(c);
                    miq_set_keepalive(c);
                    int64_t tnow = now_ms();
                    if (tnow - inbound_win_start_ms_ > 60000) {
                        inbound_win_start_ms_ = tnow;
                        inbound_accepts_in_window_ = 0;
                    }
                    if (inbound_accepts_in_window_ >= MIQ_P2P_NEW_INBOUND_CAP_PER_MIN) {
                        P2P_TRACE("reject inbound v6: per-minute cap");
                        CLOSESOCK(c);
                    } else {
                        inbound_accepts_in_window_++;

                        char ipbuf[128] = {0};
#ifdef _WIN32
                        InetNtopA(AF_INET6, &ca6.sin6_addr, ipbuf, (int)sizeof(ipbuf));
#else
                        inet_ntop(AF_INET6, &ca6.sin6_addr, ipbuf, (socklen_t)sizeof(ipbuf));
#endif
                        std::string ip(ipbuf[0] ? ipbuf : "unknown");
                        const int64_t now = now_ms();
                        if (banned_.count(ip)) {
                            P2P_TRACE(std::string("reject inbound banned(permanent) ip6=") + ip);
                            CLOSESOCK(c);
                        } else if (is_ip_banned(ip, now)) {
                            [[maybe_unused]] int64_t ban_ms_left = 0;
                            auto itb = timed_bans_.find(ip);
                            if (itb != timed_bans_.end() && itb->second > now) ban_ms_left = itb->second - now;
                            P2P_TRACE(std::string("reject inbound banned(timed) ip6=") + ip +
                                      " ms_left=" + std::to_string(ban_ms_left));
                            CLOSESOCK(c);
                        } else {
                            handle_new_peer(c, ip);
                        }
                    }
                }
            }
        }

        // Read/process peers
        std::vector<Sock> dead;
        {
            // CRITICAL: Thread-safe access to g_force_close (parallel broadcast threads write to it)
            std::lock_guard<std::mutex> lk(g_force_close_mu);
            if (!g_force_close.empty()) {
                // Don't honor force-close for peers that are helping IBD; keep them alive.
                std::vector<Sock> tmp(g_force_close.begin(), g_force_close.end());
                g_force_close.clear();
                const int64_t tnow = now_ms();
                for (Sock s : tmp) {
                    auto itp = peers_.find(s);
                    if (itp != peers_.end() && ibd_or_fetch_active(itp->second, tnow)) {
                        P2P_TRACE("skip scheduled close during IBD for " + itp->second.ip);
                        continue;
                    }
                    dead.push_back(s);
                }
            }
        }
        for (size_t i = 0; i < peer_fd_order.size(); ++i) {
            if (base + i >= fds.size()) continue;
            Sock s = peer_fd_order[i];

            auto it = peers_.find(s);
            if (it == peers_.end()) continue;

            auto &ps = it->second;

            short rev = fds[base + i].revents;
            if (rev & (POLLERR | POLLHUP | POLLNVAL)) {
                std::string error_type;
                if (rev & POLLERR) error_type += "POLLERR ";
                if (rev & POLLHUP) error_type += "POLLHUP ";
                if (rev & POLLNVAL) error_type += "POLLNVAL ";
                P2P_TRACE("close poll " + error_type + "from " + ps.ip + " socket=" + std::to_string(s));
                dead.push_back(s);
                continue;
            }

            if (!dead.empty()) {
            // Build a health-sorted candidate list once.
            std::vector<std::pair<Sock,double>> scored;
            scored.reserve(peers_.size());
            for (auto &kvp : peers_) if (std::find(dead.begin(), dead.end(), kvp.first) == dead.end()) {
                if (!kvp.second.verack_ok) continue;
                scored.emplace_back(kvp.first, kvp.second.health_score);
            }
            std::sort(scored.begin(), scored.end(),
                      [](const auto&a,const auto&b){ return a.second > b.second; });
            std::vector<Sock> cands; cands.reserve(scored.size());
            for (auto &p : scored) cands.push_back(p.first);

            auto hex2raw32 = [](const std::string& k)->std::vector<uint8_t>{
                std::vector<uint8_t> h(32);
                auto hv=[](char c)->int{ if(c>='0'&&c<='9')return c-'0';
                                         if(c>='a'&&c<='f')return 10+(c-'a');
                                         if (c>='A' && c<='F')
                                             return 10 + (c - 'A');
                                         return 0;
                                     };
                for (size_t i=0;i<32;i++) h[i] = (uint8_t)((hv(k[2*i])<<4)|hv(k[2*i+1]));
                return h;
            };

            for (Sock s_dead : dead) {
                auto itp = peers_.find(s_dead);
                if (itp == peers_.end()) continue;
                PeerState ps_old = itp->second; // copy; we’ll erase soon

                // Re-issue block requests from this peer to others.
                for (const auto& key : ps_old.inflight_blocks) {
                    // free global reservation so a new peer can pick it up
                    g_global_inflight_blocks.erase(key);
                    // choose a new peer and re-request
                    if (!cands.empty()) {
                        Sock target = rr_pick_peer_for_key(key, cands);
                        auto itT = peers_.find(target);
                        if (itT != peers_.end()) {
                            auto raw = hex2raw32(key);
                            request_block_hash(itT->second, raw);
                        }
                    }
                }
                // Drop per-socket inflight timestamps for the dead peer.
                g_inflight_block_ts.erase(s_dead);
                g_inflight_tx_ts.erase(s_dead);  // CRITICAL FIX: Also clear tx inflight tracking

                // Re-issue any pending by-index requests from this peer.
                auto itIdx = g_inflight_index_ts.find(s_dead);
                if (itIdx != g_inflight_index_ts.end()) {
                    for (const auto& kv : itIdx->second) {
                        const uint64_t idx = kv.first;
                        // pick a new target (health-first)
                        Sock target = MIQ_INVALID_SOCK;
                        if (!cands.empty()) {
                            target = rr_pick_peer_for_key(miq_idx_key(idx), cands);
                        }
                        auto itT = peers_.find(target);
                        if (itT != peers_.end()) {
                            uint8_t p8[8]; for (int j=0;j<8;j++) p8[j] = (uint8_t)((idx>>(8*j))&0xFF);
                            auto msg = encode_msg("getbi", std::vector<uint8_t>(p8,p8+8));
                            if (send_or_close(target, msg)) {
                                g_inflight_index_ts[target][idx] = now_ms();
                                g_inflight_index_order[target].push_back(idx);
                                // BUG FIX: Re-add to global tracking to prevent duplicate requests
                                {
                                    InflightLock lk(g_inflight_lock);
                                    g_global_requested_indices.insert(idx);
                                }
                                itT->second.inflight_index++;
                            }
                        }
                    }
                }
                g_inflight_index_ts.erase(s_dead);
                g_inflight_index_order.erase(s_dead);

                // Log peer disconnection
                log_info("Peer: disconnected ← " + ps_old.ip + " (remaining_peers=" + std::to_string(peers_.size() - 1) + ")");

                // CRITICAL: Save peer's reputation to IP history before disconnect
                record_ip_disconnect(ps_old.ip, ps_old.reputation_score);

                // CRITICAL FIX: Record backoff time to prevent rapid reconnection
                {
                    std::lock_guard<std::mutex> lk_backoff(g_reconnect_backoff_mu);
                    // Adaptive backoff: shorter during IBD for faster recovery
                    int64_t backoff = g_logged_headers_done ? RECONNECT_BACKOFF_STEADY_MS : RECONNECT_BACKOFF_IBD_MS;
                    g_reconnect_backoff_until[ps_old.ip] = now_ms() + backoff;
                }

                // Finally, close & erase the dead peer.
                gate_on_close(s_dead);
                CLOSESOCK(s_dead);
                peers_.erase(itp);

                // Clean up all peer-related global state to prevent stale entries
                g_outbounds.erase(s_dead);
                g_zero_hdr_batches.erase(s_dead);
                g_peer_stalls.erase(s_dead);
                g_last_hdr_ok_ms.erase(s_dead);
                g_preverack_counts.erase(s_dead);
                g_trickle_last_ms.erase(s_dead);
                g_cmd_rl.erase(s_dead);

                // LEVEL-TRIGGERED FIX 3: When peer disconnects, immediately trigger
                // all remaining peers to claim the freed work (inflight cleared by gate_on_close)
                // This ensures no delay waiting for next timer tick
                if (g_force_completion_mode.load(std::memory_order_relaxed)) {
                    #if MIQ_TIMING_INSTRUMENTATION
                    int triggered_count = 0;
                    #endif
                    for (auto& remaining_kvp : peers_) {
                        auto& remaining_ps = remaining_kvp.second;
                        if (!remaining_ps.verack_ok) continue;
                        if (!peer_is_index_capable(remaining_kvp.first)) continue;
                        fill_index_pipeline(remaining_ps);
                        #if MIQ_TIMING_INSTRUMENTATION
                        triggered_count++;
                        #endif
                    }
                    #if MIQ_TIMING_INSTRUMENTATION
                    log_info("[TIMING] FIX3: peer disconnected in force_mode, triggered " +
                            std::to_string(triggered_count) + " remaining peers");
                    #endif
                    MIQ_SCHED_LOG("FIX3: peer disconnect→immediate retrigger complete");
                }
            }
            // we handled the closes ourselves; do not let them be processed elsewhere this tick
            dead.clear();
        }
            
            bool ready = (rev & POLL_RD) != 0;

            if (ready) {
                uint8_t buf[65536];
                int n = miq_recv(s, buf, sizeof(buf));
                if (n <= 0) {
                    if (n == 0) {
                        // EOF: peer closed connection gracefully
                        log_info("P2P: peer " + ps.ip + " closed connection (EOF)");
                        dead.push_back(s);
                        continue;
                    } else if (n == -2) {
                        // EAGAIN/EWOULDBLOCK: no data yet, but connection still open
                        enforce_rx_parse_deadline(ps, s);
                        continue;
                    } else {
                        // n < 0: actual error
                        log_warn("P2P: recv error from " + ps.ip + " code=" + std::to_string(n));
                        dead.push_back(s);
                        continue;
                    }
                }

                // Track total bytes received for network stats
                p2p_stats::bytes_recv.fetch_add((uint64_t)n, std::memory_order_relaxed);

                // Log received bytes during handshake phase for diagnostics
                if (!ps.verack_ok) {
                    log_info("P2P: received " + std::to_string(n) + " bytes from " + ps.ip + " (handshake in progress)");
                }

                ps.last_ms = now_ms();

                ps.rx.insert(ps.rx.end(), buf, buf + n);
                if (!ps.rx.empty()) rx_track_start(s);
                if (ps.rx.size() > MIQ_P2P_MAX_BUFSZ) {
                    if (ibd_or_fetch_active(ps, now_ms())) {
                        log_warn("P2P: oversize buffer from " + ps.ip + " during sync -> trimming oldest bytes");
                        const size_t keep = MIQ_P2P_MAX_BUFSZ / 2;
                        if (ps.rx.size() > keep) {
                            ps.rx.erase(ps.rx.begin(), ps.rx.end() - (ptrdiff_t)keep);
                        }
                        // Keep the parse deadline running; do not clear start.
                        auto itg0 = g_gate.find(s);
                        if (itg0 != g_gate.end()) itg0->second.rx_bytes = ps.rx.size();
                        continue;
                    } else {
                        log_warn("P2P: oversize buffer from " + ps.ip + " -> banning & dropping");
                        bump_ban(ps, ps.ip, "oversize-buffer", now_ms());
                        dead.push_back(s);
                        continue;
                    }
                }

                size_t off = 0;
                miq::NetMsg m;
                // BOUNDED WORK: Limit messages processed per peer per iteration
                // This ensures no single peer can monopolize CPU time
                // Remaining messages will be processed in the next loop iteration
                constexpr size_t MAX_MSGS_PER_PEER_PER_ITER = 20;
                size_t msgs_processed = 0;
                while (msgs_processed < MAX_MSGS_PER_PEER_PER_ITER) {
                    size_t off_before = off;
                    bool ok = decode_msg(ps.rx, off, m);
                    if (!ok) {
                        // Log decode failure during handshake
                        if (!ps.verack_ok && ps.rx.size() > 0) {
                            static int64_t last_decode_fail_log_ms = 0;
                            int64_t now_log = now_ms();
                            if (now_log - last_decode_fail_log_ms > 5000) {
                                last_decode_fail_log_ms = now_log;
                                log_info("P2P: decode_msg waiting for more data from " + ps.ip +
                                         " rx_buf=" + std::to_string(ps.rx.size()) + " bytes");
                            }
                        }
                        break;
                    }
                    ++msgs_processed;
                    if (m.payload.size() > MIQ_MSG_HARD_MAX) {
                        if (!ibd_or_fetch_active(ps, now_ms())) {
                            log_warn("P2P: message over hard max (" + std::to_string(m.payload.size()) + " bytes) from " + ps.ip);
                            bump_ban(ps, ps.ip, "oversize-message", now_ms());
                            dead.push_back(s);
                            break;
                        } else {
                            // During IBD be lenient: skip this frame, keep the session alive.
                            log_warn("P2P: message over hard max during sync from " + ps.ip + " -> ignoring frame without drop");
                            continue;
                        }
                    }
                  
                    size_t advanced = (off > off_before) ? (off - off_before) : 0;
                    if (advanced == 0) {
                        miq::log_warn("P2P: decoded frame made no progress; waiting for more data");
                        enforce_rx_parse_deadline(ps, s);
                        break; // do not drop; allow more bytes to arrive
                    }
                    // Incremental compaction to avoid temporary oversize before final trim.
                    if (off >= 65536 && off <= ps.rx.size()) {
                        ps.rx.erase(ps.rx.begin(), ps.rx.begin() + (ptrdiff_t)off);
                        off = 0;
                        auto itg0 = g_gate.find(s);
                        if (itg0 != g_gate.end()) itg0->second.rx_bytes = ps.rx.size();
                    }
                    std::string cmd(m.cmd, m.cmd + 12);
                    size_t z = cmd.find('\0');
                    if (z != std::string::npos) {
                        cmd.resize(z);
                    } else {
                        bool bad = false;
                        for (unsigned char ch : cmd) { if (ch < 32 || ch > 126) { bad = true; break; } }
                        if (bad) { ++ps.mis; continue; }
                    }

                    P2P_TRACE("RX " + ps.ip + " cmd=" + cmd + " len=" + std::to_string(m.payload.size()));

                    // Log commands during handshake for debugging
                    if (!ps.verack_ok) {
                        log_info("P2P: RX from " + ps.ip + " cmd=" + cmd + " len=" + std::to_string(m.payload.size()));
                    }

                    bool send_verack = false; int close_code = 0;
                    if (gate_on_command(s, cmd, send_verack, close_code)) {
                        if (close_code) { /* traced in gate_on_command */ }
                        dead.push_back(s);
                        break;
                    }

                    if (send_verack) {
                        // Send verack to acknowledge the received version
                        auto verack = encode_msg("verack", {});
                        bool verack_sent = send_or_close(s, verack);
                        log_info("P2P: TX to " + ps.ip + " cmd=verack sent=" + (verack_sent ? "OK" : "FAILED"));

                        if (verack_sent) {
                            gate_mark_sent_verack(s);
                            log_info("P2P: marked sent_verack=true for " + ps.ip);
                        }
                    }

                    if (cmd == "version" && m.payload.size() >= 12) {
                        auto rd_u32le = [](const uint8_t* p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); };
                        auto rd_u64le = [](const uint8_t* p){ uint64_t z=0; for(int i=0;i<8;i++) z |= ((uint64_t)p[i]) << (8*i); return z; };
                        ps.version  = rd_u32le(m.payload.data());
                        ps.features = rd_u64le(m.payload.data()+4);
                        if ((ps.features & MIQ_FEAT_INDEX_BY_HEIGHT) != 0) {
                            g_peer_index_capable[(Sock)ps.sock] = true;
                        }
                    }

                    auto inv_tick = [&](unsigned add)->bool{
                        int64_t tnow = now_ms();
                        if (tnow - ps.inv_win_start_ms > (int64_t)MIQ_P2P_INV_WINDOW_MS) {
                            ps.inv_win_start_ms = tnow;
                            ps.inv_in_window = 0;
                        }
                        // clamp to avoid accidental wrap
                        uint64_t next = (uint64_t)ps.inv_in_window + (uint64_t)add;
                        if (next > (uint64_t)MIQ_P2P_INV_WINDOW_CAP + 1) next = (uint64_t)MIQ_P2P_INV_WINDOW_CAP + 1;
                        ps.inv_in_window = (uint32_t)next;
                        if (ps.inv_in_window > MIQ_P2P_INV_WINDOW_CAP) {
                            if (!ibd_or_fetch_active(ps, tnow)) {
                                if ((ps.banscore += 5) >= MIQ_P2P_MAX_BANSCORE) bump_ban(ps, ps.ip, "inv-window-overflow", tnow);
                            }
                            return false;
                        }
                        return true;
                    };
                    auto remember_inv = [&](const std::string& key)->bool{
                        if (!ps.recent_inv_keys.insert(key).second) return false;
                        if (ps.recent_inv_keys.size() > 4096) {
                            ps.recent_inv_keys.clear();
                        }
                        return true;
                    };

                    auto try_finish_handshake = [&](){
                        auto itg2 = g_gate.find(s);
                        if (itg2 == g_gate.end()) return;
                        auto& gg = itg2->second;
                        if (ps.verack_ok) return;

                        // COMPATIBILITY FIX: Some peers don't send verack properly
                        // Accept handshake if we have version exchange (got_version + sent_verack)
                        // The strict check (requiring got_verack) caused sync failures with some nodes
                        bool version_exchange_complete = gg.got_version && gg.sent_verack;
                        bool strict_handshake = gg.got_version && gg.got_verack && gg.sent_verack;

                        if (!version_exchange_complete) return;

                        // Log if using lenient handshake (missing verack from peer)
                        if (version_exchange_complete && !strict_handshake) {
                            log_warn("P2P: completing handshake without peer verack for " + ps.ip + " (compatibility mode)");
                        }

                        // The handshake is complete at this point

                        ps.verack_ok = true;
                        g_index_timeouts[(Sock)s] = 0;

                        // CRITICAL FIX: Track whether we received verack from peer
                        // Peers that don't send verack are suspicious and should NOT receive
                        // block requests until they prove they're working
                        ps.received_verack = strict_handshake;

                        // ================================================================
                        // BULLETPROOF FORK VERIFICATION
                        // Before syncing, verify peer is on the same chain by checking
                        // if they have the same block at a checkpoint height we've synced
                        // ================================================================
                        const uint64_t our_height = chain_.height();
                        uint64_t verify_height = 0;
                        std::vector<uint8_t> verify_hash;

                        // Find a checkpoint height we've already synced that we can verify
                        const auto& checkpoints = miq::get_checkpoints();
                        for (auto it = checkpoints.rbegin(); it != checkpoints.rend(); ++it) {
                            if (it->height > 0 && it->height <= our_height) {
                                // We have this checkpoint block - use it for verification
                                verify_height = it->height;
                                verify_hash = miq::checkpoint_hash_to_bytes(it->hash_hex);
                                break;
                            }
                        }

                        if (verify_height > 0 && !verify_hash.empty()) {
                            // We have checkpoint blocks - REQUIRE verification before sync
                            ps.fork_verification_pending = true;
                            ps.fork_verification_sent_ms = now_ms();
                            ps.fork_verification_height = verify_height;
                            ps.syncing = false;  // Don't sync until verified
                            g_peer_index_capable[(Sock)s] = false;  // Block sync until verified

                            // Send getheaders request starting from checkpoint hash
                            // If peer is on same chain, they'll return headers building on this
                            // If peer is on fork, their response won't connect to our checkpoint
                            std::vector<std::vector<uint8_t>> locator;
                            locator.push_back(verify_hash);

                            // Check if we need to flip endianness for this peer
                            if (g_hdr_flip[(Sock)s]) {
                                std::reverse(locator[0].begin(), locator[0].end());
                            }

                            std::vector<uint8_t> stop_hash(32, 0);
                            auto payload = build_getheaders_payload(locator, stop_hash);
                            auto msg = encode_msg("getheaders", payload);
                            if (send_or_close(s, msg)) {
                                log_info("P2P: FORK VERIFICATION - requesting headers from checkpoint " +
                                        std::to_string(verify_height) + " for peer " + ps.ip);
                            }
                        } else {
                            // No checkpoint blocks yet (initial sync) - allow sync without verification
                            // Once we sync past checkpoints, new peers will be verified

                            // CRITICAL FIX: Do NOT start block sync with peers that haven't sent verack!
                            // BUG: Peers that don't send verack were getting assigned 256 block requests,
                            // never responding, getting disconnected, then reconnecting with fresh
                            // health=100% and getting more requests. This caused sync stalls.
                            if (!ps.received_verack) {
                                log_warn("P2P: NOT starting sync with " + ps.ip +
                                        " - peer hasn't sent verack (compatibility mode only)");
                                // Allow basic communication but don't assign block requests
                                ps.fork_verified = false;
                                g_peer_index_capable[(Sock)s] = false;
                                ps.syncing = false;
                            } else {
                                ps.fork_verified = true;  // Trust during initial sync
                                g_peer_index_capable[(Sock)s] = true;
                                ps.syncing = true;
                                ps.next_index = our_height + 1;
                                fill_index_pipeline(ps);
                                log_info("P2P: Initial sync - skipping fork verification for " + ps.ip +
                                        " (no checkpoint blocks yet)");
                            }
                        }

                        const int64_t hs_ms = now_ms() - gg.t_conn_ms;
                        log_info(std::string("P2P: handshake complete with ")+ps.ip+" in "+std::to_string(hs_ms)+" ms");

                        // BIP130: Send sendheaders to prefer header announcements
                        if (!ps.sent_sendheaders) {
                            auto sendheaders_msg = encode_msg("sendheaders", {});
                            if (send_or_close(s, sendheaders_msg)) {
                                ps.sent_sendheaders = true;
                            }
                        }

                        // BIP152: Announce compact block support (version 1, HIGH-BANDWIDTH mode)
                        // High-bandwidth mode = peers send us compact blocks immediately
                        // This is critical for sub-1-second block propagation
                        {
                            std::vector<uint8_t> sendcmpct_payload;
                            sendcmpct_payload.push_back(1);  // announce = 1 (HIGH-BANDWIDTH)
                            // version = 1 (8 bytes little-endian)
                            for (int i = 0; i < 8; i++) {
                                sendcmpct_payload.push_back(i == 0 ? 1 : 0);
                            }
                            auto sendcmpct_msg = encode_msg("sendcmpct", sendcmpct_payload);
                            if (send_or_close(s, sendcmpct_msg)) {
                                ps.compact_blocks_enabled = true;
                                ps.compact_high_bandwidth = true;  // We want high-bandwidth relay
                                ps.compact_version = 1;
                            }
                        }

#if MIQ_ENABLE_HEADERS_FIRST
                        const bool peer_supports_headers = (ps.features & (1ull<<0)) != 0;
                        const bool try_headers = peer_supports_headers || (MIQ_TRY_HEADERS_ANYWAY != 0) || (ps.peer_tip_height <= 1);
                        
                        // Force header sync for new nodes
                        if (chain_.best_header_height() == 0) {
                            log_info("[SYNC] New node detected, forcing header sync");
                        }
                        
                        // Share our chain tip with new peer
                        if (chain_.height() > 0) {
                            std::vector<uint8_t> tip_hash = chain_.tip_hash();
                            std::vector<uint8_t> inv_payload;
                            inv_payload.push_back(1);  // count
                            inv_payload.push_back(2);  // type (MSG_BLOCK)
                            inv_payload.insert(inv_payload.end(), tip_hash.begin(), tip_hash.end());
                            auto inv_msg = encode_msg("inv", inv_payload);
                            if (send_or_close(s, inv_msg)) {
                                log_info("[SYNC] Shared tip with new peer " + ps.ip);
                            }
                        }
                        
                        if (try_headers) {
                            std::vector<std::vector<uint8_t>> locator;
                            chain_.build_locator(locator);
                            if (g_hdr_flip[(Sock)s]) {
                                for (auto& h : locator) std::reverse(h.begin(), h.end());
                            }
                            std::vector<uint8_t> stop(32, 0);
                            auto pl2 = build_getheaders_payload(locator, stop);
                            auto m2  = encode_msg("getheaders", pl2);
                            if (can_accept_hdr_batch(ps, now_ms()) && check_rate(ps, "hdr", 1.0, now_ms())) {
                                ps.sent_getheaders = true;
                                (void)send_or_close(s, m2);
                                ps.inflight_hdr_batches++;
                                g_last_hdr_req_ms[(Sock)s] = now_ms();
                                ps.last_hdr_batch_done_ms  = now_ms();
                            }
                            if (!g_logged_headers_started) {
                                g_logged_headers_started = true;
                                log_info("[IBD] headers phase started");
                                if (!g_ibd_headers_started_ms) g_ibd_headers_started_ms = now_ms();

                                // State machine transition: CONNECTING → HEADERS
                                miq::ibd::IBDState::instance().transition_to(miq::ibd::SyncState::HEADERS);
                            }
                        } else
#endif
                        {
                            ps.syncing = true;
                            // BITCOIN CORE FIX: Do NOT reset inflight_index
                            ps.next_index = chain_.height() + 1;
                            fill_index_pipeline(ps);
                        }

                        // Ask for addresses + publish our fee filter
                        maybe_send_getaddr(ps);
                        const uint64_t mrf = local_min_relay_kb();
                        std::vector<uint8_t> plff(8);
                        for (int i=0;i<8;i++) plff[i] = (uint8_t)((mrf >> (8*i)) & 0xFF);
                        auto ff_msg = encode_msg("feefilter", plff);
                        (void)send_or_close(s, ff_msg);
                    };
  
                    if (cmd == "version") {
                        log_info("P2P: received version from " + ps.ip + " (payload=" + std::to_string(m.payload.size()) + " bytes)");
                        int32_t peer_ver = 0; uint64_t peer_services = 0;
                        if (m.payload.size() >= 4) {
                            peer_ver = (int32_t)((uint32_t)m.payload[0] | ((uint32_t)m.payload[1]<<8) | ((uint32_t)m.payload[2]<<16) | ((uint32_t)m.payload[3]<<24));
                        }
                        if (m.payload.size() >= 12) {
                            for(int j=0;j<8;j++) peer_services |= ((uint64_t)m.payload[4+j]) << (8*j);
                        }
                        log_info("P2P: peer " + ps.ip + " version=" + std::to_string(peer_ver) + " services=0x" + std::to_string(peer_services));
                        ps.version  = peer_ver;
                        ps.features = peer_services;
                        if ((peer_services & MIQ_FEAT_INDEX_BY_HEIGHT) != 0) {
                             g_peer_index_capable[(Sock)s] = true;
                        }
                        if (ps.version > 0 && ps.version < min_peer_version_) {
                            log_warn(std::string("P2P: dropping old peer ") + ps.ip);
                            dead.push_back(s);
                            break;
                        }
                        {
                            uint64_t missing = required_features_mask_ & ~ps.features;
                            const uint64_t HDR_BIT = (1ull<<0);
                            if ((missing & ~HDR_BIT) != 0) {
                                log_warn(std::string("P2P: dropping peer missing required features ") + ps.ip);
                                dead.push_back(s); break;
                            }
                    }

                    if (m.payload.size() >= 80) {
                        size_t pos = 80;
                        if (pos < m.payload.size()) {
                            uint64_t ua_len = m.payload[pos++];
                            uint64_t ua_size;
                            if (ua_len < 0xFD) {
                                ua_size = ua_len;
                            } else if (ua_len == 0xFD && pos + 2 <= m.payload.size()) {
                                ua_size = (uint64_t)m.payload[pos] | ((uint64_t)m.payload[pos + 1] << 8);
                                pos += 2;
                            } else if (ua_len == 0xFE && pos + 4 <= m.payload.size()) {
                                ua_size = (uint64_t)m.payload[pos] | ((uint64_t)m.payload[pos + 1] << 8) 
                                          | ((uint64_t)m.payload[pos + 2] << 16) | ((uint64_t)m.payload[pos + 3] << 24);
                                pos += 4;
                            } else if (ua_len == 0xFF && pos + 8 <= m.payload.size()) {
                                ua_size = 0;
                                for (int j = 0; j < 8; ++j) {
                                    ua_size |= ((uint64_t)m.payload[pos + j]) << (8 * j);
                                }
                                pos += 8;
                            } else {
                                ua_size = 0;
                            }
                            if (pos + ua_size + 4 <= m.payload.size()) {
                                uint32_t announced_height = 0;
                                announced_height |= (uint32_t)m.payload[pos + ua_size];
                                announced_height |= (uint32_t)m.payload[pos + ua_size + 1] << 8;
                                announced_height |= (uint32_t)m.payload[pos + ua_size + 2] << 16;
                                announced_height |= (uint32_t)m.payload[pos + ua_size + 3] << 24;
                                ps.peer_tip_height = announced_height;
                                ps.announced_tip_height = announced_height;  // Save original for recovery

                                // CRITICAL FIX: Track maximum known peer tip globally
                                // This prevents premature "headers done" when peers know of higher chain
                                uint64_t old_max = g_max_known_peer_tip.load();
                                bool tip_increased = false;
                                while (announced_height > old_max) {
                                    if (g_max_known_peer_tip.compare_exchange_weak(old_max, announced_height)) {
                                        log_info("P2P: New max peer tip discovered: " + std::to_string(announced_height));
                                        tip_increased = true;
                                        break;
                                    }
                                }

                                // LEVEL-TRIGGERED FIX 4: When tip increases and already in force mode,
                                // immediately trigger all peers to request the new higher indices
                                if (tip_increased && g_force_completion_mode.load(std::memory_order_relaxed)) {
                                    #if MIQ_TIMING_INSTRUMENTATION
                                    int triggered_count = 0;
                                    #endif
                                    for (auto& other_kvp : peers_) {
                                        auto& other_ps = other_kvp.second;
                                        if (!other_ps.verack_ok) continue;
                                        if (other_kvp.first == s) continue;  // Skip current peer (not ready)
                                        if (!peer_is_index_capable(other_kvp.first)) continue;
                                        fill_index_pipeline(other_ps);
                                        #if MIQ_TIMING_INSTRUMENTATION
                                        triggered_count++;
                                        #endif
                                    }
                                    #if MIQ_TIMING_INSTRUMENTATION
                                    log_info("[TIMING] FIX4: tip increased while in force_mode, triggered " +
                                            std::to_string(triggered_count) + " peers");
                                    #endif
                                    MIQ_SCHED_LOG("FIX4: tip increase→immediate trigger complete");
                                }

                                // CRITICAL FIX: Trigger immediate sync if peer has higher tip
                                // This prevents falling behind when new blocks are announced
                                const uint64_t our_height = chain_.height();
                                if (announced_height > our_height) {
                                    log_info("P2P: peer " + ps.ip + " announces height " +
                                             std::to_string(announced_height) + " (we have " +
                                             std::to_string(our_height) + ") - triggering sync");
                                    g_sync_wants_active.store(true);

                                    // ================================================================
                                    // STATE-TRIGGERED FIX: Check force-completion mode immediately
                                    // ================================================================
                                    // When we discover we're near the tip, enable force-completion
                                    // mode IMMEDIATELY - don't wait for the next loop iteration.
                                    // This ensures duplicate requests start right away.
                                    // ================================================================
                                    const uint64_t gap = announced_height - our_height;
                                    if (gap <= FORCE_COMPLETION_THRESHOLD) {
                                        const bool was_force = g_force_completion_mode.load(std::memory_order_relaxed);
                                        if (!was_force) {
                                            g_force_completion_mode.store(true, std::memory_order_release);
                                            miq::set_near_tip_mode(true);
                                            log_info("[SYNC] FORCE-COMPLETION MODE ENABLED (peer connect): " +
                                                    std::to_string(gap) + " blocks behind - immediate sync");

                                            // TIMING: Record force-mode enable time
                                            #if MIQ_TIMING_INSTRUMENTATION
                                            g_timing_force_mode_enabled_ms.store(now_ms(), std::memory_order_relaxed);
                                            int triggered_count = 0;
                                            #endif

                                            // ================================================================
                                            // LEVEL-TRIGGERED FIX: Immediately refill ALL peer pipelines
                                            // ================================================================
                                            // Bitcoin Core invariant: state change → immediate scheduling
                                            // When force_mode enables, ALL connected peers must immediately
                                            // re-evaluate their pipelines to start duplicate requests.
                                            // Without this, only the main loop iteration triggers refill,
                                            // causing 10ms+ delays that create variance.
                                            // ================================================================
                                            for (auto& other_kvp : peers_) {
                                                auto& other_ps = other_kvp.second;
                                                if (!other_ps.verack_ok) continue;
                                                if (other_kvp.first == s) continue;  // Skip current peer (not ready yet)
                                                if (!peer_is_index_capable(other_kvp.first)) continue;
                                                fill_index_pipeline(other_ps);
                                                #if MIQ_TIMING_INSTRUMENTATION
                                                triggered_count++;
                                                #endif
                                            }

                                            #if MIQ_TIMING_INSTRUMENTATION
                                            log_info("[TIMING] FIX1: force_mode enabled, triggered " +
                                                    std::to_string(triggered_count) + " peers in same call stack");
                                            #endif
                                            MIQ_SCHED_LOG("FIX1: force_mode→immediate trigger complete");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    try_finish_handshake();
                      
                    } else if (cmd == "verack") {
                        log_info("P2P: received verack from " + ps.ip + " - handshake completing");
                        P2P_TRACE("RX " + ps.ip + " cmd=verack - handshake completing");
                        auto itg = g_gate.find(s);
                        if (itg != g_gate.end()) {
                            itg->second.got_verack = true; // (already set in gate, but idempotent)
                            itg->second.hs_last_ms = now_ms();
                        }
                        g_preverack_counts.erase(s);
#if MIQ_ENABLE_ADDRMAN
                        { uint32_t be_ip; if (parse_ipv4(ps.ip, be_ip)) { miq::NetAddr na; na.host = ps.ip; na.port = g_listen_port; na.is_ipv6=false; na.tried=true; g_addrman.mark_good(na); g_addrman.add_anchor(na); } }
#endif
                        ps.whitelisted = is_loopback(ps.ip) || is_whitelisted_ip(ps.ip);
                        try_finish_handshake();

                    // ================================================================
                    // HANDSHAKE FIREWALL (Bitcoin Core-aligned)
                    // ================================================================
                    // No protocol command except version/verack/ping/pong is processed
                    // before handshake completion.
                    //
                    // CRITICAL: During IBD, NEVER disconnect for pre-handshake messages!
                    // Bitcoin Core principle: be tolerant during sync, strict at tip.
                    // Disconnecting peers during IBD risks losing our only block sources.
                    // ================================================================
                    } else if (!ps.verack_ok &&
                               cmd != "ping" && cmd != "pong") {
                        // Reject ALL commands before handshake except ping/pong
                        P2P_TRACE("FIREWALL: Rejecting cmd=" + cmd + " from " + ps.ip + " - handshake not complete");

                        // Bitcoin Core principle: During IBD, be tolerant of eager peers
                        // Only disconnect after IBD is complete (near-tip)
                        auto ibd_state = miq::ibd::IBDState::instance().current_state();
                        if (ibd_state >= miq::ibd::SyncState::DONE) {
                            // Post-IBD: strict enforcement
                            if (++ps.mis > 5) {
                                log_warn("P2P: FIREWALL: Too many pre-handshake commands from " + ps.ip + " - disconnecting");
                                dead.push_back(s);
                                break;
                            }
                        }
                        // During IBD: log but don't count toward disconnection
                        continue;

                    } else if (cmd == "ping") {
                        auto pong = encode_msg("pong", m.payload);
                        (void)send_or_close(s, pong);

                    } else if (cmd == "pong") {
                        ps.awaiting_pong = false;
#if MIQ_ENABLE_HEADERS_FIRST
                    } else if (cmd == "headers") {
                        // Free a header slot and keep pipelining while within caps.
                        std::vector<BlockHeader> hs;
                        if (!parse_headers_payload(m.payload, hs)) {
                            if (++ps.mis > 10) { dead.push_back(s); break; }
                            continue;
                        }

                        // ================================================================
                        // FORK VERIFICATION RESPONSE HANDLER
                        // If we're waiting for verification, check if headers connect to our checkpoint
                        // ================================================================
                        if (ps.fork_verification_pending) {
                            ps.fork_verification_pending = false;  // Clear pending state

                            // Get the checkpoint hash we're verifying against
                            std::vector<uint8_t> expected_prev_hash;
                            for (const auto& cp : miq::get_checkpoints()) {
                                if (cp.height == ps.fork_verification_height) {
                                    expected_prev_hash = miq::checkpoint_hash_to_bytes(cp.hash_hex);
                                    break;
                                }
                            }

                            bool verification_passed = false;
                            if (!hs.empty() && !expected_prev_hash.empty()) {
                                // Check if first header's prev_hash matches our checkpoint
                                // This proves peer has the same block at checkpoint height
                                std::vector<uint8_t> first_prev = hs[0].prev_hash;

                                // Handle endianness
                                if (g_hdr_flip[(Sock)s]) {
                                    std::reverse(first_prev.begin(), first_prev.end());
                                }

                                if (first_prev == expected_prev_hash) {
                                    verification_passed = true;
                                    log_info("P2P: FORK VERIFICATION PASSED - peer " + ps.ip +
                                            " has same chain at checkpoint " + std::to_string(ps.fork_verification_height));
                                } else {
                                    log_warn("P2P: FORK VERIFICATION FAILED - peer " + ps.ip +
                                            " has DIFFERENT block at checkpoint " + std::to_string(ps.fork_verification_height) +
                                            " (FORKED CHAIN!)");
                                }
                            } else if (hs.empty()) {
                                // Empty response could mean:
                                // 1. Peer doesn't have blocks past checkpoint (shorter chain) - OK to sync
                                // 2. Peer doesn't recognize our checkpoint (fork) - BAD
                                // We're conservative: if peer's tip is <= our checkpoint, they're OK
                                if (ps.peer_tip_height <= ps.fork_verification_height) {
                                    verification_passed = true;
                                    log_info("P2P: FORK VERIFICATION PASSED (empty response) - peer " + ps.ip +
                                            " has shorter chain, will sync when they extend");
                                } else {
                                    log_warn("P2P: FORK VERIFICATION FAILED - peer " + ps.ip +
                                            " claims tip " + std::to_string(ps.peer_tip_height) +
                                            " but doesn't have checkpoint " + std::to_string(ps.fork_verification_height) +
                                            " (FORKED CHAIN!)");
                                }
                            }

                            if (verification_passed) {
                                // Enable sync from this peer
                                ps.fork_verified = true;
                                ps.fork_detected = false;
                                ps.fork_check_height = ps.fork_verification_height;
                                g_peer_index_capable[(Sock)s] = true;
                                ps.syncing = true;
                                ps.next_index = chain_.height() + 1;
                                fill_index_pipeline(ps);
                            } else {
                                // Mark peer as forked - never sync from them
                                ps.fork_detected = true;
                                ps.fork_verified = false;
                                ps.syncing = false;
                                g_peer_index_capable[(Sock)s] = false;

                                // Add ban score for being on fork
                                ps.banscore += 50;
                                if (ps.banscore >= 100) {
                                    log_warn("P2P: Banning forked peer " + ps.ip);
                                    dead.push_back(s);
                                    continue;
                                }
                            }

                            // If verification passed and we got headers, process them normally below
                            if (!verification_passed || hs.empty()) {
                                continue;  // Don't process headers from forked peer
                            }
                        }

                        // ACCEPT HEADERS INTO CHAIN
                        size_t accepted = 0;
                        bool used_reverse = false;
                        std::string herr;
                        for (const auto& h : hs) {
                            if (chain_.accept_header(h, herr)) {
                                accepted++;
                            } else {
                                // Client-side endianness tolerance: retry with reversed 32B fields
                                BlockHeader hr = h;
                                std::reverse(hr.prev_hash.begin(),   hr.prev_hash.end());
                                std::reverse(hr.merkle_root.begin(), hr.merkle_root.end());
                                if (chain_.accept_header(hr, herr)) {
                                    accepted++;
                                    used_reverse = true;
                                }
                            }
                        }
                        if (used_reverse) { g_hdr_flip[s] = true; }

                        if (accepted > 0) {
                            // PERFORMANCE: Throttle headers logging during sync
                            static int64_t last_hdr_log_ms = 0;
                            static uint64_t hdrs_since_log = 0;
                            int64_t now_hdr_ms = now_ms();
                            hdrs_since_log += accepted;
                            if (now_hdr_ms - last_hdr_log_ms > 2000) {  // Log at most every 2 seconds
                                last_hdr_log_ms = now_hdr_ms;
                                log_info("P2P: headers accepted=" + std::to_string(hdrs_since_log) + " best_height=" + std::to_string(chain_.best_header_height()));
                                hdrs_since_log = 0;
                            }
                            // CRITICAL FIX: Do NOT update g_last_progress_ms for headers!
                            // We only want to track BLOCK progress for stall detection.
                            // Headers can arrive even when blocks are stuck, which would prevent
                            // the seed connection logic from triggering.
                            // Update the stall probe timer but NOT g_last_progress_ms
                            g_next_stall_probe_ms = now_ms() + MIQ_P2P_STALL_RETRY_MS;

                            // CRITICAL FIX: Update g_max_known_peer_tip when headers extend beyond!
                            // This handles the case where new blocks are mined AFTER we connected.
                            // Without this, we'd think we're "caught up" at the old version height
                            // and stop syncing before reaching the actual tip.
                            uint64_t new_header_height = chain_.best_header_height();

                            // IBD PERF: Update global header height for signature skip optimization
                            // This allows should_validate_signatures() to skip signatures for
                            // deeply buried blocks during IBD
                            miq::set_best_header_height(new_header_height);
                            uint64_t old_max = g_max_known_peer_tip.load();
                            while (new_header_height > old_max) {
                                if (g_max_known_peer_tip.compare_exchange_weak(old_max, new_header_height)) {
                                    log_info("P2P: Updated max peer tip from headers: " + std::to_string(new_header_height) +
                                             " (was " + std::to_string(old_max) + ")");
                                    // Also update this peer's announced tip if headers show higher
                                    if (new_header_height > ps.announced_tip_height) {
                                        ps.announced_tip_height = new_header_height;
                                        ps.peer_tip_height = new_header_height;
                                    }

                                    // CRITICAL FIX: Re-enable peer and restart sync when headers extend!
                                    // This peer just sent us headers proving they have more blocks.
                                    // If they were demoted before, they should be re-enabled now.
                                    g_peer_index_capable[(Sock)s] = true;
                                    g_index_timeouts[(Sock)s] = 0;  // Reset timeout counter
                                    if (!ps.syncing) {
                                        ps.syncing = true;
                                        // BITCOIN CORE FIX: Do NOT reset inflight_index
                                        ps.next_index = chain_.height() + 1;
                                        log_info("P2P: Re-enabled sync on " + ps.ip + " after receiving extended headers");
                                    }

                                    // ================================================================
                                    // STATE-TRIGGERED FIX: Check force-completion mode immediately
                                    // ================================================================
                                    // When header height increases, check if we're now near tip
                                    // and should enable force-completion mode for faster sync.
                                    // ================================================================
                                    const uint64_t our_height = chain_.height();
                                    if (new_header_height > our_height) {
                                        const uint64_t gap = new_header_height - our_height;
                                        if (gap <= FORCE_COMPLETION_THRESHOLD) {
                                            const bool was_force = g_force_completion_mode.load(std::memory_order_relaxed);
                                            if (!was_force) {
                                                g_force_completion_mode.store(true, std::memory_order_release);
                                                miq::set_near_tip_mode(true);
                                                log_info("[SYNC] FORCE-COMPLETION MODE ENABLED (headers): " +
                                                        std::to_string(gap) + " blocks behind");

                                                // TIMING: Record force-mode enable time
                                                #if MIQ_TIMING_INSTRUMENTATION
                                                g_timing_force_mode_enabled_ms.store(now_ms(), std::memory_order_relaxed);
                                                int triggered_count = 0;
                                                #endif

                                                // ================================================================
                                                // LEVEL-TRIGGERED FIX: Immediately refill ALL peer pipelines
                                                // ================================================================
                                                // Bitcoin Core invariant: state change → immediate scheduling
                                                // When force_mode enables via headers, ALL peers must immediately
                                                // re-evaluate to start duplicate requests.
                                                // ================================================================
                                                for (auto& other_kvp : peers_) {
                                                    auto& other_ps = other_kvp.second;
                                                    if (!other_ps.verack_ok) continue;
                                                    if (!peer_is_index_capable(other_kvp.first)) continue;
                                                    fill_index_pipeline(other_ps);
                                                    #if MIQ_TIMING_INSTRUMENTATION
                                                    triggered_count++;
                                                    #endif
                                                }

                                                #if MIQ_TIMING_INSTRUMENTATION
                                                log_info("[TIMING] FIX2: force_mode enabled (headers), triggered " +
                                                        std::to_string(triggered_count) + " peers in same call stack");
                                                #endif
                                                MIQ_SCHED_LOG("FIX2: headers→force_mode→immediate trigger complete");
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        } else if (hs.size() > 0) {
                            log_warn("P2P: Headers REJECTED from " + ps.ip + " n=" + std::to_string(hs.size()) +
                                    " accepted=0 error=" + herr);
                        }

                        g_peer_last_fetch_ms[(Sock)ps.sock] = now_ms();
                        g_last_hdr_ok_ms[(Sock)ps.sock]     = now_ms();
                        if (ps.inflight_hdr_batches > 0) ps.inflight_hdr_batches--;

                        // CRITICAL PERFORMANCE FIX: Request blocks IMMEDIATELY after accepting headers!
                        // This is essential for fast block propagation - when a peer announces a new
                        // block via headers, we must request it right away, not wait for a later cycle.
                        if (accepted > 0) {
                            std::vector<std::vector<uint8_t>> want_blocks;
                            chain_.next_block_fetch_targets(want_blocks, 64);
                            for (const auto& bh : want_blocks) {
                                const std::string key = hexkey(bh);
                                if (g_global_inflight_blocks.count(key) || orphans_.count(key))
                                    continue;
                                // Request from this peer since they just announced the header
                                request_block_hash(ps, bh);
                            }

                            // CRITICAL FIX: ALWAYS ensure index sync is active after accepting headers
                            // This ensures we sync to the new header tip even if peer was demoted
                            if (!peer_is_index_capable((Sock)s)) {
                                g_peer_index_capable[(Sock)s] = true;
                                g_index_timeouts[(Sock)s] = 0;
                                log_info("P2P: Re-enabled index capability on " + ps.ip + " after accepting " +
                                        std::to_string(accepted) + " headers");
                            }
                            if (!ps.syncing) {
                                ps.syncing = true;
                                // BITCOIN CORE FIX: Do NOT reset inflight_index
                                ps.next_index = chain_.height() + 1;
                            }
                            fill_index_pipeline(ps);

                            // ================================================================
                            // LEVEL-TRIGGERED FIX 5: Headers extended while already in force_mode
                            // ================================================================
                            // When headers extend and we're already in force_mode, ALL peers
                            // must be triggered to request the new heights immediately.
                            // Without this, only THIS peer requests new blocks, causing variance.
                            // ================================================================
                            if (g_force_completion_mode.load(std::memory_order_relaxed)) {
                                #if MIQ_TIMING_INSTRUMENTATION
                                int triggered_count = 0;
                                #endif
                                for (auto& other_kvp : peers_) {
                                    auto& other_ps = other_kvp.second;
                                    if (!other_ps.verack_ok) continue;
                                    if (other_kvp.first == s) continue;  // Already handled above
                                    if (!peer_is_index_capable(other_kvp.first)) continue;
                                    fill_index_pipeline(other_ps);
                                    #if MIQ_TIMING_INSTRUMENTATION
                                    triggered_count++;
                                    #endif
                                }
                                #if MIQ_TIMING_INSTRUMENTATION
                                if (triggered_count > 0) {
                                    log_info("[TIMING] FIX5: headers extended in force_mode, triggered " +
                                            std::to_string(triggered_count) + " other peers");
                                }
                                #endif
                            }
                        }

                        if (hs.empty()) {
                            // Empty batch => likely tip reached for this peer.
                            maybe_mark_headers_done(true);
                        } else {
                            maybe_mark_headers_done(false);

                            int pushed = 0;
                            std::vector<std::vector<uint8_t>> locator;
                            chain_.build_locator(locator);
                            if (g_hdr_flip[(Sock)ps.sock]) {
                                for (auto& h : locator) std::reverse(h.begin(), h.end());
                            }
                            std::vector<uint8_t> stop(32, 0);
                            auto pl2 = build_getheaders_payload(locator, stop);
                            auto m2  = encode_msg("getheaders", pl2);
                            // AGGRESSIVE: During IBD, don't rate-limit headers!
                            // For small chains this should be instant
                            while (can_accept_hdr_batch(ps, now_ms()) &&
                                   pushed < MIQ_HDR_PIPELINE) {
                                ps.sent_getheaders = true;
                                (void)send_or_close(s, m2);
                                ps.inflight_hdr_batches++;
                                g_last_hdr_req_ms[(Sock)ps.sock] = now_ms();
                                ps.last_hdr_batch_done_ms        = now_ms();
                                ++pushed;
                            }
                        }
#endif

                    } else if (cmd == "invb") {
                        // CRITICAL FIX: NEVER rate-limit block announcements
                        // Blocks are critical - we MUST process every announcement immediately
                        // Rate-limiting here caused 3+ minute delays in block propagation
                        // Only rate-limit transaction announcements, not blocks
                        if (m.payload.size() == 32) {
                            if (!inv_tick(1)) {
                                P2P_TRACE_RATE("invb inv_tick failed from " + ps.ip);
                                continue;
                            }
                            auto k = hexkey(m.payload);
                            if (!remember_inv(k)) {
                                // This is extremely common during sync - don't log
                                continue;
                            }
                            if (!chain_.have_block(m.payload)) {
                                // Only trace, not log - this is hot path
                                P2P_TRACE("invb requesting block hash=" + k.substr(0, 16) + "... from " + ps.ip);
                                request_block_hash(ps, m.payload);
                                // CRITICAL FIX: Trigger sync when peer announces block we don't have
                                g_sync_wants_active.store(true);
                            }
                            // Removed: "already have block" log - too spammy during sync
                        }

                    } else if (cmd == "getb") {
                        // ================================================================
                        // STRICT IBD ISOLATION: Never serve blocks during IBD
                        // ================================================================
                        // During IBD, ALL resources must focus on downloading blocks.
                        // Serving blocks wastes bandwidth and CPU that should be used for sync.
                        // We only serve blocks when:
                        // 1. Handshake is complete AND
                        // 2. NOT in IBD mode OR we have reached our target height
                        // ================================================================
                        if (!ps.verack_ok) {
                            P2P_TRACE("DEBUG: Ignoring getb from " + ps.ip + " - handshake not complete");
                            continue;
                        }

                        // STRICT: During IBD, NEVER serve blocks unless we're at tip
                        // The old check "height < g_max_known_peer_tip" failed when both were 0
                        const uint64_t our_height = chain_.height();
                        const uint64_t peer_tip = g_max_known_peer_tip.load();
                        const uint64_t header_tip = chain_.best_header_height();
                        const uint64_t target = std::max(peer_tip, header_tip);

                        if (miq::is_ibd_mode()) {
                            // In IBD mode, only serve if we're at or very close to target
                            // This allows seeds to serve while not wasting resources during sync
                            if (our_height == 0 || (target > 0 && our_height + 10 < target)) {
                                static int64_t last_reject_log_ms = 0;
                                if (now_ms() - last_reject_log_ms > 5000) {
                                    last_reject_log_ms = now_ms();
                                    log_info("P2P: IBD ISOLATION - Ignoring getb from " + ps.ip +
                                             " (our_height=" + std::to_string(our_height) +
                                             " target=" + std::to_string(target) + ")");
                                }
                                continue;
                            }
                        }

                        g_peer_last_request_ms[(Sock)ps.sock] = now_ms();
                        if (m.payload.size() == 32) {
                            std::string hash_hex = hexkey(m.payload);
                            P2P_TRACE("DEBUG: getb request for hash " + hash_hex + " from " + ps.ip);

                            Block b;
                            if (chain_.get_block_by_hash(m.payload, b)) {
                                auto raw = ser_block(b);
                                P2P_TRACE("DEBUG: Found block by hash " + hash_hex + ", size=" + std::to_string(raw.size()) + " bytes");
                                if (raw.size() <= MIQ_FALLBACK_MAX_MSG_SIZE) {
                                    send_block(s, raw);
                                } else {
                                    P2P_TRACE("DEBUG: Block " + hash_hex + " too large (" + std::to_string(raw.size()) + " > " + std::to_string(MIQ_FALLBACK_MAX_MSG_SIZE) + ")");
                                }
                            } else {
                                P2P_TRACE("DEBUG: Block not found by hash " + hash_hex);
                            }
                        } else {
                            P2P_TRACE("DEBUG: getb invalid payload size " + std::to_string(m.payload.size()) + " (expected 32)");
                        }
                    }
                    else if (cmd == "getbi") {
                        // ================================================================
                        // STRICT IBD ISOLATION: Never serve blocks during IBD
                        // ================================================================
                        if (!ps.verack_ok) {
                            P2P_TRACE("DEBUG: Ignoring getbi from " + ps.ip + " - handshake not complete");
                            continue;
                        }

                        // STRICT: During IBD, NEVER serve blocks unless we're at tip
                        const uint64_t our_height = chain_.height();
                        const uint64_t peer_tip = g_max_known_peer_tip.load();
                        const uint64_t header_tip = chain_.best_header_height();
                        const uint64_t target = std::max(peer_tip, header_tip);

                        if (miq::is_ibd_mode()) {
                            if (our_height == 0 || (target > 0 && our_height + 10 < target)) {
                                static int64_t last_reject_log_ms = 0;
                                if (now_ms() - last_reject_log_ms > 5000) {
                                    last_reject_log_ms = now_ms();
                                    log_info("P2P: IBD ISOLATION - Ignoring getbi from " + ps.ip +
                                             " (our_height=" + std::to_string(our_height) +
                                             " target=" + std::to_string(target) + ")");
                                }
                                continue;
                            }
                        }

                        g_peer_last_request_ms[(Sock)ps.sock] = now_ms();
                        if (m.payload.size() == 8) {
                            uint64_t idx64 = 0;
                            for (int j=0;j<8;j++) idx64 |= ((uint64_t)m.payload[j]) << (8*j);
                            P2P_TRACE("DEBUG: getbi request for index " + std::to_string(idx64) + " from " + ps.ip);

                            // DIAGNOSTIC: Log getbi requests that might fail
                            uint64_t our_height = chain_.height();
                            if (idx64 > our_height) {
                                // Rate-limit this log to prevent spam
                                static std::atomic<int64_t> last_future_log_ms{0};
                                static std::atomic<int> future_req_count{0};
                                int64_t tnow = now_ms();
                                future_req_count.fetch_add(1, std::memory_order_relaxed);
                                if (tnow - last_future_log_ms.load(std::memory_order_relaxed) > 5000) {
                                    int cnt = future_req_count.exchange(0, std::memory_order_relaxed);
                                    log_warn("P2P: Peer " + ps.ip + " requested block " + std::to_string(idx64) +
                                             " but our height is only " + std::to_string(our_height) +
                                             " (count=" + std::to_string(cnt) + " requests beyond tip)");
                                    last_future_log_ms.store(tnow, std::memory_order_relaxed);
                                }
                            }

                            Block b;
                            if (chain_.get_block_by_index((size_t)idx64, b)) {
                                auto raw = ser_block(b);
                                P2P_TRACE("DEBUG: Found block at index " + std::to_string(idx64) + ", size=" + std::to_string(raw.size()) + " bytes");
                                if (raw.size() <= MIQ_FALLBACK_MAX_MSG_SIZE) {
                                    send_block(s, raw);
                                } else {
                                    P2P_TRACE("SKIP " + ps.ip + " cmd=getbi height=" + std::to_string(idx64) + " (block too large)");
                                }
                            } else {
                                // CRITICAL FIX: Send "notfound" response so peer doesn't wait for timeout
                                // When we can't serve a block, inform the peer immediately
                                // instead of leaving them hanging
                                if (idx64 <= our_height) {
                                    // This is concerning - we should have this block
                                    static std::atomic<int64_t> last_missing_log_ms{0};
                                    int64_t tnow = now_ms();
                                    if (tnow - last_missing_log_ms.load(std::memory_order_relaxed) > 10000) {
                                        log_warn("P2P: Failed to retrieve block at index " + std::to_string(idx64) +
                                                 " (our height=" + std::to_string(our_height) + ") - possible index corruption");
                                        last_missing_log_ms.store(tnow, std::memory_order_relaxed);
                                    }
                                }
                                P2P_TRACE("SKIP " + ps.ip + " cmd=getbi height=" + std::to_string(idx64) + " (block not available)");
                                // CRITICAL FIX: Actually send notfound response so peer doesn't wait for timeout
                                send_notfound_index(s, idx64);
                            }
                        } else {
                            P2P_TRACE("SKIP " + ps.ip + " cmd=getbi (invalid payload size=" + std::to_string(m.payload.size()) + ")");
                        }

                    } else if (cmd == "nfbi") {
                        // Handle "not found block index" response from peer
                        // This means the peer doesn't have the block we requested
                        if (m.payload.size() == 8) {
                            uint64_t idx64 = 0;
                            for (int j = 0; j < 8; j++) idx64 |= ((uint64_t)m.payload[j]) << (8 * j);

                            P2P_TRACE("DEBUG: Received notfound for index " + std::to_string(idx64) + " from " + ps.ip);

                            // CRITICAL FIX: Don't aggressively reduce peer_tip_height on notfound!
                            // The old code would set peer_tip = idx-1 on every notfound, causing a cascade:
                            // - Peer says "don't have block 1000" -> set peer_tip to 999
                            // - Now we only request up to 999 from this peer
                            // - But peer might actually have 5000 blocks, just not THIS specific one
                            //
                            // This caused sync stalls at 1-3k blocks because peer_tip kept getting reduced
                            // and fill_index_pipeline would cap requests at peer_limit.
                            //
                            // NEW APPROACH: Only reduce if peer_tip is EXACTLY at this index (indicating
                            // we reached their actual tip), otherwise just mark this block as failed for
                            // THIS peer and let another peer handle it.
                            if (idx64 > 0 && ps.peer_tip_height > 0 && idx64 == ps.peer_tip_height) {
                                // Peer tip was exactly at this block - likely their actual tip
                                ps.peer_tip_height = idx64 - 1;
                                ps.peer_tip_reduced_ms = now_ms();
                                P2P_TRACE("P2P: Peer " + ps.ip + " tip reduced to " + std::to_string(ps.peer_tip_height) +
                                          " (was at exact tip)");
                            } else {
                                // Don't reduce - peer just doesn't have this specific block
                                // Track that we asked and failed, so we don't ask again immediately
                                ps.peer_tip_reduced_ms = now_ms();  // Track for gap recovery retry
                                P2P_TRACE("P2P: Peer " + ps.ip + " doesn't have block " + std::to_string(idx64) +
                                          " but peer_tip (" + std::to_string(ps.peer_tip_height) + ") not reduced");
                            }

                            // Clear this index from inflight tracking for this peer
                            auto it_idx = g_inflight_index_ts[(Sock)s].find(idx64);
                            if (it_idx != g_inflight_index_ts[(Sock)s].end()) {
                                g_inflight_index_ts[(Sock)s].erase(it_idx);
                            }
                            auto& dq_idx = g_inflight_index_order[(Sock)s];
                            auto dq_it = std::find(dq_idx.begin(), dq_idx.end(), idx64);
                            if (dq_it != dq_idx.end()) {
                                dq_idx.erase(dq_it);
                            }

                            // Clear from global tracking so another peer can try
                            {
                                InflightLock lk(g_inflight_lock);
                                g_global_requested_indices.erase(idx64);
                            }

                            if (ps.inflight_index > 0) {
                                ps.inflight_index--;
                            }

                            // Track as failed delivery for reputation scoring
                            ps.blocks_failed_delivery++;
                            // CRITICAL: Record block failure in IP history (survives reconnects)
                            record_ip_block_result(ps.ip, false);

                            // CRITICAL FIX: Don't retry if index exceeds header height
                            // This prevents endless retry loops for non-existent blocks
                            const uint64_t best_hdr_h = chain_.best_header_height();
                            if (best_hdr_h > 0 && idx64 > best_hdr_h) {
                                P2P_TRACE("DEBUG: Not retrying index " + std::to_string(idx64) +
                                          " - exceeds header height " + std::to_string(best_hdr_h));
                            } else {
                                // Try another peer for this block immediately
                                // Find a peer that might have this block
                                std::vector<Sock> alt_peers;
                                for (auto& kvp : peers_) {
                                    if (kvp.first == s) continue;  // Skip current peer
                                    if (!kvp.second.verack_ok) continue;
                                    // Only try peers that claim to have this block
                                    if (kvp.second.peer_tip_height >= idx64) {
                                        alt_peers.push_back(kvp.first);
                                    }
                                }

                                if (!alt_peers.empty()) {
                                    // CRITICAL FIX: Pick the peer with the highest tip (most likely to have block)
                                    Sock best_alt = alt_peers[0];
                                    uint64_t best_tip = 0;
                                    for (Sock alt : alt_peers) {
                                        auto pit = peers_.find(alt);
                                        if (pit != peers_.end() && pit->second.peer_tip_height > best_tip) {
                                            best_tip = pit->second.peer_tip_height;
                                            best_alt = alt;
                                        }
                                    }
                                    auto pit = peers_.find(best_alt);
                                    if (pit != peers_.end()) {
                                        request_block_index(pit->second, idx64);
                                        log_info("P2P: Retrying index " + std::to_string(idx64) +
                                                 " with peer " + pit->second.ip + " (tip=" + std::to_string(best_tip) + ")");
                                    }
                                } else {
                                    // No alternative peer available - this block might not be available yet
                                    log_warn("P2P: No alternative peer for index " + std::to_string(idx64) +
                                             " - all peers may be behind");
                                }
                            }

                            // Refill pipeline since we cleared an inflight slot
                            fill_index_pipeline(ps);
                        }

                    } else if (cmd == "block") {
                        g_peer_last_fetch_ms[(Sock)ps.sock] = now_ms();
                        if (!rate_consume_block(ps, m.payload.size())) {
                            if (!ibd_or_fetch_active(ps, now_ms())) {
                                if ((ps.banscore += 5) >= MIQ_P2P_MAX_BANSCORE) bump_ban(ps, ps.ip, "block-rate", now_ms());
                            }
                            continue;
                        }
                        if (m.payload.size() > 0 && m.payload.size() <= MIQ_FALLBACK_MAX_BLOCK_SZ) {
                            Block hb;
                            if (!deser_block(m.payload, hb)) { if (++ps.mis > 10) { dead.push_back(s); } continue; }

                            const std::string bh = hexkey(hb.block_hash());
                            bool drop_unsolicited = false;
                            if (!ps.syncing) {
                                // During headers phase we prefer liveness: take orphan and chase parent.
                                const bool in_headers_phase = !g_logged_headers_done;
                                bool parent_known = chain_.header_exists(hb.header.prev_hash) || chain_.have_block(hb.header.prev_hash);
                                if (!parent_known && !in_headers_phase) {
                                    if (unsolicited_drop(ps, "block", bh)) drop_unsolicited = true;
                                }
                            }
                            if (drop_unsolicited) {
                                // Polite ignore: unsolicited blocks are common during IBD on some impls.
                                continue;
                            }
                            // clear inflight for this block (thread-safe)
                            ps.inflight_blocks.erase(bh);
                            clear_block_inflight(bh, (Sock)s);
                            P2P_TRACE_IF(true, "Received block " + bh.substr(0, 16) + "... from peer");

                            // ================================================================
                            // FORK DETECTION: Check if this block is on our chain
                            // If peer sends a block with prev_hash that doesn't match our
                            // chain at that height, they're on a different fork.
                            // ================================================================
                            // CRITICAL FIX: Do NOT reject blocks from "forked" peers!
                            // The peer might have a LONGER chain with more work.
                            // Let the reorg system evaluate it - handle_incoming_block will
                            // submit competing blocks to accept_block_for_reorg() which
                            // determines if we should switch chains.
                            // The old code rejected fork blocks with "continue", preventing
                            // reorgs to longer chains entirely.
                            // ================================================================
                            {
                                // Get expected height for this block from its prev_hash
                                int64_t parent_height = chain_.get_header_height(hb.header.prev_hash);
                                uint64_t expected_height = (parent_height >= 0) ? (uint64_t)(parent_height + 1) : 0;

                                if (expected_height > 0 && expected_height <= chain_.height()) {
                                    // We already have a block at this height - check if it matches
                                    Block our_block;
                                    if (chain_.get_block_by_index(expected_height, our_block)) {
                                        auto received_hash = hb.block_hash();
                                        auto our_hash = our_block.block_hash();
                                        if (our_hash != received_hash) {
                                            // Different block at same height - potential fork
                                            // Log once but DON'T skip - let reorg system evaluate
                                            if (!ps.fork_detected) {
                                                log_info("P2P: Peer " + ps.ip +
                                                        " has different block at height " + std::to_string(expected_height) +
                                                        " - evaluating for potential reorg");
                                                ps.fork_detected = true;
                                                ps.fork_check_height = expected_height;
                                                ps.fork_check_hash = received_hash;
                                                // DON'T disable sync - peer might have longer chain!
                                                // The reorg manager will determine if their chain has more work
                                            }
                                            // CRITICAL FIX: Fall through to handle_incoming_block!
                                            // Don't skip - let the reorg evaluation happen.
                                        }
                                    }
                                } else if (!ps.fork_verified && parent_height >= 0 && chain_.height() > 0) {
                                    // Block extends tip or is for a height we don't have yet
                                    // If it connects to our chain, peer is verified on same chain
                                    if (chain_.have_block(hb.header.prev_hash)) {
                                        ps.fork_verified = true;
                                        ps.fork_check_height = (uint64_t)parent_height;
                                        log_info("P2P: Verified peer " + ps.ip + " is on same chain (height " +
                                                std::to_string(parent_height) + ")");
                                    }
                                }
                            }

                            // FIX: Update peer_tip_height when we receive blocks via index fetch.
                            // This is critical for correct sync completion detection.
                            // When we request block at index N and receive it, peer has at least N blocks.
                            // Without this, sync can complete early if version message had stale height.

                            // Track block delivery time for reputation scoring
                            int64_t now_ms_val = now_ms();
                            int64_t delivery_time_ms = 0;

                            // accept/process
                            uint64_t old_height = chain_.height();
                            handle_incoming_block(s, m.payload);

                            // Update peer_tip_height based on blocks we've received from this peer
                            // If we received a block that extends our chain, peer has at least that many blocks
                            uint64_t new_height = chain_.height();

                            // Only update peer_tip_height if chain actually grew AND within header bounds
                            uint64_t header_tip = chain_.best_header_height();
                            if (new_height > old_height && new_height > ps.peer_tip_height) {
                                // Chain extended - peer has at least this many blocks
                                // But never set above header tip (can't have more blocks than headers)
                                if (header_tip == 0 || new_height <= header_tip) {
                                    ps.peer_tip_height = new_height;
                                    P2P_TRACE("DEBUG: Updated peer " + ps.ip + " tip_height to " +
                                              std::to_string(new_height) + " (from chain height)");
                                }
                            }

                            // Update reputation: track successful delivery
                            int64_t after_ms = now_ms();
                            delivery_time_ms = after_ms - now_ms_val;
                            ps.blocks_delivered_successfully++;
                            ps.total_block_delivery_time_ms += delivery_time_ms;
                            ps.total_blocks_received++;
                            ps.total_block_bytes_received += m.payload.size();

                            // CRITICAL: Record block success in IP history (survives reconnects)
                            record_ip_block_result(ps.ip, true);

                            // CRITICAL FIX: Recalculate health score on successful delivery
                            // Previously only timeouts affected health (decay), but deliveries didn't restore it
                            // This caused health to drop to 10% and stay there even as blocks arrived
                            {
                                double success_rate = (double)ps.blocks_delivered_successfully /
                                    (ps.blocks_delivered_successfully + ps.blocks_failed_delivery + 1);
                                double speed_factor = std::min(1.0, 30000.0 / std::max(1000.0, (double)ps.avg_block_delivery_ms));
                                ps.health_score = 0.7 * success_rate + 0.3 * speed_factor;
                            }

                            // INFLIGHT FIX: Peer delivered a block, ALWAYS decrement their inflight counter
                            // This is simpler and more reliable than trying to match specific indices
                            // The complex matching logic below can clean up tracking maps, but the counter
                            // must be decremented to allow fill_index_pipeline to request more blocks
                            if (ps.syncing && ps.inflight_index > 0) {
                                ps.inflight_index--;
                            }

                            // BULLETPROOF SYNC FIX: When chain grows, ALWAYS clear those indices from global tracking
                            // This is the most reliable way to keep sync moving - if chain accepted blocks,
                            // those indices are done and should be cleared regardless of identification.
                            if (new_height > old_height) {
                                InflightLock lk(g_inflight_lock);
                                for (uint64_t idx = old_height + 1; idx <= new_height; idx++) {
                                    g_global_requested_indices.erase(idx);
                                }
                            }

                            // CRITICAL FIX: Calculate delivered_idx FIRST and ALWAYS clear from global
                            // This was the root cause of sync stoppage - indices got stuck in global
                            // tracking when per-peer tracking was empty or out of sync.
                            uint64_t delivered_idx = 0;

                            // Method 1: Calculate from parent header height
                            int64_t parent_height = chain_.get_header_height(hb.header.prev_hash);
                            if (parent_height >= 0) {
                                delivered_idx = (uint64_t)(parent_height + 1);
                            }

                            // Method 2: Use chain growth
                            if (delivered_idx == 0 && new_height > old_height) {
                                delivered_idx = new_height;
                            }

                            // CRITICAL FIX: ALWAYS clear delivered_idx from global tracking!
                            // We received the block, so we don't need it in global anymore.
                            // Previously this was conditional on per-peer tracking, causing stalls.
                            if (delivered_idx != 0) {
                                InflightLock lk(g_inflight_lock);
                                g_global_requested_indices.erase(delivered_idx);
                            }

                            // Additional cleanup: Try to clear from per-peer tracking too
                            if (!g_inflight_index_ts[(Sock)s].empty()) {
                                // Verify this index is in THIS peer's inflight tracking
                                bool found_in_peer = false;
                                if (delivered_idx != 0) {
                                    auto it_verify = g_inflight_index_ts[(Sock)s].find(delivered_idx);
                                    if (it_verify != g_inflight_index_ts[(Sock)s].end()) {
                                        found_in_peer = true;
                                    }
                                }

                                // Try to clear the identified index from per-peer tracking
                                bool cleared = false;
                                if (found_in_peer) {
                                    g_inflight_index_ts[(Sock)s].erase(delivered_idx);
                                    auto& dq_idx = g_inflight_index_order[(Sock)s];
                                    auto dq_it = std::find(dq_idx.begin(), dq_idx.end(), delivered_idx);
                                    if (dq_it != dq_idx.end()) {
                                        dq_idx.erase(dq_it);
                                    }
                                    cleared = true;
                                }

                                // If we couldn't clear specific index, clear the oldest one
                                // This keeps per-peer tracking roughly accurate
                                if (!cleared && !g_inflight_index_order[(Sock)s].empty()) {
                                    uint64_t oldest = g_inflight_index_order[(Sock)s].front();
                                    g_inflight_index_order[(Sock)s].pop_front();
                                    g_inflight_index_ts[(Sock)s].erase(oldest);
                                    // Also clear from global (might be different from delivered_idx)
                                    {
                                        InflightLock lk(g_inflight_lock);
                                        g_global_requested_indices.erase(oldest);
                                    }
                                }
                            }

                            // NOTE: inflight_index decrement happens earlier unconditionally
                            // when ps.syncing is true. No need to decrement again here.

                            // CRITICAL FIX: Reset timeout counter AND re-enable the peer!
                            // The peer just successfully delivered a block, proving it works.
                            g_index_timeouts[(Sock)s] = 0;
                            if (!g_peer_index_capable[(Sock)s]) {
                                g_peer_index_capable[(Sock)s] = true;
                                ps.syncing = true;
                                ps.next_index = chain_.height() + 1;
                            }

                            // Refill pipeline immediately
                            fill_index_pipeline(ps);

                            std::vector<std::vector<uint8_t>> want2;
                            chain_.next_block_fetch_targets(want2, /*cap=*/1);
                            g_sync_wants_active.store(!want2.empty());
                            if (!want2.empty()) {
                                // Stick to the same peer when possible to keep strict ordering.
                                request_block_hash(ps, want2[0]);
                            }
                          
                        } else {
                            std::vector<std::vector<uint8_t>> want3;
                            chain_.next_block_fetch_targets(want3, /*cap=*/1);
                            g_sync_wants_active.store(!want3.empty());
                            if (!want3.empty()) request_block_hash(ps, want3[0]);
                        // For malformed/oversized blocks, we can't identify which index it was for
                        // Don't clear anything - let timeout mechanism handle cleanup
                        // Clearing the wrong index would break sync entirely
                          
             }
         // =====================================================================
         // V1.0 TRANSACTION HANDLERS - Thread-safe with tx_store_mu_
         // =====================================================================
         } else if (cmd == "invtx") {
                        if (!check_rate(ps, "inv", 0.25, now_ms())) {
                            if (!ibd_or_fetch_active(ps, now_ms())) {
                                bump_ban(ps, ps.ip, "inv-flood", now_ms());
                            }
                            continue;
                        }
                        if (m.payload.size() == 32) {
                            if (!inv_tick(1)) { continue; }
                            auto key = hexkey(m.payload);

                            // CRITICAL FIX: Check if already in recent_inv_keys WITHOUT inserting
                            // Only insert AFTER we successfully request or already have the tx
                            // This prevents a bug where failed request_tx calls would block
                            // subsequent invtx messages for the same transaction
                            if (ps.recent_inv_keys.count(key) > 0) { continue; }

                            // V1.0 FIX: Thread-safe check of seen_txids_
                            bool already_seen = false;
                            {
                                std::lock_guard<std::mutex> tx_lk(tx_store_mu_);
                                already_seen = seen_txids_.count(key) > 0;
                            }

                            if (already_seen) {
                                // Already have this tx - mark as remembered and skip
                                remember_inv(key);
                            } else {
                                // CRITICAL FIX: Only mark as remembered if request actually succeeds
                                // If request_tx fails (rate limited, max inflight, etc), we want
                                // to be able to try again when the peer re-announces
                                if (request_tx(ps, m.payload)) {
                                    remember_inv(key);
                                }
                                // If request failed, don't add to recent_inv_keys so we can retry
                            }
                        }

                    } else if (cmd == "gettx") {
                        if (m.payload.size() == 32) {
                            auto key = hexkey(m.payload);
                            // V1.0 FIX: Thread-safe access to tx_store_
                            std::vector<uint8_t> tx_data;
                            {
                                std::lock_guard<std::mutex> tx_lk(tx_store_mu_);
                                auto itx = tx_store_.find(key);
                                if (itx != tx_store_.end()) {
                                    tx_data = itx->second; // Copy under lock
                                }
                            }
                            // V1.0 FIX: Fallback to mempool if not in tx_store_
                            // This handles case where tx was evicted from tx_store_ but still in mempool
                            if (tx_data.empty() && mempool_) {
                                Transaction tx;
                                if (mempool_->get_transaction(m.payload, tx)) {
                                    tx_data = ser_tx(tx);
                                    // Cache for future requests
                                    std::lock_guard<std::mutex> tx_lk(tx_store_mu_);
                                    if (tx_store_.find(key) == tx_store_.end()) {
                                        tx_store_[key] = tx_data;
                                        tx_order_.push_back(key);
                                        if (tx_store_.size() > MIQ_TX_STORE_MAX) {
                                            auto victim = tx_order_.front();
                                            tx_order_.pop_front();
                                            tx_store_.erase(victim);
                                            pending_txids_.erase(victim);
                                        }
                                    }
                                }
                            }
                            if (!tx_data.empty()) {
                                if (rate_consume_tx(ps, tx_data.size())) {
                                    send_tx(s, tx_data);
                                }
                            } else {
                                MIQ_LOG_DEBUG(miq::LogCategory::NET, "gettx: tx " + key.substr(0, 16) + "... not found (requested by " + ps.ip + ")");
                            }
                        }

                    } else if (cmd == "tx") {
                        // v10.0 FIX: Always process transactions - rate limiting is now soft debt
                        // Old code banned peers for tx-rate but this caused legitimate txs to be dropped
                        (void)rate_consume_tx(ps, m.payload.size());  // Update rate tracking but don't reject

                        Transaction tx;
                        if (!deser_tx(m.payload, tx)) continue;
                        auto key = hexkey(tx.txid());

                        ps.inflight_tx.erase(key);
                        // CRITICAL FIX: Clear timestamp when tx is received
                        {
                            auto it_tx = g_inflight_tx_ts.find(s);
                            if (it_tx != g_inflight_tx_ts.end()) {
                                it_tx->second.erase(key);
                            }
                        }
                        if (unsolicited_drop(ps, "tx", key)) {
                            // Polite ignore: remote may proactively relay deps.
                            continue;
                        }

                        // V1.0 FIX: Thread-safe check-and-insert for seen_txids_
                        bool is_new_tx = false;
                        {
                            std::lock_guard<std::mutex> tx_lk(tx_store_mu_);
                            is_new_tx = seen_txids_.insert(key).second;
                        }

                        if (is_new_tx) {
                            std::string err;
                            bool accepted = false;
                            // CRITICAL FIX: Don't accept/relay transactions if mempool is not initialized
                            // Without this check, unvalidated transactions would be relayed to peers
                            if (mempool_) {
                                accepted = mempool_->accept(tx, chain_.utxo(), static_cast<uint32_t>(chain_.height()), err);
                            } else {
                                err = "mempool not initialized";
                            }
                            bool in_mempool = mempool_ && mempool_->exists(tx.txid());

                            // CRITICAL FIX: Detect orphan transactions
                            // Orphans return accepted=false with err starting with "orphan:"
                            // These should not penalize the peer, and we should fetch missing parents
                            bool is_orphan = !accepted && err.find("orphan:") == 0;

                            // V1.0 FIX: Thread-safe removal from seen_txids_ on rejection
                            // CRITICAL FIX: Enhanced ban scoring for different rejection types
                            // Skip ban scoring for orphans - they are valid txs waiting for parents
                            if (!accepted && !err.empty() && !is_orphan) {
                                MIQ_LOG_DEBUG(miq::LogCategory::NET, "tx rejected: " + key.substr(0, 16) + "... error: " + err);
                                {
                                    std::lock_guard<std::mutex> tx_lk(tx_store_mu_);
                                    seen_txids_.erase(key);
                                }

                                // CRITICAL FIX: Ban scoring based on rejection type
                                // Different rejection reasons get different scores:
                                // - Cryptographic failures (bad signature) = severe (malicious)
                                // - Policy violations (high-S, fees) = low (not malicious, just non-standard)
                                // - Double-spend = medium (could be race condition or malicious)
                                int ban_increment = 1;
                                if (err.find("bad signature") != std::string::npos) {
                                    // Invalid ECDSA signature - likely malicious or corrupted
                                    ban_increment = 20;
                                    MIQ_LOG_WARN(miq::LogCategory::NET, "bad signature from peer " + ps.ip + " - high ban score");
                                } else if (err.find("bad sig size") != std::string::npos ||
                                           err.find("bad pubkey size") != std::string::npos) {
                                    // Malformed transaction structure
                                    ban_increment = 10;
                                } else if (err.find("double-spend") != std::string::npos) {
                                    ban_increment = 10; // Medium penalty for double-spend attempts
                                } else if (err.find("high-S signature") != std::string::npos ||
                                           err.find("insufficient fee") != std::string::npos ||
                                           err.find("too many ancestors") != std::string::npos ||
                                           err.find("too many descendants") != std::string::npos) {
                                    // Policy violations - valid but non-standard transactions
                                    // These are NOT malicious, just need to be normalized/fixed by sender
                                    ban_increment = 1;
                                }

                                if (!ibd_or_fetch_active(ps, now_ms())) {
                                    ps.mis += ban_increment;
                                    if (ps.mis > 25) {
                                        MIQ_LOG_WARN(miq::LogCategory::NET, "banning peer for tx-invalid (" + err + "), ip=" + ps.ip);
                                        bump_ban(ps, ps.ip, "tx-invalid", now_ms());
                                    }
                                } else {
                                    ps.mis += ban_increment; // track during sync
                                }
                                continue; // Skip further processing for rejected tx
                            }

                            // TELEMETRY: Notify about received transaction for UI display
                            if ((accepted || is_orphan) && txids_callback_) {
                                txids_callback_({key});
                            }

                            // Handle orphan transactions - fetch missing parents
                            if (is_orphan || (accepted && !in_mempool)) {
                                MIQ_LOG_DEBUG(miq::LogCategory::NET, "orphan tx " + key.substr(0, 16) + "... fetching missing parents");
                                for (const auto& in : tx.vin) {
                                    UTXOEntry e;
                                    if (!chain_.utxo().get(in.prev.txid, in.prev.vout, e)) {
                                        send_gettx(s, in.prev.txid);
                                    }
                                }
                                // Fall through to store and relay the orphan tx
                            }

                            // V1.0 FIX: Thread-safe tx_store_ operations
                            {
                                std::lock_guard<std::mutex> tx_lk(tx_store_mu_);
                                if (tx_store_.find(key) == tx_store_.end()) {
                                    tx_store_[key] = m.payload;
                                    tx_order_.push_back(key);
                                    if (tx_store_.size() > MIQ_TX_STORE_MAX) {
                                        auto victim = tx_order_.front();
                                        tx_order_.pop_front();
                                        tx_store_.erase(victim);
                                        pending_txids_.erase(victim);
                                    }
                                }
                                // Remove from pending since we received it from network
                                // (it's already propagating)
                                pending_txids_.erase(key);
                            }

                            // Relay transaction to peers (both accepted and orphans)
                            // Orphans should also be relayed - other nodes may have the parent
                            if (accepted || is_orphan) {
                                uint64_t in_sum = 0, out_sum = 0;
                                for (const auto& o : tx.vout) out_sum += o.value;
                                bool inputs_ok = true;
                                for (const auto& in : tx.vin) {
                                    UTXOEntry e;
                                    if (!chain_.utxo().get(in.prev.txid, in.prev.vout, e)) { inputs_ok = false; break; }
                                    in_sum += e.value;
                                }
                                if (inputs_ok && in_sum >= out_sum) {
                                    uint64_t fee = in_sum - out_sum;
                                    size_t sz = m.payload.size(); if (sz == 0) sz = 1;
                                    uint64_t feerate_kb = (fee * 1000ULL + (sz - 1)) / sz;

                                    const std::vector<uint8_t> txidv = tx.txid();
                                    for (auto& kvp : peers_) {
                                        // CRITICAL FIX: Only relay to peers with completed handshake
                                        if (!kvp.second.verack_ok) continue;
                                        // Don't relay back to sender
                                        if (kvp.first == s) continue;
                                        Sock psock = kvp.first;
                                        uint64_t peer_min = peer_feefilter_kb(psock);
                                        if (peer_min && feerate_kb < peer_min) continue;
                                        trickle_enqueue(psock, txidv);
                                    }
                                } else {
                                    // no complete inputs: still advertise to help fetch deps
                                    const std::vector<uint8_t> txidv = tx.txid();
                                    for (auto& kvp : peers_) {
                                        // CRITICAL FIX: Only relay to peers with completed handshake
                                        if (!kvp.second.verack_ok) continue;
                                        // Don't relay back to sender
                                        if (kvp.first == s) continue;
                                        trickle_enqueue(kvp.first, txidv);
                                    }
                                }
                            }
                        }

                    } else if (cmd == "getaddr") {
                        send_addr_snapshot(ps);

                    } else if (cmd == "addr") {
                        handle_addr_msg(ps, m.payload);

                    } else if (cmd == "feefilter") {
                        if (m.payload.size() == 8) {
                            uint64_t kb = 0;
                            for(int j=0;j<8;j++) kb |= (uint64_t)m.payload[j] << (8*j);
                            set_peer_feefilter(s, kb);
                        } else {
                            if (++ps.mis > 10) { dead.push_back(s); break; }
                        }

                    // ─────────────────────────────────────────────────────────
                    // BIP152 Compact Blocks Protocol
                    // ─────────────────────────────────────────────────────────
                    } else if (cmd == "sendcmpct") {
                        // sendcmpct: <1 byte announce> <8 byte version>
                        if (m.payload.size() >= 9) {
                            bool high_bandwidth = (m.payload[0] != 0);
                            uint64_t version = 0;
                            for (int j = 0; j < 8; j++) {
                                version |= (uint64_t)m.payload[1 + j] << (8 * j);
                            }
                            // We support version 1 and 2
                            if (version == 1 || version == 2) {
                                ps.compact_blocks_enabled = true;
                                ps.compact_high_bandwidth = high_bandwidth;
                                ps.compact_version = version;
                                log_info("P2P: peer " + ps.ip + " supports compact blocks v" +
                                         std::to_string(version) + (high_bandwidth ? " (high-bandwidth)" : ""));
                            }
                        } else {
                            if (++ps.mis > 10) { dead.push_back(s); break; }
                        }

                    } else if (cmd == "cmpctblock") {
                        // BIP152: Full compact block implementation
                        // Reconstruct block from mempool, request missing txs if needed
                        handle_compact_block(ps, m.payload);

                    } else if (cmd == "getblocktxn") {
                        // BIP152: Peer requests specific transactions from a block
                        if (m.payload.size() >= 33) {
                            miq::BlockTransactionsRequest req;
                            if (miq::deserialize_getblocktxn(m.payload, req)) {
                                // Find the block
                                miq::Block block;
                                if (chain_.read_block_any(req.block_hash, block)) {
                                    // Build response with requested transactions
                                    miq::BlockTransactions resp;
                                    resp.block_hash = req.block_hash;
                                    resp.txs.reserve(req.indexes.size());

                                    bool valid = true;
                                    for (uint16_t idx : req.indexes) {
                                        if (idx < block.txs.size()) {
                                            resp.txs.push_back(block.txs[idx]);
                                        } else {
                                            valid = false;
                                            break;
                                        }
                                    }

                                    if (valid && !resp.txs.empty()) {
                                        auto payload = miq::serialize_blocktxn(resp);
                                        auto msg = encode_msg("blocktxn", payload);
                                        (void)send_or_close(ps.sock, msg);
                                        MIQ_LOG_DEBUG(miq::LogCategory::NET, "getblocktxn: sent " +
                                                     std::to_string(resp.txs.size()) + " txs to " + ps.ip);
                                    }
                                }
                            }
                        }

                    } else if (cmd == "blocktxn") {
                        // BIP152: Peer sends missing transactions to complete a compact block
                        if (m.payload.size() >= 33) {
                            miq::BlockTransactions bt;
                            if (miq::deserialize_blocktxn(m.payload, bt)) {
                                // Build hash hex for lookup
                                std::string hash_hex;
                                static const char hex[] = "0123456789abcdef";
                                for (uint8_t byte : bt.block_hash) {
                                    hash_hex.push_back(hex[byte >> 4]);
                                    hash_hex.push_back(hex[byte & 0xf]);
                                }

                                // Find pending compact block
                                miq::PendingCompactBlock pcb;
                                if (pending_compact_blocks_.get(hash_hex, pcb)) {
                                    // Fill in missing transactions
                                    miq::CompactBlockReconstructor reconstructor(*mempool_);
                                    if (reconstructor.fill_missing(pcb.partial_block, bt, pcb.missing_indexes)) {
                                        // Block complete! Process it
                                        pending_compact_blocks_.remove(hash_hex);

                                        MIQ_LOG_INFO(miq::LogCategory::NET, "COMPACT BLOCK " + hash_hex.substr(0, 16) +
                                                     " completed with " + std::to_string(bt.txs.size()) +
                                                     " missing txs from " + ps.ip);

                                        auto raw = ser_block(pcb.partial_block);
                                        handle_incoming_block(ps.sock, raw);
                                    } else {
                                        // Fill failed - request full block
                                        pending_compact_blocks_.remove(hash_hex);
                                        request_block_hash(ps, bt.block_hash);
                                    }
                                }
                            }
                        }

                    } else if (cmd == "sendheaders") {
                        // BIP130: Peer prefers headers announcements over inv
                        ps.prefer_headers = true;
                        log_info("P2P: peer " + ps.ip + " prefers headers announcements");

                    // ─────────────────────────────────────────────────────────
                    // BIP37 Bloom Filter Messages
                    // ─────────────────────────────────────────────────────────
                    } else if (cmd == "filterload") {
                        // Load bloom filter from SPV client
                        // Format: <filter_bytes> <nHashFuncs> <nTweak> <nFlags>
                        if (m.payload.size() >= 9) {
                            // Minimum: 1 byte filter + 4 bytes hashfuncs + 4 bytes tweak + 1 byte flags
                            // For security, we don't serve filtered data to prevent privacy attacks
                            // Just acknowledge and track that peer has a filter
                            log_info("P2P: peer " + ps.ip + " loaded bloom filter (filtered serving disabled)");
                        }

                    } else if (cmd == "filteradd") {
                        // Add data to bloom filter
                        if (m.payload.size() > 0 && m.payload.size() <= 520) {
                            // Max element size is 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)
                            log_info("P2P: peer " + ps.ip + " added to bloom filter");
                        }

                    } else if (cmd == "filterclear") {
                        // Clear bloom filter
                        log_info("P2P: peer " + ps.ip + " cleared bloom filter");

                    } else if (cmd == "merkleblock") {
                        // Merkle block for SPV (we receive this as a full node, usually ignore)
                        log_info("P2P: received merkleblock from " + ps.ip + " (ignored - full node)");

#if MIQ_ENABLE_HEADERS_FIRST
                    } else if (cmd == "getheaders") {
                        g_peer_last_request_ms[(Sock)ps.sock] = now_ms();
                        std::vector<std::vector<uint8_t>> locator;
                        std::vector<uint8_t> stop;
                        if (!parse_getheaders_payload(m.payload, locator, stop)) {
                            if (++ps.mis > 10) { dead.push_back(s); break; }
                            continue;
                        }

                        // Try native orientation first (BE as our chain stores it).
                        std::vector<BlockHeader> hs;
                        chain_.get_headers_from_locator(locator, 2000, hs);
                        if (hs.empty() && !locator.empty()) {
                            std::vector<std::vector<uint8_t>> loc_rev = locator;
                            for (auto& h : loc_rev) std::reverse(h.begin(), h.end());
                            std::vector<BlockHeader> hs2;
                            chain_.get_headers_from_locator(loc_rev, 2000, hs2);
                            if (!hs2.empty()) hs.swap(hs2);
                        }
                      
                        auto out = build_headers_payload(hs);
                        auto msg = encode_msg("headers", out);
                        (void)send_or_close(s, msg);

                    } else if (cmd == "headers") {
                        g_peer_last_fetch_ms[(Sock)ps.sock] = now_ms();
                        std::vector<BlockHeader> hs;
                        if (!parse_headers_payload(m.payload, hs)) {
                            if (++ps.mis > 10) { dead.push_back(s); break; }
                            continue;
                        }
                        const size_t kHdrBatchMax = 2000; // must match build_headers_payload()
                        size_t accepted = 0;
                        bool   used_reverse = false;
                        std::string herr;
                        for (const auto& h : hs) {
                            if (chain_.accept_header(h, herr)) {
                                accepted++;
                            } else {
                                // Client-side endianness tolerance: retry with reversed 32B fields
                                BlockHeader hr = h;
                                std::reverse(hr.prev_hash.begin(),   hr.prev_hash.end());
                                std::reverse(hr.merkle_root.begin(), hr.merkle_root.end());
                                if (chain_.accept_header(hr, herr)) {
                                    accepted++;
                                    used_reverse = true;
                                }
                            }
                        }
                        if (used_reverse) { g_hdr_flip[s] = true; }

                        if (hs.empty() || accepted == 0) {
                            int &zero_count = g_zero_hdr_batches[s];
                            if (++zero_count >= MIQ_HEADERS_EMPTY_LIMIT) {
                                zero_count = 0;
                                g_hdr_flip[s] = !g_hdr_flip[s]; // try the other orientation next
                                // CRITICAL: Mark peer as index-capable and enable fallback
                                g_peer_index_capable[(Sock)s] = true;
                                ps.syncing = true;
                                // BITCOIN CORE FIX: Do NOT reset inflight_index
                                ps.next_index = chain_.height() + 1;
                                fill_index_pipeline(ps);
                                log_warn("P2P: headers made no progress repeatedly from " + ps.ip +
                                         " → enabling index-by-height fallback");
                            }
                        } else {
                            g_zero_hdr_batches[s] = 0;
                        }

                        std::vector<std::vector<uint8_t>> want;
                        chain_.next_block_fetch_targets(want, caps_.max_blocks ? caps_.max_blocks : (size_t)64);
                        bool at_tip = (hs.empty()) || ((hs.size() < kHdrBatchMax) && (chain_.best_header_height() > chain_.height()) && want.empty());

                        if (accepted > 0) {
                            // CRITICAL FIX: Do NOT update g_last_progress_ms for headers!
                            // We only want to track BLOCK progress for stall detection.
                            // Headers arriving shouldn't prevent seed connection when blocks are stuck.
                            g_next_stall_probe_ms = now_ms() + MIQ_P2P_STALL_RETRY_MS;
                            g_last_hdr_ok_ms[(Sock)s] = now_ms();
                        } else if (hs.size() > 0) {
                            log_warn("P2P: Headers REJECTED from " + ps.ip + " n=" + std::to_string(hs.size()) +
                                    " accepted=0 error=" + herr);
                        }

                        {
                            bool zero_progress = (!at_tip) && (accepted == 0) &&
                                (now_ms() - g_last_progress_ms) > g_stall_retry_ms;
                            if (zero_progress) {
                                int &zero_count = g_zero_hdr_batches[s];
                                zero_count++;
                                g_hdr_flip[s] = !g_hdr_flip[s]; // alternate locator orientation next time
                                if (zero_count >= MIQ_HEADERS_EMPTY_LIMIT) {
                                    log_warn("P2P: no headers progress after 3 full batches; falling back to by-index sync");
                                    ps.banscore = std::min(ps.banscore + 1, MIQ_P2P_MAX_BANSCORE);
                                    // CRITICAL: Mark peer as index-capable for fallback to work
                                    g_peer_index_capable[(Sock)s] = true;
                                    ps.syncing = true;
                                    // BITCOIN CORE FIX: Do NOT reset inflight_index
                                    ps.next_index = chain_.height() + 1;
                                    fill_index_pipeline(ps);
                                    zero_count = 0;
                                    g_peer_stalls[(Sock)s]++;
                                    // CRITICAL FIX: Don't disconnect our only peer!
                                    // If we only have one peer (the seed), disconnecting it would stop sync entirely.
                                    // Only disconnect stalling peers if we have alternatives.
                                    size_t active_peers = 0;
                                    for (const auto& kvp : peers_) {
                                        if (kvp.second.verack_ok) active_peers++;
                                    }
                                    bool is_only_peer = (active_peers <= 1);
                                    if (g_peer_stalls[(Sock)s] >= MIQ_P2P_BAD_PEER_MAX_STALLS && !is_loopback(ps.ip) && !is_only_peer) {
                                        // disconnect persistently stalling peer (keeps the network moving)
                                        log_warn("P2P: disconnecting persistently stalling peer " + ps.ip);
                                        dead.push_back(s);
                                    } else if (is_only_peer && g_peer_stalls[(Sock)s] >= MIQ_P2P_BAD_PEER_MAX_STALLS) {
                                        // Only peer - don't disconnect, just log and reset stall count
                                        log_warn("P2P: peer " + ps.ip + " is stalling but is our only peer - keeping connection");
                                        g_peer_stalls[(Sock)s] = 0;  // Reset to give peer another chance
                                    }
                                }
                            } else {
                                // If we are in headers and have not advanced for a long time overall, fallback globally.
                                if (!g_logged_headers_done && (now_ms() - g_last_progress_ms) > (int64_t)MIQ_IBD_FALLBACK_AFTER_MS) {
                                    log_warn("[IBD] headers overall progress timeout; switching to index fallback");
                                    // CRITICAL: Must mark peer as index-capable BEFORE calling fill_index_pipeline
                                    // Otherwise fill_index_pipeline returns early and fallback doesn't work!
                                    g_peer_index_capable[(Sock)ps.sock] = true;
                                    ps.syncing = true;
                                    // BITCOIN CORE FIX: Do NOT reset inflight_index
                                    ps.next_index = chain_.height() + 1;
                                    fill_index_pipeline(ps);
                                }
                                g_zero_hdr_batches[s] = 0;
                            }
                        }

                        maybe_mark_headers_done(at_tip);

                        if (!want.empty()) {
                            std::vector<Sock> cands;
                            // NOTE: g_peers_mu is already locked by the outer scope at line 2685
                            for (auto& kvx : peers_) if (kvx.second.verack_ok) cands.push_back(kvx.first);
                            if (cands.empty()) cands.push_back((Sock)ps.sock);
                            for (const auto& w : want) {
        const std::string key = hexkey(w);
        if (g_global_inflight_blocks.count(key) || orphans_.count(key))
            continue;
        int64_t hdr_height = chain_.get_header_height(w);
        std::vector<Sock> cands_block;
        if (hdr_height >= 0) {
            for (Sock cs : cands) {
                auto pit = peers_.find(cs);
                if (pit == peers_.end()) continue;
                uint64_t peer_height = pit->second.peer_tip_height;
                if (peer_height > 0 && peer_height < (uint64_t)hdr_height)
                    continue;
                cands_block.push_back(cs);
            }
        } else {
            cands_block = cands;
        }
        if (cands_block.empty()) cands_block = cands;
        Sock t = rr_pick_peer_for_key(key, cands_block);
        auto itT = peers_.find(t);
        if (itT != peers_.end()) {
            request_block_hash(itT->second, w);
        }
    }
                        }

                        if (ps.inflight_hdr_batches > 0) ps.inflight_hdr_batches--;
                        ps.last_hdr_batch_done_ms = now_ms();
                        if (ps.inflight_hdr_batches == 0) ps.sent_getheaders = false;

                        if (ps.inflight_hdr_batches == 0 && !at_tip) {
                            std::vector<std::vector<uint8_t>> locator2;
                            chain_.build_locator(locator2);
                            if (g_hdr_flip[s]) {
                                for (auto& h : locator2) std::reverse(h.begin(), h.end());
                            }
                            std::vector<uint8_t> stop2(32, 0);
                            auto pl2 = build_getheaders_payload(locator2, stop2);
                            auto m2  = encode_msg("getheaders", pl2);
                            if (can_accept_hdr_batch(ps, now_ms()) && check_rate(ps, "hdr", 1.0, now_ms())) {
                                 ps.sent_getheaders = true;
                                 (void)send_or_close(s, m2);
                                 ps.inflight_hdr_batches++;
                                 g_last_hdr_req_ms[s] = now_ms();      // SEND time
                            }
                        }

#endif
                    } else {
                        if (++ps.mis > 10) { dead.push_back(s); continue; }
                    }
                }

                if (off > 0 && off <= ps.rx.size()) {
                    ps.rx.erase(ps.rx.begin(), ps.rx.begin() + (ptrdiff_t)off);
                    if (ps.rx.empty()) rx_clear_start(s);
                }
                {
                    auto itg = g_gate.find(s);
                    if (itg != g_gate.end()) itg->second.rx_bytes = ps.rx.size();
                }
                if (!ps.rx.empty()) {
                    auto it0 = g_rx_started_ms.find(s);
                    if (it0 != g_rx_started_ms.end()) {
                        int64_t eff_deadline = msg_deadline_ms_;
                        if (ps.syncing || !ps.inflight_blocks.empty()) {
                            eff_deadline *= 4; // be lenient while catching up
                        }
                        if (now_ms() - it0->second > eff_deadline) {
                            if (!ibd_or_fetch_active(ps, now_ms())) {
                                bump_ban(ps, ps.ip, "slowloris/parse-timeout", now_ms());
                            }
                            dead.push_back(s);
                            continue;
                        }
                    }
                }
            }

            int64_t tnow = now_ms();

            // Loopback leniency + defer pings until after verack
            bool is_lb = false;
            auto itg = g_gate.find(s);
            if (itg != g_gate.end()) is_lb = itg->second.is_loopback;

            int64_t hs_last = itg != g_gate.end() ? itg->second.hs_last_ms : 0;
            if (!ps.verack_ok && hs_last > 0 && (tnow - hs_last) > MIQ_P2P_VERACK_TIMEOUT_MS) {
                if (is_lb) {
                    // extend the timer for localhost tools/wallets
                    itg->second.hs_last_ms = tnow;
                } else {
                    // CRITICAL FIX: Don't disconnect our only peer on verack timeout!
                    size_t active_peers = 0;
                    for (const auto& kvp : peers_) {
                        if (kvp.second.verack_ok) active_peers++;
                    }
                    if (active_peers > 0) {
                        // We have other peers with verack, safe to disconnect this slow one
                        P2P_TRACE("close verack-timeout");
                        dead.push_back(s);
                        continue;
                    } else {
                        // This is potentially our only peer - extend timer
                        P2P_TRACE("verack-timeout but only peer - extending timer");
                        itg->second.hs_last_ms = tnow;
                    }
                }
            }

            if (ps.verack_ok) {
                if (!ps.awaiting_pong && (tnow - ps.last_ping_ms) > MIQ_P2P_PING_EVERY_MS) {
                    auto ping = encode_msg("ping", {});
                    (void)send_or_close(s, ping);
                    ps.last_ping_ms = tnow;
                    ps.awaiting_pong = true;
                } else if (ps.awaiting_pong) {
                    int64_t eff_pong_timeout = MIQ_P2P_PONG_TIMEOUT_MS *
                                               ((ps.syncing || !g_logged_headers_done) ? 6 : 1);
                    if ((tnow - ps.last_ping_ms) > eff_pong_timeout) {
                        if (!is_lb) {
                            // CRITICAL FIX: Don't disconnect our only peer on pong timeout!
                            size_t active_peers = 0;
                            for (const auto& kvp : peers_) {
                                if (kvp.second.verack_ok) active_peers++;
                            }
                            if (active_peers > 1) {
                                // We have other peers, safe to disconnect this slow one
                                P2P_TRACE("close pong-timeout");
                                dead.push_back(s);
                                continue;
                            } else {
                                // Only peer - don't disconnect, just reset ping cycle
                                P2P_TRACE("pong-timeout but only peer - resetting ping cycle");
                                ps.awaiting_pong = false;
                                ps.last_ping_ms = tnow + 5000;
                            }
                        } else {
                            // Lenient path for localhost tools/wallets
                            ps.awaiting_pong = false;
                            ps.last_ping_ms = tnow + 5000;
                        }
                    }
                }
                // Header stall detection (only when not syncing and headers not done)
                if (!ps.syncing && !g_logged_headers_done) {
                    int64_t last_ok = g_last_hdr_ok_ms.count(s) ? g_last_hdr_ok_ms[s] : 0;
                    if (last_ok && (tnow - last_ok) > (int64_t)(g_stall_retry_ms * 4) && !is_lb) {
                        log_warn("P2P: deprioritizing header-stalled peer " + ps.ip);
                        g_peer_stalls[s]++;
                        // CRITICAL FIX: Don't disconnect our only peer!
                        size_t active_peers = 0;
                        for (const auto& kvp : peers_) {
                            if (kvp.second.verack_ok) active_peers++;
                        }
                        if (g_peer_stalls[s] >= MIQ_P2P_BAD_PEER_MAX_STALLS && active_peers > 1) {
                            dead.push_back(s);
                            continue;
                        } else if (active_peers <= 1 && g_peer_stalls[s] >= MIQ_P2P_BAD_PEER_MAX_STALLS) {
                            log_warn("P2P: peer " + ps.ip + " is header-stalled but is our only peer - keeping connection");
                            g_peer_stalls[s] = 0;  // Reset stall count
                        }
                    }
                }
            }
            if (ps.syncing) {
                if ((tnow - g_last_progress_ms) > (int64_t)MIQ_P2P_STALL_RETRY_MS) {
                    // CRITICAL FIX: Use the actual inflight queue instead of formula
                    // The old calculation (next_index - inflight_index) was wrong and could
                    // produce arbitrarily high values when counters got out of sync
                    uint64_t oldest_inflight = 0;
                    auto& order_q = g_inflight_index_order[(Sock)s];
                    if (!order_q.empty()) {
                        oldest_inflight = order_q.front();
                    } else {
                        // No actual inflight requests - use chain height + 1 as next target
                        oldest_inflight = (uint64_t)chain_.height() + 1;
                    }

                    // CRITICAL FIX: Never request beyond best header height
                    // If oldest_inflight exceeds header height, it means our tracking is corrupted
                    const uint64_t best_hdr = chain_.best_header_height();
                    if (best_hdr > 0 && oldest_inflight > best_hdr) {
                        P2P_TRACE("DEBUG: Clearing corrupted inflight - idx " + std::to_string(oldest_inflight) +
                                  " exceeds header height " + std::to_string(best_hdr));
                        // BUG FIX: Clear from global tracking before erasing peer's inflight
                        {
                            InflightLock lk(g_inflight_lock);
                            auto idx_it = g_inflight_index_ts.find((Sock)s);
                            if (idx_it != g_inflight_index_ts.end()) {
                                for (const auto& kv : idx_it->second) {
                                    g_global_requested_indices.erase(kv.first);
                                }
                            }
                        }
                        // Clear this peer's inflight tracking and restart
                        g_inflight_index_ts.erase((Sock)s);
                        g_inflight_index_order.erase((Sock)s);
                        // BITCOIN CORE FIX: Reset inflight_index ONLY when we clear tracking
                        // This is the one legitimate case - we just cleared all inflight state
                        ps.inflight_index = 0;
                        ps.next_index = chain_.height() + 1;
                        fill_index_pipeline(ps);
                        continue;  // Skip to next peer
                    }

                    const int64_t last_probe =
                        (g_last_idx_probe_ms.count(oldest_inflight) ? g_last_idx_probe_ms[oldest_inflight] : 0);

                    if (tnow - last_probe >= (int64_t)MIQ_P2P_STALL_RETRY_MS) {
                        // Track failed delivery (timeout) for reputation scoring
                        ps.blocks_failed_delivery++;
                        // CRITICAL: Record block failure in IP history (survives reconnects)
                        record_ip_block_result(ps.ip, false);

                        // Re-request the same *oldest* index on this peer (retry only; do NOT inflate inflight count).
                        request_block_index(ps, oldest_inflight);
                        g_last_idx_probe_ms[oldest_inflight] = tnow;

                        // Bounded escalation: also poke exactly one other peer for this index.
                        std::vector<Sock> cands;
                        cands.reserve(peers_.size());
                        for (auto& kv2 : peers_) {
                            if (kv2.first == s) continue;
                            if (!kv2.second.verack_ok) continue;
                            cands.push_back(kv2.first);
                        }
                        if (!cands.empty()) {
                            Sock t = rr_pick_peer_for_key(miq_idx_key(oldest_inflight), cands);
                            if (t != MIQ_INVALID_SOCK) {
                                auto itT = peers_.find(t);
                                if (itT != peers_.end()) {
                                    request_block_index(itT->second, oldest_inflight);
                                }
                            }
                        }
                        log_info(std::string("[IBD] index phase stalled; retried idx=")
                                 + std::to_string(oldest_inflight) + " (escalation enabled)");
                    } else {
                        // Too soon to probe again. If this persists, log a calm status once per minute.
                        const int64_t last_wait =
                            (g_last_wait_log_ms.count(oldest_inflight) ? g_last_wait_log_ms[oldest_inflight] : 0);
                        if (tnow - last_wait >= 60000) {
                            log_info(std::string("[IBD] waiting for block ")
                                     + std::to_string(oldest_inflight)
                                     + " (likely not produced yet; throttled re-probes)");
                            g_last_wait_log_ms[oldest_inflight] = tnow;
                        }
                    }
                }
            }
#if MIQ_ENABLE_HEADERS_FIRST
            if (ps.sent_getheaders &&
                ps.inflight_hdr_batches > 0 &&
                (tnow - ps.last_hdr_batch_done_ms) >
                    (int64_t)MIQ_P2P_STALL_RETRY_MS * 2) {
                bool poked = false;
                for (auto& kvx : peers_) {
                    if (kvx.first == s) continue;
                    auto& ps2 = kvx.second;
                    if (!ps2.verack_ok) continue;
                    if (can_accept_hdr_batch(ps2, now_ms()) && check_rate(ps2, "hdr", 1.0, now_ms())) {
                        std::vector<std::vector<uint8_t>> locator2;
                        chain_.build_locator(locator2);
                        if (g_hdr_flip[kvx.first]) {
                            for (auto& h : locator2) std::reverse(h.begin(), h.end());
                        }
                        std::vector<uint8_t> stop2(32, 0);
                        auto pl2 = build_getheaders_payload(locator2, stop2);
                        auto m2  = encode_msg("getheaders", pl2);
                        ps2.sent_getheaders = true;
                        (void)send_or_close(kvx.first, m2);
                        ps2.inflight_hdr_batches++;
                        g_last_hdr_req_ms[kvx.first] = now_ms();
                        poked = true;
                        break;
                    }
                }
                if (!poked) {
                    // fall back to by-index sync for this peer.
                    ps.inflight_hdr_batches = 0;
                    ps.sent_getheaders = false;
                    // CRITICAL: Mark peer as index-capable for fallback to work
                    g_peer_index_capable[(Sock)s] = true;
                    ps.syncing = true;
                    // BITCOIN CORE FIX: Do NOT reset inflight_index
                    ps.next_index = chain_.height() + 1;
                    fill_index_pipeline(ps);
                }
            }
#endif
        }
        // Flush trickle queues once before processing dead peers
        trickle_flush();

        // Periodically persist address sets (legacy + addrman)
        {
            int64_t tnow = now_ms();
            if (tnow - last_addr_save_ms > (int64_t)MIQ_ADDR_SAVE_INTERVAL_MS) {
                save_addrs_to_disk(datadir_, addrv4_);
#if MIQ_ENABLE_ADDRMAN
                // Prune stale addresses (older than 30 days)
                uint32_t now_unix = static_cast<uint32_t>(std::time(nullptr));
                g_addrman.prune_stale(now_unix, 30);

                std::string err;
                if (!g_addrman.save(g_addrman_path, err)) {
                    log_warn("P2P: addrman periodic save failed: " + err);
                }
#endif
                last_addr_save_ms = tnow;
            }
        }

        // ---- Guarded removals (single, consistent path) --------------------
        for (Sock s : dead) {
            gate_on_close(s);
            auto it = peers_.find(s);
            if (it != peers_.end()) {
                std::string ip = it->second.ip;
                size_t inflight = it->second.inflight_blocks.size();
                if (inflight > 0) {
                    std::vector<std::string> keys;
                    keys.reserve(it->second.inflight_blocks.size());
                    for (const auto& k : it->second.inflight_blocks) keys.push_back(k);
                    // erase peer-local timers & global inflight
                    for (const auto& k : keys) {
                        g_global_inflight_blocks.erase(k);
                        g_inflight_block_ts[s].erase(k);
                    }
                    // Prepare candidate peers sorted by health (desc)
                    std::vector<std::pair<Sock,double>> cands;
                    for (const auto& kv2 : peers_) {
                        if (kv2.first == s) continue;
                        if (!kv2.second.verack_ok) continue;
                        cands.emplace_back(kv2.first, kv2.second.health_score);
                    }
                    std::sort(cands.begin(), cands.end(),
                              [](const auto& a, const auto& b){ return a.second > b.second; });
                    std::vector<Sock> cand_socks; cand_socks.reserve(cands.size());
                    for (auto& p : cands) cand_socks.push_back(p.first);
                    // Helper: hex->bytes
                    auto unhex32 = [](const std::string& k)->std::vector<uint8_t>{
                        std::vector<uint8_t> h(32);
                        auto v = [](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return 10+(c-'a'); if(c>='A'&&c<='F')return 10+(c-'A'); return 0; };
                        for (size_t i=0;i<32;i++) h[i] = (uint8_t)((v(k[2*i])<<4)|v(k[2*i+1]));
                        return h;
                    };
                    for (const auto& k : keys) {
                        if (cand_socks.empty()) break;
                        Sock t = rr_pick_peer_for_key(k, cand_socks);
                        auto itT = peers_.find(t);
                        if (itT != peers_.end()) {
                            request_block_hash(itT->second, unhex32(k));
                        }
                    }
                }

                // Always log peer disconnection for visibility
                log_info("Peer: disconnected ← " + ip + " (remaining_peers=" + std::to_string(peers_.size() - 1) + ")");

                // CRITICAL: Save peer's reputation to IP history before disconnect
                record_ip_disconnect(ip, it->second.reputation_score);

                if (it->second.sock != MIQ_INVALID_SOCK) {
                    CLOSESOCK(s);
                }
            }
            peers_.erase(s);
            g_outbounds.erase(s);
            g_zero_hdr_batches.erase(s);
            g_peer_stalls.erase(s);
            g_last_hdr_ok_ms.erase(s);
            g_preverack_counts.erase(s);
            // CRITICAL FIX: Clean up trickle queue for disconnected peer
            {
                std::lock_guard<std::mutex> lk_trickle(g_trickle_mu);
                g_trickle_q.erase(s);
                g_trickle_last_ms.erase(s);
            }
            g_cmd_rl.erase(s); // mirror cleanup in case gate_on_close wasn't hit
            {
                auto it_ts = g_inflight_block_ts.find(s);
                if (it_ts != g_inflight_block_ts.end()) {
                    for (const auto& kv : it_ts->second) {
                        g_global_inflight_blocks.erase(kv.first);
                    }
                    g_inflight_block_ts.erase(it_ts);
                }
                // CRITICAL FIX: Also clear tx inflight tracking on disconnect
                g_inflight_tx_ts.erase(s);

                // CRITICAL FIX: Clear index tracking AND global requested indices
                // BUG: Previously this code only cleared per-peer tracking but NOT
                // g_global_requested_indices, causing indices to get stuck forever.
                // Those stuck indices could never be requested by any other peer,
                // causing permanent sync stalls at specific heights.
                auto it_idx = g_inflight_index_ts.find(s);
                if (it_idx != g_inflight_index_ts.end()) {
                    // Collect indices to re-issue to other peers
                    std::vector<uint64_t> orphaned_indices;
                    orphaned_indices.reserve(it_idx->second.size());
                    for (const auto& kv : it_idx->second) {
                        orphaned_indices.push_back(kv.first);
                    }

                    // Clear from global tracking FIRST (under lock)
                    {
                        InflightLock lk(g_inflight_lock);
                        for (uint64_t idx : orphaned_indices) {
                            g_global_requested_indices.erase(idx);
                        }
                    }

                    // Re-issue requests to other peers (similar to first cleanup loop)
                    if (!orphaned_indices.empty()) {
                        // Build candidate list sorted by health score
                        std::vector<std::pair<Sock, double>> scored_peers;
                        for (const auto& kv2 : peers_) {
                            if (kv2.first == s) continue;
                            if (!kv2.second.verack_ok) continue;
                            scored_peers.emplace_back(kv2.first, kv2.second.health_score);
                        }
                        std::sort(scored_peers.begin(), scored_peers.end(),
                                  [](const auto& a, const auto& b) { return a.second > b.second; });

                        std::vector<Sock> cand_socks;
                        cand_socks.reserve(scored_peers.size());
                        for (auto& p : scored_peers) cand_socks.push_back(p.first);

                        // Re-issue each orphaned index request
                        for (uint64_t idx : orphaned_indices) {
                            if (cand_socks.empty()) break;
                            Sock target = rr_pick_peer_for_key(miq_idx_key(idx), cand_socks);
                            auto itT = peers_.find(target);
                            if (itT != peers_.end()) {
                                uint8_t p8[8];
                                for (int j = 0; j < 8; j++) p8[j] = (uint8_t)((idx >> (8 * j)) & 0xFF);
                                auto msg = encode_msg("getbi", std::vector<uint8_t>(p8, p8 + 8));
                                if (send_or_close(target, msg)) {
                                    g_inflight_index_ts[target][idx] = now_ms();
                                    g_inflight_index_order[target].push_back(idx);
                                    {
                                        InflightLock lk(g_inflight_lock);
                                        g_global_requested_indices.insert(idx);
                                    }
                                    itT->second.inflight_index++;
                                }
                            }
                        }
                    }

                    g_inflight_index_ts.erase(it_idx);
                }
                g_inflight_index_order.erase(s);
            }
        }

        // =====================================================================
        // V1.0 TRANSACTION BROADCAST & REBROADCAST SYSTEM
        // =====================================================================

        // Process queued invtx payloads (from broadcast_inv_tx)
        {
            std::vector<std::vector<uint8_t>> todos;
            {
                std::lock_guard<std::mutex> lk_tx(tx_store_mu_);
                if (!announce_tx_q_.empty()) { todos.swap(announce_tx_q_); }
            }
            if (!todos.empty()) {
                std::vector<Sock> sockets;
                // CRITICAL FIX: Only broadcast to peers that have completed handshake
                // Peers without verack_ok will ignore or buffer messages, wasting bandwidth
                // and potentially causing message ordering issues
                { std::lock_guard<std::recursive_mutex> lk2(g_peers_mu);
                  for (auto& kv : peers_) {
                      if (kv.second.verack_ok) {
                          sockets.push_back(kv.first);
                      }
                  }
                }
                if (!sockets.empty()) {
                    for (const auto& txid : todos) {
                        for (auto sock : sockets) trickle_enqueue(sock, txid);
                    }
                    MIQ_LOG_DEBUG(miq::LogCategory::NET, "broadcast_inv_tx: enqueued " +
                        std::to_string(todos.size()) + " tx(s) to " + std::to_string(sockets.size()) + " peers");
                } else {
                    // CRITICAL: No connected peers with completed handshake!
                    // Re-queue for next iteration
                    {
                        std::lock_guard<std::mutex> lk_tx(tx_store_mu_);
                        for (const auto& txid : todos) {
                            announce_tx_q_.push_back(txid);
                        }
                    }
                    MIQ_LOG_WARN(miq::LogCategory::NET, "broadcast_inv_tx: no peers ready, re-queued " +
                        std::to_string(todos.size()) + " tx(s)");
                }
            }
        }

        // V1.0 ENHANCEMENT: Transaction rebroadcast mechanism
        // Rebroadcast transactions that haven't been confirmed after REBROADCAST_DELAY_MS
        int64_t current_time = now_ms();
        if (current_time - last_rebroadcast_ms_ >= REBROADCAST_INTERVAL_MS) {
            last_rebroadcast_ms_ = current_time;

            std::vector<std::vector<uint8_t>> rebroadcast_txids;
            std::vector<std::string> expired_keys;

            {
                std::lock_guard<std::mutex> tx_lk(tx_store_mu_);
                for (auto& kv : pending_txids_) {
                    auto& info = kv.second;

                    // Check if transaction is still in mempool (not confirmed)
                    bool still_pending = mempool_ && mempool_->exists(info.txid);

                    if (still_pending) {
                        // Check if enough time has passed since last broadcast
                        if (current_time - info.last_broadcast_ms >= REBROADCAST_DELAY_MS) {
                            if (info.broadcast_count < MAX_REBROADCAST_COUNT) {
                                rebroadcast_txids.push_back(info.txid);
                                info.last_broadcast_ms = current_time;
                                info.broadcast_count++;
                            } else {
                                // Max rebroadcasts reached, remove from pending
                                expired_keys.push_back(kv.first);
                            }
                        }
                    } else {
                        // Transaction confirmed or no longer in mempool, remove from pending
                        expired_keys.push_back(kv.first);
                    }
                }

                // Clean up expired entries
                for (const auto& key : expired_keys) {
                    pending_txids_.erase(key);
                }
            }

            // Rebroadcast to all connected peers with completed handshake
            if (!rebroadcast_txids.empty()) {
                std::vector<Sock> sockets;
                { std::lock_guard<std::recursive_mutex> lk2(g_peers_mu);
                  for (auto& kv : peers_) {
                      // CRITICAL FIX: Only rebroadcast to peers with completed handshake
                      if (kv.second.verack_ok) {
                          sockets.push_back(kv.first);
                      }
                  }
                }
                if (!sockets.empty()) {
                    MIQ_LOG_DEBUG(miq::LogCategory::NET, "rebroadcast: sending " + std::to_string(rebroadcast_txids.size()) +
                        " txs to " + std::to_string(sockets.size()) + " peers");
                    for (const auto& txid : rebroadcast_txids) {
                        for (auto sock : sockets) trickle_enqueue(sock, txid);
                    }
                } else {
                    MIQ_LOG_DEBUG(miq::LogCategory::NET, "rebroadcast: no peers with completed handshake, skipping " +
                        std::to_string(rebroadcast_txids.size()) + " txs");
                }
            }
            if (!expired_keys.empty()) {
                MIQ_LOG_DEBUG(miq::LogCategory::NET, "rebroadcast: cleaned up " + std::to_string(expired_keys.size()) +
                    " confirmed/expired txs from pending");
            }
        }

        // V1.0 ENHANCEMENT: Periodic cleanup of seen_txids_ to prevent unbounded growth
        if (current_time - last_seen_cleanup_ms_ >= SEEN_TXIDS_CLEANUP_MS) {
            last_seen_cleanup_ms_ = current_time;

            std::lock_guard<std::mutex> tx_lk(tx_store_mu_);
            if (seen_txids_.size() > MAX_SEEN_TXIDS) {
                size_t old_size = seen_txids_.size();
                // Keep only txids that are in tx_store_ (recent transactions)
                std::unordered_set<std::string> keep_set;
                for (const auto& key : tx_order_) {
                    keep_set.insert(key);
                }
                // Also keep pending transactions
                for (const auto& kv : pending_txids_) {
                    keep_set.insert(kv.first);
                }
                // Replace seen_txids_ with the keep set
                seen_txids_ = std::move(keep_set);
                MIQ_LOG_INFO(miq::LogCategory::NET, "seen_txids cleanup: reduced from " + std::to_string(old_size) +
                    " to " + std::to_string(seen_txids_.size()) + " entries");
            }
        }

        // BULLETPROOF SYNC: Aggressive cleanup of stale global requested indices
        // PROPAGATION FIX: Much faster cleanup for sub-second relay guarantee
        // INVARIANT P5: "There must exist NO valid execution exceeding 1 second"
        {
            static int64_t last_idx_cleanup_ms = 0;
            constexpr int64_t IDX_CLEANUP_INTERVAL_MS = 500;    // Every 500ms (was 5s)
            constexpr int64_t IDX_STALE_THRESHOLD_MS = 2000;    // 2 seconds stale (was 15s)

            if (current_time - last_idx_cleanup_ms >= IDX_CLEANUP_INTERVAL_MS) {
                last_idx_cleanup_ms = current_time;

                InflightLock lk(g_inflight_lock);

                // Build set of all indices that are actually inflight with valid timestamps
                std::unordered_set<uint64_t> active_indices;
                for (const auto& sock_map : g_inflight_index_ts) {
                    for (const auto& idx_ts : sock_map.second) {
                        // Only keep if timestamp is recent
                        if (current_time - idx_ts.second < IDX_STALE_THRESHOLD_MS) {
                            active_indices.insert(idx_ts.first);
                        }
                    }
                }

                // Remove stale indices from global set
                size_t old_size = g_global_requested_indices.size();
                std::vector<uint64_t> to_remove;
                for (uint64_t idx : g_global_requested_indices) {
                    if (active_indices.find(idx) == active_indices.end()) {
                        to_remove.push_back(idx);
                    }
                }
                for (uint64_t idx : to_remove) {
                    g_global_requested_indices.erase(idx);
                }

                if (!to_remove.empty()) {
                    MIQ_LOG_DEBUG(miq::LogCategory::NET, "BULLETPROOF SYNC: cleaned " +
                        std::to_string(to_remove.size()) + " stale indices (was " +
                        std::to_string(old_size) + ", now " +
                        std::to_string(g_global_requested_indices.size()) + ")");
                }
            }
        }

        // BIP152: COMPACT BLOCK TIMEOUT FALLBACK
        // If we've been waiting too long for blocktxn, request full block instead
        // This prevents stalls when peers don't respond with missing transactions
        // BIP152: Compact block timeout handling
        // PROPAGATION FIX: Reduced intervals for sub-second guarantee
        // INVARIANT P5: "There must exist NO valid execution exceeding 1 second"
        {
            static int64_t last_compact_cleanup_ms = 0;
            constexpr int64_t COMPACT_CLEANUP_INTERVAL_MS = 500;    // Every 500ms (was 5s)
            constexpr int64_t COMPACT_TIMEOUT_MS = 2000;            // 2 second timeout (was 10s)

            if (current_time - last_compact_cleanup_ms >= COMPACT_CLEANUP_INTERVAL_MS) {
                last_compact_cleanup_ms = current_time;

                // Get list of timed-out pending compact blocks
                std::vector<std::pair<std::string, std::vector<uint8_t>>> timed_out;
                {
                    // Check all pending compact blocks
                    std::lock_guard<std::mutex> pcb_lk(pending_compact_blocks_.mtx());
                    auto& pending = pending_compact_blocks_.pending_map();
                    for (auto it = pending.begin(); it != pending.end(); ) {
                        if (current_time - it->second.received_ms > COMPACT_TIMEOUT_MS) {
                            // Timed out - need to request full block
                            timed_out.push_back({it->first, it->second.cb.block_hash});
                            it = pending.erase(it);
                        } else {
                            ++it;
                        }
                    }
                }

                // Request full blocks for timed-out compact blocks
                // NOTE: peers_ is accessed by the main loop thread which owns it
                // No lock needed as we're already in the main loop context
                for (const auto& timeout_pair : timed_out) {
                    const std::string& hash_hex = timeout_pair.first;
                    const std::vector<uint8_t>& block_hash = timeout_pair.second;

                    MIQ_LOG_WARN(miq::LogCategory::NET, "COMPACT BLOCK " + hash_hex.substr(0, 16) +
                                 " timed out waiting for blocktxn, requesting full block");

                    // Request full block from any connected peer
                    bool requested = false;
                    for (auto& kv : peers_) {
                        if (kv.second.verack_ok) {
                            request_block_hash(kv.second, block_hash);
                            requested = true;
                            break;  // Only need to request from one peer
                        }
                    }
                    if (!requested) {
                        MIQ_LOG_WARN(miq::LogCategory::NET, "COMPACT BLOCK " + hash_hex.substr(0, 16) +
                                     " timeout: no peers available to request full block");
                    }
                }
            }
        }

        trickle_flush();

        // COLLECT announcement queue sends for deferred execution
        // (actual sends happen AFTER lock is released)
        std::vector<std::pair<Sock, std::vector<uint8_t>>> deferred_announce_sends;
        {
            std::vector<std::vector<uint8_t>> todo;
            {
                std::lock_guard<std::mutex> lk_blk(announce_mu_);
                if (!announce_blocks_q_.empty()) {
                    todo.swap(announce_blocks_q_);
                }
            }
            for (const auto& h : todo) {
                auto m = encode_msg("invb", h);
                // CRITICAL FIX: Collect sockets, defer sends to outside lock
                for (auto& kv : peers_) {
                    if (kv.second.verack_ok) {
                        deferred_announce_sends.push_back({kv.first, m});
                    }
                }
            }
        }

        // ========================================================================
        // BUG 11 FIX: LEVEL-TRIGGERED RELAY COMPLETENESS INVARIANT (P0)
        // This is the CRITICAL structural fix for deterministic sub-second relay.
        //
        // INVARIANT: For every connected peer, if that peer does not have a
        // validated block at our tip height, relay MUST be attempted NOW.
        //
        // CRITICAL: Collect sends under lock, execute OUTSIDE lock to prevent
        // blocking other subsystems. This is how Bitcoin Core achieves reliability.
        // ========================================================================
        // DEFERRED SENDS: Collected under lock, sent outside lock (below)
        std::vector<std::pair<Sock, std::vector<uint8_t>>> deferred_relay_sends;
        {
            const uint64_t our_height = chain_.height();
            if (our_height > 0) {
                const auto our_tip_hash = chain_.tip_hash();
                if (!our_tip_hash.empty()) {
                    static std::unordered_map<std::string, int64_t> s_relay_completeness_last_ms;
                    const int64_t tnow = now_ms();
                    constexpr int64_t RELAY_COMPLETENESS_INTERVAL_MS = 100;

                    for (auto& kv : peers_) {
                        PeerState& ps = kv.second;
                        if (!ps.verack_ok) continue;

                        if (ps.peer_tip_height < our_height) {
                            const std::string peer_key = ps.ip + ":" + std::to_string(our_height);
                            auto it = s_relay_completeness_last_ms.find(peer_key);
                            if (it == s_relay_completeness_last_ms.end() ||
                                (tnow - it->second) >= RELAY_COMPLETENESS_INTERVAL_MS) {

                                s_relay_completeness_last_ms[peer_key] = tnow;

                                // COLLECT for deferred send - don't send under lock!
                                if (ps.send_queue_bytes < PeerState::MAX_SEND_QUEUE_BYTES / 2) {
                                    auto inv_msg = encode_msg("invb", our_tip_hash);
                                    if (!inv_msg.empty()) {
                                        deferred_relay_sends.push_back({kv.first, std::move(inv_msg)});
                                        ps.blocks_sent++;
                                    }
                                }
                            }
                        }
                    }

                    // Periodic cleanup
                    static int64_t s_last_relay_map_cleanup_ms = 0;
                    if (tnow - s_last_relay_map_cleanup_ms > 10000) {
                        s_last_relay_map_cleanup_ms = tnow;
                        for (auto it = s_relay_completeness_last_ms.begin();
                             it != s_relay_completeness_last_ms.end(); ) {
                            if (tnow - it->second > 60000) {
                                it = s_relay_completeness_last_ms.erase(it);
                            } else {
                                ++it;
                            }
                        }
                    }
                }
            }
        }

        // ========================================================================
        // DEBUG-ONLY INVARIANT ASSERTIONS
        // These log violations for debugging but do NOT change behavior.
        // Bitcoin Core catches bugs before users do because of this.
        // ========================================================================
        #ifndef NDEBUG
        {
            static int64_t s_last_invariant_check_ms = 0;
            const int64_t tnow = now_ms();
            // Check every 1 second to avoid log spam
            if (tnow - s_last_invariant_check_ms > 1000) {
                s_last_invariant_check_ms = tnow;
                const uint64_t our_height = chain_.height();

                // ASSERTION 1: "peer connected but missing recent block"
                // If peer is connected for >5s and still behind our tip, log it
                for (const auto& kv : peers_) {
                    const PeerState& ps = kv.second;
                    if (!ps.verack_ok) continue;
                    if (ps.peer_tip_height > 0 && ps.peer_tip_height < our_height) {
                        // Peer is behind - check how long they've been connected
                        if (ps.connected_ms > 0 && (tnow - ps.connected_ms) > 5000) {
                            MIQ_LOG_DEBUG(miq::LogCategory::NET,
                                "INVARIANT: peer " + ps.ip + " connected " +
                                std::to_string((tnow - ps.connected_ms) / 1000) +
                                "s but still behind (peer=" + std::to_string(ps.peer_tip_height) +
                                " us=" + std::to_string(our_height) + ")");
                        }
                    }
                }

                // ASSERTION 2: "relay blocked >1s"
                // Check if any block at our tip has been pending relay for >1s
                // (This would indicate level-triggered relay is failing)
                static uint64_t s_last_logged_height = 0;
                static int64_t s_height_first_seen_ms = 0;
                if (our_height != s_last_logged_height) {
                    s_last_logged_height = our_height;
                    s_height_first_seen_ms = tnow;
                } else if (s_height_first_seen_ms > 0 && (tnow - s_height_first_seen_ms) > 1000) {
                    // Check if any peer still doesn't have this block after 1s
                    size_t behind_count = 0;
                    for (const auto& kv : peers_) {
                        if (kv.second.verack_ok && kv.second.peer_tip_height < our_height) {
                            behind_count++;
                        }
                    }
                    if (behind_count > 0) {
                        MIQ_LOG_DEBUG(miq::LogCategory::NET,
                            "INVARIANT: block at height " + std::to_string(our_height) +
                            " validated " + std::to_string((tnow - s_height_first_seen_ms) / 1000) +
                            "s ago but " + std::to_string(behind_count) + " peers still behind");
                    }
                }
            }
        }
        #endif

        if (now_ms() - last_addr_save_ms > MIQ_ADDR_SAVE_INTERVAL_MS) {
            last_addr_save_ms = now_ms();
            save_addrs_to_disk(datadir_, addrv4_);
#if MIQ_ENABLE_ADDRMAN
            std::string err;
            if (!g_addrman.save(g_addrman_path, err)) {
                log_warn("P2P: addrman autosave failed: " + err);
            }
#endif
        }

        // ====================================================================
        // CRITICAL FIX: Release peer lock BEFORE doing any socket I/O
        // This prevents relay from blocking sync, mining from blocking relay, etc.
        // Bitcoin Core NEVER holds cs_vNodes during socket writes.
        // ====================================================================
        lk.unlock();

        // Execute ALL deferred sends OUTSIDE the peer lock
        // This ensures relay I/O cannot block other subsystems
        for (const auto& send_pair : deferred_announce_sends) {
            (void)send_or_close(send_pair.first, send_pair.second);
        }
        for (const auto& send_pair : deferred_relay_sends) {
            (void)send_or_close(send_pair.first, send_pair.second);
        }
    }

    save_bans();
    save_addrs_to_disk(datadir_, addrv4_);
#if MIQ_ENABLE_ADDRMAN
    {
        std::string err;
        if (!g_addrman.save(g_addrman_path, err)) {
            log_warn("P2P: addrman final save failed: " + err);
        }
    }
#endif
}
std::vector<PeerSnapshot> P2P::snapshot_peers() const {
    std::vector<PeerSnapshot> out;
    // CRITICAL FIX: Acquire lock BEFORE accessing peers_ to prevent race condition
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
    out.reserve(peers_.size());
    for (const auto& kv : peers_) {
        const auto& ps = kv.second;
        PeerSnapshot s;
        s.ip            = ps.ip;
        s.verack_ok     = ps.verack_ok;
        s.awaiting_pong = ps.awaiting_pong;
        s.mis           = ps.mis;
        s.next_index    = ps.next_index;
        s.syncing       = ps.syncing;
        s.last_seen_ms  = static_cast<double>(now_ms() - ps.last_ms);
        s.blk_tokens    = ps.blk_tokens;
        s.tx_tokens     = ps.tx_tokens;
        s.rx_buf        = ps.rx.size();
        s.inflight      = ps.inflight_tx.size();
        s.peer_tip      = ps.peer_tip_height;
        s.fork_detected = ps.fork_detected;
        s.fork_verified = ps.fork_verified;
        out.push_back(std::move(s));
    }
    return out;
}

// =============================================================================
// CONNECTION STATS & MANAGEMENT - Implementation of declared functions
// =============================================================================

P2P::ConnectionStats P2P::get_connection_stats() const {
    ConnectionStats stats{};
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);

    stats.total_connections = peers_.size();

    for (const auto& kv : peers_) {
        const auto& ps = kv.second;
        if (ps.conn_type == ConnectionType::OUTBOUND_FULL_RELAY ||
            ps.conn_type == ConnectionType::OUTBOUND_BLOCK_RELAY) {
            stats.outbound_connections++;
        } else if (ps.conn_type == ConnectionType::FEELER) {
            stats.feeler_connections++;
        } else if (ps.conn_type == ConnectionType::MANUAL) {
            stats.manual_connections++;
        } else {
            stats.inbound_connections++;
        }
        if (ps.syncing) {
            stats.syncing_peers++;
        }
        // Consider peer stalled if no activity for 2 minutes
        int64_t idle_ms = now_ms() - ps.last_ms;
        if (idle_ms > 120000) {
            stats.stalled_peers++;
        }
        stats.total_rx_buffer_bytes += ps.rx.size();
    }

    stats.banned_ips = banned_.size() + timed_bans_.size();
    stats.avg_ping_ms = 0.0; // Could be calculated from ping tracking if implemented

    return stats;
}

bool P2P::can_accept_inbound_connection(const std::string& ip) const {
    // Check if IP is banned
    if (banned_.count(ip)) return false;

    auto it = timed_bans_.find(ip);
    if (it != timed_bans_.end() && it->second > now_ms()) {
        return false;
    }

    // Check connection limits
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
    size_t inbound_count = 0;
    for (const auto& kv : peers_) {
        if (kv.second.conn_type == ConnectionType::INBOUND) {
            inbound_count++;
        }
    }

    return inbound_count < MIQ_MAX_INBOUND_CONNECTIONS;
}

bool P2P::needs_more_outbound_connections() const {
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
    size_t outbound_count = 0;
    for (const auto& kv : peers_) {
        if (kv.second.conn_type == ConnectionType::OUTBOUND_FULL_RELAY ||
            kv.second.conn_type == ConnectionType::OUTBOUND_BLOCK_RELAY ||
            kv.second.conn_type == ConnectionType::MANUAL) {
            outbound_count++;
        }
    }
    return outbound_count < MIQ_MAX_OUTBOUND_CONNECTIONS;
}

bool P2P::add_manual_connection(const std::string& host, uint16_t port) {
    // Queue a manual connection attempt
    MIQ_LOG_INFO(miq::LogCategory::NET, "add_manual_connection: queuing " + host + ":" + std::to_string(port));
    // Manual connections would be added to a queue processed by the main loop
    // For now, return true to indicate the request was accepted
    (void)host; (void)port;
    return true;
}

bool P2P::disconnect_peer(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
    for (auto& kv : peers_) {
        if (kv.second.ip == ip) {
            MIQ_LOG_INFO(miq::LogCategory::NET, "disconnect_peer: disconnecting " + ip);
            CLOSESOCK(kv.first);
            return true;
        }
    }
    return false;
}

bool P2P::disconnect_peer_by_id(size_t peer_id) {
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
    size_t idx = 0;
    for (auto& kv : peers_) {
        if (idx == peer_id) {
            MIQ_LOG_INFO(miq::LogCategory::NET, "disconnect_peer_by_id: disconnecting peer " + std::to_string(peer_id));
            CLOSESOCK(kv.first);
            return true;
        }
        idx++;
    }
    return false;
}

void P2P::ban_ip(const std::string& ip, int64_t duration_ms) {
    if (duration_ms <= 0) {
        // Permanent ban
        banned_.insert(ip);
        MIQ_LOG_WARN(miq::LogCategory::NET, "ban_ip: permanent ban on " + ip);
    } else {
        // Timed ban
        timed_bans_[ip] = now_ms() + duration_ms;
        MIQ_LOG_WARN(miq::LogCategory::NET, "ban_ip: timed ban on " + ip + " for " + std::to_string(duration_ms/1000) + "s");
    }
    // Disconnect if currently connected
    disconnect_peer(ip);
}

void P2P::unban_ip(const std::string& ip) {
    banned_.erase(ip);
    timed_bans_.erase(ip);
    MIQ_LOG_INFO(miq::LogCategory::NET, "unban_ip: unbanned " + ip);
}

bool P2P::is_banned(const std::string& ip) const {
    if (banned_.count(ip)) return true;
    auto it = timed_bans_.find(ip);
    if (it != timed_bans_.end() && it->second > now_ms()) {
        return true;
    }
    return false;
}

std::vector<std::pair<std::string, int64_t>> P2P::get_banned_ips() const {
    std::vector<std::pair<std::string, int64_t>> result;
    int64_t tnow = now_ms();

    // Permanent bans (duration = -1 to indicate permanent)
    for (const auto& ip : banned_) {
        result.emplace_back(ip, -1);
    }

    // Timed bans (remaining duration in ms)
    for (const auto& kv : timed_bans_) {
        if (kv.second > tnow) {
            result.emplace_back(kv.first, kv.second - tnow);
        }
    }

    return result;
}

std::vector<std::string> P2P::select_peers_for_eviction(size_t count) {
    std::vector<std::string> result;
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);

    // Select peers with lowest reputation score for eviction
    std::vector<std::pair<double, std::string>> scored;
    for (const auto& kv : peers_) {
        // Don't evict whitelisted peers
        if (kv.second.whitelisted) continue;
        scored.emplace_back(kv.second.reputation_score, kv.second.ip);
    }

    // Sort by score (lowest first)
    std::sort(scored.begin(), scored.end());

    for (size_t i = 0; i < count && i < scored.size(); ++i) {
        result.push_back(scored[i].second);
    }

    return result;
}

void P2P::protect_eviction_candidates(std::vector<std::string>& candidates) {
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);

    // Remove whitelisted and syncing peers from eviction candidates
    candidates.erase(
        std::remove_if(candidates.begin(), candidates.end(),
            [this](const std::string& ip) {
                for (const auto& kv : peers_) {
                    if (kv.second.ip == ip) {
                        return kv.second.whitelisted || kv.second.syncing;
                    }
                }
                return false;
            }),
        candidates.end()
    );
}

double P2P::get_network_health_score() const {
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);

    if (peers_.empty()) return 0.0;

    double score = 0.0;
    size_t count = 0;

    for (const auto& kv : peers_) {
        if (kv.second.verack_ok) {
            score += kv.second.reputation_score;
            count++;
        }
    }

    if (count == 0) return 0.0;

    // Average reputation * connection ratio
    double avg_reputation = score / count;
    double connection_ratio = std::min(1.0, (double)count / MIQ_MAX_OUTBOUND_CONNECTIONS);

    return avg_reputation * connection_ratio;
}

bool P2P::is_network_healthy() const {
    auto stats = get_connection_stats();
    // Network is healthy if we have at least 3 outbound peers and health score > 0.5
    return stats.outbound_connections >= 3 && get_network_health_score() > 0.5;
}

size_t P2P::get_total_rx_buffer_size() const {
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
    size_t total = 0;
    for (const auto& kv : peers_) {
        total += kv.second.rx.size();
    }
    return total;
}

void P2P::trim_oversized_buffers() {
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);

    for (auto& kv : peers_) {
        auto& rx = kv.second.rx;
        // If buffer is over 1MB and hasn't been processed, trim it
        if (rx.size() > 1024 * 1024) {
            MIQ_LOG_WARN(miq::LogCategory::NET, "trim_oversized_buffers: trimming " +
                std::to_string(rx.size()) + " byte buffer for " + kv.second.ip);
            rx.clear();
            rx.shrink_to_fit();
        }
    }
}

void P2P::rotate_outbound_connections() {
    // Disconnect lowest-quality outbound peer to make room for new connections
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);

    Sock worst_sock = MIQ_INVALID_SOCK;
    double worst_score = 2.0; // Higher than max possible score

    for (const auto& kv : peers_) {
        if ((kv.second.conn_type == ConnectionType::OUTBOUND_FULL_RELAY ||
             kv.second.conn_type == ConnectionType::OUTBOUND_BLOCK_RELAY) &&
            !kv.second.whitelisted &&
            !kv.second.syncing &&
            kv.second.reputation_score < worst_score) {
            worst_score = kv.second.reputation_score;
            worst_sock = kv.first;
        }
    }

    if (worst_sock != MIQ_INVALID_SOCK && worst_score < 0.3) {
        MIQ_LOG_INFO(miq::LogCategory::NET, "rotate_outbound_connections: rotating out low-quality peer");
        CLOSESOCK(worst_sock);
    }
}

void P2P::maintain_connection_diversity() {
    // Ensure we have peers from diverse IP ranges
    // For now, this is a placeholder that logs connection diversity
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);

    std::unordered_set<std::string> prefixes;
    for (const auto& kv : peers_) {
        const std::string& ip = kv.second.ip;
        // Extract /16 prefix for IPv4
        size_t dot1 = ip.find('.');
        if (dot1 != std::string::npos) {
            size_t dot2 = ip.find('.', dot1 + 1);
            if (dot2 != std::string::npos) {
                prefixes.insert(ip.substr(0, dot2));
            }
        }
    }

    MIQ_LOG_DEBUG(miq::LogCategory::NET, "maintain_connection_diversity: " +
        std::to_string(prefixes.size()) + " unique /16 prefixes from " +
        std::to_string(peers_.size()) + " peers");
}

// =============================================================================
// BIP130: sendheaders - Announce new blocks via headers instead of inv
// =============================================================================
void P2P::send_sendheaders(PeerState& ps) {
    if (ps.sent_sendheaders) return;  // Already sent

    // Send "sendheaders" message to tell peer we prefer headers announcements
    auto msg = encode_msg("sendheaders", std::vector<uint8_t>{});
    if (ps.sock != MIQ_INVALID_SOCK) {
        ssize_t w = send(ps.sock, reinterpret_cast<const char*>(msg.data()), static_cast<int>(msg.size()), 0);
        if (w > 0) {
            ps.sent_sendheaders = true;
            MIQ_LOG_DEBUG(miq::LogCategory::NET, "send_sendheaders: sent to " + ps.ip);
        }
    }
}

void P2P::broadcast_header(const std::vector<uint8_t>& header_data) {
    if (header_data.size() != 80) return;  // Invalid header size

    auto msg = encode_msg("headers", header_data);
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);

    for (auto& kv : peers_) {
        auto& ps = kv.second;
        // Only send to peers who prefer headers (BIP130)
        if (ps.verack_ok && ps.prefer_headers) {
            ssize_t w = send(ps.sock, reinterpret_cast<const char*>(msg.data()), static_cast<int>(msg.size()), 0);
            (void)w;  // Best effort
        }
    }
}

// =============================================================================
// BIP152: Compact Blocks - Reduce bandwidth for block propagation
// =============================================================================
void P2P::send_sendcmpct(PeerState& ps, bool high_bandwidth, uint64_t version) {
    // BIP152 sendcmpct message: announce_flag (1 byte) + version (8 bytes)
    std::vector<uint8_t> payload;
    payload.reserve(9);
    payload.push_back(high_bandwidth ? 1 : 0);  // announce flag
    // version as little-endian uint64_t
    for (int i = 0; i < 8; ++i) {
        payload.push_back(static_cast<uint8_t>((version >> (i * 8)) & 0xFF));
    }

    auto msg = encode_msg("sendcmpct", payload);
    if (ps.sock != MIQ_INVALID_SOCK) {
        ssize_t w = send(ps.sock, reinterpret_cast<const char*>(msg.data()), static_cast<int>(msg.size()), 0);
        if (w > 0) {
            ps.compact_blocks_enabled = true;
            ps.compact_high_bandwidth = high_bandwidth;
            ps.compact_version = version;
            MIQ_LOG_DEBUG(miq::LogCategory::NET, "send_sendcmpct: sent to " + ps.ip +
                " (high_bw=" + std::to_string(high_bandwidth) + ", v=" + std::to_string(version) + ")");
        }
    }
}

void P2P::send_cmpctblock(PeerState& ps, const std::vector<uint8_t>& block_hash) {
    // BIP152 FULL IMPLEMENTATION: Send compact block with short txids
    // This dramatically reduces bandwidth: ~1-2KB instead of ~100KB+
    // Receiver reconstructs from mempool, only requesting missing transactions

    if (block_hash.size() != 32) return;

    Block blk;
    // Find block by hash - iterate through recent blocks
    auto tip = chain_.tip();
    bool found = false;
    for (size_t i = 0; i <= std::min<size_t>(10, tip.height); ++i) {
        size_t idx = tip.height - i;
        if (chain_.get_block_by_index(idx, blk)) {
            if (blk.block_hash() == block_hash) {
                found = true;
                break;
            }
        }
    }

    if (!found) {
        MIQ_LOG_WARN(miq::LogCategory::NET, "send_cmpctblock: block not found");
        return;
    }

    // Build compact block using BIP152 format
    if (mempool_) {
        miq::CompactBlock cb = miq::CompactBlockBuilder::create(blk, *mempool_);
        auto payload = miq::serialize_compact_block(cb);
        auto msg = encode_msg("cmpctblock", payload);

        if (ps.sock != MIQ_INVALID_SOCK) {
            ssize_t w = send(ps.sock, reinterpret_cast<const char*>(msg.data()), static_cast<int>(msg.size()), 0);
            if (w > 0) {
                ps.last_compact_block_hash = block_hash;
                MIQ_LOG_DEBUG(miq::LogCategory::NET, "send_cmpctblock: sent compact block (" +
                             std::to_string(payload.size()) + " bytes, " +
                             std::to_string(cb.short_ids.size()) + " short_ids) to " + ps.ip);
            }
        }
    } else {
        // Fallback: no mempool available, send full block
        auto raw = ser_block(blk);
        auto msg = encode_msg("block", raw);
        if (ps.sock != MIQ_INVALID_SOCK) {
            ssize_t w = send(ps.sock, reinterpret_cast<const char*>(msg.data()), static_cast<int>(msg.size()), 0);
            if (w > 0) {
                ps.last_compact_block_hash = block_hash;
                MIQ_LOG_DEBUG(miq::LogCategory::NET, "send_cmpctblock: sent full block (no mempool) to " + ps.ip);
            }
        }
    }
}

void P2P::send_getblocktxn(PeerState& ps, const std::vector<uint8_t>& block_hash,
                           const std::vector<uint16_t>& indexes) {
    // BIP152 getblocktxn: request missing transactions from a compact block
    // Format: block_hash (32 bytes) + indexes_length (varint) + indexes (differentially encoded)

    if (block_hash.size() != 32) return;
    if (indexes.empty()) return;

    std::vector<uint8_t> payload;
    payload.reserve(32 + 3 + indexes.size() * 3);

    // Block hash
    payload.insert(payload.end(), block_hash.begin(), block_hash.end());

    // Indexes count (proper varint encoding for any count)
    uint64_t count = indexes.size();
    if (count < 0xFD) {
        payload.push_back(static_cast<uint8_t>(count));
    } else if (count <= 0xFFFF) {
        payload.push_back(0xFD);
        payload.push_back(static_cast<uint8_t>(count & 0xFF));
        payload.push_back(static_cast<uint8_t>((count >> 8) & 0xFF));
    } else {
        payload.push_back(0xFE);
        payload.push_back(static_cast<uint8_t>(count & 0xFF));
        payload.push_back(static_cast<uint8_t>((count >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>((count >> 16) & 0xFF));
        payload.push_back(static_cast<uint8_t>((count >> 24) & 0xFF));
    }

    // Differential encoding of indexes
    uint16_t prev = 0;
    for (uint16_t idx : indexes) {
        uint16_t diff = idx - prev;
        // Proper varint encoding
        if (diff < 0xFD) {
            payload.push_back(static_cast<uint8_t>(diff));
        } else {
            payload.push_back(0xFD);
            payload.push_back(static_cast<uint8_t>(diff & 0xFF));
            payload.push_back(static_cast<uint8_t>((diff >> 8) & 0xFF));
        }
        prev = idx + 1;  // For next differential
    }

    auto msg = encode_msg("getblocktxn", payload);
    if (ps.sock != MIQ_INVALID_SOCK) {
        ssize_t w = send(ps.sock, reinterpret_cast<const char*>(msg.data()), static_cast<int>(msg.size()), 0);
        if (w > 0) {
            MIQ_LOG_DEBUG(miq::LogCategory::NET, "send_getblocktxn: requested " +
                std::to_string(indexes.size()) + " txs from " + ps.ip);
        }
    }
}

void P2P::handle_compact_block(PeerState& ps, const std::vector<uint8_t>& payload) {
    // BIP152 FULL IMPLEMENTATION: Reconstruct block from mempool
    // This dramatically reduces bandwidth - only ~1KB instead of ~500KB

    if (payload.size() < 96) {  // header(88) + nonce(8)
        MIQ_LOG_WARN(miq::LogCategory::NET, "handle_compact_block: payload too small from " + ps.ip);
        return;
    }

    // Deserialize compact block
    miq::CompactBlock cb;
    if (!miq::deserialize_compact_block(payload, cb)) {
        MIQ_LOG_WARN(miq::LogCategory::NET, "handle_compact_block: deserialize failed from " + ps.ip);
        request_block_hash(ps, miq::dsha256(std::vector<uint8_t>(payload.begin(), payload.begin() + 88)));
        return;
    }

    // Check if we already have this block
    if (chain_.have_block(cb.block_hash)) {
        MIQ_LOG_DEBUG(miq::LogCategory::NET, "handle_compact_block: already have block from " + ps.ip);
        return;
    }

    // Try to reconstruct from mempool
    if (!mempool_) {
        MIQ_LOG_WARN(miq::LogCategory::NET, "handle_compact_block: no mempool, requesting full block");
        request_block_hash(ps, cb.block_hash);
        return;
    }

    miq::CompactBlockReconstructor reconstructor(*mempool_);
    auto result = reconstructor.reconstruct(cb);

    std::string hash_hex;
    static const char hex[] = "0123456789abcdef";
    for (uint8_t byte : cb.block_hash) {
        hash_hex.push_back(hex[byte >> 4]);
        hash_hex.push_back(hex[byte & 0xf]);
    }

    if (result.success) {
        // Full reconstruction succeeded! Process the block immediately
        MIQ_LOG_INFO(miq::LogCategory::NET, "COMPACT BLOCK " + hash_hex.substr(0, 16) +
                     " reconstructed from mempool (" + std::to_string(cb.short_ids.size()) +
                     " txs matched) from " + ps.ip);

        // Serialize and process as normal block
        auto raw = ser_block(result.block);
        handle_incoming_block(ps.sock, raw);

    } else if (!result.missing_indexes.empty()) {
        // Partial reconstruction - need to request missing transactions
        MIQ_LOG_DEBUG(miq::LogCategory::NET, "COMPACT BLOCK " + hash_hex.substr(0, 16) +
                      " needs " + std::to_string(result.missing_indexes.size()) +
                      " missing txs from " + ps.ip);

        // Store pending compact block
        miq::PendingCompactBlock pcb;
        pcb.cb = cb;
        pcb.partial_block = result.block;
        pcb.missing_indexes = result.missing_indexes;
        pcb.received_ms = now_ms();
        pcb.from_peer = ps.ip;

        pending_compact_blocks_.add(hash_hex, std::move(pcb));

        // Request missing transactions
        send_getblocktxn(ps, cb.block_hash, result.missing_indexes);

    } else {
        // Reconstruction failed for other reason - request full block
        MIQ_LOG_WARN(miq::LogCategory::NET, "handle_compact_block: reconstruct failed (" +
                     result.error + "), requesting full block from " + ps.ip);
        request_block_hash(ps, cb.block_hash);
    }
}

// =============================================================================
// BIP37: Bloom Filters for SPV clients
// =============================================================================
void P2P::handle_filterload(PeerState& ps, const std::vector<uint8_t>& payload) {
    // BIP37 filterload: SPV client sends bloom filter
    // Format: filter (var bytes) + nHashFuncs (4 bytes) + nTweak (4 bytes) + nFlags (1 byte)

    if (payload.size() < 9) {  // Minimum size
        MIQ_LOG_WARN(miq::LogCategory::NET, "handle_filterload: payload too small from " + ps.ip);
        return;
    }

    // For now, just acknowledge receipt - full implementation would:
    // 1. Store the bloom filter for this peer
    // 2. Use it to filter transactions before relaying
    // 3. Use it to filter merkle blocks

    MIQ_LOG_DEBUG(miq::LogCategory::NET, "handle_filterload: received " +
        std::to_string(payload.size()) + " byte filter from " + ps.ip);

    // Mark peer as SPV/filtered
    ps.relay_txs = true;  // Will relay matching transactions
}

void P2P::handle_filteradd(PeerState& ps, const std::vector<uint8_t>& payload) {
    // BIP37 filteradd: Add data element to existing bloom filter

    if (payload.empty() || payload.size() > 520) {  // Max element size
        MIQ_LOG_WARN(miq::LogCategory::NET, "handle_filteradd: invalid size from " + ps.ip);
        return;
    }

    MIQ_LOG_DEBUG(miq::LogCategory::NET, "handle_filteradd: adding " +
        std::to_string(payload.size()) + " bytes to filter for " + ps.ip);

    // Full implementation would add this element to peer's bloom filter
}

void P2P::handle_filterclear(PeerState& ps) {
    // BIP37 filterclear: Remove bloom filter, return to unfiltered mode

    MIQ_LOG_DEBUG(miq::LogCategory::NET, "handle_filterclear: clearing filter for " + ps.ip);

    // Reset to unfiltered relay
    ps.relay_txs = true;
}

// =============================================================================
// LOCAL BLOCK NOTIFICATION
// For locally mined blocks - queues to announcement system
// ARCHITECTURAL FIX: Mining NEVER directly triggers relay I/O
// Relay loop independently observes chain state and reacts
// =============================================================================
void P2P::notify_local_block(const Block& b, uint64_t height, uint64_t subsidy, const std::string& miner_addr) {
    auto bh = b.block_hash();
    std::string hash_hex;
    hash_hex.reserve(64);
    static const char hex[] = "0123456789abcdef";
    for (uint8_t byte : bh) {
        hash_hex.push_back(hex[byte >> 4]);
        hash_hex.push_back(hex[byte & 0xf]);
    }

    // CRITICAL ARCHITECTURAL FIX: Queue to announcement system, don't do I/O directly
    // This ensures:
    // 1. Mining thread returns immediately (no blocking on network)
    // 2. Relay I/O happens in relay thread (proper separation)
    // 3. Level-triggered relay loop will pick this up within ~10ms
    // Bitcoin Core rule: "Mining NEVER directly triggers relay"
    {
        std::lock_guard<std::mutex> lk(announce_mu_);
        if (announce_blocks_q_.size() < 1024) {
            announce_blocks_q_.push_back(bh);
        }
    }

    MIQ_LOG_INFO(miq::LogCategory::NET, "*** LOCAL BLOCK MINED *** " + hash_hex.substr(0, 16) +
                 " at height " + std::to_string(height) +
                 " queued for relay (level-triggered)");

    // PRIORITY 2: TUI callback (non-blocking)
    if (block_callback_) {
        P2PBlockInfo info;
        info.height = height;
        info.hash_hex = hash_hex;
        info.tx_count = static_cast<uint32_t>(b.txs.size());
        info.miner = miner_addr;

        // Calculate fees from coinbase
        if (!b.txs.empty()) {
            uint64_t coinbase_total = 0;
            for (const auto& out : b.txs[0].vout) coinbase_total += out.value;
            if (coinbase_total >= subsidy) {
                info.fees = coinbase_total - subsidy;
                info.fees_known = true;
            }
        }
        block_callback_(info);
    }

    // PRIORITY 3: Notify about transactions in this block
    if (txids_callback_ && b.txs.size() > 1) {
        std::vector<std::string> txids;
        txids.reserve(b.txs.size() - 1);
        for (size_t i = 1; i < b.txs.size(); ++i) {
            auto tid = b.txs[i].txid();
            std::string key;
            key.reserve(64);
            for (uint8_t byte : tid) {
                key.push_back(hex[byte >> 4]);
                key.push_back(hex[byte & 0xf]);
            }
            txids.push_back(key);
        }
        txids_callback_(txids);
    }

    // Queue for late-connecting peers (async)
    announce_block_async(bh);
}

}
