// src/p2p.cpp  (strict-filter profile, Windows SOCKET-safe)
#include "p2p.h"
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
#include <cerrno>
#include <cstdint>
#include <climits>
#include <atomic>

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

#ifndef MIQ_SEED_MODE_ENV
#define MIQ_SEED_MODE_ENV "MIQ_IS_SEED"
#endif
#ifndef MIQ_SEED_MODE_OUTBOUND_TARGET
#define MIQ_SEED_MODE_OUTBOUND_TARGET 1
#endif
#ifndef MIQ_IBD_FALLBACK_AFTER_MS
#define MIQ_IBD_FALLBACK_AFTER_MS (5 * 60 * 1000)
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
#define MIQ_INDEX_PIPELINE 64
#endif

#ifndef MIQ_HDR_PIPELINE
#define MIQ_HDR_PIPELINE 1
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
#define MIQ_P2P_BAD_PEER_MAX_STALLS 3           /* disconnect peers that stall repeatedly */
#endif
#ifndef MIQ_HEADERS_EMPTY_LIMIT
#define MIQ_HEADERS_EMPTY_LIMIT 8
#endif

#ifndef MIQ_RATE_BLOCK_BPS
#define MIQ_RATE_BLOCK_BPS (1024u * 1024u)
#endif
#ifndef MIQ_RATE_TX_BPS
#define MIQ_RATE_TX_BPS    (256u * 1024u)
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
#ifndef MIQ_DIAL_INTERVAL_MS
#define MIQ_DIAL_INTERVAL_MS 5000
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
  #ifndef MIQ_P2P_TRICKLE_MS
  #define MIQ_P2P_TRICKLE_MS 250
  #endif
  #ifndef MIQ_P2P_TRICKLE_BATCH
  #define MIQ_P2P_TRICKLE_BATCH 48
  #endif
  #ifndef MIQ_P2P_STALL_RETRY_MS
  #define MIQ_P2P_STALL_RETRY_MS 15000
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
  #ifndef MIQ_P2P_TRICKLE_MS
  #define MIQ_P2P_TRICKLE_MS 200
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

// Stall/progress trackers
static int64_t g_last_progress_ms = 0;
static size_t  g_last_progress_height = 0;
static int64_t g_next_stall_probe_ms = 0;

// Simple trickle queues per-peer (sock -> txid queue and last flush ms)
static std::unordered_map<Sock, std::vector<std::vector<uint8_t>>> g_trickle_q;
static std::unordered_map<Sock, int64_t> g_trickle_last_ms;

static std::unordered_map<Sock,int64_t> g_last_hdr_req_ms;

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
#ifndef _WIN32
    {
        int flag = 1;
        (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    }
#endif
    size_t sent = 0;
    const int kMaxSpinMs = 2000; // upper bound total wait per call
    int waited_ms = 0;



    while (sent < len) {
#ifdef _WIN32
        int n = send(s, reinterpret_cast<const char*>(data + sent), (int)std::min<size_t>(INT32_MAX, len - sent), 0);
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEWOULDBLOCK) {
                WSAPOLLFD pfd{}; pfd.fd = s; pfd.events = POLLWRNORM; pfd.revents = 0;
                int rc = WSAPoll(&pfd, 1, 10);
                if (rc <= 0 && (waited_ms += 10) >= kMaxSpinMs) return false;
                continue;
            }
            char buf[96]; sprintf_s(buf, "send() failed WSAE=%d", e);
            miq::log_warn(std::string("P2P: ") + buf);
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

static inline int miq_recv(Sock s, uint8_t* buf, size_t bufsz) {
#ifdef _WIN32
    int n = recv(s, reinterpret_cast<char*>(buf), (int)bufsz, 0);
    if (n == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK) return 0;
        char tmp[96]; sprintf_s(tmp, "recv() failed WSAE=%d", e);
        miq::log_warn(std::string("P2P: ") + tmp);
        return -1;
    }
    return n;
#else
    for (;;) {
        ssize_t n = ::recv(s, buf, bufsz, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        return (int)n;
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
        set_peer_feefilter((Sock)ps.sock, mrf);
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
    const int64_t f = (g_peer_last_fetch_ms.count(s)    ? g_peer_last_fetch_ms.at(s)    : 0);
    const int64_t r = (g_peer_last_request_ms.count(s)  ? g_peer_last_request_ms.at(s)  : 0);
    const int64_t kWindow = 5 * 60 * 1000; // 5 minutes grace
    // Also grant grace while global headers IBD hasn't finished.
    return inflight || (f && (nowms - f) < kWindow) || (r && (nowms - r) < kWindow)
           || !g_logged_headers_done || g_sync_wants_active.load();
}

static bool g_seed_mode = false;
static bool g_sequential_sync = (MIQ_SYNC_SEQUENTIAL_DEFAULT != 0);
static inline int miq_outbound_target(){
    return g_seed_mode ? MIQ_SEED_MODE_OUTBOUND_TARGET : MIQ_OUTBOUND_TARGET;
}

static inline bool hostname_is_seed(){
    const char* env_host = std::getenv("MIQ_PUBLIC_HOSTNAME");
    if (env_host && *env_host) return std::string(env_host) == MIQ_SEED_DOMAIN;
    return false;
}

// NOTE: g_global_inflight_blocks is now defined in the optimized inflight tracking section below

static std::unordered_map<Sock, bool> g_peer_index_capable; // default true; false => headers-only

static int g_headers_tip_confirmed = 0;   // consecutive confirmations of "at tip"

static inline void maybe_mark_headers_done(bool at_tip) {
    if (g_logged_headers_done) return;
    if (!g_logged_headers_started) {
        g_headers_tip_confirmed = 0;
        return;
    }

    if (g_chain_ptr && g_chain_ptr->height() < 100) {
        g_headers_tip_confirmed = 0;
        return;
    }
    
    if (at_tip) {
        if (++g_headers_tip_confirmed >= 3) {
            g_logged_headers_done = true;
            miq::log_info(std::string("[IBD] headers phase done"));
        }
    } else {
        g_headers_tip_confirmed = 0;
    }
}

static bool g_sync_green_logged = false;

static std::unordered_map<Sock,int> g_index_timeouts;
static inline void mark_index_timeout(Sock s){
    int &c = g_index_timeouts[s]; if (++c >= 3) g_peer_index_capable[s] = false;
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
  static inline void schedule_close(Sock s){ if (s!=MIQ_INVALID_SOCK) g_force_close.insert(s); }
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

// Track inflight block request timestamps without touching PeerState layout
static std::unordered_map<Sock, std::unordered_map<std::string,int64_t>> g_inflight_block_ts;

// Global set of all requested block hashes (across all peers)
static std::unordered_set<std::string> g_global_inflight_blocks;

// Track inflight index-based requests
static std::unordered_map<Sock, std::unordered_map<uint64_t,int64_t>> g_inflight_index_ts;
static std::unordered_map<Sock, std::deque<uint64_t>> g_inflight_index_order;
static int64_t g_stall_retry_ms = MIQ_P2P_STALL_RETRY_MS;

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

} // namespace

static inline bool peer_is_index_capable(Sock s) {
    auto it = g_peer_index_capable.find(s);
    // Default to true unless explicitly demoted.
    if (it == g_peer_index_capable.end()) return true;
    return it->second;
}

static inline int64_t adaptive_index_timeout_ms(const miq::PeerState& ps){
    // Base on observed block delivery; halve it for indices (headers+lookup are lighter).
    int64_t base = std::max<int64_t>(5000, ps.avg_block_delivery_ms / 2);
    // Healthier peers get tighter timeouts, weaker peers looser.
    double health = std::min(1.0, std::max(0.0, ps.health_score)); // clamp
    double health_mul = 2.0 - health; // 1.0..2.0
    // During IBD or explicit index sync, allow more slack.
    double ibd_mul = (!g_logged_headers_done || ps.syncing) ? 2.0 : 1.2;
    int64_t t = (int64_t)(base * health_mul * ibd_mul);
    int64_t max_t = (!g_logged_headers_done || ps.syncing) ? 120000 : 30000; // 120s IBD, 30s steady
    return std::max<int64_t>(5000, std::min<int64_t>(t, max_t));
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
    // Adjust based on reputation score
    // Excellent peers (0.9+): 32 blocks
    // Good peers (0.7-0.9): 24 blocks
    // Average peers (0.5-0.7): 16 blocks
    // Poor peers (<0.5): 8 blocks

    double rep = ps.reputation_score;
    uint32_t batch_size;

    if (rep >= 0.9) {
        batch_size = 32;
    } else if (rep >= 0.7) {
        batch_size = 24;
    } else if (rep >= 0.5) {
        batch_size = 16;
    } else {
        batch_size = 8;
    }

   if (!g_logged_headers_done && rep >= 0.8) {
        batch_size = std::min(256u, batch_size * 2);
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

static inline void clear_fulfilled_indices_up_to_height(size_t new_h){
    for (auto &kv : g_inflight_index_ts){
        Sock s = kv.first;
        auto &byidx = kv.second;
        auto &dq = g_inflight_index_order[s];

        // Remove from timestamp map any indices we must already have received
        for (auto it = byidx.begin(); it != byidx.end(); ){
            if (it->first <= (uint64_t)new_h) {
                it = byidx.erase(it);
            } else {
                ++it;
            }
        }

        // Trim the front of the oldest-first deque
        while (!dq.empty() && dq.front() <= (uint64_t)new_h) dq.pop_front();

        }
    
    // Return number of cleared items per socket for caller to adjust counters
    static std::unordered_map<Sock, uint32_t> cleared_counts;
    cleared_counts.clear();
    for (const auto& kv : g_inflight_index_ts) {
        Sock s = kv.first;
        for (const auto& idx_ts : kv.second) {
            if (idx_ts.first <= (uint64_t)new_h) {
                cleared_counts[s]++;
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
    (void)miq_set_nodelay(s);
    miq_set_sockbufs(s);

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
    {
        auto it = g_inflight_block_ts.find(fd);
        if (it != g_inflight_block_ts.end()) {
            for (const auto& kv : it->second) {
                g_global_inflight_blocks.erase(kv.first);
            }
        }
        g_inflight_block_ts.erase(fd);
        g_inflight_index_ts.erase(fd);
        g_inflight_index_order.erase(fd);
    }
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
    g_inflight_block_ts.erase(fd); // also drop any inflight block timers for this socket
    g_hdr_flip.erase(fd);
    g_peer_last_fetch_ms.erase(fd);
    g_peer_last_request_ms.erase(fd);
    g_peer_index_capable.erase(fd);
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
    if (it == g_gate.end()) return false;
    auto& g = it->second;

    if (!g.got_verack) {
        int64_t idle = now_ms() - g.hs_last_ms;   // will be small if traffic is flowing
        if (idle > HANDSHAKE_MS) {
            if (g.is_loopback) {
                g.hs_last_ms = now_ms();          // be lenient with localhost tools
            } else {
                close_code = 408;
                P2P_TRACE("close fd=" + std::to_string((uintptr_t)fd) + " reason=handshake-timeout");
                return true;
            }
        }
    }

    if (!cmd.empty()){
        if (cmd == "version"){
            if (!g.got_version){
                g.got_version = true;
                g.hs_last_ms = now_ms();
                should_send_verack = true;
                g_preverack_counts.erase(fd);
                g.hs_last_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now().time_since_epoch()).count();
            }
        } else if (cmd == "verack"){
            g.got_verack = true;
            g_preverack_counts.erase(fd);
            g.hs_last_ms = now_ms();
            g.hs_last_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now().time_since_epoch()).count();
        } else {
            if (!g.got_version) {
                if (miq_safe_preverack_cmd(cmd)) {
                    // Safe pre-version traffic → count as liveness so we don't trip verack timeout.
                    g.hs_last_ms = now_ms();
                    return false;
                } else {
                    g.banscore += 10;
                    if (g.banscore >= MAX_BANSCORE) { close_code = 400; P2P_TRACE("close fd="+std::to_string((uintptr_t)fd)+" reason=pre-version-bad"); return true; }
                    return false;
                }
            }
            if (!g.got_verack){
                if (!miq_safe_preverack_cmd(cmd)) { return false; /* ignore silently */ }
                // Safe pre-verack traffic also counts as liveness.
                g.hs_last_ms = now_ms();
                // Never penalize safe pre-verack getheaders/headers; drop-count only other safe cmds.
                if (!g.is_loopback && cmd != "getheaders" && cmd != "headers") {
                    int &cnt = g_preverack_counts[fd];
                    if (++cnt > MIQ_PREVERACK_QUEUE_MAX) {
                        // soft-drop extra safe messages during handshake; no banscore/close
                        return false;
                    }
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

    // Use a more compatible protocol version (similar to Bitcoin Core)
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
    const int      kMaxInflight = 16;   // wider header pipeline
    const int64_t  kMinGapMs    = 10; // keep tiny gap to avoid tight spins
    if (static_cast<uint32_t>(ps.inflight_hdr_batches) >= static_cast<uint32_t>(kMaxInflight)) return false;
    auto it = g_last_hdr_req_ms.find((Sock)ps.sock);
    int64_t last_req = (it == g_last_hdr_req_ms.end()) ? 0 : it->second;
    if (last_req && (now - last_req) < kMinGapMs) return false;
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
    g_global_inflight_blocks.clear();
    g_inflight_block_ts.clear();
    g_rr_next_idx.clear();
    g_last_hdr_req_ms.clear();

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
    if (srv_ == MIQ_INVALID_SOCK) { log_error("P2P: failed to create IPv4 server"); return false; }
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
    if (srv_ != MIQ_INVALID_SOCK) { CLOSESOCK(srv_); srv_ = MIQ_INVALID_SOCK; }
    if (g_srv6_ != MIQ_INVALID_SOCK) { CLOSESOCK(g_srv6_); g_srv6_ = MIQ_INVALID_SOCK; }
    for (auto& kv : peers_) {
        if (kv.first != MIQ_INVALID_SOCK) {
            gate_on_close(kv.first);
            CLOSESOCK(kv.first);
        }
    }
    peers_.clear();
    if (th_.joinable()) th_.join();
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
    g_force_close.clear();
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
    peers_[s] = ps;
    g_peer_index_capable[s] = false;

    g_trickle_last_ms[s] = 0;

    uint32_t be_ip;
    if (parse_ipv4(ps.ip, be_ip) && ipv4_is_public(be_ip) && !is_self_be(be_ip)) {
        addrv4_.insert(be_ip);
#if MIQ_ENABLE_ADDRMAN
        miq::NetAddr na; na.host = ps.ip; na.port = port; na.tried = true; na.is_ipv6=false;
        g_addrman.mark_good(na);
        g_addrman.add_anchor(na);
#endif
    }

    log_info("Peer: connected → " + peers_[s].ip);

    // Gate first, then mark loopback (so flag actually sticks)
    gate_on_connect(s);
    {
        std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
        // mark as outbound for gating/diversity
        g_outbounds.insert(s);
    }
    if (parse_ipv4(ps.ip, be_ip)) {
        gate_set_loopback(s, is_loopback_be(be_ip));
    }

    miq_set_keepalive(s);
    auto version_payload = miq_build_version_payload((uint32_t)chain_.height());
    P2P_TRACE("TX " + ps.ip + " cmd=version len=" + std::to_string(version_payload.size()));
    auto msg = encode_msg("version", version_payload);
    bool sent = send_or_close(s, msg);
    (void)sent; // Used by P2P_TRACE when enabled
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
    peers_[c] = ps;
    g_peer_index_capable[c] = false;

    g_trickle_last_ms[c] = 0;

    uint32_t be_ip;
    if (parse_ipv4(ip, be_ip) && ipv4_is_public(be_ip)) {
        addrv4_.insert(be_ip);
    #if MIQ_ENABLE_ADDRMAN
        miq::NetAddr na; na.host=ip; na.port=g_listen_port; na.is_ipv6=false; na.tried=false;
        g_addrman.add(na, /*from_dns=*/false);
    #endif
    }

    log_info("P2P: inbound peer " + ip);

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
        P2P_TRACE("TX " + ip + " cmd=version len=" + std::to_string(payload.size()));
    }
}

void P2P::broadcast_inv_block(const std::vector<uint8_t>& h){
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

static inline void trickle_enqueue(Sock sock, const std::vector<uint8_t>& txid){
    if (txid.size()!=32) return;
    auto& q = g_trickle_q[sock];
    if (q.size() < 4096) q.push_back(txid);
}

void P2P::broadcast_inv_tx(const std::vector<uint8_t>& txid){
    if (txid.size()!=32) return;
    // queue for loop thread so only the loop touches peers_
    std::lock_guard<std::mutex> lk(announce_tx_mu_);
    if (announce_tx_q_.size() < 8192) announce_tx_q_.push_back(txid);
}

// CRITICAL FIX: Store raw transaction for serving to peers
// This is called by RPC sendrawtransaction so peers can fetch the full tx
// after receiving the invtx announcement. Without this, peers would send
// gettx but we'd have nothing to serve them!
void P2P::store_tx_for_relay(const std::vector<uint8_t>& txid, const std::vector<uint8_t>& raw_tx){
    if (txid.size() != 32 || raw_tx.empty()) return;

    std::string key;
    key.reserve(64);
    static const char hex[] = "0123456789abcdef";
    for (uint8_t b : txid) {
        key.push_back(hex[b >> 4]);
        key.push_back(hex[b & 0xf]);
    }

    // Note: No lock needed here since this is called from RPC thread
    // and the main loop accesses tx_store_ from its own thread.
    // However, for safety, we should use the announce_tx_mu_ lock.
    std::lock_guard<std::mutex> lk(announce_tx_mu_);

    if (tx_store_.find(key) == tx_store_.end()) {
        tx_store_[key] = raw_tx;
        tx_order_.push_back(key);
        if (tx_store_.size() > MIQ_TX_STORE_MAX) {
            auto victim = tx_order_.front();
            tx_order_.pop_front();
            tx_store_.erase(victim);
        }
    }

    // Also mark as seen so we don't process it again if a peer relays it back
    seen_txids_.insert(key);
}

static void trickle_flush(){
    int64_t tnow = now_ms();
    for (auto& kv : g_trickle_q) {
        Sock s = kv.first;
        auto& q = kv.second;

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
            } else {
                break; // scheduled for close; stop emitting
            }
            ++n_send;
        }
        g_trickle_last_ms[s] = tnow;
    }
}

void P2P::request_tx(PeerState& ps, const std::vector<uint8_t>& txid){
    if (txid.size()!=32) return;
    if (!check_rate(ps, "get", 1.0, now_ms())) return;
    const size_t max_inflight_tx = caps_.max_txs ? caps_.max_txs : (size_t)128;
    if (ps.inflight_tx.size() >= max_inflight_tx) return;
    auto m = encode_msg("gettx", txid);
    if (send_or_close(ps.sock, m)) {
        ps.inflight_tx.insert(hexkey(txid));
    }
}

void P2P::send_tx(Sock sock, const std::vector<uint8_t>& raw){
    if (raw.empty()) return;
    auto m = encode_msg("tx", raw);
    (void)send_or_close(sock, m);
}

void P2P::start_sync_with_peer(PeerState& ps){
    if (!peer_is_index_capable((Sock)ps.sock) || ps.peer_tip_height <= 1) {
#if MIQ_ENABLE_HEADERS_FIRST
        std::vector<std::vector<uint8_t>> locator;
        chain_.build_locator(locator);
        if (g_hdr_flip[(Sock)ps.sock]) {
            for (auto& h : locator) std::reverse(h.begin(), h.end());
        }
        std::vector<uint8_t> stop(32, 0);
        auto pl2 = build_getheaders_payload(locator, stop);
        auto m2  = encode_msg("getheaders", pl2);
        int pushed = 0;
        while (can_accept_hdr_batch(ps, now_ms()) &&
               check_rate(ps, "hdr", 1.0, now_ms()) &&
               pushed < 4) {
            ps.sent_getheaders = true;
            (void)send_or_close(ps.sock, m2);
            ps.inflight_hdr_batches++;
            g_last_hdr_req_ms[(Sock)ps.sock] = now_ms();
            ps.last_hdr_batch_done_ms        = now_ms();
            ++pushed;
        }
        if (!g_logged_headers_started) {
            g_logged_headers_started = true;
            log_info("[IBD] headers phase started");
            if (!g_ibd_headers_started_ms) g_ibd_headers_started_ms = now_ms();
        }
#endif
        return;
    }
    // Index-capable: pipeline indices immediately.
    ps.syncing = true;
    ps.inflight_index = 0;
    ps.next_index = chain_.height() + 1;
    fill_index_pipeline(ps);
}

void P2P::fill_index_pipeline(PeerState& ps){
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

    if (!peer_is_index_capable((Sock)ps.sock)) return;

    // SYNC STATE FIX: Ensure next_index is consistent with current chain height
    uint64_t current_height = chain_.height();
    if (ps.next_index <= current_height) {
        ps.next_index = current_height + 1;
        P2P_TRACE("DEBUG: Sync state corrected - next_index updated from " +
                  std::to_string(ps.next_index - 1) + " to " + std::to_string(ps.next_index) +
                  " (chain height=" + std::to_string(current_height) + ")");
    }

    while (ps.inflight_index < pipe) {
        uint64_t idx = ps.next_index++;
        request_block_index(ps, idx);
        ps.inflight_index++;
    }
}

void P2P::request_block_index(PeerState& ps, uint64_t index){
    uint8_t p[8];
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((index >> (8 * i)) & 0xFF);
    }
    auto msg = encode_msg("getbi", std::vector<uint8_t>(p, p + 8));
    if (send_or_close(ps.sock, msg)) {
        // Track inflight timestamp and ordering per-peer for oldest-first retries
        g_inflight_index_ts[(Sock)ps.sock][index] = now_ms();
        g_inflight_index_order[(Sock)ps.sock].push_back(index);
    }
}

void P2P::request_block_hash(PeerState& ps, const std::vector<uint8_t>& h){
    if (h.size()!=32) return;
  
    size_t base_default = g_sequential_sync ? (size_t)1 : (size_t)256;
    const size_t max_inflight_blocks = caps_.max_blocks ? caps_.max_blocks : base_default;
    if (ps.inflight_blocks.size() >= max_inflight_blocks) return;
    const std::string key = hexkey(h);
    if (g_global_inflight_blocks.count(key)) return;
    auto msg = encode_msg("getb", h);
    if (send_or_close(ps.sock, msg)) {
        ps.inflight_blocks.insert(key);
        g_global_inflight_blocks.insert(key);
        g_inflight_block_ts[(Sock)ps.sock][key] = now_ms();
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
    if (ps.tx_tokens < nbytes) return false;
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
    while ( (orphan_bytes_ > orphan_bytes_limit_) ||
            (orphans_.size() > orphan_count_limit_) ) {
        if (orphan_order_.empty()) break;
        const std::string victim = orphan_order_.front();
        orphan_order_.pop_front();

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
    if (chain_.have_block(bh)) return;

    bool have_parent = chain_.have_block(b.header.prev_hash);

    if (!have_parent) {
        OrphanRec rec{ bh, b.header.prev_hash, raw };
        const std::string child_hex  = hexkey(bh);
        const std::string parent_hex = hexkey(b.header.prev_hash);

        if (orphans_.find(child_hex) == orphans_.end()) {
            orphans_.emplace(child_hex, std::move(rec));
            orphan_children_[parent_hex].push_back(child_hex);
            orphan_order_.push_back(child_hex);
            orphan_bytes_ += raw.size();
            evict_orphans_if_needed();
            // PERFORMANCE: Throttle orphan logging to avoid spam during sync
            static int64_t last_orphan_log_ms = 0;
            int64_t now_orphan_ms = now_ms();
            if (now_orphan_ms - last_orphan_log_ms > 5000) {  // Log at most every 5 seconds
                last_orphan_log_ms = now_orphan_ms;
                log_info("P2P: stored orphan (total=" + std::to_string(orphans_.size()) + ")");
            }
        }

        auto pit = peers_.find(sock);
        if (pit != peers_.end()) {
            request_block_hash(pit->second, b.header.prev_hash);
        }
        return;
    }

    std::string err;
    if (chain_.submit_block(b, err)) {
        // CRITICAL FIX: Notify mempool to remove confirmed transactions
        // Without this, confirmed transactions stay in mempool forever!
        if (mempool_) {
            mempool_->on_block_connect(b);
        }
        const std::string miner = miq_miner_from_block(b);
        std::string src_ip = "?";
        auto pit = peers_.find(sock);
        if (pit != peers_.end()) {
            src_ip = pit->second.ip;
            // Update peer performance metrics for adaptive timeout
            update_peer_performance(pit->second, hexkey(bh), g_inflight_block_ts, now_ms());
        }
        g_rr_next_idx.erase(hexkey(bh));

        // PERFORMANCE: Throttle block acceptance logging during sync (1 per second max)
        static int64_t last_block_log_ms = 0;
        // PRODUCTION: Log block acceptance at WARN level so it shows with default settings
        static uint64_t blocks_since_log = 0;
        int64_t now_block_ms = now_ms();
        blocks_since_log++;
        if (now_block_ms - last_block_log_ms > 5000) {  // Log at most every 5 seconds to reduce spam
            last_block_log_ms = now_block_ms;
            if (blocks_since_log > 1) {
                log_warn("Chain: +" + std::to_string(blocks_since_log) + " blocks → height " + std::to_string(chain_.height()));
            } else {
                log_warn("Chain: new block → height " + std::to_string(chain_.height()));
            }
            blocks_since_log = 0;
        }

        // TELEMETRY: Notify main.cpp about received blocks for UI display
        if (block_callback_) {
            P2PBlockInfo info;
            info.height = chain_.height();
            info.hash_hex = hexkey(bh);
            info.tx_count = static_cast<uint32_t>(b.txs.size());
            info.miner = miner;
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

        broadcast_inv_block(bh);
        try_connect_orphans(hexkey(bh));
        clear_fulfilled_indices_up_to_height(chain_.height());

        // SYNC STATE FIX: Update sync state for all peers when chain height changes
        uint64_t new_height = chain_.height();
        for (auto& kvp : peers_) {
            PeerState& peer = kvp.second;

            if (peer.next_index <= new_height) {
                uint64_t old_next = peer.next_index;
                peer.next_index = new_height + 1;
                if (old_next > 0 && old_next != peer.next_index) {
                    P2P_TRACE("Corrected peer " + peer.ip + " next_index from " + 
                              std::to_string(old_next) + " to " + std::to_string(peer.next_index));
                }
            }
          
            if (peer.syncing && peer.next_index <= new_height) {
                peer.next_index = new_height + 1;
                P2P_TRACE("DEBUG: Updated peer " + peer.ip + " next_index to " +
                          std::to_string(peer.next_index) + " after block acceptance");
            }

            // Adjust inflight_index counter for cleared fulfilled requests
            Sock s = (Sock)peer.sock;
            auto it = g_inflight_index_ts.find(s);
            if (it != g_inflight_index_ts.end()) {
                uint32_t cleared = 0;
                for (const auto& idx_ts : it->second) {
                    if (idx_ts.first <= new_height) cleared++;
                }
                if (cleared > 0) {
                    peer.inflight_index = (peer.inflight_index > cleared) ?
                        (peer.inflight_index - cleared) : 0;
                    P2P_TRACE("DEBUG: Adjusted peer " + peer.ip + " inflight_index by -" +
                              std::to_string(cleared) + " (now " + std::to_string(peer.inflight_index) + ")");
                }
            }
        }

        g_last_progress_ms = now_ms();
        g_last_progress_height = chain_.height();

        // Request next block immediately after accepting one (Bitcoin-style sequential sync)
        // This is more efficient than batch requests and prevents over-requesting
        uint64_t current_height = chain_.height();
        uint64_t next_height = current_height + 1;

        // During IBD, always request the next block from peers
        // The peer will respond with the block if they have it, or ignore if they don't
        for (auto& kvp : peers_) {
            auto& pps = kvp.second;
            if (!pps.verack_ok) continue;
            if (!peer_is_index_capable((Sock)pps.sock)) continue;
            uint64_t best_hdr_height = chain_.best_header_height();
            uint64_t peer_or_hdr_tip = (pps.peer_tip_height > 0)
                ? std::max<uint64_t>(pps.peer_tip_height, best_hdr_height)
                : (uint64_t)best_hdr_height;
            if (peer_or_hdr_tip > 0 && next_height > peer_or_hdr_tip) {
                P2P_TRACE("DEBUG: Not requesting block " + std::to_string(next_height) +
                          " from " + pps.ip + " (beyond peer/header tip)");
                continue;
            }
            if (pps.peer_tip_height == 0 || next_height <= pps.peer_tip_height) {
            fill_index_pipeline(pps);
          }
        }

#if MIQ_ENABLE_HEADERS_FIRST
        {
            std::vector<std::vector<uint8_t>> want_tmp;
            chain_.next_block_fetch_targets(want_tmp, (size_t)32);
            uint64_t max_peer_tip = chain_.height();
            {
                // g_peers_mu is held by the caller context in this path.
                for (auto &kvp : peers_) {
                    const auto &pps = kvp.second;
                    if (!pps.verack_ok) continue;
                    if (pps.peer_tip_height > max_peer_tip) max_peer_tip = pps.peer_tip_height;
                }
            }
            bool at_tip = want_tmp.empty() && (chain_.height() >= max_peer_tip);

            // DEBUG: Log why we think we're at tip


            maybe_mark_headers_done(at_tip);
        }
#endif
    } else {
        log_warn("P2P: reject block (" + err + ")");
    }
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

        std::string err;
        if (chain_.submit_block(ob, err)) {
            // CRITICAL FIX: Notify mempool to remove confirmed transactions
            if (mempool_) {
                mempool_->on_block_connect(ob);
            }
            const std::string miner = miq_miner_from_block(ob);
            log_info("P2P: accepted orphan as block height=" + std::to_string(chain_.height())
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
            g_last_progress_height = chain_.height();
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
            if (tnow - last_dial_ms > MIQ_DIAL_INTERVAL_MS) {
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
                     if (is_v4 && outbound_count() >= (size_t)MIQ_OUTBOUND_TARGET && violates_group_diversity(peers_, be_ip)) {
                         g_addrman.mark_attempt(*cand); continue;
                     }
                     std::string dotted = is_v4 ? be_ip_to_string(be_ip) : cand->host;
                     if (banned_.count(dotted)) { g_addrman.mark_attempt(*cand); continue; }
                     bool connected = false; for (auto& kv : peers_) if (kv.second.ip == dotted) { connected = true; break; }
                     if (connected) { g_addrman.mark_attempt(*cand); continue; }
 
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
                         { std::lock_guard<std::recursive_mutex> lk(g_peers_mu); peers_[s] = ps; g_outbounds.insert(s); }
                         g_peer_index_capable[s] = false;
                         g_trickle_last_ms[s] = 0;
                         log_info("P2P: outbound (addrman) " + ps.ip);
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
                                { std::lock_guard<std::recursive_mutex> lk(g_peers_mu); peers_[s] = ps; g_outbounds.insert(s); }
                                g_peer_index_capable[s] = false;
                                g_trickle_last_ms[s] = 0;

                                log_info("P2P: outbound to known " + ps.ip);
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
                    if (parse_ipv4(cand->host, be_ip) && ipv4_is_public(be_ip) && !is_self_be(be_ip) && !violates_group_diversity(peers_, be_ip)) {
                        std::string dotted = be_ip_to_string(be_ip);
                        if (!banned_.count(dotted)) {
                            bool connected=false; for (auto& kv:peers_) if (kv.second.ip==dotted) { connected=true; break; }
                            if (!connected) {
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
                                    { std::lock_guard<std::recursive_mutex> lk(g_peers_mu); peers_[s]=ps; g_outbounds.insert(s); }
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
            }
        }
#endif

        {
            int64_t tnow = now_ms();
            size_t h = chain_.height();
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

                // Log peer health during stalls (helps diagnose slow peers)
                if (!g_logged_headers_done) {
                    std::string health_summary;
                    for (const auto& kv : peers_) {
                        if (!kv.second.verack_ok) continue;
                        health_summary += "\n  " + kv.second.ip +
                                        ": health=" + std::to_string((int)(kv.second.health_score * 100)) + "%" +
                                        " avg_delivery=" + std::to_string(kv.second.avg_block_delivery_ms / 1000) + "s" +
                                        " blocks=" + std::to_string(kv.second.total_blocks_received) +
                                        " inflight=" + std::to_string(kv.second.inflight_blocks.size());
                    }
                    if (!health_summary.empty()) {
                        log_info("P2P: peer health summary:" + health_summary);
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
                        pps.inflight_index = 0;
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
                    {
                    std::vector<std::vector<uint8_t>> want3;
                    chain_.next_block_fetch_targets(want3, (size_t)128);
                    if (!want3.empty()) {
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
                // No peers connected during stall - rate limit logging to once per 60s
                static int64_t s_last_no_peers_log_ms = 0;
                if (tnow - s_last_no_peers_log_ms > 60000) {
                    s_last_no_peers_log_ms = tnow;
                    log_info("P2P: no peers connected (height=" + std::to_string(h) + ") - attempting to reconnect");
                }
                g_next_stall_probe_ms = tnow + g_stall_retry_ms;
            }
        }
        
        // === NEW: Adaptive timeout & retry for inflight blocks =======================
        {
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

            // Clamp to reasonable bounds: min 30s, max 180s during IBD, max 60s after
            int64_t min_timeout = 30000;
            int64_t max_timeout = !g_logged_headers_done ? 180000 : 60000;
            adaptive_timeout = std::max(min_timeout, std::min(max_timeout, adaptive_timeout));

            // Check each inflight block for this peer
            for (auto& kv : bySock.second) {
              if (tnow - kv.second > adaptive_timeout) {
                expired.emplace_back(bySock.first, kv.first);
                // Track failed delivery for health score
                ps.blocks_failed_delivery++;
                ps.health_score = std::max(0.1, ps.health_score * 0.9); // Decay health on timeout
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
                if (ps.inflight_index > 0) ps.inflight_index--; // free a slot on original peer
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
              itT->second.inflight_index++;
            }
          }
            for (auto &kvp : peers_){
            Sock s = kvp.first;
            if (g_index_timeouts[s] >= 3 && g_peer_index_capable[s]) {
              // demote
              g_peer_index_capable[s] = false;
              auto &ps = kvp.second;
              ps.syncing = false;
              ps.inflight_index = 0;
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
        }

            {
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
                if (sync_active) hard_timeout *= 4; // 4x window while syncing

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
                // Request genesis from peers
                std::vector<uint8_t> genesis_hash(32, 0);
                if (!chain_.have_block(genesis_hash)) {
                    want.push_back(genesis_hash);
                    log_info("[SYNC] Requesting genesis block for initial sync");
                }
            }

            // Debug logging for sync issues
            if (want.empty() && !g_logged_headers_done) {
                static int64_t last_fallback_activation = 0;
                int64_t now = now_ms();

                // For seed nodes with existing blocks, this is normal - reduce log spam
                bool we_are_seed = std::getenv("MIQ_FORCE_SEED") != nullptr;

                // Enhanced fallback: request headers from all connected peers
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
                    
                    // Rate-limit this warning to once per 60 seconds
                    static int64_t last_empty_targets_log = 0;
                    if (now - last_empty_targets_log > 60000) {
                        last_empty_targets_log = now;
                        log_info("[IBD] next_block_fetch_targets empty - activating aggressive index-by-height fallback");
                    }
                    bool activated_any = false;
                    for (auto &kvp : peers_) {
                        auto &pps = kvp.second;
                        if (!pps.verack_ok) continue;
                        if (!peer_is_index_capable((Sock)pps.sock)) continue;
                        if (pps.syncing && pps.inflight_index > 0) continue; // Already syncing by index

                        pps.syncing = true;
                        pps.inflight_index = 0;
                        pps.next_index = chain_.height() + 1;
                        fill_index_pipeline(pps);
                        activated_any = true;
                        log_info("[IBD] activated index-by-height sync for peer " + pps.ip +
                                " starting at height " + std::to_string(pps.next_index));
                    }
                    if (activated_any) {
                        last_fallback_activation = now;
                        g_sync_wants_active.store(true); // Force sync to continue
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
            bool any_inflight = !g_global_inflight_blocks.empty();
            if (!any_inflight) {
                for (auto &kvp : peers_) {
                    if (!kvp.second.inflight_blocks.empty()) { any_inflight = true; break; }
                    if (kvp.second.inflight_index > 0)      { any_inflight = true; break; }
                    if (kvp.second.inflight_hdr_batches > 0){ any_inflight = true; break; }
                }
            }
            const bool headers_done = g_logged_headers_done;

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
            if (!any_want && !any_inflight && headers_done && !g_sync_green_logged) {
                 g_sync_green_logged = true;
                 log_warn("Sync: complete ✓ height=" + std::to_string(chain_.height()));
                 for (auto &kvp : peers_) {
                     kvp.second.syncing = false;
                     kvp.second.inflight_index = 0;
                 }
            }
            // Improved sync completion logic: check if we have exhausted all sync methods
            const uint64_t current_height = chain_.height();
            bool can_try_index_sync = false;
            bool has_active_index_sync = false;

            // Check if we have index-capable peers that could provide more blocks
            for (auto &kvp : peers_) {
                auto &pps = kvp.second;
                if (!pps.verack_ok) continue;
                if (!peer_is_index_capable((Sock)pps.sock)) continue;

                can_try_index_sync = true;
                if (pps.syncing && pps.inflight_index > 0) {
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
            bool height_stalled = false;
            int64_t stall_threshold = headers_done ? 10000 : 30000;  // 10s after headers, 30s before

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
            int64_t refetch_interval = headers_done ? 5000 : 10000;  // 5s after headers, 10s before

            // Use continuous batch pipeline: request next blocks every 200ms
            // This works both before AND after headers phase
            bool should_refetch = false;
            static int64_t last_proactive_log = 0;
            static int64_t last_stall_log = 0;
            if (g_sequential_sync && (now - last_refetch_time > 200)) {
                // Proactive pipeline - keep requesting the next batch of blocks
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

                if (g_logged_headers_done && current_height < chain_.best_header_height()) {
                    for (auto& kvp : peers_) {
                        auto& pps = kvp.second;
                        if (!pps.verack_ok) continue;
                        if (!peer_is_index_capable((Sock)pps.sock)) continue;
                        
                        if (!pps.syncing) {
                            pps.syncing = true;
                            pps.inflight_index = 0;
                            pps.next_index = current_height + 1;
                            fill_index_pipeline(pps);
                            log_info("[SYNC] Activated index sync on " + pps.ip + 
                                   " to catch up to header tip (current=" + std::to_string(current_height) + 
                                   " header_tip=" + std::to_string(chain_.best_header_height()) + ")");
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

                    // For peers that support index-based sync, use getbi
                    if (peer_is_index_capable((Sock)pps.sock)) {
                        // Update peer reputation and adaptive batch size
                        update_peer_reputation(pps);
                        update_adaptive_batch_size(pps);

                        // Determine how many blocks to request (adaptive based on peer reputation)
                        uint64_t best_hdr_height = chain_.best_header_height();
                        uint64_t max_height = (best_hdr_height > current_height)
                            ? best_hdr_height
                            : current_height + pps.adaptive_batch_size;  // Use adaptive batch size

                        // Cap to peer's known tip height: don't request beyond what peer has sent us
                        if (pps.peer_tip_height > 0 && pps.peer_tip_height > current_height) {
                            max_height = std::min(max_height, (uint64_t)pps.peer_tip_height);
                        }

                        // Request blocks up to max_height (or current_height + adaptive_batch_size, whichever is smaller)
                        uint64_t batch_end = std::min(max_height, current_height + pps.adaptive_batch_size);

                        for (uint64_t h = current_height + 1; h <= batch_end; h++) {
                            request_block_index(pps, (uint64_t)h);
                            if (h == current_height + 1 || h == batch_end) {
                                log_info("TX " + pps.ip + " cmd=getbi height=" + std::to_string(h) +
                                        " (adaptive batch=" + std::to_string(pps.adaptive_batch_size) +
                                        ", rep=" + std::to_string(pps.reputation_score) + ")");
                            }
                        }
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

                // If we think we're done but could still try index sync, activate it
                if (!any_want && !any_inflight && headers_done && can_try_index_sync && !has_active_index_sync) {
                    static int64_t last_index_activation = 0;
                    if (now - last_index_activation > 15000) { // Try every 15 seconds
                        log_warn("[SYNC] Hash-based sync exhausted at height=" + std::to_string(current_height) +
                                ", activating index-by-height sync as final attempt");

                        // Activate index sync on ALL capable peers for maximum throughput
                        int activated_peers = 0;
                        for (auto &kvp : peers_) {
                            auto &pps = kvp.second;
                            if (!pps.verack_ok) continue;
                            if (!peer_is_index_capable((Sock)pps.sock)) continue;

                            // Always reset and reactivate to ensure fresh sync
                            pps.syncing = true;
                            pps.inflight_index = 0;
                            pps.next_index = chain_.height() + 1;
                            fill_index_pipeline(pps);
                            log_info("[SYNC] Activated aggressive index sync for peer " + pps.ip +
                                    " starting at height " + std::to_string(pps.next_index));
                            activated_peers++;
                        }

                        if (activated_peers > 0) {
                            log_info("[SYNC] Activated index sync on " + std::to_string(activated_peers) + " peers");
                        } else {
                            log_warn("[SYNC] No index-capable peers available for sync activation");
                        }

                        last_index_activation = now;
                        g_sync_wants_active.store(true);
                    }
                }
            }
        }

        trickle_flush();

        // --- build pollfd list (SNAPSHOT of peers_) ---
        std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
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

#ifdef _WIN32
        int rc = WSAPoll(fds.data(), (ULONG)fds.size(), 200);
#else
        int rc = poll(fds.data(), (nfds_t)fds.size(), 200);
#endif

        // DEBUG: Log poll results if it returns immediately (tight loop detection)
        static int64_t last_poll_time = 0;
        static int tight_loop_count = 0;
        int64_t poll_now = now_ms();
        if (poll_now - last_poll_time < 50 && rc > 0) {
            // Poll returned in less than 50ms - might be a tight loop
            tight_loop_count++;

            // If we're in a tight loop for too long, force a sleep to prevent CPU burn
            if (tight_loop_count > 100) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                tight_loop_count = 0;
            }
        } else {
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
          if (!g_force_close.empty()) {
            // Don’t honor force-close for peers that are helping IBD; keep them alive.
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
                                itT->second.inflight_index++;
                            }
                        }
                    }
                }
                g_inflight_index_ts.erase(s_dead);
                g_inflight_index_order.erase(s_dead);

                // Log peer disconnection
                log_info("Peer: disconnected ← " + ps_old.ip + " (remaining_peers=" + std::to_string(peers_.size() - 1) + ")");

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
            }
            // we handled the closes ourselves; do not let them be processed elsewhere this tick
            dead.clear();
        }
            
            bool ready = (rev & POLL_RD) != 0;

            if (ready) {
                uint8_t buf[65536];
                int n = miq_recv(s, buf, sizeof(buf));
                if (n <= 0) {
                    if (n < 0) {
                        P2P_TRACE("close read<0");
                        dead.push_back(s);
                    }
                    enforce_rx_parse_deadline(ps, s);
                    continue;
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
                while (true) {
                    size_t off_before = off;
                    bool ok = decode_msg(ps.rx, off, m);
                    if (!ok) {
                        break;
                    }
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

                    bool send_verack = false; int close_code = 0;
                    if (gate_on_command(s, cmd, send_verack, close_code)) {
                        if (close_code) { /* traced in gate_on_command */ }
                        dead.push_back(s);
                        break;
                    }
                    P2P_TRACE("DEBUG: cmd=" + cmd + " send_verack=" + (send_verack ? "true" : "false"));
                    if (send_verack) {
                        // Send verack to acknowledge the received version
                        auto verack = encode_msg("verack", {});
                        bool verack_sent = send_or_close(s, verack);
                        P2P_TRACE("TX " + ps.ip + " cmd=verack len=0 result=" + (verack_sent ? "OK" : "FAILED"));

                        if (verack_sent) {
                            gate_mark_sent_verack(s);
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
                        if (!(gg.got_version && gg.got_verack && gg.sent_verack)) return;
                        
                        // The handshake is complete at this point

                        ps.verack_ok = true;
                        const int64_t hs_ms = now_ms() - gg.t_conn_ms;
                        log_info(std::string("P2P: handshake complete with ")+ps.ip+" in "+std::to_string(hs_ms)+" ms");

                        // BIP130: Send sendheaders to prefer header announcements
                        if (!ps.sent_sendheaders) {
                            auto sendheaders_msg = encode_msg("sendheaders", {});
                            if (send_or_close(s, sendheaders_msg)) {
                                ps.sent_sendheaders = true;
                            }
                        }

                        // BIP152: Announce compact block support (version 1, low-bandwidth mode)
                        {
                            std::vector<uint8_t> sendcmpct_payload;
                            sendcmpct_payload.push_back(0);  // announce = 0 (low-bandwidth)
                            // version = 1 (8 bytes little-endian)
                            for (int i = 0; i < 8; i++) {
                                sendcmpct_payload.push_back(i == 0 ? 1 : 0);
                            }
                            auto sendcmpct_msg = encode_msg("sendcmpct", sendcmpct_payload);
                            (void)send_or_close(s, sendcmpct_msg);
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
                            }
                        } else
#endif
                        {
                            ps.syncing = true;
                            ps.inflight_index = 0;
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
                        int32_t peer_ver = 0; uint64_t peer_services = 0;
                        if (m.payload.size() >= 4) {
                            peer_ver = (int32_t)((uint32_t)m.payload[0] | ((uint32_t)m.payload[1]<<8) | ((uint32_t)m.payload[2]<<16) | ((uint32_t)m.payload[3]<<24));
                        }
                        if (m.payload.size() >= 12) {
                            for(int j=0;j<8;j++) peer_services |= ((uint64_t)m.payload[4+j]) << (8*j);
                        }
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
                            }
                        }
                    }
                    try_finish_handshake();
                      
                    } else if (cmd == "verack") {
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
                            if (++ps.mis > 10) { dead.push_back(s); }
                            continue;
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
                            g_last_progress_ms = now_ms();
                            g_next_stall_probe_ms = g_last_progress_ms + MIQ_P2P_STALL_RETRY_MS;
                            // Use received headers to raise our estimate of this peer's tip.
                            {
                                uint64_t bhh = chain_.best_header_height();
                                if (bhh > ps.peer_tip_height) ps.peer_tip_height = bhh;
                            }
                        } else if (hs.size() > 0) {
                            log_warn("P2P: Headers REJECTED from " + ps.ip + " n=" + std::to_string(hs.size()) +
                                    " accepted=0 error=" + herr);
                        }

                        g_peer_last_fetch_ms[(Sock)ps.sock] = now_ms();
                        g_last_hdr_ok_ms[(Sock)ps.sock]     = now_ms();
                        if (ps.inflight_hdr_batches > 0) ps.inflight_hdr_batches--;
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
                            while (can_accept_hdr_batch(ps, now_ms()) &&
                                   check_rate(ps, "hdr", 1.0, now_ms()) &&
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
                        // During IBD, allow higher rate of invb messages (don't rate limit)
                        bool is_ibd = ibd_or_fetch_active(ps, now_ms());
                        if (!is_ibd && !check_rate(ps, "inv", 0.5, now_ms())) {
                            // Rate-limited: only log occasionally to avoid log spam
                            P2P_TRACE_RATE("invb rate-limited from " + ps.ip);
                            bump_ban(ps, ps.ip, "inv-flood", now_ms());
                            continue;
                        }
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
                            }
                            // Removed: "already have block" log - too spammy during sync
                        }

                    } else if (cmd == "getb") {
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
                        g_peer_last_request_ms[(Sock)ps.sock] = now_ms();
                        if (m.payload.size() == 8) {
                            uint64_t idx64 = 0;
                            for (int j=0;j<8;j++) idx64 |= ((uint64_t)m.payload[j]) << (8*j);
                            P2P_TRACE("DEBUG: getbi request for index " + std::to_string(idx64) + " from " + ps.ip);

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
                                P2P_TRACE("SKIP " + ps.ip + " cmd=getbi height=" + std::to_string(idx64) + " (block not available)");
                            }
                        } else {
                            P2P_TRACE("SKIP " + ps.ip + " cmd=getbi (invalid payload size=" + std::to_string(m.payload.size()) + ")");
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
                            // clear inflight for this block
                            ps.inflight_blocks.erase(bh);
                            g_inflight_block_ts[(Sock)s].erase(bh);
                            g_global_inflight_blocks.erase(bh);

                            // NOTE: Don't update peer_tip_height here - it should only be set from
                            // the version message or headers, not from individual blocks.
                            // Setting it here causes false "syncing blocks" status when the peer
                            // sends us a block that hasn't been accepted yet.

                            // Track block delivery time for reputation scoring
                            int64_t now_ms_val = now_ms();
                            int64_t delivery_time_ms = 0;

                            // accept/process
                            uint64_t old_height = chain_.height();
                            handle_incoming_block(s, m.payload);

                            // Update reputation: track successful delivery
                            int64_t after_ms = now_ms();
                            delivery_time_ms = after_ms - now_ms_val;
                            ps.blocks_delivered_successfully++;
                            ps.total_block_delivery_time_ms += delivery_time_ms;
                            ps.total_blocks_received++;
                            ps.total_block_bytes_received += m.payload.size();

                            if (ps.inflight_index > 0) {
                                // Identify delivered block index if possible
                                auto block_hash_vec = hb.block_hash();
                                uint64_t delivered_idx = 0;
                                std::vector<uint8_t> idx_hash;
                                for (auto it2 = g_inflight_index_ts[(Sock)s].begin(); it2 != g_inflight_index_ts[(Sock)s].end(); ++it2) {
                                    if (chain_.get_hash_by_index(it2->first, idx_hash) && idx_hash == block_hash_vec) {
                                        delivered_idx = it2->first;
                                        break;
                                    }
                                }
                                if (delivered_idx == 0) {
                                    uint64_t newHeight = chain_.height();
                                    if (newHeight > old_height) {
                                        delivered_idx = old_height + 1;
                                    } else {
                                        // Fallback: assume the last requested index
                                        delivered_idx = (ps.next_index > 0 ? ps.next_index - 1 : 0);
                                    }
                                }
                                if (delivered_idx != 0) {
                                    auto it_idx = g_inflight_index_ts[(Sock)s].find(delivered_idx);
                                    if (it_idx != g_inflight_index_ts[(Sock)s].end()) {
                                        g_inflight_index_ts[(Sock)s].erase(it_idx);
                                    }
                                    auto& dq_idx = g_inflight_index_order[(Sock)s];
                                    auto dq_it = std::find(dq_idx.begin(), dq_idx.end(), delivered_idx);
                                    if (dq_it != dq_idx.end()) {
                                        dq_idx.erase(dq_it);
                                    }
                                }
                                ps.inflight_index--;
                            }

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
                        std::vector<uint8_t> idx_hash2;
                        if (!want3.empty()) {
                            auto missing_hash = want3[0];
                            for (auto it2 = g_inflight_index_ts[(Sock)s].begin(); it2 != g_inflight_index_ts[(Sock)s].end(); ++it2) {
                                if (chain_.get_hash_by_index(it2->first, idx_hash2) && idx_hash2 == missing_hash) {
                                    g_inflight_index_ts[(Sock)s].erase(it2);
                                    break;
                                }
                            }
                        }
                          
             }
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
                            if (!remember_inv(key)) { continue; }
                            // CRITICAL FIX: Do NOT insert into seen_txids_ here!
                            // Only check if we've already processed this transaction.
                            // The actual insert into seen_txids_ happens in the "tx" handler
                            // AFTER successful processing. The old code inserted here which
                            // caused the tx handler to skip processing when the actual tx
                            // data arrived (because seen_txids_.insert().second would be false).
                            if (!seen_txids_.count(key)) {
                                request_tx(ps, m.payload);
                            }
                        }

                    } else if (cmd == "gettx") {
                        if (m.payload.size() == 32) {
                            auto key = hexkey(m.payload);
                            auto itx = tx_store_.find(key);
                            if (itx != tx_store_.end()) {
                                if (rate_consume_tx(ps, itx->second.size())) {
                                    send_tx(s, itx->second);
                                }
                            }
                        }

                    } else if (cmd == "tx") {
                        if (!rate_consume_tx(ps, m.payload.size())) {
                            if (!ibd_or_fetch_active(ps, now_ms())) {
                                if ((ps.banscore += 3) >= MIQ_P2P_MAX_BANSCORE) bump_ban(ps, ps.ip, "tx-rate", now_ms());
                            }
                            continue;
                        }
                        Transaction tx;
                        if (!deser_tx(m.payload, tx)) continue;
                        auto key = hexkey(tx.txid());

                        ps.inflight_tx.erase(key);
                        if (unsolicited_drop(ps, "tx", key)) {
                        // Polite ignore: remote may proactively relay deps.
                        continue;
                    }

                        if (seen_txids_.insert(key).second) {
                            std::string err;
                            bool accepted = true;
                            if (mempool_) {
                                accepted = mempool_->accept(tx, chain_.utxo(), static_cast<uint32_t>(chain_.height()), err);
                            }
                            bool in_mempool = mempool_ && mempool_->exists(tx.txid());

                            // TELEMETRY: Notify about received transaction for UI display
                            if (accepted && in_mempool && txids_callback_) {
                                txids_callback_({key});
                            }

                            // WALLET FIX: Don't skip orphan transactions
                            // When tx is accepted as orphan (accepted=true but not in mempool),
                            // we still need to store it and relay it so it can propagate.
                            // The previous code had "continue" here which caused wallet txs
                            // to never propagate if treated as orphans.
                            if (accepted && !in_mempool) {
                                // Try to fetch missing parent transactions
                                for (const auto& in : tx.vin) {
                                    UTXOEntry e;
                                    if (!chain_.utxo().get(in.prev.txid, in.prev.vout, e)) {
                                        send_gettx(s, in.prev.txid);
                                    }
                                }
                                // Don't continue - fall through to store and relay the orphan tx
                            }

                            if (tx_store_.find(key) == tx_store_.end()) {
                                tx_store_[key] = m.payload;
                                tx_order_.push_back(key);
                                if (tx_store_.size() > MIQ_TX_STORE_MAX) {
                                    auto victim = tx_order_.front();
                                    tx_order_.pop_front();
                                    tx_store_.erase(victim);
                                }
                            }
                            if (accepted) {
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
                                        Sock psock = kvp.first;
                                        uint64_t peer_min = peer_feefilter_kb(psock);
                                        if (peer_min && feerate_kb < peer_min) continue;
                                        trickle_enqueue(psock, txidv);
                                    }
                                } else {
                                    // no complete inputs: still advertise to help fetch deps
                                    const std::vector<uint8_t> txidv = tx.txid();
                                    for (auto& kvp : peers_) trickle_enqueue(kvp.first, txidv);
                                }
                            } else if (!err.empty()) {
                                if (!ibd_or_fetch_active(ps, now_ms())) {
                                    if (++ps.mis > 25) bump_ban(ps, ps.ip, "tx-invalid", now_ms());
                                } else {
                                    ++ps.mis; // track but do not ban during sync
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
                            if (++ps.mis > 10) { dead.push_back(s); }
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
                            if (++ps.mis > 10) { dead.push_back(s); }
                        }

                    } else if (cmd == "cmpctblock") {
                        // Compact block: header + nonce + short_ids + prefilled_txn
                        // For now, we'll request the full block if we receive a compact block
                        if (m.payload.size() >= 88) { // Minimum: 88-byte header
                            // Extract block header hash from the compact block
                            // Header is: version(4) + prev_hash(32) + merkle_root(32) + time(8) + bits(4) + nonce(8)
                            std::vector<uint8_t> header_data(m.payload.begin(), m.payload.begin() + 88);

                            // Hash the header to get block hash
                            std::vector<uint8_t> block_hash(32);
                            // Note: We'd need to compute the block hash here
                            // For simplicity, just request by inverting the compact block
                            // A full implementation would reconstruct the block from mempool

                            log_info("P2P: received compact block from " + ps.ip + " (will request full block)");

                            // Store that we prefer compact blocks but need full block for now
                            // Real implementation would reconstruct from mempool and request missing txns
                        }

                    } else if (cmd == "getblocktxn") {
                        // Request for specific transactions from a block
                        // Format: <32 byte block_hash> <varint count> <varint indexes...>
                        if (m.payload.size() >= 33) {
                            std::vector<uint8_t> block_hash(m.payload.begin(), m.payload.begin() + 32);
                            // A full implementation would send back the requested transactions
                            // For now, log and skip
                            log_info("P2P: received getblocktxn from " + ps.ip);
                        }

                    } else if (cmd == "blocktxn") {
                        // Response with requested transactions
                        // Format: <32 byte block_hash> <varint count> <raw transactions...>
                        if (m.payload.size() >= 33) {
                            // A full implementation would use these to complete a compact block
                            log_info("P2P: received blocktxn from " + ps.ip);
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
                            if (++ps.mis > 10) { dead.push_back(s); }
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
                            if (++ps.mis > 10) { dead.push_back(s); }
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
                                // If peer supports index-by-height, kick that pipeline too.
                                if (peer_is_index_capable(s)) {
                                    ps.syncing = true;
                                    ps.inflight_index = 0;
                                    ps.next_index = chain_.height() + 1;
                                    fill_index_pipeline(ps);
                                    log_warn("P2P: headers made no progress repeatedly from " + ps.ip +
                                             " → enabling index-by-height fallback");
                                }
                            }
                        } else {
                            g_zero_hdr_batches[s] = 0;
                        }

                        std::vector<std::vector<uint8_t>> want;
                        chain_.next_block_fetch_targets(want, caps_.max_blocks ? caps_.max_blocks : (size_t)64);
                        bool at_tip = (hs.empty()) || ((hs.size() < kHdrBatchMax) && (chain_.best_header_height() > chain_.height()) && want.empty());

                        if (accepted > 0) {
                            // PERFORMANCE: Use the static throttle counter from above
                            // (Headers logging is already throttled by the first branch)
                            g_last_progress_ms = now_ms();
                            g_next_stall_probe_ms = g_last_progress_ms + MIQ_P2P_STALL_RETRY_MS;
                            g_last_hdr_ok_ms[(Sock)s] = g_last_progress_ms;
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
                                    ps.syncing = true;
                                    ps.inflight_index = 0;
                                    ps.next_index = chain_.height() + 1;
                                    fill_index_pipeline(ps);
                                    zero_count = 0;
                                    g_peer_stalls[(Sock)s]++;
                                    if (g_peer_stalls[(Sock)s] >= MIQ_P2P_BAD_PEER_MAX_STALLS && !is_loopback(ps.ip)) {
                                        // disconnect persistently stalling peer (keeps the network moving)
                                        log_warn("P2P: disconnecting persistently stalling peer " + ps.ip);
                                        dead.push_back(s);
                                    }
                                }
                            } else {
                                // If we are in headers and have not advanced for a long time overall, fallback globally.
                                if (!g_logged_headers_done && (now_ms() - g_last_progress_ms) > (int64_t)MIQ_IBD_FALLBACK_AFTER_MS) {
                                    log_warn("[IBD] headers overall progress timeout; switching to index fallback");
                                    ps.syncing = true;
                                    ps.next_index = chain_.height() + 1;
                                    request_block_index(ps, ps.next_index);
                                    ps.inflight_index++;
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
                        if (++ps.mis > 10) { dead.push_back(s); }
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
                    P2P_TRACE("close verack-timeout");
                    dead.push_back(s);
                    continue;
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
                            P2P_TRACE("close pong-timeout");
                            dead.push_back(s);
                            continue;
                        } else {
                            ps.awaiting_pong = false;
                            // Extend the ping timer for localhost tools
                            ps.last_ping_ms = tnow + 5000;
                        }
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
                            P2P_TRACE("close pong-timeout");
                            dead.push_back(s);
                            continue; // proceed to close handling for this peer
                        } else {
                            // Lenient path for localhost tools/wallets: don't drop, just reset the ping cycle.
                            ps.awaiting_pong = false;
                            // Small backoff to avoid hammering busy peers.
                            ps.last_ping_ms = tnow + 5000;
                        }
                    }
                }
              if (!ps.syncing && !g_logged_headers_done) {
                    int64_t last_ok = g_last_hdr_ok_ms.count(s) ? g_last_hdr_ok_ms[s] : 0;
                    if (last_ok && (tnow - last_ok) > (int64_t)(g_stall_retry_ms * 4) && !is_lb) {
                        log_warn("P2P: deprioritizing header-stalled peer " + ps.ip);
                        g_peer_stalls[s]++;
                        if (g_peer_stalls[s] >= MIQ_P2P_BAD_PEER_MAX_STALLS) dead.push_back(s);
                    }
                }
            }
            if (ps.syncing) {
                if ((tnow - g_last_progress_ms) > (int64_t)MIQ_P2P_STALL_RETRY_MS) {
                    uint64_t oldest_inflight =
                        (ps.next_index > ps.inflight_index)
                            ? (ps.next_index - ps.inflight_index)
                            : (uint64_t)chain_.height() + 1; // safe floor

                    const int64_t last_probe =
                        (g_last_idx_probe_ms.count(oldest_inflight) ? g_last_idx_probe_ms[oldest_inflight] : 0);

                    if (tnow - last_probe >= (int64_t)MIQ_P2P_STALL_RETRY_MS) {
                        // Track failed delivery (timeout) for reputation scoring
                        ps.blocks_failed_delivery++;

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
                    ps.syncing = true;
                    ps.next_index = chain_.height() + 1;
                    request_block_index(ps, ps.next_index);
                    ps.inflight_index++;
                }
            }
#endif
        }
        // ---- Guarded removals (single, consistent path) --------------------
        for (Sock s : dead) {
            // auto it_peers_count = peers_.size();  // Currently unused
            // auto it_preview = peers_.find(s);  // Currently unused

            trickle_flush();

        // Periodically persist address sets (legacy + addrman)
        {
            int64_t tnow = now_ms();
            if (tnow - last_addr_save_ms > (int64_t)MIQ_ADDR_SAVE_INTERVAL_MS) {
                save_addrs_to_disk(datadir_, addrv4_);
#if MIQ_ENABLE_ADDRMAN
                std::string err;
                if (!g_addrman.save(g_addrman_path, err)) {
                    log_warn("P2P: addrman periodic save failed: " + err);
                }
#endif
                last_addr_save_ms = tnow;
            }
        }
  
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
            g_trickle_last_ms.erase(s);
            g_cmd_rl.erase(s); // mirror cleanup in case gate_on_close wasn't hit
            {
                auto it_ts = g_inflight_block_ts.find(s);
                if (it_ts != g_inflight_block_ts.end()) {
                    for (const auto& kv : it_ts->second) {
                        g_global_inflight_blocks.erase(kv.first);
                    }
                    g_inflight_block_ts.erase(it_ts);
                }
            }
        }

        // trickle any queued invtx payloads (enqueued by broadcast_inv_tx)
        {
            std::vector<std::vector<uint8_t>> todos;
            {
                std::lock_guard<std::mutex> lk_tx(announce_tx_mu_);
                if (!announce_tx_q_.empty()) { todos.swap(announce_tx_q_); }
            }
            if (!todos.empty()) {
                std::vector<Sock> sockets;
                { std::lock_guard<std::recursive_mutex> lk2(g_peers_mu);
                  for (auto& kv : peers_) sockets.push_back(kv.first); }
                for (const auto& txid : todos) {
                    for (auto s : sockets) trickle_enqueue(s, txid);
                }
            }
        }

        trickle_flush();

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
                std::vector<Sock> sockets;
                // NOTE: g_peers_mu is already locked by the outer scope at line 4108
                // Do NOT lock it again here to avoid deadlock!
                for (auto& kv : peers_) sockets.push_back(kv.first);
                for (auto s : sockets) {
                    (void)send_or_close(s, m);
                }
            }
        }

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
    out.reserve(peers_.size());
    std::lock_guard<std::recursive_mutex> lk(g_peers_mu);
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
        out.push_back(std::move(s));
    }
    return out;
}
}
