#pragma once
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <cstdint>
#include <utility>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <chrono>
#include <functional>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
  #ifndef socklen_t
    using socklen_t = int;
  #endif
  using Sock = SOCKET;          // unified socket type on Windows
#else
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <sys/socket.h>
  #include <unistd.h>
  using Sock = int;             // unified socket type on POSIX
#endif

#include "mempool.h"

namespace miq {
    class ThreadPool;
}

// =============================================================================
// PRODUCTION-GRADE P2P NETWORK CONFIGURATION
// Optimized for millions of users and high reliability
// =============================================================================

// === Connection limits and resource management ===
#ifndef MIQ_MAX_INBOUND_CONNECTIONS
#define MIQ_MAX_INBOUND_CONNECTIONS 125  // Production: more inbound for serving
#endif
#ifndef MIQ_MAX_OUTBOUND_CONNECTIONS
#define MIQ_MAX_OUTBOUND_CONNECTIONS 12  // Production: more outbound for reliability
#endif
#ifndef MIQ_MAX_FEELER_CONNECTIONS
#define MIQ_MAX_FEELER_CONNECTIONS 2  // Production: parallel feelers
#endif
#ifndef MIQ_MAX_CONNECTIONS
#define MIQ_MAX_CONNECTIONS (MIQ_MAX_INBOUND_CONNECTIONS + MIQ_MAX_OUTBOUND_CONNECTIONS + MIQ_MAX_FEELER_CONNECTIONS)
#endif
#ifndef MIQ_PER_PEER_RX_BUFFER_LIMIT
#define MIQ_PER_PEER_RX_BUFFER_LIMIT (8 * 1024 * 1024)  // 8MB per peer
#endif
#ifndef MIQ_TOTAL_RX_BUFFER_LIMIT
#define MIQ_TOTAL_RX_BUFFER_LIMIT (200 * 1024 * 1024)  // 200MB total
#endif
#ifndef MIQ_MAX_SAME_IP_CONNECTIONS
#define MIQ_MAX_SAME_IP_CONNECTIONS 3  // Stricter per-IP limit
#endif
#ifndef MIQ_MAX_SUBNET24_CONNECTIONS
#define MIQ_MAX_SUBNET24_CONNECTIONS 6  // Stricter subnet limit
#endif
#ifndef MIQ_CONNECTION_BACKOFF_BASE_MS
#define MIQ_CONNECTION_BACKOFF_BASE_MS 30000  // 30 second base backoff
#endif
#ifndef MIQ_CONNECTION_BACKOFF_MAX_MS
#define MIQ_CONNECTION_BACKOFF_MAX_MS (12 * 60 * 60 * 1000)  // 12 hours max
#endif
#ifndef MIQ_PEER_ROTATION_INTERVAL_MS
#define MIQ_PEER_ROTATION_INTERVAL_MS (20 * 60 * 1000)  // 20 minutes
#endif
#ifndef MIQ_EVICTION_BATCH_SIZE
#define MIQ_EVICTION_BATCH_SIZE 8  // Evict more at once
#endif

// === Production network health thresholds ===
#ifndef MIQ_MIN_OUTBOUND_CONNECTIONS
#define MIQ_MIN_OUTBOUND_CONNECTIONS 4  // Minimum for healthy operation
#endif
#ifndef MIQ_PING_TIMEOUT_MS
#define MIQ_PING_TIMEOUT_MS 60000  // 60 second ping timeout
#endif
#ifndef MIQ_STALL_TIMEOUT_MS
#define MIQ_STALL_TIMEOUT_MS 120000  // 2 minute stall timeout
#endif

namespace miq {

// === Production hardening knobs (optimized for scale and security) ============
#ifndef MIQ_P2P_INV_WINDOW_MS
#define MIQ_P2P_INV_WINDOW_MS 8000  // Tighter window
#endif
#ifndef MIQ_P2P_INV_WINDOW_CAP
#define MIQ_P2P_INV_WINDOW_CAP 1000  // Higher cap for busier network
#endif
#ifndef MIQ_P2P_GETADDR_INTERVAL_MS
#define MIQ_P2P_GETADDR_INTERVAL_MS 90000  // 90 seconds
#endif
#ifndef MIQ_P2P_ADDR_BATCH_CAP
#define MIQ_P2P_ADDR_BATCH_CAP 1500  // More addresses per batch
#endif
#ifndef MIQ_P2P_NEW_INBOUND_CAP_PER_MIN
#define MIQ_P2P_NEW_INBOUND_CAP_PER_MIN 100  // More inbound for high traffic
#endif
#ifndef MIQ_P2P_BAN_MS
#define MIQ_P2P_BAN_MS (24LL*60LL*60LL*1000LL)  // 24 hour ban
#endif
#ifndef MIQ_P2P_MSG_DEADLINE_MS
#define MIQ_P2P_MSG_DEADLINE_MS 20000  // 20 second deadline
#endif
#ifndef MIQ_P2P_HDR_BATCH_SPACING_MS
#define MIQ_P2P_HDR_BATCH_SPACING_MS 100  // Faster header batching
#endif
#ifndef MIQ_P2P_MAX_BANSCORE
#define MIQ_P2P_MAX_BANSCORE 100
#endif

// === Production IBD (Initial Block Download) optimization ===
#ifndef MIQ_IBD_PARALLEL_DOWNLOADS
#define MIQ_IBD_PARALLEL_DOWNLOADS 16  // Parallel block downloads
#endif
#ifndef MIQ_IBD_STALL_TIMEOUT_MS
#define MIQ_IBD_STALL_TIMEOUT_MS 60000  // 60 second stall
#endif
#ifndef MIQ_BLOCKS_ONLY_MODE_THRESHOLD
#define MIQ_BLOCKS_ONLY_MODE_THRESHOLD 144  // 144 blocks behind = blocks-only
#endif

struct NetGroup {
    uint32_t group_id;      // /16 for IPv4
    std::string asn;        // Autonomous System Number (if available)
    int64_t last_attempt_ms;
    int consecutive_failures;
};

struct ConnectionAttempt {
    int64_t timestamp_ms;
    bool success;
};

class Chain; // fwd

struct OrphanRec {
    std::vector<uint8_t> hash;
    std::vector<uint8_t> prev;
    std::vector<uint8_t> raw;
};

// ---- Per-peer, lightweight rate counters (token buckets by "family") -------
struct RateCounters {
    int64_t last_ms{0};
    std::unordered_map<std::string, double> buckets; // family -> tokens
};

enum class ConnectionType : uint8_t {
    INBOUND,
    OUTBOUND_FULL_RELAY,
    OUTBOUND_BLOCK_RELAY,
    FEELER,
    MANUAL
};

enum class PeerSyncState : uint8_t {
    IDLE,
    SYNCING_HEADERS,
    SYNCING_BLOCKS,
    SYNCING_COMPLETE,
    STALLED,
    FAILED
};

struct PeerState {
    // headers-first (reserved/current use)
    bool     sent_getheaders{false};
    int64_t  last_headers_ms{0};

    // identity/socket
#ifdef _WIN32
    Sock     sock{INVALID_SOCKET};
#else
    Sock     sock{-1};
#endif
    std::string ip;
    ConnectionType conn_type{ConnectionType::INBOUND};

    // misc tracking
    int         mis{0};
    int64_t     last_ms{0};

    // sync
    bool        syncing{false};
    uint64_t    next_index{0};
    uint32_t    inflight_index{0};

    // per-peer RX buffer & liveness
    std::vector<uint8_t> rx;
    bool        verack_ok{false};
    int64_t     last_ping_ms{0};
    bool        awaiting_pong{false};
    int         banscore{0};

    // rate-limit tokens
    uint64_t    blk_tokens{0};
    uint64_t    tx_tokens{0};
    int64_t     last_refill_ms{0};

    // addr throttling
    int64_t     last_addr_ms{0};

    // tx relay
    std::unordered_set<std::string> inflight_tx;

    // block/header inflight tracking
    std::unordered_set<std::string> inflight_blocks;
    int                              inflight_hdr_batches{0};
    int64_t                          last_hdr_batch_done_ms{0};

    // version/features gating & whitelist flags
    uint32_t    version{0};
    uint64_t    features{0};
    bool        whitelisted{false};

    // INV/ADDR throttling state
    int64_t     inv_win_start_ms{0};
    uint32_t    inv_in_window{0};
    int64_t     last_getaddr_ms{0};
    std::unordered_set<std::string> recent_inv_keys;

    // Per-family token buckets
    RateCounters rate;

    // === Peer Reputation & Adaptive Batching ===
    // Reputation metrics
    int64_t blocks_delivered_successfully{0};   // Blocks successfully received
    int64_t blocks_failed_delivery{0};          // Blocks that timed out or failed
    int64_t total_blocks_received{0};           // Total blocks received from this peer
    int64_t total_block_bytes_received{0};      // Total bytes of blocks received
    int64_t total_block_delivery_time_ms{0};    // Sum of delivery times for averaging
    double reputation_score{1.0};               // 0.0 (bad) to 1.0 (excellent)
    double health_score{1.0};                   // 0.0 (bad) to 1.0 (good) - legacy field

    // Adaptive batching
    uint32_t adaptive_batch_size{16};           // Current batch size (adapts based on performance)
    int64_t last_batch_completion_ms{0};        // When last batch completed
    int64_t last_batch_duration_ms{0};          // How long last batch took

    // Timeout tracking
    int64_t avg_block_delivery_ms{30000};       // Running average delivery time (default 30s)
    
    // Connection quality tracking (FIX: added for better sync management)
    int64_t last_activity_ms{0};                // Last meaningful activity
    uint32_t blocks_served{0};                  // Blocks we've sent to this peer
    uint32_t headers_served{0};                 // Headers we've sent to this peer
    int64_t connected_ms{0};                    // When connection was established
    int64_t last_useful_ms{0};                  // Last time peer provided useful data
    uint32_t blocks_sent{0};                    // Blocks sent to this peer
    uint32_t blocks_received{0};                // Blocks received from this peer
    uint32_t headers_received{0};               // Headers received from this peer
    bool is_syncing{false};                     // Is this peer currently syncing from us
    std::vector<uint8_t> best_known_tip;        // Best block hash we know this peer has
    int64_t max_timeout_ms{60000};              // Maximum timeout for this peer
    int64_t last_block_received_ms{0};          // Timestamp of last block received

    // Connection health tracking
    int64_t connection_failures{0};             // Consecutive connection failures
    int64_t next_retry_ms{0};                   // Don't retry before this time

    // Track peer's block availability
    uint64_t peer_tip_height{0};
    int64_t connection_attempt_count{0};
    int64_t successful_responses{0};
    int64_t failed_responses{0};
    int64_t bytes_sent{0};
    int64_t bytes_received{0};
    PeerSyncState sync_state{PeerSyncState::IDLE};
    
    // Network group for diversity
    uint32_t network_group{0};
    
    // Eviction protection score (higher = more protected)
    double eviction_score{0.0};
    
    // Ping statistics
    int64_t min_ping_ms{INT64_MAX};
    int64_t last_ping_time_ms{0};
    std::vector<int64_t> ping_samples;  // Keep last 10 samples
    
    // Service flags
    uint64_t services{0};
    
    // Protocol version
    int32_t protocol_version{0};
    
    // User agent
    std::string user_agent;
    
    // Relay preferences
    bool relay_txs{true};
    bool prefer_headers_and_ids{false};
    
    // Connection slot tracking
    bool is_manual{false};
    bool is_feeler{false};
    
    // Flow control
    size_t send_queue_bytes{0};
    static constexpr size_t MAX_SEND_QUEUE_BYTES = 1 * 1024 * 1024;  // 1MB

    // BIP130 sendheaders support
    bool prefer_headers{false};  // Peer prefers headers over inv for blocks
    bool sent_sendheaders{false}; // We've sent sendheaders to this peer

    // BIP152 Compact blocks support
    bool compact_blocks_enabled{false};  // Peer supports compact blocks
    bool compact_high_bandwidth{false};  // High-bandwidth compact block mode
    uint64_t compact_version{0};         // Compact block version (1 or 2)
    std::vector<uint8_t> last_compact_block_hash; // Last compact block sent/received
};

// Lightweight read-only snapshot for RPC/UI
struct PeerSnapshot {
    std::string  ip;
    bool         verack_ok;
    bool         awaiting_pong;
    int          mis;
    uint64_t     next_index;
    bool         syncing;
    double       last_seen_ms;
    uint64_t     blk_tokens;
    uint64_t     tx_tokens;
    size_t       rx_buf;
    size_t       inflight;
    uint64_t     peer_tip;
    ConnectionType conn_type;
    PeerSyncState sync_state;
    int64_t      bytes_sent;
    int64_t      bytes_received;
    int64_t      connection_time_ms;
    int64_t      last_ping_ms;
    double       eviction_score;
    std::string  user_agent;
    uint32_t     network_group;
    uint64_t     services;
    bool         is_manual;
};

// Block info passed to telemetry callbacks
struct P2PBlockInfo {
    uint64_t height{0};
    std::string hash_hex;
    uint32_t tx_count{0};
    uint64_t fees{0};
    bool fees_known{false};
    std::string miner;
};

// Callback types for telemetry notifications
using BlockCallback = std::function<void(const P2PBlockInfo&)>;
using TxidsCallback = std::function<void(const std::vector<std::string>&)>;

class P2P {
public:
    explicit P2P(Chain& c);
    ~P2P();

    // Optional mempool hookup
    inline void set_mempool(Mempool* mp) { mempool_ = mp; }
    inline Mempool*       mempool()       { return mempool_; }
    inline const Mempool* mempool() const { return mempool_; }

    // Telemetry callbacks - called when blocks/txs are received from network
    inline void set_block_callback(BlockCallback cb) { block_callback_ = std::move(cb); }
    inline void set_txids_callback(TxidsCallback cb) { txids_callback_ = std::move(cb); }

    // key-based helper ("invb","getb", etc.)
    bool check_rate(PeerState& ps, const char* key);

    // explicit family:name helper
    bool check_rate(PeerState& ps,
                    const char* family,
                    const char* name,
                    uint32_t burst,
                    uint32_t window_ms);

    // token-bucket by family (cost per event)
    bool check_rate(PeerState& ps,
                    const char* family,
                    double cost,
                    int64_t now_ms);

    bool start(uint16_t port);
    void stop();

    // Outbound connect to a seed (hostname or IP)
    bool connect_seed(const std::string& host, uint16_t port);

    // Broadcast inventory
    void announce_block_async(const std::vector<uint8_t>& h);
    void broadcast_inv_block(const std::vector<uint8_t>& h);
    void broadcast_inv_tx(const std::vector<uint8_t>& txid);

    // CRITICAL FIX: Store raw transaction for serving to peers via gettx
    // This must be called when a tx is accepted via RPC (sendrawtransaction)
    // so that peers can fetch the full tx after receiving the invtx announcement
    void store_tx_for_relay(const std::vector<uint8_t>& txid, const std::vector<uint8_t>& raw_tx);

    // BIP130 sendheaders support
    void send_sendheaders(PeerState& ps);
    void broadcast_header(const std::vector<uint8_t>& header_data);

    // BIP152 Compact blocks support
    void send_sendcmpct(PeerState& ps, bool high_bandwidth, uint64_t version);
    void send_cmpctblock(PeerState& ps, const std::vector<uint8_t>& block_hash);
    void send_getblocktxn(PeerState& ps, const std::vector<uint8_t>& block_hash,
                          const std::vector<uint16_t>& indexes);
    void handle_compact_block(PeerState& ps, const std::vector<uint8_t>& payload);

    // BIP37 Bloom filter support
    void handle_filterload(PeerState& ps, const std::vector<uint8_t>& payload);
    void handle_filteradd(PeerState& ps, const std::vector<uint8_t>& payload);
    void handle_filterclear(PeerState& ps);

    // datadir for bans/peers
    inline void set_datadir(const std::string& d) { datadir_ = d; }

    // tiny, local and fast hex for keys
    std::string hexkey(const std::vector<uint8_t>& h);

    // Read-only stats
    size_t connection_count() const { return peers_.size(); }
    std::vector<PeerSnapshot> snapshot_peers() const;

    // runtime tuning knobs
    struct InflightCaps { size_t max_txs{256}; size_t max_blocks{256}; };
    inline void set_inflight_caps(size_t max_txs, size_t max_blocks) {
        caps_.max_txs   = max_txs;
        caps_.max_blocks= max_blocks;
    }
    inline void set_min_peer_version(uint32_t v) { min_peer_version_ = v; }
    inline void set_feature_required(uint64_t mask) { required_features_mask_ = mask; }
    inline void set_msg_deadlines_ms(int64_t ms) { msg_deadline_ms_ = ms; }

    // whitelist setter (IPv4/CIDR)
    inline void set_whitelist(const std::vector<std::string>& entries) {
        whitelist_ips_.clear();
        whitelist_cidrs_.clear();
        for (const auto& e : entries) {
            auto slash = e.find('/');
            if (slash == std::string::npos) {
                whitelist_ips_.insert(e);
            } else {
                std::string host = e.substr(0, slash);
                std::string bits = e.substr(slash+1);
                uint32_t be_ip = 0;
                if (!parse_ipv4(host, be_ip)) continue;
                int b = 0;
                for (char ch : bits) { if (ch<'0'||ch>'9'){ b=-1; break; } b = b*10 + (ch-'0'); }
                if (b < 0 || b > 32) continue;
                uint32_t ip_host = ntohl(be_ip);
                struct Cidr c;
                c.bits = (uint8_t)b;
                c.net  = (b==0) ? 0u : (ip_host & (~uint32_t(0) << (32-b)));
                whitelist_cidrs_.push_back(c);
            }
        }
    }

    struct ConnectionStats {
        size_t total_connections;
        size_t inbound_connections;
        size_t outbound_connections;
        size_t feeler_connections;
        size_t manual_connections;
        size_t total_rx_buffer_bytes;
        size_t banned_ips;
        double avg_ping_ms;
        size_t stalled_peers;
        size_t syncing_peers;
    };
    ConnectionStats get_connection_stats() const;
    
    // Connection slot management
    bool can_accept_inbound_connection(const std::string& ip) const;
    bool needs_more_outbound_connections() const;
    
    // Manual connection management
    bool add_manual_connection(const std::string& host, uint16_t port);
    bool disconnect_peer(const std::string& ip);
    bool disconnect_peer_by_id(size_t peer_id);
    
    // Ban management with duration
    void ban_ip(const std::string& ip, int64_t duration_ms = 0);
    void unban_ip(const std::string& ip);
    bool is_banned(const std::string& ip) const;
    std::vector<std::pair<std::string, int64_t>> get_banned_ips() const;
    
    // Advanced peer selection
    std::vector<std::string> select_peers_for_eviction(size_t count);
    void protect_eviction_candidates(std::vector<std::string>& candidates);
    
    // Network health monitoring
    double get_network_health_score() const;
    bool is_network_healthy() const;
    
    // Resource management
    size_t get_total_rx_buffer_size() const;
    void trim_oversized_buffers();
    
    // Connection rotation
    void rotate_outbound_connections();
    void maintain_connection_diversity();

private:
    // tx relay (basic)
    void request_tx(PeerState& ps, const std::vector<uint8_t>& txid);
    void send_tx(Sock sock, const std::vector<uint8_t>& raw);
    void send_block(Sock s, const std::vector<uint8_t>& raw);

    // Small caches
    mutable std::mutex announce_mu_;
    std::vector<std::vector<uint8_t>> announce_blocks_q_;
    mutable std::mutex announce_tx_mu_;
    std::vector<std::vector<uint8_t>> announce_tx_q_;
    std::unordered_set<std::string> seen_txids_;
    std::unordered_map<std::string, std::vector<uint8_t>> tx_store_;
    std::deque<std::string> tx_order_;

    Mempool* mempool_{nullptr};
    Chain& chain_;

    // Telemetry callbacks (notify main.cpp when blocks/txs received from network)
    BlockCallback block_callback_;
    TxidsCallback txids_callback_;

    std::thread th_;
    std::atomic<bool> running_{false};
#ifdef _WIN32
    Sock srv_{INVALID_SOCKET};
#else
    Sock srv_{-1};
#endif
    std::unordered_map<Sock, PeerState> peers_; // keyed by Sock everywhere
    std::unordered_set<std::string> banned_;
    std::string datadir_{"./miqdata"};

    // address manager: IPv4s in network byte order
    std::unordered_set<uint32_t> addrv4_;

    // orphan manager
    std::unordered_map<std::string, OrphanRec> orphans_;
    std::unordered_map<std::string, std::vector<std::string>> orphan_children_;
    std::deque<std::string> orphan_order_;
    size_t orphan_bytes_{0};
    size_t orphan_bytes_limit_{0};
    size_t orphan_count_limit_{0};

    // inbound rate gating
    int64_t  inbound_win_start_ms_{0};
    uint32_t inbound_accepts_in_window_{0};

    // timed bans + whitelist + feature gates
    std::unordered_map<std::string,int64_t> timed_bans_; // ip -> expiry_ms
    int64_t  default_ban_ms_{MIQ_P2P_BAN_MS};
    uint32_t min_peer_version_{0};
    uint64_t required_features_mask_{0};
    int64_t  msg_deadline_ms_{MIQ_P2P_MSG_DEADLINE_MS};

    struct Cidr { uint32_t net; uint8_t bits; };
    std::unordered_set<std::string> whitelist_ips_;
    std::vector<Cidr>               whitelist_cidrs_;

    // per-family pacing config
    struct FamilyRate { double per_sec; double burst; };
    std::unordered_map<std::string, FamilyRate> rate_cfg_{
        {"get",  {20.0,  40.0}},
        {"inv",  {100.0, 200.0}},
        {"addr", {1.0,   2.0}},
    };

    InflightCaps caps_{};

    mutable std::shared_mutex peers_rwlock_;  // Read-write lock for peer access

    // core
    void loop();
    void handle_new_peer(Sock c, const std::string& ip);
    void load_bans();
    void save_bans();
        void bump_ban(PeerState& ps, const std::string& ip, const char* reason, int64_t now_ms);

    // sync & block serving
    void start_sync_with_peer(PeerState& ps);
    void request_block_index(PeerState& ps, uint64_t index);
    void fill_index_pipeline(PeerState& ps);
    void request_block_hash(PeerState& ps, const std::vector<uint8_t>& h);
    void handle_incoming_block(Sock sock, const std::vector<uint8_t>& raw);

    // rate-limit helpers
    void rate_refill(PeerState& ps, int64_t now);
    bool rate_consume_block(PeerState& ps, size_t nbytes);
    bool rate_consume_tx(PeerState& ps, size_t nbytes);

    // addr handling
    void maybe_send_getaddr(PeerState& ps);
    void send_addr_snapshot(PeerState& ps);
    void handle_addr_msg(PeerState& ps, const std::vector<uint8_t>& payload);

    // IPv4 helpers
    bool parse_ipv4(const std::string& dotted, uint32_t& be_ip);
    bool ipv4_is_public(uint32_t be_ip);

    // orphan handlers
    void evict_orphans_if_needed();
    void remove_orphan_by_hex(const std::string& child_hex);
    void try_connect_orphans(const std::string& parent_hex);

    size_t count_connections_by_type(ConnectionType type) const;
    size_t count_connections_from_ip(const std::string& ip) const;
    size_t count_connections_from_subnet(const std::string& ip) const;
    
    // Network diversity
    uint32_t get_network_group(const std::string& ip) const;
    size_t count_connections_from_group(uint32_t group) const;
    
    // Eviction logic
    void evict_peers_if_needed();
    double calculate_eviction_score(const PeerState& ps, int64_t now_ms) const;
    void maybe_evict_peer(Sock sock, const std::string& reason);
    
    // Connection attempts tracking
    std::unordered_map<std::string, ConnectionAttempt> recent_attempts_;
    std::unordered_map<std::string, int64_t> connection_backoff_;
    bool should_attempt_connection(const std::string& ip, int64_t now_ms);
    void record_connection_attempt(const std::string& ip, bool success, int64_t now_ms);
    int64_t calculate_backoff_time(const std::string& ip) const;
    
    // Network group tracking
    std::unordered_map<uint32_t, NetGroup> network_groups_;
    
    // Resource limits enforcement
    bool enforce_peer_buffer_limit(PeerState& ps);
    bool enforce_global_buffer_limit();
    
    // Peer rotation
    int64_t last_rotation_ms_{0};
    std::vector<Sock> select_rotation_candidates();
    
    // Connection statistics
    mutable std::atomic<size_t> total_bytes_sent_{0};
    mutable std::atomic<size_t> total_bytes_received_{0};
    mutable std::atomic<size_t> total_connections_accepted_{0};
    mutable std::atomic<size_t> total_connections_rejected_{0};
    
    // Manual connections tracking
    std::unordered_set<std::string> manual_connections_;

    // ================== Inline helpers required by p2p.cpp ===================

    inline bool is_ip_banned(const std::string& ip, int64_t now_ms) const {
        if (is_loopback(ip) || is_whitelisted_ip(ip)) return false;
        auto it = timed_bans_.find(ip);
        if (it != timed_bans_.end()) {
            if (it->second > now_ms) return true;
        }
        return banned_.count(ip) != 0;
    }

    inline bool is_loopback(const std::string& ip) const {
        return ip.rfind("127.", 0) == 0;
    }

    inline bool is_whitelisted_ip(const std::string& ip) const {
        if (whitelist_ips_.count(ip)) return true;
        sockaddr_in tmp{};
    #ifdef _WIN32
        if (InetPtonA(AF_INET, ip.c_str(), &tmp.sin_addr) != 1) return false;
    #else
        if (inet_pton(AF_INET, ip.c_str(), &tmp.sin_addr) != 1) return false;
    #endif
        uint32_t host_ip = ntohl(tmp.sin_addr.s_addr);
        for (const auto& c : whitelist_cidrs_) {
            if (c.bits == 0) return true;
            uint32_t mask = (c.bits==0) ? 0u : (~uint32_t(0) << (32 - c.bits));
            if ((host_ip & mask) == (c.net & mask)) return true;
        }
        return false;
    }

    inline bool unsolicited_drop(PeerState& ps, const char* kind, const std::string& key) {
        if (!kind) return false;
        if (ps.whitelisted) return false;

        if (std::string(kind) == "tx") {
            // CRITICAL FIX: Do NOT drop unsolicited transactions!
            // Wallets send transactions directly via "tx" message without the
            // inv/gettx request-response cycle. Dropping these breaks wallet functionality.
            // Rate limiting (rate_consume_tx) already provides DoS protection.
            // Mempool validation will reject invalid transactions.
            return false;  // Never drop transactions - let mempool validate them
        }
        if (std::string(kind) == "block") {
            if (!key.empty() && ps.inflight_blocks.count(key)) return false;
            if (!key.empty() && ps.recent_inv_keys.count(key)) return false;
            return true;
        }
        if (std::string(kind) == "headers") {
            return ps.inflight_hdr_batches == 0 && !ps.sent_getheaders;
        }
        return false;
    }

    inline bool can_accept_hdr_batch(const PeerState& ps, int64_t now_ms) const {
        if (ps.inflight_hdr_batches >= 2) return false;
        if (now_ms - ps.last_hdr_batch_done_ms < MIQ_P2P_HDR_BATCH_SPACING_MS) return false;
        return true;
    }
};

}
