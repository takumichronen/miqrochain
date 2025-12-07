// src/rpc.cpp
#include "hd_wallet.h"
#include "wallet_store.h"
#include "rpc.h"
#include "p2p.h"           // P2P::broadcast_inv_tx for transaction propagation
#include "sha256.h"
#include "ibd_monitor.h"
#include "constants.h"
#include "util.h"
#include "hex.h"
#include "serialize.h"
#include "tx.h"
#include "log.h"
#include "crypto/ecdsa_iface.h"
#include "base58check.h"
#include "hash160.h"
#include "utxo.h"          // UTXOEntry & list_for_pkh
#include "difficulty.h"    // MIQ_RETARGET_INTERVAL & epoch_next_bits
#include "txindex.h"       // Fast transaction lookup by txid

#include <sstream>
#include <array>
#include <string_view>
#include <map>
#include <exception>
#include <chrono>
#include <algorithm>
#include <tuple>
#include <cmath>
#include <cctype>   // std::isxdigit
#include <string>
#include <vector>
#include <cstring>  // std::memset
#include <cstdlib>  // std::getenv, setenv
#include <iomanip>  // std::setw, std::setfill
#include <ctime>    // time()

#include <fstream>
#include <random>
#include <cerrno>
#include <cstdio>   // std::snprintf
#include <cstdint>
#include <limits>

#ifndef _WIN32
  #include <sys/stat.h>
  #include <unistd.h>
#else
  // Prevent <windows.h> from defining min/max macros that break std::min/std::max
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <direct.h>
#endif

#ifndef MIN_RELAY_FEE_RATE
// miqron/KB (miqron per kilobyte)
static constexpr uint64_t MIN_RELAY_FEE_RATE = 1000;
#endif
#ifndef DUST_THRESHOLD
static constexpr uint64_t DUST_THRESHOLD = 1000; // 0.00001000 MIQ
#endif

// --- RPC request limits ---
static constexpr size_t RPC_MAX_BODY_BYTES = 512 * 1024; // 512 KiB

// --- External miner stats (updated via setminerstats RPC) ---
struct ExternalMinerStats {
    std::atomic<double> hps{0.0};
    std::atomic<uint64_t> hashes{0};
    std::atomic<uint64_t> accepted{0};
    std::atomic<uint64_t> rejected{0};
    std::atomic<unsigned> threads{0};
    std::atomic<bool> active{false};
    std::atomic<int64_t> last_update_ms{0};
    std::atomic<int64_t> start_time_ms{0};
};
static ExternalMinerStats g_ext_miner_stats;

// --- TUI miner stats (defined in main.cpp) ---
// We declare extern to update TUI display when external miner reports stats
struct MinerStats {
    std::atomic<bool> active{false};
    std::atomic<unsigned> threads{0};
    std::atomic<uint64_t> accepted{0};
    std::atomic<uint64_t> rejected{0};
    std::atomic<uint64_t> last_height_ok{0};
    std::atomic<uint64_t> last_height_rx{0};
    std::chrono::steady_clock::time_point start{};
    std::atomic<double>   hps{0.0};
};
extern MinerStats g_miner_stats;

static int64_t rpc_now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

namespace miq {

// ======== Cookie/static-token auth helpers (HTTP layer checks MIQ_RPC_TOKEN) ========

static std::string& rpc_cookie_token() {
    static std::string tok;
    return tok;
}
static std::string& rpc_cookie_path() {
    static std::string p;
    return p;
}

static std::string join_path(const std::string& a, const std::string& b){
#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    if(a.empty()) return b;
    if(a.back()==sep) return a+b;
    return a + sep + b;
}

static std::string dirname1(const std::string& p){
    size_t pos = p.find_last_of("/\\");
    if(pos == std::string::npos) return std::string();
    return p.substr(0, pos);
}

static std::string hex32_random() {
    std::array<uint8_t,32> buf{};
    std::random_device rd;
    for (auto &b : buf) b = static_cast<uint8_t>(rd());
    return to_hex(std::vector<uint8_t>(buf.begin(), buf.end()));
}

static bool file_exists(const std::string& p) {
    std::ifstream f(p, std::ios::in | std::ios::binary);
    return f.good();
}

static bool read_first_line_trim(const std::string& p, std::string& out) {
    std::ifstream f(p, std::ios::in | std::ios::binary);
    if(!f.good()) return false;
    std::string s;
    std::getline(f, s);
    // trim spaces and newlines
    while(!s.empty() && (s.back()=='\r' || s.back()=='\n' || s.back()==' ' || s.back()=='\t')) s.pop_back();
    out = s;
    return true;
}

static bool ensure_dir_exists_simple(const std::string& path){
    if(path.empty()) return false;
#ifndef _WIN32
    // mkdir returns 0 if created, -1 if exists or error
    if(::mkdir(path.c_str(), 0700) == 0) return true;
    if(errno == EEXIST) return true;
    return false;
#else
    if(_mkdir(path.c_str()) == 0) return true;
    if(errno == EEXIST) return true;
    return false;
#endif
}

static bool write_cookie_file_secure(const std::string& p, const std::string& tok) {
#ifndef _WIN32
    // best-effort: 0600
    umask(0077);
#endif
    // ensure parent exists
    auto parent = dirname1(p);
    if(!parent.empty()) ensure_dir_exists_simple(parent);

    std::ofstream f(p, std::ios::out | std::ios::trunc | std::ios::binary);
    if(!f.good()) return false;
    f << tok << "\n";
    f.flush();
#ifndef _WIN32
    ::chmod(p.c_str(), 0600);
#endif
    return f.good();
}

// Export token to HTTP layer (checked against Authorization/X-Auth-Token)
static void export_token_to_env(const std::string& tok){
#ifdef _WIN32
    _putenv_s("MIQ_RPC_TOKEN", tok.c_str());
#else
    setenv("MIQ_RPC_TOKEN", tok.c_str(), 1);
#endif
}

// Try to read a "static" token from (in order):
//  1) env MIQ_RPC_STATIC_TOKEN
//  2) <datadir>/.rpctoken (first line)
//  3) <datadir>/miq.conf with line: rpc_static_token=YOURTOKEN
static bool try_load_static_token(const std::string& datadir, std::string& out_tok){
    // 1) env
    if (const char* s = std::getenv("MIQ_RPC_STATIC_TOKEN"); s && *s) {
        out_tok.assign(s);
        return true;
    }
    // 2) .rpctoken (first line)
    {
        std::string rpct = join_path(datadir, ".rpctoken");
        std::string t;
        if (file_exists(rpct) && read_first_line_trim(rpct, t) && !t.empty()) {
            out_tok = t;
            return true;
        }
    }
    // 3) miq.conf key=value
    {
        std::string conf = join_path(datadir, "miq.conf");
        if (file_exists(conf)) {
            std::ifstream f(conf, std::ios::in | std::ios::binary);
            std::string line;
            while (std::getline(f, line)) {
                if(!line.empty() && line.back()=='\r') line.pop_back();
                // trim leading
                size_t i = 0; while (i<line.size() && (line[i]==' ' || line[i]=='\t')) ++i;
                if (i>=line.size() || line[i]=='#' || line[i]==';') continue;
                size_t eq = line.find('=', i);
                if (eq==std::string::npos) continue;
                std::string key = line.substr(i, eq-i);
                // rtrim key
                while(!key.empty() && (key.back()==' ' || key.back()=='\t')) key.pop_back();
                if (key != "rpc_static_token") continue;
                std::string val = line.substr(eq+1);
                // trim val
                size_t a=0,b=val.size();
                while (a<b && (val[a]==' '||val[a]=='\t')) ++a;
                while (b>a && (val[b-1]==' '||val[b-1]=='\t')) --b;
                val = val.substr(a,b-a);
                if (!val.empty()) { out_tok = val; return true; }
            }
        }
    }
    return false;
}

// Try to detect datadir for cookie:
// 1) MIQ_DATADIR
// 2) From wallet path: .../wallets/default  -> strip "/wallets"
// 3) Fallback: $HOME/.miqrochain or %APPDATA%\Miqrochain
static std::string detect_datadir_for_cookie(){
    if (const char* d = std::getenv("MIQ_DATADIR"); d && *d) {
        return std::string(d);
    }
    // derive from wallet folder if possible
    std::string wfile = default_wallet_file();
    if(!wfile.empty()){
        // default_wallet_file() typically points to ".../wallets/default/<file>"
        std::string wdir = dirname1(wfile);             // .../wallets/default
        if(!wdir.empty()){
            // strip trailing "/default"
            std::string parent = dirname1(wdir);        // .../wallets
            if(!parent.empty()){
                // strip "/wallets" to reach datadir
                size_t pos = parent.find_last_of("/\\");
                if(pos != std::string::npos){
                    std::string last = parent.substr(pos+1);
                    if(last == "wallets"){
                        return parent.substr(0, pos);
                    }
                }
            }
            // if not matching expected layout, use parent of parent as best-effort
            std::string maybe = dirname1(parent);
            if(!maybe.empty()) return maybe;
        }
    }
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    std::string base = appdata && *appdata ? std::string(appdata) : std::string(".");
    return join_path(base, "Miqrochain");
#else
    const char* home = std::getenv("HOME");
    std::string base = home && *home ? std::string(home) : std::string(".");
    return join_path(base, ".miqrochain");
#endif
}

void rpc_enable_auth_cookie(const std::string& datadir) {
    std::string tok;
    bool have_static = try_load_static_token(datadir, tok);

    std::string cookiep = join_path(datadir, ".cookie");
    rpc_cookie_path() = cookiep;

    if (!have_static) {
        // No static token — load cookie or create a random one
        if (file_exists(cookiep)) {
            if (read_first_line_trim(cookiep, tok) && !tok.empty()) {
                rpc_cookie_token() = tok;
                export_token_to_env(tok);
                log_info("RPC auth cookie loaded from " + cookiep);
                return;
            } else {
                log_warn("RPC cookie file exists but unreadable/empty; recreating: " + cookiep);
            }
        }
        tok = hex32_random();
        if (!write_cookie_file_secure(cookiep, tok)) {
            log_error("Failed to write RPC cookie file at " + cookiep + " (errno=" + std::to_string(errno) + ")");
            // Fallback: still enable with in-memory token (not persisted).
            rpc_cookie_token() = tok;
            export_token_to_env(tok);
            return;
        }
        rpc_cookie_token() = tok;
        export_token_to_env(tok);
        log_info("RPC auth cookie created at " + cookiep + " (600 perms).");
        return;
    }

    // Static token chosen. Export + also mirror into .cookie for compatibility.
    rpc_cookie_token() = tok;
    export_token_to_env(tok);
    if (!write_cookie_file_secure(cookiep, tok)) {
        log_warn("Static token active, but failed to mirror to " + cookiep);
    }
    log_info("RPC static token enabled (env/.rpctoken/miq.conf).");
}

// ==============================================================================

// Produce an error-shaped JSON (kept consistent with prior code)
static std::string err(const std::string& m){
    miq::JNode n;
    std::map<std::string,miq::JNode> o;
    miq::JNode e; e.v = std::string(m);
    o["error"] = e;
    n.v = o;
    return json_dump(n);
}

// CRITICAL FIX: Wrap successful responses in {"result":...} format
// This ensures wallet clients can properly parse responses
static std::string ok(const miq::JNode& value){
    miq::JNode n;
    std::map<std::string,miq::JNode> o;
    o["result"] = value;
    n.v = o;
    return json_dump(n);
}

// Convenience overloads for common types
static std::string ok_str(const std::string& s){
    miq::JNode v; v.v = s;
    return ok(v);
}

static std::string ok_num(double d){
    miq::JNode v; v.v = d;
    return ok(v);
}

[[maybe_unused]] static std::string ok_bool(bool b){
    miq::JNode v; v.v = b;
    return ok(v);
}

static std::string ok_arr(const std::vector<miq::JNode>& arr){
    miq::JNode v; v.v = arr;
    return ok(v);
}

static std::string ok_obj(const std::map<std::string, miq::JNode>& obj){
    miq::JNode v; v.v = obj;
    return ok(v);
}

// Local difficulty helper (same formula as Chain::work_from_bits, but public here)
[[maybe_unused]] static double difficulty_from_bits(uint32_t bits){
    uint32_t exp  = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if (mant == 0) return 0.0;

    uint32_t bexp  = GENESIS_BITS >> 24;
    uint32_t bmant = GENESIS_BITS & 0x007fffff;

    long double target      = (long double)mant  * std::pow(256.0L, (long double)((int)exp - 3));
    long double base_target = (long double)bmant * std::pow(256.0L, (long double)((int)bexp - 3));
    if (target <= 0.0L) return 0.0;

    long double difficulty = base_target / target;
    if (difficulty < 0.0L) difficulty = 0.0L;
    return (double)difficulty; // cast to double for JNode
}

static bool is_hex(const std::string& s){
    if(s.empty()) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c){ return std::isxdigit(c)!=0; });
}

static uint64_t parse_amount_str(const std::string& s){
    // Accept "1.23" (MIQ) or "123456" (miqron)
    if(s.find('.')!=std::string::npos){
        long double v = std::stold(s);
        long double sat = v * (long double)COIN;
        if(sat < 0) throw std::runtime_error("negative");
        return (uint64_t) std::llround(sat);
    } else {
        unsigned long long x = std::stoull(s);
        return (uint64_t)x;
    }
}

static size_t estimate_size_bytes(size_t nin, size_t nout){
    // Conservative: ~148/vin + ~34/vout + 10
    return nin*148 + nout*34 + 10;
}

[[maybe_unused]] static uint64_t min_fee_for_size(size_t sz_bytes){
    const uint64_t rate = MIN_RELAY_FEE_RATE; // miqron/kB
    uint64_t kb = (uint64_t)((sz_bytes + 999) / 1000);
    if(kb==0) kb=1;
    return kb * rate;
}

// ---- Wallet passphrase cache (RAM only) ------------------------------------
namespace {
    static std::string g_cached_pass;
    static int64_t     g_pass_expires_ms = 0;

    static inline int64_t now_ms_rpc() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
    }
    static inline bool wallet_is_unlocked() {
        return !g_cached_pass.empty() && now_ms_rpc() < g_pass_expires_ms;
    }
    static inline void wallet_lock_cached() {
        g_cached_pass.clear();
        g_pass_expires_ms = 0;
    }
    static inline void wallet_unlock_cache_for(const std::string& pass, uint64_t seconds) {
        g_cached_pass = pass;
        g_pass_expires_ms = now_ms_rpc() + (int64_t)seconds * 1000;
    }
    static inline std::string get_wallet_pass_or_cached() {
        const char* envp = std::getenv("MIQ_WALLET_PASSPHRASE");
        if (envp && *envp) return std::string(envp);
        if (wallet_is_unlocked()) return g_cached_pass;
        return std::string();
    }
}

void RpcService::start(uint16_t port){
    // Ensure an auth token is available for the HTTP layer *without* clobbering
    // an existing one that main() may have already configured.
    const char* env_tok = std::getenv("MIQ_RPC_TOKEN");
    std::string tok = (env_tok && *env_tok) ? std::string(env_tok) : std::string();

    // Preferred cookie location for external tools (wallet/CLI/miner)
    std::string ddir = detect_datadir_for_cookie();
    if (ddir.empty()) {
#ifdef _WIN32
        ddir = ".";
#else
        ddir = ".";
#endif
    }
    ensure_dir_exists_simple(ddir);
    const std::string cookiep = join_path(ddir, ".cookie");

    if (tok.empty()) {
        // No token set yet — create a cookie+token at the standard location.
        rpc_enable_auth_cookie(ddir);
    } else {
        // A token is already active (set by main or environment). Mirror it into
        // the standard cookie path so external clients can pick it up.
        write_cookie_file_secure(cookiep, tok);
    }

    // Start HTTP server; Authorization/X-Auth-Token is validated there.
    http_.start(
        port,
        [this](const std::string& b,
               const std::vector<std::pair<std::string,std::string>>& /*headers*/) {
            try {
                return this->handle(b);
            } catch (const std::exception& ex) {
                log_error(std::string("rpc exception: ") + ex.what());
                return err("internal error");
            } catch (...) {
                log_error("rpc exception: unknown");
                return err("internal error");
            }
        }
    );
}
void RpcService::stop(){ http_.stop(); }

// simple uptime base
static std::chrono::steady_clock::time_point& rpc_start_time(){
    static auto t0 = std::chrono::steady_clock::now();
    return t0;
}

static JNode jbool(bool v){ JNode n; n.v = v; return n; }
static JNode jnum(double v){ JNode n; n.v = v; return n; }
static JNode jstr(const std::string& s){ JNode n; n.v = s; return n; }

std::string RpcService::handle(const std::string& body){
    // Request-size guard
    if (body.size() > RPC_MAX_BODY_BYTES) {
        return err("request too large");
    }

    try {
        JNode req;
        if(!json_parse(body, req)) return err("bad json");
        if(!std::holds_alternative<std::map<std::string,JNode>>(req.v)) return err("bad json obj");
        auto& obj = std::get<std::map<std::string,JNode>>(req.v);

        // ---- Header-based auth happens in http.cpp. No JSON "auth" required. ----

        auto it = obj.find("method");
        if(it==obj.end() || !std::holds_alternative<std::string>(it->second.v)) return err("missing method");
        std::string method = std::get<std::string>(it->second.v);

        std::vector<JNode> params;
        auto ip = obj.find("params");
        if(ip!=obj.end() && std::holds_alternative<std::vector<JNode>>(ip->second.v))
            params = std::get<std::vector<JNode>>(ip->second.v);

        // ---------------- basic/info ----------------
        if(method=="help"){
            static const char* k[] = {
                "help","version","ping","uptime",
                "getnetworkinfo","getblockchaininfo","getblockcount","getbestblockhash",
                "getblock","getblockhash","getcoinbaserecipient",
                "getrawmempool","getmempoolinfo","gettxout","getrawtransaction",
                "validateaddress","decodeaddress","decoderawtx",
                "getminerstats","sendrawtransaction","sendtoaddress","canceltx",
                "estimatemediantime","getdifficulty","getchaintips",
                "getpeerinfo","getconnectioncount","getnetworkinfo","listbanned","setban","disconnectnode",
                "createhdwallet","restorehdwallet","walletinfo","getnewaddress","deriveaddressat",
                "walletunlock","walletlock","getwalletinfo","listaddresses","listutxos",
                "sendfromhd","getaddressutxos","getbalance","getwallethistory",
                "getblocktemplate","getminertemplate", // Mining pool support
                "submitblock","submitrawblock","sendrawblock",
                // Blockchain Explorer API
                "getaddresstxids","getaddresshistory","getaddressbalance","getaddressdeltas",
                "getaddressindexinfo","reindexaddresses"
                // (getibdinfo exists but not listed here to keep help stable)
            };
            std::vector<JNode> v;
            for(const char* s: k){ v.push_back(jstr(s)); }
            JNode out; out.v = v; return json_dump(out);
        }

        // --- getbalance ---
        if (method == "getbalance") {
            // Load wallet
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }
            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

            miq::HdWallet w(seed, meta);

            // BIP44 gap limit - scan beyond recorded next index to find externally-used addresses
            constexpr uint32_t GAP_LIMIT = 20;

            // Collect PKHs - scan from index 0 up to next index PLUS gap limit
            // This ensures we find funds even if addresses were used externally (e.g., by miner)
            auto collect_pkh_for_range = [&](bool change, uint32_t n, std::vector<std::array<uint8_t,20>>& out){
                // Scan from 0 to n + GAP_LIMIT to discover any externally-used addresses
                uint32_t scan_limit = n + GAP_LIMIT;
                for (uint32_t i = 0; i <= scan_limit; i++){
                    std::vector<uint8_t> priv, pub;
                    if (!w.DerivePrivPub(meta.account, change?1u:0u, i, priv, pub)) continue;
                    auto h = hash160(pub);
                    if (h.size()!=20) continue;
                    std::array<uint8_t,20> p{}; std::copy(h.begin(), h.end(), p.begin());
                    out.push_back(p);
                }
            };
            std::vector<std::array<uint8_t,20>> pkhs;
            collect_pkh_for_range(false, meta.next_recv, pkhs);
            collect_pkh_for_range(true,  meta.next_change, pkhs);

            uint64_t sum = 0;
            for (const auto& pkh : pkhs){
                auto lst = chain_.utxo().list_for_pkh(std::vector<uint8_t>(pkh.begin(), pkh.end()));
                for (const auto& t : lst){
                    const auto& e2 = std::get<2>(t);
                    sum += e2.value;
                }
            }

            std::map<std::string,JNode> o;
            o["miqron"] = jnum((double)sum);
            // string MIQ for pretty print
            std::ostringstream s; s << (sum/COIN) << "." << std::setw(8) << std::setfill('0') << (sum%COIN);
            o["miq"] = jstr(s.str());

            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="version"){
            JNode n; n.v = std::string("miqrochain-rpc/1.0.0");
            return json_dump(n);
        }

        if(method=="ping"){
            return "\"pong\"";
        }

        if(method=="uptime"){
            using clock = std::chrono::steady_clock;
            auto secs = std::chrono::duration<double>(clock::now() - rpc_start_time()).count();
            return json_dump(jnum(secs));
        }

        if(method=="getnetworkinfo"){
            std::map<std::string,JNode> o;
            JNode n;  n.v = std::string(CHAIN_NAME);                 o["chain"] = n;
            JNode b;  b.v = (double)RPC_PORT;                        o["rpcport"] = b;
            JNode be; be.v = std::string(crypto::ECDSA::backend());  o["crypto_backend"] = be;
            JNode r;  r.v = o; return json_dump(r);
        }

        if(method=="getblockchaininfo"){
            auto tip = chain_.tip();
            std::map<std::string,JNode> o;
            JNode a; a.v = std::string(CHAIN_NAME);              o["chain"] = a;
            JNode h; h.v = (double)tip.height;                   o["height"] = h;
            JNode b; b.v = (double)tip.height;                   o["blocks"] = b;  // alias for height
            JNode hh; hh.v = to_hex(tip.hash);                   o["bestblockhash"] = hh;
            JNode d; d.v = (double)Chain::work_from_bits_public(tip.bits); o["difficulty"] = d;
            return ok_obj(o);
        }

        // --- IBD snapshot ---
        if(method=="getibdinfo"){
            auto s = miq::get_ibd_info_snapshot();
            std::map<std::string,JNode> o;
            o["ibd_active"]                = jbool(s.ibd_active);
            o["best_block_height"]         = jnum((double)s.best_block_height);
            o["est_best_header_height"]    = jnum((double)s.est_best_header_height);
            o["headers_ahead"]             = jnum((double)s.headers_ahead);
            o["peers"]                     = jnum((double)s.peers);
            o["phase"]                     = jstr(s.phase);
            o["started_ms"]                = jnum((double)s.started_ms);
            o["last_update_ms"]            = jnum((double)s.last_update_ms);
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="getblockcount"){
            return ok_num((double)chain_.tip().height);
        }

        if(method=="getbestblockhash"){
            return ok_str(to_hex(chain_.tip().hash));
        }

        if(method=="getblockhash"){
            if(params.size()<1 || !std::holds_alternative<double>(params[0].v))
                return err("need height");
            size_t idx = (size_t)std::get<double>(params[0].v);
            Block b; if(!chain_.get_block_by_index(idx, b)) return err("not found");
            JNode n; n.v = std::string(to_hex(b.block_hash()));
            return json_dump(n);
        }

        // getblock(height or hex_hash) -> {hash,time,txs,hex}
        if(method=="getblock"){
            if(params.size()<1) return err("need index_or_hash");

            Block b;
            bool ok = false;

            if(std::holds_alternative<double>(params[0].v)){
                size_t idx = (size_t)std::get<double>(params[0].v);
                ok = chain_.get_block_by_index(idx, b);
            } else if(std::holds_alternative<std::string>(params[0].v)){
                const std::string hstr = std::get<std::string>(params[0].v);
                if(!is_hex(hstr)) return err("bad hash hex");
                std::vector<uint8_t> want;
                try { want = from_hex(hstr); } catch(...) { return err("bad hash hex"); }

                // OPTIMIZATION: Use hash index for O(1) lookup instead of O(n) scan
                ok = chain_.get_block_by_hash_fast(want, b);
            } else {
                return err("bad arg");
            }

            if(!ok) return err("not found");

            std::map<std::string,JNode> o;
            JNode h;   h.v  = std::string(to_hex(b.block_hash())); o["hash"] = h;
            JNode t;   t.v  = (double)b.header.time;               o["time"] = t;
            JNode nt;  nt.v = (double)b.txs.size();                o["txs"]  = nt;
            JNode raw; raw.v = std::string(to_hex(ser_block(b)));  o["hex"]  = raw;

            JNode out; out.v = o; return json_dump(out);
        }

        // who gets the coinbase vout0?
        if(method=="getcoinbaserecipient"){
            if(params.size()<1) return err("need index_or_hash");

            Block b;
            bool ok = false;

            if(std::holds_alternative<double>(params[0].v)){
                size_t idx = (size_t)std::get<double>(params[0].v);
                ok = chain_.get_block_by_index(idx, b);
            } else if(std::holds_alternative<std::string>(params[0].v)){
                const std::string hstr = std::get<std::string>(params[0].v);
                if(!is_hex(hstr)) return err("bad hash hex");
                std::vector<uint8_t> want;
                try { want = from_hex(hstr); } catch(...) { return err("bad hash hex"); }

                auto tip = chain_.tip();
                for(size_t i=0;i<= (size_t)tip.height;i++){
                    Block tb;
                    if(chain_.get_block_by_index(i, tb)){
                        if(tb.block_hash() == want){ b = tb; ok = true; break; }
                    }
                }
            } else {
                return err("bad arg");
            }

            if(!ok) return err("not found");
            if(b.txs.empty()) return err("no transactions in block");
            const Transaction& cb = b.txs[0];
            if(cb.vout.empty()) return err("coinbase has no outputs");
            const TxOut& o0 = cb.vout[0];

            std::map<std::string,JNode> o;
            JNode val; val.v = (double)o0.value;            o["value"] = val;   // in miqron
            JNode pk ; pk.v  = std::string(to_hex(o0.pkh)); o["pkh"]   = pk;
            // Include full coinbase txid for downstream scripts
            JNode tx ; tx.v  = std::string(to_hex(cb.txid())); o["txid"] = tx;

            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="gettipinfo"){
            auto tip = chain_.tip();
            std::map<std::string,JNode> o;
            o["height"] = jnum((double)tip.height);
            // Harden: canonical hex bits + numeric mirror
            char bhex[9]; std::snprintf(bhex, sizeof(bhex), "%08x", tip.bits);
            o["bits"]     = jstr(std::string(bhex));   // canonical
            o["bits_u32"] = jnum((double)tip.bits);    // mirror (legacy)
            o["time"]     = jnum((double)tip.time);
            o["hash"]     = jstr(to_hex(tip.hash));
            JNode out; out.v = o; return json_dump(out);
        }

        // ---------- BIP22 GETBLOCKTEMPLATE (for pool mining) ----------
        if (method == "getblocktemplate") {
            // BIP22 compliant getblocktemplate implementation
            auto tip = chain_.tip();

            // Parse optional params for capabilities/mode
            [[maybe_unused]] bool longpoll = false;
            std::string mode = "template";
            if (!params.empty() && std::holds_alternative<std::map<std::string, JNode>>(params[0].v)) {
                auto& p = std::get<std::map<std::string, JNode>>(params[0].v);
                if (p.count("mode") && std::holds_alternative<std::string>(p.at("mode").v)) {
                    mode = std::get<std::string>(p.at("mode").v);
                }
                if (p.count("longpollid") && std::holds_alternative<std::string>(p.at("longpollid").v)) {
                    longpoll = true;
                }
            }

            // Handle submit mode
            if (mode == "submit") {
                return err("use submitblock RPC for block submission");
            }

            // Compute the next block's bits (retarget-aware)
            uint32_t next_bits = tip.bits;
            try {
                auto last = chain_.last_headers(MIQ_RETARGET_INTERVAL);
                next_bits = miq::epoch_next_bits(
                    last,
                    BLOCK_TIME_SECS,
                    GENESIS_BITS,
                    tip.height + 1,
                    MIQ_RETARGET_INTERVAL
                );
            } catch(const std::exception& e) {
                // PRODUCTION FIX: Log difficulty calculation errors (uses fallback)
                log_error(std::string("getblocktemplate: epoch_next_bits failed: ") + e.what());
            } catch(...) {
                log_error("getblocktemplate: epoch_next_bits failed with unknown error");
            }

            // Compute MTP for mintime
            int64_t mtp = tip.time;
            try {
                auto hdrs = chain_.last_headers(11);
                if (!hdrs.empty()) {
                    std::vector<int64_t> ts; ts.reserve(hdrs.size());
                    for (auto& p : hdrs) ts.push_back(p.first);
                    std::sort(ts.begin(), ts.end());
                    mtp = ts[ts.size()/2];
                }
            } catch(const std::exception& e) {
                // PRODUCTION FIX: Log MTP calculation errors (uses fallback)
                log_error(std::string("getblocktemplate: MTP calculation failed: ") + e.what());
            } catch(...) {
                log_error("getblocktemplate: MTP calculation failed with unknown error");
            }
            const int64_t mintime = mtp + 1;
            const int64_t curtime = std::max<int64_t>(static_cast<int64_t>(time(nullptr)), mintime);

            // Build coinbase value (subsidy + fees)
            uint64_t subsidy = INITIAL_SUBSIDY;
            uint64_t halvings = (tip.height + 1) / HALVING_INTERVAL;
            if (halvings < 64) subsidy = INITIAL_SUBSIDY >> halvings;
            else subsidy = 0;

            // FIX: Collect mempool transactions using SIZE limit instead of COUNT limit
            // Previously used collect(5000) which limited by count, missing profitable txs
            // Now uses collect_for_block with proper size limit (MAX_BLOCK_SIZE - coinbase overhead)
            // Reserve ~1KB for coinbase transaction
            static constexpr size_t COINBASE_RESERVED_SIZE = 1024;
            static constexpr size_t BLOCK_TX_SIZE_LIMIT = MAX_BLOCK_SIZE - COINBASE_RESERVED_SIZE;
            std::vector<Transaction> txs_vec;
            mempool_.collect_for_block(txs_vec, BLOCK_TX_SIZE_LIMIT);
            std::vector<JNode> tx_arr;
            uint64_t total_fees = 0;

            for (const auto& tx : txs_vec) {
                auto raw = ser_tx(tx);
                uint32_t vsize = (uint32_t)raw.size();
                uint64_t in_sum = 0, out_sum = 0;

                // Calculate fee
                for (const auto& in : tx.vin) {
                    UTXOEntry e;
                    if (chain_.utxo().get(in.prev.txid, in.prev.vout, e)) {
                        in_sum += e.value;
                    }
                }
                for (const auto& o : tx.vout) out_sum += o.value;
                uint64_t fee = (in_sum > out_sum) ? (in_sum - out_sum) : 0;
                total_fees += fee;

                // BIP22 transaction format
                std::map<std::string, JNode> txobj;
                txobj["data"] = jstr(to_hex(raw));
                txobj["txid"] = jstr(to_hex(tx.txid()));
                txobj["hash"] = jstr(to_hex(tx.txid())); // No segwit, same as txid
                txobj["fee"] = jnum((double)fee);
                txobj["sigops"] = jnum((double)(tx.vin.size())); // Simplified
                txobj["weight"] = jnum((double)(vsize * 4)); // No segwit

                // Dependencies
                std::vector<JNode> deps;
                JNode dd; dd.v = deps;
                txobj["depends"] = dd;

                JNode txnode; txnode.v = txobj;
                tx_arr.push_back(txnode);
            }

            // Build target from bits (big-endian for BIP22)
            uint8_t target_be[32]; std::memset(target_be, 0, 32);
            {
                const uint32_t exp  = next_bits >> 24;
                const uint32_t mant = next_bits & 0x007fffff;
                if (mant) {
                    if (exp <= 3) {
                        uint32_t mant2 = mant >> (8 * (3 - exp));
                        target_be[29] = uint8_t((mant2 >> 16) & 0xff);
                        target_be[30] = uint8_t((mant2 >>  8) & 0xff);
                        target_be[31] = uint8_t((mant2 >>  0) & 0xff);
                    } else {
                        int pos = int(32) - int(exp);
                        if (pos < 0) { target_be[0]=target_be[1]=target_be[2]=0xff; }
                        else {
                            if (pos > 29) pos = 29;
                            target_be[pos+0] = uint8_t((mant >> 16) & 0xff);
                            target_be[pos+1] = uint8_t((mant >>  8) & 0xff);
                            target_be[pos+2] = uint8_t((mant >>  0) & 0xff);
                        }
                    }
                }
            }

            // Build BIP22 response
            std::map<std::string, JNode> result;
            result["version"] = jnum(1.0);
            result["previousblockhash"] = jstr(to_hex(tip.hash));

            // Transactions array
            JNode txs_node; txs_node.v = tx_arr;
            result["transactions"] = txs_node;

            // Coinbase-related
            result["coinbasevalue"] = jnum((double)(subsidy + total_fees));

            // Target & bits
            result["target"] = jstr(to_hex(std::vector<uint8_t>(target_be, target_be+32)));
            char bits_hex[9]; std::snprintf(bits_hex, sizeof(bits_hex), "%08x", next_bits);
            result["bits"] = jstr(std::string(bits_hex));

            // Times
            result["curtime"] = jnum((double)curtime);
            result["mintime"] = jnum((double)mintime);

            // Mutable fields (BIP22)
            std::vector<JNode> mutable_arr;
            mutable_arr.push_back(jstr("time"));
            mutable_arr.push_back(jstr("transactions"));
            mutable_arr.push_back(jstr("prevblock"));
            JNode mut_node; mut_node.v = mutable_arr;
            result["mutable"] = mut_node;

            // Other BIP22 fields
            result["height"] = jnum((double)(tip.height + 1));
            result["sigoplimit"] = jnum(80000.0);
            result["sizelimit"] = jnum((double)(4 * 1024 * 1024));
            result["weightlimit"] = jnum((double)(4 * 1024 * 1024 * 4));

            // Longpoll ID (tip hash for change detection)
            result["longpollid"] = jstr(to_hex(tip.hash) + std::to_string(tip.height));

            // Capabilities
            std::vector<JNode> caps;
            caps.push_back(jstr("proposal"));
            caps.push_back(jstr("longpoll"));
            JNode caps_node; caps_node.v = caps;
            result["capabilities"] = caps_node;

            JNode out; out.v = result;
            return json_dump(out);
        }

        // ---------- MINER TEMPLATE (for external miners) ----------
        if (method == "getminertemplate") {
            // Return a compact template: prev hash, bits (NEXT block's bits), time, height,
            // coinbase_pkh (recommended pkh to receive fees), and a transaction list.
            // Transactions are presented as raw hex with fee and dependency hints.
            auto tip = chain_.tip();

            // Choose coinbase receiver: for now we don't have a node-owned address
            // so just return zeros; miners MUST override.
            std::vector<uint8_t> pkh(20, 0);

            // FIX: Collect mempool txs using SIZE limit instead of COUNT limit
            // Previously used collect(5000) which limited by count, missing profitable txs
            // Now uses collect_for_block with proper size limit (MAX_BLOCK_SIZE - coinbase overhead)
            static constexpr size_t COINBASE_RESERVED_SIZE = 1024;
            static constexpr size_t BLOCK_TX_SIZE_LIMIT = MAX_BLOCK_SIZE - COINBASE_RESERVED_SIZE;
            std::vector<Transaction> txs_vec;
            mempool_.collect_for_block(txs_vec, BLOCK_TX_SIZE_LIMIT);
            log_info("getminertemplate: mempool size=" + std::to_string(mempool_.size()) +
                     ", orphan pool size=" + std::to_string(mempool_.orphan_count()) +
                     ", collected " + std::to_string(txs_vec.size()) + " txs for template (size-limited to " +
                     std::to_string(BLOCK_TX_SIZE_LIMIT) + " bytes)");

            // DIAGNOSTIC: If no transactions and mempool is empty, log the state
            if (txs_vec.empty() && mempool_.size() == 0) {
                log_info("getminertemplate: empty mempool - no pending transactions");
            }
            std::vector<JNode> arr;

            // CRITICAL FIX: Preserve topological order from collect_for_block!
            // collect_for_block returns transactions in parent-first order (parents before children)
            // This order MUST be preserved so chained transactions can be validated in the same block.
            // Previously we used std::map which sorted by txid, destroying the correct order.

            // Build JSON array directly in correct order from txs_vec
            for (const auto& tx : txs_vec) {
                auto raw = ser_tx(tx);
                uint32_t vsize = (uint32_t)raw.size();
                uint64_t in_sum = 0, out_sum = 0;
                std::string txid_hex = to_hex(tx.txid());
                std::vector<std::string> depends;

                // Calculate fee and track dependencies
                for (const auto& in : tx.vin) {
                    bool found = false;
                    // First check if parent is in mempool (for chained transactions)
                    Transaction parent_tx;
                    if (mempool_.get_transaction(in.prev.txid, parent_tx)) {
                        if (in.prev.vout < parent_tx.vout.size()) {
                            in_sum += parent_tx.vout[in.prev.vout].value;
                            // dependency edge (in-mempool parent)
                            depends.push_back(to_hex(in.prev.txid));
                            found = true;
                        }
                    }
                    // Fallback to UTXO set
                    if (!found) {
                        UTXOEntry e;
                        if (chain_.utxo().get(in.prev.txid, in.prev.vout, e)) {
                            in_sum += e.value;
                        }
                    }
                }
                for (const auto& o : tx.vout) out_sum += o.value;
                uint64_t fee = (in_sum > out_sum) ? (in_sum - out_sum) : 0;

                // Build JSON object for this transaction
                std::map<std::string, JNode> o;
                o["txid"]   = jstr(txid_hex);
                o["fee"]    = jnum((double)fee);
                o["vsize"]  = jnum((double)vsize);
                o["hex"]    = jstr(to_hex(raw));
                // depends[] array
                std::vector<JNode> d;
                for (const auto& dep : depends) d.push_back(jstr(dep));
                JNode dd; dd.v = d;
                o["depends"] = dd;
                JNode x; x.v = o;
                arr.push_back(x);  // Preserves order from txs_vec!
            }

            // CRITICAL DEBUG: Log the exact order being sent to miner
            if (txs_vec.size() > 1) {
                std::string order_log = "getminertemplate TX ORDER sent to miner: ";
                for (size_t i = 0; i < txs_vec.size(); ++i) {
                    std::string txid_short = to_hex(txs_vec[i].txid()).substr(0, 8);
                    order_log += "[" + std::to_string(i) + "]=" + txid_short + " ";
                }
                log_info(order_log);
            }

            // Compute the *next block's* bits (retarget-aware).
            uint32_t next_bits = tip.bits;
            try {
                auto last = chain_.last_headers(MIQ_RETARGET_INTERVAL);
                next_bits = miq::epoch_next_bits(
                    last,
                    BLOCK_TIME_SECS,
                    GENESIS_BITS,
                    /*next_height=*/ tip.height + 1,
                    /*interval=*/ MIQ_RETARGET_INTERVAL
                );
            } catch(const std::exception& e) {
                // PRODUCTION FIX: Log difficulty calculation errors (uses fallback)
                log_error(std::string("getminertemplate: epoch_next_bits failed: ") + e.what());
            } catch(...) {
                log_error("getminertemplate: epoch_next_bits failed with unknown error");
            }

            // --- NEW: compute MTP (median of last 11 header times) and expose mintime ---
            int64_t mtp = tip.time;
            try {
                auto hdrs = chain_.last_headers(11);
                if (!hdrs.empty()) {
                    std::vector<int64_t> ts; ts.reserve(hdrs.size());
                    for (auto& p : hdrs) ts.push_back(p.first);
                    std::sort(ts.begin(), ts.end());
                    mtp = ts[ts.size()/2];
                }
            } catch(const std::exception& e) {
                // PRODUCTION FIX: Log MTP calculation errors (uses fallback)
                log_error(std::string("getminertemplate: MTP calculation failed: ") + e.what());
            } catch(...) {
                log_error("getminertemplate: MTP calculation failed with unknown error");
            }
            const int64_t mintime = mtp + 1;

            std::map<std::string, JNode> o;
            o["version"]        = jnum(1.0);
            o["prev_hash"]      = jstr(to_hex(tip.hash));

            // Harden: canonical hex bits + numeric mirrors for both next and tip bits
            char nb[9], tb[9];
            std::snprintf(nb, sizeof(nb), "%08x", next_bits);
            std::snprintf(tb, sizeof(tb), "%08x", tip.bits);
            o["bits"]           = jstr(std::string(nb));           // canonical for miners
            o["bits_u32"]       = jnum((double)next_bits);         // mirror (legacy)
            o["tip_bits"]       = jstr(std::string(tb));           // diagnostics (canonical)
            o["tip_bits_u32"]   = jnum((double)tip.bits);          // diagnostics mirror

            o["mintime"]        = jnum((double)mintime);           // *** enforce time >= mintime ***
            o["time"]           = jnum((double)std::max<int64_t>(static_cast<int64_t>(time(nullptr)), mintime));
            o["height"]         = jnum((double)(tip.height + 1));
            o["coinbase_pkh"]   = jstr(to_hex(pkh));
            o["max_block_bytes"]= jnum((double)(900 * 1024)); // HINT for miners

            // Big-endian target preview for the *next* block's bits
            uint8_t target_be[32]; std::memset(target_be, 0, 32);
            {
                const uint32_t exp  = next_bits >> 24;
                const uint32_t mant = next_bits & 0x007fffff;
                if (mant) {
                    if (exp <= 3) {
                        uint32_t mant2 = mant >> (8 * (3 - exp));
                        target_be[29] = uint8_t((mant2 >> 16) & 0xff);
                        target_be[30] = uint8_t((mant2 >>  8) & 0xff);
                        target_be[31] = uint8_t((mant2 >>  0) & 0xff);
                    } else {
                        int pos = int(32) - int(exp);
                        if (pos < 0) { target_be[0]=target_be[1]=target_be[2]=0xff; }
                        else {
                            if (pos > 29) pos = 29;
                            target_be[pos+0] = uint8_t((mant >> 16) & 0xff);
                            target_be[pos+1] = uint8_t((mant >>  8) & 0xff);
                            target_be[pos+2] = uint8_t((mant >>  0) & 0xff);
                        }
                    }
                }
            }
            o["target_be_hex"] = jstr(to_hex(std::vector<uint8_t>(target_be, target_be+32)));

            // txs array
            JNode A; A.v = arr; o["txs"] = A;

            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="decodeaddress"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need address");
            uint8_t ver=0; std::vector<uint8_t> payload;
            if(!base58check_decode(std::get<std::string>(params[0].v), ver, payload))
                return err("bad address");
            std::map<std::string,JNode> o;
            JNode v; v.v = (double)ver;               o["version"]     = v;
            JNode p; p.v = (double)payload.size();    o["payload_size"]= p;
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="validateaddress"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need address");
            uint8_t ver=0; std::vector<uint8_t> payload;
            bool ok2 = base58check_decode(std::get<std::string>(params[0].v), ver, payload);
            std::map<std::string,JNode> o;
            o["isvalid"] = jbool(ok2 && ver==VERSION_P2PKH && payload.size()==20);
            o["version"] = jnum((double)ver);
            if(ok2 && payload.size()==20){ o["pkh"] = jstr(to_hex(payload)); }
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="decoderawtx"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need txhex");
            std::vector<uint8_t> raw;
            try { raw = from_hex(std::get<std::string>(params[0].v)); }
            catch(...) { return err("bad txhex"); }
            Transaction tx;
            if(!deser_tx(raw, tx)) return err("bad tx");
            std::map<std::string,JNode> o;
            o["txid"] = jstr(to_hex(tx.txid()));
            o["size"] = jnum((double)raw.size());
            // vin
            {
                std::vector<JNode> arr;
                for(const auto& in: tx.vin){
                    std::map<std::string,JNode> i;
                    i["prev_txid"] = jstr(to_hex(in.prev.txid));
                    i["vout"]      = jnum((double)in.prev.vout);
                    i["pubkey"]    = jstr(to_hex(in.pubkey));
                    i["siglen"]    = jnum((double)in.sig.size());
                    JNode n; n.v = i; arr.push_back(n);
                }
                JNode n; n.v = arr; o["vin"] = n;
            }
            // vout
            {
                std::vector<JNode> arr;
                for(const auto& out: tx.vout){
                    std::map<std::string,JNode> v;
                    v["value"] = jnum((double)out.value);
                    v["pkh"]   = jstr(to_hex(out.pkh));
                    JNode n; n.v = v; arr.push_back(n);
                }
                JNode n; n.v = arr; o["vout"] = n;
            }
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="getrawmempool"){
            auto ids = mempool_.txids();
            std::vector<JNode> v;
            for(auto& id: ids){ JNode s; s.v = std::string(to_hex(id)); v.push_back(s); }
            // CRITICAL FIX: Wrap in {"result":...} format
            return ok_arr(v);
        }

        // DIAGNOSTIC: Get mempool statistics including orphan info
        if(method=="getmempoolinfo"){
            auto stats = mempool_.get_stats();
            std::map<std::string, JNode> o;
            o["size"] = jnum((double)stats.tx_count);
            o["bytes"] = jnum((double)stats.bytes_used);
            o["orphan_count"] = jnum((double)stats.orphan_count);
            o["orphan_bytes"] = jnum((double)stats.orphan_bytes);
            o["min_fee_rate"] = jnum(stats.min_fee_rate);
            o["max_fee_rate"] = jnum(stats.max_fee_rate);
            o["avg_fee_rate"] = jnum(stats.avg_fee_rate);
            o["total_fees"] = jnum((double)stats.total_fees);
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="gettxout"){
            if(params.size()<2) return err("need txid & vout");
            if(!std::holds_alternative<std::string>(params[0].v)) return err("need txid");
            if(!std::holds_alternative<double>(params[1].v))      return err("need vout");

            const std::string txidhex = std::get<std::string>(params[0].v);
            uint32_t vout = (uint32_t)std::get<double>(params[1].v);

            std::vector<uint8_t> txid;
            try { txid = from_hex(txidhex); }
            catch(...) { return err("bad txid"); }

            UTXOEntry e;
            if(chain_.utxo().get(txid, vout, e)){
                std::map<std::string,JNode> o;
                JNode val; val.v = (double)e.value;  o["value"]    = val;
                JNode cb;  cb.v  = e.coinbase;       o["coinbase"] = cb;
                JNode n;   n.v   = o; return json_dump(n);
            } else {
                return "null";
            }
        }

        // getrawtransaction - look up transaction by txid
        // CRITICAL FIX: Now uses TxIndex for O(1) lookup of confirmed transactions
        if(method=="getrawtransaction"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need txid");
            const std::string txidhex = std::get<std::string>(params[0].v);

            std::vector<uint8_t> txid;
            try { txid = from_hex(txidhex); }
            catch(...) { return err("bad txid"); }

            // Check mempool first
            Transaction tx;
            if(mempool_.get_transaction(txid, tx)){
                // Serialize the transaction
                std::vector<uint8_t> raw = ser_tx(tx);
                std::map<std::string,JNode> o;
                o["hex"] = jstr(to_hex(raw));
                o["txid"] = jstr(txidhex);
                o["in_mempool"] = jbool(true);
                o["confirmed"] = jbool(false);
                o["confirmations"] = jnum(0);
                JNode n; n.v = o; return json_dump(n);
            }

            // CRITICAL FIX: Use TxIndex for O(1) lookup of confirmed transactions
            TxLocation loc;
            if (chain_.txindex().get(txid, loc) && loc.valid) {
                Block blk;
                if (chain_.get_block_by_index(loc.block_height, blk)) {
                    if (loc.tx_position < blk.txs.size()) {
                        const auto& btx = blk.txs[loc.tx_position];
                        std::vector<uint8_t> raw = ser_tx(btx);
                        auto tip = chain_.tip();
                        std::map<std::string,JNode> o;
                        o["hex"] = jstr(to_hex(raw));
                        o["txid"] = jstr(txidhex);
                        o["in_mempool"] = jbool(false);
                        o["confirmed"] = jbool(true);
                        o["confirmations"] = jnum((double)(tip.height - loc.block_height + 1));
                        o["block_height"] = jnum((double)loc.block_height);
                        o["block_hash"] = jstr(to_hex(blk.block_hash()));
                        JNode n; n.v = o; return json_dump(n);
                    }
                }
            }

            // Fallback: check if any outputs exist in UTXO set (for backwards compatibility)
            for(uint32_t vout = 0; vout < 100; ++vout) {
                UTXOEntry e;
                if(chain_.utxo().get(txid, vout, e)){
                    // Transaction exists in chain (has unspent outputs)
                    std::map<std::string,JNode> o;
                    o["txid"] = jstr(txidhex);
                    o["confirmed"] = jbool(true);
                    JNode n; n.v = o; return json_dump(n);
                }
            }

            return err("Transaction not found");
        }

        // gettransactioninfo - Get comprehensive transaction details including block info
        // v12.0: Returns full tx details with inputs, outputs, block height, difficulty, block hash
        if(method=="gettransactioninfo"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need txid");
            const std::string txidhex = std::get<std::string>(params[0].v);

            std::vector<uint8_t> txid;
            try { txid = from_hex(txidhex); }
            catch(...) { return err("bad txid"); }

            std::map<std::string,JNode> result;
            result["txid"] = jstr(txidhex);

            // Check mempool first
            Transaction tx;
            bool in_mempool = mempool_.get_transaction(txid, tx);
            if(in_mempool){
                result["confirmed"] = jbool(false);
                result["in_mempool"] = jbool(true);
                result["confirmations"] = jnum(0);

                // Serialize tx for hex
                std::vector<uint8_t> raw = ser_tx(tx);
                result["hex"] = jstr(to_hex(raw));
                result["size"] = jnum((double)raw.size());

                // Inputs
                std::vector<JNode> inputs;
                uint64_t total_input = 0;
                for(size_t i = 0; i < tx.vin.size(); ++i){
                    std::map<std::string,JNode> inp;
                    inp["index"] = jnum((double)i);
                    inp["prev_txid"] = jstr(to_hex(tx.vin[i].prev.txid));
                    inp["prev_vout"] = jnum((double)tx.vin[i].prev.vout);
                    // Try to get value from UTXO set
                    UTXOEntry prev_e;
                    if(chain_.utxo().get(tx.vin[i].prev.txid, tx.vin[i].prev.vout, prev_e)){
                        inp["value"] = jnum((double)prev_e.value);
                        inp["address"] = jstr(base58check_encode(VERSION_P2PKH, prev_e.pkh));
                        total_input += prev_e.value;
                    }
                    JNode n; n.v = inp; inputs.push_back(n);
                }
                JNode vin; vin.v = inputs; result["vin"] = vin;
                result["total_input"] = jnum((double)total_input);

                // Outputs
                std::vector<JNode> outputs;
                uint64_t total_output = 0;
                for(size_t i = 0; i < tx.vout.size(); ++i){
                    std::map<std::string,JNode> out;
                    out["index"] = jnum((double)i);
                    out["value"] = jnum((double)tx.vout[i].value);
                    out["address"] = jstr(base58check_encode(VERSION_P2PKH, tx.vout[i].pkh));
                    total_output += tx.vout[i].value;
                    JNode n; n.v = out; outputs.push_back(n);
                }
                JNode vout; vout.v = outputs; result["vout"] = vout;
                result["total_output"] = jnum((double)total_output);

                // Fee
                if(total_input > 0){
                    uint64_t fee = (total_input > total_output) ? (total_input - total_output) : 0;
                    result["fee"] = jnum((double)fee);
                    if(raw.size() > 0){
                        result["fee_rate"] = jnum((double)fee / (double)raw.size());
                    }
                }

                JNode out; out.v = result; return json_dump(out);
            }

            // CRITICAL FIX: Use TxIndex for O(1) transaction lookup instead of scanning blocks
            // This makes transaction lookups instant instead of scanning up to 10,000 blocks
            auto tip = chain_.tip();
            TxLocation loc;
            bool found_in_index = chain_.txindex().get(txid, loc);

            // If not in index, fall back to block scanning (for backwards compatibility during index build)
            uint64_t found_height = 0;
            size_t found_tx_idx = 0;
            Block found_blk;
            bool found_in_chain = false;

            if (found_in_index && loc.valid) {
                // Fast path: use TxIndex result
                if (chain_.get_block_by_index(loc.block_height, found_blk)) {
                    if (loc.tx_position < found_blk.txs.size()) {
                        const auto& btx = found_blk.txs[loc.tx_position];
                        if (btx.txid() == txid) {
                            found_in_chain = true;
                            found_height = loc.block_height;
                            found_tx_idx = loc.tx_position;
                        }
                    }
                }
            }

            // Fallback: scan recent blocks if not found in index (during initial index build)
            if (!found_in_chain) {
                uint64_t scan_start = (tip.height > 10000) ? (tip.height - 10000) : 0;
                for(uint64_t h = tip.height; h >= scan_start && h <= tip.height; --h){
                    Block blk;
                    if(!chain_.get_block_by_index(h, blk)) continue;

                    for(size_t tx_idx = 0; tx_idx < blk.txs.size(); ++tx_idx){
                        const auto& btx = blk.txs[tx_idx];
                        if(btx.txid() == txid){
                            found_in_chain = true;
                            found_height = h;
                            found_tx_idx = tx_idx;
                            found_blk = blk;
                            break;
                        }
                    }
                    if (found_in_chain) break;
                    if(h == 0) break;
                }
            }

            if (found_in_chain) {
                const auto& btx = found_blk.txs[found_tx_idx];

                // Found the transaction!
                result["confirmed"] = jbool(true);
                result["in_mempool"] = jbool(false);
                result["confirmations"] = jnum((double)(tip.height - found_height + 1));

                // Block info
                result["block_height"] = jnum((double)found_height);
                result["block_hash"] = jstr(to_hex(found_blk.block_hash()));
                result["block_time"] = jnum((double)found_blk.header.time);
                result["block_bits"] = jnum((double)found_blk.header.bits);

                // Calculate difficulty from bits
                uint32_t bits = found_blk.header.bits;
                double difficulty = 1.0;
                if(bits > 0){
                    uint32_t exp = (bits >> 24) & 0xFF;
                    uint32_t mant = bits & 0x00FFFFFF;
                    if(mant > 0){
                        double target = (double)mant * pow(256.0, (double)(exp - 3));
                        if(target > 0){
                            difficulty = (double)0xFFFF * pow(2.0, 208.0) / target;
                        }
                    }
                }
                result["difficulty"] = jnum(difficulty);

                result["tx_index"] = jnum((double)found_tx_idx);
                result["is_coinbase"] = jbool(found_tx_idx == 0);

                // Serialize tx
                std::vector<uint8_t> raw = ser_tx(btx);
                result["hex"] = jstr(to_hex(raw));
                result["size"] = jnum((double)raw.size());

                // Inputs - CRITICAL FIX: Look up value/address from parent transactions
                std::vector<JNode> inputs;
                uint64_t total_input = 0;
                bool is_coinbase = (found_tx_idx == 0);
                for(size_t i = 0; i < btx.vin.size(); ++i){
                    std::map<std::string,JNode> inp;
                    inp["index"] = jnum((double)i);
                    if(is_coinbase){
                        inp["coinbase"] = jbool(true);
                        inp["coinbase_data"] = jstr(to_hex(btx.vin[i].sig));
                    } else {
                        inp["prev_txid"] = jstr(to_hex(btx.vin[i].prev.txid));
                        inp["prev_vout"] = jnum((double)btx.vin[i].prev.vout);

                        // CRITICAL FIX: Look up the parent transaction to get value and address
                        // First try TxIndex for O(1) lookup
                        TxLocation parent_loc;
                        if (chain_.txindex().get(btx.vin[i].prev.txid, parent_loc) && parent_loc.valid) {
                            Block parent_blk;
                            if (chain_.get_block_by_index(parent_loc.block_height, parent_blk)) {
                                if (parent_loc.tx_position < parent_blk.txs.size()) {
                                    const auto& parent_tx = parent_blk.txs[parent_loc.tx_position];
                                    if (btx.vin[i].prev.vout < parent_tx.vout.size()) {
                                        const auto& spent_out = parent_tx.vout[btx.vin[i].prev.vout];
                                        inp["value"] = jnum((double)spent_out.value);
                                        inp["address"] = jstr(base58check_encode(VERSION_P2PKH, spent_out.pkh));
                                        total_input += spent_out.value;
                                    }
                                }
                            }
                        }
                    }
                    JNode n; n.v = inp; inputs.push_back(n);
                }
                JNode vin; vin.v = inputs; result["vin"] = vin;
                result["total_input"] = jnum((double)total_input);

                // Outputs
                std::vector<JNode> outputs;
                uint64_t total_output = 0;
                for(size_t i = 0; i < btx.vout.size(); ++i){
                    std::map<std::string,JNode> out;
                    out["index"] = jnum((double)i);
                    out["value"] = jnum((double)btx.vout[i].value);
                    out["address"] = jstr(base58check_encode(VERSION_P2PKH, btx.vout[i].pkh));
                    // Check if output is spent
                    UTXOEntry e;
                    out["spent"] = jbool(!chain_.utxo().get(txid, (uint32_t)i, e));
                    total_output += btx.vout[i].value;
                    JNode n; n.v = out; outputs.push_back(n);
                }
                JNode vout; vout.v = outputs; result["vout"] = vout;
                result["total_output"] = jnum((double)total_output);

                // Fee (for non-coinbase) - CRITICAL FIX: Also calculate fee_rate
                if(!is_coinbase && total_input > total_output){
                    uint64_t fee = total_input - total_output;
                    result["fee"] = jnum((double)fee);
                    if(raw.size() > 0){
                        result["fee_rate"] = jnum((double)fee / (double)raw.size());
                    }
                }

                JNode out; out.v = result; return json_dump(out);
            }

            return err("Transaction not found");
        }

        if(method=="sendrawtransaction"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need txhex");
            const std::string h = std::get<std::string>(params[0].v);

            std::vector<uint8_t> raw;
            try { raw = from_hex(h); }
            catch(...) { return err("bad txhex"); }

            Transaction tx;
            if(!deser_tx(raw, tx)) return err("bad tx");

            auto tip = chain_.tip(); std::string e;

            // CRITICAL FIX: Check if this transaction conflicts with any existing mempool tx
            // If so, try RBF (Replace-By-Fee) path instead of regular accept
            bool has_conflict = false;
            for (const auto& in : tx.vin) {
                if (mempool_.has_spent_input(in.prev.txid, in.prev.vout)) {
                    has_conflict = true;
                    break;
                }
            }

            bool accepted = false;
            std::string txid_hex = to_hex(tx.txid());
            log_info("sendrawtransaction: attempting to accept tx " + txid_hex.substr(0, 16) + "...");

            if (has_conflict) {
                // Try RBF - accept_replacement validates fee bump rules
                log_info("sendrawtransaction: tx has conflict, trying RBF path");
                accepted = mempool_.accept_replacement(tx, chain_.utxo(), static_cast<uint32_t>(tip.height), e);
            } else {
                // Normal accept path for non-conflicting transactions
                accepted = mempool_.accept(tx, chain_.utxo(), static_cast<uint32_t>(tip.height), e);
            }

            if(accepted){
                log_info("sendrawtransaction: tx " + txid_hex.substr(0, 16) + "... ACCEPTED into mempool (size=" + std::to_string(mempool_.size()) + ")");
                // CRITICAL FIX: Broadcast transaction to P2P network
                // Without this, transactions only sit in local mempool and never propagate!
                if(p2p_) {
                    std::vector<uint8_t> txid = tx.txid();
                    // CRITICAL FIX: Store raw tx so we can serve it when peers request via gettx
                    // Without this, peers receive invtx, send gettx, but we have nothing to serve!
                    p2p_->store_tx_for_relay(txid, raw);
                    p2p_->broadcast_inv_tx(txid);
                    // CRITICAL FIX: Notify telemetry so TUI shows the transaction in "Recent TXIDs"
                    p2p_->notify_local_tx(txid);
                }
                // CRITICAL FIX: Return properly formatted {"result":"txid"} response
                return ok_str(to_hex(tx.txid()));
            } else {
                log_warn("sendrawtransaction: tx " + txid_hex.substr(0, 16) + "... REJECTED: " + e);
                return err(e);
            }
        }

        // ------------- canceltx: Cancel a pending transaction from mempool -------------
        // This allows users to cancel stuck transactions that exceed limits or have issues
        // The funds will be released back to the wallet's spendable balance
        if (method == "canceltx") {
            if (params.size() < 1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need txid");

            const std::string txid_hex = std::get<std::string>(params[0].v);

            // Validate hex
            if (txid_hex.length() != 64 || !is_hex(txid_hex))
                return err("invalid txid (must be 64 hex characters)");

            std::vector<uint8_t> txid;
            try { txid = from_hex(txid_hex); }
            catch (...) { return err("invalid txid hex"); }

            // Verify the transaction is in mempool and belongs to our wallet
            Transaction tx;
            if (!mempool_.get_transaction(txid, tx)) {
                return err("transaction not found in mempool (may already be confirmed or never existed)");
            }

            // Optional: Verify ownership (check if inputs are from our wallet)
            // For now, we allow canceling any mempool transaction the user knows the txid of
            // This is a security consideration - in production you might want to verify ownership

            std::string cancel_err;
            if (!mempool_.remove_transaction(txid, cancel_err)) {
                return err(cancel_err);
            }

            log_info("canceltx: Successfully canceled transaction " + txid_hex.substr(0, 16) + "...");

            // Return success with details
            std::map<std::string, JNode> result;
            result["success"] = jbool(true);
            result["txid"] = jstr(txid_hex);
            result["message"] = jstr("Transaction canceled and removed from mempool. Funds released to wallet.");

            return ok_obj(result);
        }

        // ------------- NEW: submitblock / submitrawblock / sendrawblock -------------
        if (method=="submitblock" || method=="submitrawblock" || method=="sendrawblock") {
            if (params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("submitblock: need hex string");

            const std::string h = std::get<std::string>(params[0].v);
            std::vector<uint8_t> raw;
            try { raw = from_hex(h); }
            catch(...) { return err("submitblock: bad hex"); }

            Block b;
            if(!deser_block(raw, b)) return err("submitblock: cannot deserialize block");

            std::string e;
            if(!chain_.submit_block(b, e)){
                return err(std::string("submitblock: rejected: ")+e);
            }

            // CRITICAL FIX: Notify mempool to remove confirmed transactions
            mempool_.on_block_connect(b);

            // CRITICAL FIX: Notify TUI about the new locally-mined block
            // This ensures Recent Blocks and Recent TXIDs update for local mining
            if(p2p_) {
                uint64_t block_height = chain_.tip().height;

                // Calculate subsidy for this block height
                uint64_t subsidy = INITIAL_SUBSIDY;
                uint64_t halvings = block_height / HALVING_INTERVAL;
                if (halvings < 64) subsidy = INITIAL_SUBSIDY >> halvings;
                else subsidy = 0;

                // Extract miner address from coinbase if available
                std::string miner_addr;
                if (!b.txs.empty() && !b.txs[0].vout.empty()) {
                    // Try to get base58 address from coinbase output
                    const auto& pkh = b.txs[0].vout[0].pkh;
                    if (pkh.size() == 20) {
                        miner_addr = base58check_encode(VERSION_P2PKH, pkh);
                    }
                }
                p2p_->notify_local_block(b, block_height, subsidy, miner_addr);
            }

            // Build a small success object
            std::map<std::string,JNode> o;
            o["accepted"] = jbool(true);
            o["hash"]     = jstr(to_hex(b.block_hash()));
            o["height"]   = jnum((double)chain_.tip().height);
            JNode out; out.v = o; return json_dump(out);
        }

        // Miner stats - returns external miner stats if active
        if(method=="getminerstats"){
            std::map<std::string,JNode> o;

            // Check if external miner is active (updated within last 30 seconds)
            int64_t now = rpc_now_ms();
            int64_t last_update = g_ext_miner_stats.last_update_ms.load();
            bool ext_active = g_ext_miner_stats.active.load() && (now - last_update < 30000);

            if (ext_active) {
                // Return external miner stats
                double hps = g_ext_miner_stats.hps.load();
                uint64_t hashes = g_ext_miner_stats.hashes.load();
                uint64_t accepted = g_ext_miner_stats.accepted.load();
                uint64_t rejected = g_ext_miner_stats.rejected.load();
                unsigned threads = g_ext_miner_stats.threads.load();
                int64_t start = g_ext_miner_stats.start_time_ms.load();
                double seconds = (now - start) / 1000.0;
                if (seconds < 0) seconds = 0;

                o["hps"] = jnum(hps);
                o["hashes"] = jnum((double)hashes);
                o["total"] = jnum((double)hashes);
                o["seconds"] = jnum(seconds);
                o["accepted"] = jnum((double)accepted);
                o["rejected"] = jnum((double)rejected);
                o["threads"] = jnum((double)threads);
                o["active"] = jbool(true);
            } else {
                // No active miner
                o["hps"] = jnum(0.0);
                o["hashes"] = jnum(0.0);
                o["total"] = jnum(0.0);
                o["seconds"] = jnum(0.0);
                o["active"] = jbool(false);
            }

            JNode out; out.v = o; return json_dump(out);
        }

        // Set miner stats - for external miner to report its stats
        if(method=="setminerstats"){
            // params: [hps, hashes, accepted, rejected, threads]
            double hps = 0.0;
            uint64_t hashes = 0, accepted = 0, rejected = 0;
            unsigned threads = 0;

            if (params.size() >= 1 && std::holds_alternative<double>(params[0].v))
                hps = std::get<double>(params[0].v);
            if (params.size() >= 2 && std::holds_alternative<double>(params[1].v))
                hashes = (uint64_t)std::get<double>(params[1].v);
            if (params.size() >= 3 && std::holds_alternative<double>(params[2].v))
                accepted = (uint64_t)std::get<double>(params[2].v);
            if (params.size() >= 4 && std::holds_alternative<double>(params[3].v))
                rejected = (uint64_t)std::get<double>(params[3].v);
            if (params.size() >= 5 && std::holds_alternative<double>(params[4].v))
                threads = (unsigned)std::get<double>(params[4].v);

            int64_t now = rpc_now_ms();

            // Initialize start time if first update
            if (!g_ext_miner_stats.active.load()) {
                g_ext_miner_stats.start_time_ms.store(now);
            }

            g_ext_miner_stats.hps.store(hps);
            g_ext_miner_stats.hashes.store(hashes);
            g_ext_miner_stats.accepted.store(accepted);
            g_ext_miner_stats.rejected.store(rejected);
            g_ext_miner_stats.threads.store(threads);
            g_ext_miner_stats.active.store(true);
            g_ext_miner_stats.last_update_ms.store(now);

            // Also update TUI miner stats (g_miner_stats defined in main.cpp)
            if (!g_miner_stats.active.load()) {
                g_miner_stats.start = std::chrono::steady_clock::now();
            }
            g_miner_stats.hps.store(hps);
            g_miner_stats.accepted.store(accepted);
            g_miner_stats.rejected.store(rejected);
            g_miner_stats.threads.store(threads);
            g_miner_stats.active.store(true);

            return "{\"result\":\"ok\"}";
        }

        // ---------------- address UTXO lookup (for mobile/GUI) ----------------
        if (method == "getaddressutxos") {
            // Expect params = ["<Base58Check-P2PKH>"] or [["addr1", "addr2", ...]]
            auto itParams = obj.find("params");
            if (itParams == obj.end() ||
                !std::holds_alternative<std::vector<JNode>>(itParams->second.v))
                return err("usage: getaddressutxos <address> or getaddressutxos [addr1, addr2, ...]");

            auto& ps = std::get<std::vector<JNode>>(itParams->second.v);
            if (ps.empty())
                return err("usage: getaddressutxos <address> or getaddressutxos [addr1, addr2, ...]");

            // v12.0: Support batch address queries for faster wallet sync
            // Accept either single address string or array of addresses
            std::vector<std::string> addresses;

            if (std::holds_alternative<std::string>(ps[0].v)) {
                // Single address (legacy mode)
                addresses.push_back(std::get<std::string>(ps[0].v));
            } else if (std::holds_alternative<std::vector<JNode>>(ps[0].v)) {
                // Array of addresses (batch mode)
                auto& addr_arr = std::get<std::vector<JNode>>(ps[0].v);
                addresses.reserve(addr_arr.size());
                for (const auto& node : addr_arr) {
                    if (std::holds_alternative<std::string>(node.v)) {
                        addresses.push_back(std::get<std::string>(node.v));
                    }
                }
            } else {
                return err("usage: getaddressutxos <address> or getaddressutxos [addr1, addr2, ...]");
            }

            // Build array of UTXOs from all addresses
            std::vector<JNode> arr;
            arr.reserve(addresses.size() * 10);  // Pre-allocate for efficiency

            for (const auto& addr : addresses) {
                // Decode address
                uint8_t ver = 0; std::vector<uint8_t> payload;
                if (!base58check_decode(addr, ver, payload)) continue;  // Skip invalid
                if (ver != VERSION_P2PKH || payload.size() != 20) continue;

                // Query UTXO set
                auto entries = chain_.utxo().list_for_pkh(payload);

                for (const auto& t : entries) {
                    const auto& txid = std::get<0>(t);
                    uint32_t vout    = std::get<1>(t);
                    const auto& e    = std::get<2>(t);

                    std::map<std::string,JNode> o;
                    o["coinbase"] = jbool(e.coinbase);
                    o["height"]   = jnum((double)e.height);
                    o["txid"]  = jstr(to_hex(txid));
                    o["vout"]  = jnum((double)vout);
                    o["value"] = jnum((double)e.value);
                    o["pkh"]   = jstr(to_hex(e.pkh));
                    o["address"] = jstr(addr);  // Include source address for client convenience
                    JNode n; n.v = o; arr.push_back(n);
                }
            }
            // CRITICAL FIX: Wrap in {"result":...} format
            return ok_arr(arr);
        }

        // --- HD wallet RPCs ---

        // --- createhdwallet ---
        if (method == "createhdwallet") {
            auto get_opt = [&](size_t i)->std::string{
                return (params.size()>i && std::holds_alternative<std::string>(params[i].v))
                       ? std::get<std::string>(params[i].v) : std::string();
            };
            std::string mnemonic = get_opt(0);
            std::string mpass    = get_opt(1);
            std::string wpass    = get_opt(2);

            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }

            std::vector<uint8_t> seed(64);
            if(mnemonic.empty()){
                std::string outmn;
                if(!miq::HdWallet::GenerateMnemonic(128, outmn)) return err("mnemonic generation failed");
                mnemonic = outmn;
            }
            if(!miq::HdWallet::MnemonicToSeed(mnemonic, mpass, seed)) return err("mnemonic->seed failed");

            miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
            std::string e;
            if(!SaveHdWallet(wdir, seed, meta, wpass, e)) return err(e);

            std::map<std::string,JNode> o;
            o["mnemonic"]  = jstr(mnemonic);
            o["wallet_dir"]= jstr(wdir);
            JNode out; out.v = o; return json_dump(out);
        }

        // --- restorehdwallet ---
        if (method == "restorehdwallet") {
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v)) return err("mnemonic required");
            auto get_opt = [&](size_t i)->std::string{
                return (params.size()>i && std::holds_alternative<std::string>(params[i].v))
                       ? std::get<std::string>(params[i].v) : std::string();
            };
            std::string mnemonic = std::get<std::string>(params[0].v);
            std::string mpass    = get_opt(1);
            std::string wpass    = get_opt(2);

            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }

            std::vector<uint8_t> seed;
            if(!miq::HdWallet::MnemonicToSeed(mnemonic, mpass, seed)) return err("mnemonic->seed failed");

            // Scan for used addresses with BIP44 gap limit of 20
            miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
            miq::HdWallet w(seed, meta);

            constexpr uint32_t GAP_LIMIT = 20;
            constexpr uint32_t MAX_SCAN = 1000; // safety cap

            // Scan receive addresses (chain 0)
            uint32_t gap_recv = 0;
            for (uint32_t i = 0; i < MAX_SCAN && gap_recv < GAP_LIMIT; ++i) {
                std::vector<uint8_t> priv, pub;
                if (!w.DerivePrivPub(meta.account, 0, i, priv, pub)) break;
                auto pkh = hash160(pub);
                auto utxos = chain_.utxo().list_for_pkh(pkh);
                if (!utxos.empty()) {
                    meta.next_recv = i + 1;
                    gap_recv = 0;
                } else {
                    ++gap_recv;
                }
            }

            // Scan change addresses (chain 1)
            uint32_t gap_change = 0;
            for (uint32_t i = 0; i < MAX_SCAN && gap_change < GAP_LIMIT; ++i) {
                std::vector<uint8_t> priv, pub;
                if (!w.DerivePrivPub(meta.account, 1, i, priv, pub)) break;
                auto pkh = hash160(pub);
                auto utxos = chain_.utxo().list_for_pkh(pkh);
                if (!utxos.empty()) {
                    meta.next_change = i + 1;
                    gap_change = 0;
                } else {
                    ++gap_change;
                }
            }

            std::string e;
            if(!SaveHdWallet(wdir, seed, meta, wpass, e)) return err(e);

            std::map<std::string,JNode> o;
            o["status"] = jstr("ok");
            o["addresses_scanned_recv"] = jnum((double)(meta.next_recv + GAP_LIMIT));
            o["addresses_scanned_change"] = jnum((double)(meta.next_change + GAP_LIMIT));
            o["next_recv_index"] = jnum((double)meta.next_recv);
            o["next_change_index"] = jnum((double)meta.next_change);
            JNode out; out.v = o; return json_dump(out);
        }

        // --- scanaddresses (rescan wallet addresses for UTXOs) ---
        if (method == "scanaddresses") {
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }

            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

            miq::HdWallet w(seed, meta);

            constexpr uint32_t GAP_LIMIT = 20;
            constexpr uint32_t MAX_SCAN = 1000;

            uint32_t old_recv = meta.next_recv;
            uint32_t old_change = meta.next_change;

            // Scan receive addresses starting from current index
            uint32_t gap_recv = 0;
            for (uint32_t i = meta.next_recv; i < MAX_SCAN && gap_recv < GAP_LIMIT; ++i) {
                std::vector<uint8_t> priv, pub;
                if (!w.DerivePrivPub(meta.account, 0, i, priv, pub)) break;
                auto pkh = hash160(pub);
                auto utxos = chain_.utxo().list_for_pkh(pkh);
                if (!utxos.empty()) {
                    meta.next_recv = i + 1;
                    gap_recv = 0;
                } else {
                    ++gap_recv;
                }
            }

            // Scan change addresses
            uint32_t gap_change = 0;
            for (uint32_t i = meta.next_change; i < MAX_SCAN && gap_change < GAP_LIMIT; ++i) {
                std::vector<uint8_t> priv, pub;
                if (!w.DerivePrivPub(meta.account, 1, i, priv, pub)) break;
                auto pkh = hash160(pub);
                auto utxos = chain_.utxo().list_for_pkh(pkh);
                if (!utxos.empty()) {
                    meta.next_change = i + 1;
                    gap_change = 0;
                } else {
                    ++gap_change;
                }
            }

            // Save updated meta
            if (meta.next_recv != old_recv || meta.next_change != old_change) {
                if(!SaveHdWallet(wdir, seed, meta, pass, e)) return err(e);
            }

            std::map<std::string,JNode> o;
            o["next_recv_index"] = jnum((double)meta.next_recv);
            o["next_change_index"] = jnum((double)meta.next_change);
            o["new_recv_found"] = jnum((double)(meta.next_recv - old_recv));
            o["new_change_found"] = jnum((double)(meta.next_change - old_change));
            JNode out; out.v = o; return json_dump(out);
        }

        // --- walletinfo ---
        if (method == "walletinfo") {
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }

            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

            std::map<std::string,JNode> o;
            o["account"]     = jnum((double)meta.account);
            o["next_recv"]   = jnum((double)meta.next_recv);
            o["next_change"] = jnum((double)meta.next_change);
            JNode out; out.v = o; return json_dump(out);
        }

        // --- getnewaddress ---
        if (method == "getnewaddress") {
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }

            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

            miq::HdWallet w(seed, meta);
            std::string addr;
            if(!w.GetNewAddress(addr)) return err("derive failed");

            if(!SaveHdWallet(wdir, seed, w.meta(), pass, e)) return err(e);
            return json_dump(jstr(addr));
        }

        // --- deriveaddressat ---
        if (method == "deriveaddressat") {
            if(params.size()<1) return err("index required");
            uint32_t idx = 0;
            if (std::holds_alternative<double>(params[0].v)) {
                idx = (uint32_t)std::get<double>(params[0].v);
            } else if (std::holds_alternative<std::string>(params[0].v)) {
                try { idx = (uint32_t)std::stoul(std::get<std::string>(params[0].v)); }
                catch(...) { return err("bad index"); }
            } else {
                return err("bad index");
            }

            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }

            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

            miq::HdWallet w(seed, meta);
            std::string addr;
            if(!w.GetAddressAt(idx, addr)) return err("derive failed");
            return json_dump(jstr(addr));
        }

        // --- walletunlock (cache passphrase with timeout) ---
        if (method == "walletunlock") {
            if (params.size() < 1 || !std::holds_alternative<std::string>(params[0].v)) {
                return err("usage: walletunlock pass [timeout_sec]");
            }
            std::string pass = std::get<std::string>(params[0].v);
            if (pass.empty()) return err("empty passphrase refused");

            uint64_t timeout_s = 300;
            if (params.size() >= 2) {
                if (std::holds_alternative<double>(params[1].v)) {
                    // SECURITY FIX: Validate double before casting to uint64_t
                    double dval = std::get<double>(params[1].v);
                    if (dval < 0.0 || dval > 86400.0 * 365.0) return err("invalid timeout");
                    timeout_s = (uint64_t)dval;
                } else if (std::holds_alternative<std::string>(params[1].v)) {
                    try { timeout_s = (uint64_t)std::stoull(std::get<std::string>(params[1].v)); }
                    catch(...) { return err("bad timeout"); }
                }
                if (timeout_s == 0) return err("timeout must be >0");
            }

            // Validate passphrase by attempting to load
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }
            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            if (!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

            wallet_unlock_cache_for(pass, timeout_s);

            std::map<std::string,JNode> o;
            o["ok"]                = jbool(true);
            o["unlocked_until_ms"] = jnum((double)g_pass_expires_ms);
            JNode out; out.v = o; return json_dump(out);
        }

        // --- walletlock ---
        if (method == "walletlock") {
            wallet_lock_cached();
            return "\"ok\"";
        }

        // --- getwalletinfo (unlocked status + meta + balance + pending) ---
        if (method == "getwalletinfo") {
            std::map<std::string,JNode> o;
            o["unlocked"]          = jbool(wallet_is_unlocked());
            o["unlocked_until_ms"] = jnum((double)g_pass_expires_ms);

            // Time remaining
            int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            int unlock_left = (g_pass_expires_ms > now_ms) ? (int)((g_pass_expires_ms - now_ms) / 1000) : 0;
            o["unlock_seconds_left"] = jnum((double)unlock_left);
            o["locked"] = jbool(!wallet_is_unlocked());

            // Try to surface meta from disk using helper (env or cached pass)
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }
            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            std::string pass = get_wallet_pass_or_cached();
            if (LoadHdWallet(wdir, seed, meta, pass, e)) {
                o["next_recv"]   = jnum((double)meta.next_recv);
                o["next_change"] = jnum((double)meta.next_change);

                // Compute balance
                miq::HdWallet w(seed, meta);
                const uint64_t curH = chain_.tip().height;
                constexpr uint32_t GAP_LIMIT = 20;

                uint64_t confirmed_balance = 0;
                uint64_t pending_balance = 0;
                uint64_t immature_balance = 0;
                int pending_tx_count = 0;

                // Collect PKHs
                std::unordered_set<std::string> our_pkhs_hex;
                auto collect_pkhs = [&](uint32_t chain_idx, uint32_t max_idx) {
                    for (uint32_t i = 0; i <= max_idx + GAP_LIMIT; ++i) {
                        std::vector<uint8_t> priv, pub;
                        if (!w.DerivePrivPub(meta.account, chain_idx, i, priv, pub)) continue;
                        auto pkh = hash160(pub);
                        our_pkhs_hex.insert(to_hex(pkh));
                    }
                };
                collect_pkhs(0, meta.next_recv);
                collect_pkhs(1, meta.next_change);

                // Scan UTXOs for confirmed balance
                for (const auto& pkh_hex : our_pkhs_hex) {
                    auto pkh_vec = from_hex(pkh_hex);
                    auto lst = chain_.utxo().list_for_pkh(pkh_vec);
                    for (const auto& t : lst) {
                        const auto& txid = std::get<0>(t);
                        uint32_t vout = std::get<1>(t);
                        const auto& ue = std::get<2>(t);

                        // Skip if already spent in mempool
                        if (mempool_.has_spent_input(txid, vout)) {
                            continue;
                        }

                        // Check coinbase maturity
                        // CRITICAL FIX: Use <= to match mempool validation (mempool.cpp:135)
                        // Mempool rejects if: height + 1 <= coinbase_height + COINBASE_MATURITY
                        // Using < here would allow spending 1 block too early, causing tx rejection
                        if (ue.coinbase) {
                            uint64_t mature_h = ue.height + COINBASE_MATURITY;
                            if (curH + 1 <= mature_h) {
                                immature_balance += ue.value;
                                continue;
                            }
                        }

                        confirmed_balance += ue.value;
                    }
                }

                // Check mempool for pending transactions and balances
                std::unordered_set<std::string> counted_txids;
                {
                    std::vector<Transaction> mempool_txs;
                    mempool_.snapshot(mempool_txs);

                    for (const auto& tx : mempool_txs) {
                        bool involves_us = false;

                        // Check outputs (incoming pending)
                        for (size_t vout = 0; vout < tx.vout.size(); ++vout) {
                            const auto& out = tx.vout[vout];
                            if (out.pkh.size() == 20) {
                                std::string pkh_hex = to_hex(out.pkh);
                                if (our_pkhs_hex.count(pkh_hex)) {
                                    // Only count if not already spent in mempool
                                    auto txid = tx.txid();
                                    if (!mempool_.has_spent_input(txid, (uint32_t)vout)) {
                                        pending_balance += out.value;
                                    }
                                    involves_us = true;
                                }
                            }
                        }

                        // Check inputs (outgoing)
                        for (const auto& in : tx.vin) {
                            UTXOEntry spent_utxo;
                            if (chain_.utxo().get(in.prev.txid, in.prev.vout, spent_utxo)) {
                                std::string pkh_hex = to_hex(spent_utxo.pkh);
                                if (our_pkhs_hex.count(pkh_hex)) {
                                    involves_us = true;
                                }
                            }
                        }

                        if (involves_us) {
                            std::string txid_hex = to_hex(tx.txid());
                            if (!counted_txids.count(txid_hex)) {
                                counted_txids.insert(txid_hex);
                                pending_tx_count++;
                            }
                        }
                    }
                }

                uint64_t total_balance = confirmed_balance + pending_balance;

                // Format balance as MIQ string
                std::ostringstream bal_str;
                bal_str << (total_balance/COIN) << "." << std::setw(8) << std::setfill('0') << (total_balance%COIN);
                o["balance"] = jstr(bal_str.str());
                o["balance_miqron"] = jnum((double)total_balance);
                o["confirmed_balance"] = jnum((double)confirmed_balance);
                o["pending_balance"] = jnum((double)pending_balance);
                o["immature_balance"] = jnum((double)immature_balance);
                o["pending_tx_count"] = jnum((double)pending_tx_count);
            }
            JNode out; out.v = o; return json_dump(out);
        }

        // --- listaddresses [count?] ---
        if (method == "listaddresses") {
            int want = -1;
            if (params.size()>0) {
                if (std::holds_alternative<double>(params[0].v)) want = (int)std::get<double>(params[0].v);
                else if (std::holds_alternative<std::string>(params[0].v)) {
                    try { want = (int)std::stoul(std::get<std::string>(params[0].v)); } catch(...) { return err("bad count"); }
                }
            }

            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }

            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

            miq::HdWallet w(seed, meta);
            // Include at least address 0 plus all used addresses
            int n = (want>0) ? std::min<int>(want, (int)meta.next_recv + 1) : (int)meta.next_recv + 1;

            std::vector<JNode> arr;
            for (int i=0;i<n;i++){
                std::string addr;
                if (w.GetAddressAt((uint32_t)i, addr)) arr.push_back(jstr(addr));
            }
            JNode out; out.v = arr; return json_dump(out);
        }

        // --- listutxos (now includes spendability/maturity) ---
        if (method == "listutxos") {
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }

            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

            miq::HdWallet w(seed, meta);

            const uint64_t curH = chain_.tip().height;

            // BIP44 gap limit for discovering externally-used addresses
            constexpr uint32_t GAP_LIMIT = 20;

            // Scan from index 0 up to next index PLUS gap limit
            auto collect_pkh_for_range = [&](bool change, uint32_t n, std::vector<std::array<uint8_t,20>>& out){
                uint32_t scan_limit = n + GAP_LIMIT;
                for (uint32_t i = 0; i <= scan_limit; i++){
                    std::vector<uint8_t> priv, pub;
                    if (!w.DerivePrivPub(meta.account, change?1u:0u, i, priv, pub)) continue;
                    auto h = hash160(pub);
                    if (h.size()!=20) continue;
                    std::array<uint8_t,20> p{}; std::copy(h.begin(), h.end(), p.begin());
                    out.push_back(p);
                }
            };
            std::vector<std::array<uint8_t,20>> pkhs;
            collect_pkh_for_range(false, meta.next_recv, pkhs);
            collect_pkh_for_range(true,  meta.next_change, pkhs);

            std::vector<JNode> outarr;
            for (const auto& pkh : pkhs){
                auto lst = chain_.utxo().list_for_pkh(std::vector<uint8_t>(pkh.begin(), pkh.end()));
                for (const auto& t : lst){
                    const auto& txid = std::get<0>(t);
                    uint32_t vout    = std::get<1>(t);
                    const auto& e2   = std::get<2>(t);

                    bool spendable = true;
                    uint64_t mat_in = 0, at_h = 0;
                    if (e2.coinbase) {
                        uint64_t mature_h = e2.height + COINBASE_MATURITY;
                        at_h = mature_h;
                        // CRITICAL FIX: Use <= to match mempool validation (mempool.cpp:135)
                        // Mempool rejects if: height + 1 <= coinbase_height + COINBASE_MATURITY
                        if (curH + 1 <= mature_h) { // next block height still <= mature
                            spendable = false;
                            mat_in = mature_h - curH; // blocks until spendable (at mature_h + 1)
                        }
                    }

                    std::map<std::string,JNode> o;
                    o["txid"]      = jstr(to_hex(txid));
                    o["vout"]      = jnum((double)vout);
                    o["value"]     = jnum((double)e2.value);
                    o["pkh"]       = jstr(to_hex(e2.pkh));
                    o["coinbase"]  = jbool(e2.coinbase);
                    o["spendable"] = jbool(spendable);
                    o["matures_in"]= jnum((double)mat_in);
                    if (e2.coinbase) o["at_height"] = jnum((double)at_h);
                    JNode n; n.v = o; outarr.push_back(n);
                }
            }
            JNode out; out.v = outarr; return json_dump(out);
        }

        // --- getwallethistory - Get all transactions involving wallet addresses ---
        // This scans the blockchain for all transactions that:
        // 1. Have outputs paying to our addresses (incoming)
        // 2. Have inputs spending from our addresses (outgoing)
        // Returns a list sorted by block height (most recent first)
        if (method == "getwallethistory") {
            int limit = 100;  // Default limit
            if (params.size() >= 1) {
                if (std::holds_alternative<double>(params[0].v)) {
                    limit = (int)std::get<double>(params[0].v);
                } else if (std::holds_alternative<std::string>(params[0].v)) {
                    try { limit = std::stoi(std::get<std::string>(params[0].v)); }
                    catch(...) { limit = 100; }
                }
            }
            if (limit <= 0) limit = 100;
            if (limit > 1000) limit = 1000;  // Cap at 1000

            // Load wallet
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }
            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

            miq::HdWallet w(seed, meta);
            const uint64_t curH = chain_.tip().height;

            // Collect all our PKHs as hex strings for fast lookup
            constexpr uint32_t GAP_LIMIT = 20;
            std::unordered_set<std::string> our_pkhs_hex;

            auto collect_pkhs = [&](uint32_t chain_idx, uint32_t max_idx) {
                for (uint32_t i = 0; i <= max_idx + GAP_LIMIT; ++i) {
                    std::vector<uint8_t> priv, pub;
                    if (!w.DerivePrivPub(meta.account, chain_idx, i, priv, pub)) continue;
                    auto pkh = hash160(pub);
                    our_pkhs_hex.insert(to_hex(pkh));
                }
            };
            collect_pkhs(0, meta.next_recv);   // External addresses
            collect_pkhs(1, meta.next_change); // Change addresses

            // Structure to hold transaction details
            struct WalletTx {
                std::vector<uint8_t> txid;
                uint64_t block_height;
                int64_t net_value;  // Positive = incoming, negative = outgoing
                bool confirmed;
                uint64_t timestamp;
                std::string type;  // "receive", "send", "self"
            };
            std::vector<WalletTx> history;

            // First, check mempool for pending transactions
            {
                std::vector<Transaction> mempool_txs;
                mempool_.snapshot(mempool_txs);

                for (const auto& tx : mempool_txs) {
                    int64_t incoming = 0, outgoing = 0;
                    bool involves_us = false;

                    // Check outputs (incoming)
                    for (const auto& out : tx.vout) {
                        if (out.pkh.size() == 20) {
                            std::string pkh_hex = to_hex(out.pkh);
                            if (our_pkhs_hex.count(pkh_hex)) {
                                incoming += out.value;
                                involves_us = true;
                            }
                        }
                    }

                    // Check inputs (outgoing) - need to look up the spent outputs
                    for (const auto& in : tx.vin) {
                        UTXOEntry spent_utxo;
                        // Check if input spends one of our UTXOs
                        if (chain_.utxo().get(in.prev.txid, in.prev.vout, spent_utxo)) {
                            std::string pkh_hex = to_hex(spent_utxo.pkh);
                            if (our_pkhs_hex.count(pkh_hex)) {
                                outgoing += spent_utxo.value;
                                involves_us = true;
                            }
                        }
                        // Also check mempool for chained transactions
                        Transaction parent_tx;
                        if (mempool_.get_transaction(in.prev.txid, parent_tx)) {
                            if (in.prev.vout < parent_tx.vout.size()) {
                                const auto& parent_out = parent_tx.vout[in.prev.vout];
                                std::string pkh_hex = to_hex(parent_out.pkh);
                                if (our_pkhs_hex.count(pkh_hex)) {
                                    outgoing += parent_out.value;
                                    involves_us = true;
                                }
                            }
                        }
                    }

                    if (involves_us) {
                        WalletTx wtx;
                        wtx.txid = tx.txid();
                        wtx.block_height = UINT64_MAX;
                        wtx.net_value = incoming - outgoing;
                        wtx.confirmed = false;
                        wtx.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
                        wtx.type = (outgoing == 0) ? "receive" : (incoming == 0 || incoming == outgoing) ? "send" : "self";
                        history.push_back(wtx);
                    }
                }
            }

            // Scan confirmed blocks (from most recent to oldest)
            size_t blocks_scanned = 0;
            for (int64_t h = (int64_t)curH; h >= 0 && (int)history.size() < limit; --h) {
                Block blk;
                if (!chain_.get_block_by_index((size_t)h, blk)) continue;
                blocks_scanned++;

                for (const auto& tx : blk.txs) {
                    int64_t incoming = 0, outgoing = 0;
                    bool involves_us = false;
                    bool is_coinbase = tx.vin.size() > 0 && tx.vin[0].prev.txid.empty();

                    // Check outputs (incoming)
                    for (const auto& out : tx.vout) {
                        if (out.pkh.size() == 20) {
                            std::string pkh_hex = to_hex(out.pkh);
                            if (our_pkhs_hex.count(pkh_hex)) {
                                incoming += out.value;
                                involves_us = true;
                            }
                        }
                    }

                    // Check inputs (outgoing) - for non-coinbase transactions
                    if (!is_coinbase) {
                        for (const auto& in : tx.vin) {
                            // We need to find what UTXO was spent
                            // Look up the parent transaction to get the output value/pkh
                            miq::TxLocation loc;
                            if (chain_.txindex().get(in.prev.txid, loc)) {
                                Block parent_blk;
                                if (chain_.get_block_by_index(loc.block_height, parent_blk)) {
                                    if (loc.tx_position < parent_blk.txs.size()) {
                                        const auto& parent_tx = parent_blk.txs[loc.tx_position];
                                        if (in.prev.vout < parent_tx.vout.size()) {
                                            const auto& spent_out = parent_tx.vout[in.prev.vout];
                                            std::string pkh_hex = to_hex(spent_out.pkh);
                                            if (our_pkhs_hex.count(pkh_hex)) {
                                                outgoing += spent_out.value;
                                                involves_us = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (involves_us) {
                        WalletTx wtx;
                        wtx.txid = tx.txid();
                        wtx.block_height = (uint64_t)h;
                        wtx.net_value = incoming - outgoing;
                        wtx.confirmed = true;
                        wtx.timestamp = blk.header.time;
                        wtx.type = is_coinbase ? "coinbase" :
                                   (outgoing == 0) ? "receive" :
                                   (incoming == 0) ? "send" : "self";
                        history.push_back(wtx);
                    }
                }

                // Stop early if we have enough transactions
                if ((int)history.size() >= limit * 2) break;
            }

            // Sort by block height (pending first, then most recent confirmed)
            std::sort(history.begin(), history.end(), [](const WalletTx& a, const WalletTx& b) {
                // Pending transactions (UINT64_MAX) come first
                if (a.block_height == UINT64_MAX && b.block_height != UINT64_MAX) return true;
                if (b.block_height == UINT64_MAX && a.block_height != UINT64_MAX) return false;
                // Then sort by height descending
                return a.block_height > b.block_height;
            });

            // Limit results
            if ((int)history.size() > limit) {
                history.resize(limit);
            }

            // Build response
            std::vector<JNode> arr;
            for (const auto& wtx : history) {
                std::map<std::string, JNode> o;
                o["txid"] = jstr(to_hex(wtx.txid));
                o["confirmations"] = jnum(wtx.confirmed ? (double)(curH - wtx.block_height + 1) : 0.0);
                o["block_height"] = jnum(wtx.confirmed ? (double)wtx.block_height : -1.0);
                o["amount"] = jnum((double)wtx.net_value);

                // Format amount as MIQ string
                bool negative = wtx.net_value < 0;
                uint64_t abs_val = negative ? (uint64_t)(-wtx.net_value) : (uint64_t)wtx.net_value;
                std::ostringstream s;
                if (negative) s << "-";
                s << (abs_val/COIN) << "." << std::setw(8) << std::setfill('0') << (abs_val%COIN);
                o["amount_miq"] = jstr(s.str());

                o["type"] = jstr(wtx.type);
                o["confirmed"] = jbool(wtx.confirmed);
                o["timestamp"] = jnum((double)wtx.timestamp);

                JNode n; n.v = o; arr.push_back(n);
            }

            // Build result with metadata including blocks_scanned for monitoring
            std::map<std::string, JNode> result;
            JNode txArr; txArr.v = arr;
            result["transactions"] = txArr;
            result["blocks_scanned"] = jnum((double)blocks_scanned);
            result["count"] = jnum((double)arr.size());

            JNode out; out.v = result; return json_dump(out);
        }

        // -------- Spend from HD wallet (filters immature coinbase) --------
        if (method == "sendfromhd") {
            // params: [to_address, amount, feerate(optional miqron per kB)]
            if (params.size() < 2
                || !std::holds_alternative<std::string>(params[0].v)
                || !std::holds_alternative<std::string>(params[1].v)) {
                return err("need to_address, amount");
            }
            const std::string toaddr = std::get<std::string>(params[0].v);
            const std::string amtstr = std::get<std::string>(params[1].v);

            uint64_t feerate = MIN_RELAY_FEE_RATE;
            if (params.size() >= 3) {
                if (std::holds_alternative<double>(params[2].v)) {
                    // SECURITY FIX: Validate double before casting to uint64_t
                    double dval = std::get<double>(params[2].v);
                    if (dval < 0.0 || dval > (double)UINT64_MAX) return err("invalid feerate");
                    feerate = (uint64_t)dval;
                } else if (std::holds_alternative<std::string>(params[2].v)) {
                    try { feerate = (uint64_t)std::stoull(std::get<std::string>(params[2].v)); }
                    catch(...) { return err("bad feerate"); }
                }
                if (feerate == 0) feerate = MIN_RELAY_FEE_RATE;
            }

            // decode destination
            uint8_t ver=0; std::vector<uint8_t> to_payload;
            if(!base58check_decode(toaddr, ver, to_payload) || to_payload.size()!=20 || ver!=VERSION_P2PKH)
                return err("bad to_address");

            // amount
            uint64_t amount = 0;
            try { amount = parse_amount_str(amtstr); }
            catch(...) { return err("bad amount"); }
            if (amount == 0) return err("amount must be >0");

            // No transfer limit - like Bitcoin, allow any amount up to user's balance
            // The only limit is MAX_MONEY (total supply) which is checked elsewhere

            // Load wallet data
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }
            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string werr;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, werr)) return err(werr);

            miq::HdWallet w(seed, meta);
            const uint64_t curH = chain_.tip().height;

            // BIP44 gap limit for discovering externally-used addresses
            constexpr uint32_t GAP_LIMIT = 20;

            struct OwnedUtxo {
                std::vector<uint8_t> txid; uint32_t vout; UTXOEntry e;
                std::vector<uint8_t> priv; std::vector<uint8_t> pub; std::vector<uint8_t> pkh;
            };
            std::vector<OwnedUtxo> owned_all;   // all funds we control
            std::vector<OwnedUtxo> spendables;  // filtered mature funds

            uint64_t total_balance = 0, spendable_balance = 0, locked_balance = 0;
            uint64_t soonest_mature_h = (std::numeric_limits<uint64_t>::max)();

            auto maybe_push = [&](uint32_t chain, uint32_t limit){
                // Scan up to limit + GAP_LIMIT to find externally-used addresses
                for (uint32_t i = 0; i <= limit + GAP_LIMIT; ++i) {
                    std::vector<uint8_t> priv, pub;
                    if (!w.DerivePrivPub(meta.account, chain, i, priv, pub)) continue;
                    auto pkh = hash160(pub);
                    auto lst = chain_.utxo().list_for_pkh(pkh);
                    for (auto& t : lst){
                        OwnedUtxo ou;
                        ou.txid = std::get<0>(t);
                        ou.vout = std::get<1>(t);
                        ou.e    = std::get<2>(t);
                        ou.priv = priv;
                        ou.pub  = pub;
                        ou.pkh  = pkh;
                        owned_all.push_back(ou);

                        total_balance += ou.e.value;

                        bool is_spendable = true;

                        // CRITICAL FIX: Skip UTXOs already spent in mempool
                        // This prevents double-spend attempts when sending multiple transactions
                        // before the first one confirms
                        if (mempool_.has_spent_input(ou.txid, ou.vout)) {
                            is_spendable = false;
                            // Don't add to locked_balance - these are pending, not locked
                        }

                        // Check coinbase maturity
                        // CRITICAL FIX: Use <= to match mempool validation (mempool.cpp:135)
                        // Mempool rejects if: height + 1 <= coinbase_height + COINBASE_MATURITY
                        // Using < here would build tx with immature coinbase, causing mempool rejection
                        if (is_spendable && ou.e.coinbase) {
                            uint64_t m_h = ou.e.height + COINBASE_MATURITY;
                            if (curH + 1 <= m_h) {
                                is_spendable = false;
                                locked_balance += ou.e.value;
                                soonest_mature_h = std::min<uint64_t>(soonest_mature_h, m_h);
                            }
                        }
                        if (is_spendable) {
                            spendables.push_back(owned_all.back());
                            spendable_balance += ou.e.value;
                        }
                    }
                }
            };
            maybe_push(0, meta.next_recv);
            maybe_push(1, meta.next_change);

            // CRITICAL FIX: Also consider unconfirmed outputs from our own mempool transactions
            // This enables transaction chaining: send tx1 with change, then immediately
            // spend that change in tx2 without waiting for tx1 to confirm.
            {
                // Build a set of our PKHs for fast lookup
                std::unordered_set<std::string> our_pkhs;
                for (const auto& ou : owned_all) {
                    std::string pkh_hex;
                    pkh_hex.reserve(40);
                    for (uint8_t b : ou.pkh) {
                        static const char hex[] = "0123456789abcdef";
                        pkh_hex.push_back(hex[b >> 4]);
                        pkh_hex.push_back(hex[b & 0xf]);
                    }
                    our_pkhs.insert(pkh_hex);
                }

                // Scan mempool for transactions with outputs paying to our addresses
                std::vector<Transaction> mempool_txs;
                mempool_.snapshot(mempool_txs);

                for (const auto& mtx : mempool_txs) {
                    auto mtxid = mtx.txid();
                    for (size_t vout = 0; vout < mtx.vout.size(); ++vout) {
                        const auto& mout = mtx.vout[vout];
                        if (mout.pkh.size() != 20) continue;

                        // Check if this output pays to one of our addresses
                        std::string out_pkh_hex;
                        out_pkh_hex.reserve(40);
                        for (uint8_t b : mout.pkh) {
                            static const char hex[] = "0123456789abcdef";
                            out_pkh_hex.push_back(hex[b >> 4]);
                            out_pkh_hex.push_back(hex[b & 0xf]);
                        }

                        if (our_pkhs.count(out_pkh_hex)) {
                            // This mempool output pays to us!
                            // Check if it's already spent in mempool
                            if (!mempool_.has_spent_input(mtxid, (uint32_t)vout)) {
                                // Find the private key for this PKH
                                for (const auto& ou : owned_all) {
                                    std::string ou_pkh_hex;
                                    ou_pkh_hex.reserve(40);
                                    for (uint8_t b : ou.pkh) {
                                        static const char hex[] = "0123456789abcdef";
                                        ou_pkh_hex.push_back(hex[b >> 4]);
                                        ou_pkh_hex.push_back(hex[b & 0xf]);
                                    }
                                    if (ou_pkh_hex == out_pkh_hex) {
                                        OwnedUtxo unconf;
                                        unconf.txid = mtxid;
                                        unconf.vout = (uint32_t)vout;
                                        unconf.e.value = mout.value;
                                        unconf.e.pkh = mout.pkh;
                                        unconf.e.height = UINT64_MAX;  // Mark as unconfirmed (will sort last)
                                        unconf.e.coinbase = false;
                                        unconf.priv = ou.priv;
                                        unconf.pub = ou.pub;
                                        unconf.pkh = ou.pkh;
                                        spendables.push_back(unconf);
                                        spendable_balance += mout.value;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (owned_all.empty() && spendables.empty()) return err("no funds");

            if (spendables.empty()) {
                if (locked_balance > 0 && soonest_mature_h != (std::numeric_limits<uint64_t>::max)()) {
                    char buf[160];
                    std::snprintf(buf, sizeof(buf),
                                  "no spendable utxos: %llu locked until height %llu",
                                  (unsigned long long)locked_balance,
                                  (unsigned long long)soonest_mature_h);
                    return err(buf);
                } else {
                    return err("no spendable utxos (balance=0)");
                }
            }

            // Oldest-first coin selection: (height asc, txid lex, vout asc)
            auto lex_less = [](const std::vector<uint8_t>& A, const std::vector<uint8_t>& B){
                return std::lexicographical_compare(A.begin(), A.end(), B.begin(), B.end());
            };
            std::sort(spendables.begin(), spendables.end(),
                      [&](const OwnedUtxo& A, const OwnedUtxo& B){
                          if (A.e.height != B.e.height) return A.e.height < B.e.height;
                          if (A.txid != B.txid) return lex_less(A.txid, B.txid);
                          return A.vout < B.vout;
                      });

            Transaction tx;
            uint64_t in_sum = 0;

            auto fee_for = [&](size_t nin, size_t nout)->uint64_t{
                size_t sz = estimate_size_bytes(nin, nout);
                uint64_t kb = (uint64_t)((sz + 999) / 1000);
                if (kb==0) kb=1;
                return kb * feerate;
            };

            for (size_t k = 0; k < spendables.size(); ++k){
                const auto& u = spendables[k];
                TxIn in; in.prev.txid = u.txid; in.prev.vout = u.vout;
                tx.vin.push_back(in);
                in_sum += u.e.value;

                uint64_t fee_guess = fee_for(tx.vin.size(), 2);
                if (in_sum >= amount + fee_guess) break;
            }
            if (tx.vin.empty()) return err("insufficient funds");

            // Outputs & fee
            TxOut out; out.pkh = to_payload;

            uint64_t fee_final = 0, change = 0;
            {
                size_t est_size = estimate_size_bytes(tx.vin.size(), 2);
                (void)est_size;
                fee_final = fee_for(tx.vin.size(), 2);
                if(in_sum < amount + fee_final){
                    size_t est_size1 = estimate_size_bytes(tx.vin.size(), 1);
                    (void)est_size1;
                    fee_final = fee_for(tx.vin.size(), 1);
                    if(in_sum < amount + fee_final) return err("insufficient funds (need amount+fee)");
                    change = 0;
                } else {
                    change = in_sum - amount - fee_final;
                    if(change < DUST_THRESHOLD){
                        change = 0;
                        size_t est_size2 = estimate_size_bytes(tx.vin.size(), 1);
                        (void)est_size2;
                        fee_final = fee_for(tx.vin.size(), 1);
                        if(in_sum < amount + fee_final) return err("insufficient after dust fold");
                    }
                }
            }

            out.value = amount;
            tx.vout.push_back(out);

            // Change -> new change address (m/44'/coin'/account'/1/index)
            std::vector<uint8_t> change_priv, change_pub; std::vector<uint8_t> change_pkh;
            bool used_change = false;
            if (change > 0) {
                if (!w.DerivePrivPub(meta.account, 1, meta.next_change, change_priv, change_pub))
                    return err("derive change failed");
                change_pkh = hash160(change_pub);
                TxOut ch; ch.value = change; ch.pkh = change_pkh;
                tx.vout.push_back(ch);
                used_change = true;
            }

            // Sighash and sign each input with its matching key
            auto sighash = [&](){
                Transaction t=tx; for(auto& i: t.vin){ i.sig.clear(); i.pubkey.clear(); }
                return dsha256(ser_tx(t));
            }();
            for (auto& in : tx.vin){
                const OwnedUtxo* key = nullptr;
                for (const auto& u : spendables){
                    if (u.txid == in.prev.txid && u.vout == in.prev.vout) { key = &u; break; }
                }
                if (!key) return err("internal: key lookup failed");
                std::vector<uint8_t> sig64;
                if(!crypto::ECDSA::sign(key->priv, sighash, sig64)) return err("sign failed");
                in.sig = sig64;
                in.pubkey = key->pub;
            }

            auto tip = chain_.tip(); std::string e;

            // DIAGNOSTIC: Log transaction details before submission
            log_info("sendfromhd: attempting tx with " + std::to_string(tx.vin.size()) + " inputs, " +
                     std::to_string(tx.vout.size()) + " outputs, tip height=" + std::to_string(tip.height));
            for (size_t i = 0; i < tx.vin.size(); ++i) {
                const auto& in = tx.vin[i];
                log_info("  input[" + std::to_string(i) + "]: " + to_hex(in.prev.txid).substr(0, 16) + ":" + std::to_string(in.prev.vout));
            }

            if(mempool_.accept(tx, chain_.utxo(), static_cast<uint32_t>(tip.height), e)){
                log_info("sendfromhd: tx " + to_hex(tx.txid()).substr(0, 16) + " accepted into mempool (size=" +
                         std::to_string(mempool_.size()) + ")");
                // CRITICAL FIX: Broadcast transaction to P2P network
                // Without this, transactions only sit in local mempool and never propagate!
                if(p2p_) {
                    std::vector<uint8_t> txid = tx.txid();
                    // Store raw tx so peers can fetch it via gettx after invtx
                    std::vector<uint8_t> raw = ser_tx(tx);
                    p2p_->store_tx_for_relay(txid, raw);
                    p2p_->broadcast_inv_tx(txid);
                    // Notify telemetry so TUI shows the transaction in "Recent TXIDs"
                    p2p_->notify_local_tx(txid);
                }
                if (used_change) {
                    HdAccountMeta newm = w.meta();
                    newm.next_change = meta.next_change + 1;
                    if(!SaveHdWallet(wdir, seed, newm, pass, e)) {
                        log_warn(std::string("sendfromhd: SaveHdWallet failed: ") + e);
                    }
                }
                // CRITICAL FIX: Return properly formatted {"result":"txid"} response
                return ok_str(to_hex(tx.txid()));
            } else {
                log_warn("sendfromhd: tx rejected: " + e);
                return err(e);
            }
        }

        // ---------------- chain-related helpers ----------------

        if(method=="estimatemediantime"){
            auto hdrs = chain_.last_headers(11);
            if(hdrs.empty()){
                return ok_num(0.0);
            }
            std::vector<int64_t> ts;
            ts.reserve(hdrs.size());
            for(auto& p : hdrs) ts.push_back(p.first);
            std::sort(ts.begin(), ts.end());
            double mtp = (double)ts[ts.size()/2];
            return ok_num(mtp);
        }

        if(method=="getdifficulty"){
            double d = (double)Chain::work_from_bits_public(chain_.tip().bits);
            return ok_num(d);
        }

        if(method=="getchaintips"){
            // Minimal: only the active tip
            auto tip = chain_.tip();
            std::map<std::string,JNode> t;
            t["height"]    = jnum((double)tip.height);
            t["hash"]      = jstr(to_hex(tip.hash));
            t["branchlen"] = jnum(0.0);
            t["status"]    = jstr("active");
            JNode tipnode; tipnode.v = t;              // renamed to avoid shadowing 'obj'
            std::vector<JNode> arr; arr.push_back(tipnode);
            JNode out; out.v = arr; return json_dump(out);
        }

        // ---------------- p2p info ----------------

        if(method=="getpeerinfo"){
            std::vector<JNode> peers;
            if(p2p_) {
                auto snapshots = p2p_->snapshot_peers();
                for(const auto& s : snapshots) {
                    std::map<std::string, JNode> peer;
                    peer["addr"] = jstr(s.ip);
                    peer["syncing"] = jbool(s.syncing);
                    peer["verack"] = jbool(s.verack_ok);
                    peer["awaiting_pong"] = jbool(s.awaiting_pong);
                    peer["misbehavior"] = jnum((double)s.mis);
                    peer["last_seen_ms"] = jnum(s.last_seen_ms);
                    peer["peer_tip"] = jnum((double)s.peer_tip);
                    peer["rx_buffer"] = jnum((double)s.rx_buf);
                    peer["inflight_tx"] = jnum((double)s.inflight);
                    JNode pnode; pnode.v = peer;
                    peers.push_back(pnode);
                }
            }
            JNode out; out.v = peers;
            return json_dump(out);
        }

        if(method=="getconnectioncount"){
            size_t count = 0;
            if(p2p_) {
                auto stats = p2p_->get_connection_stats();
                count = stats.total_connections;
            }
            return json_dump(jnum((double)count));
        }

        if(method=="getnetworkinfo"){
            std::map<std::string, JNode> info;
            if(p2p_) {
                auto stats = p2p_->get_connection_stats();
                info["connections"] = jnum((double)stats.total_connections);
                info["inbound"] = jnum((double)stats.inbound_connections);
                info["outbound"] = jnum((double)stats.outbound_connections);
                info["syncing_peers"] = jnum((double)stats.syncing_peers);
                info["stalled_peers"] = jnum((double)stats.stalled_peers);
                info["banned_ips"] = jnum((double)stats.banned_ips);
                info["network_healthy"] = jbool(p2p_->is_network_healthy());
                info["health_score"] = jnum(p2p_->get_network_health_score());
            } else {
                info["connections"] = jnum(0.0);
                info["network_healthy"] = jbool(false);
            }
            JNode out; out.v = info;
            return json_dump(out);
        }

        if(method=="listbanned"){
            std::vector<JNode> bans;
            if(p2p_) {
                auto banned = p2p_->get_banned_ips();
                for(const auto& b : banned) {
                    std::map<std::string, JNode> entry;
                    entry["ip"] = jstr(b.first);
                    entry["remaining_ms"] = jnum((double)b.second);
                    entry["permanent"] = jbool(b.second < 0);
                    JNode enode; enode.v = entry;
                    bans.push_back(enode);
                }
            }
            JNode out; out.v = bans;
            return json_dump(out);
        }

        if(method=="setban"){
            if(params.size() < 2) return err("setban requires ip and action");
            std::string node_ip = std::get<std::string>(params[0].v);
            std::string action = std::get<std::string>(params[1].v);
            if(!p2p_) return err("p2p not available");

            if(action == "add") {
                int64_t duration_ms = 24 * 60 * 60 * 1000; // Default 24 hours
                if(params.size() > 2) {
                    duration_ms = (int64_t)(std::get<double>(params[2].v) * 1000);
                }
                p2p_->ban_ip(node_ip, duration_ms);
                return json_dump(jbool(true));
            } else if(action == "remove") {
                p2p_->unban_ip(node_ip);
                return json_dump(jbool(true));
            }
            return err("unknown action: " + action);
        }

        if(method=="disconnectnode"){
            if(params.empty()) return err("disconnectnode requires ip");
            std::string node_ip = std::get<std::string>(params[0].v);
            if(!p2p_) return err("p2p not available");
            bool success = p2p_->disconnect_peer(node_ip);
            return success ? json_dump(jbool(true)) : err("peer not found");
        }

        // ================== BIP158 COMPACT BLOCK FILTER RPC ENDPOINTS ==================
        // These endpoints allow SPV clients to fetch compact block filters and filter headers

#if MIQ_HAVE_GCS_FILTERS
        // getcfilterheaders(start_height, count) -> array of filter header hashes
        if(method=="getcfilterheaders" || method=="getfilterheaders" || method=="getcfheaders"){
            uint32_t start = 0, count = 2000;
            if(params.size() >= 1 && std::holds_alternative<double>(params[0].v))
                start = (uint32_t)std::get<double>(params[0].v);
            if(params.size() >= 2 && std::holds_alternative<double>(params[1].v))
                count = (uint32_t)std::get<double>(params[1].v);
            if(count > 2000) count = 2000; // Safety limit

            std::vector<std::array<uint8_t,32>> headers;
            if(!chain_.get_filter_headers(start, count, headers))
                return err("failed to get filter headers");

            std::vector<JNode> arr;
            arr.reserve(headers.size());
            for(const auto& h : headers){
                arr.push_back(jstr(to_hex(std::vector<uint8_t>(h.begin(), h.end()))));
            }
            JNode out; out.v = arr; return json_dump(out);
        }

        // getcfilter(start_height, count) -> array of {block_hash, filter_hex} objects
        if(method=="getcfilter" || method=="getblockfilter" || method=="getcffilter"){
            uint32_t start = 0, count = 100;
            if(params.size() >= 1 && std::holds_alternative<double>(params[0].v))
                start = (uint32_t)std::get<double>(params[0].v);
            if(params.size() >= 2 && std::holds_alternative<double>(params[1].v))
                count = (uint32_t)std::get<double>(params[1].v);
            if(count > 100) count = 100; // Safety limit (filters can be large)

            std::vector<std::pair<std::array<uint8_t,32>, std::vector<uint8_t>>> filters;
            if(!chain_.get_filters_with_hash(start, count, filters))
                return err("failed to get filters");

            std::vector<JNode> arr;
            arr.reserve(filters.size());
            for(const auto& f : filters){
                std::map<std::string,JNode> o;
                o["block_hash"] = jstr(to_hex(std::vector<uint8_t>(f.first.begin(), f.first.end())));
                o["filter"] = jstr(to_hex(f.second));
                o["height"] = jnum((double)(start + arr.size()));
                JNode n; n.v = o; arr.push_back(n);
            }
            JNode out; out.v = arr; return json_dump(out);
        }

        // getfiltercount -> number of filters stored
        if(method=="getfiltercount"){
            auto tip = chain_.tip();
            std::map<std::string,JNode> o;
            o["filter_height"] = jnum((double)tip.height);
            o["tip_height"] = jnum((double)tip.height);
            JNode out; out.v = o; return json_dump(out);
        }
#endif

        // ================== NODE INFO AND DIAGNOSTICS ==================

        // getnodeinfo -> comprehensive node status (for operators)
        if(method=="getnodeinfo"){
            auto tip = chain_.tip();
            std::map<std::string,JNode> o;
            o["version"] = jstr("1.0.0");
            o["height"] = jnum((double)tip.height);
            o["hash"] = jstr(to_hex(tip.hash));
            o["time"] = jnum((double)tip.time);
            o["issued"] = jnum((double)tip.issued);

            // Mempool stats
            o["mempool_size"] = jnum((double)mempool_.size());
            o["mempool_bytes"] = jnum((double)mempool_.bytes_used());

            // P2P stats if available
            if(p2p_) {
                auto stats = p2p_->get_connection_stats();
                o["peers"] = jnum((double)stats.total_connections);
                o["inbound"] = jnum((double)stats.inbound_connections);
                o["outbound"] = jnum((double)stats.outbound_connections);
                o["syncing_peers"] = jnum((double)stats.syncing_peers);
            }

#if MIQ_HAVE_GCS_FILTERS
            o["filters_enabled"] = jbool(true);
#else
            o["filters_enabled"] = jbool(false);
#endif

            JNode out; out.v = o; return json_dump(out);
        }

        // getreorginfo -> reorg manager status
        if(method=="getreorginfo"){
            std::map<std::string,JNode> o;
            o["tip_height"] = jnum((double)chain_.tip().height);
            o["tip_hash"] = jstr(to_hex(chain_.tip().hash));
            // Could add more reorg stats here
            JNode out; out.v = o; return json_dump(out);
        }

        // ================== BLOCKCHAIN EXPLORER API ==================
        // These endpoints enable full-featured blockchain explorer functionality

        // getaddresstxids(address, [start_height], [end_height], [skip], [limit])
        // Returns transaction IDs for an address, sorted by height (most recent first)
        if(method=="getaddresstxids"){
            if(params.size() < 1 || !std::holds_alternative<std::string>(params[0].v))
                return err("usage: getaddresstxids <address> [start_height] [end_height] [skip] [limit]");

            const std::string addr = std::get<std::string>(params[0].v);

            // Decode address to PKH
            uint8_t ver = 0;
            std::vector<uint8_t> pkh;
            if (!base58check_decode(addr, ver, pkh) || pkh.size() != 20 || ver != VERSION_P2PKH)
                return err("invalid address");

            // Parse optional parameters
            uint64_t start_height = 0;
            uint64_t end_height = UINT64_MAX;
            size_t skip = 0;
            size_t limit = 100;

            if (params.size() >= 2 && std::holds_alternative<double>(params[1].v))
                start_height = (uint64_t)std::get<double>(params[1].v);
            if (params.size() >= 3 && std::holds_alternative<double>(params[2].v))
                end_height = (uint64_t)std::get<double>(params[2].v);
            if (params.size() >= 4 && std::holds_alternative<double>(params[3].v))
                skip = (size_t)std::get<double>(params[3].v);
            if (params.size() >= 5 && std::holds_alternative<double>(params[4].v))
                limit = (size_t)std::get<double>(params[4].v);

            if (limit > 1000) limit = 1000;  // Safety limit

            // Query address index
            auto txids = chain_.addressindex().get_address_txids(pkh, start_height, end_height, skip, limit);

            std::vector<JNode> arr;
            arr.reserve(txids.size());
            for (const auto& txid : txids) {
                arr.push_back(jstr(to_hex(txid)));
            }

            std::map<std::string, JNode> result;
            JNode txid_arr; txid_arr.v = arr;
            result["txids"] = txid_arr;
            result["count"] = jnum((double)arr.size());
            result["address"] = jstr(addr);
            result["start_height"] = jnum((double)start_height);
            result["end_height"] = jnum((double)end_height);

            JNode out; out.v = result; return json_dump(out);
        }

        // getaddresshistory(address, [start_height], [end_height], [skip], [limit])
        // Returns full transaction history for an address with details
        if(method=="getaddresshistory"){
            if(params.size() < 1 || !std::holds_alternative<std::string>(params[0].v))
                return err("usage: getaddresshistory <address> [start_height] [end_height] [skip] [limit]");

            const std::string addr = std::get<std::string>(params[0].v);

            // Decode address to PKH
            uint8_t ver = 0;
            std::vector<uint8_t> pkh;
            if (!base58check_decode(addr, ver, pkh) || pkh.size() != 20 || ver != VERSION_P2PKH)
                return err("invalid address");

            // Parse optional parameters
            uint64_t start_height = 0;
            uint64_t end_height = UINT64_MAX;
            size_t skip = 0;
            size_t limit = 100;

            if (params.size() >= 2 && std::holds_alternative<double>(params[1].v))
                start_height = (uint64_t)std::get<double>(params[1].v);
            if (params.size() >= 3 && std::holds_alternative<double>(params[2].v))
                end_height = (uint64_t)std::get<double>(params[2].v);
            if (params.size() >= 4 && std::holds_alternative<double>(params[3].v))
                skip = (size_t)std::get<double>(params[3].v);
            if (params.size() >= 5 && std::holds_alternative<double>(params[4].v))
                limit = (size_t)std::get<double>(params[4].v);

            if (limit > 500) limit = 500;  // Safety limit (history entries are larger)

            // Query address index
            auto history = chain_.addressindex().get_address_history(pkh, start_height, end_height, skip, limit);

            std::vector<JNode> arr;
            arr.reserve(history.size());
            for (const auto& entry : history) {
                std::map<std::string, JNode> o;
                o["txid"] = jstr(to_hex(entry.txid));
                o["height"] = jnum((double)entry.block_height);
                o["tx_pos"] = jnum((double)entry.tx_position);
                o["timestamp"] = jnum((double)entry.timestamp);
                o["is_input"] = jbool(entry.is_input);
                o["value"] = jnum((double)entry.value);
                o["io_index"] = jnum((double)entry.io_index);

                // Format value as MIQ string
                std::ostringstream s;
                s << (entry.value / COIN) << "." << std::setw(8) << std::setfill('0') << (entry.value % COIN);
                o["value_miq"] = jstr(s.str());

                if (entry.is_input && !entry.spent_txid.empty()) {
                    o["spent_txid"] = jstr(to_hex(entry.spent_txid));
                    o["spent_vout"] = jnum((double)entry.spent_vout);
                }

                // Confirmations
                auto tip = chain_.tip();
                if (entry.block_height > 0 && entry.block_height <= tip.height) {
                    o["confirmations"] = jnum((double)(tip.height - entry.block_height + 1));
                } else {
                    o["confirmations"] = jnum(0);
                }

                JNode n; n.v = o; arr.push_back(n);
            }

            std::map<std::string, JNode> result;
            JNode hist_arr; hist_arr.v = arr;
            result["history"] = hist_arr;
            result["count"] = jnum((double)arr.size());
            result["address"] = jstr(addr);
            result["tx_count"] = jnum((double)chain_.addressindex().get_address_tx_count(pkh));

            JNode out; out.v = result; return json_dump(out);
        }

        // getaddressbalance(address)
        // Returns balance details for an address
        if(method=="getaddressbalance"){
            if(params.size() < 1 || !std::holds_alternative<std::string>(params[0].v))
                return err("usage: getaddressbalance <address>");

            const std::string addr = std::get<std::string>(params[0].v);

            // Decode address to PKH
            uint8_t ver = 0;
            std::vector<uint8_t> pkh;
            if (!base58check_decode(addr, ver, pkh) || pkh.size() != 20 || ver != VERSION_P2PKH)
                return err("invalid address");

            // Get balance from address index
            auto tip = chain_.tip();
            auto bal = chain_.addressindex().get_address_balance(pkh, tip.height, COINBASE_MATURITY);

            std::map<std::string, JNode> result;
            result["address"] = jstr(addr);

            // Balances in miqrons
            result["confirmed"] = jnum((double)bal.confirmed);
            result["unconfirmed"] = jnum((double)bal.unconfirmed);
            result["immature"] = jnum((double)bal.immature);
            result["total_received"] = jnum((double)bal.total_received);
            result["total_sent"] = jnum((double)bal.total_sent);

            // Balances as MIQ strings
            auto fmt_miq = [](uint64_t v) -> std::string {
                std::ostringstream s;
                s << (v / COIN) << "." << std::setw(8) << std::setfill('0') << (v % COIN);
                return s.str();
            };
            result["confirmed_miq"] = jstr(fmt_miq(bal.confirmed));
            result["unconfirmed_miq"] = jstr(fmt_miq(bal.unconfirmed));
            result["immature_miq"] = jstr(fmt_miq(bal.immature));
            result["total_received_miq"] = jstr(fmt_miq(bal.total_received));
            result["total_sent_miq"] = jstr(fmt_miq(bal.total_sent));

            // Statistics
            result["tx_count"] = jnum((double)bal.tx_count);
            result["utxo_count"] = jnum((double)bal.utxo_count);

            JNode out; out.v = result; return json_dump(out);
        }

        // getaddressdeltas(address, [start_height], [end_height])
        // Returns balance changes (deltas) for an address per block
        if(method=="getaddressdeltas"){
            if(params.size() < 1 || !std::holds_alternative<std::string>(params[0].v))
                return err("usage: getaddressdeltas <address> [start_height] [end_height]");

            const std::string addr = std::get<std::string>(params[0].v);

            // Decode address to PKH
            uint8_t ver = 0;
            std::vector<uint8_t> pkh;
            if (!base58check_decode(addr, ver, pkh) || pkh.size() != 20 || ver != VERSION_P2PKH)
                return err("invalid address");

            uint64_t start_height = 0;
            uint64_t end_height = UINT64_MAX;

            if (params.size() >= 2 && std::holds_alternative<double>(params[1].v))
                start_height = (uint64_t)std::get<double>(params[1].v);
            if (params.size() >= 3 && std::holds_alternative<double>(params[2].v))
                end_height = (uint64_t)std::get<double>(params[2].v);

            // Get full history and compute deltas per block
            auto history = chain_.addressindex().get_address_history(pkh, start_height, end_height, 0, 10000);

            // Aggregate by block height
            std::map<uint64_t, int64_t> deltas;  // height -> net change
            for (const auto& entry : history) {
                if (entry.is_input) {
                    deltas[entry.block_height] -= (int64_t)entry.value;
                } else {
                    deltas[entry.block_height] += (int64_t)entry.value;
                }
            }

            std::vector<JNode> arr;
            for (const auto& kv : deltas) {
                std::map<std::string, JNode> o;
                o["height"] = jnum((double)kv.first);
                o["satoshis"] = jnum((double)kv.second);

                // Format as MIQ
                bool negative = kv.second < 0;
                uint64_t abs_val = negative ? (uint64_t)(-kv.second) : (uint64_t)kv.second;
                std::ostringstream s;
                if (negative) s << "-";
                s << (abs_val / COIN) << "." << std::setw(8) << std::setfill('0') << (abs_val % COIN);
                o["miq"] = jstr(s.str());

                JNode n; n.v = o; arr.push_back(n);
            }

            std::map<std::string, JNode> result;
            JNode deltas_arr; deltas_arr.v = arr;
            result["deltas"] = deltas_arr;
            result["count"] = jnum((double)arr.size());
            result["address"] = jstr(addr);

            JNode out; out.v = result; return json_dump(out);
        }

        // reindexaddresses -> trigger address index rebuild
        if(method=="reindexaddresses"){
            // This is a long-running operation, run synchronously for now
            bool success = chain_.reindex_addresses([](uint64_t cur, uint64_t total) {
                // Log progress periodically
                if (cur % 1000 == 0) {
                    log_info("Address reindex: " + std::to_string(cur) + "/" + std::to_string(total));
                }
                return true;
            });

            std::map<std::string, JNode> result;
            result["success"] = jbool(success);
            result["address_count"] = jnum((double)chain_.addressindex().address_count());
            result["indexed_height"] = jnum((double)chain_.addressindex().best_indexed_height());

            JNode out; out.v = result; return json_dump(out);
        }

        // getaddressindexinfo -> address index statistics
        if(method=="getaddressindexinfo"){
            std::map<std::string, JNode> result;
            result["enabled"] = jbool(chain_.addressindex().is_enabled());
            result["address_count"] = jnum((double)chain_.addressindex().address_count());
            result["transaction_count"] = jnum((double)chain_.addressindex().transaction_count());
            result["block_hash_count"] = jnum((double)chain_.addressindex().block_hash_count());
            result["best_indexed_height"] = jnum((double)chain_.addressindex().best_indexed_height());
            result["disk_usage_bytes"] = jnum((double)chain_.addressindex().disk_usage());

            JNode out; out.v = result; return json_dump(out);
        }

        // ============================================================================
        // CHAIN DOCTOR RPC COMMANDS
        // These commands provide production-grade chain recovery capabilities
        // ============================================================================

        // disconnectblock - Disconnect the tip block (for chain recovery)
        // params: [count] - optional number of blocks to disconnect (default: 1)
        if(method=="disconnectblock"){
            uint64_t count = 1;
            if (params.size() >= 1 && std::holds_alternative<double>(params[0].v)) {
                count = static_cast<uint64_t>(std::get<double>(params[0].v));
            }

            // Safety limit - don't allow disconnecting more than 100 blocks at once
            if (count > 100) {
                return err("cannot disconnect more than 100 blocks at once (safety limit)");
            }

            auto tip = chain_.tip();
            if (tip.height < count) {
                return err("cannot disconnect " + std::to_string(count) + " blocks - only " + std::to_string(tip.height) + " blocks exist");
            }

            std::vector<std::string> disconnected_hashes;
            uint64_t start_height = tip.height;

            for (uint64_t i = 0; i < count; ++i) {
                std::string disconnect_err;
                auto before_tip = chain_.tip();

                if (!chain_.disconnect_tip_once(disconnect_err)) {
                    // Report what we managed to disconnect before failure
                    std::map<std::string, JNode> result;
                    result["success"] = jbool(false);
                    result["error"] = jstr(disconnect_err);
                    result["disconnected_count"] = jnum((double)disconnected_hashes.size());
                    result["start_height"] = jnum((double)start_height);
                    result["current_height"] = jnum((double)chain_.tip().height);

                    std::vector<JNode> hashes_arr;
                    for (const auto& h : disconnected_hashes) {
                        JNode n; n.v = h; hashes_arr.push_back(n);
                    }
                    JNode arr; arr.v = hashes_arr;
                    result["disconnected_hashes"] = arr;

                    JNode out; out.v = result; return json_dump(out);
                }

                disconnected_hashes.push_back(to_hex(before_tip.hash));
                log_info("disconnectblock: disconnected block " + std::to_string(before_tip.height) +
                         " hash=" + to_hex(before_tip.hash).substr(0, 16) + "...");
            }

            // Success - all blocks disconnected
            std::map<std::string, JNode> result;
            result["success"] = jbool(true);
            result["disconnected_count"] = jnum((double)count);
            result["start_height"] = jnum((double)start_height);
            result["new_height"] = jnum((double)chain_.tip().height);
            result["new_tip_hash"] = jstr(to_hex(chain_.tip().hash));

            std::vector<JNode> hashes_arr;
            for (const auto& h : disconnected_hashes) {
                JNode n; n.v = h; hashes_arr.push_back(n);
            }
            JNode arr; arr.v = hashes_arr;
            result["disconnected_hashes"] = arr;

            JNode out; out.v = result; return json_dump(out);
        }

        // validatechain - Validate chain integrity (quick check)
        // Returns info about chain state and any detected issues
        if(method=="validatechain"){
            std::map<std::string, JNode> result;
            auto tip = chain_.tip();

            result["height"] = jnum((double)tip.height);
            result["tip_hash"] = jstr(to_hex(tip.hash));
            result["utxo_count"] = jnum((double)chain_.utxo().size());

            // Check last N blocks for connectivity
            uint64_t check_depth = 50;
            if (params.size() >= 1 && std::holds_alternative<double>(params[0].v)) {
                check_depth = static_cast<uint64_t>(std::get<double>(params[0].v));
            }
            if (check_depth > tip.height) check_depth = tip.height;

            bool chain_valid = true;
            std::string chain_error;
            uint64_t error_height = 0;

            // Verify chain connectivity
            Block cur_block;
            if (chain_.get_block_by_hash(tip.hash, cur_block)) {
                for (uint64_t i = 0; i < check_depth && chain_valid; ++i) {
                    uint64_t h = tip.height - i;
                    if (h == 0) break;

                    Block prev_block;
                    if (!chain_.get_block_by_hash(cur_block.header.prev_hash, prev_block)) {
                        chain_valid = false;
                        chain_error = "missing parent block";
                        error_height = h;
                        break;
                    }

                    // Verify the prev_hash actually points to parent
                    if (cur_block.header.prev_hash != prev_block.block_hash()) {
                        chain_valid = false;
                        chain_error = "prev_hash mismatch";
                        error_height = h;
                        break;
                    }

                    cur_block = prev_block;
                }
            } else {
                chain_valid = false;
                chain_error = "cannot read tip block";
            }

            result["chain_valid"] = jbool(chain_valid);
            result["checked_depth"] = jnum((double)check_depth);

            if (!chain_valid) {
                result["error"] = jstr(chain_error);
                result["error_height"] = jnum((double)error_height);
                result["recommendation"] = jstr("Use miq-chain-doctor scan to find corruption, then truncate to fix");
            }

            JNode out; out.v = result; return json_dump(out);
        }

        // getchaindiagnostics - Get detailed chain diagnostics
        if(method=="getchaindiagnostics"){
            std::map<std::string, JNode> result;
            auto tip = chain_.tip();

            // Basic info
            result["height"] = jnum((double)tip.height);
            result["tip_hash"] = jstr(to_hex(tip.hash));
            result["tip_time"] = jnum((double)tip.time);
            result["tip_bits"] = jnum((double)tip.bits);
            result["total_issued"] = jnum((double)tip.issued);
            result["utxo_count"] = jnum((double)chain_.utxo().size());

            // Index stats
            result["txindex_entries"] = jnum((double)chain_.txindex().size());
            result["addressindex_enabled"] = jbool(chain_.addressindex().is_enabled());
            if (chain_.addressindex().is_enabled()) {
                result["addressindex_addresses"] = jnum((double)chain_.addressindex().address_count());
                result["addressindex_height"] = jnum((double)chain_.addressindex().best_indexed_height());
            }

            // Data directory info
            result["datadir"] = jstr(chain_.datadir());

            JNode out; out.v = result; return json_dump(out);
        }

        return err("unknown method");
    } catch(const std::exception& ex){
        log_error(std::string("rpc handle exception: ")+ex.what());
        return err("internal error");
    } catch(...){
        log_error("rpc handle exception: unknown");
        return err("internal error");
    }
}

}
