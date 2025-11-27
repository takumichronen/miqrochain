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
#include "miner.h"
#include "base58check.h"
#include "hash160.h"
#include "utxo.h"          // UTXOEntry & list_for_pkh
#include "difficulty.h"    // MIQ_RETARGET_INTERVAL & epoch_next_bits

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
// sat/KB (miqron per kilobyte)
static constexpr uint64_t MIN_RELAY_FEE_RATE = 1000;
#endif
#ifndef DUST_THRESHOLD
static constexpr uint64_t DUST_THRESHOLD = 1000; // 0.00001000 MIQ
#endif

// --- RPC request limits ---
static constexpr size_t RPC_MAX_BODY_BYTES = 512 * 1024; // 512 KiB

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
    const uint64_t rate = MIN_RELAY_FEE_RATE; // sat/kB
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
                "getrawmempool","gettxout","getrawtransaction",
                "validateaddress","decodeaddress","decoderawtx",
                "getminerstats","sendrawtransaction","sendtoaddress",
                "estimatemediantime","getdifficulty","getchaintips",
                "getpeerinfo","getconnectioncount",
                "createhdwallet","restorehdwallet","walletinfo","getnewaddress","deriveaddressat",
                "walletunlock","walletlock","getwalletinfo","listaddresses","listutxos",
                "sendfromhd","getaddressutxos","getbalance",
                "getblocktemplate","getminertemplate", // Mining pool support
                "submitblock","submitrawblock","sendrawblock"
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
            JNode n; std::map<std::string,JNode> o;
            JNode a; a.v = std::string(CHAIN_NAME);              o["chain"] = a;
            JNode h; h.v = (double)tip.height;                   o["height"] = h;
            JNode b; b.v = (double)tip.height;                   o["blocks"] = b;  // alias for height
            JNode hh; hh.v = to_hex(tip.hash);                   o["bestblockhash"] = hh;
            JNode d; d.v = (double)Chain::work_from_bits_public(tip.bits); o["difficulty"] = d;
            JNode r; r.v = o; return json_dump(r);
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
            JNode n; n.v = (double)chain_.tip().height;
            return json_dump(n);
        }

        if(method=="getbestblockhash"){
            JNode n; n.v = std::string(to_hex(chain_.tip().hash));
            return json_dump(n);
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

            // Collect mempool transactions
            auto txs_vec = mempool_.collect(5000);
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

            // Collect mempool txs with simple fee & size estimates.
            auto txs_vec = mempool_.collect(5000);
            std::vector<JNode> arr;

            // Build a quick index from txid -> (fee, vsize, hex, depends[])
            std::map<std::string, std::tuple<uint64_t, uint32_t, std::string, std::vector<std::string>>> mapTx;
            std::map<std::string, std::vector<std::string>> mapDeps;

            for (const auto& tx : txs_vec) {
                auto raw = ser_tx(tx);
                uint32_t vsize = (uint32_t)raw.size();
                uint64_t in_sum = 0, out_sum = 0;

                // Sum in/out (best-effort using UTXO view; if missing, fee=0)
                for (const auto& in : tx.vin) {
                    UTXOEntry e;
                    if (chain_.utxo().get(in.prev.txid, in.prev.vout, e)) {
                        in_sum += e.value;
                        // dependency edge
                        mapDeps[to_hex(tx.txid())].push_back(to_hex(in.prev.txid));
                    }
                }
                for (const auto& o : tx.vout) out_sum += o.value;
                uint64_t fee = (in_sum > out_sum) ? (in_sum - out_sum) : 0;

                // Store
                mapTx[to_hex(tx.txid())] = std::make_tuple(fee, vsize, to_hex(raw), std::vector<std::string>{});
            }

            // Transfer to JSON (use "hex" so external miner picks it up)
            for (auto& kv : mapTx) {
                const std::string& txid = kv.first;
                auto& tup = kv.second;
                auto itd = mapDeps.find(txid);
                if (itd != mapDeps.end()) {
                    std::get<3>(tup) = itd->second;
                }
                std::map<std::string, JNode> o;
                o["txid"]   = jstr(txid);
                o["fee"]    = jnum((double)std::get<0>(tup));
                o["vsize"]  = jnum((double)std::get<1>(tup));
                o["hex"]    = jstr(std::get<2>(tup)); // "hex" (not "raw")
                // depends[]
                std::vector<JNode> d; for (auto& dep : std::get<3>(tup)) d.push_back(jstr(dep));
                JNode dd; dd.v = d; o["depends"] = dd;
                JNode x; x.v = o; arr.push_back(x);
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
            JNode arr; std::vector<JNode> v;
            for(auto& id: ids){ JNode s; s.v = std::string(to_hex(id)); v.push_back(s); }
            arr.v = v; return json_dump(arr);
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

        // getrawtransaction - look up transaction by txid (mempool only for now)
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
                JNode hex; hex.v = std::string(to_hex(raw)); o["hex"] = hex;
                JNode tid; tid.v = txidhex; o["txid"] = tid;
                JNode n; n.v = o; return json_dump(n);
            }

            // Not found in mempool - check if any outputs exist in UTXO set
            // This indicates the transaction was mined
            for(uint32_t vout = 0; vout < 100; ++vout) {  // Check first 100 outputs
                UTXOEntry e;
                if(chain_.utxo().get(txid, vout, e)){
                    // Transaction exists in chain (has unspent outputs)
                    std::map<std::string,JNode> o;
                    JNode tid; tid.v = txidhex; o["txid"] = tid;
                    JNode confirmed; confirmed.v = true; o["confirmed"] = confirmed;
                    JNode n; n.v = o; return json_dump(n);
                }
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
            if(mempool_.accept(tx, chain_.utxo(), static_cast<uint32_t>(tip.height), e)){
                // CRITICAL FIX: Broadcast transaction to P2P network
                // Without this, transactions only sit in local mempool and never propagate!
                if(p2p_) {
                    std::vector<uint8_t> txid = tx.txid();
                    // CRITICAL FIX: Store raw tx so we can serve it when peers request via gettx
                    // Without this, peers receive invtx, send gettx, but we have nothing to serve!
                    p2p_->store_tx_for_relay(txid, raw);
                    p2p_->broadcast_inv_tx(txid);
                }
                JNode r; r.v = std::string(to_hex(tx.txid())); return json_dump(r);
            } else {
                return err(e);
            }
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

            // Build a small success object
            std::map<std::string,JNode> o;
            o["accepted"] = jbool(true);
            o["hash"]     = jstr(to_hex(b.block_hash()));
            o["height"]   = jnum((double)chain_.tip().height);
            JNode out; out.v = o; return json_dump(out);
        }

        // Miner stats
        if(method=="getminerstats"){
            using clock = std::chrono::steady_clock;
            static clock::time_point prev = clock::now();

            const uint64_t hashes = miner_hashes_snapshot_and_reset();
            const auto now = clock::now();
            double secs = std::chrono::duration<double>(now - prev).count();
            if (secs <= 0) secs = 1e-9;
            prev = now;

            const double hps = double(hashes) / secs;
            const uint64_t total = miner_hashes_total();

            std::map<std::string,JNode> o;
            JNode jh; jh.v = (double)hashes;         o["hashes"]  = jh;
            JNode js; js.v = secs;                   o["seconds"] = js;
            JNode jj; jj.v = hps;                    o["hps"]     = jj;
            JNode jt; jt.v = (double)total;          o["total"]   = jt;

            JNode out; out.v = o; return json_dump(out);
        }

        // ---------------- address UTXO lookup (for mobile/GUI) ----------------
        if (method == "getaddressutxos") {
            // Expect params = ["<Base58Check-P2PKH>"]
            auto itParams = obj.find("params");
            if (itParams == obj.end() ||
                !std::holds_alternative<std::vector<JNode>>(itParams->second.v))
                return err("usage: getaddressutxos <address>");

            auto& ps = std::get<std::vector<JNode>>(itParams->second.v);
            if (ps.size() != 1 || !std::holds_alternative<std::string>(ps[0].v))
                return err("usage: getaddressutxos <address>");

            const std::string addr = std::get<std::string>(ps[0].v);

            // Decode address
            uint8_t ver = 0; std::vector<uint8_t> payload;
            if (!base58check_decode(addr, ver, payload))
                return err("bad address");
            if (ver != VERSION_P2PKH || payload.size() != 20)
                return err("bad address");

            // Query UTXO set
            auto entries = chain_.utxo().list_for_pkh(payload);

            // Build array of objects
            std::vector<JNode> arr;
            arr.reserve(entries.size());
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
                JNode n; n.v = o; arr.push_back(n);
            }
            JNode out; out.v = arr; return json_dump(out);
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

        // --- getwalletinfo (unlocked status + meta if readable) ---
        if (method == "getwalletinfo") {
            std::map<std::string,JNode> o;
            o["unlocked"]          = jbool(wallet_is_unlocked());
            o["unlocked_until_ms"] = jnum((double)g_pass_expires_ms);

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
                        if (curH + 1 < mature_h) { // next block height still < mature
                            spendable = false;
                            mat_in = mature_h - (curH + 1);
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
                        if (ou.e.coinbase) {
                            uint64_t m_h = ou.e.height + COINBASE_MATURITY;
                            if (curH + 1 < m_h) {
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

            if (owned_all.empty()) return err("no funds");

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
            if(mempool_.accept(tx, chain_.utxo(), static_cast<uint32_t>(tip.height), e)){
                // CRITICAL FIX: Broadcast transaction to P2P network
                // Without this, transactions only sit in local mempool and never propagate!
                if(p2p_) {
                    std::vector<uint8_t> txid = tx.txid();
                    p2p_->broadcast_inv_tx(txid);
                }
                if (used_change) {
                    HdAccountMeta newm = w.meta();
                    newm.next_change = meta.next_change + 1;
                    if(!SaveHdWallet(wdir, seed, newm, pass, e)) {
                        log_warn(std::string("sendfromhd: SaveHdWallet failed: ") + e);
                    }
                }
                JNode r; r.v = std::string(to_hex(tx.txid())); return json_dump(r);
            } else {
                return err(e);
            }
        }

        // ---------------- chain-related helpers ----------------

        if(method=="estimatemediantime"){
            auto hdrs = chain_.last_headers(11);
            if(hdrs.empty()){
                return json_dump(jnum(0.0));
            }
            std::vector<int64_t> ts;
            ts.reserve(hdrs.size());
            for(auto& p : hdrs) ts.push_back(p.first);
            std::sort(ts.begin(), ts.end());
            double mtp = (double)ts[ts.size()/2];
            return json_dump(jnum(mtp));
        }

        if(method=="getdifficulty"){
            double d = (double)Chain::work_from_bits_public(chain_.tip().bits);
            return json_dump(jnum(d));
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

        // ---------------- p2p stubs ----------------

        if(method=="getpeerinfo"){
            std::vector<JNode> v; JNode out; out.v = v; return json_dump(out);
        }

        if(method=="getconnectioncount"){
            return json_dump(jnum(0.0));
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
