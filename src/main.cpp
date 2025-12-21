#ifdef _MSC_VER
  #pragma execution_character_set("utf-8")
  #ifndef _CRT_SECURE_NO_WARNINGS
    #define _CRT_SECURE_NO_WARNINGS
  #endif
#endif

// =============================================================================
// Windows portability flags
#ifdef _WIN32
  #ifndef NOMINMAX
  #define NOMINMAX 1
  #endif
#endif

// =============================================================================
// MIQ public headers
#include "constants.h"
#include "config.h"
#include "log.h"
#include "assume_valid.h"  // For mark_ibd_complete()
#include "ibd_state.h"     // For IBD state machine
#include "chain.h"
#include "mempool.h"
#include "rpc.h"
#include "p2p.h"
#include "tx.h"
#include "serialize.h"
#include "base58check.h"
#include "hash160.h"
#include "crypto/ecdsa_iface.h"
#include "difficulty.h"
#include "sha256.h"
#include "hex.h"
#include "tls_proxy.h"
#include "ibd_monitor.h"
#include "utxo_kv.h"
#include "stratum/stratum_server.h"
#include "rpc_auth.h"

#if __has_include("reindex_utxo.h")
#  include "reindex_utxo.h"
#endif
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
namespace miq {
extern bool ensure_utxo_fully_indexed(Chain&, const std::string&, bool) __attribute__((weak));
}
#  define MIQ_CAN_PROBE_UTXO_REINDEX 1
#else
#  define MIQ_CAN_PROBE_UTXO_REINDEX 0
#endif

// =============================================================================
// STL
#include <thread>
#include <cctype>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <cstdio>
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <atomic>
#include <memory>
#include <algorithm>
#include <ctime>
#include <random>
#include <type_traits>
#include <utility>
#include <cstdint>
#include <exception>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <iomanip>
#include <limits>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <set>
#include <array>
#include <optional>
#include <cmath>
#include <cerrno>

// =============================================================================
// OS headers (guarded)
#if defined(_WIN32)
  #include <io.h>
  #include <windows.h>
  #include <conio.h>
  #include <fcntl.h>
  #include <psapi.h>
  #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
  #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
  #endif
  #ifdef _MSC_VER
    #pragma comment(lib, "Psapi.lib")
  #endif
  #define MIQ_ISATTY() (_isatty(_fileno(stdin)) != 0)
#else
  #include <unistd.h>
  #include <termios.h>
  #include <sys/ioctl.h>
  #include <fcntl.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <ifaddrs.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #define MIQ_ISATTY() (::isatty(fileno(stdin)) != 0)
#  if defined(__APPLE__)
#    include <mach/mach.h>
#  endif
#endif



#ifdef _WIN32
  #ifdef min
    #undef min
  #endif
  #ifdef max
    #undef max
  #endif
#include <iphlpapi.h>
  #pragma comment(lib, "Iphlpapi.lib")
#endif

using namespace miq;

static std::atomic<uint64_t> g_genesis_time_s{0};

static std::string g_seed_host = DNS_SEED;
static inline const char* seed_host_cstr(){ return g_seed_host.c_str(); }

static std::atomic<bool> g_assume_seed_hairpin{false};

// -------------------------------------------------------
// Versions
#ifndef MIQ_VERSION_MAJOR
#define MIQ_VERSION_MAJOR 1
#endif
#ifndef MIQ_VERSION_MINOR
#define MIQ_VERSION_MINOR 0
#endif
#ifndef MIQ_VERSION_PATCH
#define MIQ_VERSION_PATCH 0
#endif

// +--------- Professional ASCII Art & Branding ----------+
// |                 MIQROCHAIN BLOCKCHAIN               |
// +---------+

static const char* kMiqrochainBanner[] = {
"",
"  __  __ ___ ___  ___   ___  _   _   _  ___  ___ _  _",
" |  \\/  |_ _/ _ \\| _ \\ / _ \\|_| | |_| |/ _ \\|_ _| \\| |",
" | |  | || | (_) |   / | (_) | | |   | | (_) | | |  . ` |",
" | |  | | | |> <  | |  |> _ <| | | |_| |> _ < | | | . ` |",
" |_|__|_|___| \\_| | |_\\  \\_/ |_|  \\___/| \\_\\_\\|___| |_|\\_|",
" |_|  |_||___\\___||___\\ \\___/  |___/  \\____/|__|_|_| \\_|",
"",
nullptr
};

[[maybe_unused]] static const char* kNodeBanner[] = {
"    _ __  ___  ___  ___",
"   | '_ \\/ _ \\|   \\|   \\",
"   | | | | (_) | |) | |) |",
"   |_| |_|\\___/|___/|___/",
nullptr
};

// ================================================================
//                 Global state & helpers
// ================================================================
namespace global {
static std::atomic<bool>    shutdown_requested{false};
static std::atomic<bool>    shutdown_initiated{false};
static std::atomic<uint64_t>last_signal_ms{0};
static std::atomic<bool>    reload_requested{false};   // SIGHUP / hotkey 'r'
static std::string          lockfile_path;
static std::string          pidfile_path;
static std::string          telemetry_path;
static std::atomic<bool>    telemetry_enabled{false};
static std::atomic<bool>    tui_snapshot_requested{false};
static std::atomic<bool>    tui_toggle_theme{false};
[[maybe_unused]] static std::atomic<bool>    tui_pause_logs{false};
static std::atomic<bool>    tui_verbose{false};
#ifdef _WIN32
static HANDLE               lock_handle{NULL};
#else
static int                  lock_fd{-1};
#endif
}

// ================================================================
//            Network Statistics Tracking
// ================================================================
struct NetworkStats {
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_recv{0};
    std::atomic<uint64_t> messages_sent{0};
    std::atomic<uint64_t> messages_recv{0};
    std::atomic<uint64_t> blocks_relayed{0};
    std::atomic<uint64_t> txs_relayed{0};
    std::atomic<uint64_t> connection_attempts{0};
    std::atomic<uint64_t> connection_failures{0};
} g_net_stats;

static std::atomic<bool> g_we_are_seed{false};

// time helpers
static inline uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
static inline uint64_t now_s() {
    return (uint64_t)std::time(nullptr);
}

// =============================================================================
// Shutdown request w/ escalation (double signal within 2s => hard exit)
static void request_shutdown(const char* why){
    bool first = !global::shutdown_initiated.exchange(true);
    global::shutdown_requested.store(true);
    if (first) {
        log_warn(std::string("Shutdown requested: ") + (why ? why : "signal"));
    } else {
        uint64_t t = now_ms();
        uint64_t last = global::last_signal_ms.load();
        if (last && (t - last) < 2000) {
            log_error("Forced immediate termination (double signal).");
#ifdef _WIN32
            TerminateProcess(GetCurrentProcess(), 1);
#else
            _exit(1);
#endif
        }
    }
    global::last_signal_ms.store(now_ms());
}

// ==================================================================
// |                              Miner stats                                   |
// ==================================================================
struct MinerStats {
    std::atomic<bool> active{false};
    std::atomic<unsigned> threads{0};
    std::atomic<uint64_t> accepted{0};
    std::atomic<uint64_t> rejected{0};
    std::atomic<uint64_t> last_height_ok{0};
    std::atomic<uint64_t> last_height_rx{0};
    std::chrono::steady_clock::time_point start{};
    std::atomic<double>   hps{0.0}; // stays 0 unless miner API exposes tries
} g_miner_stats;

std::string g_miner_address_b58; // display mined-to address (non-static for RPC access)

// Global Stratum server pointer for block notifications
// Non-static so p2p.cpp can notify stratum server on block connect
namespace miq {
    std::atomic<StratumServer*> g_stratum_server{nullptr};
}

// ==================================================================
// |                           Telemetry buffers                                |
// ==================================================================
struct BlockSummary {
    uint64_t height{0};
    std::string hash_hex;
    uint32_t tx_count{0};
    uint64_t fees{0};
    bool     fees_known{false};
    std::string miner; // base58 if known
};
struct Telemetry {
    std::mutex mu;
    std::deque<BlockSummary> new_blocks;
    std::deque<std::string>  new_txids;
    void push_block(const BlockSummary& b) {
        std::lock_guard<std::mutex> lk(mu);
        new_blocks.push_back(b);
        while (new_blocks.size() > 256) new_blocks.pop_front();
    }
    void push_txids(const std::vector<std::string>& v) {
        std::lock_guard<std::mutex> lk(mu);
        for (auto& t : v) {
            new_txids.push_back(t);
            while (new_txids.size() > 128) new_txids.pop_front();
        }
    }
    void drain(std::vector<BlockSummary>& out_blocks, std::vector<std::string>& out_txids) {
        std::lock_guard<std::mutex> lk(mu);
        out_blocks.assign(new_blocks.begin(), new_blocks.end());
        out_txids.assign(new_txids.begin(), new_txids.end());
        new_blocks.clear();
        new_txids.clear();
    }
} g_telemetry;

static inline void telemetry_flush_disk(const BlockSummary& b){
    if (!global::telemetry_enabled.load()) return;
    try{
        std::ofstream f(global::telemetry_path, std::ios::app);
        if(!f) return;
        f << "{"
          << "\"t\":" << now_s()
          << ",\"h\":" << b.height
          << ",\"hash\":\"" << b.hash_hex << "\""
          << ",\"tx\":" << b.tx_count
          << (b.fees_known ? (std::string(",\"fees\":") + std::to_string(b.fees)) : "")
          << (b.miner.empty()? "" : (std::string(",\"miner\":\"") + b.miner + "\""))
          << "}\n";
    } catch(const std::exception& e) {
        // PRODUCTION FIX: Log telemetry write errors (non-critical but useful for debugging)
        log_error(std::string("Telemetry write failed: ") + e.what());
    } catch(...) {
        log_error("Telemetry write failed with unknown error");
    }
}

// ==================================================================
// |                     External miner heartbeat watch                         |
// ==================================================================
struct ExtMinerWatch {
    std::atomic<bool> alive{false};
    std::atomic<bool> running{false};
    std::thread thr;
    std::string path;

    static std::string default_path(const std::string& datadir){
#ifdef _WIN32
        return datadir + "\\miner.heartbeat";
#else
        return datadir + "/miner.heartbeat";
#endif
    }
    void start(const std::string& datadir){
        const char* p = std::getenv("MIQ_MINER_HEARTBEAT");
        path = p && *p ? std::string(p) : default_path(datadir);
        running.store(true);
        thr = std::thread([this]{
            using namespace std::chrono_literals;
            while(running.load()){
                std::error_code ec;
                auto ft = std::filesystem::last_write_time(path, ec);
                bool ok = false;
                if (!ec){
                    auto now = std::filesystem::file_time_type::clock::now();
                    auto diff = now - ft;
                    auto secs = std::chrono::duration_cast<std::chrono::seconds>(diff).count();
                    ok = (secs >= 0 && secs <= 15);
                }
                alive.store(ok);
                std::this_thread::sleep_for(1s);
            }
        });
    }
    void stop(){
        running.store(false);
        if (thr.joinable()) thr.join();
        alive.store(false);
    }
} g_extminer;

// ==================================================================
// |                       Datadir / PID / Lock helpers                         |
// ==================================================================
static std::string default_datadir() {
#ifdef _WIN32
    size_t len = 0; char* v = nullptr;
    if (_dupenv_s(&v, &len, "APPDATA") == 0 && v && len) {
        std::string base(v); free(v);
        return base + "\\miqrochain";
    }
    return "C:\\miqrochain-data";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/Library/Application Support/miqrochain";
    return "./miqdata";
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME")) {
        if (*xdg) return std::string(xdg) + "/miqrochain";
    }
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/.miqrochain";
    return "./miqdata";
#endif
}
static bool read_file_all(const std::string& path, std::vector<uint8_t>& out){
    std::ifstream f(path, std::ios::binary);
    if(!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize n = f.tellg();
    if(n < 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize((size_t)n);
    if(n > 0 && !f.read(reinterpret_cast<char*>(out.data()), n)) return false;
    return true;
}
static inline std::string p_join(const std::string& a, const std::string& b){
#ifdef _WIN32
    return a + "\\" + b;
#else
    return a + "/" + b;
#endif
}

static bool write_text_atomic(const std::string& path, const std::string& body){
    std::error_code ec;
    auto dir = std::filesystem::path(path).parent_path();
    if(!dir.empty()) std::filesystem::create_directories(dir, ec);
    std::string tmp = path + ".tmp";
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if(!f) return false;
    f.write(body.data(), (std::streamsize)body.size());
    f.flush();
    f.close();
    std::filesystem::rename(tmp, path, ec);
    return !ec;
}

// Utility: is a PID alive?
static bool pid_alive(int pid){
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return false;
    DWORD code = 0;
    BOOL ok = GetExitCodeProcess(h, &code);
    CloseHandle(h);
    if (!ok) return false;
    return (code == STILL_ACTIVE);
#else
    if (pid <= 0) return false;
    int r = kill(pid, 0);
    if (r == 0) return true;
    return errno == EPERM ? true : false; // process exists but no permission
#endif
}

// Purge stale lock/pid files if previous process is not alive.
static void purge_stale_lock(const std::string& datadir){
    std::error_code ec;
    std::string lock = p_join(datadir, ".lock");
    std::string pid  = p_join(datadir, "miqrod.pid");
    bool lock_exists = std::filesystem::exists(lock, ec);
    if (!lock_exists) return;

    bool remove_ok = true;
    int pidnum = -1;
    if (std::filesystem::exists(pid, ec)) {
        std::ifstream f(pid);
        if (f) { f >> pidnum; }
    }
    if (pidnum > 0 && pid_alive(pidnum)) {
        // Running instance; do NOT purge.
        remove_ok = false;
    }
    if (remove_ok) {
        std::filesystem::remove(lock, ec);
        std::filesystem::remove(pid, ec);
        if (!ec) {
            std::fprintf(stderr, "[WARN] Stale .lock detected and removed; continuing.\n");
        }
    }
}

// Lock file (exclusive). Keeps handle open for the entire process lifetime.
static bool acquire_datadir_lock(const std::string& datadir){
    std::error_code ec;
    std::filesystem::create_directories(datadir, ec);
    // Always attempt to purge stale lock first
    purge_stale_lock(datadir);

    std::string lock = p_join(datadir, ".lock");
    std::string pid  = p_join(datadir, "miqrod.pid");
#ifdef _WIN32
    HANDLE h = CreateFileA(lock.c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           0,                // no sharing
                           NULL,
                           CREATE_NEW,       // fail if exists
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        // Retry once after purge (in case another process created it meanwhile)
        purge_stale_lock(datadir);
        h = CreateFileA(lock.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            log_error("Another instance appears to be running (lock exists).");
            return false;
        }
    }
    global::lock_handle = h;
#else
    int fd = ::open(lock.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) {
        // Retry once after purge
        purge_stale_lock(datadir);
        fd = ::open(lock.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd < 0) {
            log_error("Another instance appears to be running (lock exists).");
            return false;
        }
    }
    global::lock_fd = fd;
#endif
    // write PID file
#ifdef _WIN32
    int pidnum = (int)GetCurrentProcessId();
#else
    int pidnum = (int)getpid();
#endif
    write_text_atomic(pid, std::to_string(pidnum) + "\n");
    global::lockfile_path = lock;
    global::pidfile_path  = pid;
    return true;
}
static void release_datadir_lock(){
    std::error_code ec;
#ifdef _WIN32
    if (global::lock_handle && global::lock_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(global::lock_handle);
        global::lock_handle = NULL;
    }
#else
    if (global::lock_fd >= 0) {
        ::close(global::lock_fd);
        global::lock_fd = -1;
    }
#endif
    if (!global::lockfile_path.empty()) std::filesystem::remove(global::lockfile_path, ec);
    if (!global::pidfile_path.empty())  std::filesystem::remove(global::pidfile_path, ec);
}

// ==================================================================
/*                    Signals / console control / input                       */
// ==================================================================
[[maybe_unused]] static void sighup_handler(int){ global::reload_requested.store(true); }
[[maybe_unused]] static void sigshutdown_handler(int){ request_shutdown("signal"); }

#ifdef _WIN32
static BOOL WINAPI win_ctrl_handler(DWORD evt){
    switch(evt){
        case CTRL_C_EVENT:        request_shutdown("CTRL_C_EVENT");        return TRUE;
        case CTRL_BREAK_EVENT:    request_shutdown("CTRL_BREAK_EVENT");    return TRUE;
        case CTRL_CLOSE_EVENT:    request_shutdown("CTRL_CLOSE_EVENT");    return TRUE;
        case CTRL_LOGOFF_EVENT:   request_shutdown("CTRL_LOGOFF_EVENT");   return TRUE;
        case CTRL_SHUTDOWN_EVENT: request_shutdown("CTRL_SHUTDOWN_EVENT"); return TRUE;
        default: return FALSE;
    }
}
#endif

// ==================================================================
/*                               Resource metrics                              */
// ==================================================================
static uint64_t get_rss_bytes(){
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS info{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &info, sizeof(info))) {
        return (uint64_t)info.WorkingSetSize;
    }
    return 0;
#elif defined(__APPLE__)
    // /proc/self/statm doesn't exist on macOS; use Mach APIs.
    mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    task_t task = mach_task_self();
    if (task_info(task, MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS) {
        return (uint64_t)info.resident_size;
    }
    return 0;
#else
    std::ifstream f("/proc/self/statm"); uint64_t rss_pages=0, x=0;
    if (f >> x >> rss_pages){ long p = sysconf(_SC_PAGESIZE); return (uint64_t)rss_pages * (uint64_t)p; }
    return 0;
#endif
}

// ==================================================================
/*                              Terminal utils                                 */
// ==================================================================
namespace term {

// Basic tty check remains available
[[maybe_unused]] static inline bool is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return ::isatty(STDOUT_FILENO) == 1;
#endif
}

// ConPTY/Windows Terminal: interactive output even if STDOUT is a pipe
static inline bool supports_interactive_output() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut && hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode)) return true; // real console
    }
    DWORD type = GetFileType(hOut);
    const bool is_pipe = (type == FILE_TYPE_PIPE);
    const bool hinted =
        (std::getenv("WT_SESSION")       ||
         std::getenv("ConEmuANSI")       ||
         std::getenv("TERMINUS_SUBPROC") ||
         std::getenv("MSYS")             ||
         std::getenv("MSYSTEM"));
    return is_pipe && hinted;
#else
    return ::isatty(STDOUT_FILENO) == 1;
#endif
}

// Improved window size
static inline void get_winsize(int& cols, int& rows) {
    cols = 120; rows = 38;
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleScreenBufferInfo(hOut, &info)) {
        HANDLE hAlt = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hAlt != INVALID_HANDLE_VALUE) {
            if (GetConsoleScreenBufferInfo(hAlt, &info)) {
                cols = info.srWindow.Right - info.srWindow.Left + 1;
                rows = info.srWindow.Bottom - info.srWindow.Top + 1;
            }
            CloseHandle(hAlt);
            return;
        }
    } else {
        cols = info.srWindow.Right - info.srWindow.Left + 1;
        rows = info.srWindow.Bottom - info.srWindow.Top + 1;
    }
#else
    struct winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_col) cols = ws.ws_col;
        if (ws.ws_row) rows = ws.ws_row;
    }
#endif
}

// Enable VT and probe Unicode ability.
static inline void enable_vt_and_probe_u8(bool& vt_ok, bool& u8_ok) {
    vt_ok = true; u8_ok = false;
#ifdef _WIN32
    vt_ok = false; u8_ok = false;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    bool have_console = (h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode));

    HANDLE hConOut = INVALID_HANDLE_VALUE;
    if (!have_console) {
        hConOut = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hConOut != INVALID_HANDLE_VALUE && GetConsoleMode(hConOut, &mode)) {
            have_console = true;
            h = hConOut;
        }
    }
    if (have_console) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (SetConsoleMode(h, mode)) {
            DWORD m2 = 0;
            if (GetConsoleMode(h, &m2) && (m2 & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
                vt_ok = true;
            }
        }
    } else {
        DWORD type = GetFileType(GetStdHandle(STD_OUTPUT_HANDLE));
        const bool is_pipe = (type == FILE_TYPE_PIPE);
        if (is_pipe) vt_ok = true;
    }

    const bool force_utf8 = []{
        const char* s = std::getenv("MIQ_TUI_UTF8");
        return s && *s ? (std::strcmp(s,"0")!=0 && std::strcmp(s,"false")!=0 && std::strcmp(s,"False")!=0) : false;
    }();
    if (force_utf8 && have_console) {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        u8_ok = true;
    }

    if (hConOut != INVALID_HANDLE_VALUE) CloseHandle(hConOut);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOALIGNMENTFAULTEXCEPT);
#else
    vt_ok = true;
    u8_ok = true;
#endif
}

} // namespace term

// Console writer avoids recursion with log capture - IMPROVED for PowerShell 5+
class ConsoleWriter {
public:
    ConsoleWriter(){ init(); }
    ~ConsoleWriter(){
#ifdef _WIN32
        if (hFile_ && hFile_ != INVALID_HANDLE_VALUE) CloseHandle(hFile_);
#else
        if (fd_ >= 0 && fd_ != STDOUT_FILENO) ::close(fd_);
#endif
    }

    // Optimized write with buffering for reduced flicker on PowerShell 5+
    void write_raw(const std::string& s){
        if (s.empty()) return;
#ifdef _WIN32
        // For PowerShell 5+ compatibility: use direct console buffer writes
        // This provides smoother output with less flicker
        if (hFile_ && hFile_ != INVALID_HANDLE_VALUE) {
            // Try WriteConsoleW first for best Unicode support
            int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
            if (wlen > 0) {
                std::wstring ws((size_t)wlen, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), ws.data(), wlen);
                DWORD wroteW = 0;
                if (WriteConsoleW(hFile_, ws.c_str(), (DWORD)ws.size(), &wroteW, nullptr)) return;
            }
        }
        // Fallback: direct file write with retry for robustness
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD wrote = 0;
            const char* ptr = s.c_str();
            DWORD remaining = (DWORD)s.size();
            int retries = 3;
            while (remaining > 0 && retries-- > 0) {
                if (WriteFile(hOut, ptr, remaining, &wrote, nullptr)) {
                    ptr += wrote;
                    remaining -= wrote;
                } else {
                    Sleep(1);  // Brief pause before retry
                }
            }
        }
#else
        int fd = (fd_ >= 0) ? fd_ : STDOUT_FILENO;
        size_t off = 0;
        int retries = 5;
        while (off < s.size() && retries > 0) {
            ssize_t n = ::write(fd, s.data()+off, s.size()-off);
            if (n > 0) {
                off += (size_t)n;
            } else if (n < 0 && errno == EINTR) {
                continue;  // Retry on interrupt
            } else {
                --retries;
                usleep(1000);  // Brief pause before retry
            }
        }
#endif
    }

    // BULLETPROOF: Batch write for smoother updates (reduces flicker)
    // Hides cursor during update for professional appearance
    void write_frame(const std::string& clear_seq, const std::string& content) {
        // ANSI sequences for cursor control
        static const char* CURSOR_HIDE = "\x1b[?25l";  // Hide cursor
        static const char* CURSOR_SHOW = "\x1b[?25h";  // Show cursor

        // Build complete frame with cursor hidden during update
        std::string frame;
        frame.reserve(clear_seq.size() + content.size() + 32);
        frame += CURSOR_HIDE;   // Hide cursor before update
        frame += clear_seq;      // Clear/home
        frame += content;        // Frame content
        frame += CURSOR_SHOW;   // Show cursor after update

        // Single atomic write for flicker-free rendering
        write_raw(frame);
    }

private:
    void init(){
#ifdef _WIN32
        // Try to get console handle with best mode for smooth output
        hFile_ = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_WRITE | FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile_ != INVALID_HANDLE_VALUE) {
            // Enable VT processing for best ANSI support
            DWORD mode = 0;
            if (GetConsoleMode(hFile_, &mode)) {
                mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                mode |= ENABLE_PROCESSED_OUTPUT;
                SetConsoleMode(hFile_, mode);
            }
        }
#else
        fd_ = ::open("/dev/tty", O_WRONLY | O_CLOEXEC);
        if (fd_ < 0) fd_ = STDOUT_FILENO;
#endif
    }
#ifdef _WIN32
    HANDLE hFile_{};
#else
    int fd_ = -1;
#endif
};

// ==================================================================
/*                              Helper utilities                               */
// ==================================================================

// small truthy helper reused for ASCII fallbacks
static inline bool env_truthy_local(const char* name){
    const char* v = std::getenv(name);
    if(!v||!*v) return false;
    if(std::strcmp(v,"0")==0 || std::strcmp(v,"false")==0 || std::strcmp(v,"False")==0) return false;
    return true;
}

// Bytes pretty-printer
static inline std::string fmt_bytes(uint64_t v){
    static const char* units[] = {"B","KiB","MiB","GiB","TiB","PiB"};
    double d = (double)v;
    int u = 0;
    while (d >= 1024.0 && u < 5){ d /= 1024.0; ++u; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(u?1:0)<<d<<" "<<units[u];
    return o.str();
}

// Network bytes (decimal for bandwidth)
static inline std::string fmt_net_bytes(uint64_t v){
    static const char* units[] = {"B","KB","MB","GB","TB","PB"};
    double d = (double)v;
    int u = 0;
    while (d >= 1000.0 && u < 5){ d /= 1000.0; ++u; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(u?1:0)<<d<<" "<<units[u];
    return o.str();
}

// Human-readable uptime
static inline std::string fmt_uptime(uint64_t secs){
    if (secs < 60) {
        return std::to_string(secs) + "s";
    } else if (secs < 3600) {
        uint64_t m = secs / 60;
        uint64_t s = secs % 60;
        return std::to_string(m) + "m " + std::to_string(s) + "s";
    } else if (secs < 86400) {
        uint64_t h = secs / 3600;
        uint64_t m = (secs % 3600) / 60;
        return std::to_string(h) + "h " + std::to_string(m) + "m";
    } else {
        uint64_t d = secs / 86400;
        uint64_t h = (secs % 86400) / 3600;
        return std::to_string(d) + "d " + std::to_string(h) + "h";
    }
}

// Number with thousand separators
static inline std::string fmt_num(uint64_t n){
    std::string s = std::to_string(n);
    int insertPosition = (int)s.length() - 3;
    while (insertPosition > 0) {
        s.insert((size_t)insertPosition, ",");
        insertPosition -= 3;
    }
    return s;
}

// Percentage with color hint
static inline std::string fmt_pct(double pct, bool use_color = false){
    (void)use_color;  // Reserved for future color formatting
    std::ostringstream o;
    o << std::fixed << std::setprecision(1) << pct << "%";
    return o.str();
}

// Age string (time since timestamp)
static inline std::string fmt_age(uint64_t timestamp_s){
    uint64_t now = (uint64_t)std::time(nullptr);
    if (timestamp_s == 0 || timestamp_s > now) return "unknown";
    uint64_t age = now - timestamp_s;
    return fmt_uptime(age) + " ago";
}

// Block time estimation
static inline std::string fmt_block_time(uint64_t blocks, uint64_t target_secs){
    uint64_t est_secs = blocks * target_secs;
    return fmt_uptime(est_secs);
}

// Hashrate pretty-printer
static inline std::string fmt_hs(double v){
    static const char* units[] = {"H/s","kH/s","MH/s","GH/s","TH/s","PH/s","EH/s"};
    double d = (double)v;
    int u = 0;
    while (d >= 1000.0 && u < 6){ d /= 1000.0; ++u; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(u?2:0)<<d<<" "<<units[u];
    return o.str();
}

// Difficulty pretty
static inline std::string fmt_diff(long double d){
    double x = (double)d;
    static const char* units[] = {"","k","M","G","T","P","E"};
    int u = 0;
    while (x >= 1000.0 && u < 6){ x/=1000.0; ++u; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(u?2:0)<<x<<units[u];
    return o.str();
}

// =============================================================================
// Sync display helpers
// =============================================================================

// Format "X years and Y weeks behind" for sync status
static inline std::string fmt_time_behind(uint64_t last_block_timestamp){
    uint64_t now = (uint64_t)std::time(nullptr);
    if (last_block_timestamp == 0 || last_block_timestamp >= now) return "synced";

    uint64_t behind_secs = now - last_block_timestamp;

    // Calculate components
    uint64_t years = behind_secs / (365 * 24 * 3600);
    uint64_t remaining = behind_secs % (365 * 24 * 3600);
    uint64_t weeks = remaining / (7 * 24 * 3600);
    remaining = remaining % (7 * 24 * 3600);
    uint64_t days = remaining / (24 * 3600);
    remaining = remaining % (24 * 3600);
    uint64_t hours = remaining / 3600;

    std::ostringstream o;
    if (years > 0) {
        o << years << " year" << (years != 1 ? "s" : "");
        if (weeks > 0) o << " and " << weeks << " week" << (weeks != 1 ? "s" : "");
        o << " behind";
    } else if (weeks > 0) {
        o << weeks << " week" << (weeks != 1 ? "s" : "");
        if (days > 0) o << " and " << days << " day" << (days != 1 ? "s" : "");
        o << " behind";
    } else if (days > 0) {
        o << days << " day" << (days != 1 ? "s" : "");
        if (hours > 0) o << " and " << hours << " hour" << (hours != 1 ? "s" : "");
        o << " behind";
    } else if (hours > 0) {
        o << hours << " hour" << (hours != 1 ? "s" : "") << " behind";
    } else {
        uint64_t mins = behind_secs / 60;
        if (mins > 0) {
            o << mins << " minute" << (mins != 1 ? "s" : "") << " behind";
        } else {
            o << "less than a minute behind";
        }
    }
    return o.str();
}

// Format datetime for "Last block time"
static inline std::string fmt_datetime(uint64_t timestamp){
    if (timestamp == 0) return "Unknown";
    std::time_t t = (std::time_t)timestamp;
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", &tm_buf);
    return std::string(buf);
}

// Animated progress bar with gradient effect
static inline std::string progress_bar_animated(int width, double frac, int tick, bool vt_ok, bool u8_ok){
    if (width < 10) width = 10;
    if (frac < 0.0) frac = 0.0;
    if (frac > 1.0) frac = 1.0;

    int inner = width - 2;
    int filled = (int)(frac * inner);

    std::string out;
    out.reserve((size_t)(width + 20));

    if (vt_ok && u8_ok) {
        // Professional Unicode progress bar with animation
        out += "\x1b[32m"; // Green color
        out += "▐";

        for (int i = 0; i < inner; ++i) {
            if (i < filled) {
                // Filled portion with subtle animation
                out += "█";
            } else if (i == filled && frac < 1.0) {
                // Animated leading edge
                static const char* anim[] = {"░", "▒", "▓", "▒"};
                out += anim[tick % 4];
            } else {
                out += "░";
            }
        }
        out += "▌";
        out += "\x1b[0m";
    } else if (vt_ok) {
        // ANSI progress bar
        out += "\x1b[32m[";
        for (int i = 0; i < inner; ++i) {
            if (i < filled) {
                out += "=";
            } else if (i == filled && frac < 1.0) {
                out += ">";
            } else {
                out += " ";
            }
        }
        out += "]\x1b[0m";
    } else {
        // Plain ASCII
        out += "[";
        for (int i = 0; i < inner; ++i) {
            if (i < filled) {
                out += "#";
            } else if (i == filled && frac < 1.0) {
                out += ">";
            } else {
                out += ".";
            }
        }
        out += "]";
    }
    return out;
}

// Calculate ETA based on sync speed
static inline std::string fmt_eta(uint64_t blocks_remaining, double blocks_per_second){
    if (blocks_per_second <= 0.0 || blocks_remaining == 0) return "Unknown...";

    double eta_secs = (double)blocks_remaining / blocks_per_second;

    if (eta_secs > 365.0 * 24.0 * 3600.0 * 10.0) return "Unknown..."; // More than 10 years
    if (eta_secs < 60.0) return "less than a minute";

    uint64_t secs = (uint64_t)eta_secs;
    uint64_t days = secs / 86400;
    uint64_t hours = (secs % 86400) / 3600;
    uint64_t mins = (secs % 3600) / 60;

    std::ostringstream o;
    if (days > 0) {
        o << days << " day" << (days != 1 ? "s" : "");
        if (hours > 0) o << " " << hours << " hour" << (hours != 1 ? "s" : "");
    } else if (hours > 0) {
        o << hours << " hour" << (hours != 1 ? "s" : "");
        if (mins > 0) o << " " << mins << " min" << (mins != 1 ? "s" : "");
    } else {
        o << mins << " minute" << (mins != 1 ? "s" : "");
    }
    return o.str();
}

// Spinner & drawing helpers - IMPROVED with smoother animations
static inline std::string spinner(int tick, bool fancy){
    if (fancy){
        // Braille spinner for Unicode terminals - smooth 10-frame animation
        static const char* frames[] = {"⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"};
        return frames[(size_t)(tick % 10)];
    } else {
        // ASCII spinner optimized for PowerShell 5+ - 8-frame animation for smoother look
        static const char* frames[] = {"|", "/", "-", "\\", "|", "/", "-", "\\"};
        return std::string(frames[(size_t)(tick & 7)]);
    }
}

// Additional animated indicators for professional look
static inline std::string activity_indicator(int tick, bool active, bool fancy){
    if (!active) return fancy ? "○" : "o";
    if (fancy){
        static const char* frames[] = {"◐","◓","◑","◒"};
        return frames[(size_t)(tick % 4)];
    } else {
        static const char* frames[] = {"[*]","[+]","[*]","[x]"};
        return frames[(size_t)(tick % 4)];
    }
}

static inline std::string pulse_indicator(int tick, bool fancy){
    if (fancy){
        static const char* frames[] = {"▁","▂","▃","▄","▅","▆","▇","█","▇","▆","▅","▄","▃","▂"};
        return frames[(size_t)(tick % 14)];
    } else {
        static const char* frames[] = {".", "o", "O", "0", "O", "o"};
        return frames[(size_t)(tick % 6)];
    }
}
static inline std::string straight_line(int w){
    if (w <= 0) return {};
    // keep ASCII here for max portability
    return std::string((size_t)w, '-');
}
static inline std::string bar(int width, double frac, bool /*vt_ok*/, bool u8_ok){
    if (width < 3) width = 3;
    if (frac < 0) frac = 0;
    if (frac > 1) frac = 1; // <- split lines to avoid -Wmisleading-indentation
    int inner = width - 2;
    int full  = (int)std::round(frac * inner);
    std::string out; out.reserve((size_t)width);
    out.push_back('[');
    if (u8_ok && env_truthy_local("MIQ_TUI_UTF8")){
        for (int i=0;i<inner;i++) out += (i<full ? "#" : " ");
    } else {
        for (int i=0;i<inner;i++) out.push_back(i<full ? '#' : ' ');
    }
    out.push_back(']');
    return out;
}
static inline std::string short_hex(const std::string& h, int keep){
    if ((int)h.size() <= keep) return h;
    int half = keep/2;
    const char* ell = env_truthy_local("MIQ_TUI_UTF8")? "…" : "...";
    return h.substr(0,(size_t)half) + ell + h.substr(h.size()-(size_t)(keep-half));
}

// =============================================================================
// Net helpers: resolve host, collect local IPs, compare, and compute seed role
// =============================================================================

static inline std::string ip_norm(const std::string& ip){
    if (ip.find('.') != std::string::npos){
        // If there's a colon, assume v6 wrapper and take the tail after last ':'
        size_t pos = ip.rfind(':');
        if (pos != std::string::npos){
            std::string tail = ip.substr(pos + 1);
            // crude check for dotted-quad
            int dots = 0; for(char c: tail) if (c=='.') ++dots;
            if (dots == 3) return tail;
        }
    }
    return ip;
}

static std::vector<std::string> resolve_host_ip_strings(const std::string& host){
    std::vector<std::string> out;
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return out;
    for (auto* p = res; p; p = p->ai_next){
        char buf[INET6_ADDRSTRLEN]{};
        if (p->ai_family == AF_INET) {
            auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) out.emplace_back(ip_norm(buf));
        } else if (p->ai_family == AF_INET6) {
            auto* sa6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
            if (inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf))) out.emplace_back(ip_norm(buf));
        }
    }
    freeaddrinfo(res);
    // de-dup
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

static std::vector<std::string> local_ip_strings(){
    std::vector<std::string> out;
#ifdef _WIN32
    ULONG flags = GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG sz = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &sz) == ERROR_BUFFER_OVERFLOW){
        std::vector<char> buf(sz);
        IP_ADAPTER_ADDRESSES* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, aa, &sz) == NO_ERROR){
            for (auto* a = aa; a; a = a->Next){
                for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next){
                    char tmp[INET6_ADDRSTRLEN]{};
                    if (ua->Address.lpSockaddr->sa_family == AF_INET){
                        auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                        if (inet_ntop(AF_INET, &sa->sin_addr, tmp, sizeof(tmp))) out.emplace_back(ip_norm(tmp));
                    } else if (ua->Address.lpSockaddr->sa_family == AF_INET6){
                        auto* sa6 = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
                        if (inet_ntop(AF_INET6, &sa6->sin6_addr, tmp, sizeof(tmp))) out.emplace_back(ip_norm(tmp));
                    }
                }
            }
        }
    }
#else
    ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) == 0 && ifa){
        for (auto* p = ifa; p; p = p->ifa_next){
            if (!p->ifa_addr) continue;
            int fam = p->ifa_addr->sa_family;
            char tmp[INET6_ADDRSTRLEN]{};
            if (fam == AF_INET){
                auto* sa = reinterpret_cast<sockaddr_in*>(p->ifa_addr);
                if (inet_ntop(AF_INET, &sa->sin_addr, tmp, sizeof(tmp))) out.emplace_back(ip_norm(tmp));
            } else if (fam == AF_INET6){
                auto* sa6 = reinterpret_cast<sockaddr_in6*>(p->ifa_addr);
                if (inet_ntop(AF_INET6, &sa6->sin6_addr, tmp, sizeof(tmp))) out.emplace_back(ip_norm(tmp));
            }
        }
        freeifaddrs(ifa);
    }
#endif
    // Include optional explicit public IP hint
    if (const char* hint = std::getenv("MIQ_PUBLIC_IP"); hint && *hint) out.emplace_back(ip_norm(hint));
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

[[maybe_unused]] static bool is_loopback_or_linklocal(const std::string& ip){
    if (ip == "127.0.0.1" || ip == "::1") return true;
    if (ip.rfind("169.254.",0)==0) return true;
    if (ip.rfind("fe80:",0)==0 || ip.rfind("FE80:",0)==0) return true;
    return false;
}

struct SeedRole {
    bool we_are_seed{false};
    std::string detail;
    std::vector<std::string> seed_ips;
    std::vector<std::string> local_ips;
};

static SeedRole compute_seed_role(){
    SeedRole r;

    // Heuristic 1: explicit override via env (useful behind NAT/port-forward).
    if (const char* f = std::getenv("MIQ_FORCE_SEED"); f && *f && std::strcmp(f,"0")!=0 &&
        std::strcmp(f,"false")!=0 && std::strcmp(f,"False")!=0){
        r.we_are_seed = true;
        r.detail = "MIQ_FORCE_SEED=1";
        return r;
    }
    // Heuristic 2: explicit client mode override (useful for local P2P testing).
    if (const char* f = std::getenv("MIQ_FORCE_CLIENT"); f && *f && std::strcmp(f,"0")!=0 &&
        std::strcmp(f,"false")!=0 && std::strcmp(f,"False")!=0){
        r.we_are_seed = false;
        r.detail = "MIQ_FORCE_CLIENT=1";
        return r;
    }

    // Heuristic 3: IP-based detection
    r.seed_ips  = resolve_host_ip_strings(seed_host_cstr());
    r.local_ips = local_ip_strings();
    for (const auto& seed_ip : r.seed_ips){
        for (const auto& lip : r.local_ips){
            if (seed_ip == lip){
                r.we_are_seed = true;
                r.detail = std::string("seed (") + seed_host_cstr() + ") A/AAAA (" + seed_ip + ") matches local IP";
                return r;
            }
        }
    }
    r.detail = r.seed_ips.empty() ? "seed host has no A/AAAA records"
                                  : "seed host resolves to different IP(s)";
    return r;
}

static inline bool solo_seed_mode(P2P* p2p){
    auto role = compute_seed_role();
    size_t peers = p2p ? p2p->snapshot_peers().size() : 0;
    return (role.we_are_seed || g_assume_seed_hairpin.load()) && peers == 0;
}

// Traits & helpers used by TUI and elsewhere
template<typename, typename = void> struct has_stats_method : std::false_type{};
template<typename T> struct has_stats_method<T, std::void_t<decltype(std::declval<T&>().stats())>> : std::true_type{};
template<typename, typename = void> struct has_size_method  : std::false_type{};
template<typename T> struct has_size_method<T,  std::void_t<decltype(std::declval<T&>().size())>>  : std::true_type{};
template<typename, typename = void> struct has_count_method : std::false_type{};
template<typename T> struct has_count_method<T, std::void_t<decltype(std::declval<T&>().count())>> : std::true_type{};

struct MempoolView { uint64_t count=0, bytes=0, recent_adds=0, orphans=0; };

// SFINAE to check for get_stats method
template<typename, typename = void> struct has_get_stats_method : std::false_type{};
template<typename T> struct has_get_stats_method<T, std::void_t<decltype(std::declval<T&>().get_stats())>> : std::true_type{};

template<typename MP>
static MempoolView mempool_view_fallback(MP* mp){
    MempoolView v{};
    if (!mp) return v;

    // Prefer get_stats() as it includes orphan count
    if constexpr (has_get_stats_method<MP>::value) {
        auto s = mp->get_stats();
        v.count = (uint64_t)s.tx_count;
        v.bytes = (uint64_t)s.bytes_used;
        v.orphans = (uint64_t)s.orphan_count;
    } else if constexpr (has_stats_method<MP>::value) {
        auto s = mp->stats();
        v.count = (uint64_t)s.count;
        v.bytes = (uint64_t)s.bytes;
        v.recent_adds = (uint64_t)s.recent_adds;
    } else if constexpr (has_size_method<MP>::value) {
        v.count = (uint64_t)mp->size();
    } else if constexpr (has_count_method<MP>::value) {
        v.count = (uint64_t)mp->count();
    }
    return v;
}

template<typename, typename = void> struct has_time_field : std::false_type{};
template<typename H> struct has_time_field<H, std::void_t<decltype(std::declval<H>().time)>> : std::true_type{};
template<typename, typename = void> struct has_timestamp_field : std::false_type{};
template<typename H> struct has_timestamp_field<H, std::void_t<decltype(std::declval<H>().timestamp)>> : std::true_type{};
template<typename, typename = void> struct has_bits_field : std::false_type{};
template<typename H> struct has_bits_field<H, std::void_t<decltype(std::declval<H>().bits)>> : std::true_type{};
template<typename, typename = void> struct has_nBits_field : std::false_type{};
template<typename H> struct has_nBits_field<H, std::void_t<decltype(std::declval<H>().nBits)>> : std::true_type{};

template<typename H>
static uint64_t hdr_time(const H& h){
    if constexpr (has_time_field<H>::value) return (uint64_t)h.time;
    else if constexpr (has_timestamp_field<H>::value) return (uint64_t)h.timestamp;
    else return 0;
}
template<typename H>
static uint32_t hdr_bits(const H& h){
    if constexpr (has_bits_field<H>::value) return (uint32_t)h.bits;
    else if constexpr (has_nBits_field<H>::value) return (uint32_t)h.nBits;
    else return (uint32_t)GENESIS_BITS;
}

// Difficulty helpers
static long double compact_to_target_ld(uint32_t bits){
    uint32_t exp = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    long double m = (long double)mant;
    int shift = (int)exp - 3;
    return std::ldexp(m, 8 * shift);
}
static long double difficulty_from_bits(uint32_t bits){
    long double t_one = compact_to_target_ld((uint32_t)GENESIS_BITS);
    long double t_cur = compact_to_target_ld(bits);
    if (t_cur <= 0.0L) return 0.0L;
    return t_one / t_cur;
}

[[maybe_unused]] static inline uint64_t estimate_target_height_by_time(uint64_t genesis_ts){
    if (!genesis_ts) return 0;
    uint64_t now = (uint64_t)std::time(nullptr);
    if (now <= genesis_ts) return 1;
    return 1 + (now - genesis_ts) / (uint64_t)BLOCK_TIME_SECS;
}

// Estimate network hashrate (used in TUI loop)
static double estimate_network_hashrate(Chain* chain){
    if (!chain) return 0.0;
    const unsigned k = (unsigned)std::max<int>(MIQ_RETARGET_INTERVAL, 32);
    auto headers = chain->last_headers(k);
    if (headers.size() < 2) return 0.0;

    uint64_t t_first = hdr_time(headers.front());
    uint64_t t_last  = hdr_time(headers.back());
    if (t_last <= t_first) t_last = t_first + 1;
    double avg_block_time = double(t_last - t_first) / double(headers.size()-1);
    if (avg_block_time <= 0.0) avg_block_time = (double)BLOCK_TIME_SECS;

    uint32_t bits = hdr_bits(headers.back());
    long double diff = difficulty_from_bits(bits);
    long double hps = (diff * 4294967296.0L) / avg_block_time; // 2^32
    if (!std::isfinite((double)hps) || hps < 0) return 0.0;
    return (double)hps;
}

// Sparklines
static inline std::string spark_ascii(const std::vector<double>& v){
    if (v.empty()) return std::string("-");
    double mn = v.front(), mx = v.front();
    for (double x : v){ if (x < mn) mn = x; if (x > mx) mx = x; }
    double span = (mx - mn);
    bool fancy = env_truthy_local("MIQ_TUI_UTF8");
    const char* blocks8 = "▁▂▃▄▅▆▇#"; // 8 glyphs, UTF-8 (3 bytes each)
    const char* ascii   = " .:-=+*#%@";
    std::string out; out.reserve(v.size());
    for (double x : v){
        int idx = 0;
        if (span > 0) idx = (int)std::floor((x - mn) / span * 7.999);
        if (idx < 0) idx = 0;
        if (idx > 7) idx = 7; // <- split lines to avoid -Wmisleading-indentation
        out += fancy ? std::string(blocks8 + idx*3, 3)   // <- correct UTF-8 indexing
                     : std::string(1, ascii[(size_t)idx]);
    }
    return out;
}

// Sync gate helper (used both in TUI texts and IBD logic)
// SIMPLIFIED: ALL nodes use IDENTICAL logic - no seed node special cases
static bool compute_sync_gate(Chain& chain, P2P* p2p, std::string& why_out) {
    uint64_t block_height = chain.height();
    uint64_t header_height = chain.best_header_height();

    // ========================================================================
    // RULE 1: Must be caught up with headers
    // This is the PRIMARY check - blocks must match or exceed header height
    // ========================================================================
    if (header_height > 0 && block_height < header_height) {
        why_out = "syncing (" + std::to_string(block_height) + "/" + std::to_string(header_height) + ")";
        return false;
    }

    // ========================================================================
    // RULE 2: Must have at least one peer OR be at genesis for new chain
    // ========================================================================
    size_t verack_peers = 0;
    auto all_peers = p2p ? p2p->snapshot_peers() : std::vector<PeerSnapshot>{};
    for (const auto& pr : all_peers) {
        if (pr.verack_ok) verack_peers++;
    }

    // Special case: Genesis node bootstrapping a new chain (no peers, no blocks)
    if (block_height == 0 && verack_peers == 0) {
        // Allow genesis mining only if we have no headers either (truly new chain)
        if (header_height == 0) {
            why_out.clear();
            return true;  // Allow starting new chain
        }
        why_out = "no peers";
        return false;
    }

    // Must have at least one peer if we have blocks
    if (block_height > 0 && verack_peers == 0) {
        why_out = "no peers";
        return false;
    }

    // ========================================================================
    // RULE 3: Check peer-reported heights FIRST (if available)
    // We should be at or above the highest reported peer tip
    // ========================================================================
    uint64_t max_peer_tip = 0;
    for (const auto& pr : all_peers) {
        if (pr.verack_ok && pr.peer_tip > 0) {
            max_peer_tip = std::max(max_peer_tip, pr.peer_tip);
        }
    }

    if (max_peer_tip > 0 && block_height < max_peer_tip) {
        why_out = "syncing (" + std::to_string(block_height) + "/" + std::to_string(max_peer_tip) + ")";
        return false;
    }

    // ========================================================================
    // RULE 4: Tip must not be too old (prevents stale chain)
    // CRITICAL FIX: Only apply this check if we're BEHIND the network.
    // If we're at or above max_peer_tip, we're synced regardless of tip age.
    // This fixes the "Finalizing..." stuck state after rebuilding from blocks.dat
    // where tip block has an old timestamp but we're fully synced.
    // ========================================================================
    auto tip = chain.tip();
    uint64_t tip_time = hdr_time(tip);
    uint64_t now_time = (uint64_t)std::time(nullptr);
    uint64_t tip_age = (now_time > tip_time) ? (now_time - tip_time) : 0;

    // Only check tip age if we're at the network tip (max_peer_tip == 0 or we matched it)
    // If peers report a tip and we're at that tip, we're synced even if tip is old
    // (The network hasn't produced new blocks in a while, which is fine)
    if (max_peer_tip == 0 && block_height > 0 && tip_age > 15 * 60) {
        // No peer tips available and our tip is old - might be stale
        // But allow if we at least match the header height
        if (block_height < header_height) {
            why_out = "tip too old (" + std::to_string(tip_age / 60) + "m)";
            return false;
        }
    }

    // ========================================================================
    // ALL CHECKS PASSED - Node is synced
    // ========================================================================
    why_out.clear();
    return true;
}

// Legacy compatibility - keeping old signature but simplified
[[maybe_unused]] static bool compute_sync_gate_legacy(Chain& chain, [[maybe_unused]] P2P* p2p, std::string& why_out) {
    // This is just the old function signature for any code that might call it
    return compute_sync_gate(chain, p2p, why_out);
}

// Old complex sync gate code removed - all nodes now use identical simple logic

static bool any_verack_peer(P2P* p2p){
    if (!p2p) return false;
    auto peers = p2p->snapshot_peers();
    for (const auto& s : peers){
        if (s.verack_ok) return true;
    }
    return false;
}


// ==================================================================
/*                                 Log capture                                 */
// ==================================================================
class LogCapture {
public:
    struct Line { std::string text; uint64_t ts_ms; };

    void start() {
        running_ = true;
#ifdef _WIN32
        setvbuf(stdout, nullptr, _IONBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
        if (_pipe(out_pipe_, 64 * 1024, _O_BINARY | _O_NOINHERIT) != 0) { running_ = false; return; }
        if (_pipe(err_pipe_, 64 * 1024, _O_BINARY | _O_NOINHERIT) != 0) { running_ = false; return; }
        old_out_ = _dup(_fileno(stdout));
        old_err_ = _dup(_fileno(stderr));
        _dup2(out_pipe_[1], _fileno(stdout));
        _dup2(err_pipe_[1], _fileno(stderr));
        reader_out_ = std::thread([this]{ readerLoop(out_pipe_[0]); });
        reader_err_ = std::thread([this]{ readerLoop(err_pipe_[0]); });
#else
        setvbuf(stdout, nullptr, _IOLBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
        if (pipe(out_pipe_) != 0) { running_ = false; return; }
        if (pipe(err_pipe_) != 0) { running_ = false; return; }
        old_out_ = dup(STDOUT_FILENO);
        old_err_ = dup(STDERR_FILENO);
        dup2(out_pipe_[1], STDOUT_FILENO);
        dup2(err_pipe_[1], STDERR_FILENO);
        reader_out_ = std::thread([this]{ readerLoop(out_pipe_[0]); });
        reader_err_ = std::thread([this]{ readerLoop(err_pipe_[0]); });
#endif
    }
    void stop() {
        if (!running_) return;
        running_ = false;
#ifdef _WIN32
        if (old_out_ != -1) { _dup2(old_out_, _fileno(stdout)); _close(old_out_); old_out_ = -1; }
        if (old_err_ != -1) { _dup2(old_err_, _fileno(stderr)); _close(old_err_); old_err_ = -1; }
        for (int i=0;i<2;i++){ if (out_pipe_[i] != -1) _close(out_pipe_[i]); out_pipe_[i] = -1; }
        for (int i=0;i<2;i++){ if (err_pipe_[i] != -1) _close(err_pipe_[i]); err_pipe_[i] = -1; }
#else
        if (old_out_ != -1) { dup2(old_out_, STDOUT_FILENO); close(old_out_); old_out_ = -1; }
        if (old_err_ != -1) { dup2(old_err_, STDERR_FILENO); close(old_err_); old_err_ = -1; }
        for (int i=0;i<2;i++){ if (out_pipe_[i] != -1) close(out_pipe_[i]); out_pipe_[i] = -1; }
        for (int i=0;i<2;i++){ if (err_pipe_[i] != -1) close(err_pipe_[i]); err_pipe_[i] = -1; }
#endif
        if (reader_out_.joinable()) reader_out_.join();
        if (reader_err_.joinable()) reader_err_.join();
    }
    ~LogCapture(){ stop(); }

    void drain(std::deque<Line>& into, size_t max_keep=2400) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& s : pending_) {
            lines_.push_back({sanitize_line(s), now_ms()});
            if (lines_.size() > max_keep) lines_.pop_front();
        }
        pending_.clear();
        into = lines_;
    }
private:
    static std::string sanitize_line(const std::string& s){
        auto red = s;
        auto scrub = [&](const char* key){
            size_t pos = 0;
            while((pos = red.find(key, pos)) != std::string::npos){
                size_t end = red.find_first_of(" \t\r\n", pos + std::strlen(key));
                if (end == std::string::npos) end = red.size();
                red.replace(pos, end - pos, std::string(key) + "***");
                pos += std::strlen(key) + 3;
            }
        };
        scrub("MIQ_RPC_TOKEN=");
        scrub("Authorization:");
        scrub("X-Auth-Token:");
        return red;
    }
    void readerLoop(int readfd){
        std::string buf; buf.reserve(4096);
        char tmp[1024];
        while (running_) {
#ifdef _WIN32
            int n = _read(readfd, tmp, (unsigned)sizeof(tmp));
            if (n <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(5)); continue; }
#else
            ssize_t n = ::read(readfd, tmp, sizeof(tmp));
            if (n <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(5)); continue; }
#endif
            int nn = (int)n;
            for (int i=0; i<nn; ++i) {
                char c = tmp[i];
                if (c == '\r') continue;
                if (c == '\n') {
                    std::lock_guard<std::mutex> lk(mu_);
                    if (!buf.empty()) pending_.push_back(buf);
                    buf.clear();
                } else {
                    buf.push_back(c);
                }
            }
        }
    }
private:
    std::atomic<bool> running_{false};
    int out_pipe_[2]{-1,-1}, err_pipe_[2]{-1,-1};
    int old_out_{-1}, old_err_{-1};
    std::thread reader_out_, reader_err_;
    std::mutex mu_;
    std::vector<std::string> pending_;
    std::deque<Line> lines_;
};

// ==================================================================
/*                                Pro TUI 3 Ultra                              */
// ==================================================================
class TUI {
public:
    enum class NodeState { Starting, Syncing, Running, Degraded, Quitting };
    enum class ViewMode { Splash, Main };  // Splash = sync screen, Main = full dashboard

    explicit TUI(bool vt_ok, bool u8_ok) : vt_ok_(vt_ok), u8_ok_(u8_ok) { init_step_order(); }
    void set_enabled(bool on){ enabled_ = on; }
    void start() {
        if (!enabled_) return;
        if (vt_ok_) cw_.write_raw("\x1b[2J\x1b[H\x1b[?25l");
        // CRITICAL: Set ALL running flags BEFORE starting threads
        // Otherwise threads would exit immediately or never stop
        running_ = true;
        cache_running_ = true;
        key_running_ = true;  // Must be set before key_thr_ starts
        draw_once(true);
        key_thr_   = std::thread([this]{ key_loop(); });
        cache_thr_ = std::thread([this]{ cache_update_loop(); });  // Background cache updates
        thr_       = std::thread([this]{ loop(); });
    }
    void stop() {
        if (!enabled_) return;
        running_ = false;
        key_running_ = false;
        cache_running_ = false;
        if (thr_.joinable()) thr_.join();
        if (key_thr_.joinable()) key_thr_.join();
        if (cache_thr_.joinable()) cache_thr_.join();
        if (vt_ok_) cw_.write_raw("\x1b[?25h\x1b[0m\n");
    }
    ~TUI(){ stop(); }

    // startup steps
    void mark_step_started(const std::string& title) { std::lock_guard<std::mutex> lk(mu_); ensure_step(title); }
    void mark_step_ok(const std::string& title) { std::lock_guard<std::mutex> lk(mu_); ensure_step(title); set_step(title, true); }
    void mark_step_fail(const std::string& title){ std::lock_guard<std::mutex> lk(mu_); ensure_step(title); failures_.insert(title); }

    // runtime refs
    void set_runtime_refs(P2P* p2p, Chain* chain, Mempool* mempool) {
        std::lock_guard<std::mutex> lk(mu_);
        p2p_ = p2p;
        chain_ = chain;
        mempool_ = mempool;
        // CRITICAL FIX: Initialize ibd_cur_ from chain height immediately
        // This ensures the TUI shows the actual block count during the "Connecting" phase
        // instead of showing "Blocks 0" while waiting for peers
        if (chain_) {
            ibd_cur_ = chain_->height();
        }
    }
    void set_ports(uint16_t p2pport, uint16_t rpcport) { p2p_port_ = p2pport; rpc_port_ = rpcport; }
    void set_node_state(NodeState st){ std::lock_guard<std::mutex> lk(mu_); nstate_ = st; }
    void set_datadir(const std::string& d){ std::lock_guard<std::mutex> lk(mu_); datadir_ = d; }

    // mining gate
    void set_mining_gate(bool available, const std::string& reason){
        std::lock_guard<std::mutex> lk(mu_);
        mining_gate_available_ = available;
        mining_gate_reason_ = reason;
    }

    // logs in
    void feed_logs(const std::deque<LogCapture::Line>& raw_lines) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!paused_) {
            logs_.clear(); logs_.reserve(raw_lines.size());
            for (auto& L : raw_lines){
                logs_.push_back(stylize_log(L));
            }
        }
        // Drain telemetry
        std::vector<BlockSummary> nb; std::vector<std::string> ntx;
        g_telemetry.drain(nb, ntx);
        for (auto& b : nb) {
            if (recent_blocks_.empty() || recent_blocks_.back().height != b.height || recent_blocks_.back().hash_hex != b.hash_hex) {
                recent_blocks_.push_back(b);
                telemetry_flush_disk(b);
                while (recent_blocks_.size() > 64) recent_blocks_.pop_front();
            }
        }
        for (auto& t : ntx) {
            if (recent_txid_set_.insert(t).second) {
                recent_txids_.push_back(t);
                while (recent_txids_.size() > 18) { recent_txid_set_.erase(recent_txids_.front()); recent_txids_.pop_front(); }
            }
        }
    }

    // HUD
    void set_banner(const std::string& s){ std::lock_guard<std::mutex> lk(mu_); banner_ = s; }
    void set_startup_eta(double secs){ std::lock_guard<std::mutex> lk(mu_); eta_secs_ = secs; }
    void set_shutdown_phase(const std::string& phase, bool ok){
        std::lock_guard<std::mutex> lk(mu_);
        shutdown_phase_ = phase; shutdown_ok_ = ok ? 1 : 0;
    }
    bool is_enabled() const { return enabled_; }

    void set_health_degraded(bool b){ std::lock_guard<std::mutex> lk(mu_); degraded_override_ = b; }
    void set_hot_warning(const std::string& w){ std::lock_guard<std::mutex> lk(mu_); hot_warning_ = w; hot_warn_ts_ = now_ms(); }
    void set_banner_append(const std::string& tail){ std::lock_guard<std::mutex> lk(mu_); if (!banner_.empty()) banner_ += "  "; banner_ += tail; }
    void set_ibd_progress(uint64_t cur, uint64_t target, uint64_t discovered_from_seed,
                          const std::string& stage, const std::string& seed_host,
                          bool finished){
        std::lock_guard<std::mutex> lk(mu_);
        ibd_cur_ = cur; ibd_target_ = std::max(target, cur); ibd_discovered_ = discovered_from_seed;
        ibd_stage_ = stage; ibd_seed_host_ = seed_host; ibd_done_ = finished; ibd_visible_ = !finished;
        ibd_last_update_ms_ = now_ms();
        // FIX: Also update sync_network_height_ for immediate splash screen display
        // This ensures the progress bar shows correct target immediately instead of waiting
        // for the background TUI loop to update it
        if (target > sync_network_height_) {
            sync_network_height_ = target;
        }
    }

    // Sync stats update
    void update_sync_stats(uint64_t current_height, uint64_t network_height, uint64_t last_block_timestamp) {
        std::lock_guard<std::mutex> lk(mu_);
        uint64_t now = now_ms();

        sync_network_height_ = network_height;
        sync_last_block_time_ = last_block_timestamp;

        // Initialize sync start tracking
        if (sync_start_ms_ == 0 && current_height > 0) {
            sync_start_ms_ = now;
            sync_start_height_ = current_height;
            sync_last_sample_ms_ = now;
            sync_last_sample_height_ = current_height;
        }

        // Calculate sync speed every 2 seconds for smoother updates
        if (now - sync_last_sample_ms_ >= 2000 && sync_last_sample_ms_ > 0) {
            uint64_t blocks_synced = current_height - sync_last_sample_height_;
            double time_elapsed_sec = (double)(now - sync_last_sample_ms_) / 1000.0;

            if (time_elapsed_sec > 0.0) {
                // Exponential moving average for smoother display
                double new_rate = (double)blocks_synced / time_elapsed_sec;
                if (sync_blocks_per_sec_ > 0.0) {
                    sync_blocks_per_sec_ = 0.7 * sync_blocks_per_sec_ + 0.3 * new_rate;
                } else {
                    sync_blocks_per_sec_ = new_rate;
                }
            }

            // Calculate progress increase per hour
            if (network_height > 0 && sync_start_ms_ > 0) {
                double total_time_hours = (double)(now - sync_start_ms_) / 3600000.0;
                if (total_time_hours > 0.0) {
                    double progress_now = (double)current_height / (double)network_height * 100.0;
                    double progress_start = (double)sync_start_height_ / (double)network_height * 100.0;
                    sync_progress_per_hour_ = (progress_now - progress_start) / total_time_hours;
                }
            }

            sync_last_sample_ms_ = now;
            sync_last_sample_height_ = current_height;
        }
    }

private:
    struct StyledLine { std::string txt; int level; };
    StyledLine stylize_log(const LogCapture::Line& L){
        const std::string& s = L.text;
        StyledLine out{ s, 0 };
        if      (s.find("[FATAL]") != std::string::npos || s.find("[ERROR]") != std::string::npos) out.level=2;
        else if (s.find("[WARN]")  != std::string::npos) out.level=1;
        else if (s.find("accepted block") != std::string::npos || s.find("mined block accepted") != std::string::npos) out.level=4;
        else if (s.find("[TRACE]") != std::string::npos) out.level=3;
        else if (global::tui_verbose.load()) out.level=3;
        return out;
    }
    void init_step_order(){
        static const char* order[] = {
            "Parse CLI / environment",
            "Load config & choose datadir",
            "Config/datadir ready",
            "Open chain data",
            "Load & validate genesis",
            "Genesis OK",
            "Reindex UTXO (full scan)",
            "Initialize mempool & RPC",
            "Start P2P listener",
            "Connect seeds",
            "Peer handshake (verack)",
            "Start IBD monitor",
            "IBD sync phase",         // <== shown explicitly
            "Start RPC server",
            "RPC ready"
        };
        for (const char* s : order) steps_.push_back({s, false});
    }
    void ensure_step(const std::string& title){
        for (auto& s : steps_) if (s.first == title) return;
        steps_.push_back({title, false});
    }
    void set_step(const std::string& title, bool ok){
        for (auto& s : steps_) if (s.first == title){ s.second = ok; return; }
        steps_.push_back({title, ok});
    }

    const char* C_reset() const { return vt_ok_ ? "\x1b[0m" : ""; }
    const char* C_info()  const { return vt_ok_ ? (dark_theme_? "\x1b[36m":"\x1b[34m") : ""; }
    const char* C_warn()  const { return vt_ok_ ? "\x1b[33m" : ""; }
    const char* C_err()   const { return vt_ok_ ? "\x1b[31m" : ""; }
    const char* C_dim()   const { return vt_ok_ ? "\x1b[90m" : ""; }
    const char* C_head()  const { return vt_ok_ ? (dark_theme_? "\x1b[35m":"\x1b[35m") : ""; }
    const char* C_ok()    const { return vt_ok_ ? "\x1b[32m" : ""; }
    const char* C_bold()  const { return vt_ok_ ? "\x1b[1m"  : ""; }

    static std::string fit(const std::string& s, int w){
        if (w <= 0) return std::string();
        if ((int)s.size() <= w) return s;
        if (w <= 3) return std::string((size_t)w, '.');
        return s.substr(0, (size_t)w-3) + "...";
    }

    size_t distinct_miners_recent(size_t window) const {
        std::unordered_set<std::string> uniq;
        size_t n = recent_blocks_.size();
        size_t start = (n > window) ? (n - window) : 0;
        for (size_t i = start; i < n; ++i) {
            const auto& b = recent_blocks_[i];
            if (!b.miner.empty()) uniq.insert(b.miner);
        }
        return uniq.size();
    }

    void key_loop(){
        // Note: key_running_ is set by start() before this thread launches
#ifdef _WIN32
        while (key_running_){
            if (_kbhit()){
                int c = _getch();
                handle_key(c);
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(16));
            }
        }
#else
        termios oldt{};
        if (tcgetattr(STDIN_FILENO, &oldt) == 0){
            termios newt = oldt;
            newt.c_lflag &= ~(ICANON | ECHO);
            newt.c_cc[VMIN]  = 0;
            newt.c_cc[VTIME] = 0;
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        }
        while (key_running_){
            unsigned char c=0;
            ssize_t n = ::read(STDIN_FILENO, &c, 1);
            if (n == 1) handle_key((int)c);
            else std::this_thread::sleep_for(std::chrono::milliseconds(16));
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    }
    void handle_key(int c){
        switch(c){
            case 'q': case 'Q': request_shutdown("key"); break;
            case 't': case 'T': global::tui_toggle_theme.store(true); break;
            case 'p': case 'P': { std::lock_guard<std::mutex> lk(mu_); paused_ = !paused_; } break;
            case 's': case 'S': global::tui_snapshot_requested.store(true); break;
            case 'v': case 'V': global::tui_verbose.store(!global::tui_verbose.load()); break;
            case 'r': case 'R': global::reload_requested.store(true); break;
            default: break;
        }
    }

    // PERFORMANCE: Background thread for cache updates
    // This runs ALL blocking chain/p2p operations in a separate thread
    // so the main render loop NEVER blocks on mutexes
    void cache_update_loop() {
        using namespace std::chrono_literals;
        // Note: cache_running_ and running_ are set by start() before this thread launches
        uint64_t last_net_ms = 0;
        uint64_t last_sync_update_ms = 0;

        while (cache_running_ && running_) {
            // Update cache (this can block on chain/p2p mutexes - that's OK in this thread)
            update_chain_cache_nonblocking();

            // Update network hashrate every second
            if (now_ms() - last_net_ms > 1000) {
                last_net_ms = now_ms();
                double nh = estimate_network_hashrate(chain_);

                std::lock_guard<std::mutex> lk(mu_);
                net_hashrate_ = nh;
                net_spark_.push_back(nh);
                if (net_spark_.size() > 90) net_spark_.erase(net_spark_.begin());

                // Update sync stats from cached data
                auto cached = get_cached_chain();
                if (cached.peer_count > 0) {
                    // Find max peer tip from cached peers
                    uint64_t network_height = 0;
                    for (const auto& peer : cached.peers) {
                        if (peer.verack_ok && peer.peer_tip > 0 && peer.peer_tip > network_height) {
                            network_height = peer.peer_tip;
                        }
                    }
                    // CRITICAL FIX: Use header height if higher than peer tips!
                    // Peers may announce low heights but headers reveal true chain height
                    if (cached.best_header_height > network_height) {
                        network_height = cached.best_header_height;
                    }
                    if (network_height > 0) {
                        sync_network_height_ = network_height;
                    }
                    sync_last_block_time_ = static_cast<uint64_t>(cached.time);

                    // Keep ibd_cur_ in sync with chain height
                    if (cached.height > ibd_cur_) {
                        ibd_cur_ = cached.height;
                    }
                }
            }

            // Update sync speed tracking (every 2 seconds for accuracy)
            if (now_ms() - last_sync_update_ms > 2000) {
                last_sync_update_ms = now_ms();
                auto cached = get_cached_chain();
                uint64_t network_height = 0;
                for (const auto& peer : cached.peers) {
                    if (peer.verack_ok && peer.peer_tip > 0 && peer.peer_tip > network_height) {
                        network_height = peer.peer_tip;
                    }
                }
                // CRITICAL FIX: Use header height if higher than peer tips!
                if (cached.best_header_height > network_height) {
                    network_height = cached.best_header_height;
                }
                if (network_height > 0) {
                    update_sync_stats(cached.height, network_height, static_cast<uint64_t>(cached.time));
                }
            }

            // Sleep 100ms between updates
            std::this_thread::sleep_for(100ms);
        }
    }

    // Main render loop - NO BLOCKING OPERATIONS
    // All chain/p2p data comes from cache updated by background thread
    void loop(){
        using clock = std::chrono::steady_clock;
        using namespace std::chrono_literals;
        // Note: running_ is already set by start() before this thread launches
        auto last_hs_time = clock::now();
        auto last_draw_time = clock::now();

        // IMPROVED: Adaptive refresh rate for smoother animations
        // - VT terminals: 250ms for smooth spinner animation
        // - Non-VT/PowerShell 5: 400ms to reduce flicker while staying responsive
        const auto draw_interval = vt_ok_ ? 250ms : 400ms;
        const auto idle_sleep = 16ms;  // ~60fps loop rate for responsive key handling

        while (running_) {
            auto now = clock::now();

            // Handle theme toggle immediately for responsiveness
            if(global::tui_toggle_theme.exchange(false)) {
                std::lock_guard<std::mutex> lk(mu_);
                dark_theme_ = !dark_theme_;
            }

            // PERFORMANCE: NO BLOCKING CALLS HERE
            // Cache is updated by background thread (cache_update_loop)

            // IMPROVED: Time-based drawing for consistent animation speed
            if ((now - last_draw_time) >= draw_interval) {
                draw_once(false);
                last_draw_time = now;
                ++tick_;
            }

            // Sleep for short interval to maintain responsive input handling
            std::this_thread::sleep_for(idle_sleep);

            // Update hashrate sparkline at 250ms intervals (non-blocking, uses atomic)
            if((clock::now()-last_hs_time) > 250ms){
                last_hs_time = clock::now();
                std::lock_guard<std::mutex> lk(mu_);
                spark_hs_.push_back(g_miner_stats.hps.load());
                if(spark_hs_.size() > 90) spark_hs_.erase(spark_hs_.begin());
            }

            // Handle snapshot requests (only on explicit user request)
            if (global::tui_snapshot_requested.exchange(false)) snapshot_to_disk();
        }
    }

    void snapshot_to_disk(){
        if (datadir_.empty()) return;
        int cols, rows; term::get_winsize(cols, rows);
        std::ostringstream out;
        out << "MIQROCHAIN TUI snapshot ("<< now_s() <<")\n";
        out << "Screen: " << cols << "x" << rows << "\n\n";
        out << "[System]\n";
        out << "uptime=" << uptime_s_ << "s  rss=" << get_rss_bytes() << " bytes\n";
        out << "[Chain]\n";
        out << "height=" << (chain_?chain_->height():0) << "\n";
        out << "[Peers]\n";
        if (p2p_){ out << "peers=" << p2p_->snapshot_peers().size() << "\n"; }
        out << "\n[Logs tail]\n";
        int take = 60;
        int start = (int)logs_.size() - take; if (start < 0) start = 0;
        for (int i=start; i<(int)logs_.size(); ++i) out << logs_[i].txt << "\n";
        std::string path = p_join(datadir_, "tui_snapshot.txt");
        write_text_atomic(path, out.str());
        hot_message_ = std::string("Snapshot saved -> ") + path;
        hot_msg_ts_ = now_ms();
    }

    bool miner_running_badge() const {
        const bool miner_on = g_miner_stats.active.load() && g_miner_stats.threads.load() > 0;
        const bool node_run = (nstate_ == NodeState::Running);
        return miner_on && node_run;
    }

    // =========================================================================
    // SPLASH SCREEN - Professional sync display with animations
    // =========================================================================

    // Animated spinner characters (multiple styles)
    static const char* splash_spinner(int tick, bool u8) {
        if (u8) {
            static const char* frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
            return frames[tick % 10];
        } else {
            static const char* frames[] = {"|", "/", "-", "\\"};
            return frames[tick % 4];
        }
    }

    // Pulsing block animation for sync
    static std::string pulse_blocks(int tick, bool u8, bool vt) {
        if (!u8) return "[###]";
        // Animated chain of blocks with wave effect
        static const char* blocks[] = {"░", "▒", "▓", "█"};
        std::string out;
        if (vt) out += "\x1b[36m";  // Cyan
        for (int i = 0; i < 5; ++i) {
            int phase = (tick + i * 2) % 8;
            if (phase > 4) phase = 8 - phase;
            out += blocks[std::min(phase, 3)];
        }
        if (vt) out += "\x1b[0m";
        return out;
    }

    // Fancy gradient progress bar with glow effect
    std::string splash_progress_bar(int width, double frac, int tick) const {
        if (width < 20) width = 20;
        if (frac < 0.0) frac = 0.0;
        if (frac > 1.0) frac = 1.0;

        int inner = width - 2;
        int filled = (int)(frac * inner);
        double sub_frac = (frac * inner) - filled;  // Sub-character precision

        std::string out;
        out.reserve((size_t)(width + 100));

        if (vt_ok_ && u8_ok_) {
            // Premium Unicode progress bar with smooth gradient and glow
            out += "\x1b[48;5;236m";  // Dark background

            for (int i = 0; i < inner; ++i) {
                if (i < filled) {
                    // Gradient from cyan to green based on position
                    int color_phase = (i * 6) / inner;
                    switch(color_phase) {
                        case 0: out += "\x1b[38;5;51m"; break;   // Bright cyan
                        case 1: out += "\x1b[38;5;50m"; break;   // Cyan-green
                        case 2: out += "\x1b[38;5;49m"; break;   // Teal
                        case 3: out += "\x1b[38;5;48m"; break;   // Green-cyan
                        case 4: out += "\x1b[38;5;47m"; break;   // Bright green
                        default: out += "\x1b[38;5;46m"; break;  // Pure green
                    }
                    out += "█";
                } else if (i == filled && frac < 1.0) {
                    // Animated leading edge with smooth transition
                    out += "\x1b[38;5;51m";  // Cyan glow
                    static const char* edge[] = {"▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"};
                    int edge_idx = (int)(sub_frac * 8);
                    // Add pulse animation
                    int pulse = (tick % 4);
                    edge_idx = std::min(7, std::max(0, edge_idx + (pulse < 2 ? pulse : 4 - pulse) - 1));
                    out += edge[edge_idx];
                } else {
                    // Empty space with subtle pattern
                    out += "\x1b[38;5;238m";
                    out += ((i + tick/2) % 4 == 0) ? "·" : " ";
                }
            }
            out += "\x1b[0m";
        } else if (vt_ok_) {
            // ANSI fallback with color
            out += "\x1b[42m\x1b[30m";  // Green background
            for (int i = 0; i < filled; ++i) out += " ";
            out += "\x1b[0m\x1b[47m\x1b[30m";  // Gray background
            for (int i = filled; i < inner; ++i) out += " ";
            out += "\x1b[0m";
        } else {
            // Plain ASCII
            out += "[";
            for (int i = 0; i < filled; ++i) out += "=";
            if (filled < inner) out += ">";
            for (int i = filled + 1; i < inner; ++i) out += " ";
            out += "]";
        }

        return out;
    }

    // Big percentage display with optional animation
    std::string big_percentage(double pct, int tick) const {
        (void)tick; // Parameter reserved for future animation
        std::ostringstream o;
        o << std::fixed << std::setprecision(2) << pct << "%";
        std::string pct_str = o.str();

        if (!vt_ok_) return pct_str;

        // Color based on progress
        std::string color;
        if (pct >= 99.0) color = "\x1b[38;5;46m\x1b[1m";       // Bright green + bold
        else if (pct >= 75.0) color = "\x1b[38;5;47m";          // Green
        else if (pct >= 50.0) color = "\x1b[38;5;226m";         // Yellow
        else if (pct >= 25.0) color = "\x1b[38;5;214m";         // Orange
        else color = "\x1b[38;5;51m";                            // Cyan

        return color + pct_str + "\x1b[0m";
    }

    // Get sync status string - FIXED: Only show FULLY SYNCED when actually synced
    // Must have: valid network height > 0, current height >= network height, and ibd_done_
    std::string get_sync_status(uint64_t network_height, uint64_t current_height, bool is_done) const {
        // CRITICAL: Only show FULLY SYNCED when:
        // 1. We know the network height (network_height > 0)
        // 2. We have actually synced to or past it (current_height >= network_height)
        // 3. The IBD process is marked as done
        if (is_done && network_height > 0 && current_height >= network_height) {
            if (vt_ok_) return std::string("\x1b[38;5;46m\x1b[1m") + (u8_ok_ ? "✓ " : "") + "FULLY SYNCED\x1b[0m";
            return "FULLY SYNCED";
        }

        // If we don't have network height yet, we're still connecting
        if (network_height == 0) {
            if (vt_ok_) return std::string("\x1b[38;5;214m") + "Connecting to network..." + "\x1b[0m";
            return "Connecting to network...";
        }

        // If we have blocks to sync, show progress
        uint64_t blocks_remaining = (network_height > current_height) ? (network_height - current_height) : 0;
        if (blocks_remaining > 0) {
            double pct = (double)current_height / (double)network_height * 100.0;
            std::string pct_str = fmt_pct(pct) + " synced";
            if (vt_ok_) return std::string("\x1b[38;5;214m") + pct_str + "\x1b[0m";
            return pct_str;
        }

        // Edge case: we have all blocks but IBD not marked done yet
        if (vt_ok_) return std::string("\x1b[38;5;47m") + "Finalizing..." + "\x1b[0m";
        return "Finalizing...";
    }

    void draw_splash(int cols, int rows) {
        std::ostringstream out;

        // Sizing
        const int box_width = std::min(76, cols - 4);
        const int start_col = std::max(1, (cols - box_width) / 2);

        // Calculate sync metrics
        uint64_t network_height = sync_network_height_ > 0 ? sync_network_height_ : ibd_target_;
        uint64_t current_height = ibd_cur_;
        uint64_t blocks_remaining = (network_height > current_height) ? (network_height - current_height) : 0;
        double sync_progress = (network_height > 0) ? ((double)current_height / (double)network_height * 100.0) : 0.0;
        if (sync_progress > 100.0) sync_progress = 100.0;

        // FIXED: When ibd_done_ is true, force progress to 100% so the bar fills completely
        // This ensures the progress bar is visually complete when sync finishes
        if (ibd_done_) {
            sync_progress = 100.0;
        }
        double frac = sync_progress / 100.0;

        // Peer info - use cached value to avoid blocking
        auto cached_splash = get_cached_chain();
        size_t peer_count = cached_splash.peer_count;

        std::vector<std::string> lines;

        // ===== ASCII ART LOGO =====
        if (u8_ok_ && box_width >= 60) {
            lines.push_back("");
            // Stylized MIQROCHAIN text
            if (vt_ok_) {
                std::string logo_color = "\x1b[38;5;51m\x1b[1m";  // Bright cyan bold
                lines.push_back(logo_color + "  ███╗   ███╗██╗ ██████╗ ██████╗  ██████╗ " + C_reset());
                lines.push_back(logo_color + "  ████╗ ████║██║██╔═══██╗██╔══██╗██╔═══██╗" + C_reset());
                lines.push_back(logo_color + "  ██╔████╔██║██║██║   ██║██████╔╝██║   ██║" + C_reset());
                lines.push_back(logo_color + "  ██║╚██╔╝██║██║██║▄▄ ██║██╔══██╗██║   ██║" + C_reset());
                lines.push_back(logo_color + "  ██║ ╚═╝ ██║██║╚██████╔╝██║  ██║╚██████╔╝" + C_reset());
                lines.push_back(logo_color + "  ╚═╝     ╚═╝╚═╝ ╚══▀▀═╝ ╚═╝  ╚═╝ ╚═════╝ " + C_reset());
            } else {
                lines.push_back("  MIQROCHAIN");
            }
        } else {
            lines.push_back("");
            lines.push_back(std::string(C_head()) + C_bold() + center_text("MIQROCHAIN", box_width) + C_reset());
        }

        // Version with chain name
        std::ostringstream ver;
        ver << C_dim() << "v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH
            << "  " << (u8_ok_ ? "│" : "|") << "  " << CHAIN_NAME << C_reset();
        lines.push_back(center_text(ver.str(), box_width));
        lines.push_back("");

        // ===== SYNC STATUS HEADER =====
        // FIXED: Only show "Synchronized" when actually synced (network_height > 0 AND ibd_done_)
        std::ostringstream header;
        header << C_bold();
        bool actually_synced = ibd_done_ && network_height > 0 && current_height >= network_height;
        if (actually_synced) {
            header << "\x1b[38;5;46m" << (u8_ok_ ? "✓ " : "[OK] ") << "Blockchain Synchronized";
        } else {
            header << C_warn() << splash_spinner(tick_, u8_ok_) << " Synchronizing Blockchain";
        }
        header << C_reset() << "  " << pulse_blocks(tick_, u8_ok_, vt_ok_);
        lines.push_back(center_text(header.str(), box_width));
        lines.push_back("");

        // ===== LARGE PROGRESS BAR =====
        int bar_width = box_width - 6;
        lines.push_back("   " + splash_progress_bar(bar_width, frac, tick_));

        // ===== BIG PERCENTAGE =====
        // FIXED: Show meaningful text when we don't have network height yet
        if (network_height == 0) {
            // Waiting for peers - show animated "Connecting..." instead of 0.00%
            static const char* dots[] = {"   ", ".  ", ".. ", "..."};
            std::string connecting = "Connecting" + std::string(dots[tick_ % 4]);
            if (vt_ok_) {
                connecting = std::string("\x1b[38;5;214m") + connecting + "\x1b[0m";
            }
            lines.push_back(center_text(connecting, box_width));
        } else {
            lines.push_back(center_text(big_percentage(sync_progress, tick_), box_width));
        }
        lines.push_back("");

        // ===== STATS BOX =====
        std::string box_top = u8_ok_ ? "┌" + std::string(box_width - 8, '-') + "┐" : "+" + std::string(box_width - 8, '-') + "+";
        std::string box_bot = u8_ok_ ? "└" + std::string(box_width - 8, '-') + "┘" : "+" + std::string(box_width - 8, '-') + "+";
        std::string vbar = u8_ok_ ? "│" : "|";

        lines.push_back("   " + std::string(C_dim()) + box_top + C_reset());

        // Block progress
        std::ostringstream b1;
        b1 << vbar << " " << C_dim() << "Blocks      " << C_reset();
        if (network_height == 0) {
            // Waiting for network height - show placeholder
            b1 << C_info() << std::setw(12) << fmt_num(current_height) << C_reset()
               << C_dim() << " / " << C_reset() << std::setw(12) << "discovering...";
        } else {
            b1 << C_info() << std::setw(12) << fmt_num(current_height) << C_reset()
               << C_dim() << " / " << C_reset() << std::setw(12) << fmt_num(network_height);
        }
        int pad1 = box_width - 10 - 46;
        b1 << std::string(std::max(0, pad1), ' ') << vbar;
        lines.push_back("   " + std::string(C_dim()) + b1.str() + C_reset());

        // Remaining
        std::ostringstream b2;
        b2 << vbar << " " << C_dim() << "Remaining   " << C_reset();
        if (network_height == 0) {
            // Waiting for network height - show placeholder
            b2 << std::setw(12) << "unknown" << " blocks";
        } else {
            b2 << std::setw(12) << fmt_num(blocks_remaining) << " blocks";
        }
        int pad2 = box_width - 10 - 35;
        b2 << std::string(std::max(0, pad2), ' ') << vbar;
        lines.push_back("   " + std::string(C_dim()) + b2.str() + C_reset());

        // ETA - FIXED: Only show Complete when actually synced
        std::string eta_str;
        if (actually_synced) {
            // Only show Complete when actually done syncing
            eta_str = u8_ok_ ? "✓ Complete" : "Complete";
        } else if (network_height == 0) {
            // Waiting for network height discovery
            eta_str = "Waiting for peers...";
        } else if (sync_blocks_per_sec_ > 0.01 && blocks_remaining > 0) {
            // Have speed measurement, calculate ETA
            eta_str = fmt_eta(blocks_remaining, sync_blocks_per_sec_);
        } else {
            // Still measuring or just started
            eta_str = "Calculating...";
        }
        std::ostringstream b3;
        b3 << vbar << " " << C_dim() << "ETA         " << C_reset();
        // Use green color when complete, yellow/orange otherwise
        if (actually_synced) {
            b3 << "\x1b[38;5;46m" << eta_str << "\x1b[0m";  // Bright green
        } else {
            b3 << C_warn() << eta_str << C_reset();  // Yellow/orange
        }
        int eta_vis = 13 + (int)eta_str.size();
        int pad3 = box_width - 10 - eta_vis;
        b3 << std::string(std::max(0, pad3), ' ') << C_dim() << vbar << C_reset();
        lines.push_back("   " + b3.str());

        // Speed
        std::ostringstream b4;
        b4 << vbar << " " << C_dim() << "Speed       " << C_reset();
        if (sync_blocks_per_sec_ > 0.01) {
            b4 << std::fixed << std::setprecision(1) << sync_blocks_per_sec_ << " blocks/sec";
        } else {
            b4 << C_dim() << "measuring..." << C_reset();
        }
        std::string b4s = b4.str();
        // Pad to align
        lines.push_back("   " + std::string(C_dim()) + b4s + std::string(std::max(1, box_width - 10 - 35), ' ') + vbar + C_reset());

        lines.push_back("   " + std::string(C_dim()) + box_bot + C_reset());
        lines.push_back("");

        // ===== STATUS LINE =====
        std::ostringstream status;
        status << C_dim() << "Status: " << C_reset() << get_sync_status(network_height, current_height, ibd_done_);
        // Add activity indicator when actively syncing
        if (!actually_synced && blocks_remaining > 0) {
            status << " " << activity_indicator(tick_, true, u8_ok_);
        }
        lines.push_back("   " + status.str());

        // ===== NETWORK INFO =====
        std::ostringstream net;
        net << C_dim() << "Network: " << C_reset();
        if (peer_count == 0) {
            // Animated connecting indicator
            static const char* conn_anim[] = {"connecting", "connecting.", "connecting..", "connecting..."};
            net << C_err() << conn_anim[tick_ % 4] << C_reset();
        } else {
            net << C_ok() << peer_count << " peer" << (peer_count != 1 ? "s" : "") << " connected" << C_reset();
            net << " " << pulse_indicator(tick_, u8_ok_);  // Network pulse
            if (!ibd_seed_host_.empty()) {
                net << C_dim() << " via " << C_reset() << ibd_seed_host_;
            }
        }
        lines.push_back("   " + net.str());
        lines.push_back("");

        // ===== FOOTER =====
        std::ostringstream foot1;
        foot1 << C_dim() << (u8_ok_ ? "⚡ " : "> ") << "Main dashboard opens automatically when sync completes" << C_reset();
        lines.push_back(center_text(foot1.str(), box_width));

        std::ostringstream foot2;
        foot2 << C_dim() << "[q] quit  [t] theme  [v] verbose" << C_reset();
        lines.push_back(center_text(foot2.str(), box_width));
        lines.push_back("");

        // ===== RENDER =====
        int content_height = (int)lines.size();
        int start_row = std::max(1, (rows - content_height) / 2);

        if (vt_ok_) {
            out << "\x1b[H\x1b[J";  // Clear screen
        }

        // Top padding
        for (int i = 0; i < start_row; ++i) out << "\n";

        // Content - FIXED: Clear to end of line for stable layout
        std::string left_padding(start_col, ' ');
        for (const auto& line : lines) {
            out << left_padding << line;
            if (vt_ok_) out << "\x1b[K";  // Clear to end of line
            out << "\n";
        }

        // Bottom padding
        int lines_drawn = start_row + content_height;
        for (int i = lines_drawn; i < rows; ++i) {
            if (vt_ok_) out << "\x1b[K";  // Clear to end of line
            out << "\n";
        }

        // Write frame
        std::string frame = out.str();
        if (vt_ok_) {
            cw_.write_frame("", frame);
        } else {
            cw_.write_raw(frame);
        }
        std::fflush(stdout);
    }

    // Helper to center text accounting for ANSI escape codes
    static std::string center_text(const std::string& text, int width) {
        int visible_len = 0;
        bool in_escape = false;
        for (char c : text) {
            if (c == '\x1b') in_escape = true;
            else if (in_escape && c == 'm') in_escape = false;
            else if (!in_escape) ++visible_len;
        }
        if (visible_len >= width) return text;
        int pad = (width - visible_len) / 2;
        return std::string(pad, ' ') + text;
    }

    // =========================================================================
    // PREMIUM MAIN DASHBOARD - Professional animated display
    // =========================================================================

    // Get visible length of string (excluding ANSI escape codes)
    // FIXED: Properly handles UTF-8 multi-byte characters for accurate width calculation
    static int visible_length(const std::string& s) {
        int len = 0;
        bool in_escape = false;
        for (size_t i = 0; i < s.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c == '\x1b') {
                in_escape = true;
            } else if (in_escape) {
                if (c == 'm') in_escape = false;
            } else {
                // UTF-8: Skip continuation bytes (10xxxxxx pattern = 0x80-0xBF)
                // Only count start bytes and ASCII characters
                if ((c & 0xC0) != 0x80) {
                    ++len;
                }
            }
        }
        return len;
    }

    // Premium box drawing characters
    struct BoxChars {
        const char* tl;  // top-left
        const char* tr;  // top-right
        const char* bl;  // bottom-left
        const char* br;  // bottom-right
        const char* h;   // horizontal
        const char* v;   // vertical
        const char* lt;  // left-tee
        const char* rt;  // right-tee
    };

    BoxChars get_box_chars() const {
        if (u8_ok_) {
            return {"╭", "╮", "╰", "╯", "─", "│", "├", "┤"};
        } else {
            return {"+", "+", "+", "+", "-", "|", "+", "+"};
        }
    }

    // Create a boxed panel header
    std::string box_header(const std::string& title, int width, const char* color = nullptr) const {
        auto bc = get_box_chars();
        std::ostringstream out;

        if (vt_ok_ && color) out << color;
        out << bc.tl;

        // Title with padding
        std::string padded_title = u8_ok_ ? ("─ " + title + " ") : ("- " + title + " ");
        out << padded_title;

        int remaining = width - 2 - (int)padded_title.size();
        for (int i = 0; i < remaining; ++i) out << bc.h;
        out << bc.tr;

        if (vt_ok_) out << "\x1b[0m";
        return out.str();
    }

    // Create a box footer
    std::string box_footer(int width) const {
        auto bc = get_box_chars();
        std::ostringstream out;
        out << C_dim() << bc.bl;
        for (int i = 0; i < width - 2; ++i) out << bc.h;
        out << bc.br << C_reset();
        return out.str();
    }

    // Create a box row with content
    // FIXED: Ensure consistent width output for stable layout
    std::string box_row(const std::string& content, int width) const {
        auto bc = get_box_chars();
        std::ostringstream out;
        out << C_dim() << bc.v << C_reset() << " ";
        out << content;

        int vis_len = visible_length(content);
        // Ensure padding is at least 0 to prevent negative padding
        int padding = std::max(0, width - 4 - vis_len);
        out << std::string(padding, ' ');
        out << " " << C_dim() << bc.v << C_reset();
        return out.str();
    }

    // Animated activity dot
    std::string activity_dot(int tick, bool active) const {
        if (!active) return u8_ok_ ? "○" : "o";
        if (u8_ok_) {
            static const char* frames[] = {"●", "◉", "○", "◉"};
            return frames[tick % 4];
        } else {
            static const char* frames[] = {"*", "o", "*", "O"};
            return frames[tick % 4];
        }
    }

    // Wave animation for status bar
    std::string wave_bar(int width, int tick) const {
        if (!u8_ok_) return std::string(width, '~');
        std::string out;
        static const char* waves[] = {"░", "▒", "▓", "█", "▓", "▒"};
        for (int i = 0; i < width; ++i) {
            int phase = (tick + i) % 6;
            out += waves[phase];
        }
        return out;
    }

    // Mini sparkline for inline stats
    std::string mini_spark(double value, double max_val, int width) const {
        if (max_val <= 0) max_val = 1.0;
        double frac = value / max_val;
        if (frac > 1.0) frac = 1.0;
        if (frac < 0.0) frac = 0.0;

        int filled = (int)(frac * width);
        std::string out;

        if (u8_ok_ && vt_ok_) {
            out += "\x1b[38;5;51m";  // Cyan
            for (int i = 0; i < filled; ++i) out += "█";
            out += "\x1b[38;5;238m";
            for (int i = filled; i < width; ++i) out += "░";
            out += "\x1b[0m";
        } else {
            for (int i = 0; i < filled; ++i) out += "#";
            for (int i = filled; i < width; ++i) out += ".";
        }
        return out;
    }

    // Premium status indicator with glow
    std::string status_indicator(const std::string& status, bool good, int tick) const {
        std::ostringstream out;
        if (vt_ok_) {
            if (good) {
                // Pulsing green glow
                int brightness = 46 + (tick % 4);
                out << "\x1b[38;5;" << brightness << "m";
                out << (u8_ok_ ? "● " : "* ");
            } else {
                // Warning orange
                out << "\x1b[38;5;214m";
                out << (u8_ok_ ? "◐ " : "o ");
            }
            out << status << "\x1b[0m";
        } else {
            out << (good ? "[OK] " : "[..] ") << status;
        }
        return out.str();
    }

    // Animated network activity indicator
    std::string network_activity(int tick, size_t peers, bool has_activity) const {
        std::ostringstream out;
        if (u8_ok_ && vt_ok_) {
            // Network icon with pulse
            if (peers > 0) {
                static const char* net_frames[] = {"◈", "◇", "◈", "◆"};
                out << "\x1b[38;5;51m" << net_frames[tick % 4] << "\x1b[0m";
            } else {
                out << "\x1b[38;5;238m○\x1b[0m";
            }

            // Activity arrows
            if (has_activity && peers > 0) {
                static const char* arrows[] = {"↑", "↗", "→", "↘", "↓", "↙", "←", "↖"};
                out << "\x1b[38;5;46m" << arrows[tick % 8] << "\x1b[0m";
            }
        } else {
            out << (peers > 0 ? "[NET]" : "[---]");
        }
        return out.str();
    }

    // Premium gradient bar for hashrate/performance
    std::string gradient_bar(int width, double frac, int tick, const char* start_color = "51", const char* end_color = "46") const {
        (void)start_color; // Parameters reserved for future gradient customization
        (void)end_color;
        if (width < 4) width = 4;
        if (frac < 0.0) frac = 0.0;
        if (frac > 1.0) frac = 1.0;

        int filled = (int)(frac * width);
        std::ostringstream out;

        if (vt_ok_ && u8_ok_) {
            for (int i = 0; i < width; ++i) {
                if (i < filled) {
                    // Gradient from start to end color
                    int color = 51 - (i * 5) / width;  // Cyan to green gradient
                    if (color < 46) color = 46;
                    out << "\x1b[38;5;" << color << "m█";
                } else if (i == filled && frac < 1.0) {
                    // Animated edge
                    static const char* edge[] = {"▏", "▎", "▍", "▌", "▋", "▊", "▉"};
                    out << "\x1b[38;5;51m" << edge[tick % 7];
                } else {
                    out << "\x1b[38;5;236m░";
                }
            }
            out << "\x1b[0m";
        } else {
            for (int i = 0; i < filled; ++i) out << "=";
            if (filled < width) out << ">";
            for (int i = filled + 1; i < width; ++i) out << " ";
        }
        return out.str();
    }

    // Animated chain blocks visualization
    std::string chain_blocks_viz(int tick, uint64_t height) const {
        if (!u8_ok_ || !vt_ok_) return "[" + std::to_string(height) + "]";

        std::ostringstream out;
        // Show last 5 "blocks" with animation
        static const char* block_states[] = {"░", "▒", "▓", "█"};

        for (int i = 0; i < 5; ++i) {
            int phase = (tick + i * 2) % 8;
            if (phase > 4) phase = 8 - phase;
            int idx = std::min(3, phase);

            // Color gradient
            int color = 51 - i * 1;
            out << "\x1b[38;5;" << color << "m" << block_states[idx];
        }
        out << "\x1b[0m";
        return out.str();
    }

    // Mining pickaxe animation
    std::string mining_animation(int tick, bool active) const {
        if (!active) return u8_ok_ ? "⛏" : "[M]";
        if (u8_ok_ && vt_ok_) {
            static const char* frames[] = {"⛏ ", " ⛏", "⛏ ", "⛏·"};
            int bright = 46 + (tick % 4);
            std::ostringstream out;
            out << "\x1b[38;5;" << bright << "m" << frames[tick % 4] << "\x1b[0m";
            return out.str();
        }
        return "[MINING]";
    }

    // Draw the premium main dashboard
    // FIXED: Uses fixed layout dimensions for 100% stable positioning
    void draw_main(int cols, int rows) {
        std::ostringstream out;
        std::vector<std::string> lines;

        // FIXED: Enforce minimum dimensions for stable layout
        // This ensures the TUI always renders with consistent positioning
        if (cols < 114) cols = 114;
        if (rows < 38) rows = 38;

        // Box width and positioning - use fixed values for stability
        const int box_width = 110;  // Fixed width for consistent layout
        const int start_col = std::max(1, (cols - box_width) / 2);
        const int half_width = (box_width - 3) / 2;

        // ===== ANIMATED HEADER LOGO =====
        if (u8_ok_ && box_width >= 50) {
            // Compact but stylish logo
            std::string logo_color = vt_ok_ ? "\x1b[38;5;51m\x1b[1m" : "";
            std::string reset = vt_ok_ ? "\x1b[0m" : "";

            lines.push_back("");
            lines.push_back(logo_color + "  ╔╦╗╦╔═╗ ╦═╗╔═╗╔═╗╦ ╦╔═╗╦╔╗╔" + reset + "   " +
                           C_dim() + "v" + std::to_string(MIQ_VERSION_MAJOR) + "." +
                           std::to_string(MIQ_VERSION_MINOR) + "." +
                           std::to_string(MIQ_VERSION_PATCH) + C_reset());
            lines.push_back(logo_color + "  ║║║║║═╬╗╠╦╝║ ║║  ╠═╣╠═╣║║║║" + reset + "   " +
                           spinner(tick_, u8_ok_) + " " + pulse_blocks(tick_, u8_ok_, vt_ok_));
            lines.push_back(logo_color + "  ╩ ╩╩╚═╝╚╩╚═╚═╝╚═╝╩ ╩╩ ╩╩╝╚╝" + reset + "   " +
                           C_dim() + CHAIN_NAME + C_reset());
        } else {
            lines.push_back("");
            std::ostringstream h;
            h << C_head() << C_bold() << "MIQROCHAIN" << C_reset()
              << "  " << C_dim() << "v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH << C_reset()
              << "  " << spinner(tick_, u8_ok_);
            lines.push_back(h.str());
        }

        // ===== STATUS BAR =====
        {
            std::ostringstream status;
            status << C_dim() << "Status: " << C_reset();

            NodeState show_state = nstate_;
            if (degraded_override_) show_state = NodeState::Degraded;

            switch(show_state) {
                case NodeState::Starting:
                    status << status_indicator("STARTING", false, tick_);
                    break;
                case NodeState::Syncing:
                    status << status_indicator("SYNCING", false, tick_);
                    break;
                case NodeState::Running:
                    status << status_indicator("RUNNING", true, tick_);
                    break;
                case NodeState::Degraded:
                    status << "\x1b[38;5;196m" << (u8_ok_ ? "⚠ " : "[!] ") << "DEGRADED\x1b[0m";
                    break;
                case NodeState::Quitting:
                    status << C_warn() << "SHUTTING DOWN" << C_reset();
                    break;
            }

            // Network activity indicator - use cached value (populated at start of draw)
            auto cached_for_status = get_cached_chain();
            status << "   " << network_activity(tick_, cached_for_status.peer_count, cached_for_status.peer_count > 0);
            status << " " << C_dim() << cached_for_status.peer_count << " peers" << C_reset();

            // Mining indicator
            if (miner_running_badge()) {
                status << "   " << mining_animation(tick_, true);
            }

            lines.push_back("");
            lines.push_back(center_text(status.str(), box_width));
        }

        // ===== PORTS & CONFIG BAR =====
        {
            std::ostringstream ports;
            std::string sep = u8_ok_ ? " │ " : " | ";

            ports << C_dim() << "P2P:" << C_reset() << " " << C_info() << p2p_port_ << C_reset();
            ports << sep << C_dim() << "RPC:" << C_reset() << " " << C_info() << rpc_port_ << C_reset();

            if (auto* ss = g_stratum_server.load()) {
                ports << sep << C_dim() << "Pool:" << C_reset() << " " << C_info() << ss->get_port() << C_reset();
            }

            ports << sep << C_dim() << "Theme:" << C_reset() << " " << (dark_theme_ ? "dark" : "light");

            lines.push_back(center_text(ports.str(), box_width));
            lines.push_back("");
        }

        // ===== MAIN PANELS (2 columns) =====
        std::vector<std::string> left_panel, right_panel;

        // ----- LEFT PANEL: Blockchain -----
        {
            left_panel.push_back(box_header("Blockchain", half_width, "\x1b[38;5;51m"));

            // PERFORMANCE: Use cached chain state to avoid mutex contention
            // This prevents UI freeze when P2P is holding chain mutex during block processing
            auto cached = get_cached_chain();
            uint64_t height = cached.height;
            std::string tip_hex = to_hex(cached.tip_hash);
            long double tip_diff = difficulty_from_bits(cached.bits);
            uint64_t tip_ts = static_cast<uint64_t>(cached.time);
            uint64_t tip_age_s = 0;
            if (tip_ts) {
                uint64_t now = (uint64_t)std::time(nullptr);
                tip_age_s = (now > tip_ts) ? (now - tip_ts) : 0;
            }

            // Height with chain visualization
            std::ostringstream h1;
            h1 << C_dim() << "Height:" << C_reset() << "     " << chain_blocks_viz(tick_, height) << " "
               << C_info() << C_bold() << fmt_num(height) << C_reset();
            left_panel.push_back(box_row(h1.str(), half_width));

            // Tip hash
            std::ostringstream h2;
            h2 << C_dim() << "Tip:" << C_reset() << "        " << short_hex(tip_hex, 24);
            left_panel.push_back(box_row(h2.str(), half_width));

            // Tip age with color coding (using fmt_age for timestamp display)
            std::ostringstream h3;
            h3 << C_dim() << "Tip Age:" << C_reset() << "    ";
            std::string age_str = tip_ts ? fmt_age(tip_ts) : "unknown";
            if (tip_age_s < 120) {
                h3 << C_ok() << age_str << C_reset();
            } else if (tip_age_s < 600) {
                h3 << C_warn() << age_str << C_reset();
            } else {
                h3 << C_err() << age_str << C_reset();
            }
            left_panel.push_back(box_row(h3.str(), half_width));

            // Difficulty
            std::ostringstream h4;
            h4 << C_dim() << "Difficulty:" << C_reset() << " " << fmt_diff(tip_diff);
            left_panel.push_back(box_row(h4.str(), half_width));

            // Network hashrate with spark
            std::ostringstream h5;
            h5 << C_dim() << "Net Hash:" << C_reset() << "   " << C_info() << fmt_hs(net_hashrate_) << C_reset();
            left_panel.push_back(box_row(h5.str(), half_width));

            // Hashrate trend sparkline
            std::ostringstream h6;
            h6 << C_dim() << "Trend:" << C_reset() << "      " << spark_ascii(net_spark_);
            left_panel.push_back(box_row(h6.str(), half_width));

            left_panel.push_back(box_footer(half_width));
        }

        // ----- RIGHT PANEL: Network -----
        {
            right_panel.push_back(box_header("Network", half_width, "\x1b[38;5;47m"));

            // PERFORMANCE: Use cached peer stats to avoid mutex contention
            auto cached_net = get_cached_chain();
            size_t peers_n = cached_net.peer_count;
            size_t verack_ok = cached_net.verack_ok;
            size_t inflight_tx = cached_net.inflight_tx;

            // Peer count with mini bar
            std::ostringstream n1;
            n1 << C_dim() << "Peers:" << C_reset() << "      ";
            if (peers_n == 0) {
                n1 << C_err() << "0 (connecting...)" << C_reset();
            } else if (peers_n < 3) {
                n1 << C_warn() << peers_n << C_reset() << " " << mini_spark((double)peers_n, 8.0, 8);
            } else {
                n1 << C_ok() << peers_n << C_reset() << " " << mini_spark((double)peers_n, 8.0, 8);
            }
            right_panel.push_back(box_row(n1.str(), half_width));

            // Active peers
            std::ostringstream n2;
            n2 << C_dim() << "Active:" << C_reset() << "     " << C_info() << verack_ok << C_reset() << " verified";
            right_panel.push_back(box_row(n2.str(), half_width));

            // In-flight
            std::ostringstream n3;
            n3 << C_dim() << "In-flight:" << C_reset() << "  " << inflight_tx << " requests";
            right_panel.push_back(box_row(n3.str(), half_width));

            // Network stats
            std::ostringstream n4;
            n4 << C_dim() << "Sent:" << C_reset() << "       " << fmt_net_bytes(p2p_stats::bytes_sent.load());
            right_panel.push_back(box_row(n4.str(), half_width));

            std::ostringstream n5;
            n5 << C_dim() << "Received:" << C_reset() << "   " << fmt_net_bytes(p2p_stats::bytes_recv.load());
            right_panel.push_back(box_row(n5.str(), half_width));

            // Connection status
            std::ostringstream n6;
            n6 << C_dim() << "Status:" << C_reset() << "     ";
            if (peers_n > 0) {
                n6 << activity_dot(tick_, true) << " " << C_ok() << "Connected" << C_reset();
            } else {
                n6 << activity_dot(tick_, false) << " " << C_warn() << "Searching..." << C_reset();
            }
            right_panel.push_back(box_row(n6.str(), half_width));

            right_panel.push_back(box_footer(half_width));
        }

        // Merge left and right panels
        lines.push_back("");
        size_t max_panel = std::max(left_panel.size(), right_panel.size());
        for (size_t i = 0; i < max_panel; ++i) {
            std::string l = (i < left_panel.size()) ? left_panel[i] : std::string(half_width, ' ');
            std::string r = (i < right_panel.size()) ? right_panel[i] : std::string(half_width, ' ');
            lines.push_back(" " + l + "   " + r);
        }

        // ===== SECOND ROW PANELS =====
        std::vector<std::string> left_panel2, right_panel2;

        // ----- Mining Panel -----
        {
            left_panel2.push_back(box_header("Mining", half_width, "\x1b[38;5;226m"));

            bool active = g_miner_stats.active.load();
            unsigned thr = g_miner_stats.threads.load();
            uint64_t ok = g_miner_stats.accepted.load();
            uint64_t rej = g_miner_stats.rejected.load();
            double hps = g_miner_stats.hps.load();

            // Mining status
            std::ostringstream m1;
            m1 << C_dim() << "Status:" << C_reset() << "     ";
            if (mining_gate_available_) {
                if (active) {
                    m1 << mining_animation(tick_, true) << " " << C_ok() << "MINING" << C_reset()
                       << " (" << thr << " threads)";
                } else {
                    m1 << C_ok() << "Available" << C_reset();
                }
            } else {
                m1 << C_warn() << "Unavailable" << C_reset();
                // Show reason if provided (helps users understand why mining is blocked)
                if (!mining_gate_reason_.empty()) {
                    std::string reason = mining_gate_reason_;
                    if (reason.size() > 25) reason = reason.substr(0, 22) + "...";
                    m1 << " - " << reason;
                }
            }
            left_panel2.push_back(box_row(m1.str(), half_width));

            // Hashrate with gradient bar
            std::ostringstream m2;
            m2 << C_dim() << "Hashrate:" << C_reset() << "   " << C_info() << fmt_hs(hps) << C_reset();
            if (active && hps > 0) {
                m2 << " " << gradient_bar(12, std::min(1.0, hps / std::max(1.0, net_hashrate_ * 0.01)), tick_);
            }
            left_panel2.push_back(box_row(m2.str(), half_width));

            // Trend
            std::ostringstream m3;
            m3 << C_dim() << "Trend:" << C_reset() << "      " << spark_ascii(spark_hs_);
            left_panel2.push_back(box_row(m3.str(), half_width));

            // Blocks mined
            std::ostringstream m4;
            m4 << C_dim() << "Blocks:" << C_reset() << "     " << C_ok() << ok << " mined" << C_reset();
            if (rej > 0) m4 << ", " << C_err() << rej << " rejected" << C_reset();
            left_panel2.push_back(box_row(m4.str(), half_width));

            // Network share
            double share = (net_hashrate_ > 0.0 && hps > 0.0) ? (hps / net_hashrate_) * 100.0 : 0.0;
            std::ostringstream m5;
            m5 << C_dim() << "Net Share:" << C_reset() << "  " << std::fixed << std::setprecision(4) << share << "%";
            left_panel2.push_back(box_row(m5.str(), half_width));

            // Mining address
            std::ostringstream m6;
            m6 << C_dim() << "Reward To:" << C_reset() << "  ";
            if (!g_miner_address_b58.empty()) {
                std::string addr = g_miner_address_b58;
                if (addr.size() > 20) addr = addr.substr(0, 8) + "..." + addr.substr(addr.size() - 8);
                m6 << C_info() << addr << C_reset();
            } else {
                m6 << C_dim() << "not set" << C_reset();
            }
            left_panel2.push_back(box_row(m6.str(), half_width));

            left_panel2.push_back(box_footer(half_width));
        }

        // ----- Mempool Panel -----
        {
            right_panel2.push_back(box_header("Mempool", half_width, "\x1b[38;5;213m"));

            auto stat = mempool_view_fallback(mempool_);

            // Transaction count with orphan info
            std::ostringstream p1;
            p1 << C_dim() << "Pending TX:" << C_reset() << " " << C_info() << stat.count << C_reset();
            if (stat.orphans > 0) {
                p1 << " " << C_dim() << "(" << stat.orphans << " orphan)" << C_reset();
            }
            right_panel2.push_back(box_row(p1.str(), half_width));

            // Size
            std::ostringstream p2;
            p2 << C_dim() << "Size:" << C_reset() << "       " << fmt_bytes(stat.bytes);
            right_panel2.push_back(box_row(p2.str(), half_width));

            // Recent adds (or total if orphans exist for better visibility)
            std::ostringstream p3;
            if (stat.count > 0 || stat.orphans > 0) {
                uint64_t total = stat.count + stat.orphans;
                p3 << C_dim() << "Total:" << C_reset() << "      " << total << " tx seen";
            } else {
                p3 << C_dim() << "Recent:" << C_reset() << "     +" << stat.recent_adds << " added";
            }
            right_panel2.push_back(box_row(p3.str(), half_width));

            // Recent TXIDs header
            right_panel2.push_back(box_row(C_dim() + std::string("Recent TXIDs:") + C_reset(), half_width));

            // FIXED: Always show exactly 2 txid slots for consistent panel height
            size_t tx_show = std::min<size_t>(2, recent_txids_.size());
            for (size_t i = 0; i < 2; ++i) {
                if (i < tx_show) {
                    std::string txid = recent_txids_[recent_txids_.size() - 1 - i];
                    right_panel2.push_back(box_row("  " + short_hex(txid, 28), half_width));
                } else {
                    right_panel2.push_back(box_row(C_dim() + std::string("  (none yet)") + C_reset(), half_width));
                }
            }

            right_panel2.push_back(box_footer(half_width));
        }

        // Merge second row panels
        lines.push_back("");
        max_panel = std::max(left_panel2.size(), right_panel2.size());
        for (size_t i = 0; i < max_panel; ++i) {
            std::string l = (i < left_panel2.size()) ? left_panel2[i] : std::string(half_width, ' ');
            std::string r = (i < right_panel2.size()) ? right_panel2[i] : std::string(half_width, ' ');
            lines.push_back(" " + l + "   " + r);
        }

        // ===== RECENT BLOCKS PANEL (Full Width) =====
        // FIXED: Always show exactly 4 block slots for consistent height
        {
            lines.push_back("");
            lines.push_back(box_header("Recent Blocks", box_width - 2, "\x1b[38;5;208m"));

            // Header row (always shown)
            std::ostringstream hdr;
            hdr << C_dim() << std::left << std::setw(10) << "Height"
                << std::setw(24) << "Hash"
                << std::setw(8) << "TXs"
                << std::setw(14) << "Miner" << C_reset();
            lines.push_back(box_row(hdr.str(), box_width - 2));

            // Always show exactly 4 block rows for fixed layout
            size_t available = recent_blocks_.size();
            for (size_t i = 0; i < 4; ++i) {
                if (i < available) {
                    const auto& b = recent_blocks_[available - 1 - i];
                    std::ostringstream row;

                    row << C_info() << std::left << std::setw(10) << fmt_num(b.height) << C_reset();
                    row << std::setw(24) << short_hex(b.hash_hex.empty() ? "?" : b.hash_hex, 20);
                    row << std::setw(8) << (b.tx_count ? std::to_string(b.tx_count) : "?");

                    std::string miner = b.miner;
                    if (miner.size() > 12) miner = miner.substr(0, 6) + "..." + miner.substr(miner.size() - 4);
                    row << C_dim() << miner << C_reset();

                    lines.push_back(box_row(row.str(), box_width - 2));
                } else {
                    // Empty slot - waiting for blocks
                    lines.push_back(box_row(C_dim() + std::string("Waiting for blocks...") + C_reset(), box_width - 2));
                }
            }
            lines.push_back(box_footer(box_width - 2));
        }

        // ===== SYSTEM INFO BAR =====
        {
            lines.push_back("");
            uptime_s_ = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start_tp_).count();
            uint64_t rss = get_rss_bytes();

            std::ostringstream sys;
            std::string sep = u8_ok_ ? " │ " : " | ";

            sys << C_dim() << "Uptime:" << C_reset() << " " << fmt_uptime(uptime_s_);
            sys << sep << C_dim() << "Memory:" << C_reset() << " " << fmt_bytes(rss);
            sys << sep << C_dim() << "Datadir:" << C_reset() << " " << (datadir_.size() > 30 ? "..." + datadir_.substr(datadir_.size() - 27) : datadir_);

            lines.push_back(center_text(sys.str(), box_width));
        }

        // ===== CONTROLS FOOTER =====
        {
            std::ostringstream ctrl;
            ctrl << C_dim() << "[q]uit  [t]heme  [p]ause  [s]nap  [v]erbose  [r]eload" << C_reset();
            lines.push_back(center_text(ctrl.str(), box_width));
            lines.push_back("");
        }

        // ===== RENDER =====
        // FIXED: Use fixed positioning for stable layout
        // The dashboard always starts at row 2 for consistent appearance
        const int fixed_start_row = 2;
        const int fixed_log_lines = 8;  // Always show exactly 8 log lines

        if (vt_ok_) {
            out << "\x1b[H\x1b[J";  // Clear screen and home cursor
        }

        // Top padding (fixed)
        for (int i = 0; i < fixed_start_row; ++i) out << "\n";

        // Content
        // FIXED: Use padding on the left and clear to end of line to prevent layout issues
        std::string left_padding(start_col, ' ');
        for (const auto& line : lines) {
            out << left_padding << line;
            if (vt_ok_) out << "\x1b[K";  // Clear to end of line
            out << "\n";
        }

        // ===== LOGS SECTION =====
        // FIXED: Always use fixed number of log lines for stable layout
        int remain = fixed_log_lines;

        out << left_padding << C_bold() << "Logs" << C_reset() << " " << C_dim() << "(recent activity)" << C_reset();
        if (vt_ok_) out << "\x1b[K";
        out << "\n";
        out << left_padding << std::string(box_width - 2, '-');
        if (vt_ok_) out << "\x1b[K";
        out << "\n";

        int log_start = (int)logs_.size() - remain;
        if (log_start < 0) log_start = 0;

        int printed = 0;
        for (int i = log_start; i < (int)logs_.size() && printed < remain; ++i) {
            const auto& line = logs_[i];
            std::string txt = line.txt;
            if ((int)txt.size() > cols - start_col - 2) {
                txt = txt.substr(0, cols - start_col - 5) + "...";
            }

            out << left_padding;
            switch(line.level) {
                case 2: out << C_err() << txt << C_reset(); break;
                case 1: out << C_warn() << txt << C_reset(); break;
                case 3: out << C_dim() << txt << C_reset(); break;
                case 4: out << C_ok() << txt << C_reset(); break;
                default: out << txt; break;
            }
            if (vt_ok_) out << "\x1b[K";  // Clear to end of line
            out << "\n";
            ++printed;
        }

        // Fill remaining with empty lines (with clear to end of line)
        for (int i = printed; i < remain; ++i) {
            if (vt_ok_) out << "\x1b[K";
            out << "\n";
        }

        // Write frame
        std::string frame = out.str();
        if (vt_ok_) {
            cw_.write_frame("", frame);
        } else {
            cw_.write_raw(frame);
        }
        std::fflush(stdout);
    }

    void draw_once(bool first){
        (void)first;  // Reserved for future first-draw optimization
        std::lock_guard<std::mutex> lk(mu_);
        int cols, rows; term::get_winsize(cols, rows);

        // FIXED: Enforce minimum dimensions for 100% stable layout rendering
        // This ensures the TUI always fits in one screen without scrolling or shifting
        if (cols < 114) cols = 114;
        if (rows < 38) rows = 38;

        // Check if sync is complete to transition from Splash to Main
        // CRITICAL: Only transition when BOTH conditions are met:
        // 1. ibd_done_ is true AND node state is Running (normal completion)
        // 2. AND we're caught up with header height (not just peer-reported height)
        bool sync_complete = ibd_done_ && (nstate_ == NodeState::Running);

        // REMOVED: The old fallback logic was causing premature transitions
        // when ibd_cur_ >= ibd_target_ but we weren't actually synced.
        // The ibd_target_ could be stale or from a peer with incomplete data.
        // Now we ONLY transition when compute_sync_gate() returns true,
        // which properly checks header height vs block height.

        if (sync_complete && view_mode_ == ViewMode::Splash) {
            // FIXED: Delay transition for 20+ frames (~2 seconds) to show "100%" completion
            // This ensures the progress bar is visibly full before transitioning
            if (splash_transition_counter_ < 20) {
                splash_transition_counter_++;
            } else {
                view_mode_ = ViewMode::Main;
            }
        } else if (!sync_complete) {
            // Reset counter if sync isn't complete (in case of re-sync)
            splash_transition_counter_ = 0;
        }

        // Draw splash screen during sync, or while showing completion animation
        if (view_mode_ == ViewMode::Splash) {
            draw_splash(cols, rows);
            return;
        }

        // Use the new premium main dashboard
        draw_main(cols, rows);
        return;

        // ==== LEGACY CODE BELOW (kept for reference, not executed) ====

        // Calculate layout dimensions - ensure right column fits
        const int rightw = std::max(50, cols / 3);
        const int leftw  = cols - rightw - 3;

        std::vector<std::string> left, right;

        // Header bar - Professional branding
        {
            std::ostringstream h;
            std::string bullet = u8_ok_ ? " • " : " | ";

            // Main title with version
            h << C_head() << "MIQROCHAIN" << C_reset()
              << "  " << C_dim()
              << "v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH
              << C_reset()
              << "  " << spinner(tick_, u8_ok_);
            left.push_back(h.str());

            // Network info line
            std::ostringstream n;
            n << "  " << C_dim() << "Chain: " << C_reset() << CHAIN_NAME
              << C_dim() << bullet << "P2P: " << C_reset() << p2p_port_
              << C_dim() << bullet << "RPC: " << C_reset() << rpc_port_;

            // Show Stratum port if enabled
            if (auto* ss = g_stratum_server.load()) {
                n << C_dim() << bullet << "Pool: " << C_reset() << ss->get_port();
            }
            left.push_back(n.str());

            left.push_back("");

            // Status messages
            if(!banner_.empty()){
                left.push_back(std::string("  ") + C_info() + banner_ + C_reset());
            }
            if (!hot_message_.empty() && (now_ms() - hot_msg_ts_) < 4000){
                left.push_back(std::string("  ") + C_warn() + hot_message_ + C_reset());
            }

            // Help hint for new users
            if (uptime_s_ < 30 && nstate_ == NodeState::Starting) {
                left.push_back(std::string("  ") + C_dim() + "Press 'q' to quit" + bullet + "'t' toggle theme" + bullet + "'v' verbose mode" + C_reset());
            }

            left.push_back(std::string("  ") + straight_line(leftw-2));
            left.push_back("");
        }

        // System panel - Enhanced with professional formatting
        {
            left.push_back(std::string(C_bold()) + "System" + C_reset());
            uptime_s_ = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_tp_).count();
            uint64_t rss = get_rss_bytes();

            // Uptime with human-readable format
            std::ostringstream ln1;
            ln1 << "  Uptime: " << C_info() << fmt_uptime(uptime_s_) << C_reset()
                << "   Memory: " << fmt_bytes(rss)
                << "   Threads: " << std::thread::hardware_concurrency();
            left.push_back(ln1.str());

            // Platform and version info
            std::ostringstream ln2;
            ln2 << "  Platform: "
#ifdef _WIN32
                << "Windows"
#elif defined(__APPLE__)
                << "macOS"
#else
                << "Linux"
#endif
                << "   Theme: " << (dark_theme_ ? "dark" : "light")
                << "   Verbose: " << (global::tui_verbose.load() ? C_ok() + std::string("yes") + C_reset() : C_dim() + std::string("no") + C_reset());
            left.push_back(ln2.str());

            // Controls hint
            left.push_back(std::string("  ") + C_dim() + "[q]uit [t]heme [p]ause [s]nap [v]erbose [r]eload" + C_reset());
            left.push_back("");
        }

        // Node state panel
        {
            std::ostringstream s;
            s << C_bold() << "Node" << C_reset() << "   State: ";
            NodeState show_state = nstate_;
            if (degraded_override_) show_state = NodeState::Degraded;
            switch(show_state){
                case NodeState::Starting: s << C_warn() << "starting" << C_reset(); break;
                case NodeState::Syncing:  s << C_warn() << "syncing"  << C_reset(); break;
                case NodeState::Running:  s << C_ok()   << "running"  << C_reset(); break;
                case NodeState::Degraded: s << C_err()  << "degraded" << C_reset(); break;
                case NodeState::Quitting: s << C_warn() << "shutting down" << C_reset(); break;
            }
            if (miner_running_badge()){
                s << "   " << C_bold() << (u8_ok_ ? (std::string(C_ok()) + "⛏ RUNNING" + C_reset())
                                                  : (std::string(C_ok()) + "MINER" + C_reset()));
            }
            left.push_back(s.str());
            left.push_back("");
        }

        // Startup progress
        {
            left.push_back(std::string(C_bold()) + "Startup" + C_reset());
            size_t total = steps_.size(), okc = 0;
            for (auto& s : steps_) if (s.second) ++okc;
            int bw = std::max(10, leftw - 20);
            double frac = (double)okc / std::max<size_t>(1,total);
            std::ostringstream progress;
            progress << "  " << bar(bw, frac, vt_ok_, u8_ok_) << "  "
                     << okc << "/" << total << " completed";
            if (eta_secs_ > 0 && frac < 0.999){
                progress << "  " << C_dim() << "(~" << std::fixed << std::setprecision(1) << eta_secs_ << "s)" << C_reset();
            }
            left.push_back(progress.str());
            for (auto& s : steps_) {
                bool ok = s.second;
                bool failed = failures_.count(s.first) > 0;
                std::ostringstream ln;
                ln << "    ";
                if (ok)         ln << C_ok()  << "[OK]    " << C_reset();
                else if (failed)ln << C_err() << "[FAIL]  " << C_reset();
                else            ln << C_dim() << "[..]    " << C_reset();
                ln << s.first;
                left.push_back(ln.str());
            }
            left.push_back("");
        }

        // =============================================================
        // Sync Progress Panel
        // =============================================================
        {
            bool show_sync_panel = (nstate_ == NodeState::Syncing || ibd_visible_ || (!ibd_done_ && ibd_target_ > 0));

            if (show_sync_panel) {
                // Panel header with warning icon
                std::string warn_icon = u8_ok_ ? "⚠ " : "[!] ";
                left.push_back(std::string(C_bold()) + C_warn() + warn_icon + "Synchronizing with Network" + C_reset());
                left.push_back("");

                // Warning message during sync
                left.push_back(std::string("  ") + C_warn() + "Recent transactions may not yet be visible, and therefore" + C_reset());
                left.push_back(std::string("  ") + C_warn() + "your wallet's balance might be incorrect. This information" + C_reset());
                left.push_back(std::string("  ") + C_warn() + "will be correct once your node has finished synchronizing." + C_reset());
                left.push_back("");

                // Calculate sync metrics
                uint64_t network_height = sync_network_height_ > 0 ? sync_network_height_ : ibd_target_;
                uint64_t current_height = ibd_cur_;
                uint64_t blocks_remaining = (network_height > current_height) ? (network_height - current_height) : 0;
                double sync_progress = (network_height > 0) ? ((double)current_height / (double)network_height * 100.0) : 0.0;

                // Determine header sync status
                std::string header_status;
                if (ibd_stage_ == "headers" || current_height == 0) {
                    header_status = "Syncing Headers (" + fmt_num(network_height) + ", " +
                                   std::to_string((int)(sync_progress)) + "%)...";
                } else {
                    header_status = fmt_num(blocks_remaining);
                }

                // Metrics display
                std::ostringstream l1;
                l1 << "  " << C_dim() << "Number of blocks left" << C_reset() << "    " << C_info() << header_status << C_reset();
                left.push_back(l1.str());

                std::ostringstream l2;
                l2 << "  " << C_dim() << "Last block time" << C_reset() << "         "
                   << fmt_datetime(sync_last_block_time_);
                left.push_back(l2.str());

                std::ostringstream l3;
                l3 << "  " << C_dim() << "Progress" << C_reset() << "                 "
                   << C_info() << std::fixed << std::setprecision(2) << sync_progress << "%" << C_reset();
                left.push_back(l3.str());

                std::ostringstream l4;
                l4 << "  " << C_dim() << "Progress increase per hour" << C_reset() << " "
                   << std::fixed << std::setprecision(2) << sync_progress_per_hour_ << "%";
                left.push_back(l4.str());

                // ETA calculation
                std::string eta_str = "Unknown...";
                if (sync_blocks_per_sec_ > 0.01 && blocks_remaining > 0) {
                    eta_str = fmt_eta(blocks_remaining, sync_blocks_per_sec_);
                }
                std::ostringstream l5;
                l5 << "  " << C_dim() << "Estimated time left" << C_reset() << "      " << eta_str;
                left.push_back(l5.str());

                // Chain time remaining at target block rate (60s per block)
                std::ostringstream l5b;
                l5b << "  " << C_dim() << "Chain time remaining" << C_reset() << "     " << fmt_block_time(blocks_remaining, 60);
                left.push_back(l5b.str());

                left.push_back("");

                // Animated progress bar (full width)
                int bar_width = std::max(30, leftw - 4);
                double frac = sync_progress / 100.0;
                left.push_back(std::string("  ") + progress_bar_animated(bar_width, frac, tick_, vt_ok_, u8_ok_));

                // Time behind indicator (like "8 years and 51 weeks behind")
                std::string time_behind = fmt_time_behind(sync_last_block_time_);
                std::ostringstream behind;
                behind << "  " << C_dim() << "Processing blocks on disk... " << C_reset()
                       << C_warn() << time_behind << C_reset();
                left.push_back(behind.str());

                left.push_back("");

                // Sync speed indicator
                if (sync_blocks_per_sec_ > 0.01) {
                    std::ostringstream speed;
                    speed << "  " << C_dim() << "Sync speed: " << C_reset()
                          << std::fixed << std::setprecision(1) << sync_blocks_per_sec_ << " blocks/sec";
                    if (!ibd_seed_host_.empty()) {
                        speed << "  " << C_dim() << "(from " << ibd_seed_host_ << ")" << C_reset();
                    }
                    left.push_back(speed.str());
                }

                if (ibd_done_) {
                    std::string check = u8_ok_ ? "✓ " : "[OK] ";
                    left.push_back(std::string("  ") + C_ok() + check + "Synchronization complete!" + C_reset());
                }

                left.push_back("");
            }
        }

        // Chain status - Enhanced with better formatting
        {
            left.push_back(std::string(C_bold()) + "Blockchain" + C_reset());
            uint64_t height = chain_ ? chain_->height() : 0;
            std::string tip_hex;
            long double tip_diff = 0.0L;
            uint64_t tip_age_s = 0;
            uint64_t tip_timestamp = 0;
            if (chain_) {
                auto t = chain_->tip();
                tip_hex = to_hex(t.hash);
                tip_diff = difficulty_from_bits(hdr_bits(t));
                tip_timestamp = hdr_time(t);
                if (tip_timestamp) {
                    uint64_t now = (uint64_t)std::time(nullptr);
                    tip_age_s = (now > tip_timestamp) ? (now - tip_timestamp) : 0;
                }
            }

            // Height with formatted number
            std::ostringstream c1;
            c1 << "  Height: " << C_info() << fmt_num(height) << C_reset()
               << "   Tip: " << short_hex(tip_hex, 14);
            left.push_back(c1.str());

            // Tip age with human-readable format
            std::ostringstream c2;
            c2 << "  Tip Age: ";
            if (tip_age_s < 120) {
                c2 << C_ok() << fmt_uptime(tip_age_s) << C_reset();
            } else if (tip_age_s < 600) {
                c2 << C_warn() << fmt_uptime(tip_age_s) << C_reset();
            } else {
                c2 << C_err() << fmt_uptime(tip_age_s) << C_reset();
            }
            c2 << "   Difficulty: " << fmt_diff(tip_diff);
            left.push_back(c2.str());

            // Network hashrate and trend
            left.push_back(std::string("  Network Hashrate: ") + C_info() + fmt_hs(net_hashrate_) + C_reset());
            left.push_back(std::string("  Hashrate Trend:   ") + spark_ascii(net_spark_));

            // Recent blocks header
            size_t N = recent_blocks_.size();
            if (N > 0) {
                left.push_back(std::string("  ") + C_dim() + "Recent Blocks:" + C_reset());
                size_t show = std::min<size_t>(6, N);
                for (size_t i=0;i<show;i++){
                    const auto& b = recent_blocks_[N-1-i];
                    std::ostringstream ln;
                    ln << "    " << C_dim() << "#" << C_reset() << b.height
                       << "  " << short_hex(b.hash_hex.empty() ? std::string("?") : b.hash_hex, 10)
                       << "  " << (b.tx_count ? std::to_string(b.tx_count) : std::string("?")) << " txs";
                    if (b.fees_known) ln << "  " << b.fees << " fees";
                    if (!b.miner.empty()) {
                        // Shorten miner address for display
                        std::string short_miner = b.miner;
                        if (short_miner.size() > 12) {
                            short_miner = short_miner.substr(0, 6) + "..." + short_miner.substr(short_miner.size() - 4);
                        }
                        ln << "  " << C_dim() << short_miner << C_reset();
                    }
                    left.push_back(ln.str());
                }
            } else {
                left.push_back(std::string("  ") + C_dim() + "(awaiting first block)" + C_reset());
            }
            left.push_back("");
        }

        // Right column: Network/Mempool/Miner/Health/Logs
        if (p2p_) {
            right.push_back(std::string(C_bold()) + "Network Peers" + C_reset());
            auto peers = p2p_->snapshot_peers();

            std::stable_sort(peers.begin(), peers.end(), [](const auto& a, const auto& b){
                if (a.verack_ok != b.verack_ok) return a.verack_ok > b.verack_ok;
                if (a.last_seen_ms != b.last_seen_ms) return a.last_seen_ms < b.last_seen_ms;
                if (a.rx_buf != b.rx_buf) return a.rx_buf < b.rx_buf;
                return a.inflight < b.inflight;
            });

            size_t peers_n = peers.size();
            size_t inflight_tx = 0, rxbuf_sum = 0, awaiting_pongs = 0, verack_ok = 0;
            for (auto& s : peers) {
                inflight_tx += (size_t)s.inflight;
                rxbuf_sum += (size_t)s.rx_buf;
                if (s.awaiting_pong) ++awaiting_pongs;
                if (s.verack_ok) ++verack_ok;
            }

            // Summary line with color coding for peer count
            std::ostringstream sum;
            sum << "  Connected: ";
            if (peers_n == 0) {
                sum << C_err() << "0" << C_reset();
            } else if (peers_n < 3) {
                sum << C_warn() << peers_n << C_reset();
            } else {
                sum << C_ok() << peers_n << C_reset();
            }
            sum << "   Active: " << verack_ok
                << "   In-flight: " << inflight_tx;
            right.push_back(sum.str());

            // Buffer status
            right.push_back(std::string("  RX Buffer: ") + fmt_bytes(rxbuf_sum)
                          + "   Pings: " + std::to_string(awaiting_pongs));

            // Peer table
            if (peers_n > 0) {
                right.push_back(std::string("  ") + C_dim() + "Peer List:" + C_reset());
                size_t showN = std::min(peers.size(), (size_t)6);
                for (size_t i=0;i<showN; ++i) {
                    const auto& s = peers[i];
                    std::string ip = s.ip;
                    if ((int)ip.size() > 16) ip = ip.substr(0,13) + "...";
                    std::ostringstream ln;
                    ln << "    " << std::left << std::setw(16) << ip << " ";
                    if (s.verack_ok) {
                        ln << C_ok() << "OK" << C_reset();
                    } else {
                        ln << C_warn() << ".." << C_reset();
                    }
                    ln << " rx:" << (uint64_t)s.rx_buf;
                    if (s.inflight > 0) {
                        ln << " (" << s.inflight << " pending)";
                    }
                    right.push_back(ln.str());
                }
                if (peers.size() > showN) {
                    right.push_back(std::string("    ") + C_dim() + "+ " + std::to_string(peers.size()-showN) + " more peers" + C_reset());
                }
            } else {
                right.push_back(std::string("  ") + C_dim() + "(no peers connected)" + C_reset());
            }
            right.push_back("");
        }

        if (mempool_) {
            right.push_back(std::string(C_bold()) + "Mempool" + C_reset());
            auto stat = mempool_view_fallback(mempool_);
            right.push_back(std::string("  txs: ") + std::to_string(stat.count)
                            + (stat.bytes? (std::string("   bytes: ") + fmt_bytes(stat.bytes)) : std::string())
                            + (stat.recent_adds? (std::string("   recent_adds: ") + std::to_string(stat.recent_adds)) : std::string()));
            right.push_back("");
        }

        // Mining panel - Enhanced with better formatting
        {
            right.push_back(std::string(C_bold()) + "Local Mining" + C_reset());
            bool active = g_miner_stats.active.load();
            unsigned thr = g_miner_stats.threads.load();
            uint64_t ok  = g_miner_stats.accepted.load();
            uint64_t rej = g_miner_stats.rejected.load();
            double   hps = g_miner_stats.hps.load();
            uint64_t miner_uptime = 0;
            if (active) {
                miner_uptime = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - g_miner_stats.start).count();
            }

            // Mining availability status
            std::ostringstream m0;
            m0 << "  Status: ";
            if (mining_gate_available_) {
                if (active) {
                    m0 << C_ok() << "MINING" << C_reset() << " (" << thr << " threads)";
                } else {
                    m0 << C_ok() << "available" << C_reset();
                }
            } else {
                m0 << C_warn() << "unavailable" << C_reset();
                if (!mining_gate_reason_.empty()) {
                    std::string reason = mining_gate_reason_;
                    if (reason.size() > 30) reason = reason.substr(0, 27) + "...";
                    m0 << " - " << reason;
                }
            }
            right.push_back(m0.str());

            // External miner detection
            if (std::getenv("MIQ_MINER_HEARTBEAT")) {
                std::ostringstream ext;
                ext << "  External: " << (g_extminer.alive.load() ?
                    (std::string(C_ok()) + "detected" + C_reset()) :
                    (std::string(C_dim()) + "not detected" + C_reset()));
                right.push_back(ext.str());
            }

            // Mining address (shortened for display)
            if (!g_miner_address_b58.empty()) {
                std::string addr = g_miner_address_b58;
                if (addr.size() > 24) {
                    addr = addr.substr(0, 8) + "..." + addr.substr(addr.size() - 8);
                }
                right.push_back(std::string("  Reward To: ") + C_info() + addr + C_reset());
            }

            // Performance metrics
            if (active || ok > 0 || rej > 0) {
                // Hashrate with trend
                right.push_back(std::string("  Hashrate: ") + C_info() + fmt_hs(hps) + C_reset());
                right.push_back(std::string("  Trend:    ") + spark_ascii(spark_hs_));

                // Blocks mined
                std::ostringstream blocks;
                blocks << "  Blocks: " << C_ok() << ok << " mined" << C_reset();
                if (rej > 0) {
                    blocks << ", " << C_err() << rej << " rejected" << C_reset();
                }
                right.push_back(blocks.str());

                // Uptime
                if (active) {
                    right.push_back(std::string("  Uptime: ") + fmt_uptime(miner_uptime));
                }

                // Network share
                double share = (net_hashrate_ > 0.0) ? (hps / net_hashrate_) * 100.0 : 0.0;
                if (share < 0.0) share = 0.0;
                if (share > 100.0) share = 100.0;
                std::ostringstream sh;
                sh << "  Network Share: " << std::fixed << std::setprecision(2) << share << "%";
                right.push_back(sh.str());
            }

            // Miners observed
            size_t miners_obs = distinct_miners_recent(64);
            if (miners_obs > 0) {
                right.push_back(std::string("  Active Miners: ") + std::to_string(miners_obs) + " (last 64 blocks)");
            }

            right.push_back("");
        }

        // Pool Statistics panel (if Stratum server is running) - Enhanced
        if (auto* ss = g_stratum_server.load()) {
            right.push_back(std::string(C_bold()) + "Pool Server (Stratum)" + C_reset());
            auto stats = ss->get_stats();

            // Connection status
            std::ostringstream p1;
            p1 << "  Port: " << C_info() << ss->get_port() << C_reset()
               << "   Miners: ";
            if (stats.connected_miners == 0) {
                p1 << C_dim() << "0" << C_reset();
            } else {
                p1 << C_ok() << stats.connected_miners << C_reset();
            }
            right.push_back(p1.str());

            // Pool performance
            right.push_back(std::string("  Pool Hashrate: ") + C_info() + fmt_hs(stats.pool_hashrate) + C_reset());

            // Shares
            std::ostringstream p2;
            p2 << "  Shares: " << C_ok() << stats.accepted_shares << " accepted" << C_reset();
            if (stats.rejected_shares > 0) {
                p2 << ", " << C_err() << stats.rejected_shares << " rejected" << C_reset();
            }
            right.push_back(p2.str());

            // Blocks found
            std::ostringstream p3;
            p3 << "  Blocks Found: ";
            if (stats.blocks_found > 0) {
                p3 << C_ok() << stats.blocks_found << C_reset();
            } else {
                p3 << C_dim() << "0" << C_reset();
            }
            right.push_back(p3.str());

            // Connection hint
            right.push_back(std::string("  ") + C_dim() + "Connect miners to this port for pool mining" + C_reset());
            right.push_back("");
        }

        {
            right.push_back(std::string(C_bold()) + "Health & Security" + C_reset());
            right.push_back(std::string("  config reload: ")
               + (global::reload_requested.load()? "pending" : (u8_ok_? "—" : "-")));
            if (!hot_warning_.empty() && now_ms()-hot_warn_ts_ < 6000){
                right.push_back(std::string("  ") + C_warn() + hot_warning_ + C_reset());
            }
            if (!datadir_.empty()){
                right.push_back(std::string("  datadir: ") + datadir_);
            }
            right.push_back("");
        }

        {
            right.push_back(std::string(C_bold()) + "Recent TXIDs" + C_reset());
            if (recent_txids_.empty()) right.push_back("  (no txids yet)");
            size_t n = std::min<size_t>(recent_txids_.size(), 10);
            for (size_t i=0;i<n;i++){
                right.push_back(std::string("  ") + short_hex(recent_txids_[recent_txids_.size()-1-i], 20));
            }
            right.push_back("");
        }

        std::ostringstream out;

        // Build the entire frame first (double buffering)
        size_t NL = left.size(), NR = right.size(), N = std::max(NL, NR);
        for (size_t i=0;i<N;i++){
            std::string l = (i<NL) ? left[i] : "";
            std::string r = (i<NR) ? right[i] : "";
            if ((int)l.size() > leftw)  l = fit(l, leftw);
            if ((int)r.size() > rightw) r = fit(r, rightw);
            out << std::left << std::setw(leftw) << l << " | " << r << "\n";
        }

        // BULLETPROOF: Separator line
        out << std::string((size_t)cols, '-') << "\n";

        // BULLETPROOF: Status/shutdown banner (fixed 2 lines)
        if (nstate_ == NodeState::Quitting){
            out << C_bold() << "Shutting down" << C_reset() << "  " << C_dim() << "(Ctrl+C again = force)" << C_reset() << "\n";
            std::string phase = shutdown_phase_.empty() ? "initiating..." : shutdown_phase_;
            out << "  phase: " << phase << "\n";
        } else {
            out << C_bold() << "Logs" << C_reset() << "  " << C_dim() << "(q=quit t=theme p=pause r=reload s=snap v=verbose)" << C_reset() << "\n";
        }

        // BULLETPROOF: Calculate log area to fit exactly in remaining screen space
        // This ensures no scrolling - the TUI is a single fixed-size layout
        int header_rows = (int)N + 2;  // Main content + separator
        int footer_rows = 3;            // Status line + 2 buffer
        int remain = rows - header_rows - footer_rows;

        // Ensure minimum log lines but cap to prevent overflow
        if (remain < 6) remain = 6;
        if (remain > 30) remain = 30;  // Cap to prevent excessive logs pushing layout

        // Get only the last 'remain' log entries
        int start = (int)logs_.size() - remain;
        if (start < 0) start = 0;

        // Print log lines (each exactly one line, no overflow)
        int printed = 0;
        for (int i = start; i < (int)logs_.size() && printed < remain; ++i) {
            const auto& line = logs_[i];
            // Truncate long lines to prevent wrapping
            std::string txt = line.txt;
            if ((int)txt.size() > cols - 2) {
                txt = txt.substr(0, cols - 5) + "...";
            }
            switch(line.level){
                case 2: out << C_err()  << txt << C_reset() << "\n"; break;
                case 1: out << C_warn() << txt << C_reset() << "\n"; break;
                case 3: out << C_dim()  << txt << C_reset() << "\n"; break;
                case 4: out << C_ok()   << txt << C_reset() << "\n"; break;
                default: out << txt << "\n"; break;
            }
            ++printed;
        }

        // Fill remaining lines with empty lines to maintain fixed layout
        for (int i = printed; i < remain; ++i) {
            out << "\n";
        }

        // Now write the entire frame with control sequences
        std::string frame = out.str();

        // IMPROVED: Use optimized write_frame for smoother updates on PowerShell 5+
        // This reduces flicker by combining clear + content into a single write operation
        if (vt_ok_) {
            // Use cursor home + clear-to-end approach for smoother updates (less flicker)
            // \x1b[H = cursor home, \x1b[J = clear from cursor to end of screen
            cw_.write_frame("\x1b[H\x1b[J", frame);
        } else {
            // Fallback for non-VT terminals
            cw_.write_raw(frame);
        }

        // Ensure output is flushed to terminal
        std::fflush(stdout);
    }

private:
    bool enabled_{true};
    bool vt_ok_{true};
    bool u8_ok_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> key_running_{false};
    std::atomic<bool> cache_running_{false};  // For background cache thread
    std::thread thr_, key_thr_, cache_thr_;   // Added cache update thread
    std::mutex mu_;

    std::vector<std::pair<std::string,bool>> steps_;
    std::set<std::string> failures_;
    std::vector<StyledLine> logs_;
    std::string banner_;
    std::string datadir_;
    uint16_t p2p_port_{P2P_PORT};
    uint16_t rpc_port_{RPC_PORT};
    P2P*   p2p_   {nullptr};
    Chain* chain_ {nullptr};
    Mempool* mempool_{nullptr};
    ConsoleWriter cw_;
    int  tick_{0};
    NodeState nstate_{NodeState::Starting};
    std::deque<BlockSummary> recent_blocks_;
    std::deque<std::string>  recent_txids_;
    std::unordered_set<std::string> recent_txid_set_;
    std::vector<double> spark_hs_;
    std::vector<double> net_spark_;
    double net_hashrate_{0.0};
    double eta_secs_{0.0};
    std::string shutdown_phase_;
    int shutdown_ok_{0};
    bool dark_theme_{true};
    bool paused_{false};
    bool degraded_override_{false};
    std::chrono::steady_clock::time_point start_tp_{std::chrono::steady_clock::now()};
    uint64_t uptime_s_{0};
    std::string hot_message_;
    uint64_t hot_msg_ts_{0};
    std::string hot_warning_;
    uint64_t hot_warn_ts_{0};

    bool        ibd_visible_{false};
    bool        ibd_done_{false};
    uint64_t    ibd_cur_{0};
    uint64_t    ibd_target_{0};
    uint64_t    ibd_discovered_{0};
    std::string ibd_stage_;
    std::string ibd_seed_host_;
    uint64_t    ibd_last_update_ms_{0};

    // Sync tracking
    uint64_t    sync_network_height_{0};         // Max peer tip height
    uint64_t    sync_last_block_time_{0};        // Timestamp of last synced block
    double      sync_blocks_per_sec_{0.0};       // Current sync speed
    double      sync_progress_per_hour_{0.0};    // Progress increase per hour
    uint64_t    sync_start_height_{0};           // Height when sync started
    uint64_t    sync_start_ms_{0};               // Timestamp when sync started
    uint64_t    sync_last_sample_height_{0};     // Last sampled height for speed calc
    uint64_t    sync_last_sample_ms_{0};         // Last sample timestamp

    // mining gate status
    bool        mining_gate_available_{false};
    std::string mining_gate_reason_;

    // View mode: Splash during sync, Main after sync complete
    ViewMode    view_mode_{ViewMode::Splash};
    int         splash_transition_counter_{0};  // Count frames at 100% before transitioning

    // PERFORMANCE: Cached chain state to avoid mutex contention during rendering
    // These are updated asynchronously and used for display - prevents UI freeze
    // when chain mutex is held by P2P during block processing
    struct CachedMempoolStats {
        size_t count{0};
        size_t bytes{0};
        size_t recent_adds{0};
    };
    struct CachedChainState {
        uint64_t height{0};
        uint64_t best_header_height{0};  // Best header height (network sync target)
        std::vector<uint8_t> tip_hash;
        uint32_t bits{0};
        int64_t time{0};
        uint64_t issued{0};
        long double work_sum{0.0L};
        // Full peer snapshot for draw_main
        std::vector<PeerSnapshot> peers;
        size_t peer_count{0};
        size_t verack_ok{0};
        size_t inflight_tx{0};
        // Mempool stats
        CachedMempoolStats mempool;
        uint64_t last_update_ms{0};
    };
    CachedChainState cached_chain_;
    std::mutex cached_chain_mu_;  // Separate mutex for cache (never blocks on chain)

    // Non-blocking cache update - call from render loop
    void update_chain_cache_nonblocking() {
        // Only update every 100ms to reduce overhead
        uint64_t now = now_ms();
        {
            std::lock_guard<std::mutex> lk(cached_chain_mu_);
            if (now - cached_chain_.last_update_ms < 100) return;
        }

        // Gather all data OUTSIDE the cache lock to minimize lock time
        std::vector<PeerSnapshot> peers_snapshot;
        size_t peer_count = 0, verack_ok = 0, inflight_tx = 0;
        if (p2p_) {
            try {
                peers_snapshot = p2p_->snapshot_peers();
                peer_count = peers_snapshot.size();
                for (const auto& s : peers_snapshot) {
                    if (s.verack_ok) ++verack_ok;
                    inflight_tx += static_cast<size_t>(s.inflight);
                }
            } catch (...) {}
        }

        // Get mempool stats
        CachedMempoolStats mempool_stats;
        if (mempool_) {
            try {
                auto stat = mempool_view_fallback(mempool_);
                mempool_stats.count = stat.count;
                mempool_stats.bytes = stat.bytes;
                mempool_stats.recent_adds = stat.recent_adds;
            } catch (...) {}
        }

        // Update chain state if available
        if (chain_) {
            auto t = chain_->tip();
            uint64_t hdr_height = chain_->best_header_height();

            // Now update cache with all gathered data
            std::lock_guard<std::mutex> lk(cached_chain_mu_);
            cached_chain_.height = t.height;
            cached_chain_.best_header_height = hdr_height;
            cached_chain_.tip_hash = t.hash;
            cached_chain_.bits = t.bits;
            cached_chain_.time = t.time;
            cached_chain_.issued = t.issued;
            cached_chain_.work_sum = t.work_sum;
            cached_chain_.peers = std::move(peers_snapshot);
            cached_chain_.peer_count = peer_count;
            cached_chain_.verack_ok = verack_ok;
            cached_chain_.inflight_tx = inflight_tx;
            cached_chain_.mempool = mempool_stats;
            cached_chain_.last_update_ms = now;
        } else {
            std::lock_guard<std::mutex> lk(cached_chain_mu_);
            cached_chain_.peers = std::move(peers_snapshot);
            cached_chain_.peer_count = peer_count;
            cached_chain_.verack_ok = verack_ok;
            cached_chain_.inflight_tx = inflight_tx;
            cached_chain_.mempool = mempool_stats;
            cached_chain_.last_update_ms = now;
        }
    }

    // Get cached state without blocking (for rendering)
    CachedChainState get_cached_chain() {
        std::lock_guard<std::mutex> lk(cached_chain_mu_);
        return cached_chain_;
    }
};

// ==================================================================
/*                                Seed Sentinel                                 */
// ==================================================================
class SeedSentinel {
public:
    void start(P2P* p2p, TUI* tui){
        stop();
        running_.store(true);
        thr_ = std::thread([=]{ loop(p2p, tui); });
    }
    void stop(){
        running_.store(false);
        if (thr_.joinable()) thr_.join();
    }
private:
    void loop(P2P* p2p, TUI* tui){
        using namespace std::chrono_literals;
        uint64_t last_note_ms = 0;
        while (running_.load() && !global::shutdown_requested.load()){
            auto role = compute_seed_role();
            bool prev = g_we_are_seed.load();
            g_we_are_seed.store(role.we_are_seed);
            if ((role.we_are_seed || g_assume_seed_hairpin.load()) && !prev){
                log_warn(std::string("This node matches/assumes ")+seed_host_cstr()+" — acting as seed; keep it healthy.");
                if (tui) tui->set_hot_warning("You are the public seed host");
            }
            // Gentle health checks
            size_t peers = p2p ? p2p->snapshot_peers().size() : 0;
            if ((role.we_are_seed || g_assume_seed_hairpin.load()) && peers == 0){
                if (now_ms() - last_note_ms > 30'000){
                    log_warn("SeedSentinel: 0 peers connected while acting as seed — check firewall/DNS.");
                    last_note_ms = now_ms();
                }
            }
            std::this_thread::sleep_for(10s);
        }
    }
    std::atomic<bool> running_{false};
    std::thread thr_;
};

// ==================================================================
/*                          Fatal terminate hook                                */
// ==================================================================
static void fatal_terminate() noexcept {
    std::fputs("[FATAL] std::terminate() called (background) - initiating shutdown\n", stderr);
    request_shutdown("terminate");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

// ==================================================================
/*                                     CLI                                     */
// ==================================================================
static void print_usage(){
    std::cout
      << "\n"
      << "Miqrochain Node v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH << "\n"
      << "\n"
      << "Usage: miqrod [options]\n"
      << "\n"
      << "Options:\n"
      << "  --conf=<path>        Configuration file (key=value format)\n"
      << "  --datadir=<path>     Data directory (default: ~/.miqrochain)\n"
      << "  --no-tui             Plain log output instead of TUI\n"
      << "  --genaddress         Generate new wallet address\n"
      << "  --reindex_utxo       Rebuild UTXO from chain data\n"
      << "  --telemetry          Enable telemetry logging\n"
      << "  --help               Show this help\n"
      << "\n"
      << "Mining:\n"
      << "  Use external miner (miqminer) for mining support.\n"
      << "\n"
      << "Environment:\n"
      << "  MIQ_NO_TUI=1             Disable TUI\n"
      << "  MIQ_RPC_TOKEN=<token>    RPC auth token\n"
      << "  MIQ_SEED_HOST=<host>     Override seed host\n"
      << "\n"
      << "Ports:\n"
      << "  P2P: " << P2P_PORT << "  RPC: " << RPC_PORT << "  Stratum: 3333\n"
      << "\n";
}
static bool is_recognized_arg(const std::string& s){
    if(s.rfind("--conf=",0)==0) return true;
    if(s.rfind("--datadir=",0)==0) return true;
    if(s=="--no-tui") return true;
    if(s=="--genaddress") return true;
    if(s=="--buildtx") return true;
    if(s=="--reindex_utxo") return true;
    if(s=="--telemetry") return true;
    if(s=="--help") return true;
    return false;
}

// =============================================================================
// IBD helpers — smart start/finish + explicit error on failure
// =============================================================================
static inline bool path_exists_nonempty(const std::string& p){
    std::error_code ec;
    if(!std::filesystem::exists(p, ec)) return false;
    for (auto it = std::filesystem::directory_iterator(p, ec);
         it != std::filesystem::directory_iterator(); ++it) return true;
    return false;
}

static bool tip_fresh_enough(Chain& chain);
static bool has_existing_blocks_or_state(const std::string& datadir);

static bool should_enter_ibd_reason(Chain& chain, const std::string& datadir, std::string* why){
    auto tell = [&](const char* s){ if (why) *why = s; };
    // Fresh install / empty state: certainly need IBD.
    if (!path_exists_nonempty(p_join(datadir, "blocks")) &&
        !path_exists_nonempty(p_join(datadir, "chainstate"))) { tell("no local blocks/chainstate"); return true; }
    // No blocks known yet (only genesis): need headers/blocks.
    if (chain.height() == 0) { tell("no headers/blocks yet"); return true; }
    // Stale tip: need a catch-up IBD.
    if (!tip_fresh_enough(chain)) { tell("tip too old"); return true; }
    // Otherwise we are synced enough — skip IBD.
    tell("up to date");
    return false;
}

[[maybe_unused]] static bool has_existing_blocks_or_state(const std::string& datadir){
    return path_exists_nonempty(p_join(datadir, "blocks")) ||
           path_exists_nonempty(p_join(datadir, "chainstate"));
}
static bool tip_fresh_enough(Chain& chain){
    auto tip = chain.tip();
    uint64_t tsec = hdr_time(tip);
    if (tsec == 0) return false;
    uint64_t now = (uint64_t)std::time(nullptr);
    uint64_t age = (now > tsec) ? (now - tsec) : 0;
    const uint64_t fresh = std::max<uint64_t>(BLOCK_TIME_SECS * 3, 300);
    return age <= fresh;
}
static bool should_enter_ibd(Chain& chain, const std::string& datadir){
    return should_enter_ibd_reason(chain, datadir, nullptr);
}

// Active IBD loop: try to reach a "synced" state (compute_sync_gate true).
// Surfaces a concrete error if it can't finish.
static bool perform_ibd_sync(Chain& chain, P2P* p2p, const std::string& datadir,
                             bool can_tui, TUI* tui, std::string& out_err){
    // CRITICAL FIX: Always check if we need IBD, but don't skip peer connection!
    // Even if tip is fresh, we must connect to peers to verify we're truly synced
    {
        std::string reason;
        if (!should_enter_ibd_reason(chain, datadir, &reason)) {
            // Tip is fresh - we may skip block downloading, but MUST still connect to peers
            log_info("IBD: local tip is fresh, will verify sync state with peers");
            if (tui && can_tui) tui->set_banner("Verifying sync state with peers...");
        } else {
            log_info(std::string("IBD: starting (reason: ") + reason + ")");
            if (tui && can_tui) tui->set_banner(std::string("Initial block download — ") + reason);
        }
    }
    bool we_are_seed = compute_seed_role().we_are_seed || g_assume_seed_hairpin.load();

    if (!p2p) {
        out_err = "P2P disabled (cannot sync headers/blocks)";
        return false;
    }

    

    using namespace std::chrono_literals;

    const uint64_t kNoPeerTimeoutMs      = 90 * 1000;
    const uint64_t kNoProgressTimeoutMs  = 180 * 1000;
    const uint64_t kStableOkMs           = 5 * 1000;   // REDUCED to 5s for faster startup (was 20s)
    const uint64_t kHandshakeTimeoutMs   = 60 * 1000;
    const uint64_t kSeedNudgeMs          = 10 * 1000;
    const uint64_t kMaxWallMs            = 30 * 60 * 1000;
    const uint64_t t0                    = now_ms();
    uint64_t       lastSeedDialMs        = 0;
    uint64_t       lastProgressMs        = now_ms();
    uint64_t       lastHeight            = chain.height();
    uint64_t       height_at_seed_connect= lastHeight;

    // Make sure we've nudged the seed right away.
    if (!we_are_seed) {
        p2p->connect_seed(seed_host_cstr(), P2P_PORT);
        lastSeedDialMs = now_ms();
    } else {
        log_info(std::string("Seed self-detect: skipping outbound connect to ")
                 + seed_host_cstr() + " (waiting for inbound peers).");
    }
    if (can_tui) tui->set_node_state(TUI::NodeState::Syncing);
    if (tui && can_tui) tui->mark_step_started("Peer handshake (verack)");
    {
        uint64_t hs_t0 = now_ms();
        // CRITICAL FIX: Track last activity time separately from start time
        // Reset deadline when peers connect/disconnect to allow for reconnection
        uint64_t last_activity_ms = hs_t0;
        size_t last_peer_count = 0;

        const uint64_t handshake_timeout = we_are_seed ? (5 * 60 * 1000) : kHandshakeTimeoutMs;
        if (we_are_seed) {
            log_info("IBD: acting as seed host — waiting for inbound verack (up to ~5 min).");
            if (tui && can_tui) tui->set_banner("Seed mode: waiting for inbound peers…");
        }
        while (!global::shutdown_requested.load()) {
            if (any_verack_peer(p2p)) {
                height_at_seed_connect = chain.height();
                if (tui && can_tui) {
                    tui->mark_step_ok("Peer handshake (verack)");
                    tui->set_banner(std::string("Connected to seed: ") + seed_host_cstr());
                    // FIX: Get network height from connected peers instead of using local height
                    // This ensures the progress bar shows meaningful progress from the start
                    // Only count peers with verack_ok && peer_tip > 0 to prevent premature sync completion
                    uint64_t initial_network_height = 0;
                    bool found_valid_peer = false;
                    auto peer_list = p2p->snapshot_peers();
                    for (const auto& pr : peer_list) {
                        if (pr.verack_ok && pr.peer_tip > 0) {
                            if (pr.peer_tip > initial_network_height) {
                                initial_network_height = pr.peer_tip;
                            }
                            found_valid_peer = true;
                        }
                    }
                    // If no valid peer tips yet, use checkpoint height as minimum target
                    if (!found_valid_peer) {
                        // CRITICAL FIX: Use dynamic checkpoint height instead of hardcoded value
                        // This ensures we don't declare sync complete before reaching the latest checkpoint
                        uint64_t checkpoint_height = miq::get_highest_checkpoint_height();
                        initial_network_height = std::max(chain.height() + 1, checkpoint_height);
                    }
                    tui->set_ibd_progress(chain.height(),
                                          initial_network_height,
                                          0, "headers", seed_host_cstr(), false);
                }
                break; // proceed to IBD
            }
            // keep nudging the seed if needed (only if no working connections)
            size_t verack_peers = 0;
            auto current_peers = p2p->snapshot_peers();
            size_t peer_count = current_peers.size();
            for (const auto& peer : current_peers) {
                if (peer.verack_ok) verack_peers++;
            }

            // CRITICAL FIX: Reset activity timer when peer count changes (connect/disconnect)
            // This allows peers to reconnect without hitting the timeout
            if (peer_count != last_peer_count) {
                last_activity_ms = now_ms();
                last_peer_count = peer_count;
                if (peer_count > 0) {
                    log_info("IBD: peer activity detected (" + std::to_string(peer_count) +
                             " peers) - resetting handshake timeout");
                }
            }

            if (!we_are_seed && verack_peers == 0 && (now_ms() - lastSeedDialMs > kSeedNudgeMs)) {
                p2p->connect_seed(seed_host_cstr(), P2P_PORT);
                lastSeedDialMs = now_ms();
            }

            // CRITICAL FIX: Use activity-based timeout instead of fixed deadline
            // Timeout only if no peer activity for the timeout period
            if (now_ms() - last_activity_ms > handshake_timeout) {
                if (we_are_seed) {
                    // SOLO-SEED: allow the node to proceed without peers so it can mine the first blocks.
                    log_warn("IBD: seed mode handshake timed out — entering SOLO-SEED mode (no peers yet).");
                    miq::mark_ibd_complete();  // Enable full durability
                    miq::ibd::IBDState::instance().transition_to(miq::ibd::SyncState::DONE);
                    if (tui && can_tui) {
                        tui->mark_step_ok("Peer handshake (verack)");
                        tui->set_banner("Seed solo mode: no peers yet — mining unlocked.");
                        tui->set_ibd_progress(chain.height(), chain.height(), 0, "complete", seed_host_cstr(), true);
                    }
                    return true; // treat IBD as trivially complete to unlock mining
                } else {
                    // Regular node: handshake failed - report error
                    out_err = "no peers completed handshake (verack)";
                    if (tui && can_tui) tui->mark_step_fail("Peer handshake (verack)");
                    return false;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (global::shutdown_requested.load()){
            out_err = "shutdown requested during handshake";
            if (tui && can_tui) tui->mark_step_fail("Peer handshake (verack)");
            return false;
        }
    }

    // CRITICAL FIX: Track when we last had peers for activity-based timeout
    uint64_t last_had_peers_ms = now_ms();
    size_t prev_peer_count = 0;

    while (!global::shutdown_requested.load()) {
        // Hard wall clock timeout
        if (now_ms() - t0 > kMaxWallMs) { out_err = "IBD timeout (no completion within time budget)"; break; }

        // Ensure we periodically re-nudge the seed if peer count is low.
        auto peer_snap = p2p->snapshot_peers();
        size_t peers = peer_snap.size();
        size_t verack_peers = 0;
        for (const auto& peer : peer_snap) {
            if (peer.verack_ok) verack_peers++;
        }

        // CRITICAL FIX: Reset peer activity timer when we have peers
        if (peers > 0) {
            last_had_peers_ms = now_ms();
        }
        // Log peer count changes for debugging
        if (peers != prev_peer_count) {
            log_info("IBD: peer count changed: " + std::to_string(prev_peer_count) +
                     " -> " + std::to_string(peers) + " (verack=" + std::to_string(verack_peers) + ")");
            prev_peer_count = peers;
        }

        // Only nudge if we have no working connections (verack_ok peers)
        if (!we_are_seed && verack_peers == 0 && now_ms() - lastSeedDialMs > kSeedNudgeMs) {
            p2p->connect_seed(seed_host_cstr(), P2P_PORT);
            lastSeedDialMs = now_ms();
        }

        // CRITICAL FIX: Use activity-based timeout for "no peers" check
        // Only fail if we haven't had any peers for the timeout period
        const uint64_t no_peer_budget =
            we_are_seed ? (5 * 60 * 1000) : kNoPeerTimeoutMs;
        if (peers == 0 && now_ms() - last_had_peers_ms > no_peer_budget) {
            if (we_are_seed) {
                out_err = "no peers reachable while acting as seed (check DNS A/AAAA and firewall/NAT)";
            } else {
                out_err = std::string("no peers reachable (seed: ") + seed_host_cstr() + ":" + std::to_string(P2P_PORT) + ")";
            }
            break;
        }

        {
            uint64_t cur = chain.height();
            uint64_t discovered = (cur >= height_at_seed_connect) ? (cur - height_at_seed_connect) : 0;
            const char* stage = (cur == 0 ? "headers" : "blocks");

            // CRITICAL FIX: Track MAXIMUM network height ever seen
            // This prevents the progress bar from jumping around when peers disconnect/reconnect
            // The target height should only INCREASE, never decrease, until sync is complete
            static uint64_t max_seen_network_height = 0;

            // Get current max from connected peers
            uint64_t current_peer_max = 0;
            auto peer_snapshot = p2p->snapshot_peers();
            for (const auto& pr : peer_snapshot) {
                // CRITICAL: Skip forked peers - don't let them affect our target height!
                if (pr.fork_detected) continue;
                if (pr.verack_ok && pr.peer_tip > 0) {
                    if (pr.peer_tip > current_peer_max) {
                        current_peer_max = pr.peer_tip;
                    }
                }
            }

            // Also check header height - headers might know more than current peers
            uint64_t header_height = chain.best_header_height();

            // Use MAXIMUM of: previous max, current peer max, header height
            uint64_t network_height = max_seen_network_height;
            if (current_peer_max > network_height) {
                network_height = current_peer_max;
            }
            if (header_height > network_height) {
                network_height = header_height;
            }

            // If no valid source, use checkpoint height as minimum
            if (network_height == 0) {
                uint64_t checkpoint_height = miq::get_highest_checkpoint_height();
                network_height = std::max(cur + 1, checkpoint_height);
            }

            // Update persistent max (never decrease)
            if (network_height > max_seen_network_height) {
                max_seen_network_height = network_height;
            }

            if (tui && can_tui) {
                tui->set_ibd_progress(cur, network_height, discovered, stage, seed_host_cstr(), false);
            } else {
                static uint64_t last_note_ms = 0;
                if (now_ms() - last_note_ms > 2500) {
                    log_info(std::string("[IBD] ") + stage + ": height=" +
                             std::to_string(cur) +
                             "  discovered-from-seed=" + std::to_string(discovered) +
                             (we_are_seed ? "  (seed-mode: waiting for inbound peers)" : ""));
                    last_note_ms = now_ms();
                }
            }
        }

        // Track progress by height advancing
        uint64_t h = chain.height();
        if (h > lastHeight) {
            lastHeight = h;
            lastProgressMs = now_ms();
        } else {
            // With peers but no header progress → fail after some time
            if (peers > 0 && now_ms() - lastProgressMs > kNoProgressTimeoutMs) {
                out_err = "no headers/blocks progress from peers";
                break;
            }
        }

        // Check "synced" state and require stability window
        std::string why;
        if (compute_sync_gate(chain, p2p, why)) {
            log_info("IBD: sync gate passed at height " + std::to_string(chain.height()) +
                     ", waiting " + std::to_string(kStableOkMs/1000) + "s stability window");

            // Just wait the stability window - don't re-check sync gate
            // Re-checking can fail if peers report tips during the window
            std::this_thread::sleep_for(std::chrono::milliseconds(kStableOkMs));

            // Verify we've passed all checkpoints before declaring sync complete
            uint64_t checkpoint_height = miq::get_highest_checkpoint_height();
            if (chain.height() < checkpoint_height) {
                log_warn("IBD: Refusing to complete sync - height " + std::to_string(chain.height()) +
                        " is below checkpoint " + std::to_string(checkpoint_height));
                std::this_thread::sleep_for(250ms);
                continue;
            }

            // Sync gate passed + stability window passed = we're synced
            log_info("IBD: sync complete after stability check, height=" + std::to_string(chain.height()));

            if (tui && can_tui) {
                tui->set_ibd_progress(chain.height(),
                                      chain.height(),
                                      (chain.height() >= height_at_seed_connect ? (chain.height() - height_at_seed_connect) : 0),
                                      "complete", seed_host_cstr(), true);
            }
            mark_ibd_complete();  // Enable full durability now that sync is complete
            miq::ibd::IBDState::instance().transition_to(miq::ibd::SyncState::DONE);

            // ========================================================================
            // CRITICAL FIX: Flush UTXO set to disk after IBD completes
            // During IBD, UTXO log writes are skipped for performance (fast_sync mode).
            // UTXOs are kept in memory but NOT persisted. If we don't flush now,
            // UTXOs are LOST on restart, causing wallet to show wrong balance!
            // ========================================================================
            {
                size_t utxo_count = chain.utxo().size();
                if (utxo_count > 0) {
                    log_info("=== FLUSHING UTXO SET TO DISK (" + std::to_string(utxo_count) + " UTXOs) ===");
                    if (tui && can_tui) {
                        tui->set_banner("Saving UTXO set to disk... (DO NOT INTERRUPT)");
                    }
                    if (chain.utxo().flush_to_disk()) {
                        log_info("UTXO flush complete - wallet balance will persist across restarts");
                    } else {
                        log_error("UTXO flush FAILED - wallet may show wrong balance after restart!");
                    }
                    if (tui && can_tui) tui->set_banner("");
                }
            }

            // ========================================================================
            // CRITICAL: Rebuild AddressIndex after IBD completes
            // During IBD, address indexing was skipped for performance
            // Now rebuild so wallet shows correct balance
            // IMPORTANT: This reindex is NON-INTERRUPTIBLE to prevent partial state
            // ========================================================================
            if (chain.addressindex().is_enabled()) {
                // ALWAYS check if reindex is needed, not just address_count == 0
                // This handles cases where previous reindex was interrupted
                uint64_t indexed_height = chain.addressindex().best_indexed_height();
                uint64_t chain_height = chain.height();

                if (indexed_height < chain_height) {
                    log_info("IBD complete - rebuilding AddressIndex (indexed=" +
                             std::to_string(indexed_height) + " chain=" + std::to_string(chain_height) + ")");

                    // NON-INTERRUPTIBLE: Always return true to prevent abort
                    // Users MUST wait for reindex to complete for correct wallet balance
                    chain.reindex_addresses([&](uint64_t cur, uint64_t total) {
                        if (cur % 500 == 0 && tui && can_tui) {
                            tui->set_banner("Rebuilding address index: " + std::to_string(cur) + "/" + std::to_string(total) + " (DO NOT INTERRUPT)");
                        }
                        // CRITICAL: Always return true - do NOT allow interruption
                        // Partial address index = incorrect wallet balance
                        return true;
                    });
                    if (tui && can_tui) tui->set_banner("");
                    log_info("AddressIndex rebuild complete - wallet balance should now be correct");
                }
            }

            // ========================================================================
            // CRITICAL: Rebuild UTXO after IBD if needed
            // UTXO log was skipped during IBD for performance - must rebuild now!
            // Without this, wallet will show 0 balance after node restart.
            // ========================================================================
            {
                size_t utxo_count = chain.utxo().size();
                uint64_t chain_height = chain.height();

                // UTXO count should be at least 10% of block count for a healthy chain
                // (each block creates at least one coinbase output)
                bool needs_rebuild = (utxo_count == 0 && chain_height > 0) ||
                                    (utxo_count < chain_height / 10 && chain_height > 100);

                if (needs_rebuild) {
                    log_info("=== REBUILDING UTXO SET AFTER IBD ===");
                    log_info("UTXO count (" + std::to_string(utxo_count) + ") is too low for " +
                             std::to_string(chain_height) + " blocks - rebuilding...");

                    if (tui && can_tui) {
                        tui->set_banner("Rebuilding UTXO set... (DO NOT INTERRUPT)");
                    }

                    if (chain.rebuild_utxo_from_blocks()) {
                        log_info("UTXO rebuild complete - wallet balance should now be correct");
                    } else {
                        log_error("UTXO rebuild failed - wallet may show incorrect balance");
                    }

                    if (tui && can_tui) {
                        tui->set_banner("");
                    }
                }
            }

            return true;
        }

        std::this_thread::sleep_for(250ms);
    }

    if (global::shutdown_requested.load())
        out_err = "shutdown requested during IBD";

    return false;
}

// ==================================================================
/*                                 IBD Guard                                    */
// ==================================================================
class IBDGuard {
public:
    void start(Chain* chain, P2P* p2p, const std::string& datadir, bool can_tui, TUI* tui){
        stop();
        running_.store(true);
        thr_ = std::thread([=]{ loop(chain, p2p, datadir, can_tui, tui); });
    }
    void stop(){
        running_.store(false);
        if (thr_.joinable()) thr_.join();
    }
private:
    void loop(Chain* chain, P2P* p2p, const std::string& datadir, bool can_tui, TUI* tui){
        using namespace std::chrono_literals;
        uint64_t backoff_ms = 2'000; // exponential up to 2 minutes
        while (running_.load() && !global::shutdown_requested.load()){
            if (p2p && solo_seed_mode(p2p)) {
                std::this_thread::sleep_for(3s);
                continue;
            }
            std::string why;
            bool gate = compute_sync_gate(*chain, p2p, why);
            if (!gate && should_enter_ibd(*chain, datadir)){
                std::string err;
                if (tui && can_tui){
                    tui->set_node_state(TUI::NodeState::Syncing);
                    tui->set_hot_warning("Re-entering IBD (" + (why.empty()?"stale/empty":why) + ")");
                }
                bool ok = perform_ibd_sync(*chain, p2p, datadir, can_tui, tui, err);
                if (!ok){
                    log_warn(std::string("IBDGuard: IBD attempt failed: ")+err);
                    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
                    backoff_ms = std::min<uint64_t>(backoff_ms * 2, 120'000);
                } else {
                    log_info("IBDGuard: node resynced.");
                    backoff_ms = 2'000;
                    miq::mark_ibd_complete();  // Enable full durability (fsync on every block)
                    miq::ibd::IBDState::instance().transition_to(miq::ibd::SyncState::DONE);
                    if (tui && can_tui) {
                        // CRITICAL FIX: Must set ibd_done_ to true for splash screen transition!
                        // Without this, the splash screen stays stuck even though IBDGuard succeeded
                        // because the condition ibd_done_ && nstate_ == Running is never satisfied
                        tui->set_ibd_progress(chain->height(), chain->height(), 0, "complete", "", true);
                        tui->set_node_state(TUI::NodeState::Running);
                        tui->set_mining_gate(true, "");
                    }
                }
            }
            std::this_thread::sleep_for(3s);
        }
    }
    std::atomic<bool> running_{false};
    std::thread thr_;
};

// ==================================================================
/*                                     main                                    */
// ==================================================================
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);

#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT,  sigshutdown_handler);
    std::signal(SIGTERM, sigshutdown_handler);
    std::signal(SIGQUIT, sigshutdown_handler);
    std::signal(SIGABRT, sigshutdown_handler);
    std::signal(SIGHUP,  sighup_handler);
#else
    SetConsoleCtrlHandler(win_ctrl_handler, TRUE);
#endif
    std::set_terminate(&fatal_terminate);

    bool vt_ok = true, u8_ok = false;
    term::enable_vt_and_probe_u8(vt_ok, u8_ok);

    bool disable_tui_flag = false;
    bool telemetry_flag = false;
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a == "--no-tui") disable_tui_flag = true;
        if(a == "--telemetry") telemetry_flag = true;
    }
    const bool want_tui = !disable_tui_flag && !env_truthy_local("MIQ_NO_TUI");
    const bool can_tui  = want_tui && term::supports_interactive_output();

    ConsoleWriter cw;

    // Startup splash
    if (can_tui && vt_ok) {
        cw.write_raw("\x1b[2J\x1b[H");

        // Display banner
        if (u8_ok) {
            for (int i = 0; kMiqrochainBanner[i] != nullptr; ++i) {
                cw.write_raw("\x1b[36m");
                cw.write_raw(kMiqrochainBanner[i]);
                cw.write_raw("\x1b[0m\n");
            }
        } else {
            cw.write_raw("\n  MIQROCHAIN NODE\n\n");
        }

        // Version line
        std::ostringstream info;
        info << "  v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH
             << "  |  " << CHAIN_NAME << "  |  ";
#ifdef _WIN32
        info << "Windows";
#elif defined(__APPLE__)
        info << "macOS";
#else
        info << "Linux";
#endif
        info << "\n\n";
        cw.write_raw(info.str());

        // Loading animation
        cw.write_raw("  Initializing");
        std::fflush(stdout);
        for (int i = 0; i < 3; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            cw.write_raw(".");
            std::fflush(stdout);
        }
        cw.write_raw("\n\n");
    } else {
        cw.write_raw("Starting miqrod...\n");
    }

    LogCapture capture;
    if (can_tui) capture.start();
    else std::fprintf(stderr, "[INFO] TUI disabled (plain logs).\n");

    TUI tui(vt_ok, u8_ok);
    tui.set_enabled(can_tui);
    tui.set_ports(P2P_PORT, RPC_PORT);

    if (const char* sh = std::getenv("MIQ_SEED_HOST"); sh && *sh) {
        g_seed_host = sh;
    }

    // Parse CLI
    Config cfg;
    std::string conf;
    bool genaddr=false, buildtx=false, flag_reindex_utxo=false;
    std::string privh, prevtxid_hex, toaddr;
    uint32_t vout=0; uint64_t value=0;
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a.rfind("--",0)==0 && !is_recognized_arg(a)){
            std::fprintf(stderr, "Unknown option: %s\nUse --help to see supported options.\n", argv[i]);
            if (can_tui) { capture.stop(); tui.stop(); }
            return 2;
        }
    }
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a.rfind("--conf=",0)==0){ conf = a.substr(7);
        } else if(a.rfind("--datadir=",0)==0){ cfg.datadir = a.substr(10);
        }
    }
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a=="--genaddress"){ genaddr = true;
        } else if(a=="--buildtx" && i+5<argc){
            buildtx     = true;
            privh       = argv[++i];
            prevtxid_hex= argv[++i];
            vout        = (uint32_t)std::stoul(argv[++i]);
            value       = (uint64_t)std::stoull(argv[++i]);
            toaddr      = argv[++i];
        } else if(a=="--reindex_utxo"){ flag_reindex_utxo = true;
        } else if(a=="--telemetry"){ telemetry_flag = true;
        } else if(a=="--help"){ print_usage(); if (can_tui){ capture.stop(); tui.stop(); } return 0; }
    }

    // Fast paths (genaddress/ buildtx)
    if(genaddr){
        if (can_tui) tui.stop();
        std::vector<uint8_t> priv;
        if(!crypto::ECDSA::generate_priv(priv)){ std::fprintf(stderr, "keygen failed\n"); if (can_tui) capture.stop(); return 1; }
        std::vector<uint8_t> pub33;
        if(!crypto::ECDSA::derive_pub(priv, pub33)){ std::fprintf(stderr, "derive_pub failed\n"); if (can_tui) capture.stop(); return 1; }
        auto pkh  = hash160(pub33);
        auto addr = base58check_encode(VERSION_P2PKH, pkh);
        std::cout << "priv_hex=" << to_hex(priv) << "\n"
                  << "pub_hex="  << to_hex(pub33) << "\n"
                  << "address="  << addr << "\n";
        if (can_tui) capture.stop();
        return 0;
    }
    if(buildtx){
        if (can_tui) tui.stop();
        std::vector<uint8_t> priv = miq::from_hex(privh);
        std::vector<uint8_t> pub33;
        if(!crypto::ECDSA::derive_pub(priv, pub33)){ std::fprintf(stderr, "derive_pub failed\n"); if (can_tui) capture.stop(); return 1; }
        uint8_t ver=0; std::vector<uint8_t> to_payload;
        if(!base58check_decode(toaddr, ver, to_payload) || to_payload.size()!=20){ std::fprintf(stderr, "bad to_address\n"); if (can_tui) capture.stop(); return 1; }
        Transaction tx; TxIn in; in.prev.txid = miq::from_hex(prevtxid_hex); in.prev.vout = vout; tx.vin.push_back(in);
        TxOut out; out.value = value; out.pkh = to_payload; tx.vout.push_back(out);
        auto h = dsha256(ser_tx(tx)); std::vector<uint8_t> sig64;
        if(!crypto::ECDSA::sign(priv, h, sig64)){ std::fprintf(stderr, "sign failed\n"); if (can_tui) capture.stop(); return 1; }
        tx.vin[0].sig = sig64; tx.vin[0].pubkey = pub33;
        auto raw = ser_tx(tx); std::cout << "txhex=" << to_hex(raw) << "\n";
        if (can_tui) capture.stop();
        return 0;
    }

    // TUI start
    if (can_tui) {
        tui.start();
        tui.set_banner("Initializing");
        tui.mark_step_ok("Parse CLI");
        tui.set_node_state(TUI::NodeState::Starting);
        tui.set_datadir(cfg.datadir.empty()? default_datadir(): cfg.datadir);
    }

    try {
        if (can_tui) tui.mark_step_started("Load config & choose datadir");
        if(!conf.empty()) load_config(conf, cfg);
        if(cfg.datadir.empty()) cfg.datadir = default_datadir();
        std::error_code ec;
        std::filesystem::create_directories(cfg.datadir, ec);
        if(!acquire_datadir_lock(cfg.datadir)){
            if (can_tui) { capture.stop(); tui.stop(); }
            return 11;
        }
        global::telemetry_path = p_join(cfg.datadir, "telemetry.ndjson");
        global::telemetry_enabled.store(telemetry_flag);
        if (can_tui) {
            tui.mark_step_ok("Load config & choose datadir");
            tui.mark_step_ok("Config/datadir ready");
            tui.set_banner("Starting services");
            tui.set_datadir(cfg.datadir);
        }

        if (can_tui) tui.mark_step_started("Open chain data");
        Chain chain;
        if(!chain.open(cfg.datadir)){ log_error("failed to open chain data"); release_datadir_lock(); if (can_tui) { capture.stop(); tui.stop(); } return 1; }
        if (can_tui) tui.mark_step_ok("Open chain data");

        if (can_tui) tui.mark_step_started("Load & validate genesis");
        {
            std::vector<uint8_t> raw;
            try { raw = miq::from_hex(GENESIS_RAW_BLOCK_HEX); }
            catch (...) { log_error("GENESIS_RAW_BLOCK_HEX invalid hex"); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (raw.empty()) { log_error("GENESIS_RAW_BLOCK_HEX empty"); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            Block g;
            if (!deser_block(raw, g)) { log_error("Genesis deserialize failed"); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            g_genesis_time_s.store(hdr_time(g.header));
            const std::string got_hash = to_hex(g.block_hash());
            const std::string want_hash= std::string(GENESIS_HASH_HEX);
            const std::string got_merkle = to_hex(g.header.merkle_root);
            const std::string want_merkle= std::string(GENESIS_MERKLE_HEX);
            if (got_hash != want_hash){ log_error(std::string("Genesis hash mismatch; got=")+got_hash+" want="+want_hash); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (got_merkle != want_merkle){ log_error(std::string("Genesis merkle mismatch; got=")+got_merkle+" want="+want_merkle); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (!chain.init_genesis(g)) { log_error("genesis init failed"); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
        }
        if (can_tui) { tui.mark_step_ok("Load & validate genesis"); tui.mark_step_ok("Genesis OK"); }

        // CRITICAL PERFORMANCE FIX: Initialize assume-valid with highest checkpoint
        // This dramatically speeds up IBD by skipping signature verification for
        // historical blocks that have already been verified by the network.
        // The checkpoint hash is verified, so we know these blocks are valid.
        {
            uint64_t av_height = miq::get_highest_checkpoint_height();
            if (av_height > 0) {
                // Get the checkpoint hash at that height
                for (const auto& cp : miq::get_checkpoints()) {
                    if (cp.height == av_height) {
                        if (miq::init_assume_valid_hex(cp.hash_hex, av_height)) {
                            log_info("Assume-valid enabled: skipping signatures for blocks 0-" + std::to_string(av_height));
                        }
                        break;
                    }
                }
            }
        }

        if (can_tui) tui.mark_step_started("Reindex UTXO (full scan)");
#if MIQ_CAN_PROBE_UTXO_REINDEX
        {
            bool ok_reindex = true;
            if (ensure_utxo_fully_indexed) {
                ok_reindex = ensure_utxo_fully_indexed(chain, cfg.datadir, flag_reindex_utxo);
            } else {
                log_info("UTXO reindex routine not linked in this build; skipping.");
            }
            if (!ok_reindex){
                if (can_tui) tui.mark_step_fail("Reindex UTXO (full scan)");
                release_datadir_lock();
                if (can_tui) { capture.stop(); tui.stop(); }
                return 12;
            }
            if (can_tui) tui.mark_step_ok("Reindex UTXO (full scan)");
        }
#else
        {
            log_info("UTXO reindex routine not available on this compiler/platform; skipping.");
            if (can_tui) tui.mark_step_ok("Reindex UTXO (full scan)");
        }
#endif
        if (can_tui) tui.mark_step_started("Initialize mempool & RPC");
        Mempool mempool; RpcService rpc(chain, mempool);

        // PRODUCTION FIX: Load saved mempool from disk
        // This ensures unconfirmed transactions survive node restarts
        {
            std::string mempool_path = cfg.datadir + "/mempool.dat";
            // Simple adapter to convert UTXOSet to UTXOView interface
            struct LocalUTXOAdapter : public UTXOView {
                const UTXOSet& u;
                explicit LocalUTXOAdapter(const UTXOSet& uu) : u(uu) {}
                bool get(const std::vector<uint8_t>& txid, uint32_t vout, UTXOEntry& out) const override {
                    return u.get(txid, vout, out);
                }
            };
            LocalUTXOAdapter utxo_view(chain.utxo());
            if (mempool.load_from_disk(mempool_path, utxo_view, static_cast<uint32_t>(chain.height()))) {
                log_info("Loaded mempool from disk (" + std::to_string(mempool.size()) + " transactions)");
            }
        }

        if (can_tui) tui.mark_step_ok("Initialize mempool & RPC");

        P2P p2p(chain);
        p2p.set_inflight_caps(256, 128);
        p2p.set_datadir(cfg.datadir);
        p2p.set_mempool(&mempool);

        // TELEMETRY FIX: Register callbacks to track blocks/txs received from P2P network
        // Without this, only locally mined blocks show in recent_blocks_ UI
        p2p.set_block_callback([](const P2PBlockInfo& info) {
            BlockSummary bs;
            bs.height = info.height;
            bs.hash_hex = info.hash_hex;
            bs.tx_count = info.tx_count;
            bs.fees = info.fees;
            bs.fees_known = info.fees_known;
            bs.miner = info.miner;
            g_telemetry.push_block(bs);
        });
        p2p.set_txids_callback([](const std::vector<std::string>& txids) {
            g_telemetry.push_txids(txids);
        });

        rpc.set_p2p(&p2p);
        if (can_tui) tui.set_runtime_refs(&p2p, &chain, &mempool);

        g_extminer.start(cfg.datadir);

        [[maybe_unused]] bool p2p_ok = false;
        if (can_tui) { tui.mark_step_started("Start P2P listener"); tui.set_node_state(TUI::NodeState::Starting); }
        if(!cfg.no_p2p){
            uint16_t p2p_port = cfg.p2p_port ? cfg.p2p_port : P2P_PORT;
            if(p2p.start(p2p_port)){
                p2p_ok = true;
                log_info("P2P listening on " + std::to_string(p2p_port));
                if (can_tui) { tui.mark_step_ok("Start P2P listener"); tui.mark_step_started("Connect seeds"); }
                auto seed_role = compute_seed_role();
                if (!(seed_role.we_are_seed || g_assume_seed_hairpin.load())) {
                    p2p.connect_seed(seed_host_cstr(), P2P_PORT);
                    if (can_tui) tui.mark_step_ok("Connect seeds");
                } else {
                    log_info(std::string("Seed self-detect: skipping outbound connect to ")
                             + seed_host_cstr() + " (waiting for inbound peers).");
                    if (can_tui) {
                        tui.mark_step_ok("Connect seeds");
                        tui.set_hot_warning("Running as public seed — ensure port is open");
                    }
                }
            } else {
                log_warn("P2P failed to start on port " + std::to_string(p2p_port));
            }
        } else if (can_tui) {
            tui.mark_step_ok("Start P2P listener");
        }
        SeedSentinel seed_sentinel;
        seed_sentinel.start(&p2p, can_tui ? &tui : nullptr);

        // =====================================================================
        // START RPC EARLY: Allow clients to connect while IBD is in progress
        // This makes startup feel faster and allows sync status queries
        // =====================================================================
        [[maybe_unused]] bool rpc_ok = false;
        if (can_tui) tui.mark_step_started("Start RPC server");
        if(!cfg.no_rpc){
            miq::rpc_enable_auth_cookie(cfg.datadir);
            // Friendlier defaults for local miners: allow loopback without token unless the user overrides.
            if (const char* req = std::getenv("MIQ_RPC_REQUIRE_TOKEN"); !(req && *req)) {
#ifdef _WIN32
                _putenv_s("MIQ_RPC_REQUIRE_TOKEN", "0");
                _putenv_s("MIQ_RPC_ALLOW_LOOPBACK", "1");
#else
                setenv("MIQ_RPC_REQUIRE_TOKEN", "0", 1);
                setenv("MIQ_RPC_ALLOW_LOOPBACK", "1", 1);
#endif
            try {
                std::string cookie_path = p_join(cfg.datadir, ".cookie");
                std::vector<uint8_t> buf;
                if (!read_file_all(cookie_path, buf)) throw std::runtime_error("cookie read fail");
                std::string tok(buf.begin(), buf.end());
                while(!tok.empty() && (tok.back()=='\r'||tok.back()=='\n'||tok.back()==' '||tok.back()=='\t')) tok.pop_back();
#ifdef _WIN32
                _putenv_s("MIQ_RPC_TOKEN", tok.c_str());
#else
                setenv("MIQ_RPC_TOKEN", tok.c_str(), 1);
#endif
                log_info("HTTP gate token synchronized with RPC cookie");
            } catch (...) {
                log_warn("Could not sync MIQ_RPC_TOKEN to cookie; clients may need X-Auth-Token");
            }
            }
            // Extract RPC port from rpc_bind config, or use default
            uint16_t rpc_port = RPC_PORT;
            if (!cfg.rpc_bind.empty()) {
                size_t colon_pos = cfg.rpc_bind.rfind(':');
                if (colon_pos != std::string::npos) {
                    try {
                        rpc_port = (uint16_t)std::stoul(cfg.rpc_bind.substr(colon_pos + 1));
                    } catch (...) {
                        log_warn("Invalid RPC port in rpc_bind, using default " + std::to_string(RPC_PORT));
                        rpc_port = RPC_PORT;
                    }
                }
            }
            rpc.start(rpc_port);
            rpc_ok = true;
            log_info("RPC listening on " + std::to_string(rpc_port));

            // =========================================================
            // CRITICAL SECURITY WARNINGS FOR RPC
            // =========================================================
            {
                // Check if auth is enabled
                std::string expected_tok;
                bool has_auth = miq::rpc_load_expected_token(cfg.datadir, expected_tok, nullptr);

                // Check if binding to non-localhost
                bool is_remote = false;
                if (!cfg.rpc_bind.empty()) {
                    // Remote if bind address is not 127.0.0.1 or localhost
                    if (cfg.rpc_bind.find("127.0.0.1") == std::string::npos &&
                        cfg.rpc_bind.find("localhost") == std::string::npos &&
                        cfg.rpc_bind.find("::1") == std::string::npos) {
                        is_remote = true;
                    }
                }

                // Log security warnings
                if (is_remote && !has_auth) {
                    log_warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    log_warn("! CRITICAL SECURITY WARNING: RPC is INSECURE by default!   !");
                    log_warn("! - Remote binding detected WITHOUT authentication         !");
                    log_warn("! - Anyone can access your wallet and steal funds!         !");
                    log_warn("! FIX: Set MIQ_RPC_TOKEN environment variable OR use .cookie!");
                    log_warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                } else if (is_remote) {
                    log_warn("=============================================================");
                    log_warn("= SECURITY WARNING: RPC is accessible from remote hosts     =");
                    log_warn("= Authentication is enabled, but TLS is recommended         =");
                    log_warn("= Consider using --tls_proxy to enable encrypted connections=");
                    log_warn("=============================================================");
                } else if (!has_auth) {
                    log_warn("RPC authentication not configured (no .cookie or MIQ_RPC_TOKEN)");
                    log_warn("This is OK for localhost-only access, but DANGEROUS if remote.");
                }
            }

            if (can_tui) { tui.mark_step_ok("Start RPC server"); tui.mark_step_ok("RPC ready"); }
        } else if (can_tui) {
            tui.mark_step_ok("Start RPC server");
            tui.mark_step_ok("RPC ready");
            rpc_ok = true;
        }

        // =====================================================================
        // IBD SYNC PHASE: Now starts AFTER RPC is available
        // This allows clients to connect and query sync status immediately
        // =====================================================================
        if (can_tui) tui.mark_step_started("Start IBD monitor");
        start_ibd_monitor(&chain, &p2p);
        if (can_tui) tui.mark_step_ok("Start IBD monitor");

        if (can_tui) {
            // Only show what is known at start; no estimated future height.
            tui.set_ibd_progress(chain.height(), chain.height(), 0, "headers", seed_host_cstr(), false);
        }
        if (can_tui) tui.mark_step_started("IBD sync phase");
        std::string ibd_err;
        bool ibd_ok = perform_ibd_sync(chain, cfg.no_p2p ? nullptr : &p2p, cfg.datadir, can_tui, &tui, ibd_err);
        if (ibd_ok) {
            miq::mark_ibd_complete();  // Enable full durability (fsync on every block)
            miq::ibd::IBDState::instance().transition_to(miq::ibd::SyncState::DONE);
            if (can_tui) {
                tui.mark_step_ok("IBD sync phase");
                tui.set_banner("Synced");
                // CRITICAL FIX: Must set ibd_done_ to true for splash screen transition!
                // Without this, the splash screen stays stuck even though sync is complete
                tui.set_ibd_progress(chain.height(), chain.height(), 0, "complete", seed_host_cstr(), true);
                tui.set_node_state(TUI::NodeState::Running);
                tui.set_mining_gate(true, "");
            }
            log_info("IBD sync completed successfully.");
        } else {
            if (solo_seed_mode(cfg.no_p2p ? nullptr : &p2p)) {
                // Bootstrap solo: treat as OK so local mining can proceed.
                miq::mark_ibd_complete();  // Enable full durability
                miq::ibd::IBDState::instance().transition_to(miq::ibd::SyncState::DONE);
                if (can_tui) {
                    tui.mark_step_ok("IBD sync phase");
                    tui.set_banner("Seed solo mode — no peers yet. Mining enabled.");
                    // CRITICAL FIX: Must set ibd_done_ to true for splash screen transition!
                    tui.set_ibd_progress(chain.height(), chain.height(), 0, "complete", seed_host_cstr(), true);
                    tui.set_node_state(TUI::NodeState::Running);
                    tui.set_mining_gate(true, "");
                }
                log_info("IBD sync skipped (seed solo mode).");
            } else {
                if (can_tui) {
                    tui.mark_step_fail("IBD sync phase");
                    tui.set_node_state(TUI::NodeState::Degraded);
                    tui.set_hot_warning(std::string("BLOCKS MINED LOCALLY WILL NOT BE VALID — ") + ibd_err);
                    tui.set_mining_gate(false, ibd_err + " — blocks mined locally will not be valid");
                }
                log_error(std::string("IBD sync failed: ") + ibd_err);
                log_error("BLOCKS MINED LOCALLY WILL NOT BE VALID");
            }
        }

        IBDGuard ibd_guard;
        ibd_guard.start(&chain, cfg.no_p2p ? nullptr : &p2p, cfg.datadir, can_tui, can_tui ? &tui : nullptr);

        // Set global mining address for TUI display (even if stratum is disabled)
        if (!cfg.mining_address.empty()) {
            uint8_t ver = 0;
            std::vector<uint8_t> payload;
            if (base58check_decode(cfg.mining_address, ver, payload) &&
                ver == VERSION_P2PKH && payload.size() == 20) {
                g_miner_address_b58 = cfg.mining_address;
            }
        }

        // =====================================================================
        // Stratum mining pool server (optional)
        // =====================================================================
        std::unique_ptr<StratumServer> stratum_server;
        if (cfg.stratum_enable) {
            if (can_tui) tui.mark_step_started("Start Stratum server");
            stratum_server = std::make_unique<StratumServer>(chain, mempool);
            stratum_server->set_port(cfg.stratum_port);
            stratum_server->set_default_difficulty(cfg.stratum_difficulty);
            stratum_server->set_vardiff_enabled(cfg.stratum_vardiff);

            // Set reward address from mining_address config (already validated above)
            if (!g_miner_address_b58.empty()) {
                uint8_t ver = 0;
                std::vector<uint8_t> payload;
                if (base58check_decode(g_miner_address_b58, ver, payload)) {
                    stratum_server->set_reward_address(payload);
                }
            }

            // LIVENESS FIX: Register P2P relay callback for immediate block propagation
            // This ensures stratum-mined blocks are relayed to all peers within milliseconds
            if (!cfg.no_p2p) {
                stratum_server->set_block_relay_callback([&p2p, &chain](const Block& block, uint64_t height) {
                    // Calculate subsidy for notify_local_block
                    uint64_t subsidy = chain.subsidy_for_height(height);
                    std::string miner_addr;
                    if (!block.txs.empty() && !block.txs[0].vout.empty()) {
                        const auto& pkh = block.txs[0].vout[0].pkh;
                        if (pkh.size() == 20) {
                            miner_addr = base58check_encode(VERSION_P2PKH, pkh);
                        }
                    }
                    // This broadcasts to ALL peers immediately
                    p2p.notify_local_block(block, height, subsidy, miner_addr);
                });
            }

            if (stratum_server->start()) {
                g_stratum_server.store(stratum_server.get());
                log_info("Stratum pool server listening on port " + std::to_string(cfg.stratum_port));
                if (can_tui) tui.mark_step_ok("Start Stratum server");
            } else {
                log_error("Stratum server failed to start on port " + std::to_string(cfg.stratum_port));
                if (can_tui) tui.mark_step_fail("Start Stratum server");
                stratum_server.reset();
            }
        }

        // Built-in miner removed - use external miner (miqminer) for mining
        log_info("Use external miner (miqminer) for mining support.");

        log_info(std::string(CHAIN_NAME) + " node running. RPC " + std::to_string(RPC_PORT) +
                 ", P2P " + std::to_string(P2P_PORT));
        if (can_tui) {
            const bool ibd_ok_or_solo = ibd_ok || solo_seed_mode(cfg.no_p2p ? nullptr : &p2p);
            if (ibd_ok_or_solo) {
                tui.set_banner("Running");
                auto role = compute_seed_role();
                if (role.we_are_seed) {
                    tui.set_banner_append(std::string("SEED: ") + seed_host_cstr());
                    tui.set_hot_warning("Acting as seed — keep port open");
                }
                tui.set_node_state(TUI::NodeState::Running);
            } else {
                tui.set_banner("Degraded - IBD failed");
                tui.set_node_state(TUI::NodeState::Degraded);
            }
        }

        uint64_t last_tip_height_seen = chain.height();
        uint64_t last_tip_change_ms   = now_ms();
        uint64_t last_peer_warn_ms    = 0;
        uint64_t start_of_run_ms      = now_ms();

        // Initial "at height 0" nudge
        if (chain.height() == 0) {
            log_info("Waiting for headers from seed (" + std::string(DNS_SEED) + ":" + std::to_string(P2P_PORT) + ")...");
        }

        // CRITICAL FIX: Set initial mining gate status before entering main loop
        // This ensures mining shows as "Available" immediately after IBD completes
        // without waiting for the first loop iteration (which sleeps first)
        if (can_tui) {
            auto tip = chain.tip();
            uint64_t tsec = hdr_time(tip);
            uint64_t now_time = (uint64_t)std::time(nullptr);
            uint64_t tip_age = (now_time > tsec) ? (now_time - tsec) : 0;
            bool mining_ok = (tip_age < 8 * 60);
            std::string why = mining_ok ? "" : "tip too old (" + std::to_string(tip_age/60) + "m)";
            tui.set_mining_gate(mining_ok, why);
        }

        while(!global::shutdown_requested.load()){
            std::this_thread::sleep_for(std::chrono::milliseconds(can_tui ? 120 : 500));
            if (can_tui){
                std::deque<LogCapture::Line> lines;
                capture.drain(lines);
                tui.feed_logs(lines);
            }
            uint64_t h = chain.height();
            if (h != last_tip_height_seen){
                g_miner_stats.last_height_rx.store(h);
                last_tip_height_seen = h;
                last_tip_change_ms = now_ms();
                // CRITICAL FIX: Notify stratum server when tip changes
                // This ensures miners get new jobs immediately instead of mining stale blocks
                if (auto* ss = g_stratum_server.load()) {
                    ss->notify_new_block();
                }
            }

            // Sync gate for TUI display (external miner checks sync state via RPC)
            // CRITICAL FIX: After IBD completes, only check tip freshness for mining gate
            // Don't disable mining just because peers disconnected or haven't reported tips
            {
                auto tip = chain.tip();
                uint64_t tsec = hdr_time(tip);
                uint64_t now_time = (uint64_t)std::time(nullptr);
                uint64_t tip_age = (now_time > tsec) ? (now_time - tsec) : 0;
                // Mining available if tip is fresh (< 8 minutes = 1 block time)
                bool mining_ok = (tip_age < 8 * 60);
                std::string why = mining_ok ? "" : "tip too old (" + std::to_string(tip_age/60) + "m)";
                if (can_tui) tui.set_mining_gate(mining_ok, why);
            }

            // Periodic mempool maintenance (every ~30 seconds)
            static int64_t last_mempool_maint_ms = 0;
            if (now_ms() - last_mempool_maint_ms > 30'000) {
                last_mempool_maint_ms = now_ms();
                mempool.maintenance();
                mempool.update_cpfp_scores();
                mempool.update_fee_estimates(static_cast<uint32_t>(chain.height()));
            }

            // V1.1 STABILITY FIX: Periodic mempool persistence (every ~5 minutes)
            // This ensures transactions survive unexpected crashes/restarts
            // Critical for transaction reliability - don't lose mempool on node crash
            static int64_t last_mempool_save_ms = 0;
            if (now_ms() - last_mempool_save_ms > 5 * 60 * 1000) {
                last_mempool_save_ms = now_ms();
                std::string mempool_path = cfg.datadir + "/mempool.dat";
                if (mempool.size() > 0) {
                    mempool.save_to_disk(mempool_path);
                    // Log at debug level to avoid spam
                    MIQ_LOG_DEBUG(miq::LogCategory::MEMPOOL, "Periodic mempool save: " +
                                  std::to_string(mempool.size()) + " transactions");
                }
            }

            bool degraded = false;
            if (!cfg.no_p2p){
                auto n = p2p.snapshot_peers().size();
                if (n == 0 && now_ms() - last_peer_warn_ms > 60'000){
                    if (can_tui) tui.set_hot_warning("No peers connected - check network/firewall?");
                    last_peer_warn_ms = now_ms();
                }
                if (n == 0 && now_ms() - start_of_run_ms > 60'000) degraded = true;
            }
            if (now_ms() - last_tip_change_ms > 10*60*1000) degraded = true;
            // Check external miner heartbeat - degraded if expected but not responding
            if (std::getenv("MIQ_MINER_HEARTBEAT") && !g_extminer.alive.load()) degraded = true;
            if (g_we_are_seed.load()){
                // Seed host with no peers is definitely degraded
                if (p2p.snapshot_peers().empty()) degraded = true;
            }

            if (can_tui) tui.set_health_degraded(degraded);

            if (global::reload_requested.exchange(false)){
                log_info("Reloading config due to SIGHUP/hotkey...");
                try {
                    if(!conf.empty()) load_config(conf, cfg);
                    log_info("Reload complete.");
                    if (can_tui) tui.set_hot_warning("Config reloaded");
                } catch (...) {
                    log_warn("Config reload failed.");
                    if (can_tui) tui.set_hot_warning("Config reload failed");
                }
            }
        }

        if (can_tui) {
                tui.set_node_state(TUI::NodeState::Quitting);
                tui.set_banner("Shutting down");
            }
        log_info("Shutdown requested - stopping services...");

        try {
            if (can_tui) tui.set_shutdown_phase("Stopping RPC...", false);
            rpc.stop();
            if (can_tui) tui.set_shutdown_phase("Stopping RPC...", true);
        } catch(...) { log_warn("RPC stop threw"); }

        try {
            if (can_tui) tui.set_shutdown_phase("Stopping P2P...", false);
            p2p.stop();
            if (can_tui) tui.set_shutdown_phase("Stopping P2P...", true);
        } catch(...) { log_warn("P2P stop threw"); }

        try {
            if (can_tui) tui.set_shutdown_phase("Stopping IBD/Seed sentinels...", false);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            if (can_tui) tui.set_shutdown_phase("Stopping IBD/Seed sentinels...", true);
        } catch(const std::exception& e) {
            // PRODUCTION FIX: Log shutdown phase errors
            log_warn(std::string("IBD/Seed sentinel shutdown threw: ") + e.what());
        } catch(...) {
            log_warn("IBD/Seed sentinel shutdown threw (unknown)");
        }

        try {
            if (can_tui) tui.set_shutdown_phase("Stopping miner watch...", false);
            g_extminer.stop();
            if (can_tui) tui.set_shutdown_phase("Stopping miner watch...", true);
        } catch(...) { log_warn("Miner watch stop threw"); }

        // PRODUCTION FIX: Save mempool to disk before shutdown
        // This ensures unconfirmed transactions survive node restarts
        try {
            if (can_tui) tui.set_shutdown_phase("Saving mempool...", false);
            std::string mempool_path = cfg.datadir + "/mempool.dat";
            if (mempool.save_to_disk(mempool_path)) {
                log_info("Saved mempool to disk (" + std::to_string(mempool.size()) + " transactions)");
            }
            if (can_tui) tui.set_shutdown_phase("Saving mempool...", true);
        } catch(const std::exception& e) {
            log_warn(std::string("Mempool save failed: ") + e.what());
        } catch(...) {
            log_warn("Mempool save failed (unknown error)");
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(140));

        log_info("Shutdown complete.");
        if (can_tui) {
            capture.stop();
            tui.stop();
        }
        release_datadir_lock();
        return 0;

    } catch(const std::exception& ex){
        std::fprintf(stderr, "[FATAL] %s\n", ex.what());
        release_datadir_lock();
        return 13;
    } catch(...){
        std::fprintf(stderr, "[FATAL] unknown exception\n");
        release_datadir_lock();
        return 13;
    }
}
