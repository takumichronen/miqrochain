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
#include "miner.h"
#include "sha256.h"
#include "hex.h"
#include "tls_proxy.h"
#include "ibd_monitor.h"
#include "utxo_kv.h"
#include "stratum/stratum_server.h"

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
  #ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
  #define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
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

static std::string g_miner_address_b58; // display mined-to address

// Global Stratum server pointer for block notifications
static std::atomic<StratumServer*> g_stratum_server{nullptr};

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
static inline void trim_inplace(std::string& s){
    auto notspace = [](unsigned char ch){ return !std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
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
// IMPORTANT: On Windows, we only enable UTF-8/Unicode mode for terminals that
// actually support extended Unicode glyphs. PowerShell 5 (legacy) uses fonts
// like Consolas that don't have glyphs for many Unicode characters, causing
// garbled output. We detect modern terminals that handle Unicode properly.
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

    // Check if user explicitly set UTF-8 preference
    const char* utf8_env = std::getenv("MIQ_TUI_UTF8");
    const bool force_utf8 = utf8_env && *utf8_env &&
        (std::strcmp(utf8_env,"1")==0 || std::strcmp(utf8_env,"true")==0 || std::strcmp(utf8_env,"True")==0);
    const bool disable_utf8 = utf8_env && *utf8_env &&
        (std::strcmp(utf8_env,"0")==0 || std::strcmp(utf8_env,"false")==0 || std::strcmp(utf8_env,"False")==0);

    // Detect modern terminals that properly support Unicode:
    // - Windows Terminal (WT_SESSION env var)
    // - ConEmu (ConEmuANSI env var)
    // - VS Code integrated terminal (TERM_PROGRAM=vscode)
    // - MSYS2/Git Bash/MinGW (MSYSTEM or MSYS env var)
    // - Alacritty, WezTerm, etc (TERM_PROGRAM set)
    //
    // Legacy PowerShell 5 running in conhost.exe does NOT properly render
    // extended Unicode characters (box-drawing, emojis, Braille, etc.)
    // even with code page 65001 set - the default fonts lack glyphs.
    const bool is_modern_terminal =
        std::getenv("WT_SESSION") ||           // Windows Terminal
        std::getenv("ConEmuANSI") ||           // ConEmu
        std::getenv("TERM_PROGRAM") ||         // VS Code, Alacritty, WezTerm, etc.
        std::getenv("MSYSTEM") ||              // MSYS2/MinGW
        std::getenv("MSYS") ||                 // MSYS
        std::getenv("TERMINUS_SUBPROC") ||     // Terminus
        std::getenv("ALACRITTY_LOG") ||        // Alacritty
        std::getenv("WEZTERM_PANE");           // WezTerm

    // Set UTF-8 code page for proper string handling
    if (have_console) {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);

        // Enable stdin VT sequences if available
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        if (hIn && hIn != INVALID_HANDLE_VALUE) {
            DWORD inMode = 0;
            if (GetConsoleMode(hIn, &inMode)) {
                inMode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
                SetConsoleMode(hIn, inMode);
            }
        }
    }

    // Only enable Unicode graphics on modern terminals or if user forces it
    // Default to ASCII mode for legacy PowerShell 5 / conhost.exe
    if (force_utf8) {
        u8_ok = true;
    } else if (disable_utf8) {
        u8_ok = false;
    } else if (is_modern_terminal) {
        u8_ok = true;
    } else {
        // Legacy Windows console (PowerShell 5, cmd.exe in conhost)
        // Use ASCII-safe mode to avoid garbled characters
        u8_ok = false;
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
        // For PowerShell 5+ compatibility: use WriteConsoleW for proper Unicode support
        // Convert UTF-8 to wide string and use WriteConsoleW
        int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
        if (wlen > 0) {
            std::wstring ws((size_t)wlen, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), ws.data(), wlen);
            DWORD wroteW = 0;

            // Try our console handle first
            if (hFile_ && hFile_ != INVALID_HANDLE_VALUE) {
                if (WriteConsoleW(hFile_, ws.c_str(), (DWORD)ws.size(), &wroteW, nullptr)) return;
            }

            // Fallback: try STD_OUTPUT_HANDLE with WriteConsoleW
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            if (hOut != INVALID_HANDLE_VALUE) {
                if (WriteConsoleW(hOut, ws.c_str(), (DWORD)ws.size(), &wroteW, nullptr)) return;
            }
        }

        // Last resort fallback: WriteFile (may not handle Unicode properly but ensures output)
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

// UTF-8 enabled by default (opt-out model for Windows PowerShell 5+ compatibility)
// Returns true unless MIQ_TUI_UTF8 is explicitly set to 0/false
static inline bool is_utf8_enabled(){
    const char* v = std::getenv("MIQ_TUI_UTF8");
    if(!v||!*v) return true;  // Default: enabled
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
// Bitcoin Core-like sync display helpers
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

// Animated progress bar with gradient effect (Bitcoin Core style)
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
    // Use same logic for both paths - u8_ok already indicates UTF-8 support
    for (int i=0;i<inner;i++) out.push_back(i<full ? '#' : ' ');
    out.push_back(']');
    return out;
}
static inline std::string short_hex(const std::string& h, int keep){
    if ((int)h.size() <= keep) return h;
    int half = keep/2;
    const char* ell = is_utf8_enabled() ? "…" : "...";
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

static inline bool is_private_v4(const std::string& ip){
    return ip.rfind("10.",0)==0
        || ip.rfind("192.168.",0)==0
        || (ip.rfind("172.",0)==0 && [] (const std::string& s){
              // 172.16.0.0/12
              int a=0; char dot=0;
              if (std::sscanf(s.c_str(),"172.%d%c",&a,&dot)==2 && dot=='.') return (a>=16 && a<=31);
              return false;
           }(ip));
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

struct MempoolView { uint64_t count=0, bytes=0, recent_adds=0; };
template<typename MP>
static MempoolView mempool_view_fallback(MP* mp){
    MempoolView v{};
    if (!mp) return v;
    if constexpr (has_stats_method<MP>::value) {
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
    bool fancy = is_utf8_enabled();
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
static bool compute_sync_gate(Chain& chain, P2P* p2p, std::string& why_out) {
    size_t peers = p2p ? p2p->snapshot_peers().size() : 0;
    const bool we_are_seed = compute_seed_role().we_are_seed;
    const bool seed_solo = we_are_seed && peers == 0;

    if (!seed_solo && peers == 0) {
        why_out = "no peers";
        return false;
    }

    uint64_t h = chain.height();

    if (h == 0) {
        if (seed_solo) {
            why_out.clear();
            return true; // allow solo mining from genesis regardless of timestamp
        }
        why_out = "headers syncing";
        return false;
    }

    // For seed nodes (solo or with peers), allow serving blocks even with stale tips
    // This is necessary to bootstrap the chain and serve historical blocks to peers
    if (we_are_seed) {
        why_out.clear();
        return true;
    }

    // For peer nodes that have successfully synced blocks from a seed, also allow stale tips
    // This handles the case where we've synced historical blocks that are legitimately old
    if (peers > 0) {
        // Only finish sync once we've reached all known blocks from peers
        uint64_t max_peer_tip = 0;
        // Gather each peer's advertised tip height
        auto peer_list = p2p->snapshot_peers();
        for (const auto& pr : peer_list) {
            max_peer_tip = std::max(max_peer_tip, pr.peer_tip);
        }
        if (h >= max_peer_tip) {
            why_out.clear();
            return true;
        } else {
            why_out = "syncing blocks";
            return false;
        }
    }

    auto tip = chain.tip();
    uint64_t tsec = hdr_time(tip);
    if (tsec == 0) {
        why_out = "waiting for headers time";
        return false;
    }
    uint64_t now = (uint64_t)std::time(nullptr);
    uint64_t age = (now > tsec) ? (now - tsec) : 0;
    const uint64_t fresh = std::max<uint64_t>(BLOCK_TIME_SECS * 3, 300);

    if (age > fresh) {
        why_out = "tip too old";
        return false;
    }

    why_out.clear();
    return true;
}

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
        draw_once(true);
        key_thr_ = std::thread([this]{ key_loop(); });
        thr_     = std::thread([this]{ loop(); });
    }
    void stop() {
        if (!enabled_) return;
        running_ = false;
        key_running_ = false;
        if (thr_.joinable()) thr_.join();
        if (key_thr_.joinable()) key_thr_.join();
        if (vt_ok_) cw_.write_raw("\x1b[?25h\x1b[0m\n");
    }
    ~TUI(){ stop(); }

    // startup steps
    void mark_step_started(const std::string& title) { std::lock_guard<std::mutex> lk(mu_); ensure_step(title); }
    void mark_step_ok(const std::string& title) { std::lock_guard<std::mutex> lk(mu_); ensure_step(title); set_step(title, true); }
    void mark_step_fail(const std::string& title){ std::lock_guard<std::mutex> lk(mu_); ensure_step(title); failures_.insert(title); }

    // runtime refs
    void set_runtime_refs(P2P* p2p, Chain* chain, Mempool* mempool) { p2p_ = p2p; chain_ = chain; mempool_ = mempool; }
    void set_ports(uint16_t p2pport, uint16_t rpcport) { p2p_port_ = p2pport; rpc_port_ = rpcport; }
    void set_node_state(NodeState st){ std::lock_guard<std::mutex> lk(mu_); nstate_ = st; }
    void set_datadir(const std::string& d){ std::lock_guard<std::mutex> lk(mu_); datadir_ = d; }

    // mining gate
    void set_mining_gate(bool available, const std::string& reason){
        std::lock_guard<std::mutex> lk(mu_);
        mining_gate_available_ = available;
        mining_gate_reason_ = reason;
    }

    // logs in - with spam filtering
    void feed_logs(const std::deque<LogCapture::Line>& raw_lines) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!paused_) {
            logs_.clear(); logs_.reserve(raw_lines.size());
            for (auto& L : raw_lines){
                auto styled = stylize_log(L);
                // Skip filtered messages (level -1)
                if (styled.level >= 0) {
                    logs_.push_back(styled);
                }
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
    }

    // Bitcoin Core-like sync stats update
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

    // Check if a log message should be filtered (spam reduction)
    // Returns true if the message should be HIDDEN (filtered out)
    bool should_filter_log(const std::string& s) const {
        // In verbose mode, show everything
        if (global::tui_verbose.load()) return false;

        // Filter out spammy sync/download messages - these are shown on splash screen
        static const char* spam_patterns[] = {
            "downloading block",
            "Downloading block",
            "fetching block",
            "Fetching block",
            "requesting block",
            "Requesting block",
            "received block",
            "got block",
            "block download",
            "sync progress",
            "Sync progress",
            "syncing block",
            "Syncing block",
            "IBD progress",
            "headers progress",
            "Headers progress",
            "fetching headers",
            "Fetching headers",
            "peer latency",
            "Peer latency",
            "ping time",
            "pong received",
            "Pong received",
            "inv received",
            "getdata sent",
            "Getdata sent"
        };

        for (const char* pattern : spam_patterns) {
            if (s.find(pattern) != std::string::npos) {
                return true;  // Filter this message
            }
        }

        return false;  // Don't filter - show the message
    }

    // Stylize and categorize a log line
    StyledLine stylize_log(const LogCapture::Line& L){
        const std::string& s = L.text;

        // Filter spam messages (unless verbose mode)
        if (should_filter_log(s)) {
            return StyledLine{"", -1};  // level -1 = filtered/hidden
        }

        StyledLine out{ s, 0 };

        // Priority categorization for important messages
        if (s.find("[FATAL]") != std::string::npos || s.find("[ERROR]") != std::string::npos) {
            out.level = 2;  // Error - red
        }
        else if (s.find("[WARN]") != std::string::npos) {
            out.level = 1;  // Warning - yellow
        }
        else if (s.find("accepted block") != std::string::npos ||
                 s.find("mined block accepted") != std::string::npos ||
                 s.find("new block") != std::string::npos ||
                 s.find("Block mined") != std::string::npos) {
            out.level = 4;  // Success - green (important events)
        }
        else if (s.find("peer connected") != std::string::npos ||
                 s.find("Peer connected") != std::string::npos ||
                 s.find("new peer") != std::string::npos ||
                 s.find("verack") != std::string::npos) {
            out.level = 5;  // Info - cyan (network events)
        }
        else if (s.find("transaction") != std::string::npos ||
                 s.find("tx accepted") != std::string::npos ||
                 s.find("mempool") != std::string::npos) {
            out.level = 5;  // Info - cyan (tx events)
        }
        else if (s.find("[TRACE]") != std::string::npos ||
                 s.find("[DEBUG]") != std::string::npos) {
            out.level = 3;  // Dim - trace/debug
        }
        else if (s.find("RPC") != std::string::npos ||
                 s.find("rpc") != std::string::npos) {
            out.level = 0;  // Normal - RPC info
        }
        else {
            // Regular log message
            out.level = 0;
        }

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
        key_running_ = true;
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

    void loop(){
        using clock = std::chrono::steady_clock;
        using namespace std::chrono_literals;
        running_ = true;
        auto last_hs_time = clock::now();
        auto last_draw_time = clock::now();
        uint64_t last_stats_ms = now_ms();
        uint64_t last_net_ms   = now_ms();

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

            // IMPROVED: Time-based drawing for consistent animation speed
            if ((now - last_draw_time) >= draw_interval) {
                draw_once(false);
                last_draw_time = now;
                ++tick_;
            }

            // Sleep for short interval to maintain responsive input handling
            std::this_thread::sleep_for(idle_sleep);

            // Update hashrate sparkline at 250ms intervals
            if((clock::now()-last_hs_time) > 250ms){
                last_hs_time = clock::now();
                std::lock_guard<std::mutex> lk(mu_);
                spark_hs_.push_back(g_miner_stats.hps.load());
                if(spark_hs_.size() > 90) spark_hs_.erase(spark_hs_.begin());
            }

            // Handle snapshot requests
            if (global::tui_snapshot_requested.exchange(false)) snapshot_to_disk();

            // Update miner stats every second
            if (now_ms() - last_stats_ms > 1000) {
                last_stats_ms = now_ms();
                miq::MinerStats ms = miq::miner_stats_now();
                g_miner_stats.hps.store(ms.hps);
            }

            // Update network hashrate every second
            if (now_ms() - last_net_ms > 1000){
                last_net_ms = now_ms();
                double nh = estimate_network_hashrate(chain_);
                std::lock_guard<std::mutex> lk(mu_);
                net_hashrate_ = nh;
                net_spark_.push_back(nh);
                if (net_spark_.size() > 90) net_spark_.erase(net_spark_.begin());

                // Update Bitcoin Core-like sync stats
                if (chain_ && p2p_) {
                    uint64_t network_height = 0;

                    // Get max peer tip for network height
                    auto peers = p2p_->snapshot_peers();
                    for (const auto& peer : peers) {
                        if (peer.peer_tip > network_height) {
                            network_height = peer.peer_tip;
                        }
                    }

                    // Get last block timestamp
                    auto tip = chain_->tip();
                    uint64_t last_block_time = hdr_time(tip);

                    // Store values (already have lock)
                    sync_network_height_ = network_height;
                    sync_last_block_time_ = last_block_time;
                }
            }

            // Update sync speed tracking (every 2 seconds for accuracy)
            static uint64_t last_sync_update_ms = 0;
            if (chain_ && p2p_ && now_ms() - last_sync_update_ms > 2000) {
                last_sync_update_ms = now_ms();
                uint64_t current_height = chain_->height();
                uint64_t network_height = 0;
                auto peers = p2p_->snapshot_peers();
                for (const auto& peer : peers) {
                    if (peer.peer_tip > network_height) network_height = peer.peer_tip;
                }
                uint64_t last_block_time = hdr_time(chain_->tip());
                update_sync_stats(current_height, network_height, last_block_time);
            }
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
    // PREMIUM TUI COMPONENT SYSTEM - Professional visualization library
    // =========================================================================

    // -------------------------------------------------------------------------
    // COLOR PALETTE - Professional color scheme for consistent branding
    // -------------------------------------------------------------------------
    struct ColorPalette {
        static constexpr int PRIMARY = 51;      // Bright cyan - main brand color
        static constexpr int SECONDARY = 39;    // Blue - secondary actions
        static constexpr int ACCENT = 214;      // Orange - highlights
        static constexpr int SUCCESS = 46;      // Green - positive states
        static constexpr int WARNING = 226;     // Yellow - caution
        static constexpr int DANGER = 196;      // Red - errors (avoid ERROR - Windows macro conflict)
        static constexpr int INFO = 87;         // Light cyan - information
        static constexpr int MUTED = 240;       // Gray - disabled/secondary text
        static constexpr int BORDER = 27;       // Dark blue - borders
        static constexpr int TEXT = 252;        // Light gray - main text
        static constexpr int TEXT_DIM = 245;    // Dimmer text
        static constexpr int BG_DARK = 235;     // Dark background
        static constexpr int BG_PANEL = 236;    // Panel background
    };

    // -------------------------------------------------------------------------
    // WINDOW FRAME - Professional window with title, shadow, and animations
    // -------------------------------------------------------------------------
    struct WindowFrame {
        std::string title;
        std::string icon;
        int x, y, width, height;
        int border_color;
        bool has_shadow;
        bool animate_border;
        int animation_phase;

        WindowFrame(const std::string& t, const std::string& ico, int w, int h)
            : title(t), icon(ico), x(0), y(0), width(w), height(h),
              border_color(ColorPalette::BORDER), has_shadow(true),
              animate_border(true), animation_phase(0) {}
    };

    // Draw a professional window frame with optional shadow and animation
    std::string draw_window_frame(const WindowFrame& wf, int tick) const {
        std::ostringstream out;
        int w = wf.width;

        if (!vt_ok_) {
            // ASCII fallback
            out << "+" << std::string(w - 2, '-') << "+\n";
            out << "| " << wf.title << std::string(w - 4 - (int)wf.title.size(), ' ') << " |\n";
            out << "+" << std::string(w - 2, '-') << "+\n";
            return out.str();
        }

        // Shadow effect (rendered first, offset)
        if (wf.has_shadow && u8_ok_) {
            out << "\x1b[38;5;235m ";
            for (int i = 0; i < w; ++i) out << "▄";
            out << "\n";
        }

        // Top border with animation
        out << "\x1b[38;5;" << wf.border_color << "m";
        if (u8_ok_) {
            out << "╭";
            for (int i = 0; i < w - 2; ++i) {
                if (wf.animate_border) {
                    int pulse = (tick + i) % 20;
                    int c = (pulse < 10) ? wf.border_color + (pulse % 5) : wf.border_color + (10 - pulse % 5);
                    out << "\x1b[38;5;" << c << "m─";
                } else {
                    out << "─";
                }
            }
            out << "\x1b[38;5;" << wf.border_color << "m╮";
        } else {
            out << "+" << std::string(w - 2, '-') << "+";
        }
        out << "\x1b[0m";
        if (wf.has_shadow) out << "\x1b[38;5;235m▐\x1b[0m";
        out << "\n";

        // Title bar
        out << "\x1b[38;5;" << wf.border_color << "m" << (u8_ok_ ? "│" : "|") << "\x1b[0m";
        out << "\x1b[48;5;" << ColorPalette::BG_PANEL << "m";

        // Icon with glow effect
        if (!wf.icon.empty() && u8_ok_) {
            int icon_color = (tick % 4 < 2) ? ColorPalette::PRIMARY : ColorPalette::SECONDARY;
            out << " \x1b[38;5;" << icon_color << "m" << wf.icon << "\x1b[0m";
            out << "\x1b[48;5;" << ColorPalette::BG_PANEL << "m";
        }

        // Title with gradient
        out << " \x1b[38;5;255m\x1b[1m" << wf.title << "\x1b[0m";
        out << "\x1b[48;5;" << ColorPalette::BG_PANEL << "m";

        // Fill rest of title bar
        int title_len = (int)wf.title.size() + (wf.icon.empty() ? 2 : 4 + (int)wf.icon.size());
        out << std::string(w - 2 - title_len, ' ');
        out << "\x1b[0m\x1b[38;5;" << wf.border_color << "m" << (u8_ok_ ? "│" : "|") << "\x1b[0m";
        if (wf.has_shadow) out << "\x1b[38;5;235m▐\x1b[0m";
        out << "\n";

        // Separator under title
        out << "\x1b[38;5;" << wf.border_color << "m" << (u8_ok_ ? "├" : "+");
        for (int i = 0; i < w - 2; ++i) out << (u8_ok_ ? "─" : "-");
        out << (u8_ok_ ? "┤" : "+") << "\x1b[0m";
        if (wf.has_shadow) out << "\x1b[38;5;235m▐\x1b[0m";
        out << "\n";

        return out.str();
    }

    // Draw window content area row
    std::string draw_window_row(const std::string& content, int width, int border_color, bool has_shadow) const {
        std::ostringstream out;
        if (!vt_ok_) {
            out << "| " << content;
            int pad = width - 4 - visible_length(content);
            if (pad > 0) out << std::string(pad, ' ');
            out << " |\n";
            return out.str();
        }

        out << "\x1b[38;5;" << border_color << "m" << (u8_ok_ ? "│" : "|") << "\x1b[0m";
        out << "\x1b[48;5;" << ColorPalette::BG_PANEL << "m ";
        out << content;
        int vis_len = visible_length(content);
        int pad = width - 4 - vis_len;
        if (pad > 0) out << std::string(pad, ' ');
        out << " \x1b[0m";
        out << "\x1b[38;5;" << border_color << "m" << (u8_ok_ ? "│" : "|") << "\x1b[0m";
        if (has_shadow) out << "\x1b[38;5;235m▐\x1b[0m";
        out << "\n";
        return out.str();
    }

    // Draw window bottom border
    std::string draw_window_bottom(int width, int border_color, bool has_shadow, int tick, bool animate) const {
        std::ostringstream out;
        if (!vt_ok_) {
            out << "+" << std::string(width - 2, '-') << "+\n";
            return out.str();
        }

        out << "\x1b[38;5;" << border_color << "m";
        if (u8_ok_) {
            out << "╰";
            for (int i = 0; i < width - 2; ++i) {
                if (animate) {
                    int pulse = (tick + i) % 20;
                    int c = (pulse < 10) ? border_color + (pulse % 5) : border_color + (10 - pulse % 5);
                    out << "\x1b[38;5;" << c << "m─";
                } else {
                    out << "─";
                }
            }
            out << "\x1b[38;5;" << border_color << "m╯";
        } else {
            out << "+" << std::string(width - 2, '-') << "+";
        }
        out << "\x1b[0m";
        if (has_shadow) out << "\x1b[38;5;235m▐\x1b[0m";
        out << "\n";

        // Shadow bottom
        if (has_shadow && u8_ok_) {
            out << " \x1b[38;5;235m";
            for (int i = 0; i < width; ++i) out << "▀";
            out << "\x1b[0m\n";
        }
        return out.str();
    }

    // -------------------------------------------------------------------------
    // GAUGE - Animated circular/arc gauge for metrics
    // -------------------------------------------------------------------------
    std::string draw_gauge(double value, double max_val, int width, const std::string& label,
                           int color_low, int color_mid, int color_high, int tick) const {
        if (width < 10) width = 10;
        double pct = (max_val > 0) ? (value / max_val) : 0;
        if (pct < 0) pct = 0;
        if (pct > 1) pct = 1;

        std::ostringstream out;

        if (!vt_ok_ || !u8_ok_) {
            // ASCII fallback
            int filled = (int)(pct * (width - 2));
            out << "[";
            for (int i = 0; i < width - 2; ++i) {
                out << (i < filled ? "#" : ".");
            }
            out << "] " << (int)(pct * 100) << "%";
            return out.str();
        }

        // Determine color based on value
        int color;
        if (pct < 0.33) color = color_low;
        else if (pct < 0.66) color = color_mid;
        else color = color_high;

        // Animated gauge with gradient fill
        int inner = width - 4;
        int filled = (int)(pct * inner);

        out << "\x1b[38;5;240m⟨\x1b[0m";
        for (int i = 0; i < inner; ++i) {
            if (i < filled) {
                // Gradient from low to high color
                int grad_color = color_low + (int)((double)i / inner * (color_high - color_low));
                // Add shimmer effect
                bool shimmer = ((i + tick) % 6 == 0);
                if (shimmer) grad_color = 255;
                out << "\x1b[38;5;" << grad_color << "m█\x1b[0m";
            } else if (i == filled && pct < 1.0) {
                // Animated edge
                static const char* edge_chars[] = {"░", "▒", "▓", "█", "▓", "▒"};
                out << "\x1b[38;5;" << color << "m" << edge_chars[tick % 6] << "\x1b[0m";
            } else {
                out << "\x1b[38;5;236m░\x1b[0m";
            }
        }
        out << "\x1b[38;5;240m⟩\x1b[0m";

        // Percentage with color
        out << " \x1b[38;5;" << color << "m\x1b[1m" << (int)(pct * 100) << "%\x1b[0m";

        if (!label.empty()) {
            out << " \x1b[38;5;245m" << label << "\x1b[0m";
        }

        return out.str();
    }

    // -------------------------------------------------------------------------
    // SPARKLINE GRAPH - Mini line graph for trends
    // -------------------------------------------------------------------------
    std::string draw_sparkline(const std::vector<double>& data, int width, int color, bool show_minmax) const {
        if (data.empty() || width < 3) {
            return vt_ok_ ? "\x1b[38;5;240m(no data)\x1b[0m" : "(no data)";
        }

        std::ostringstream out;

        if (!u8_ok_) {
            // ASCII fallback
            double max_v = *std::max_element(data.begin(), data.end());
            double min_v = *std::min_element(data.begin(), data.end());
            double range = max_v - min_v;
            if (range < 0.001) range = 1;

            for (size_t i = 0; i < std::min(data.size(), (size_t)width); ++i) {
                double norm = (data[i] - min_v) / range;
                if (norm < 0.25) out << "_";
                else if (norm < 0.5) out << "-";
                else if (norm < 0.75) out << "=";
                else out << "#";
            }
            return out.str();
        }

        // Unicode sparkline characters (8 levels)
        static const char* sparks[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};

        double max_v = *std::max_element(data.begin(), data.end());
        double min_v = *std::min_element(data.begin(), data.end());
        double range = max_v - min_v;
        if (range < 0.001) range = 1;

        if (vt_ok_) out << "\x1b[38;5;" << color << "m";

        size_t start = (data.size() > (size_t)width) ? data.size() - width : 0;
        for (size_t i = start; i < data.size(); ++i) {
            double norm = (data[i] - min_v) / range;
            int level = (int)(norm * 7.999);
            if (level < 0) level = 0;
            if (level > 7) level = 7;

            // Color gradient based on value
            if (vt_ok_) {
                int c = color - (7 - level) * 2;
                if (c < 16) c = 16;
                out << "\x1b[38;5;" << c << "m";
            }
            out << sparks[level];
        }

        if (vt_ok_) out << "\x1b[0m";

        // Min/max labels
        if (show_minmax && vt_ok_) {
            out << " \x1b[38;5;240m[" << std::fixed << std::setprecision(1) << min_v
                << "-" << max_v << "]\x1b[0m";
        }

        return out.str();
    }

    // -------------------------------------------------------------------------
    // PROGRESS RING - Circular progress indicator
    // -------------------------------------------------------------------------
    std::string draw_progress_ring(double pct, int tick) const {
        if (!u8_ok_) {
            return "[" + std::to_string((int)(pct * 100)) + "%]";
        }

        std::ostringstream out;

        // 8 segments for the ring
        static const char* segments[] = {"◜", "◝", "◞", "◟", "◠", "◡", "◜", "◝"};
        int filled = (int)(pct * 8);

        if (vt_ok_) {
            // Animated spinning effect
            int anim_offset = tick % 8;
            for (int i = 0; i < 8; ++i) {
                int seg_idx = (i + anim_offset) % 8;
                if (i < filled) {
                    out << "\x1b[38;5;" << ColorPalette::SUCCESS << "m";
                } else {
                    out << "\x1b[38;5;236m";
                }
                out << segments[seg_idx];
            }
            out << "\x1b[0m";
        } else {
            for (int i = 0; i < 8; ++i) {
                out << segments[i];
            }
        }

        return out.str();
    }

    // -------------------------------------------------------------------------
    // METRICS ROW - Formatted metric with label, value, and optional trend
    // -------------------------------------------------------------------------
    std::string draw_metric(const std::string& label, const std::string& value,
                            int value_color, const std::string& trend = "") const {
        std::ostringstream out;

        if (!vt_ok_) {
            out << label << ": " << value;
            if (!trend.empty()) out << " " << trend;
            return out.str();
        }

        // Label (dimmed)
        out << "\x1b[38;5;" << ColorPalette::TEXT_DIM << "m" << label << "\x1b[0m";

        // Spacing
        int label_len = (int)label.size();
        int pad = 14 - label_len;
        if (pad > 0) out << std::string(pad, ' ');

        // Value (colored)
        out << "\x1b[38;5;" << value_color << "m\x1b[1m" << value << "\x1b[0m";

        // Trend indicator
        if (!trend.empty()) {
            out << " \x1b[38;5;240m" << trend << "\x1b[0m";
        }

        return out.str();
    }

    // -------------------------------------------------------------------------
    // STATUS INDICATOR - Animated status dot with label
    // -------------------------------------------------------------------------
    std::string draw_status(const std::string& label, bool ok, int tick, bool animate = true) const {
        std::ostringstream out;

        if (!vt_ok_) {
            out << (ok ? "[OK]" : "[--]") << " " << label;
            return out.str();
        }

        if (ok) {
            // Pulsing green dot
            if (animate && u8_ok_) {
                static const int pulse_colors[] = {46, 47, 48, 49, 48, 47};
                int c = pulse_colors[tick % 6];
                out << "\x1b[38;5;" << c << "m●\x1b[0m";
            } else {
                out << "\x1b[38;5;" << ColorPalette::SUCCESS << "m" << (u8_ok_ ? "●" : "*") << "\x1b[0m";
            }
        } else {
            // Static gray dot
            out << "\x1b[38;5;" << ColorPalette::MUTED << "m" << (u8_ok_ ? "○" : "o") << "\x1b[0m";
        }

        out << " \x1b[38;5;" << ColorPalette::TEXT << "m" << label << "\x1b[0m";
        return out.str();
    }

    // -------------------------------------------------------------------------
    // NETWORK SIGNAL - Signal strength indicator
    // -------------------------------------------------------------------------
    std::string draw_signal(int strength, int max_strength, int tick) const {
        if (!u8_ok_) {
            std::string bars = "";
            for (int i = 0; i < max_strength; ++i) {
                bars += (i < strength) ? "|" : ".";
            }
            return "[" + bars + "]";
        }

        std::ostringstream out;
        static const char* levels[] = {"▁", "▂", "▃", "▅", "▇"};

        for (int i = 0; i < max_strength; ++i) {
            if (i < strength) {
                // Color based on signal strength
                int color;
                double ratio = (double)strength / max_strength;
                if (ratio > 0.66) color = ColorPalette::SUCCESS;
                else if (ratio > 0.33) color = ColorPalette::WARNING;
                else color = ColorPalette::DANGER;

                // Add shimmer animation
                bool shimmer = (i == strength - 1) && (tick % 4 < 2);
                if (shimmer && vt_ok_) color = 255;

                if (vt_ok_) out << "\x1b[38;5;" << color << "m";
                out << levels[i % 5];
                if (vt_ok_) out << "\x1b[0m";
            } else {
                if (vt_ok_) out << "\x1b[38;5;236m";
                out << "▁";
                if (vt_ok_) out << "\x1b[0m";
            }
        }

        return out.str();
    }

    // -------------------------------------------------------------------------
    // BLOCK VISUALIZATION - Block with hash preview
    // -------------------------------------------------------------------------
    std::string draw_block_mini(uint64_t height, const std::string& hash, int txs, int tick) const {
        std::ostringstream out;

        if (!u8_ok_) {
            out << "#" << height << " " << short_hex(hash, 8) << " " << txs << "tx";
            return out.str();
        }

        // Block icon with animation
        bool highlight = (tick % 8 < 2);
        int block_color = highlight ? ColorPalette::PRIMARY : ColorPalette::SECONDARY;

        if (vt_ok_) {
            out << "\x1b[38;5;" << block_color << "m◼\x1b[0m ";
            out << "\x1b[38;5;" << ColorPalette::INFO << "m#" << height << "\x1b[0m ";
            out << "\x1b[38;5;240m" << short_hex(hash, 8) << "\x1b[0m ";
            out << "\x1b[38;5;" << ColorPalette::TEXT << "m" << txs << "tx\x1b[0m";
        } else {
            out << "# " << height << " " << short_hex(hash, 8) << " " << txs << "tx";
        }

        return out.str();
    }

    // -------------------------------------------------------------------------
    // ANIMATED LOADING - Various loading animations
    // -------------------------------------------------------------------------
    std::string draw_loading(int style, int tick) const {
        if (!u8_ok_) {
            static const char* ascii_spin[] = {"|", "/", "-", "\\"};
            return std::string("[") + ascii_spin[tick % 4] + "]";
        }

        std::ostringstream out;

        switch (style) {
            case 0: {
                // Braille spinner
                static const char* braille[] = {"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"};
                if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::PRIMARY << "m";
                out << braille[tick % 8];
                break;
            }
            case 1: {
                // Dots spinner
                static const char* dots[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
                if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::ACCENT << "m";
                out << dots[tick % 10];
                break;
            }
            case 2: {
                // Arc spinner
                static const char* arcs[] = {"◜", "◠", "◝", "◞", "◡", "◟"};
                if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::SUCCESS << "m";
                out << arcs[tick % 6];
                break;
            }
            case 3: {
                // Block bounce
                static const char* blocks[] = {"▖", "▘", "▝", "▗"};
                if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::INFO << "m";
                out << blocks[tick % 4];
                break;
            }
            default: {
                // Default braille
                static const char* def[] = {"⠿", "⡿", "⣿", "⣷", "⣯", "⣟"};
                if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::PRIMARY << "m";
                out << def[tick % 6];
            }
        }

        if (vt_ok_) out << "\x1b[0m";
        return out.str();
    }

    // -------------------------------------------------------------------------
    // HEAT MAP - Color intensity based on value
    // -------------------------------------------------------------------------
    std::string draw_heatmap_cell(double value, double max_val) const {
        double pct = (max_val > 0) ? (value / max_val) : 0;
        if (pct < 0) pct = 0;
        if (pct > 1) pct = 1;

        if (!u8_ok_) {
            if (pct < 0.25) return ".";
            if (pct < 0.5) return "o";
            if (pct < 0.75) return "O";
            return "#";
        }

        // Heat colors: blue -> cyan -> green -> yellow -> orange -> red
        int color;
        if (pct < 0.2) color = 21;       // Blue
        else if (pct < 0.4) color = 39;  // Cyan
        else if (pct < 0.6) color = 46;  // Green
        else if (pct < 0.8) color = 226; // Yellow
        else color = 196;                // Red

        std::ostringstream out;
        if (vt_ok_) out << "\x1b[38;5;" << color << "m";
        out << "█";
        if (vt_ok_) out << "\x1b[0m";
        return out.str();
    }

    // -------------------------------------------------------------------------
    // TREND ARROW - Direction indicator
    // -------------------------------------------------------------------------
    std::string draw_trend_arrow(double current, double previous) const {
        if (!u8_ok_) {
            if (current > previous * 1.01) return "^";
            if (current < previous * 0.99) return "v";
            return "=";
        }

        std::ostringstream out;
        if (current > previous * 1.05) {
            if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::SUCCESS << "m";
            out << "▲▲";
        } else if (current > previous * 1.01) {
            if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::SUCCESS << "m";
            out << "▲";
        } else if (current < previous * 0.95) {
            if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::DANGER << "m";
            out << "▼▼";
        } else if (current < previous * 0.99) {
            if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::DANGER << "m";
            out << "▼";
        } else {
            if (vt_ok_) out << "\x1b[38;5;" << ColorPalette::MUTED << "m";
            out << "━";
        }
        if (vt_ok_) out << "\x1b[0m";
        return out.str();
    }

    // -------------------------------------------------------------------------
    // BADGE - Styled label/tag
    // -------------------------------------------------------------------------
    std::string draw_badge(const std::string& text, int bg_color, int text_color) const {
        std::ostringstream out;

        if (!vt_ok_) {
            return "[" + text + "]";
        }

        if (u8_ok_) {
            out << "\x1b[48;5;" << bg_color << "m\x1b[38;5;" << text_color << "m";
            out << " " << text << " ";
            out << "\x1b[0m";
        } else {
            out << "\x1b[38;5;" << text_color << "m[" << text << "]\x1b[0m";
        }

        return out.str();
    }

    // -------------------------------------------------------------------------
    // DIVIDER - Styled horizontal line
    // -------------------------------------------------------------------------
    std::string draw_divider(int width, int style, int color, int tick) const {
        std::ostringstream out;

        if (!vt_ok_) {
            char c = (style == 0) ? '-' : (style == 1) ? '=' : '~';
            return std::string(width, c);
        }

        out << "\x1b[38;5;" << color << "m";

        switch (style) {
            case 0: // Thin line
                for (int i = 0; i < width; ++i) out << (u8_ok_ ? "─" : "-");
                break;
            case 1: // Thick line
                for (int i = 0; i < width; ++i) out << (u8_ok_ ? "━" : "=");
                break;
            case 2: // Dotted
                for (int i = 0; i < width; ++i) {
                    out << (u8_ok_ ? ((i % 2 == 0) ? "·" : " ") : ".");
                }
                break;
            case 3: // Animated gradient
                for (int i = 0; i < width; ++i) {
                    int pulse = (tick + i) % 10;
                    int c = color + (pulse < 5 ? pulse : 10 - pulse);
                    out << "\x1b[38;5;" << c << "m" << (u8_ok_ ? "═" : "=");
                }
                break;
            default:
                out << std::string(width, u8_ok_ ? *"─" : '-');
        }

        out << "\x1b[0m";
        return out.str();
    }

    // -------------------------------------------------------------------------
    // HEADER BANNER - Main title with effects
    // -------------------------------------------------------------------------
    std::string draw_header_banner(int width, int tick) const {
        std::ostringstream out;

        if (!vt_ok_ || !u8_ok_) {
            out << "+" << std::string(width - 2, '=') << "+\n";
            out << "| MIQROCHAIN NODE";
            out << std::string(width - 20, ' ') << " |\n";
            out << "+" << std::string(width - 2, '=') << "+\n";
            return out.str();
        }

        // Animated top border
        out << "\x1b[38;5;" << ColorPalette::BORDER << "m╔";
        for (int i = 0; i < width - 2; ++i) {
            int pulse = (tick + i) % 24;
            int c;
            if (pulse < 8) c = ColorPalette::BORDER + pulse;
            else if (pulse < 16) c = ColorPalette::BORDER + (16 - pulse);
            else c = ColorPalette::BORDER + (pulse - 16);
            out << "\x1b[38;5;" << c << "m═";
        }
        out << "\x1b[38;5;" << ColorPalette::BORDER << "m╗\x1b[0m\n";

        // Logo line with gradient animation
        out << "\x1b[38;5;" << ColorPalette::BORDER << "m║\x1b[0m ";

        // Animated logo
        static const int logo_colors[] = {51, 50, 49, 48, 47, 46, 45, 44, 43, 42};
        int lc = logo_colors[tick % 10];
        out << "\x1b[38;5;" << lc << "m\x1b[1m◆ MIQROCHAIN\x1b[0m";

        // Version
        out << " \x1b[38;5;" << ColorPalette::MUTED << "mv" << MIQ_VERSION_MAJOR << "."
            << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH << "\x1b[0m";

        // Separator
        out << " \x1b[38;5;240m│\x1b[0m ";

        // Chain name
        out << "\x1b[38;5;" << ColorPalette::INFO << "m" << CHAIN_NAME << "\x1b[0m";

        // Separator
        out << " \x1b[38;5;240m│\x1b[0m ";

        // Animated spinner
        out << draw_loading(0, tick);

        // Separator
        out << " \x1b[38;5;240m│\x1b[0m ";

        // State badge
        NodeState show_state = degraded_override_ ? NodeState::Degraded : nstate_;
        switch (show_state) {
            case NodeState::Starting:
                out << draw_badge("STARTING", ColorPalette::ACCENT, 0);
                break;
            case NodeState::Syncing:
                out << draw_badge("SYNCING", ColorPalette::ACCENT, 0);
                break;
            case NodeState::Running:
                out << draw_badge("RUNNING", ColorPalette::SUCCESS, 0);
                break;
            case NodeState::Degraded:
                out << draw_badge("DEGRADED", ColorPalette::DANGER, 255);
                break;
            case NodeState::Quitting:
                out << draw_badge("SHUTDOWN", ColorPalette::WARNING, 0);
                break;
        }

        // Miner badge if active
        if (miner_running_badge()) {
            out << " \x1b[38;5;240m│\x1b[0m " << draw_badge("⛏ MINING", ColorPalette::SUCCESS, 0);
        }

        // Pad to end
        int content_len = 75 + (miner_running_badge() ? 15 : 0);
        int pad = width - content_len - 2;
        if (pad > 0) out << std::string(pad, ' ');

        out << "\x1b[38;5;" << ColorPalette::BORDER << "m║\x1b[0m\n";

        return out.str();
    }

    // =========================================================================
    // ADVANCED PANEL SYSTEM - Professional multi-panel layouts with animations
    // =========================================================================

    // Panel configuration for advanced layouts
    struct PanelConfig {
        std::string title;
        std::string icon;
        int min_width;
        int min_height;
        int border_color;
        bool animated_border;
        bool has_shadow;
    };

    // Draw a complete panel with content
    std::string draw_panel(const PanelConfig& cfg, const std::vector<std::string>& content,
                           int width, int tick) const {
        std::ostringstream out;
        int inner_w = width - 4;

        if (!vt_ok_) {
            // ASCII fallback
            out << "+" << std::string(width - 2, '-') << "+\n";
            out << "| " << cfg.title << std::string(width - 4 - (int)cfg.title.size(), ' ') << " |\n";
            out << "+" << std::string(width - 2, '-') << "+\n";
            for (const auto& line : content) {
                out << "| " << line;
                int pad = width - 4 - (int)line.size();
                if (pad > 0) out << std::string(pad, ' ');
                out << " |\n";
            }
            out << "+" << std::string(width - 2, '-') << "+\n";
            return out.str();
        }

        int bc = cfg.border_color > 0 ? cfg.border_color : ColorPalette::BORDER;

        // Top border with optional animation
        out << "\x1b[38;5;" << bc << "m" << (u8_ok_ ? "╭" : "+");
        for (int i = 0; i < width - 2; ++i) {
            if (cfg.animated_border && u8_ok_) {
                int pulse = (tick + i) % 12;
                int c = bc + (pulse < 6 ? pulse : 12 - pulse);
                out << "\x1b[38;5;" << c << "m─";
            } else {
                out << (u8_ok_ ? "─" : "-");
            }
        }
        out << "\x1b[38;5;" << bc << "m" << (u8_ok_ ? "╮" : "+") << "\x1b[0m\n";

        // Title bar
        out << "\x1b[38;5;" << bc << "m" << (u8_ok_ ? "│" : "|") << "\x1b[0m";
        out << "\x1b[48;5;" << ColorPalette::BG_PANEL << "m ";
        if (!cfg.icon.empty() && u8_ok_) {
            int icon_c = (tick % 6 < 3) ? ColorPalette::PRIMARY : ColorPalette::SECONDARY;
            out << "\x1b[38;5;" << icon_c << "m" << cfg.icon << "\x1b[0m ";
        }
        out << "\x1b[38;5;255m\x1b[1m" << cfg.title << "\x1b[0m";
        out << "\x1b[48;5;" << ColorPalette::BG_PANEL << "m";
        int title_len = (int)cfg.title.size() + (cfg.icon.empty() ? 1 : 4);
        out << std::string(inner_w - title_len, ' ');
        out << "\x1b[0m\x1b[38;5;" << bc << "m" << (u8_ok_ ? "│" : "|") << "\x1b[0m\n";

        // Separator
        out << "\x1b[38;5;" << bc << "m" << (u8_ok_ ? "├" : "+");
        for (int i = 0; i < width - 2; ++i) out << (u8_ok_ ? "─" : "-");
        out << (u8_ok_ ? "┤" : "+") << "\x1b[0m\n";

        // Content
        for (const auto& line : content) {
            out << "\x1b[38;5;" << bc << "m" << (u8_ok_ ? "│" : "|") << "\x1b[0m";
            out << "\x1b[48;5;" << ColorPalette::BG_PANEL << "m ";
            out << line;
            int vis_len = visible_length(line);
            int pad = inner_w - vis_len;
            if (pad > 0) out << std::string(pad, ' ');
            out << " \x1b[0m\x1b[38;5;" << bc << "m" << (u8_ok_ ? "│" : "|") << "\x1b[0m\n";
        }

        // Bottom border
        out << "\x1b[38;5;" << bc << "m" << (u8_ok_ ? "╰" : "+");
        for (int i = 0; i < width - 2; ++i) {
            if (cfg.animated_border && u8_ok_) {
                int pulse = (tick + i) % 12;
                int c = bc + (pulse < 6 ? pulse : 12 - pulse);
                out << "\x1b[38;5;" << c << "m─";
            } else {
                out << (u8_ok_ ? "─" : "-");
            }
        }
        out << "\x1b[38;5;" << bc << "m" << (u8_ok_ ? "╯" : "+") << "\x1b[0m\n";

        return out.str();
    }

    // =========================================================================
    // NETWORK TOPOLOGY VISUALIZATION - Peer map with quality indicators
    // =========================================================================

    // Peer quality score (0-100)
    int calculate_peer_quality(uint64_t latency_ms, uint64_t bytes_recv, bool verack_ok) const {
        if (!verack_ok) return 0;
        int score = 50;
        // Latency scoring
        if (latency_ms < 50) score += 30;
        else if (latency_ms < 100) score += 20;
        else if (latency_ms < 200) score += 10;
        else if (latency_ms > 500) score -= 20;
        // Activity scoring
        if (bytes_recv > 1000000) score += 20;
        else if (bytes_recv > 100000) score += 10;
        if (score < 0) score = 0;
        if (score > 100) score = 100;
        return score;
    }

    // Draw peer quality bar
    std::string draw_peer_quality(int quality, int width) const {
        if (width < 5) width = 5;
        std::ostringstream out;

        if (!vt_ok_ || !u8_ok_) {
            int filled = quality * width / 100;
            out << "[";
            for (int i = 0; i < width; ++i) {
                out << (i < filled ? "#" : ".");
            }
            out << "]";
            return out.str();
        }

        int color;
        if (quality >= 80) color = ColorPalette::SUCCESS;
        else if (quality >= 50) color = ColorPalette::WARNING;
        else color = ColorPalette::DANGER;

        int filled = quality * width / 100;
        for (int i = 0; i < width; ++i) {
            if (i < filled) {
                out << "\x1b[38;5;" << color << "m█\x1b[0m";
            } else {
                out << "\x1b[38;5;236m░\x1b[0m";
            }
        }
        return out.str();
    }

    // Draw network topology map
    std::string draw_network_topology(int width, int tick) const {
        std::ostringstream out;

        if (!p2p_) {
            return vt_ok_ ? "\x1b[38;5;240m(no P2P connection)\x1b[0m" : "(no P2P)";
        }

        auto peers = p2p_->snapshot_peers();
        if (peers.empty()) {
            return vt_ok_ ? "\x1b[38;5;240m(searching for peers...)\x1b[0m" : "(searching...)";
        }

        // Sort by quality
        std::vector<std::pair<int, size_t>> quality_idx;
        for (size_t i = 0; i < peers.size(); ++i) {
            int q = calculate_peer_quality(0, 0, peers[i].verack_ok);
            quality_idx.push_back({q, i});
        }
        std::sort(quality_idx.rbegin(), quality_idx.rend());

        // Draw mini topology - center node with spokes
        if (u8_ok_ && vt_ok_) {
            // Animated center node
            static const char* center_frames[] = {"◉", "◎", "●", "◎"};
            int c_color = (tick % 8 < 4) ? ColorPalette::PRIMARY : ColorPalette::SECONDARY;
            out << "\x1b[38;5;" << c_color << "m" << center_frames[tick % 4] << "\x1b[0m";

            // Connection spokes
            size_t show_peers = std::min(peers.size(), (size_t)8);
            for (size_t i = 0; i < show_peers; ++i) {
                const auto& p = peers[quality_idx[i].second];
                int q = quality_idx[i].first;
                int color = (q >= 80) ? ColorPalette::SUCCESS :
                           (q >= 50) ? ColorPalette::WARNING : ColorPalette::DANGER;

                // Animated connection line
                bool active = (tick + (int)i) % 4 < 2;
                out << "\x1b[38;5;" << (active ? color : 240) << "m";
                out << (p.verack_ok ? "━" : "╌");
                out << (p.verack_ok ? "●" : "○");
                out << "\x1b[0m ";
            }
        } else {
            out << "[NODE]";
            for (size_t i = 0; i < std::min(peers.size(), (size_t)4); ++i) {
                out << (peers[i].verack_ok ? "-*" : "-o");
            }
        }

        return out.str();
    }

    // Draw detailed peer list with quality metrics
    std::vector<std::string> draw_peer_details(int width) const {
        std::vector<std::string> lines;

        if (!p2p_) return lines;

        auto peers = p2p_->snapshot_peers();
        if (peers.empty()) {
            lines.push_back(vt_ok_ ? "\x1b[38;5;240m  No peers connected\x1b[0m" : "  No peers");
            return lines;
        }

        // Header
        if (vt_ok_) {
            lines.push_back("\x1b[38;5;245m  IP Address        Quality  Status\x1b[0m");
        } else {
            lines.push_back("  IP Address        Quality  Status");
        }

        size_t show = std::min(peers.size(), (size_t)6);
        for (size_t i = 0; i < show; ++i) {
            const auto& p = peers[i];
            std::ostringstream ln;

            std::string ip = p.ip;
            if (ip.size() > 15) ip = ip.substr(0, 12) + "...";

            int quality = calculate_peer_quality(0, 0, p.verack_ok);

            if (vt_ok_) {
                ln << "  ";
                ln << (p.verack_ok ? "\x1b[38;5;46m●\x1b[0m" : "\x1b[38;5;240m○\x1b[0m");
                ln << " \x1b[38;5;252m" << std::left << std::setw(15) << ip << "\x1b[0m ";
                ln << draw_peer_quality(quality, 8) << " ";

                if (p.verack_ok) {
                    ln << "\x1b[38;5;46mActive\x1b[0m";
                } else {
                    ln << "\x1b[38;5;240mConnecting\x1b[0m";
                }
            } else {
                ln << "  " << (p.verack_ok ? "*" : "o") << " ";
                ln << std::left << std::setw(15) << ip << " ";
                ln << "[" << quality << "%] ";
                ln << (p.verack_ok ? "Active" : "Connecting");
            }
            lines.push_back(ln.str());
        }

        if (peers.size() > show) {
            std::ostringstream more;
            if (vt_ok_) {
                more << "  \x1b[38;5;240m+ " << (peers.size() - show) << " more peers\x1b[0m";
            } else {
                more << "  + " << (peers.size() - show) << " more";
            }
            lines.push_back(more.str());
        }

        return lines;
    }

    // =========================================================================
    // MINING PERFORMANCE DASHBOARD - Advanced mining visualization
    // =========================================================================

    // Mining history for graphs
    struct MiningHistory {
        std::deque<double> hashrates;      // Last N hashrate samples
        std::deque<uint64_t> block_times;  // Time between blocks
        std::deque<double> efficiency;     // Hash/second per thread
        static constexpr size_t MAX_SAMPLES = 60;

        void add_hashrate(double hr) {
            hashrates.push_back(hr);
            if (hashrates.size() > MAX_SAMPLES) hashrates.pop_front();
        }

        void add_block_time(uint64_t time_s) {
            block_times.push_back(time_s);
            if (block_times.size() > MAX_SAMPLES) block_times.pop_front();
        }

        double avg_hashrate() const {
            if (hashrates.empty()) return 0;
            double sum = 0;
            for (auto h : hashrates) sum += h;
            return sum / hashrates.size();
        }

        double peak_hashrate() const {
            if (hashrates.empty()) return 0;
            return *std::max_element(hashrates.begin(), hashrates.end());
        }
    };

    // Draw mining performance graph
    std::string draw_mining_graph(const std::vector<double>& data, int width, int height, int tick) const {
        if (data.empty() || width < 5 || height < 2) {
            return vt_ok_ ? "\x1b[38;5;240m(no data)\x1b[0m" : "(no data)";
        }

        std::ostringstream out;

        if (!u8_ok_) {
            // Simple ASCII sparkline
            return spark_ascii(data);
        }

        double max_val = *std::max_element(data.begin(), data.end());
        double min_val = *std::min_element(data.begin(), data.end());
        double range = max_val - min_val;
        if (range < 0.001) range = 1;

        // Draw mini bar graph
        size_t start = (data.size() > (size_t)width) ? data.size() - width : 0;

        for (size_t i = start; i < data.size(); ++i) {
            double norm = (data[i] - min_val) / range;
            int bar_height = (int)(norm * 8);
            if (bar_height > 7) bar_height = 7;

            // Gradient color based on value
            int color;
            if (norm > 0.8) color = ColorPalette::SUCCESS;
            else if (norm > 0.5) color = ColorPalette::INFO;
            else if (norm > 0.2) color = ColorPalette::WARNING;
            else color = ColorPalette::MUTED;

            // Add shimmer effect on recent values
            if (i == data.size() - 1 && (tick % 4 < 2)) {
                color = 255;
            }

            static const char* bars[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
            out << "\x1b[38;5;" << color << "m" << bars[bar_height] << "\x1b[0m";
        }

        return out.str();
    }

    // Draw mining statistics panel content
    std::vector<std::string> draw_mining_stats(int width, int tick) const {
        std::vector<std::string> lines;

        bool active = g_miner_stats.active.load();
        double hps = g_miner_stats.hps.load();
        uint64_t threads = g_miner_stats.threads.load();
        uint64_t accepted = g_miner_stats.accepted.load();
        uint64_t rejected = g_miner_stats.rejected.load();

        // Status line with animated indicator
        std::ostringstream status;
        if (vt_ok_) {
            if (active) {
                static const int pulse[] = {46, 47, 48, 49, 48, 47};
                int c = pulse[tick % 6];
                status << "\x1b[38;5;" << c << "m● MINING ACTIVE\x1b[0m";
                status << "  \x1b[38;5;240m(" << threads << " threads)\x1b[0m";
            } else if (mining_gate_available_) {
                status << "\x1b[38;5;240m○ Ready to mine\x1b[0m";
            } else {
                status << "\x1b[38;5;196m○ Mining unavailable\x1b[0m";
            }
        } else {
            status << (active ? "* MINING" : "o Idle");
        }
        lines.push_back(status.str());

        if (active || accepted > 0) {
            // Hashrate with trend
            std::ostringstream hr;
            if (vt_ok_) {
                hr << "\x1b[38;5;245mHashrate\x1b[0m  \x1b[38;5;87m\x1b[1m" << fmt_hs(hps) << "\x1b[0m";
            } else {
                hr << "Hashrate: " << fmt_hs(hps);
            }
            lines.push_back(hr.str());

            // Hashrate sparkline
            if (!spark_hs_.empty()) {
                std::ostringstream spark;
                if (vt_ok_) {
                    spark << "\x1b[38;5;245mTrend\x1b[0m     ";
                    spark << draw_mining_graph(spark_hs_, 24, 1, tick);
                } else {
                    spark << "Trend: " << spark_ascii(spark_hs_);
                }
                lines.push_back(spark.str());
            }

            // Blocks found
            std::ostringstream blocks;
            if (vt_ok_) {
                blocks << "\x1b[38;5;245mBlocks\x1b[0m    \x1b[38;5;46m" << accepted << " found\x1b[0m";
                if (rejected > 0) {
                    blocks << "  \x1b[38;5;196m" << rejected << " rejected\x1b[0m";
                }
            } else {
                blocks << "Blocks: " << accepted << " found";
            }
            lines.push_back(blocks.str());

            // Efficiency
            if (threads > 0) {
                double eff = hps / threads;
                std::ostringstream effln;
                if (vt_ok_) {
                    effln << "\x1b[38;5;245mEfficiency\x1b[0m\x1b[38;5;183m " << fmt_hs(eff) << "/thread\x1b[0m";
                } else {
                    effln << "Efficiency: " << fmt_hs(eff) << "/thread";
                }
                lines.push_back(effln.str());
            }
        }

        return lines;
    }

    // =========================================================================
    // PROFESSIONAL LOG VIEWER - Filtered, searchable log display
    // =========================================================================

    // Log filter state
    mutable std::string log_filter_text_;
    mutable int log_filter_level_{0};  // 0=all, 1=warn+, 2=error only, 3=debug
    mutable bool log_filter_active_{false};

    // Filter logs based on current settings
    std::vector<StyledLine> filter_logs(size_t max_lines) const {
        std::vector<StyledLine> filtered;

        for (const auto& log : logs_) {
            // Level filter
            if (log_filter_level_ > 0) {
                if (log_filter_level_ == 1 && log.level > 1) continue;  // warn+ only
                if (log_filter_level_ == 2 && log.level != 2) continue; // error only
                if (log_filter_level_ == 3 && log.level != 3) continue; // debug only
            }

            // Text filter
            if (!log_filter_text_.empty()) {
                if (log.txt.find(log_filter_text_) == std::string::npos) continue;
            }

            filtered.push_back(log);
        }

        // Return last N
        if (filtered.size() > max_lines) {
            return std::vector<StyledLine>(filtered.end() - max_lines, filtered.end());
        }
        return filtered;
    }

    // Draw log entry with enhanced styling
    std::string draw_log_entry(const StyledLine& log, int width, int tick) const {
        std::ostringstream out;

        std::string txt = log.txt;
        if ((int)txt.size() > width - 4) {
            txt = txt.substr(0, width - 7) + "...";
        }

        if (!vt_ok_) {
            return txt;
        }

        // Level indicator
        std::string level_icon;
        int color;
        switch (log.level) {
            case 2:  // Error
                level_icon = u8_ok_ ? "✖ " : "[E] ";
                color = ColorPalette::DANGER;
                break;
            case 1:  // Warning
                level_icon = u8_ok_ ? "⚠ " : "[W] ";
                color = ColorPalette::WARNING;
                break;
            case 3:  // Debug
                level_icon = u8_ok_ ? "◌ " : "[D] ";
                color = ColorPalette::MUTED;
                break;
            case 4:  // Success
                level_icon = u8_ok_ ? "✓ " : "[+] ";
                color = ColorPalette::SUCCESS;
                break;
            case 5:  // Info highlight
                level_icon = u8_ok_ ? "◆ " : "[I] ";
                color = ColorPalette::INFO;
                break;
            default:
                level_icon = "  ";
                color = ColorPalette::TEXT;
        }

        // Highlight recent entries
        bool recent = (tick % 8 < 4) && (&log == &logs_.back());

        out << "\x1b[38;5;" << color << "m" << level_icon;
        if (recent) out << "\x1b[1m";
        out << txt;
        out << "\x1b[0m";

        return out.str();
    }

    // Draw log viewer header with filter info
    std::string draw_log_header(int width, int tick) const {
        std::ostringstream out;

        if (!vt_ok_) {
            return "[ LOGS ]";
        }

        out << "\x1b[38;5;255m\x1b[1m";
        out << (u8_ok_ ? "📜 " : "");
        out << "SYSTEM LOG\x1b[0m";

        // Filter indicator
        if (log_filter_active_) {
            out << "  \x1b[38;5;214m[FILTERED]\x1b[0m";
        }

        // Log count
        out << "  \x1b[38;5;240m(" << logs_.size() << " entries)\x1b[0m";

        // Controls hint
        out << "  \x1b[38;5;236m[f]filter [c]clear [↑↓]scroll\x1b[0m";

        return out.str();
    }

    // =========================================================================
    // REAL-TIME METRICS DASHBOARD - Live data visualization
    // =========================================================================

    // Metrics history storage
    struct MetricsHistory {
        std::deque<double> cpu_usage;
        std::deque<uint64_t> memory_usage;
        std::deque<double> network_in;
        std::deque<double> network_out;
        std::deque<uint64_t> block_heights;
        std::deque<size_t> peer_counts;
        std::deque<size_t> mempool_sizes;
        static constexpr size_t MAX_HISTORY = 120;

        void add_sample(double cpu, uint64_t mem, double net_in, double net_out,
                       uint64_t height, size_t peers, size_t mempool) {
            cpu_usage.push_back(cpu);
            memory_usage.push_back(mem);
            network_in.push_back(net_in);
            network_out.push_back(net_out);
            block_heights.push_back(height);
            peer_counts.push_back(peers);
            mempool_sizes.push_back(mempool);

            while (cpu_usage.size() > MAX_HISTORY) cpu_usage.pop_front();
            while (memory_usage.size() > MAX_HISTORY) memory_usage.pop_front();
            while (network_in.size() > MAX_HISTORY) network_in.pop_front();
            while (network_out.size() > MAX_HISTORY) network_out.pop_front();
            while (block_heights.size() > MAX_HISTORY) block_heights.pop_front();
            while (peer_counts.size() > MAX_HISTORY) peer_counts.pop_front();
            while (mempool_sizes.size() > MAX_HISTORY) mempool_sizes.pop_front();
        }
    };

    // Draw metrics overview panel
    std::vector<std::string> draw_metrics_overview(int width, int tick) const {
        std::vector<std::string> lines;

        uint64_t rss = get_rss_bytes();
        size_t peer_count = p2p_ ? p2p_->snapshot_peers().size() : 0;
        size_t mempool_count = 0;
        if (mempool_) {
            auto stat = mempool_view_fallback(mempool_);
            mempool_count = stat.count;
        }
        uint64_t height = chain_ ? chain_->height() : 0;

        // Memory usage with mini graph
        std::ostringstream mem;
        if (vt_ok_) {
            mem << "\x1b[38;5;245mMemory\x1b[0m    ";
            mem << draw_gauge((double)rss, 500.0 * 1024 * 1024, 16, "",
                             ColorPalette::SUCCESS, ColorPalette::WARNING, ColorPalette::DANGER, tick);
            mem << " \x1b[38;5;183m" << fmt_bytes(rss) << "\x1b[0m";
        } else {
            mem << "Memory: " << fmt_bytes(rss);
        }
        lines.push_back(mem.str());

        // Peer health indicator
        std::ostringstream peers;
        if (vt_ok_) {
            peers << "\x1b[38;5;245mPeers\x1b[0m     ";
            peers << draw_signal((int)std::min(peer_count, (size_t)5), 5, tick);
            peers << " \x1b[38;5;252m" << peer_count << " connected\x1b[0m";
        } else {
            peers << "Peers: " << peer_count;
        }
        lines.push_back(peers.str());

        // Chain height with trend
        std::ostringstream chain_ln;
        if (vt_ok_) {
            chain_ln << "\x1b[38;5;245mChain\x1b[0m     ";
            chain_ln << "\x1b[38;5;51m#" << fmt_num(height) << "\x1b[0m";

            // Add mini sparkline for block progress
            if (!net_spark_.empty()) {
                chain_ln << " " << draw_sparkline(net_spark_, 12, ColorPalette::INFO, false);
            }
        } else {
            chain_ln << "Chain: #" << fmt_num(height);
        }
        lines.push_back(chain_ln.str());

        // Mempool status
        std::ostringstream mp;
        if (vt_ok_) {
            mp << "\x1b[38;5;245mMempool\x1b[0m   ";
            if (mempool_count > 0) {
                mp << "\x1b[38;5;214m" << mempool_count << " tx\x1b[0m";
            } else {
                mp << "\x1b[38;5;240mempty\x1b[0m";
            }
        } else {
            mp << "Mempool: " << mempool_count << " tx";
        }
        lines.push_back(mp.str());

        return lines;
    }

    // Draw combined multi-metric sparkline display
    std::string draw_multi_sparkline(int width, int tick) const {
        std::ostringstream out;

        if (!vt_ok_ || !u8_ok_) {
            return "";
        }

        // Create labels and data
        struct MetricLine {
            std::string label;
            const std::vector<double>* data;
            int color;
        };

        std::vector<double> peer_data;
        if (p2p_) {
            peer_data.push_back((double)p2p_->snapshot_peers().size());
        }

        // Network hashrate sparkline
        if (!net_spark_.empty()) {
            out << "\x1b[38;5;245mNet H/s\x1b[0m ";
            out << draw_sparkline(net_spark_, width - 10, ColorPalette::INFO, false);
        }

        return out.str();
    }

    // =========================================================================
    // MATRIX TRANSITION ANIMATION - Epic digital rain decode effect
    // =========================================================================

    // Matrix rain column state
    struct MatrixColumn {
        int y;           // Current head position
        int length;      // Trail length
        int speed;       // Fall speed (1-3)
        int char_tick;   // Character change timer
        bool active;
    };

    // Initialize matrix rain columns
    mutable std::vector<MatrixColumn> matrix_columns_;
    mutable int transition_frame_{0};
    mutable bool transition_active_{false};
    static constexpr int TRANSITION_FRAMES = 45;  // ~1.5 seconds at 30fps

    void init_matrix_transition(int cols) const {
        matrix_columns_.clear();
        matrix_columns_.resize(cols);
        std::mt19937 rng(static_cast<unsigned int>(std::chrono::steady_clock::now().time_since_epoch().count()));
        for (int i = 0; i < cols; ++i) {
            matrix_columns_[i].y = -(int)(rng() % 20);  // Staggered start
            matrix_columns_[i].length = 5 + rng() % 15;
            matrix_columns_[i].speed = 1 + rng() % 3;
            matrix_columns_[i].char_tick = rng() % 4;
            matrix_columns_[i].active = true;
        }
        transition_frame_ = 0;
        transition_active_ = true;
    }

    // Get matrix character (katakana-like + numbers + symbols)
    char get_matrix_char(int tick) const {
        static const char chars[] = "0123456789ABCDEF@#$%&*+=<>{}[]|/\\~";
        return chars[(tick * 7 + 13) % (sizeof(chars) - 1)];
    }

    // Draw matrix transition frame
    void draw_matrix_transition(int cols, int rows) {
        if (!transition_active_) return;

        std::ostringstream out;
        out << "\x1b[H";  // Home cursor

        // Matrix green color palette
        static const int greens[] = {22, 28, 34, 40, 46, 82, 118, 154, 190, 226, 231};

        // Resize columns if needed
        if ((int)matrix_columns_.size() != cols) {
            init_matrix_transition(cols);
        }

        // Build frame buffer
        std::vector<std::string> screen(rows);
        for (int row = 0; row < rows; ++row) {
            screen[row].reserve(cols * 20);  // Pre-allocate for ANSI codes
        }

        // Update and render each column
        for (int x = 0; x < cols && x < (int)matrix_columns_.size(); ++x) {
            auto& col = matrix_columns_[x];

            // Update position
            if (transition_frame_ % col.speed == 0) {
                col.y++;
            }
            col.char_tick++;

            // Render trail
            for (int t = 0; t < col.length && col.active; ++t) {
                int y = col.y - t;
                if (y >= 0 && y < rows) {
                    // Brightness based on trail position
                    int brightness = col.length - t;
                    int color_idx = std::min(10, brightness * 11 / col.length);

                    if (t == 0) {
                        // Head is white/bright
                        screen[y] += "\x1b[38;5;231m";
                    } else {
                        screen[y] += "\x1b[38;5;" + std::to_string(greens[color_idx]) + "m";
                    }

                    // Character with slight randomization
                    char c = get_matrix_char(col.char_tick + t + x);
                    screen[y] += c;
                    screen[y] += "\x1b[0m";
                }
            }
        }

        // Phase 2: Decode effect - reveal MIQROCHAIN text
        int decode_start = TRANSITION_FRAMES / 3;
        if (transition_frame_ > decode_start) {
            int decode_progress = (transition_frame_ - decode_start) * 100 / (TRANSITION_FRAMES - decode_start);

            // Center text reveal
            const char* reveal_text = "◆ MIQROCHAIN NODE ◆";
            int text_len = 19;
            int text_x = (cols - text_len) / 2;
            int text_y = rows / 2;

            if (text_y >= 0 && text_y < rows && decode_progress > 20) {
                std::string reveal_line;

                // Clear line first
                reveal_line += "\x1b[" + std::to_string(text_y + 1) + ";1H";
                reveal_line += std::string(cols, ' ');
                reveal_line += "\x1b[" + std::to_string(text_y + 1) + ";" + std::to_string(text_x + 1) + "H";

                // Animated color reveal
                static const int logo_colors[] = {46, 47, 48, 49, 50, 51, 50, 49, 48, 47};
                int color = logo_colors[transition_frame_ % 10];

                reveal_line += "\x1b[38;5;" + std::to_string(color) + "m\x1b[1m";

                // Gradually reveal characters
                int chars_to_show = text_len * decode_progress / 100;
                for (int i = 0; i < text_len; ++i) {
                    if (i < chars_to_show) {
                        reveal_line += reveal_text[i];
                    } else {
                        reveal_line += get_matrix_char(transition_frame_ + i);
                    }
                }
                reveal_line += "\x1b[0m";

                out << reveal_line;
            }

            // Subtitle reveal
            if (decode_progress > 60) {
                const char* subtitle = "[ BLOCKCHAIN SYNCHRONIZED - ENTERING DASHBOARD ]";
                int sub_len = 48;
                int sub_x = (cols - sub_len) / 2;
                int sub_y = text_y + 2;

                if (sub_y < rows) {
                    out << "\x1b[" << (sub_y + 1) << ";" << (sub_x + 1) << "H";
                    out << "\x1b[38;5;46m" << subtitle << "\x1b[0m";
                }
            }
        }

        // Output frame
        for (int row = 0; row < rows; ++row) {
            out << "\x1b[" << (row + 1) << ";1H";
            if (!screen[row].empty()) {
                out << screen[row];
            }
        }

        std::string frame = out.str();
        cw_.write_frame("", frame);
        std::fflush(stdout);

        transition_frame_++;

        // End transition
        if (transition_frame_ >= TRANSITION_FRAMES) {
            transition_active_ = false;
            // Clear screen for main dashboard
            std::cout << "\x1b[H\x1b[J" << std::flush;
        }
    }

    // =========================================================================
    // ULTIMATE MAIN DASHBOARD - Premium node monitoring with epic visuals
    // =========================================================================

    // Animated fire effect for active mining
    std::string draw_fire_bar(int width, int tick) const {
        if (!u8_ok_ || width < 5) return "";
        std::ostringstream out;
        static const int fire_colors[] = {196, 202, 208, 214, 220, 226, 227, 228, 229, 230};
        static const char* fire_chars[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};

        for (int i = 0; i < width; ++i) {
            int phase = (tick * 2 + i * 3) % 16;
            int height = (phase < 8) ? phase : (16 - phase);
            int color_idx = (tick + i) % 10;
            out << "\x1b[38;5;" << fire_colors[color_idx] << "m" << fire_chars[height % 8] << "\x1b[0m";
        }
        return out.str();
    }

    // Animated wave effect
    std::string draw_wave(int width, int tick, int color) const {
        if (!u8_ok_ || width < 3) return "";
        std::ostringstream out;
        static const char* wave[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▄", "▃", "▂"};

        for (int i = 0; i < width; ++i) {
            int phase = (tick + i) % 14;
            out << "\x1b[38;5;" << color << "m" << wave[phase] << "\x1b[0m";
        }
        return out.str();
    }

    // DNA helix animation for blockchain visualization
    std::string draw_dna_helix(int width, int tick) const {
        if (!u8_ok_ || width < 10) return "";
        std::ostringstream out;

        for (int i = 0; i < width; ++i) {
            double phase = (tick * 0.3 + i * 0.5);
            double sin_val = std::sin(phase);
            double cos_val = std::cos(phase);

            if (sin_val > 0.7) {
                out << "\x1b[38;5;51m●\x1b[0m";
            } else if (sin_val < -0.7) {
                out << "\x1b[38;5;201m●\x1b[0m";
            } else if (cos_val > 0) {
                out << "\x1b[38;5;240m─\x1b[0m";
            } else {
                out << "\x1b[38;5;236m─\x1b[0m";
            }
        }
        return out.str();
    }

    // Animated activity pulse ring
    std::string draw_pulse_ring(bool active, int tick) const {
        if (!u8_ok_) return active ? "[*]" : "[ ]";

        if (!active) {
            return "\x1b[38;5;240m○\x1b[0m";
        }

        static const char* rings[] = {"◯", "◎", "◉", "●", "◉", "◎"};
        static const int colors[] = {46, 47, 48, 49, 48, 47};
        int frame = tick % 6;

        std::ostringstream out;
        out << "\x1b[38;5;" << colors[frame] << "m" << rings[frame] << "\x1b[0m";
        return out.str();
    }

    // Draw fancy section divider with title
    std::string draw_section_divider(const std::string& title, const std::string& icon, int width, int tick) const {
        if (!vt_ok_) {
            int pad = width - (int)title.size() - 5;
            if (pad < 0) pad = 0;
            return "--- " + title + " " + std::string(pad, '-');
        }

        std::ostringstream out;
        int title_len = visible_length(title) + (icon.empty() ? 0 : 2);
        int left_len = 3;
        int right_len = width - title_len - left_len - 4;
        if (right_len < 3) right_len = 3;

        // Left segment with animation
        out << "\x1b[38;5;240m";
        for (int i = 0; i < left_len; ++i) {
            int pulse = (tick + i) % 8;
            int c = 236 + (pulse < 4 ? pulse : 8 - pulse);
            out << "\x1b[38;5;" << c << "m" << (u8_ok_ ? "─" : "-");
        }

        // Icon and title
        out << "\x1b[0m ";
        if (!icon.empty() && u8_ok_) {
            int icon_c = (tick % 6 < 3) ? ColorPalette::PRIMARY : ColorPalette::ACCENT;
            out << "\x1b[38;5;" << icon_c << "m" << icon << "\x1b[0m ";
        }
        out << "\x1b[38;5;255m\x1b[1m" << title << "\x1b[0m ";

        // Right segment with animation
        for (int i = 0; i < right_len; ++i) {
            int pulse = (tick + i + 5) % 8;
            int c = 236 + (pulse < 4 ? pulse : 8 - pulse);
            out << "\x1b[38;5;" << c << "m" << (u8_ok_ ? "─" : "-");
        }
        out << "\x1b[0m";

        return out.str();
    }

    // Draw epic stats box with glow effect
    std::string draw_stat_box(const std::string& label, const std::string& value, int color, int tick, bool highlight = false) const {
        std::ostringstream out;

        if (!vt_ok_) {
            return label + ": " + value;
        }

        // Glow effect for highlighted stats
        int border_c = highlight ? ((tick % 4 < 2) ? color : color + 2) : 240;

        if (u8_ok_) {
            out << "\x1b[38;5;" << border_c << "m┌";
            for (size_t i = 0; i < label.size() + 2; ++i) out << "─";
            out << "┐\x1b[0m ";
        }

        out << "\x1b[38;5;245m" << label << "\x1b[0m ";
        out << "\x1b[38;5;" << color << "m\x1b[1m" << value << "\x1b[0m";

        return out.str();
    }

    // Draw blockchain blocks visualization
    std::string draw_blockchain_viz(int num_blocks, int tick) const {
        if (!u8_ok_) return "[CHAIN]";
        std::ostringstream out;

        out << "\x1b[38;5;240m⟦\x1b[0m";
        for (int i = 0; i < num_blocks && i < 12; ++i) {
            // Animated block color
            int phase = (tick + i * 2) % 8;
            int color;
            if (i == num_blocks - 1) {
                // Latest block glows
                static const int glow[] = {46, 47, 48, 49, 50, 51, 50, 49};
                color = glow[tick % 8];
            } else {
                color = 39 + (phase < 4 ? phase : 8 - phase);
            }

            out << "\x1b[38;5;" << color << "m█\x1b[0m";
            if (i < num_blocks - 1 && i < 11) {
                out << "\x1b[38;5;240m─\x1b[0m";
            }
        }
        out << "\x1b[38;5;240m⟧\x1b[0m";

        return out.str();
    }

    // =========================================================================
    // ULTRA PREMIUM COMPONENTS - Expert level visualizations
    // =========================================================================

    // Epic glowing text effect
    std::string draw_glow_text(const std::string& text, int color, int tick, bool bold = true) const {
        if (!vt_ok_) return text;
        std::ostringstream out;

        // Pulse between color and brighter version
        int pulse = tick % 8;
        int c = color + (pulse < 4 ? pulse : 8 - pulse);
        if (c > 255) c = 255;

        out << "\x1b[38;5;" << c << "m";
        if (bold) out << "\x1b[1m";
        out << text << "\x1b[0m";
        return out.str();
    }

    // Animated radar sweep effect
    std::string draw_radar(int size, int tick) const {
        if (!u8_ok_ || size < 3) return "[O]";
        std::ostringstream out;

        static const char* radar_chars[] = {"◴", "◷", "◶", "◵"};
        int frame = tick % 4;

        out << "\x1b[38;5;46m" << radar_chars[frame] << "\x1b[0m";
        return out.str();
    }

    // Activity heat indicator (shows intensity with color)
    std::string draw_heat_indicator(double value, double max_val, int tick) const {
        if (!u8_ok_) {
            if (value > max_val * 0.8) return "[HOT]";
            if (value > max_val * 0.5) return "[MED]";
            return "[LOW]";
        }

        double ratio = max_val > 0 ? value / max_val : 0;
        if (ratio > 1.0) ratio = 1.0;

        std::ostringstream out;

        // Heat colors from cool to hot
        int color;
        std::string icon;
        if (ratio > 0.8) {
            static const int hot[] = {196, 202, 208, 214, 208, 202};
            color = hot[tick % 6];
            icon = "🔥";
        } else if (ratio > 0.5) {
            color = 214 + (tick % 3);
            icon = "◆";
        } else if (ratio > 0.2) {
            color = 226;
            icon = "◇";
        } else {
            color = 240;
            icon = "○";
        }

        out << "\x1b[38;5;" << color << "m" << icon << "\x1b[0m";
        return out.str();
    }

    // Epic animated counter with rolling digits effect
    std::string draw_rolling_number(uint64_t value, int width, int color, int tick) const {
        std::string num_str = fmt_num(value);
        if (!vt_ok_) return num_str;

        std::ostringstream out;
        out << "\x1b[38;5;" << color << "m";

        // Add subtle animation to last digit
        if (u8_ok_ && tick % 4 == 0) {
            out << "\x1b[1m";
        }
        out << num_str << "\x1b[0m";
        return out.str();
    }

    // Network activity visualization (mini traffic graph)
    std::string draw_network_activity(int width, int tick) const {
        if (!u8_ok_ || width < 5) return "";
        std::ostringstream out;

        // Simulated network activity bars
        static const char* bars[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};

        for (int i = 0; i < width; ++i) {
            // Create wave-like pattern
            int phase = (tick * 2 + i * 3) % 16;
            int height = (phase < 8) ? phase : (16 - phase);
            if (height > 7) height = 7;

            // Color based on height
            int color = 39 + height;
            out << "\x1b[38;5;" << color << "m" << bars[height] << "\x1b[0m";
        }
        return out.str();
    }

    // Draw epic animated logo line
    std::string draw_logo_animation(int width, int tick) const {
        if (!u8_ok_) return "";
        std::ostringstream out;

        // Particle effect
        int particle_pos = (tick * 2) % width;
        for (int i = 0; i < width; ++i) {
            int dist = std::abs(i - particle_pos);
            if (dist == 0) {
                out << "\x1b[38;5;231m★\x1b[0m";  // Bright particle
            } else if (dist < 3) {
                static const int trail[] = {255, 252, 249};
                out << "\x1b[38;5;" << trail[dist - 1] << "m·\x1b[0m";
            } else {
                out << "\x1b[38;5;236m─\x1b[0m";
            }
        }
        return out.str();
    }

    // System load meter with animated fill
    std::string draw_load_meter(double load, int width, int tick) const {
        if (width < 5) return "";
        std::ostringstream out;

        if (!u8_ok_) {
            int filled = (int)(load * width);
            out << "[";
            for (int i = 0; i < width; ++i) {
                out << (i < filled ? "=" : " ");
            }
            out << "]";
            return out.str();
        }

        int filled = (int)(load * width);

        // Gradient fill with animation
        for (int i = 0; i < width; ++i) {
            if (i < filled) {
                // Color gradient based on position
                int color;
                double pos_ratio = (double)i / width;
                if (pos_ratio < 0.5) {
                    color = 46;  // Green
                } else if (pos_ratio < 0.75) {
                    color = 226;  // Yellow
                } else {
                    color = 196 + (tick % 3);  // Red with pulse
                }

                // Shimmer effect on edge
                if (i == filled - 1 && tick % 4 < 2) {
                    color = 231;  // White flash
                }

                out << "\x1b[38;5;" << color << "m█\x1b[0m";
            } else {
                out << "\x1b[38;5;236m░\x1b[0m";
            }
        }
        return out.str();
    }

    // Animated connection indicator
    std::string draw_connection_status(bool connected, int quality, int tick) const {
        if (!u8_ok_) {
            return connected ? "[*]" : "[ ]";
        }

        std::ostringstream out;

        if (!connected) {
            // Scanning animation
            static const char* scan[] = {"◜", "◝", "◞", "◟"};
            out << "\x1b[38;5;240m" << scan[tick % 4] << "\x1b[0m";
        } else {
            // Quality-based indicator with pulse
            int color;
            std::string icon;
            if (quality >= 80) {
                static const int good[] = {46, 47, 48, 49, 48, 47};
                color = good[tick % 6];
                icon = "◉";
            } else if (quality >= 50) {
                color = 214 + (tick % 3);
                icon = "◎";
            } else {
                color = 196;
                icon = "○";
            }
            out << "\x1b[38;5;" << color << "m" << icon << "\x1b[0m";
        }
        return out.str();
    }

    // Epic timestamp display
    std::string draw_timestamp(int tick) const {
        if (!vt_ok_) return "";

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm* tm = std::localtime(&time);

        std::ostringstream out;
        out << "\x1b[38;5;240m";

        // Blinking colon
        out << std::setfill('0') << std::setw(2) << tm->tm_hour;
        out << ((tick % 2 == 0) ? "\x1b[38;5;252m:\x1b[38;5;240m" : "\x1b[38;5;236m:\x1b[38;5;240m");
        out << std::setfill('0') << std::setw(2) << tm->tm_min;
        out << ((tick % 2 == 0) ? "\x1b[38;5;252m:\x1b[38;5;240m" : "\x1b[38;5;236m:\x1b[38;5;240m");
        out << std::setfill('0') << std::setw(2) << tm->tm_sec;
        out << "\x1b[0m";

        return out.str();
    }

    // Cyber-punk style label
    std::string draw_cyber_label(const std::string& text, int color, int tick) const {
        if (!vt_ok_) return "[" + text + "]";
        std::ostringstream out;

        // Animated brackets
        int bracket_c = 240 + (tick % 4);
        out << "\x1b[38;5;" << bracket_c << "m⟨\x1b[0m";
        out << "\x1b[38;5;" << color << "m" << text << "\x1b[0m";
        out << "\x1b[38;5;" << bracket_c << "m⟩\x1b[0m";

        return out.str();
    }

    // Draw horizontal animated line with glow
    std::string draw_glow_line(int width, int color, int tick) const {
        if (!u8_ok_ || width < 1) return "";
        std::ostringstream out;

        // Traveling glow effect
        int glow_pos = (tick * 3) % width;

        for (int i = 0; i < width; ++i) {
            int dist = std::abs(i - glow_pos);
            int c;
            if (dist == 0) {
                c = 231;  // White center
            } else if (dist < 3) {
                c = color + (3 - dist) * 2;
                if (c > 255) c = 255;
            } else {
                c = color;
            }
            out << "\x1b[38;5;" << c << "m─\x1b[0m";
        }
        return out.str();
    }

    // =========================================================================
    // SPLASH SCREEN - ULTRA PROFESSIONAL sync display with premium animations
    // =========================================================================

    // Animated spinner characters (multiple styles) - enhanced with more frames
    // Uses ASCII for legacy terminals (PowerShell 5, cmd.exe)
    static const char* splash_spinner(int tick, bool u8) {
        if (u8) {
            // Premium 12-frame braille spinner for ultra-smooth animation
            static const char* frames[] = {"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷", "⠿", "⡿", "⣟", "⣯"};
            return frames[tick % 12];
        } else {
            // ASCII spinner that works in all terminals
            static const char* frames[] = {"[|]", "[/]", "[-]", "[\\]"};
            return frames[tick % 4];
        }
    }

    // Cyber matrix-style rain effect for splash background (ASCII-safe)
    static std::string cyber_rain(int width, int tick, bool vt) {
        if (!vt) return "";
        std::string out;
        // ASCII-safe characters only for maximum compatibility
        static const char* chars[] = {"0", "1", "o", "x", ".", " ", " ", " "};
        for (int i = 0; i < width; ++i) {
            int phase = (tick + i * 3) % 8;
            int brightness = (tick + i * 7) % 6;
            if (brightness < 2) {
                out += "\x1b[38;5;22m";  // Dark green
            } else if (brightness < 4) {
                out += "\x1b[38;5;28m";  // Medium green
            } else {
                out += "\x1b[38;5;46m";  // Bright green
            }
            out += chars[phase];
        }
        out += "\x1b[0m";
        return out;
    }

    // Animated blockchain visualization
    static std::string blockchain_anim(int tick, bool u8, bool vt) {
        if (!vt) return "[===CHAIN===]";

        if (!u8) {
            // ASCII animation for legacy terminals
            std::string out = "\x1b[36m[";
            static const char* ascii_blocks[] = {"#", "O", "o", "#", "O", "o"};
            for (int i = 0; i < 7; ++i) {
                int phase = (tick + i * 2) % 6;
                int color = (phase < 3) ? 36 : 96;  // Cyan / bright cyan
                out += "\x1b[" + std::to_string(color) + "m";
                out += ascii_blocks[phase];
                if (i < 6) out += "-";
            }
            out += "\x1b[36m]\x1b[0m";
            return out;
        }

        std::string out;
        // Animated chain with flowing blocks
        static const char* blocks[] = {"░", "▒", "▓", "█", "▓", "▒"};
        static const char* links[] = {"─", "═", "━", "═"};

        out += "\x1b[38;5;39m";  // Bright blue
        out += "⟦";
        for (int i = 0; i < 7; ++i) {
            int phase = (tick + i * 2) % 6;
            // Gradient from cyan to green
            int color = 51 - (i % 4);
            out += "\x1b[38;5;" + std::to_string(color) + "m";
            out += blocks[phase];
            if (i < 6) {
                out += "\x1b[38;5;240m";
                out += links[tick % 4];
            }
        }
        out += "\x1b[38;5;39m⟧\x1b[0m";
        return out;
    }

    // Pulsing glow effect around text
    static std::string glow_text(const std::string& text, int tick, bool vt) {
        if (!vt) return text;
        // Cycle through bright colors for glow effect
        static const int colors[] = {51, 87, 123, 159, 195, 231, 195, 159, 123, 87};
        int color = colors[tick % 10];
        return "\x1b[38;5;" + std::to_string(color) + "m\x1b[1m" + text + "\x1b[0m";
    }

    // Network activity pulse visualization
    static std::string network_pulse(int tick, int peers, bool u8, bool vt) {
        if (!vt) return peers > 0 ? "[CONNECTED]" : "[SEARCHING]";

        std::string out;
        if (peers == 0) {
            // Searching animation
            if (u8) {
                static const char* search[] = {"◜ ", " ◝", " ◞", "◟ "};
                out += "\x1b[38;5;208m";  // Orange
                out += search[tick % 4];
            } else {
                // ASCII animated dots
                static const char* dots[] = {".", "..", "...", ".."};
                out += "\x1b[33m";  // Yellow
                out += dots[tick % 4];
            }
            out += " Searching";
            out += "\x1b[0m";
        } else {
            // Connected with signal strength
            if (u8) {
                static const char* signals[] = {"▁▃▅▇", "▁▃▅█", "▂▄▆█", "▁▃▆█"};
                out += "\x1b[38;5;46m";  // Bright green
                out += signals[tick % 4];
            } else {
                // ASCII signal bars
                static const char* ascii_sig[] = {"[|  ]", "[|| ]", "[|||]", "[|| ]"};
                out += "\x1b[32m";  // Green
                out += ascii_sig[tick % 4];
            }
            out += " " + std::to_string(peers) + " peer" + (peers != 1 ? "s" : "");
            out += "\x1b[0m";
        }
        return out;
    }

    // ULTRA-PREMIUM gradient progress bar with electric glow effect
    std::string splash_progress_bar(int width, double frac, int tick) const {
        if (width < 20) width = 20;
        if (frac < 0.0) frac = 0.0;
        if (frac > 1.0) frac = 1.0;

        int inner = width - 4;  // Room for fancy brackets
        int filled = (int)(frac * inner);

        std::string out;
        out.reserve((size_t)(width + 200));

        if (vt_ok_ && u8_ok_) {
            // PREMIUM: Electric neon progress bar with rainbow gradient
            out += "\x1b[38;5;27m▐\x1b[48;5;235m";  // Left cap with dark bg

            for (int i = 0; i < inner; ++i) {
                if (i < filled) {
                    // Rainbow gradient: blue -> cyan -> green -> yellow
                    double pos = (double)i / (double)inner;
                    int color;
                    if (pos < 0.25) {
                        color = 27 + (int)(pos * 4 * 8);  // Blue to cyan
                    } else if (pos < 0.5) {
                        color = 51 - (int)((pos - 0.25) * 4 * 6);  // Cyan to green
                    } else if (pos < 0.75) {
                        color = 46 + (int)((pos - 0.5) * 4 * 40);  // Green to yellow
                    } else {
                        color = 226 - (int)((pos - 0.75) * 4 * 10);  // Yellow bright
                    }
                    // Add shimmer effect
                    if ((i + tick) % 8 < 2) color = 231;  // White flash
                    out += "\x1b[38;5;" + std::to_string(color) + "m█";
                } else if (i == filled && frac < 1.0) {
                    // Animated glowing leading edge
                    static const char* edge[] = {"░", "▒", "▓", "█", "▓", "▒"};
                    int edge_idx = (tick % 6);
                    out += "\x1b[38;5;231m";  // White glow
                    out += edge[edge_idx];
                } else {
                    // Subtle animated background pattern
                    int pattern_phase = (i + tick/2) % 6;
                    if (pattern_phase == 0) {
                        out += "\x1b[38;5;237m·";
                    } else if (pattern_phase == 3) {
                        out += "\x1b[38;5;238m•";
                    } else {
                        out += "\x1b[38;5;235m ";
                    }
                }
            }
            out += "\x1b[0m\x1b[38;5;27m▌\x1b[0m";  // Right cap

        } else if (vt_ok_) {
            // ANSI colors with ASCII characters for PowerShell 5 compatibility
            // Professional animated gradient using only safe ASCII chars
            out += "\x1b[1;97m[\x1b[0m";
            for (int i = 0; i < inner; ++i) {
                if (i < filled) {
                    // Animated color gradient: blue -> cyan -> green -> yellow
                    double pos = (double)i / (double)inner;
                    int color_code;
                    if (pos < 0.25) color_code = 34;       // Blue
                    else if (pos < 0.5) color_code = 36;   // Cyan
                    else if (pos < 0.75) color_code = 32;  // Green
                    else color_code = 33;                   // Yellow

                    // Add shimmer/pulse effect
                    bool shimmer = ((i + tick) % 6 == 0);
                    if (shimmer) {
                        out += "\x1b[1;97m#\x1b[0m";  // Bright white flash
                    } else {
                        out += "\x1b[1;" + std::to_string(color_code) + "m#\x1b[0m";
                    }
                } else if (i == filled && frac < 1.0) {
                    // Animated leading edge with pulsing effect
                    static const char* edge_chars[] = {".", "o", "O", "o"};
                    out += "\x1b[1;93m" + std::string(edge_chars[tick % 4]) + "\x1b[0m";
                } else {
                    // Background with subtle animation
                    int bg_phase = (i + tick/2) % 4;
                    if (bg_phase == 0) {
                        out += "\x1b[90m.\x1b[0m";
                    } else {
                        out += "\x1b[90m-\x1b[0m";
                    }
                }
            }
            out += "\x1b[1;97m]\x1b[0m";
        } else {
            // Plain ASCII with nice pattern
            out += "[";
            for (int i = 0; i < inner; ++i) {
                if (i < filled) out += "#";
                else if (i == filled && frac < 1.0) out += ">";
                else out += ".";
            }
            out += "]";
        }

        return out;
    }

    // EPIC big percentage display with glow animation
    std::string big_percentage(double pct, int tick) const {
        std::ostringstream o;
        o << std::fixed << std::setprecision(2) << pct << "%";
        std::string pct_str = o.str();

        if (!vt_ok_) return "[ " + pct_str + " ]";

        std::string out;

        // Dynamic color based on progress with pulse effect
        int base_color;
        if (pct >= 99.0) {
            // Complete! Celebratory rainbow flash
            static const int rainbow[] = {46, 226, 208, 201, 51, 46};
            base_color = rainbow[tick % 6];
        } else if (pct >= 75.0) {
            base_color = 46;   // Green
        } else if (pct >= 50.0) {
            base_color = 226;  // Yellow
        } else if (pct >= 25.0) {
            base_color = 214;  // Orange
        } else {
            base_color = 51;   // Cyan
        }

        // Add subtle glow pulse
        bool bright = (tick % 4) < 2;

        // Left bracket - ASCII-safe
        std::string left_bracket = u8_ok_ ? "⟨ " : "[ ";
        std::string right_bracket = u8_ok_ ? " ⟩" : " ]";
        out += "\x1b[38;5;240m" + left_bracket + "\x1b[0m";

        out += "\x1b[38;5;" + std::to_string(base_color) + "m";
        if (bright) out += "\x1b[1m";  // Bold on pulse
        out += pct_str;
        out += "\x1b[0m";

        out += "\x1b[38;5;240m" + right_bracket + "\x1b[0m";

        return out;
    }

    // Get sync status string with cool animated indicators
    std::string get_sync_status(uint64_t blocks_remaining, double sync_pct, uint64_t network_height) const {
        // IMPORTANT: Only show as synced if we actually have network height data
        // and we're truly synchronized (not just at startup with no data)
        bool has_network_data = network_height > 0;
        bool actually_synced = has_network_data && (blocks_remaining == 0 || sync_pct >= 99.9);

        if (!has_network_data) {
            // Still initializing - no network height known yet
            if (vt_ok_) {
                std::string spinner;
                if (u8_ok_) {
                    static const char* init_frames[] = {"◐", "◓", "◑", "◒"};
                    spinner = init_frames[tick_ % 4];
                } else {
                    static const char* ascii_frames[] = {".", "o", "O", "o"};
                    spinner = ascii_frames[tick_ % 4];
                }
                return std::string("\x1b[38;5;214m") + spinner + " Initializing...\x1b[0m";
            }
            return "Initializing...";
        }

        if (actually_synced) {
            if (vt_ok_) {
                std::string check = u8_ok_ ? "✓ " : "[OK] ";
                return std::string("\x1b[38;5;46m\x1b[1m") + check + "BLOCKCHAIN SYNCHRONIZED\x1b[0m";
            }
            return "[OK] BLOCKCHAIN SYNCHRONIZED";
        }

        // Only show time behind if actually behind
        std::string time_behind = fmt_time_behind(sync_last_block_time_);
        if (time_behind == "synced") {
            if (vt_ok_) {
                std::string check = u8_ok_ ? "✓ " : "[OK] ";
                return std::string("\x1b[38;5;46m") + check + "Synchronized\x1b[0m";
            }
            return "[OK] Synchronized";
        }

        if (vt_ok_) {
            std::string clock = u8_ok_ ? "⏳ " : "[~] ";
            return std::string("\x1b[38;5;214m") + clock + time_behind + "\x1b[0m";
        }
        return time_behind;
    }

    void draw_splash(int cols, int rows) {
        std::ostringstream out;

        // Sizing - wider box for epic look
        const int box_width = std::min(84, cols - 4);
        const int start_col = std::max(1, (cols - box_width) / 2);

        // Calculate sync metrics
        uint64_t network_height = sync_network_height_ > 0 ? sync_network_height_ : ibd_target_;
        uint64_t current_height = ibd_cur_;
        uint64_t blocks_remaining = (network_height > current_height) ? (network_height - current_height) : 0;
        double sync_progress = (network_height > 0) ? ((double)current_height / (double)network_height * 100.0) : 0.0;
        if (sync_progress > 100.0) sync_progress = 100.0;
        double frac = sync_progress / 100.0;

        // Peer info
        size_t peer_count = p2p_ ? p2p_->snapshot_peers().size() : 0;

        std::vector<std::string> lines;

        // ===== CYBER BORDER TOP =====
        if (vt_ok_ && u8_ok_) {
            std::string border;
            border += "\x1b[38;5;27m╔";
            for (int i = 0; i < box_width - 2; ++i) {
                int pulse = (tick_ + i) % 12;
                if (pulse < 3) border += "\x1b[38;5;33m";
                else if (pulse < 6) border += "\x1b[38;5;39m";
                else if (pulse < 9) border += "\x1b[38;5;45m";
                else border += "\x1b[38;5;51m";
                border += "═";
            }
            border += "\x1b[38;5;27m╗\x1b[0m";
            lines.push_back(border);
        } else if (vt_ok_) {
            // ANSI colors but ASCII characters
            std::string border;
            border += "\x1b[36m+";
            for (int i = 0; i < box_width - 2; ++i) {
                int pulse = (tick_ + i) % 4;
                if (pulse < 2) border += "\x1b[36m";
                else border += "\x1b[96m";
                border += "=";
            }
            border += "\x1b[36m+\x1b[0m";
            lines.push_back(border);
        } else {
            // Pure ASCII
            lines.push_back("+" + std::string(box_width - 2, '=') + "+");
        }

        // ===== EPIC ASCII ART LOGO =====
        if (u8_ok_ && box_width >= 70) {
            lines.push_back("");
            if (vt_ok_) {
                // Animated gradient logo - cycles through electric colors
                int color_offset = tick_ % 6;
                static const int logo_colors[] = {51, 45, 39, 33, 27, 21};

                auto logo_line = [&](const char* text) {
                    std::string ln = "\x1b[38;5;" + std::to_string(logo_colors[color_offset]) + "m\x1b[1m";
                    ln += text;
                    ln += "\x1b[0m";
                    return ln;
                };

                // BIGGER, more impressive ASCII art
                lines.push_back(logo_line("    ███╗   ███╗██╗ ██████╗ ██████╗  ██████╗  ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗"));
                lines.push_back(logo_line("    ████╗ ████║██║██╔═══██╗██╔══██╗██╔═══██╗██╔════╝██║  ██║██╔══██╗██║████╗  ██║"));
                lines.push_back(logo_line("    ██╔████╔██║██║██║   ██║██████╔╝██║   ██║██║     ███████║███████║██║██╔██╗ ██║"));
                lines.push_back(logo_line("    ██║╚██╔╝██║██║██║▄▄ ██║██╔══██╗██║   ██║██║     ██╔══██║██╔══██║██║██║╚██╗██║"));
                lines.push_back(logo_line("    ██║ ╚═╝ ██║██║╚██████╔╝██║  ██║╚██████╔╝╚██████╗██║  ██║██║  ██║██║██║ ╚████║"));
                lines.push_back(logo_line("    ╚═╝     ╚═╝╚═╝ ╚══▀▀═╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝"));
            } else {
                lines.push_back("  MIQROCHAIN NODE");
            }
        } else if (box_width >= 60) {
            // ASCII-safe logo for PowerShell 5 and other legacy terminals
            lines.push_back("");
            if (vt_ok_) {
                int color_offset = tick_ % 6;
                static const int logo_colors[] = {36, 96, 32, 92, 34, 94};  // Cycling ANSI colors
                std::string col = "\x1b[" + std::to_string(logo_colors[color_offset]) + "m\x1b[1m";
                std::string rst = "\x1b[0m";
                lines.push_back(col + "    M   M  III   QQQ   RRRR    OOO    CCCC  H   H   AAA   III  N   N" + rst);
                lines.push_back(col + "    MM MM   I   Q   Q  R   R  O   O  C      H   H  A   A   I   NN  N" + rst);
                lines.push_back(col + "    M M M   I   Q   Q  RRRR   O   O  C      HHHHH  AAAAA   I   N N N" + rst);
                lines.push_back(col + "    M   M   I   Q  QQ  R  R   O   O  C      H   H  A   A   I   N  NN" + rst);
                lines.push_back(col + "    M   M  III   QQQQ  R   R   OOO    CCCC  H   H  A   A  III  N   N" + rst);
            } else {
                lines.push_back("    M   M  III   QQQ   RRRR    OOO    CCCC  H   H   AAA   III  N   N");
                lines.push_back("    MM MM   I   Q   Q  R   R  O   O  C      H   H  A   A   I   NN  N");
                lines.push_back("    M M M   I   Q   Q  RRRR   O   O  C      HHHHH  AAAAA   I   N N N");
                lines.push_back("    M   M   I   Q  QQ  R  R   O   O  C      H   H  A   A   I   N  NN");
                lines.push_back("    M   M  III   QQQQ  R   R   OOO    CCCC  H   H  A   A  III  N   N");
            }
        } else {
            lines.push_back("");
            lines.push_back(glow_text("MIQROCHAIN", tick_, vt_ok_));
        }

        // ===== TAGLINE WITH BLOCKCHAIN ANIMATION =====
        lines.push_back("");
        if (vt_ok_) {
            std::string tagline = "\x1b[38;5;240m" + std::string(u8_ok_ ? "━━━━━━━━━━━━━" : "-------------") + "\x1b[0m  ";
            tagline += blockchain_anim(tick_, u8_ok_, vt_ok_);
            tagline += "  \x1b[38;5;240m" + std::string(u8_ok_ ? "━━━━━━━━━━━━━" : "-------------") + "\x1b[0m";
            lines.push_back(center_text(tagline, box_width));
        }

        // ===== VERSION & NETWORK INFO =====
        std::ostringstream ver;
        if (vt_ok_) {
            std::string sep = u8_ok_ ? "│" : "|";
            ver << "\x1b[38;5;243mv" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH
                << "\x1b[0m  \x1b[38;5;240m" << sep << "\x1b[0m  \x1b[38;5;75m" << CHAIN_NAME << "\x1b[0m"
                << "  \x1b[38;5;240m" << sep << "\x1b[0m  " << network_pulse(tick_, (int)peer_count, u8_ok_, vt_ok_);
        } else {
            ver << "v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH
                << " | " << CHAIN_NAME << " | " << peer_count << " peers";
        }
        lines.push_back(center_text(ver.str(), box_width));
        lines.push_back("");

        // ===== SYNC STATUS HEADER WITH EFFECTS =====
        // IMPORTANT: Only show as complete if we have network data AND are actually synced
        bool has_network_data = network_height > 0;
        bool actually_complete = has_network_data && sync_progress >= 99.9;

        std::ostringstream header;
        if (actually_complete) {
            // EPIC completion animation - only when TRULY complete
            if (vt_ok_) {
                static const int celebrate_colors[] = {46, 226, 208, 201, 51, 46};
                int c = celebrate_colors[tick_ % 6];
                header << "\x1b[38;5;" << c << "m\x1b[1m";
                header << (u8_ok_ ? "★ ✓ " : "[*] ");
                header << "BLOCKCHAIN SYNCHRONIZED";
                header << (u8_ok_ ? " ✓ ★" : " [*]");
                header << "\x1b[0m";
            } else {
                header << "[OK] BLOCKCHAIN SYNCHRONIZED";
            }
        } else if (!has_network_data) {
            // No network data yet - show initializing state
            if (vt_ok_) {
                header << "\x1b[38;5;214m" << splash_spinner(tick_, u8_ok_) << " \x1b[0m";
                header << "\x1b[38;5;255m\x1b[1mCONNECTING TO NETWORK\x1b[0m";
            } else {
                header << splash_spinner(tick_, u8_ok_) << " CONNECTING TO NETWORK";
            }
        } else {
            // Syncing in progress
            if (vt_ok_) {
                header << "\x1b[38;5;214m" << splash_spinner(tick_, u8_ok_) << " \x1b[0m";
                header << "\x1b[38;5;255m\x1b[1mSYNCHRONIZING BLOCKCHAIN\x1b[0m";
            } else {
                header << splash_spinner(tick_, u8_ok_) << " SYNCHRONIZING BLOCKCHAIN";
            }
        }
        lines.push_back(center_text(header.str(), box_width));
        lines.push_back("");

        // ===== MEGA PROGRESS BAR =====
        int bar_width = box_width - 8;
        lines.push_back("    " + splash_progress_bar(bar_width, frac, tick_));

        // ===== EPIC PERCENTAGE DISPLAY =====
        lines.push_back(center_text(big_percentage(sync_progress, tick_), box_width));
        lines.push_back("");

        // ===== PREMIUM STATS PANEL =====
        std::string panel_top = u8_ok_ ? "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
                                       : "+--------------------------------------------------------------+";
        std::string panel_bot = u8_ok_ ? "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
                                       : "+--------------------------------------------------------------+";
        std::string vbar = u8_ok_ ? "┃" : "|";
        int panel_inner = 62;

        if (vt_ok_) lines.push_back("    \x1b[38;5;240m" + panel_top + "\x1b[0m");
        else lines.push_back("    " + panel_top);

        // Row 1: Block Progress with mini-visualization
        {
            std::ostringstream row;
            row << vbar << " ";
            if (vt_ok_) {
                row << "\x1b[38;5;75m" << (u8_ok_ ? "◆ " : "> ") << "\x1b[38;5;248mBlocks\x1b[0m     ";
                row << "\x1b[38;5;87m" << std::setw(12) << fmt_num(current_height) << "\x1b[0m";
                row << "\x1b[38;5;240m / \x1b[0m";
                row << "\x1b[38;5;255m" << std::setw(12) << fmt_num(network_height) << "\x1b[0m";
            } else {
                row << "> Blocks       " << std::setw(12) << fmt_num(current_height);
                row << " / " << std::setw(12) << fmt_num(network_height);
            }
            std::string r = row.str();
            int vis_len = 45;
            r += std::string(panel_inner - vis_len, ' ') + vbar;
            lines.push_back(std::string("    ") + (vt_ok_ ? "\x1b[38;5;240m" : "") + r + (vt_ok_ ? "\x1b[0m" : ""));
        }

        // Row 2: Remaining
        {
            std::ostringstream row;
            row << vbar << " ";
            if (vt_ok_) {
                row << "\x1b[38;5;214m" << (u8_ok_ ? "◇ " : "> ") << "\x1b[38;5;248mRemaining\x1b[0m  ";
                row << "\x1b[38;5;214m" << std::setw(12) << fmt_num(blocks_remaining) << "\x1b[0m";
                row << " blocks";
            } else {
                row << "> Remaining    " << std::setw(12) << fmt_num(blocks_remaining) << " blocks";
            }
            std::string r = row.str();
            int vis_len = 38;
            r += std::string(panel_inner - vis_len, ' ') + vbar;
            lines.push_back(std::string("    ") + (vt_ok_ ? "\x1b[38;5;240m" : "") + r + (vt_ok_ ? "\x1b[0m" : ""));
        }

        // Row 3: Speed with trend indicator
        {
            std::ostringstream row;
            row << vbar << " ";
            if (vt_ok_) {
                row << "\x1b[38;5;46m" << (u8_ok_ ? "◈ " : "> ") << "\x1b[38;5;248mSpeed\x1b[0m      ";
                if (sync_blocks_per_sec_ > 0.01) {
                    row << "\x1b[38;5;46m" << std::fixed << std::setprecision(1) << sync_blocks_per_sec_ << "\x1b[0m blk/s";
                    // Trend indicator
                    row << "  " << (u8_ok_ ? "↑" : "^");
                } else {
                    row << "\x1b[38;5;240m" << (u8_ok_ ? "◌ measuring..." : "measuring...") << "\x1b[0m";
                }
            } else {
                row << "> Speed        ";
                if (sync_blocks_per_sec_ > 0.01) {
                    row << std::fixed << std::setprecision(1) << sync_blocks_per_sec_ << " blk/s";
                } else {
                    row << "measuring...";
                }
            }
            std::string r = row.str();
            int vis_len = 40;
            r += std::string(panel_inner - vis_len, ' ') + vbar;
            lines.push_back(std::string("    ") + (vt_ok_ ? "\x1b[38;5;240m" : "") + r + (vt_ok_ ? "\x1b[0m" : ""));
        }

        // Row 4: ETA
        {
            std::string eta_str = "Calculating...";
            // Only show complete if we ACTUALLY have data and are synced
            if (actually_complete) {
                eta_str = u8_ok_ ? "✓ Complete" : "Complete";
            } else if (!has_network_data) {
                eta_str = u8_ok_ ? "◌ Awaiting peers..." : "Awaiting peers...";
            } else if (sync_blocks_per_sec_ > 0.01 && blocks_remaining > 0) {
                eta_str = fmt_eta(blocks_remaining, sync_blocks_per_sec_);
            }

            std::ostringstream row;
            row << vbar << " ";
            if (vt_ok_) {
                row << "\x1b[38;5;226m" << (u8_ok_ ? "◉ " : "> ") << "\x1b[38;5;248mETA\x1b[0m        ";
                row << "\x1b[38;5;226m" << eta_str << "\x1b[0m";
            } else {
                row << "> ETA          " << eta_str;
            }
            std::string r = row.str();
            int vis_len = 16 + (int)eta_str.size();
            r += std::string(std::max(1, panel_inner - vis_len), ' ') + vbar;
            lines.push_back(std::string("    ") + (vt_ok_ ? "\x1b[38;5;240m" : "") + r + (vt_ok_ ? "\x1b[0m" : ""));
        }

        if (vt_ok_) lines.push_back("    \x1b[38;5;240m" + panel_bot + "\x1b[0m");
        else lines.push_back("    " + panel_bot);

        lines.push_back("");

        // ===== STATUS LINE =====
        std::ostringstream status;
        status << C_dim() << (u8_ok_ ? "⚡ " : "> ") << "Status: " << C_reset() << get_sync_status(blocks_remaining, sync_progress, network_height);
        lines.push_back(center_text(status.str(), box_width));

        // ===== NETWORK INFO =====
        std::ostringstream net;
        net << C_dim() << (u8_ok_ ? "🌐 " : "@ ") << "Network: " << C_reset();
        if (peer_count == 0) {
            static const char* conn_anim[] = {"scanning", "scanning.", "scanning..", "scanning..."};
            if (vt_ok_) net << "\x1b[38;5;208m" << conn_anim[tick_ % 4] << "\x1b[0m";
            else net << conn_anim[tick_ % 4];
        } else {
            if (vt_ok_) net << "\x1b[38;5;46m" << peer_count << " peer" << (peer_count != 1 ? "s" : "") << " active\x1b[0m";
            else net << peer_count << " peers active";
            if (!ibd_seed_host_.empty()) {
                net << C_dim() << " via " << C_reset();
                if (vt_ok_) net << "\x1b[38;5;75m" << ibd_seed_host_ << "\x1b[0m";
                else net << ibd_seed_host_;
            }
        }
        lines.push_back(center_text(net.str(), box_width));
        lines.push_back("");

        // ===== CYBER BORDER BOTTOM =====
        if (vt_ok_ && u8_ok_) {
            std::string border;
            border += "\x1b[38;5;27m╚";
            for (int i = 0; i < box_width - 2; ++i) {
                int pulse = (tick_ + i) % 12;
                if (pulse < 3) border += "\x1b[38;5;33m";
                else if (pulse < 6) border += "\x1b[38;5;39m";
                else if (pulse < 9) border += "\x1b[38;5;45m";
                else border += "\x1b[38;5;51m";
                border += "═";
            }
            border += "\x1b[38;5;27m╝\x1b[0m";
            lines.push_back(border);
        } else if (vt_ok_) {
            // ANSI colors but ASCII characters
            std::string border;
            border += "\x1b[36m+";
            for (int i = 0; i < box_width - 2; ++i) {
                int pulse = (tick_ + i) % 4;
                if (pulse < 2) border += "\x1b[36m";
                else border += "\x1b[96m";
                border += "=";
            }
            border += "\x1b[36m+\x1b[0m";
            lines.push_back(border);
        } else {
            // Pure ASCII
            lines.push_back("+" + std::string(box_width - 2, '=') + "+");
        }
        lines.push_back("");

        // ===== FOOTER =====
        std::ostringstream foot1;
        if (vt_ok_) {
            foot1 << "\x1b[38;5;240m" << (u8_ok_ ? "⚡ " : "> ");
            foot1 << "Dashboard opens automatically when sync completes\x1b[0m";
        } else {
            foot1 << "> Dashboard opens automatically when sync completes";
        }
        lines.push_back(center_text(foot1.str(), box_width));

        std::ostringstream foot2;
        if (vt_ok_) {
            foot2 << "\x1b[38;5;240m[q] quit  [t] theme  [v] verbose\x1b[0m";
        } else {
            foot2 << "[q] quit  [t] theme  [v] verbose";
        }
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

        // Content
        std::string padding(start_col, ' ');
        for (const auto& line : lines) {
            out << padding << line << "\n";
        }

        // Bottom padding
        int lines_drawn = start_row + content_height;
        for (int i = lines_drawn; i < rows; ++i) out << "\n";

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
    // ULTRA-PROFESSIONAL MAIN DASHBOARD - Premium node monitoring interface
    // =========================================================================

    // Create animated panel header with icon
    std::string panel_header(const std::string& title, const char* icon, int width) const {
        if (!vt_ok_) return "[ " + title + " ]";

        std::string out;
        // Animated glow on panel headers
        int glow = (tick_ % 8 < 4) ? 255 : 250;

        out += "\x1b[38;5;" + std::to_string(glow) + "m\x1b[1m";
        if (u8_ok_ && icon) out += std::string(icon) + " ";
        out += title;
        out += "\x1b[0m";

        return out;
    }

    // Create styled metric line with label and value
    std::string metric_line(const std::string& label, const std::string& value, int color = 0) const {
        std::ostringstream out;
        out << "  ";
        if (vt_ok_) {
            out << "\x1b[38;5;245m" << label << "\x1b[0m ";
            if (color > 0) out << "\x1b[38;5;" << color << "m";
            out << value;
            if (color > 0) out << "\x1b[0m";
        } else {
            out << label << " " << value;
        }
        return out.str();
    }

    // Create animated activity indicator
    std::string activity_dot(bool active) const {
        if (!vt_ok_) return active ? "[*]" : "[ ]";
        if (!active) return "\x1b[38;5;240m○\x1b[0m";

        // Pulsing dot animation
        static const int pulse_colors[] = {46, 47, 48, 49, 48, 47};
        int c = pulse_colors[tick_ % 6];
        return "\x1b[38;5;" + std::to_string(c) + "m●\x1b[0m";
    }

    // Create mini sparkline bar
    std::string mini_bar(double frac, int width) const {
        if (width < 3) width = 3;
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1;

        int filled = (int)(frac * width);
        std::string out;

        if (vt_ok_ && u8_ok_) {
            out += "\x1b[38;5;240m[\x1b[0m";
            for (int i = 0; i < width; ++i) {
                if (i < filled) {
                    // Color gradient
                    int c = 46 + (i * 5 / width);
                    out += "\x1b[38;5;" + std::to_string(c) + "m█\x1b[0m";
                } else {
                    out += "\x1b[38;5;236m░\x1b[0m";
                }
            }
            out += "\x1b[38;5;240m]\x1b[0m";
        } else {
            out += "[";
            for (int i = 0; i < width; ++i) {
                out += (i < filled) ? "#" : ".";
            }
            out += "]";
        }
        return out;
    }

    void draw_once(bool first){
        (void)first;
        std::lock_guard<std::mutex> lk(mu_);
        int cols, rows; term::get_winsize(cols, rows);

        // Enforce minimum dimensions
        if (cols < 120) cols = 120;
        if (rows < 36) rows = 36;

        // Check sync transition
        bool sync_complete = ibd_done_ || (ibd_target_ > 0 && ibd_cur_ >= ibd_target_);

        // Handle transition states
        if (sync_complete && view_mode_ == ViewMode::Splash) {
            if (!splash_transition_done_) {
                // Start Matrix transition animation
                splash_transition_done_ = true;
                if (vt_ok_ && u8_ok_) {
                    init_matrix_transition(cols);
                }
            }

            // Run Matrix transition if active
            if (transition_active_ && vt_ok_ && u8_ok_) {
                draw_matrix_transition(cols, rows);
                return;
            }

            // Transition complete, switch to main
            view_mode_ = ViewMode::Main;
        }

        if (view_mode_ == ViewMode::Splash && !sync_complete) {
            draw_splash(cols, rows);
            return;
        }

        // Layout for ULTIMATE dashboard
        const int rightw = std::max(56, cols / 3);
        const int leftw  = cols - rightw - 3;

        std::vector<std::string> left, right;
        std::ostringstream out;

        // ═══════════════════════════════════════════════════════════════════════
        // ULTIMATE HEADER - Animated premium branding bar with effects
        // ═══════════════════════════════════════════════════════════════════════
        {
            if (vt_ok_ && u8_ok_) {
                // ─── TOP BORDER with rainbow wave animation ───
                out << "\x1b[38;5;27m╔";
                for (int i = 0; i < cols - 2; ++i) {
                    // Rainbow wave effect
                    int wave_phase = (tick_ * 2 + i) % 36;
                    int color;
                    if (wave_phase < 6) color = 21 + wave_phase;       // Blue to cyan
                    else if (wave_phase < 12) color = 27 + (wave_phase - 6) * 2;  // Cyan shades
                    else if (wave_phase < 18) color = 39 + (wave_phase - 12);     // Cyan to green
                    else if (wave_phase < 24) color = 45 - (wave_phase - 18);     // Green back
                    else if (wave_phase < 30) color = 39 - (wave_phase - 24);     // Back to blue
                    else color = 33 - (wave_phase - 30);              // Blue shades
                    out << "\x1b[38;5;" << color << "m═";
                }
                out << "\x1b[38;5;27m╗\x1b[0m\n";

                // ─── LOGO LINE with epic effects ───
                out << "\x1b[38;5;27m║\x1b[0m\x1b[48;5;233m ";

                // Animated diamond logo
                static const int diamond_colors[] = {51, 50, 49, 48, 47, 46, 82, 118, 154, 190};
                int dc = diamond_colors[tick_ % 10];
                out << "\x1b[38;5;" << dc << "m\x1b[1m◆\x1b[0m\x1b[48;5;233m ";

                // MIQROCHAIN with letter-by-letter color wave
                const char* logo = "MIQROCHAIN";
                for (int i = 0; logo[i]; ++i) {
                    int letter_phase = (tick_ + i * 2) % 12;
                    int lc = 45 + (letter_phase < 6 ? letter_phase : 12 - letter_phase);
                    out << "\x1b[38;5;" << lc << "m\x1b[1m" << logo[i];
                }
                out << "\x1b[0m\x1b[48;5;233m";

                // Version badge
                out << "  \x1b[38;5;238m[\x1b[38;5;245mv" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH << "\x1b[38;5;238m]\x1b[0m\x1b[48;5;233m";

                // Animated separator
                out << "  \x1b[38;5;" << (236 + tick_ % 4) << "m│\x1b[0m\x1b[48;5;233m  ";

                // Chain name with glow
                int chain_glow = (tick_ % 8 < 4) ? 75 : 81;
                out << "\x1b[38;5;" << chain_glow << "m" << CHAIN_NAME << "\x1b[0m\x1b[48;5;233m";

                // Separator
                out << "  \x1b[38;5;" << (236 + tick_ % 4) << "m│\x1b[0m\x1b[48;5;233m  ";

                // Animated activity indicator
                out << draw_loading(0, tick_);
                out << "\x1b[48;5;233m";

                // Separator
                out << "  \x1b[38;5;" << (236 + tick_ % 4) << "m│\x1b[0m\x1b[48;5;233m  ";

                // Node state with animated badge
                NodeState show_state = degraded_override_ ? NodeState::Degraded : nstate_;
                switch(show_state) {
                    case NodeState::Starting:
                        out << "\x1b[48;5;94m\x1b[38;5;230m ● STARTING \x1b[0m\x1b[48;5;233m";
                        break;
                    case NodeState::Syncing: {
                        static const int sync_colors[] = {214, 215, 216, 217, 216, 215};
                        out << "\x1b[48;5;" << (sync_colors[tick_ % 6] - 180) << "m\x1b[38;5;" << sync_colors[tick_ % 6] << "m ● SYNCING \x1b[0m\x1b[48;5;233m";
                        break;
                    }
                    case NodeState::Running: {
                        static const int run_colors[] = {46, 47, 48, 49, 48, 47};
                        out << "\x1b[48;5;22m\x1b[38;5;" << run_colors[tick_ % 6] << "m ● RUNNING \x1b[0m\x1b[48;5;233m";
                        break;
                    }
                    case NodeState::Degraded:
                        out << "\x1b[48;5;52m\x1b[38;5;196m ● DEGRADED \x1b[0m\x1b[48;5;233m";
                        break;
                    case NodeState::Quitting:
                        out << "\x1b[48;5;94m\x1b[38;5;214m ● SHUTDOWN \x1b[0m\x1b[48;5;233m";
                        break;
                }

                // Mining badge with fire effect if active
                if (miner_running_badge()) {
                    out << "  \x1b[38;5;" << (236 + tick_ % 4) << "m│\x1b[0m\x1b[48;5;233m  ";
                    static const int fire_c[] = {196, 202, 208, 214, 220, 226};
                    out << "\x1b[48;5;52m\x1b[38;5;" << fire_c[tick_ % 6] << "m ⛏ MINING \x1b[0m\x1b[48;5;233m";
                }

                // Uptime
                uptime_s_ = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start_tp_).count();
                out << "  \x1b[38;5;" << (236 + tick_ % 4) << "m│\x1b[0m\x1b[48;5;233m  ";
                out << "\x1b[38;5;240m⏱ \x1b[38;5;252m" << fmt_uptime(uptime_s_) << "\x1b[0m\x1b[48;5;233m";

                // Live timestamp
                out << "  \x1b[38;5;" << (236 + tick_ % 4) << "m│\x1b[0m\x1b[48;5;233m  ";
                out << draw_timestamp(tick_);
                out << "\x1b[48;5;233m";

                // Pad to end
                int used = 108 + (miner_running_badge() ? 18 : 0);
                int pad = cols - used - 2;
                if (pad > 0) out << std::string(pad, ' ');
                out << "\x1b[0m\x1b[38;5;27m║\x1b[0m\n";

                // ─── DNA HELIX VISUALIZATION LINE ───
                out << "\x1b[38;5;27m║\x1b[0m\x1b[48;5;233m ";
                out << "\x1b[38;5;240m⟦\x1b[0m\x1b[48;5;233m";
                out << draw_dna_helix(cols - 8, tick_);
                out << "\x1b[48;5;233m\x1b[38;5;240m⟧\x1b[0m\x1b[48;5;233m ";
                out << "\x1b[0m\x1b[38;5;27m║\x1b[0m\n";

                // ─── COLUMN DIVIDER ───
                out << "\x1b[38;5;27m╠";
                for (int i = 0; i < leftw - 1; ++i) {
                    int pulse = (tick_ + i) % 12;
                    int c = 24 + (pulse < 6 ? pulse : 12 - pulse);
                    out << "\x1b[38;5;" << c << "m═";
                }
                out << "\x1b[38;5;27m╦";
                for (int i = 0; i < rightw; ++i) {
                    int pulse = (tick_ + i + 6) % 12;
                    int c = 24 + (pulse < 6 ? pulse : 12 - pulse);
                    out << "\x1b[38;5;" << c << "m═";
                }
                out << "\x1b[38;5;27m╣\x1b[0m\n";

            } else {
                // ASCII fallback
                out << "+" << std::string(cols - 2, '=') << "+\n";
                out << "| MIQROCHAIN v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH;
                out << " | " << CHAIN_NAME << " | " << spinner(tick_, false);
                NodeState show_state = degraded_override_ ? NodeState::Degraded : nstate_;
                out << " | ";
                switch(show_state) {
                    case NodeState::Starting: out << "STARTING"; break;
                    case NodeState::Syncing: out << "SYNCING"; break;
                    case NodeState::Running: out << "RUNNING"; break;
                    case NodeState::Degraded: out << "DEGRADED"; break;
                    case NodeState::Quitting: out << "SHUTDOWN"; break;
                }
                if (miner_running_badge()) out << " | MINING";
                out << std::string(20, ' ') << "|\n";
                out << "+" << std::string(leftw - 1, '=') << "+" << std::string(rightw, '=') << "+\n";
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // LEFT COLUMN - System, Node, Blockchain with ULTIMATE visuals
        // ═══════════════════════════════════════════════════════════════════════

        // System Panel - Enhanced with gauges and animations
        {
            left.push_back(draw_section_divider("SYSTEM METRICS", "⚙", leftw - 2, tick_));

            uint64_t rss = get_rss_bytes();

            // Memory gauge with visualization
            std::ostringstream mem_line;
            if (vt_ok_ && u8_ok_) {
                mem_line << "  \x1b[38;5;245m⟨MEM⟩\x1b[0m ";
                mem_line << draw_gauge((double)rss, 512.0 * 1024 * 1024, 18, "",
                                       ColorPalette::SUCCESS, ColorPalette::WARNING, ColorPalette::DANGER, tick_);
                mem_line << " \x1b[38;5;183m" << fmt_bytes(rss) << "\x1b[0m";
            } else {
                mem_line << "  Memory: " << fmt_bytes(rss);
            }
            left.push_back(mem_line.str());

            // Platform info with icons
            std::ostringstream plat;
            if (vt_ok_) {
                plat << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mPlatform\x1b[0m \x1b[38;5;252m";
#ifdef _WIN32
                plat << "Windows";
#elif defined(__APPLE__)
                plat << "macOS";
#else
                plat << "Linux";
#endif
                plat << "\x1b[0m  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mCPUs\x1b[0m \x1b[38;5;87m";
                plat << std::thread::hardware_concurrency() << "\x1b[0m";
            } else {
                plat << "  Platform: Linux  CPUs: " << std::thread::hardware_concurrency();
            }
            left.push_back(plat.str());
            left.push_back("");
        }

        // Network Ports Panel - Enhanced with status indicators
        {
            left.push_back(draw_section_divider("NETWORK PORTS", "🌐", leftw - 2, tick_));

            std::ostringstream ports;
            if (vt_ok_ && u8_ok_) {
                // P2P port with pulse
                ports << "  " << draw_pulse_ring(true, tick_) << " \x1b[38;5;245mP2P\x1b[0m ";
                ports << "\x1b[38;5;46m" << p2p_port_ << "\x1b[0m";

                // RPC port
                ports << "  " << draw_pulse_ring(true, tick_ + 2) << " \x1b[38;5;245mRPC\x1b[0m ";
                ports << "\x1b[38;5;87m" << rpc_port_ << "\x1b[0m";

                // Stratum port if active
                if (auto* ss = g_stratum_server.load()) {
                    ports << "  " << draw_pulse_ring(true, tick_ + 4) << " \x1b[38;5;245mStratum\x1b[0m ";
                    ports << "\x1b[38;5;214m" << ss->get_port() << "\x1b[0m";
                }
            } else {
                ports << "  P2P: " << p2p_port_ << "  RPC: " << rpc_port_;
            }
            left.push_back(ports.str());
            left.push_back("");
        }

        // Sync Status Panel - Enhanced with progress visualization
        {
            uint64_t network_height = sync_network_height_ > 0 ? sync_network_height_ : ibd_target_;
            uint64_t current_height = ibd_cur_;
            bool is_synced = ibd_done_ || (network_height > 0 && current_height >= network_height);

            left.push_back(draw_section_divider("SYNC STATUS", "⚡", leftw - 2, tick_));

            std::ostringstream sync;
            if (vt_ok_ && u8_ok_) {
                if (is_synced) {
                    // Epic synced animation
                    static const int glow_c[] = {46, 47, 48, 49, 50, 51, 50, 49, 48, 47};
                    int gc = glow_c[tick_ % 10];
                    sync << "  \x1b[38;5;" << gc << "m\x1b[1m✓ FULLY SYNCHRONIZED\x1b[0m";
                    sync << "  \x1b[38;5;240m│\x1b[0m  ";
                    sync << draw_blockchain_viz(8, tick_);
                } else if (network_height > 0) {
                    double pct = (double)current_height / (double)network_height * 100.0;

                    // Animated sync indicator
                    sync << "  " << draw_loading(1, tick_) << " ";

                    // Progress percentage with glow
                    int pct_color = (pct < 50) ? ColorPalette::WARNING : ColorPalette::INFO;
                    sync << "\x1b[38;5;" << pct_color << "m\x1b[1m";
                    sync << std::fixed << std::setprecision(1) << pct << "%\x1b[0m  ";

                    // Progress bar
                    sync << draw_gauge(pct, 100.0, 20, "", ColorPalette::INFO, ColorPalette::SUCCESS, ColorPalette::SUCCESS, tick_);
                } else {
                    sync << "  " << draw_loading(2, tick_) << " \x1b[38;5;240mInitializing...\x1b[0m";
                }
            } else {
                sync << "  " << (is_synced ? "[OK] Synced" : "Syncing...");
            }
            left.push_back(sync.str());

            // Block counts
            if (vt_ok_ && network_height > 0) {
                std::ostringstream blocks;
                blocks << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;87m" << fmt_num(current_height) << "\x1b[0m";
                blocks << " \x1b[38;5;240m/\x1b[0m \x1b[38;5;252m" << fmt_num(network_height) << " blocks\x1b[0m";
                left.push_back(blocks.str());
            }
            left.push_back("");
        }

        // Blockchain Panel - Enhanced with advanced visualizations
        {
            left.push_back(draw_section_divider("BLOCKCHAIN", "⛓", leftw - 2, tick_));

            uint64_t height = chain_ ? chain_->height() : 0;
            std::string tip_hex;
            long double tip_diff = 0.0L;
            uint64_t tip_age_s = 0;

            if (chain_) {
                auto t = chain_->tip();
                tip_hex = to_hex(t.hash);
                tip_diff = difficulty_from_bits(hdr_bits(t));
                uint64_t tip_ts = hdr_time(t);
                if (tip_ts) {
                    uint64_t now = (uint64_t)std::time(nullptr);
                    tip_age_s = (now > tip_ts) ? (now - tip_ts) : 0;
                }
            }

            // Height with epic animation
            std::ostringstream h1;
            if (vt_ok_ && u8_ok_) {
                static const int height_colors[] = {51, 50, 49, 48, 47, 46, 82, 118};
                int hc = height_colors[tick_ % 8];
                h1 << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mHeight\x1b[0m     \x1b[38;5;" << hc << "m\x1b[1m#" << fmt_num(height) << "\x1b[0m";
            } else {
                h1 << "  Height: #" << fmt_num(height);
            }
            left.push_back(h1.str());

            // Tip hash with subtle animation
            std::ostringstream h2;
            if (vt_ok_) {
                h2 << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mTip\x1b[0m        \x1b[38;5;240m" << short_hex(tip_hex, 20) << "\x1b[0m";
            } else {
                h2 << "  Tip: " << short_hex(tip_hex, 20);
            }
            left.push_back(h2.str());

            // Tip age with color-coded freshness
            std::ostringstream h3;
            if (vt_ok_ && u8_ok_) {
                h3 << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mTip Age\x1b[0m    ";
                int age_color;
                std::string age_icon;
                if (tip_age_s < 120) {
                    age_color = ColorPalette::SUCCESS;
                    age_icon = "✓";
                } else if (tip_age_s < 600) {
                    age_color = ColorPalette::WARNING;
                    age_icon = "◐";
                } else {
                    age_color = ColorPalette::DANGER;
                    age_icon = "✗";
                }
                h3 << "\x1b[38;5;" << age_color << "m" << age_icon << " " << fmt_uptime(tip_age_s) << "\x1b[0m";
            } else {
                h3 << "  Tip Age: " << fmt_uptime(tip_age_s);
            }
            left.push_back(h3.str());

            // Difficulty with visual indicator
            std::ostringstream h4;
            if (vt_ok_) {
                h4 << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mDifficulty\x1b[0m \x1b[38;5;183m" << fmt_diff(tip_diff) << "\x1b[0m";
            } else {
                h4 << "  Difficulty: " << fmt_diff(tip_diff);
            }
            left.push_back(h4.str());

            // Network hashrate with sparkline
            std::ostringstream h5;
            if (vt_ok_ && u8_ok_) {
                h5 << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mNet H/s\x1b[0m    \x1b[38;5;87m" << fmt_hs(net_hashrate_) << "\x1b[0m";
            } else {
                h5 << "  Net Hashrate: " << fmt_hs(net_hashrate_);
            }
            left.push_back(h5.str());

            // Animated hashrate sparkline
            if (vt_ok_ && u8_ok_ && !net_spark_.empty()) {
                std::ostringstream spark;
                spark << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mTrend\x1b[0m      ";
                spark << draw_sparkline(net_spark_, 24, ColorPalette::INFO, true);
                left.push_back(spark.str());
            }
            left.push_back("");
        }

        // Recent Blocks Panel - Enhanced with block visualization
        {
            left.push_back(draw_section_divider("RECENT BLOCKS", "◆", leftw - 2, tick_));

            // Animated chain visualization
            if (vt_ok_ && u8_ok_) {
                std::ostringstream chain_viz;
                chain_viz << "  " << draw_blockchain_viz(std::min((int)recent_blocks_.size(), 10), tick_);
                left.push_back(chain_viz.str());
            }

            size_t N = recent_blocks_.size();
            if (N > 0) {
                size_t show = std::min<size_t>(4, N);
                for (size_t i = 0; i < show; i++) {
                    const auto& b = recent_blocks_[N - 1 - i];
                    std::ostringstream ln;
                    if (vt_ok_ && u8_ok_) {
                        // Newest block gets glow effect
                        bool newest = (i == 0);
                        if (newest) {
                            static const int glow[] = {51, 50, 49, 48, 47, 46};
                            int gc = glow[tick_ % 6];
                            ln << "  \x1b[38;5;" << gc << "m●\x1b[0m ";
                        } else {
                            ln << "  \x1b[38;5;240m○\x1b[0m ";
                        }
                        ln << "\x1b[38;5;87m#" << b.height << "\x1b[0m ";
                        ln << "\x1b[38;5;240m" << short_hex(b.hash_hex.empty() ? "?" : b.hash_hex, 10) << "\x1b[0m ";
                        ln << "\x1b[38;5;252m" << (b.tx_count ? std::to_string(b.tx_count) : "?") << "tx\x1b[0m";
                    } else {
                        ln << "  #" << b.height << " " << short_hex(b.hash_hex, 8) << " " << b.tx_count << "tx";
                    }
                    left.push_back(ln.str());
                }
            } else {
                left.push_back(vt_ok_ ? "  \x1b[38;5;240m(awaiting blocks)\x1b[0m" : "  (awaiting blocks)");
            }
            left.push_back("");
        }

        // ═══════════════════════════════════════════════════════════════════════
        // RIGHT COLUMN - Peers, Mining, Mempool with ULTIMATE visuals
        // ═══════════════════════════════════════════════════════════════════════

        // Network Peers Panel - Enhanced with topology visualization
        if (p2p_) {
            right.push_back(draw_section_divider("NETWORK PEERS", "📡", rightw - 2, tick_));

            auto peers = p2p_->snapshot_peers();
            size_t peers_n = peers.size();
            size_t verack_ok = 0;
            for (const auto& s : peers) if (s.verack_ok) ++verack_ok;

            // Network topology visualization
            if (vt_ok_ && u8_ok_) {
                std::ostringstream topo;
                topo << "  " << draw_network_topology(rightw - 6, tick_);
                right.push_back(topo.str());
            }

            // Peer stats with signal bars
            std::ostringstream psum;
            if (vt_ok_ && u8_ok_) {
                psum << "  " << draw_signal((int)std::min(peers_n, (size_t)5), 5, tick_) << " ";
                if (peers_n == 0) psum << "\x1b[38;5;196m";
                else if (peers_n < 3) psum << "\x1b[38;5;214m";
                else psum << "\x1b[38;5;46m";
                psum << peers_n << " connected\x1b[0m";
                psum << "  \x1b[38;5;240m│\x1b[0m  \x1b[38;5;46m" << verack_ok << " active\x1b[0m";
            } else {
                psum << "  Connected: " << peers_n << "  Active: " << verack_ok;
            }
            right.push_back(psum.str());

            // Peer list with quality indicators
            if (peers_n > 0) {
                std::stable_sort(peers.begin(), peers.end(), [](const auto& a, const auto& b){
                    return a.verack_ok > b.verack_ok;
                });
                size_t showN = std::min(peers.size(), (size_t)5);
                for (size_t i = 0; i < showN; ++i) {
                    const auto& s = peers[i];
                    std::string ip = s.ip;
                    if (ip.size() > 18) ip = ip.substr(0, 15) + "...";
                    std::ostringstream ln;
                    if (vt_ok_ && u8_ok_) {
                        int quality = calculate_peer_quality(0, 0, s.verack_ok);
                        ln << "  " << draw_pulse_ring(s.verack_ok, tick_ + (int)i);
                        ln << " \x1b[38;5;252m" << std::left << std::setw(18) << ip << "\x1b[0m ";
                        ln << draw_peer_quality(quality, 6);
                    } else {
                        ln << "  " << (s.verack_ok ? "[*]" : "[ ]") << " " << ip;
                    }
                    right.push_back(ln.str());
                }
                if (peers.size() > showN) {
                    right.push_back(vt_ok_ ?
                        "  \x1b[38;5;240m+ " + std::to_string(peers.size() - showN) + " more peers\x1b[0m" :
                        "  + " + std::to_string(peers.size() - showN) + " more");
                }
            }
            right.push_back("");
        }

        // Mining Panel - Enhanced with fire effects and graphs
        {
            right.push_back(draw_section_divider("MINING", "⛏", rightw - 2, tick_));

            bool active = g_miner_stats.active.load();
            double hps = g_miner_stats.hps.load();
            uint64_t threads = g_miner_stats.threads.load();
            uint64_t blocks_mined = g_miner_stats.accepted.load();

            // Fire effect bar when mining
            if (active && vt_ok_ && u8_ok_) {
                std::ostringstream fire;
                fire << "  " << draw_fire_bar(rightw - 6, tick_);
                right.push_back(fire.str());
            }

            // Status with epic indicator
            std::ostringstream m1;
            if (vt_ok_ && u8_ok_) {
                if (mining_gate_available_) {
                    if (active) {
                        static const int mine_c[] = {196, 202, 208, 214, 220, 226};
                        int mc = mine_c[tick_ % 6];
                        m1 << "  \x1b[48;5;52m\x1b[38;5;" << mc << "m ⛏ MINING ACTIVE \x1b[0m";
                        m1 << " \x1b[38;5;240m" << threads << " threads\x1b[0m";
                    } else {
                        m1 << "  " << draw_pulse_ring(false, tick_) << " \x1b[38;5;46mReady to mine\x1b[0m";
                    }
                } else {
                    m1 << "  \x1b[38;5;240m○ Mining unavailable\x1b[0m";
                }
            } else {
                m1 << "  Status: " << (active ? "ACTIVE" : (mining_gate_available_ ? "Available" : "Unavailable"));
            }
            right.push_back(m1.str());

            if (active || blocks_mined > 0) {
                // Hashrate with gauge
                std::ostringstream m2;
                if (vt_ok_ && u8_ok_) {
                    m2 << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mHashrate\x1b[0m \x1b[38;5;87m\x1b[1m" << fmt_hs(hps) << "\x1b[0m";
                } else {
                    m2 << "  Hashrate: " << fmt_hs(hps);
                }
                right.push_back(m2.str());

                // Hashrate sparkline with animation
                if (vt_ok_ && u8_ok_ && !spark_hs_.empty()) {
                    std::ostringstream spark;
                    spark << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mTrend\x1b[0m    ";
                    spark << draw_mining_graph(spark_hs_, 20, 1, tick_);
                    right.push_back(spark.str());
                }

                // Blocks mined with celebration effect
                std::ostringstream m3;
                if (vt_ok_ && u8_ok_) {
                    m3 << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mBlocks\x1b[0m   ";
                    if (blocks_mined > 0) {
                        static const int gold[] = {220, 221, 222, 223, 222, 221};
                        m3 << "\x1b[38;5;" << gold[tick_ % 6] << "m\x1b[1m" << blocks_mined << " found!\x1b[0m";
                    } else {
                        m3 << "\x1b[38;5;240m0 found\x1b[0m";
                    }
                } else {
                    m3 << "  Blocks: " << blocks_mined << " mined";
                }
                right.push_back(m3.str());

                // Efficiency
                if (threads > 0 && vt_ok_) {
                    double eff = hps / threads;
                    std::ostringstream m4;
                    m4 << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mEfficiency\x1b[0m \x1b[38;5;183m" << fmt_hs(eff) << "/thread\x1b[0m";
                    right.push_back(m4.str());
                }
            }
            right.push_back("");
        }

        // Mempool Panel - Enhanced
        if (mempool_) {
            right.push_back(draw_section_divider("MEMPOOL", "📋", rightw - 2, tick_));

            auto stat = mempool_view_fallback(mempool_);
            std::ostringstream mp;
            if (vt_ok_ && u8_ok_) {
                mp << "  " << draw_pulse_ring(stat.count > 0, tick_) << " ";
                mp << "\x1b[38;5;51m" << stat.count << "\x1b[0m \x1b[38;5;245mtransactions\x1b[0m";
                if (stat.bytes) {
                    mp << "  \x1b[38;5;240m│\x1b[0m  \x1b[38;5;183m" << fmt_bytes(stat.bytes) << "\x1b[0m";
                }
            } else {
                mp << "  Transactions: " << stat.count;
            }
            right.push_back(mp.str());
            right.push_back("");
        }

        // Pool Server Panel (if active) - Enhanced
        if (auto* ss = g_stratum_server.load()) {
            right.push_back(draw_section_divider("POOL SERVER", "🏊", rightw - 2, tick_));

            auto stats = ss->get_stats();
            std::ostringstream ps;
            if (vt_ok_ && u8_ok_) {
                ps << "  " << draw_pulse_ring(stats.connected_miners > 0, tick_) << " ";
                ps << "\x1b[38;5;46m" << stats.connected_miners << "\x1b[0m \x1b[38;5;245mminers\x1b[0m";
                ps << "  \x1b[38;5;240m│\x1b[0m  \x1b[38;5;87m" << fmt_hs(stats.pool_hashrate) << "\x1b[0m";
            } else {
                ps << "  Miners: " << stats.connected_miners << "  Hashrate: " << fmt_hs(stats.pool_hashrate);
            }
            right.push_back(ps.str());

            std::ostringstream ps2;
            if (vt_ok_) {
                ps2 << "  \x1b[38;5;240m◆\x1b[0m \x1b[38;5;245mShares\x1b[0m \x1b[38;5;46m" << stats.accepted_shares << "\x1b[0m";
                ps2 << "  \x1b[38;5;240m│\x1b[0m  \x1b[38;5;245mBlocks\x1b[0m \x1b[38;5;226m" << stats.blocks_found << "\x1b[0m";
            } else {
                ps2 << "  Shares: " << stats.accepted_shares << "  Blocks: " << stats.blocks_found;
            }
            right.push_back(ps2.str());
            right.push_back("");
        }

        // Health Panel - Enhanced with visual indicators
        {
            right.push_back(draw_section_divider("NODE HEALTH", "❤", rightw - 2, tick_));

            // Overall health status
            std::ostringstream hp;
            if (vt_ok_ && u8_ok_) {
                bool healthy = (nstate_ == NodeState::Running);
                if (healthy) {
                    static const int pulse_c[] = {46, 47, 48, 49, 48, 47};
                    hp << "  \x1b[38;5;" << pulse_c[tick_ % 6] << "m● ALL SYSTEMS OPERATIONAL\x1b[0m";
                } else {
                    hp << "  \x1b[38;5;214m◐ System initializing...\x1b[0m";
                }
            } else {
                hp << "  Node " << (nstate_ == NodeState::Running ? "operational" : "starting");
            }
            right.push_back(hp.str());

            // Health indicators
            if (vt_ok_ && u8_ok_) {
                std::ostringstream h1;
                h1 << "  " << draw_status("P2P Network", p2p_ && p2p_->snapshot_peers().size() > 0, tick_);
                right.push_back(h1.str());

                std::ostringstream h2;
                h2 << "  " << draw_status("Blockchain", chain_ != nullptr, tick_ + 2);
                right.push_back(h2.str());

                std::ostringstream h3;
                h3 << "  " << draw_status("Mempool", mempool_ != nullptr, tick_ + 4);
                right.push_back(h3.str());
            }

            if (!hot_warning_.empty() && now_ms() - hot_warn_ts_ < 6000) {
                right.push_back(vt_ok_ ? "  \x1b[38;5;214m⚠ " + hot_warning_ + "\x1b[0m" : "  ! " + hot_warning_);
            }
            right.push_back("");
        }

        // Recent TXIDs Panel - Enhanced
        {
            right.push_back(draw_section_divider("RECENT TXs", "📝", rightw - 2, tick_));

            if (recent_txids_.empty()) {
                right.push_back(vt_ok_ ? "  \x1b[38;5;240m(awaiting transactions)\x1b[0m" : "  (no transactions)");
            } else {
                size_t n = std::min<size_t>(recent_txids_.size(), 4);
                for (size_t i = 0; i < n; i++) {
                    std::string txid = short_hex(recent_txids_[recent_txids_.size() - 1 - i], 28);
                    std::ostringstream tx_ln;
                    if (vt_ok_ && u8_ok_) {
                        // Newest TX gets highlight
                        if (i == 0) {
                            static const int tx_c[] = {51, 50, 49, 48, 47, 46};
                            tx_ln << "  \x1b[38;5;" << tx_c[tick_ % 6] << "m●\x1b[0m \x1b[38;5;252m" << txid << "\x1b[0m";
                        } else {
                            tx_ln << "  \x1b[38;5;240m○ " << txid << "\x1b[0m";
                        }
                    } else {
                        tx_ln << "  " << txid;
                    }
                    right.push_back(tx_ln.str());
                }
            }
            right.push_back("");
        }

        // ═══════════════════════════════════════════════════════════════════════
        // RENDER COLUMNS
        // ═══════════════════════════════════════════════════════════════════════

        size_t NL = left.size(), NR = right.size(), N = std::max(NL, NR);
        std::string vert_sep = vt_ok_ ? "\x1b[38;5;27m║\x1b[0m" : "|";

        for (size_t i = 0; i < N; i++) {
            std::string l = (i < NL) ? left[i] : "";
            std::string r = (i < NR) ? right[i] : "";

            // Pad left column
            int l_vis = visible_length(l);
            if (l_vis < leftw - 1) l += std::string(leftw - 1 - l_vis, ' ');

            out << vert_sep << l << vert_sep << r << "\n";
        }

        // ═══════════════════════════════════════════════════════════════════════
        // LOG AREA - Professional styled log display
        // ═══════════════════════════════════════════════════════════════════════

        // Log header bar
        if (vt_ok_ && u8_ok_) {
            out << "\x1b[38;5;27m╠";
            for (int i = 0; i < cols - 2; ++i) out << "═";
            out << "╣\x1b[0m\n";

            out << "\x1b[38;5;27m║\x1b[0m ";
            out << "\x1b[38;5;255m\x1b[1m📜 LOGS\x1b[0m";
            out << "  \x1b[38;5;240m[q]quit [t]theme [p]pause [v]verbose [s]snap [r]reload\x1b[0m";
            out << std::string(cols - 70, ' ');
            out << "\x1b[38;5;27m║\x1b[0m\n";

            out << "\x1b[38;5;27m╠";
            for (int i = 0; i < cols - 2; ++i) out << "─";
            out << "╣\x1b[0m\n";
        } else {
            out << "+" << std::string(cols - 2, '-') << "+\n";
            out << "| LOGS  [q]quit [t]theme [p]pause [v]verbose\n";
            out << "+" << std::string(cols - 2, '-') << "+\n";
        }

        // Calculate remaining space for logs
        int header_lines = (int)N + 6;  // Header + columns + log header
        int footer_lines = 2;
        int log_space = rows - header_lines - footer_lines;
        if (log_space < 4) log_space = 4;
        if (log_space > 20) log_space = 20;

        // Render logs
        int log_start = (int)logs_.size() - log_space;
        if (log_start < 0) log_start = 0;

        int printed = 0;
        for (int i = log_start; i < (int)logs_.size() && printed < log_space; ++i) {
            const auto& line = logs_[i];
            std::string txt = line.txt;
            if ((int)txt.size() > cols - 4) {
                txt = txt.substr(0, cols - 7) + "...";
            }

            if (vt_ok_) {
                out << "\x1b[38;5;27m║\x1b[0m ";
                switch(line.level) {
                    case 2: out << "\x1b[38;5;196m" << txt << "\x1b[0m"; break;
                    case 1: out << "\x1b[38;5;214m" << txt << "\x1b[0m"; break;
                    case 3: out << "\x1b[38;5;240m" << txt << "\x1b[0m"; break;
                    case 4: out << "\x1b[38;5;46m" << txt << "\x1b[0m"; break;
                    case 5: out << "\x1b[38;5;87m" << txt << "\x1b[0m"; break;
                    default: out << "\x1b[38;5;252m" << txt << "\x1b[0m"; break;
                }
                // Pad to edge
                int txt_len = (int)txt.size();
                if (txt_len < cols - 4) out << std::string(cols - 4 - txt_len, ' ');
                out << "\x1b[38;5;27m║\x1b[0m";
            } else {
                out << "| " << txt;
            }
            out << "\n";
            ++printed;
        }

        // Fill remaining log space
        for (int i = printed; i < log_space; ++i) {
            if (vt_ok_) {
                out << "\x1b[38;5;27m║\x1b[0m" << std::string(cols - 2, ' ') << "\x1b[38;5;27m║\x1b[0m\n";
            } else {
                out << "|" << std::string(cols - 2, ' ') << "|\n";
            }
        }

        // Bottom border
        if (vt_ok_ && u8_ok_) {
            out << "\x1b[38;5;27m╚";
            for (int i = 0; i < cols - 2; ++i) {
                int pulse = (tick_ + i) % 16;
                int c = (pulse < 8) ? 27 + pulse : 35 - (pulse - 8);
                out << "\x1b[38;5;" << c << "m═";
            }
            out << "\x1b[38;5;27m╝\x1b[0m\n";
        } else {
            out << "+" << std::string(cols - 2, '=') << "+\n";
        }

        // Write frame
        std::string frame = out.str();
        if (vt_ok_) {
            cw_.write_frame("\x1b[H\x1b[J", frame);
        } else {
            cw_.write_raw(frame);
        }
        std::fflush(stdout);
    }

    // Helper to calculate visible string length (excluding ANSI codes)
    static int visible_length(const std::string& s) {
        int len = 0;
        bool in_escape = false;
        for (char c : s) {
            if (c == '\x1b') in_escape = true;
            else if (in_escape && c == 'm') in_escape = false;
            else if (!in_escape) ++len;
        }
        return len;
    }

private:
    bool enabled_{true};
    bool vt_ok_{true};
    bool u8_ok_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> key_running_{false};
    std::thread thr_, key_thr_;
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

    // Bitcoin Core-like sync tracking
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
    bool        splash_transition_done_{false};  // Track if we've shown transition animation
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
/*                               Miner worker                                   */
// ==================================================================
static uint64_t sum_coinbase_outputs(const Block& b) {
    if (b.txs.empty()) return 0;
    uint64_t s = 0; for (const auto& o : b.txs[0].vout) s += o.value; return s;
}
static void miner_worker(Chain* chain, Mempool* mempool, P2P* p2p,
                         const std::vector<uint8_t> mine_pkh,
                         unsigned threads) {
    g_miner_stats.active.store(true);
    g_miner_stats.threads.store(threads);
    g_miner_stats.start = std::chrono::steady_clock::now();

    std::random_device rd;
    const uint64_t seed =
        uint64_t(std::chrono::high_resolution_clock::now().time_since_epoch().count()) ^
        uint64_t(rd()) ^
        uint64_t(std::hash<std::thread::id>{}(std::this_thread::get_id()));
    std::mt19937_64 gen(seed);

    const size_t kBlockMaxBytes = 900 * 1024;

    while (!global::shutdown_requested.load()) {
        try {
            auto t = chain->tip();
            Transaction cbt; TxIn cin; cin.prev.txid = std::vector<uint8_t>(32, 0); cin.prev.vout = 0;
            cbt.vin.push_back(cin);
            TxOut cbout; cbout.value = chain->subsidy_for_height(t.height + 1);
            if (mine_pkh.size() != 20) {
                log_error(std::string("miner assign pkh fatal: pkh size != 20 (got ") + std::to_string(mine_pkh.size()) + ")");
                std::this_thread::sleep_for(std::chrono::milliseconds(80));
                continue;
            }
            cbout.pkh.resize(20);
            std::memcpy(cbout.pkh.data(), mine_pkh.data(), 20);
            cbt.vout.push_back(cbout);
            cbt.lock_time = static_cast<uint32_t>(t.height + 1);

            const uint32_t ch = static_cast<uint32_t>(t.height + 1);
            const uint32_t now = static_cast<uint32_t>(time(nullptr));
            const uint64_t extraNonce = gen();
            std::vector<uint8_t> tag; tag.reserve(1+4+4+8);
            tag.push_back(0x01);
            tag.push_back(uint8_t(ch      & 0xff)); tag.push_back(uint8_t((ch>>8) & 0xff));
            tag.push_back(uint8_t((ch>>16)& 0xff)); tag.push_back(uint8_t((ch>>24)& 0xff));
            tag.push_back(uint8_t(now      & 0xff)); tag.push_back(uint8_t((now>>8) & 0xff));
            tag.push_back(uint8_t((now>>16)& 0xff)); tag.push_back(uint8_t((now>>24)& 0xff));
            for (int i=0;i<8;i++) tag.push_back(uint8_t((extraNonce >> (8*i)) & 0xff));
            cbt.vin[0].sig = std::move(tag);

            std::vector<Transaction> txs;
            try {
                const size_t coinbase_sz = ser_tx(cbt).size();
                const size_t budget = (kBlockMaxBytes > coinbase_sz) ? (kBlockMaxBytes - coinbase_sz) : 0;
                auto cands = mempool->collect(120000);
                size_t used=0;
                for (auto& tx : cands) {
                    size_t sz = ser_tx(tx).size();
                    if (used + sz > budget) continue;
                    txs.emplace_back(std::move(tx));
                    used += sz;
                    if (used >= budget) break;
                }
            } catch(...) { txs.clear(); }

            Block b;
            try {
                auto last = chain->last_headers(MIQ_RETARGET_INTERVAL);
                uint32_t nb = miq::epoch_next_bits(
                    last, BLOCK_TIME_SECS, GENESIS_BITS,
                    /*next_height=*/ t.height + 1, /*interval=*/ MIQ_RETARGET_INTERVAL);
                b = miq::mine_block(t.hash, nb, cbt, txs, threads);
            } catch (...) {
                log_error("miner mine_block fatal");
                continue;
            }

            try {
                std::string err;
                if (chain->submit_block(b, err)) {
                    // CRITICAL FIX: Notify mempool to remove confirmed transactions
                    if (mempool) {
                        mempool->on_block_connect(b);
                    }
                    std::string miner_addr = "(unknown)";
                    std::string cb_txid_hex = "(n/a)";
                    if (!b.txs.empty()) {
                        cb_txid_hex = to_hex(b.txs[0].txid());
                        if (!b.txs[0].vout.empty() && b.txs[0].vout[0].pkh.size()==20) {
                            miner_addr = base58check_encode(VERSION_P2PKH, b.txs[0].vout[0].pkh);
                        }
                    }
                    int noncb = (int)b.txs.size() - 1;
                    g_miner_stats.accepted.fetch_add(1);
                    g_miner_stats.last_height_ok.store(t.height + 1);
                    g_miner_stats.last_height_rx.store(t.height + 1);

                    BlockSummary bs;
                    bs.height    = t.height + 1;
                    bs.hash_hex  = to_hex(b.block_hash());
                    bs.tx_count  = (uint32_t)b.txs.size();
                    uint64_t coinbase_total = sum_coinbase_outputs(b);
                    uint64_t subsidy = chain->subsidy_for_height(bs.height);
                    if (coinbase_total >= subsidy) { bs.fees = coinbase_total - subsidy; bs.fees_known = true; }
                    bs.miner = miner_addr;
                    g_telemetry.push_block(bs);
                    if (noncb > 0) {
                        std::vector<std::string> txids; txids.reserve((size_t)noncb);
                        for (size_t i=1;i<b.txs.size();++i) txids.push_back(to_hex(b.txs[i].txid()));
                        g_telemetry.push_txids(txids);
                    }

                    log_warn("⛏ MINED block height=" + std::to_string(bs.height)
                             + " txs=" + std::to_string(std::max(0, noncb))
                             + (bs.fees_known ? (" fees=" + std::to_string(bs.fees)) : ""));
                    if (!global::shutdown_requested.load() && p2p) {
                        p2p->announce_block_async(b.block_hash());
                    }
                    // Notify Stratum server of new block for job refresh
                    if (auto* ss = g_stratum_server.load()) {
                        ss->notify_new_block();
                    }
                } else {
                    g_miner_stats.rejected.fetch_add(1);
                    log_warn(std::string("mined block rejected: ") + err);
                }
            } catch (...) {
                log_error("miner submit_block fatal");
            }

        } catch (...) {
            log_error("miner outer fatal");
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
        }
    }
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
      << "  --mine               Enable built-in miner\n"
      << "  --genaddress         Generate new wallet address\n"
      << "  --reindex_utxo       Rebuild UTXO from chain data\n"
      << "  --telemetry          Enable telemetry logging\n"
      << "  --help               Show this help\n"
      << "\n"
      << "Environment:\n"
      << "  MIQ_NO_TUI=1             Disable TUI\n"
      << "  MIQ_MINER_THREADS=N      Miner threads (default: auto)\n"
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
    if(s=="--mine") return true;
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
    {
        std::string reason;
        if (!should_enter_ibd_reason(chain, datadir, &reason)) {
            return true;
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
    const uint64_t kStableOkMs           = 8 * 1000;
    const uint64_t kHandshakeTimeoutMs   = 60 * 1000;
    const uint64_t kSeedNudgeMs          = 10 * 1000;
    const uint64_t kMaxWallMs            = 30 * 60 * 1000;
    const uint64_t t0                    = now_ms();
    uint64_t       lastSeedDialMs        = 0;
    uint64_t       lastProgressMs        = now_ms();
    uint64_t       lastHeight            = chain.height();
    uint64_t       height_at_seed_connect= lastHeight;
    uint32_t       seed_dials            = 0;

    // Make sure we’ve nudged the seed right away.
    if (!we_are_seed) {
        p2p->connect_seed(seed_host_cstr(), P2P_PORT);
        lastSeedDialMs = now_ms();
        ++seed_dials;
    } else {
        log_info(std::string("Seed self-detect: skipping outbound connect to ")
                 + seed_host_cstr() + " (waiting for inbound peers).");
    }
    if (can_tui) tui->set_node_state(TUI::NodeState::Syncing);
    if (tui && can_tui) tui->mark_step_started("Peer handshake (verack)");
    {
        const uint64_t hs_t0 = now_ms();
        const uint64_t handshake_deadline_ms =
            we_are_seed ? (hs_t0 + 5 * 60 * 1000) : (hs_t0 + kHandshakeTimeoutMs);
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
                    tui->set_ibd_progress(chain.height(),
                                          chain.height(),
                                          0, "headers", seed_host_cstr(), false);
                }
                break; // proceed to IBD
            }
            // keep nudging the seed if needed (only if no working connections)
            size_t verack_peers = 0;
            for (const auto& peer : p2p->snapshot_peers()) {
                if (peer.verack_ok) verack_peers++;
            }

            if (!we_are_seed && verack_peers == 0 && (now_ms() - lastSeedDialMs > kSeedNudgeMs)) {
                p2p->connect_seed(seed_host_cstr(), P2P_PORT);
                lastSeedDialMs = now_ms();
                ++seed_dials;
                if (seed_dials >= 5) {
                    auto ips = resolve_host_ip_strings(seed_host_cstr());
                    bool any_public = false;
                    for (auto& ip : ips) { if (!is_private_v4(ip) && !is_loopback_or_linklocal(ip)) { any_public = true; break; } }
                    if (any_public && p2p && p2p->snapshot_peers().empty()){
                        g_assume_seed_hairpin.store(true);
                        we_are_seed = true;
                        log_warn("IBD: assuming SEED mode due to probable NAT hairpin (repeated seed dial fails with 0 peers).");
                        if (tui && can_tui) tui->set_banner("Seed solo mode (hairpin) — waiting for inbound peers…");
                    }
                }
            }

            if (now_ms() > handshake_deadline_ms) {
                if (we_are_seed) {
                    // SOLO-SEED: allow the node to proceed without peers so it can mine the first blocks.
                    log_warn("IBD: seed mode handshake timed out — entering SOLO-SEED mode (no peers yet).");
                    if (tui && can_tui) {
                        tui->mark_step_ok("Peer handshake (verack)");
                        tui->set_banner("Seed solo mode: no peers yet — mining unlocked.");
                        tui->set_ibd_progress(chain.height(), chain.height(), 0, "complete", seed_host_cstr(), true);
                    }
                    return true; // treat IBD as trivially complete to unlock mining
                } else {
                    if (g_assume_seed_hairpin.load()){
                        log_warn("IBD: hairpin seed assumption during handshake — proceeding in SOLO-SEED mode.");
                        if (tui && can_tui) {
                            tui->mark_step_ok("Peer handshake (verack)");
                            tui->set_banner("Seed solo mode (hairpin) — mining unlocked.");
                            tui->set_ibd_progress(chain.height(), chain.height(), 0, "complete", seed_host_cstr(), true);
                        }
                        return true;
                    }
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

    while (!global::shutdown_requested.load()) {
        // Hard wall clock timeout
        if (now_ms() - t0 > kMaxWallMs) { out_err = "IBD timeout (no completion within time budget)"; break; }

        // Ensure we periodically re-nudge the seed if peer count is low.
        size_t peers = p2p->snapshot_peers().size();
        size_t verack_peers = 0;
        for (const auto& peer : p2p->snapshot_peers()) {
            if (peer.verack_ok) verack_peers++;
        }

        // Only nudge if we have no working connections (verack_ok peers)
        if (!we_are_seed && verack_peers == 0 && now_ms() - lastSeedDialMs > kSeedNudgeMs) {
            p2p->connect_seed(seed_host_cstr(), P2P_PORT);
            lastSeedDialMs = now_ms();
            ++seed_dials;
        }

        // Early no-peer failure
        const uint64_t no_peer_budget =
            we_are_seed ? (5 * 60 * 1000) : kNoPeerTimeoutMs;
        if (peers == 0 && now_ms() - t0 > no_peer_budget) {
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
            if (tui && can_tui) {
                tui->set_ibd_progress(cur, cur, discovered, stage, seed_host_cstr(), false);
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

        // Check "synced" state and require short stability window
        std::string why;
        if (compute_sync_gate(chain, p2p, why)) {
            const uint64_t okStart = now_ms();
            bool stable = true;
            while (now_ms() - okStart < kStableOkMs) {
                std::this_thread::sleep_for(200ms);
                if (!compute_sync_gate(chain, p2p, why)) { stable = false; break; }
            }
            if (stable) {
            if (tui && can_tui) {
                    tui->set_ibd_progress(chain.height(),
                                          chain.height(),
                                          (chain.height() >= height_at_seed_connect ? (chain.height() - height_at_seed_connect) : 0),
                                          "complete", seed_host_cstr(), true);
                }
                return true;
            }
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
                    if (tui && can_tui) tui->set_node_state(TUI::NodeState::Running);
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
    bool genaddr=false, buildtx=false, mine_flag=false, flag_reindex_utxo=false;
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
        } else if(a=="--mine"){ mine_flag = true;
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
        if (can_tui) tui.mark_step_ok("Initialize mempool & RPC");

        P2P p2p(chain);
        p2p.set_inflight_caps(256, 128);
        p2p.set_datadir(cfg.datadir);
        p2p.set_mempool(&mempool);
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
        if (can_tui) tui.mark_step_started("Start IBD monitor");
        start_ibd_monitor(&chain, &p2p);
        if (can_tui) tui.mark_step_ok("Start IBD monitor");

        // =====================================================================
        // NEW STEP: IBD sync phase (smart start/finish, surfaces real error)
        // =====================================================================
        if (can_tui) {
            // Only show what is known at start; no estimated future height.
            tui.set_ibd_progress(chain.height(), chain.height(), 0, "headers", seed_host_cstr(), false);
        }
        if (can_tui) tui.mark_step_started("IBD sync phase");
        std::string ibd_err;
        bool ibd_ok = perform_ibd_sync(chain, cfg.no_p2p ? nullptr : &p2p, cfg.datadir, can_tui, &tui, ibd_err);
        if (ibd_ok) {
            if (can_tui) {
                tui.mark_step_ok("IBD sync phase");
                tui.set_banner("Synced");
                tui.set_node_state(TUI::NodeState::Running);
                tui.set_mining_gate(true, "");
            }
            log_info("IBD sync completed successfully.");
        } else {
            if (solo_seed_mode(cfg.no_p2p ? nullptr : &p2p)) {
                // Bootstrap solo: treat as OK so local mining can proceed.
                if (can_tui) {
                    tui.mark_step_ok("IBD sync phase");
                    tui.set_banner("Seed solo mode — no peers yet. Mining enabled.");
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
            if (can_tui) { tui.mark_step_ok("Start RPC server"); tui.mark_step_ok("RPC ready"); }
        } else if (can_tui) {
            tui.mark_step_ok("Start RPC server");
            tui.mark_step_ok("RPC ready");
            rpc_ok = true;
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

            // Set reward address from mining_address config
            if (!cfg.mining_address.empty()) {
                uint8_t ver = 0;
                std::vector<uint8_t> payload;
                if (base58check_decode(cfg.mining_address, ver, payload) &&
                    ver == VERSION_P2PKH && payload.size() == 20) {
                    stratum_server->set_reward_address(payload);
                } else {
                    log_warn("Invalid mining_address for Stratum; pool coinbase will use empty PKH");
                }
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

        // Prepare built-in miner (address prompt), but DO NOT start until synced.
        unsigned thr_count = 0;
        std::vector<uint8_t> mine_pkh;
        bool miner_spawned = false;
        bool miner_armed   = false;

        if (mine_flag) {
            if (cfg.miner_threads) thr_count = cfg.miner_threads;
            if (thr_count == 0) {
                if (const char* s = std::getenv("MIQ_MINER_THREADS")) {
                    char* end = nullptr; long v = std::strtol(s, &end, 10);
                    if (end != s && v > 0 && v <= 256) thr_count = (unsigned)v;
                }
            }
            if (thr_count == 0) thr_count = std::max(1u, std::thread::hardware_concurrency());

            // First try to use mining_address from config file
            std::string addr = cfg.mining_address;

            // If no config address, try interactive prompt (only if TTY available)
            if (addr.empty() && MIQ_ISATTY()) {
                std::cout << "Enter P2PKH Base58 address to mine to (will start when synced; empty to cancel): ";
                std::getline(std::cin, addr);
                trim_inplace(addr);
            }

            if (!addr.empty()) {
                uint8_t ver=0; std::vector<uint8_t> payload;
                if (base58check_decode(addr, ver, payload) && ver==VERSION_P2PKH && payload.size()==20) {
                    mine_pkh = payload;
                    g_miner_address_b58 = addr;
                    miner_armed = true;
                    log_info("Miner armed; waiting for node to finish syncing before start.");
                } else {
                    log_error("Invalid mining address; built-in miner disabled.");
                }
            } else {
                if (cfg.mining_address.empty() && !MIQ_ISATTY()) {
                    log_info("No mining address in config and no TTY available; built-in miner disabled.");
                } else {
                    log_info("No address entered; built-in miner disabled.");
                }
            }
        } else {
            log_info("Miner not started (use external miner or pass --mine).");
        }

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
            }

            // Sync gate & mining availability
            {
                std::string why;
                bool synced = compute_sync_gate(chain, &p2p, why);
                if (can_tui) tui.set_mining_gate(synced, synced ? "" : why);

                if (synced && miner_armed && !miner_spawned) {
                    // Start miner now
                    P2P* p2p_ptr = cfg.no_p2p ? nullptr : &p2p;
                    std::thread th(miner_worker, &chain, &mempool, p2p_ptr, mine_pkh, thr_count);
                    th.detach();
                    miner_spawned = true;
                    log_info("Sync complete — mining can start.");
                    if (can_tui) tui.set_hot_warning("Mining started");
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
            if (!miner_armed && std::getenv("MIQ_MINER_HEARTBEAT") && !g_extminer.alive.load()) degraded = true;
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
