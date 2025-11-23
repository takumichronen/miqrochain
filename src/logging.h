// logging.h - Production-grade logging system for miqrochain
// Bitcoin Core-level structured logging with rotation and filtering
#ifndef MIQ_LOGGING_H
#define MIQ_LOGGING_H

#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <memory>
#include <atomic>
#include <map>
#include <functional>
#include <cstdarg>

namespace miq {
namespace logging {

// =============================================================================
// Log Levels
// =============================================================================

enum class Level {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5,
    OFF = 6
};

inline const char* level_to_string(Level level) {
    switch (level) {
        case Level::TRACE: return "TRACE";
        case Level::DEBUG: return "DEBUG";
        case Level::INFO:  return "INFO";
        case Level::WARN:  return "WARN";
        case Level::ERROR: return "ERROR";
        case Level::FATAL: return "FATAL";
        default:           return "UNKNOWN";
    }
}

inline const char* level_to_color(Level level) {
    switch (level) {
        case Level::TRACE: return "\033[0;37m"; // White
        case Level::DEBUG: return "\033[0;36m"; // Cyan
        case Level::INFO:  return "\033[0;32m"; // Green
        case Level::WARN:  return "\033[0;33m"; // Yellow
        case Level::ERROR: return "\033[0;31m"; // Red
        case Level::FATAL: return "\033[1;31m"; // Bold Red
        default:           return "\033[0m";
    }
}

// =============================================================================
// Log Categories (for filtering)
// =============================================================================

enum class Category : uint32_t {
    NONE        = 0,
    NET         = (1 << 0),
    TOR         = (1 << 1),
    MEMPOOL     = (1 << 2),
    HTTP        = (1 << 3),
    BENCH       = (1 << 4),
    ZMQ         = (1 << 5),
    WALLETDB    = (1 << 6),
    RPC         = (1 << 7),
    ESTIMATEFEE = (1 << 8),
    ADDRMAN     = (1 << 9),
    SELECTCOINS = (1 << 10),
    REINDEX     = (1 << 11),
    CMPCTBLOCK  = (1 << 12),
    RAND        = (1 << 13),
    PRUNE       = (1 << 14),
    PROXY       = (1 << 15),
    MEMPOOLREJ  = (1 << 16),
    LIBEVENT    = (1 << 17),
    COINDB      = (1 << 18),
    QT          = (1 << 19),
    LEVELDB     = (1 << 20),
    VALIDATION  = (1 << 21),
    I2P         = (1 << 22),
    IPC         = (1 << 23),
    LOCK        = (1 << 24),
    UTIL        = (1 << 25),
    BLOCKSTORE  = (1 << 26),
    TXRECONCILIATION = (1 << 27),
    SCAN        = (1 << 28),
    TXPACKAGES  = (1 << 29),
    ALL         = 0xFFFFFFFF
};

inline Category operator|(Category a, Category b) {
    return static_cast<Category>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline Category operator&(Category a, Category b) {
    return static_cast<Category>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline const char* category_to_string(Category cat) {
    switch (cat) {
        case Category::NET:         return "net";
        case Category::TOR:         return "tor";
        case Category::MEMPOOL:     return "mempool";
        case Category::HTTP:        return "http";
        case Category::BENCH:       return "bench";
        case Category::ZMQ:         return "zmq";
        case Category::WALLETDB:    return "walletdb";
        case Category::RPC:         return "rpc";
        case Category::ESTIMATEFEE: return "estimatefee";
        case Category::ADDRMAN:     return "addrman";
        case Category::SELECTCOINS: return "selectcoins";
        case Category::REINDEX:     return "reindex";
        case Category::CMPCTBLOCK:  return "cmpctblock";
        case Category::RAND:        return "rand";
        case Category::PRUNE:       return "prune";
        case Category::PROXY:       return "proxy";
        case Category::MEMPOOLREJ:  return "mempoolrej";
        case Category::LIBEVENT:    return "libevent";
        case Category::COINDB:      return "coindb";
        case Category::QT:          return "qt";
        case Category::LEVELDB:     return "leveldb";
        case Category::VALIDATION:  return "validation";
        case Category::I2P:         return "i2p";
        case Category::IPC:         return "ipc";
        case Category::LOCK:        return "lock";
        case Category::UTIL:        return "util";
        case Category::BLOCKSTORE:  return "blockstore";
        case Category::TXRECONCILIATION: return "txreconciliation";
        case Category::SCAN:        return "scan";
        case Category::TXPACKAGES:  return "txpackages";
        default:                    return "unknown";
    }
}

// =============================================================================
// Log Entry
// =============================================================================

struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    Level level;
    Category category;
    std::string message;
    std::string file;
    int line;
    std::string function;
    std::thread::id thread_id;

    std::string format() const {
        std::ostringstream ss;

        // Timestamp
        auto time_t = std::chrono::system_clock::to_time_t(timestamp);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()) % 1000;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count();

        // Level
        ss << " [" << std::setw(5) << level_to_string(level) << "]";

        // Category
        if (category != Category::NONE) {
            ss << " [" << category_to_string(category) << "]";
        }

        // Thread ID (last 4 digits)
        std::ostringstream tid_ss;
        tid_ss << thread_id;
        std::string tid_str = tid_ss.str();
        if (tid_str.length() > 4) {
            tid_str = tid_str.substr(tid_str.length() - 4);
        }
        ss << " [" << tid_str << "]";

        // Message
        ss << " " << message;

        // Source location (debug only)
        if (!file.empty()) {
            ss << " (" << file << ":" << line << ")";
        }

        return ss.str();
    }

    std::string format_colored() const {
        std::ostringstream ss;
        const char* color = level_to_color(level);
        const char* reset = "\033[0m";

        // Timestamp (dim)
        auto time_t = std::chrono::system_clock::to_time_t(timestamp);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()) % 1000;
        ss << "\033[2m";
        ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count();
        ss << reset;

        // Level (colored)
        ss << " " << color << "[" << std::setw(5) << level_to_string(level) << "]" << reset;

        // Category (cyan)
        if (category != Category::NONE) {
            ss << " \033[0;36m[" << category_to_string(category) << "]\033[0m";
        }

        // Message
        ss << " " << message;

        return ss.str();
    }

    std::string format_json() const {
        std::ostringstream ss;

        auto time_t = std::chrono::system_clock::to_time_t(timestamp);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()) % 1000;

        ss << "{";
        ss << "\"timestamp\":\"";
        ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z\"";
        ss << ",\"level\":\"" << level_to_string(level) << "\"";
        if (category != Category::NONE) {
            ss << ",\"category\":\"" << category_to_string(category) << "\"";
        }
        ss << ",\"message\":\"" << escape_json(message) << "\"";
        if (!file.empty()) {
            ss << ",\"file\":\"" << file << "\"";
            ss << ",\"line\":" << line;
        }
        ss << "}";

        return ss.str();
    }

private:
    static std::string escape_json(const std::string& s) {
        std::string result;
        result.reserve(s.length());
        for (char c : s) {
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:   result += c; break;
            }
        }
        return result;
    }
};

// =============================================================================
// Logger
// =============================================================================

class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    // Configuration
    void set_level(Level level) { min_level_ = level; }
    Level get_level() const { return min_level_; }

    void enable_category(Category cat) {
        enabled_categories_ = enabled_categories_ | cat;
    }

    void disable_category(Category cat) {
        enabled_categories_ = static_cast<Category>(
            static_cast<uint32_t>(enabled_categories_) & ~static_cast<uint32_t>(cat));
    }

    bool is_category_enabled(Category cat) const {
        return (enabled_categories_ & cat) == cat;
    }

    void set_console_output(bool enable) { console_output_ = enable; }
    void set_file_output(bool enable) { file_output_ = enable; }
    void set_json_format(bool enable) { json_format_ = enable; }
    void set_color_output(bool enable) { color_output_ = enable; }
    void set_timestamps(bool enable) { timestamps_ = enable; }
    void set_source_location(bool enable) { source_location_ = enable; }

    // File output
    bool open_log_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (log_file_.is_open()) {
            log_file_.close();
        }
        log_file_.open(path, std::ios::app);
        if (!log_file_.is_open()) {
            return false;
        }
        log_path_ = path;
        return true;
    }

    void close_log_file() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (log_file_.is_open()) {
            log_file_.close();
        }
    }

    // Log rotation
    void rotate_log() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!log_file_.is_open() || log_path_.empty()) return;

        log_file_.close();

        // Rename current log to .old
        std::string old_path = log_path_ + ".old";
        std::remove(old_path.c_str());
        std::rename(log_path_.c_str(), old_path.c_str());

        // Reopen
        log_file_.open(log_path_, std::ios::app);
    }

    // Main logging function
    void log(Level level, Category category, const std::string& message,
             const char* file = nullptr, int line = 0, const char* func = nullptr) {
        if (level < min_level_) return;
        if (category != Category::NONE && !is_category_enabled(category)) return;

        LogEntry entry;
        entry.timestamp = std::chrono::system_clock::now();
        entry.level = level;
        entry.category = category;
        entry.message = message;
        entry.thread_id = std::this_thread::get_id();

        if (source_location_ && file) {
            // Extract just the filename
            std::string filepath(file);
            size_t pos = filepath.find_last_of("/\\");
            entry.file = (pos != std::string::npos) ? filepath.substr(pos + 1) : filepath;
            entry.line = line;
        }
        if (func) {
            entry.function = func;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        // Console output
        if (console_output_) {
            if (color_output_) {
                std::cout << entry.format_colored() << std::endl;
            } else {
                std::cout << entry.format() << std::endl;
            }
        }

        // File output
        if (file_output_ && log_file_.is_open()) {
            if (json_format_) {
                log_file_ << entry.format_json() << std::endl;
            } else {
                log_file_ << entry.format() << std::endl;
            }

            // Check for rotation
            log_lines_++;
            if (log_lines_ >= max_log_lines_) {
                rotate_log();
                log_lines_ = 0;
            }
        }

        // Callbacks
        for (const auto& callback : callbacks_) {
            callback(entry);
        }
    }

    // Formatted logging
    void logf(Level level, Category category, const char* file, int line,
              const char* func, const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);

        char buffer[4096];
        vsnprintf(buffer, sizeof(buffer), fmt, args);

        va_end(args);

        log(level, category, buffer, file, line, func);
    }

    // Add callback for custom log handling
    void add_callback(std::function<void(const LogEntry&)> callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.push_back(callback);
    }

    // Statistics
    uint64_t get_log_count() const { return log_count_.load(); }

private:
    Logger()
        : min_level_(Level::INFO)
        , enabled_categories_(Category::ALL)
        , console_output_(true)
        , file_output_(false)
        , json_format_(false)
        , color_output_(true)
        , timestamps_(true)
        , source_location_(false)
        , log_lines_(0)
        , max_log_lines_(100000) {}

    ~Logger() {
        close_log_file();
    }

    Level min_level_;
    Category enabled_categories_;
    bool console_output_;
    bool file_output_;
    bool json_format_;
    bool color_output_;
    bool timestamps_;
    bool source_location_;

    std::string log_path_;
    std::ofstream log_file_;
    size_t log_lines_;
    size_t max_log_lines_;

    std::atomic<uint64_t> log_count_{0};
    std::vector<std::function<void(const LogEntry&)>> callbacks_;
    std::mutex mutex_;
};

// =============================================================================
// Logging Macros
// =============================================================================

#define MIQ_LOG(level, ...) \
    miq::logging::Logger::instance().log( \
        level, miq::logging::Category::NONE, __VA_ARGS__, __FILE__, __LINE__, __func__)

#define MIQ_LOG_CAT(level, cat, ...) \
    miq::logging::Logger::instance().log( \
        level, cat, __VA_ARGS__, __FILE__, __LINE__, __func__)

#define LOG_TRACE(...) MIQ_LOG(miq::logging::Level::TRACE, __VA_ARGS__)
#define LOG_DEBUG(...) MIQ_LOG(miq::logging::Level::DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  MIQ_LOG(miq::logging::Level::INFO, __VA_ARGS__)
#define LOG_WARN(...)  MIQ_LOG(miq::logging::Level::WARN, __VA_ARGS__)
#define LOG_ERROR(...) MIQ_LOG(miq::logging::Level::ERROR, __VA_ARGS__)
#define LOG_FATAL(...) MIQ_LOG(miq::logging::Level::FATAL, __VA_ARGS__)

// Category-specific macros
#define LOG_NET(level, ...)      MIQ_LOG_CAT(level, miq::logging::Category::NET, __VA_ARGS__)
#define LOG_MEMPOOL(level, ...)  MIQ_LOG_CAT(level, miq::logging::Category::MEMPOOL, __VA_ARGS__)
#define LOG_RPC(level, ...)      MIQ_LOG_CAT(level, miq::logging::Category::RPC, __VA_ARGS__)
#define LOG_VALIDATION(level, ...) MIQ_LOG_CAT(level, miq::logging::Category::VALIDATION, __VA_ARGS__)

// =============================================================================
// Scoped Timer for Performance Logging
// =============================================================================

class ScopedLogTimer {
public:
    ScopedLogTimer(const std::string& name, Level level = Level::DEBUG)
        : name_(name), level_(level) {
        start_ = std::chrono::high_resolution_clock::now();
    }

    ~ScopedLogTimer() {
        auto end = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration<double, std::milli>(end - start_).count();

        std::ostringstream ss;
        ss << name_ << " completed in " << std::fixed << std::setprecision(2) << ms << " ms";

        Logger::instance().log(level_, Category::BENCH, ss.str());
    }

private:
    std::string name_;
    Level level_;
    std::chrono::high_resolution_clock::time_point start_;
};

#define LOG_TIME(name) miq::logging::ScopedLogTimer _timer_##__LINE__(name)

// =============================================================================
// Conditional Logging
// =============================================================================

#define LOG_IF(cond, level, ...) \
    do { if (cond) MIQ_LOG(level, __VA_ARGS__); } while(0)

#define LOG_ONCE(level, ...) \
    do { \
        static bool _logged_##__LINE__ = false; \
        if (!_logged_##__LINE__) { \
            _logged_##__LINE__ = true; \
            MIQ_LOG(level, __VA_ARGS__); \
        } \
    } while(0)

// Every N calls
#define LOG_EVERY_N(n, level, ...) \
    do { \
        static int _count_##__LINE__ = 0; \
        if (++_count_##__LINE__ >= (n)) { \
            _count_##__LINE__ = 0; \
            MIQ_LOG(level, __VA_ARGS__); \
        } \
    } while(0)

} // namespace logging
} // namespace miq

#endif // MIQ_LOGGING_H
