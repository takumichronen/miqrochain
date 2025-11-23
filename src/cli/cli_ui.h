// cli_ui.h - Professional CLI UI components for miqrochain
// Production-grade terminal interface with colors, progress bars, and formatting
#ifndef MIQ_CLI_UI_H
#define MIQ_CLI_UI_H

#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <mutex>
#include <atomic>

namespace miq {
namespace cli {

// =============================================================================
// ANSI Color Codes
// =============================================================================

namespace color {
    // Reset
    constexpr const char* RESET = "\033[0m";

    // Regular colors
    constexpr const char* BLACK = "\033[0;30m";
    constexpr const char* RED = "\033[0;31m";
    constexpr const char* GREEN = "\033[0;32m";
    constexpr const char* YELLOW = "\033[0;33m";
    constexpr const char* BLUE = "\033[0;34m";
    constexpr const char* MAGENTA = "\033[0;35m";
    constexpr const char* CYAN = "\033[0;36m";
    constexpr const char* WHITE = "\033[0;37m";

    // Bold colors
    constexpr const char* BOLD_BLACK = "\033[1;30m";
    constexpr const char* BOLD_RED = "\033[1;31m";
    constexpr const char* BOLD_GREEN = "\033[1;32m";
    constexpr const char* BOLD_YELLOW = "\033[1;33m";
    constexpr const char* BOLD_BLUE = "\033[1;34m";
    constexpr const char* BOLD_MAGENTA = "\033[1;35m";
    constexpr const char* BOLD_CYAN = "\033[1;36m";
    constexpr const char* BOLD_WHITE = "\033[1;37m";

    // Dim colors
    constexpr const char* DIM = "\033[2m";

    // Background colors
    constexpr const char* BG_BLACK = "\033[40m";
    constexpr const char* BG_RED = "\033[41m";
    constexpr const char* BG_GREEN = "\033[42m";
    constexpr const char* BG_YELLOW = "\033[43m";
    constexpr const char* BG_BLUE = "\033[44m";
    constexpr const char* BG_MAGENTA = "\033[45m";
    constexpr const char* BG_CYAN = "\033[46m";
    constexpr const char* BG_WHITE = "\033[47m";

    // Styles
    constexpr const char* BOLD = "\033[1m";
    constexpr const char* UNDERLINE = "\033[4m";
    constexpr const char* BLINK = "\033[5m";
    constexpr const char* REVERSE = "\033[7m";

    // Cursor control
    constexpr const char* CURSOR_UP = "\033[A";
    constexpr const char* CURSOR_DOWN = "\033[B";
    constexpr const char* CLEAR_LINE = "\033[2K";
    constexpr const char* SAVE_CURSOR = "\033[s";
    constexpr const char* RESTORE_CURSOR = "\033[u";
    constexpr const char* HIDE_CURSOR = "\033[?25l";
    constexpr const char* SHOW_CURSOR = "\033[?25h";
}

// =============================================================================
// UI Configuration
// =============================================================================

struct UIConfig {
    bool use_colors = true;
    bool use_unicode = true;
    int terminal_width = 80;
    bool verbose = false;
    bool quiet = false;

    static UIConfig& instance() {
        static UIConfig config;
        return config;
    }
};

// =============================================================================
// Utility Functions
// =============================================================================

inline std::string colorize(const std::string& text, const char* color) {
    if (!UIConfig::instance().use_colors) return text;
    return std::string(color) + text + color::RESET;
}

inline std::string bold(const std::string& text) {
    return colorize(text, color::BOLD);
}

inline std::string success(const std::string& text) {
    return colorize(text, color::GREEN);
}

inline std::string error(const std::string& text) {
    return colorize(text, color::RED);
}

inline std::string warning(const std::string& text) {
    return colorize(text, color::YELLOW);
}

inline std::string info(const std::string& text) {
    return colorize(text, color::CYAN);
}

inline std::string dim(const std::string& text) {
    return colorize(text, color::DIM);
}

// =============================================================================
// Number Formatting
// =============================================================================

inline std::string format_number(uint64_t n) {
    std::string s = std::to_string(n);
    int len = s.length();
    int comma_count = (len - 1) / 3;

    std::string result;
    result.reserve(len + comma_count);

    for (int i = 0; i < len; ++i) {
        if (i > 0 && (len - i) % 3 == 0) {
            result += ',';
        }
        result += s[i];
    }
    return result;
}

inline std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    int unit = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit < 5) {
        size /= 1024.0;
        unit++;
    }

    std::ostringstream ss;
    if (unit == 0) {
        ss << bytes << " " << units[unit];
    } else {
        ss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    }
    return ss.str();
}

inline std::string format_hashrate(double hps) {
    const char* units[] = {"H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"};
    int unit = 0;

    while (hps >= 1000.0 && unit < 6) {
        hps /= 1000.0;
        unit++;
    }

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2) << hps << " " << units[unit];
    return ss.str();
}

inline std::string format_duration(int64_t seconds) {
    if (seconds < 0) seconds = 0;

    int64_t days = seconds / 86400;
    int64_t hours = (seconds % 86400) / 3600;
    int64_t minutes = (seconds % 3600) / 60;
    int64_t secs = seconds % 60;

    std::ostringstream ss;
    if (days > 0) {
        ss << days << "d " << hours << "h";
    } else if (hours > 0) {
        ss << hours << "h " << minutes << "m";
    } else if (minutes > 0) {
        ss << minutes << "m " << secs << "s";
    } else {
        ss << secs << "s";
    }
    return ss.str();
}

inline std::string format_amount(uint64_t satoshis, const std::string& unit = "MIQ") {
    constexpr uint64_t COIN = 100000000;
    uint64_t whole = satoshis / COIN;
    uint64_t frac = satoshis % COIN;

    std::ostringstream ss;
    ss << format_number(whole) << "." << std::setw(8) << std::setfill('0') << frac << " " << unit;
    return ss.str();
}

inline std::string format_percentage(double pct) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2) << pct << "%";
    return ss.str();
}

// =============================================================================
// Progress Bar
// =============================================================================

class ProgressBar {
public:
    ProgressBar(int width = 50, const std::string& prefix = "")
        : width_(width), prefix_(prefix), current_(0), total_(100), started_(false) {}

    void start(uint64_t total, const std::string& msg = "") {
        total_ = total > 0 ? total : 1;
        current_ = 0;
        message_ = msg;
        started_ = true;
        start_time_ = std::chrono::steady_clock::now();
        render();
    }

    void update(uint64_t current, const std::string& msg = "") {
        current_ = std::min(current, total_);
        if (!msg.empty()) message_ = msg;
        render();
    }

    void increment(uint64_t delta = 1) {
        update(current_ + delta);
    }

    void finish(const std::string& msg = "") {
        current_ = total_;
        if (!msg.empty()) message_ = msg;
        render();
        std::cout << std::endl;
        started_ = false;
    }

    void set_message(const std::string& msg) {
        message_ = msg;
        render();
    }

private:
    void render() {
        if (!started_) return;

        double pct = (double)current_ / (double)total_;
        int filled = (int)(pct * width_);

        // Calculate ETA
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - start_time_).count();
        double eta_secs = 0;
        if (current_ > 0 && pct < 1.0) {
            eta_secs = elapsed * (1.0 - pct) / pct;
        }

        std::ostringstream ss;

        // Prefix
        if (!prefix_.empty()) {
            ss << prefix_ << " ";
        }

        // Bar
        ss << "[";
        if (UIConfig::instance().use_unicode) {
            for (int i = 0; i < width_; ++i) {
                if (i < filled) ss << "█";
                else if (i == filled) ss << "▓";
                else ss << "░";
            }
        } else {
            for (int i = 0; i < width_; ++i) {
                if (i < filled) ss << "#";
                else ss << "-";
            }
        }
        ss << "] ";

        // Percentage
        ss << std::fixed << std::setprecision(1) << std::setw(5) << (pct * 100) << "% ";

        // Progress count
        ss << "(" << format_number(current_) << "/" << format_number(total_) << ") ";

        // ETA
        if (current_ < total_ && eta_secs > 0) {
            ss << "ETA: " << format_duration((int64_t)eta_secs) << " ";
        }

        // Message
        if (!message_.empty()) {
            ss << "- " << message_;
        }

        std::string line = ss.str();

        // Clear line and print
        std::cout << "\r" << color::CLEAR_LINE << line << std::flush;
    }

    int width_;
    std::string prefix_;
    std::string message_;
    uint64_t current_;
    uint64_t total_;
    bool started_;
    std::chrono::steady_clock::time_point start_time_;
};

// =============================================================================
// Spinner
// =============================================================================

class Spinner {
public:
    Spinner(const std::string& message = "Loading")
        : message_(message), running_(false), frame_(0) {
        if (UIConfig::instance().use_unicode) {
            frames_ = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
        } else {
            frames_ = {"|", "/", "-", "\\"};
        }
    }

    void start() {
        running_ = true;
        thread_ = std::thread([this]() {
            while (running_) {
                render();
                std::this_thread::sleep_for(std::chrono::milliseconds(80));
            }
        });
    }

    void stop(const std::string& final_msg = "") {
        running_ = false;
        if (thread_.joinable()) {
            thread_.join();
        }

        std::cout << "\r" << color::CLEAR_LINE;
        if (!final_msg.empty()) {
            std::cout << success("✓") << " " << final_msg << std::endl;
        }
    }

    void set_message(const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        message_ = msg;
    }

private:
    void render() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "\r" << color::CLEAR_LINE
                  << info(frames_[frame_ % frames_.size()]) << " " << message_
                  << std::flush;
        frame_++;
    }

    std::string message_;
    std::vector<std::string> frames_;
    std::atomic<bool> running_;
    size_t frame_;
    std::thread thread_;
    std::mutex mutex_;
};

// =============================================================================
// Table
// =============================================================================

class Table {
public:
    enum class Align { LEFT, CENTER, RIGHT };

    Table() = default;

    void add_column(const std::string& header, int width = 0, Align align = Align::LEFT) {
        columns_.push_back({header, width, align});
    }

    void add_row(const std::vector<std::string>& row) {
        rows_.push_back(row);
    }

    void set_header_color(const char* color) {
        header_color_ = color;
    }

    std::string render() const {
        if (columns_.empty()) return "";

        // Calculate column widths
        std::vector<int> widths(columns_.size());
        for (size_t i = 0; i < columns_.size(); ++i) {
            widths[i] = std::max(widths[i], (int)columns_[i].header.length());
            if (columns_[i].width > 0) {
                widths[i] = columns_[i].width;
            }
        }

        for (const auto& row : rows_) {
            for (size_t i = 0; i < row.size() && i < widths.size(); ++i) {
                widths[i] = std::max(widths[i], (int)row[i].length());
            }
        }

        std::ostringstream ss;

        // Header separator
        ss << render_separator(widths, "┌", "─", "┬", "┐") << "\n";

        // Header row
        ss << "│";
        for (size_t i = 0; i < columns_.size(); ++i) {
            std::string cell = align_text(columns_[i].header, widths[i], columns_[i].align);
            if (UIConfig::instance().use_colors && header_color_) {
                ss << " " << header_color_ << cell << color::RESET << " │";
            } else {
                ss << " " << cell << " │";
            }
        }
        ss << "\n";

        // Header/body separator
        ss << render_separator(widths, "├", "─", "┼", "┤") << "\n";

        // Data rows
        for (const auto& row : rows_) {
            ss << "│";
            for (size_t i = 0; i < columns_.size(); ++i) {
                std::string value = (i < row.size()) ? row[i] : "";
                std::string cell = align_text(value, widths[i], columns_[i].align);
                ss << " " << cell << " │";
            }
            ss << "\n";
        }

        // Bottom separator
        ss << render_separator(widths, "└", "─", "┴", "┘") << "\n";

        return ss.str();
    }

    void print() const {
        std::cout << render();
    }

private:
    struct Column {
        std::string header;
        int width;
        Align align;
    };

    static std::string align_text(const std::string& text, int width, Align align) {
        if ((int)text.length() >= width) {
            return text.substr(0, width);
        }

        int padding = width - (int)text.length();
        std::string result;

        switch (align) {
            case Align::LEFT:
                result = text + std::string(padding, ' ');
                break;
            case Align::RIGHT:
                result = std::string(padding, ' ') + text;
                break;
            case Align::CENTER:
                result = std::string(padding / 2, ' ') + text +
                         std::string(padding - padding / 2, ' ');
                break;
        }
        return result;
    }

    std::string render_separator(const std::vector<int>& widths,
                                 const char* left, const char* fill,
                                 const char* mid, const char* right) const {
        std::ostringstream ss;
        ss << left;
        for (size_t i = 0; i < widths.size(); ++i) {
            for (int j = 0; j < widths[i] + 2; ++j) {
                ss << fill;
            }
            if (i < widths.size() - 1) {
                ss << mid;
            }
        }
        ss << right;
        return ss.str();
    }

    std::vector<Column> columns_;
    std::vector<std::vector<std::string>> rows_;
    const char* header_color_ = color::BOLD_CYAN;
};

// =============================================================================
// Box Drawing
// =============================================================================

class Box {
public:
    enum class Style { SINGLE, DOUBLE, ROUNDED, BOLD };

    Box(int width = 60, Style style = Style::SINGLE)
        : width_(width), style_(style) {
        set_style(style);
    }

    void set_title(const std::string& title) {
        title_ = title;
    }

    void add_line(const std::string& line) {
        lines_.push_back(line);
    }

    void add_separator() {
        lines_.push_back("\x00SEP");
    }

    std::string render() const {
        std::ostringstream ss;

        // Top border with title
        ss << chars_.tl;
        if (!title_.empty()) {
            ss << chars_.h << " " << title_ << " ";
            int remaining = width_ - 4 - (int)title_.length();
            for (int i = 0; i < remaining; ++i) ss << chars_.h;
        } else {
            for (int i = 0; i < width_; ++i) ss << chars_.h;
        }
        ss << chars_.tr << "\n";

        // Content lines
        for (const auto& line : lines_) {
            if (line == "\x00SEP") {
                // Separator
                ss << chars_.ml;
                for (int i = 0; i < width_; ++i) ss << chars_.h;
                ss << chars_.mr << "\n";
            } else {
                // Content
                ss << chars_.v << " ";
                int content_width = width_ - 2;
                if ((int)line.length() <= content_width) {
                    ss << line << std::string(content_width - (int)line.length(), ' ');
                } else {
                    ss << line.substr(0, content_width);
                }
                ss << " " << chars_.v << "\n";
            }
        }

        // Bottom border
        ss << chars_.bl;
        for (int i = 0; i < width_; ++i) ss << chars_.h;
        ss << chars_.br << "\n";

        return ss.str();
    }

    void print() const {
        std::cout << render();
    }

private:
    struct BoxChars {
        const char* tl; // top-left
        const char* tr; // top-right
        const char* bl; // bottom-left
        const char* br; // bottom-right
        const char* h;  // horizontal
        const char* v;  // vertical
        const char* ml; // middle-left
        const char* mr; // middle-right
    };

    void set_style(Style style) {
        if (!UIConfig::instance().use_unicode) {
            chars_ = {"+", "+", "+", "+", "-", "|", "+", "+"};
            return;
        }

        switch (style) {
            case Style::SINGLE:
                chars_ = {"┌", "┐", "└", "┘", "─", "│", "├", "┤"};
                break;
            case Style::DOUBLE:
                chars_ = {"╔", "╗", "╚", "╝", "═", "║", "╠", "╣"};
                break;
            case Style::ROUNDED:
                chars_ = {"╭", "╮", "╰", "╯", "─", "│", "├", "┤"};
                break;
            case Style::BOLD:
                chars_ = {"┏", "┓", "┗", "┛", "━", "┃", "┣", "┫"};
                break;
        }
    }

    int width_;
    Style style_;
    std::string title_;
    std::vector<std::string> lines_;
    BoxChars chars_;
};

// =============================================================================
// Status Display
// =============================================================================

class StatusDisplay {
public:
    StatusDisplay() = default;

    void set(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        items_[key] = value;
    }

    void remove(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        items_.erase(key);
    }

    void render() {
        std::lock_guard<std::mutex> lock(mutex_);

        // Save cursor position
        std::cout << color::SAVE_CURSOR;

        // Move to bottom of screen and clear
        for (size_t i = 0; i < items_.size(); ++i) {
            std::cout << color::CURSOR_UP << color::CLEAR_LINE;
        }

        // Print status items
        for (const auto& [key, value] : items_) {
            std::cout << dim(key + ": ") << value << "\n";
        }

        // Restore cursor
        std::cout << color::RESTORE_CURSOR << std::flush;
    }

private:
    std::map<std::string, std::string> items_;
    std::mutex mutex_;
};

// =============================================================================
// ASCII Art Logo
// =============================================================================

inline void print_logo() {
    const char* logo = R"(
  ███╗   ███╗██╗ ██████╗ ██████╗  ██████╗  ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
  ████╗ ████║██║██╔═══██╗██╔══██╗██╔═══██╗██╔════╝██║  ██║██╔══██╗██║████╗  ██║
  ██╔████╔██║██║██║   ██║██████╔╝██║   ██║██║     ███████║███████║██║██╔██╗ ██║
  ██║╚██╔╝██║██║██║▄▄ ██║██╔══██╗██║   ██║██║     ██╔══██║██╔══██║██║██║╚██╗██║
  ██║ ╚═╝ ██║██║╚██████╔╝██║  ██║╚██████╔╝╚██████╗██║  ██║██║  ██║██║██║ ╚████║
  ╚═╝     ╚═╝╚═╝ ╚══▀▀═╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
)";

    if (UIConfig::instance().use_colors) {
        std::cout << color::BOLD_CYAN << logo << color::RESET << std::endl;
    } else {
        std::cout << logo << std::endl;
    }
}

inline void print_mini_logo() {
    if (UIConfig::instance().use_unicode) {
        std::cout << colorize("⛓ ", color::CYAN)
                  << bold("MIQROCHAIN") << " "
                  << dim("v1.0.0") << std::endl;
    } else {
        std::cout << "[*] MIQROCHAIN v1.0.0" << std::endl;
    }
}

// =============================================================================
// Common CLI Patterns
// =============================================================================

inline void print_header(const std::string& title) {
    int width = 60;
    std::string border(width, '=');

    std::cout << "\n" << colorize(border, color::CYAN) << "\n";
    std::cout << "  " << bold(title) << "\n";
    std::cout << colorize(border, color::CYAN) << "\n\n";
}

inline void print_success(const std::string& msg) {
    std::cout << success("✓") << " " << msg << std::endl;
}

inline void print_error(const std::string& msg) {
    std::cout << error("✗") << " " << msg << std::endl;
}

inline void print_warning(const std::string& msg) {
    std::cout << warning("⚠") << " " << msg << std::endl;
}

inline void print_info(const std::string& msg) {
    std::cout << info("ℹ") << " " << msg << std::endl;
}

inline void print_key_value(const std::string& key, const std::string& value, int key_width = 20) {
    std::cout << std::left << std::setw(key_width) << (key + ":") << " " << value << std::endl;
}

inline bool confirm(const std::string& prompt) {
    std::cout << warning("?") << " " << prompt << " [y/N]: ";
    std::string input;
    std::getline(std::cin, input);

    return !input.empty() && (input[0] == 'y' || input[0] == 'Y');
}

// =============================================================================
// Detect Terminal Capabilities
// =============================================================================

inline void detect_terminal_capabilities() {
    // Check if we're in a terminal
    #ifdef _WIN32
    // Windows terminal detection
    // Enable ANSI escape sequences on Windows 10+
    #include <windows.h>
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(hOut, &mode)) {
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        UIConfig::instance().use_colors = true;
    }
    #else
    // Unix terminal detection
    const char* term = std::getenv("TERM");
    if (term && (std::string(term).find("xterm") != std::string::npos ||
                 std::string(term).find("color") != std::string::npos ||
                 std::string(term) == "screen" ||
                 std::string(term) == "linux")) {
        UIConfig::instance().use_colors = true;
    }

    // Check COLORTERM
    const char* colorterm = std::getenv("COLORTERM");
    if (colorterm) {
        UIConfig::instance().use_colors = true;
    }

    // Check NO_COLOR environment variable
    if (std::getenv("NO_COLOR")) {
        UIConfig::instance().use_colors = false;
    }
    #endif
}

} // namespace cli
} // namespace miq

#endif // MIQ_CLI_UI_H
