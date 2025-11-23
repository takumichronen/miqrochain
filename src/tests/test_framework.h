// test_framework.h - Comprehensive Bitcoin Core-style testing framework
// Production-grade testing infrastructure for miqrochain
#ifndef MIQ_TEST_FRAMEWORK_H
#define MIQ_TEST_FRAMEWORK_H

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <map>
#include <atomic>
#include <mutex>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <random>

namespace miq {
namespace test {

// =============================================================================
// Test Result Types
// =============================================================================

enum class TestStatus {
    PASSED,
    FAILED,
    SKIPPED,
    ERROR
};

struct TestResult {
    std::string name;
    TestStatus status;
    std::string message;
    double duration_ms;
    std::string file;
    int line;

    TestResult() : status(TestStatus::PASSED), duration_ms(0.0), line(0) {}
};

struct TestSuiteResult {
    std::string name;
    std::vector<TestResult> results;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    int errors = 0;
    double total_duration_ms = 0.0;

    void add(const TestResult& r) {
        results.push_back(r);
        total_duration_ms += r.duration_ms;
        switch (r.status) {
            case TestStatus::PASSED: passed++; break;
            case TestStatus::FAILED: failed++; break;
            case TestStatus::SKIPPED: skipped++; break;
            case TestStatus::ERROR: errors++; break;
        }
    }

    bool all_passed() const { return failed == 0 && errors == 0; }
    int total() const { return passed + failed + skipped + errors; }
};

// =============================================================================
// Assertion Macros
// =============================================================================

class TestAssertionError : public std::runtime_error {
public:
    std::string file;
    int line;

    TestAssertionError(const std::string& msg, const std::string& f, int l)
        : std::runtime_error(msg), file(f), line(l) {}
};

#define MIQ_TEST_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            throw miq::test::TestAssertionError( \
                std::string("Assertion failed: ") + #cond, __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_ASSERT_MSG(cond, msg) \
    do { \
        if (!(cond)) { \
            throw miq::test::TestAssertionError( \
                std::string(msg) + " (" + #cond + ")", __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_ASSERT_EQ(a, b) \
    do { \
        auto _a = (a); auto _b = (b); \
        if (_a != _b) { \
            std::ostringstream _ss; \
            _ss << "Expected " << #a << " == " << #b << ", got " << _a << " != " << _b; \
            throw miq::test::TestAssertionError(_ss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_ASSERT_NE(a, b) \
    do { \
        auto _a = (a); auto _b = (b); \
        if (_a == _b) { \
            std::ostringstream _ss; \
            _ss << "Expected " << #a << " != " << #b << ", got " << _a << " == " << _b; \
            throw miq::test::TestAssertionError(_ss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_ASSERT_LT(a, b) \
    do { \
        auto _a = (a); auto _b = (b); \
        if (!(_a < _b)) { \
            std::ostringstream _ss; \
            _ss << "Expected " << #a << " < " << #b << ", got " << _a << " >= " << _b; \
            throw miq::test::TestAssertionError(_ss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_ASSERT_LE(a, b) \
    do { \
        auto _a = (a); auto _b = (b); \
        if (!(_a <= _b)) { \
            std::ostringstream _ss; \
            _ss << "Expected " << #a << " <= " << #b << ", got " << _a << " > " << _b; \
            throw miq::test::TestAssertionError(_ss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_ASSERT_GT(a, b) \
    do { \
        auto _a = (a); auto _b = (b); \
        if (!(_a > _b)) { \
            std::ostringstream _ss; \
            _ss << "Expected " << #a << " > " << #b << ", got " << _a << " <= " << _b; \
            throw miq::test::TestAssertionError(_ss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_ASSERT_GE(a, b) \
    do { \
        auto _a = (a); auto _b = (b); \
        if (!(_a >= _b)) { \
            std::ostringstream _ss; \
            _ss << "Expected " << #a << " >= " << #b << ", got " << _a << " < " << _b; \
            throw miq::test::TestAssertionError(_ss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_ASSERT_NEAR(a, b, eps) \
    do { \
        auto _a = (a); auto _b = (b); auto _eps = (eps); \
        if (std::fabs(_a - _b) > _eps) { \
            std::ostringstream _ss; \
            _ss << "Expected |" << #a << " - " << #b << "| <= " << _eps \
                << ", got |" << _a << " - " << _b << "| = " << std::fabs(_a - _b); \
            throw miq::test::TestAssertionError(_ss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_ASSERT_THROWS(expr, exc_type) \
    do { \
        bool _caught = false; \
        try { expr; } \
        catch (const exc_type&) { _caught = true; } \
        catch (...) { \
            throw miq::test::TestAssertionError( \
                "Wrong exception type for: " #expr, __FILE__, __LINE__); \
        } \
        if (!_caught) { \
            throw miq::test::TestAssertionError( \
                "Expected exception not thrown: " #expr, __FILE__, __LINE__); \
        } \
    } while(0)

#define MIQ_TEST_FAIL(msg) \
    throw miq::test::TestAssertionError(msg, __FILE__, __LINE__)

#define MIQ_TEST_SKIP(msg) \
    throw miq::test::TestSkipException(msg)

class TestSkipException : public std::runtime_error {
public:
    explicit TestSkipException(const std::string& msg) : std::runtime_error(msg) {}
};

// =============================================================================
// Test Case Base Class
// =============================================================================

class TestCase {
public:
    virtual ~TestCase() = default;

    // Override these in derived test classes
    virtual void SetUp() {}
    virtual void TearDown() {}
    virtual void Run() = 0;

    std::string name() const { return name_; }
    void set_name(const std::string& n) { name_ = n; }

protected:
    std::string name_;
};

// =============================================================================
// Test Suite
// =============================================================================

class TestSuite {
public:
    using TestFunc = std::function<void()>;

    explicit TestSuite(const std::string& name) : name_(name) {}

    void add_test(const std::string& name, TestFunc func) {
        tests_.push_back({name, func});
    }

    TestSuiteResult run() {
        TestSuiteResult result;
        result.name = name_;

        std::cout << "\n========================================\n";
        std::cout << "  Test Suite: " << name_ << "\n";
        std::cout << "========================================\n";

        for (const auto& test : tests_) {
            TestResult tr;
            tr.name = test.first;

            auto start = std::chrono::high_resolution_clock::now();

            try {
                test.second();
                tr.status = TestStatus::PASSED;
                std::cout << "  [PASS] " << test.first << "\n";
            }
            catch (const TestSkipException& e) {
                tr.status = TestStatus::SKIPPED;
                tr.message = e.what();
                std::cout << "  [SKIP] " << test.first << ": " << e.what() << "\n";
            }
            catch (const TestAssertionError& e) {
                tr.status = TestStatus::FAILED;
                tr.message = e.what();
                tr.file = e.file;
                tr.line = e.line;
                std::cout << "  [FAIL] " << test.first << "\n";
                std::cout << "         " << e.what() << "\n";
                std::cout << "         at " << e.file << ":" << e.line << "\n";
            }
            catch (const std::exception& e) {
                tr.status = TestStatus::ERROR;
                tr.message = e.what();
                std::cout << "  [ERROR] " << test.first << ": " << e.what() << "\n";
            }
            catch (...) {
                tr.status = TestStatus::ERROR;
                tr.message = "Unknown exception";
                std::cout << "  [ERROR] " << test.first << ": Unknown exception\n";
            }

            auto end = std::chrono::high_resolution_clock::now();
            tr.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();

            result.add(tr);
        }

        return result;
    }

private:
    std::string name_;
    std::vector<std::pair<std::string, TestFunc>> tests_;
};

// =============================================================================
// Test Runner
// =============================================================================

class TestRunner {
public:
    static TestRunner& instance() {
        static TestRunner runner;
        return runner;
    }

    void register_suite(std::shared_ptr<TestSuite> suite) {
        suites_.push_back(suite);
    }

    int run_all() {
        std::cout << "\n";
        std::cout << "================================================================\n";
        std::cout << "  MIQROCHAIN COMPREHENSIVE TEST SUITE\n";
        std::cout << "  Bitcoin Core Reliability Level Testing\n";
        std::cout << "================================================================\n";

        auto global_start = std::chrono::high_resolution_clock::now();

        int total_passed = 0;
        int total_failed = 0;
        int total_skipped = 0;
        int total_errors = 0;

        for (auto& suite : suites_) {
            auto result = suite->run();
            total_passed += result.passed;
            total_failed += result.failed;
            total_skipped += result.skipped;
            total_errors += result.errors;
            results_.push_back(result);
        }

        auto global_end = std::chrono::high_resolution_clock::now();
        double total_ms = std::chrono::duration<double, std::milli>(global_end - global_start).count();

        // Print summary
        std::cout << "\n";
        std::cout << "================================================================\n";
        std::cout << "  TEST SUMMARY\n";
        std::cout << "================================================================\n";
        std::cout << "  Passed:  " << total_passed << "\n";
        std::cout << "  Failed:  " << total_failed << "\n";
        std::cout << "  Skipped: " << total_skipped << "\n";
        std::cout << "  Errors:  " << total_errors << "\n";
        std::cout << "  Total:   " << (total_passed + total_failed + total_skipped + total_errors) << "\n";
        std::cout << "  Time:    " << std::fixed << std::setprecision(2) << total_ms << " ms\n";
        std::cout << "================================================================\n";

        if (total_failed == 0 && total_errors == 0) {
            std::cout << "  STATUS: ALL TESTS PASSED\n";
        } else {
            std::cout << "  STATUS: TESTS FAILED\n";
        }
        std::cout << "================================================================\n\n";

        return (total_failed + total_errors > 0) ? 1 : 0;
    }

private:
    TestRunner() = default;
    std::vector<std::shared_ptr<TestSuite>> suites_;
    std::vector<TestSuiteResult> results_;
};

// =============================================================================
// Test Registration Macros
// =============================================================================

#define MIQ_TEST_SUITE(name) \
    static auto _test_suite_##name = std::make_shared<miq::test::TestSuite>(#name); \
    static bool _test_suite_##name##_registered = []() { \
        miq::test::TestRunner::instance().register_suite(_test_suite_##name); \
        return true; \
    }()

#define MIQ_TEST(suite, name) \
    static void _test_##suite##_##name(); \
    static bool _test_##suite##_##name##_registered = []() { \
        _test_suite_##suite->add_test(#name, _test_##suite##_##name); \
        return true; \
    }(); \
    static void _test_##suite##_##name()

// =============================================================================
// Deterministic Random Number Generator for Tests
// =============================================================================

class TestRandom {
public:
    explicit TestRandom(uint64_t seed = 12345) : gen_(seed), seed_(seed) {}

    void reset() { gen_.seed(seed_); }
    void reseed(uint64_t seed) { seed_ = seed; gen_.seed(seed); }

    uint64_t rand64() {
        return std::uniform_int_distribution<uint64_t>()(gen_);
    }

    uint32_t rand32() {
        return std::uniform_int_distribution<uint32_t>()(gen_);
    }

    int rand_range(int min, int max) {
        return std::uniform_int_distribution<int>(min, max)(gen_);
    }

    double rand_double() {
        return std::uniform_real_distribution<double>(0.0, 1.0)(gen_);
    }

    std::vector<uint8_t> rand_bytes(size_t n) {
        std::vector<uint8_t> v(n);
        for (size_t i = 0; i < n; ++i) {
            v[i] = static_cast<uint8_t>(rand32() & 0xFF);
        }
        return v;
    }

    std::string rand_hex(size_t bytes) {
        static const char* hex = "0123456789abcdef";
        std::string s;
        s.reserve(bytes * 2);
        for (size_t i = 0; i < bytes; ++i) {
            uint8_t b = static_cast<uint8_t>(rand32() & 0xFF);
            s += hex[b >> 4];
            s += hex[b & 0xF];
        }
        return s;
    }

private:
    std::mt19937_64 gen_;
    uint64_t seed_;
};

// =============================================================================
// Performance Benchmark Support
// =============================================================================

struct BenchmarkResult {
    std::string name;
    int iterations;
    double total_ms;
    double avg_ms;
    double min_ms;
    double max_ms;
    double ops_per_sec;
};

class Benchmark {
public:
    explicit Benchmark(const std::string& name, int iterations = 1000)
        : name_(name), iterations_(iterations) {}

    template<typename Func>
    BenchmarkResult run(Func&& func) {
        BenchmarkResult result;
        result.name = name_;
        result.iterations = iterations_;
        result.min_ms = std::numeric_limits<double>::max();
        result.max_ms = 0.0;
        result.total_ms = 0.0;

        // Warmup
        for (int i = 0; i < std::min(10, iterations_ / 10); ++i) {
            func();
        }

        // Actual benchmark
        for (int i = 0; i < iterations_; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            func();
            auto end = std::chrono::high_resolution_clock::now();

            double ms = std::chrono::duration<double, std::milli>(end - start).count();
            result.total_ms += ms;
            result.min_ms = std::min(result.min_ms, ms);
            result.max_ms = std::max(result.max_ms, ms);
        }

        result.avg_ms = result.total_ms / iterations_;
        result.ops_per_sec = 1000.0 / result.avg_ms;

        return result;
    }

    static void print_result(const BenchmarkResult& r) {
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "Benchmark: " << r.name << "\n";
        std::cout << "  Iterations: " << r.iterations << "\n";
        std::cout << "  Total:      " << r.total_ms << " ms\n";
        std::cout << "  Average:    " << r.avg_ms << " ms\n";
        std::cout << "  Min:        " << r.min_ms << " ms\n";
        std::cout << "  Max:        " << r.max_ms << " ms\n";
        std::cout << "  Ops/sec:    " << r.ops_per_sec << "\n";
    }

private:
    std::string name_;
    int iterations_;
};

// =============================================================================
// Mock Objects for Testing
// =============================================================================

template<typename T>
class Mock {
public:
    void expect_call(const std::string& method, int times = 1) {
        expected_calls_[method] = times;
        actual_calls_[method] = 0;
    }

    void record_call(const std::string& method) {
        actual_calls_[method]++;
    }

    bool verify() const {
        for (const auto& [method, expected] : expected_calls_) {
            auto it = actual_calls_.find(method);
            int actual = (it != actual_calls_.end()) ? it->second : 0;
            if (actual != expected) {
                return false;
            }
        }
        return true;
    }

    std::string verification_error() const {
        std::ostringstream ss;
        for (const auto& [method, expected] : expected_calls_) {
            auto it = actual_calls_.find(method);
            int actual = (it != actual_calls_.end()) ? it->second : 0;
            if (actual != expected) {
                ss << "Method '" << method << "': expected " << expected
                   << " calls, got " << actual << "\n";
            }
        }
        return ss.str();
    }

private:
    std::map<std::string, int> expected_calls_;
    std::map<std::string, int> actual_calls_;
};

// =============================================================================
// Test Utilities
// =============================================================================

inline std::string hex_encode(const std::vector<uint8_t>& data) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(data.size() * 2);
    for (uint8_t b : data) {
        s += hex[b >> 4];
        s += hex[b & 0xF];
    }
    return s;
}

inline std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> data;
    data.reserve(hex.size() / 2);

    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };

    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        data.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return data;
}

inline bool vectors_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

// Timing utility
class ScopedTimer {
public:
    explicit ScopedTimer(const std::string& name) : name_(name) {
        start_ = std::chrono::high_resolution_clock::now();
    }

    ~ScopedTimer() {
        auto end = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(end - start_).count();
        std::cout << "[TIMER] " << name_ << ": " << std::fixed
                  << std::setprecision(3) << ms << " ms\n";
    }

private:
    std::string name_;
    std::chrono::high_resolution_clock::time_point start_;
};

} // namespace test
} // namespace miq

#endif // MIQ_TEST_FRAMEWORK_H
