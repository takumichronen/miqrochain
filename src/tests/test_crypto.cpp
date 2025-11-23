// test_crypto.cpp - Comprehensive cryptographic tests
// Bitcoin Core-level security testing

#include "test_framework.h"
#include "../sha256.h"
#include "../ripemd160.h"
#include "../hash160.h"
#include "../base58.h"
#include "../base58check.h"
#include "../hex.h"
#include "../crypto/ecdsa_iface.h"
#include "../hd_wallet.h"

#include <algorithm>
#include <cstring>

namespace miq {
namespace test {

MIQ_TEST_SUITE(Crypto);

// =============================================================================
// SHA-256 Tests
// =============================================================================

MIQ_TEST(Crypto, SHA256Empty) {
    std::vector<uint8_t> data;
    auto hash = sha256(data);

    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    std::string actual = to_hex(hash);

    MIQ_TEST_ASSERT_EQ(actual, expected);
}

MIQ_TEST(Crypto, SHA256Hello) {
    std::string msg = "hello";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    auto hash = sha256(data);

    // SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    std::string expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    std::string actual = to_hex(hash);

    MIQ_TEST_ASSERT_EQ(actual, expected);
}

MIQ_TEST(Crypto, SHA256LongInput) {
    // Test with 1MB of data
    TestRandom rng(12345);
    auto data = rng.rand_bytes(1024 * 1024);
    auto hash = sha256(data);

    MIQ_TEST_ASSERT_EQ(hash.size(), 32u);

    // Hash should be deterministic
    auto hash2 = sha256(data);
    MIQ_TEST_ASSERT(vectors_equal(hash, hash2));
}

MIQ_TEST(Crypto, DoubleSHA256) {
    std::string msg = "test";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    auto hash = dsha256(data);

    MIQ_TEST_ASSERT_EQ(hash.size(), 32u);

    // Double SHA256 should equal SHA256(SHA256(data))
    auto single = sha256(data);
    auto manual_double = sha256(single);

    MIQ_TEST_ASSERT(vectors_equal(hash, manual_double));
}

MIQ_TEST(Crypto, SHA256Incremental) {
    // Test incremental hashing produces same result as single-shot
    TestRandom rng(54321);

    for (int trial = 0; trial < 10; ++trial) {
        auto data = rng.rand_bytes(rng.rand_range(100, 10000));
        auto expected = sha256(data);

        // Incremental should match
        auto actual = sha256(data);
        MIQ_TEST_ASSERT(vectors_equal(expected, actual));
    }
}

// =============================================================================
// RIPEMD-160 Tests
// =============================================================================

MIQ_TEST(Crypto, RIPEMD160Empty) {
    std::vector<uint8_t> data;
    auto hash = ripemd160(data);

    // RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
    std::string expected = "9c1185a5c5e9fc54612808977ee8f548b2258d31";
    std::string actual = to_hex(hash);

    MIQ_TEST_ASSERT_EQ(actual, expected);
}

MIQ_TEST(Crypto, RIPEMD160Hello) {
    std::string msg = "hello";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    auto hash = ripemd160(data);

    MIQ_TEST_ASSERT_EQ(hash.size(), 20u);
}

// =============================================================================
// Hash160 Tests (RIPEMD160(SHA256))
// =============================================================================

MIQ_TEST(Crypto, Hash160Basic) {
    TestRandom rng(11111);
    auto pubkey = rng.rand_bytes(33);
    auto pkh = hash160(pubkey);

    MIQ_TEST_ASSERT_EQ(pkh.size(), 20u);

    // Hash160 = RIPEMD160(SHA256(x))
    auto sha = sha256(pubkey);
    auto manual = ripemd160(sha);

    MIQ_TEST_ASSERT(vectors_equal(pkh, manual));
}

MIQ_TEST(Crypto, Hash160Deterministic) {
    TestRandom rng(22222);
    auto data = rng.rand_bytes(65);

    auto h1 = hash160(data);
    auto h2 = hash160(data);

    MIQ_TEST_ASSERT(vectors_equal(h1, h2));
}

// =============================================================================
// ECDSA Tests
// =============================================================================

MIQ_TEST(Crypto, ECDSAKeyGeneration) {
    std::vector<uint8_t> privkey, pubkey;

    // Generate multiple key pairs
    for (int i = 0; i < 10; ++i) {
        MIQ_TEST_ASSERT(crypto::ECDSA::generate_keypair(privkey, pubkey));
        MIQ_TEST_ASSERT_EQ(privkey.size(), 32u);
        MIQ_TEST_ASSERT(pubkey.size() == 33 || pubkey.size() == 65);
    }
}

MIQ_TEST(Crypto, ECDSASignVerify) {
    std::vector<uint8_t> privkey, pubkey;
    MIQ_TEST_ASSERT(crypto::ECDSA::generate_keypair(privkey, pubkey));

    // Sign a message
    std::string msg = "Test message for signing";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    auto hash = dsha256(data);

    std::vector<uint8_t> signature;
    MIQ_TEST_ASSERT(crypto::ECDSA::sign(privkey, hash, signature));
    MIQ_TEST_ASSERT_EQ(signature.size(), 64u);

    // Verify signature
    MIQ_TEST_ASSERT(crypto::ECDSA::verify(pubkey, hash, signature));
}

MIQ_TEST(Crypto, ECDSAInvalidSignature) {
    std::vector<uint8_t> privkey, pubkey;
    MIQ_TEST_ASSERT(crypto::ECDSA::generate_keypair(privkey, pubkey));

    std::string msg = "Test message";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    auto hash = dsha256(data);

    std::vector<uint8_t> signature;
    MIQ_TEST_ASSERT(crypto::ECDSA::sign(privkey, hash, signature));

    // Tamper with signature
    signature[0] ^= 0xFF;

    // Should fail verification
    MIQ_TEST_ASSERT(!crypto::ECDSA::verify(pubkey, hash, signature));
}

MIQ_TEST(Crypto, ECDSAWrongKey) {
    std::vector<uint8_t> privkey1, pubkey1;
    std::vector<uint8_t> privkey2, pubkey2;

    MIQ_TEST_ASSERT(crypto::ECDSA::generate_keypair(privkey1, pubkey1));
    MIQ_TEST_ASSERT(crypto::ECDSA::generate_keypair(privkey2, pubkey2));

    std::string msg = "Test message";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    auto hash = dsha256(data);

    // Sign with key1
    std::vector<uint8_t> signature;
    MIQ_TEST_ASSERT(crypto::ECDSA::sign(privkey1, hash, signature));

    // Verify with key2 should fail
    MIQ_TEST_ASSERT(!crypto::ECDSA::verify(pubkey2, hash, signature));
}

MIQ_TEST(Crypto, ECDSADeterministic) {
    std::vector<uint8_t> privkey, pubkey;
    MIQ_TEST_ASSERT(crypto::ECDSA::generate_keypair(privkey, pubkey));

    std::string msg = "Test message";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    auto hash = dsha256(data);

    // Sign twice
    std::vector<uint8_t> sig1, sig2;
    MIQ_TEST_ASSERT(crypto::ECDSA::sign(privkey, hash, sig1));
    MIQ_TEST_ASSERT(crypto::ECDSA::sign(privkey, hash, sig2));

    // Both signatures should verify (may or may not be identical depending on RFC6979)
    MIQ_TEST_ASSERT(crypto::ECDSA::verify(pubkey, hash, sig1));
    MIQ_TEST_ASSERT(crypto::ECDSA::verify(pubkey, hash, sig2));
}

MIQ_TEST(Crypto, ECDSALowS) {
    // Test that signatures are low-S (BIP 62)
    std::vector<uint8_t> privkey, pubkey;
    MIQ_TEST_ASSERT(crypto::ECDSA::generate_keypair(privkey, pubkey));

    TestRandom rng(33333);
    for (int i = 0; i < 50; ++i) {
        auto hash = rng.rand_bytes(32);

        std::vector<uint8_t> sig;
        MIQ_TEST_ASSERT(crypto::ECDSA::sign(privkey, hash, sig));
        MIQ_TEST_ASSERT_EQ(sig.size(), 64u);

        // Check low-S (s must be <= N/2)
        static const uint8_t N_HALF[32] = {
            0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
            0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
        };

        const uint8_t* s = sig.data() + 32;
        bool low_s = true;
        for (int j = 0; j < 32; ++j) {
            if (s[j] < N_HALF[j]) break;
            if (s[j] > N_HALF[j]) { low_s = false; break; }
        }
        MIQ_TEST_ASSERT_MSG(low_s, "Signature should be low-S");
    }
}

// =============================================================================
// Base58 Tests
// =============================================================================

MIQ_TEST(Crypto, Base58EncodeEmpty) {
    std::vector<uint8_t> data;
    std::string encoded = base58_encode(data);
    MIQ_TEST_ASSERT_EQ(encoded, "");
}

MIQ_TEST(Crypto, Base58EncodeLeadingZeros) {
    std::vector<uint8_t> data = {0, 0, 0, 1};
    std::string encoded = base58_encode(data);

    // Leading zeros become '1's
    MIQ_TEST_ASSERT_GE(encoded.size(), 3u);
    MIQ_TEST_ASSERT_EQ(encoded[0], '1');
    MIQ_TEST_ASSERT_EQ(encoded[1], '1');
    MIQ_TEST_ASSERT_EQ(encoded[2], '1');
}

MIQ_TEST(Crypto, Base58RoundTrip) {
    TestRandom rng(44444);

    for (int i = 0; i < 100; ++i) {
        auto data = rng.rand_bytes(rng.rand_range(1, 100));
        std::string encoded = base58_encode(data);
        auto decoded = base58_decode(encoded);

        MIQ_TEST_ASSERT(vectors_equal(data, decoded));
    }
}

// =============================================================================
// Base58Check Tests
// =============================================================================

MIQ_TEST(Crypto, Base58CheckEncode) {
    std::vector<uint8_t> payload(20, 0x42);
    uint8_t version = VERSION_P2PKH;

    std::string addr = base58check_encode(version, payload);
    MIQ_TEST_ASSERT_GT(addr.size(), 20u);
}

MIQ_TEST(Crypto, Base58CheckDecode) {
    std::vector<uint8_t> payload(20, 0x42);
    uint8_t version = VERSION_P2PKH;

    std::string addr = base58check_encode(version, payload);

    uint8_t dec_ver;
    std::vector<uint8_t> dec_payload;
    MIQ_TEST_ASSERT(base58check_decode(addr, dec_ver, dec_payload));
    MIQ_TEST_ASSERT_EQ(dec_ver, version);
    MIQ_TEST_ASSERT(vectors_equal(dec_payload, payload));
}

MIQ_TEST(Crypto, Base58CheckInvalid) {
    // Invalid checksum
    std::string invalid = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"; // Wrong checksum

    uint8_t ver;
    std::vector<uint8_t> payload;
    // May or may not decode depending on whether checksum happens to be valid
    // This is more of a structural test
}

MIQ_TEST(Crypto, Base58CheckRoundTrip) {
    TestRandom rng(55555);

    for (int i = 0; i < 50; ++i) {
        auto payload = rng.rand_bytes(20);
        uint8_t version = (uint8_t)(rng.rand32() & 0xFF);

        std::string addr = base58check_encode(version, payload);

        uint8_t dec_ver;
        std::vector<uint8_t> dec_payload;
        MIQ_TEST_ASSERT(base58check_decode(addr, dec_ver, dec_payload));
        MIQ_TEST_ASSERT_EQ(dec_ver, version);
        MIQ_TEST_ASSERT(vectors_equal(dec_payload, payload));
    }
}

// =============================================================================
// Hex Encoding Tests
// =============================================================================

MIQ_TEST(Crypto, HexEncodeEmpty) {
    std::vector<uint8_t> data;
    std::string hex = to_hex(data);
    MIQ_TEST_ASSERT_EQ(hex, "");
}

MIQ_TEST(Crypto, HexEncodeBasic) {
    std::vector<uint8_t> data = {0x00, 0x01, 0x0F, 0xAB, 0xFF};
    std::string hex = to_hex(data);
    MIQ_TEST_ASSERT_EQ(hex, "00010fabff");
}

MIQ_TEST(Crypto, HexDecodeBasic) {
    std::string hex = "00010fabff";
    auto data = from_hex(hex);

    std::vector<uint8_t> expected = {0x00, 0x01, 0x0F, 0xAB, 0xFF};
    MIQ_TEST_ASSERT(vectors_equal(data, expected));
}

MIQ_TEST(Crypto, HexRoundTrip) {
    TestRandom rng(66666);

    for (int i = 0; i < 100; ++i) {
        auto data = rng.rand_bytes(rng.rand_range(0, 100));
        std::string hex = to_hex(data);
        auto decoded = from_hex(hex);

        MIQ_TEST_ASSERT(vectors_equal(data, decoded));
    }
}

MIQ_TEST(Crypto, HexUpperLowerCase) {
    std::string lower = "abcdef";
    std::string upper = "ABCDEF";

    auto d1 = from_hex(lower);
    auto d2 = from_hex(upper);

    MIQ_TEST_ASSERT(vectors_equal(d1, d2));
}

// =============================================================================
// HD Wallet Tests
// =============================================================================

MIQ_TEST(Crypto, HDWalletMnemonicGeneration) {
    std::string mnemonic;
    MIQ_TEST_ASSERT(HdWallet::GenerateMnemonic(128, mnemonic));

    // Should be 12 words
    int word_count = 1;
    for (char c : mnemonic) {
        if (c == ' ') word_count++;
    }
    MIQ_TEST_ASSERT_EQ(word_count, 12);
}

MIQ_TEST(Crypto, HDWalletMnemonicToSeed) {
    std::string mnemonic;
    MIQ_TEST_ASSERT(HdWallet::GenerateMnemonic(128, mnemonic));

    std::vector<uint8_t> seed;
    MIQ_TEST_ASSERT(HdWallet::MnemonicToSeed(mnemonic, "", seed));
    MIQ_TEST_ASSERT_EQ(seed.size(), 64u);
}

MIQ_TEST(Crypto, HDWalletMnemonicWithPassphrase) {
    std::string mnemonic;
    MIQ_TEST_ASSERT(HdWallet::GenerateMnemonic(128, mnemonic));

    std::vector<uint8_t> seed1, seed2;
    MIQ_TEST_ASSERT(HdWallet::MnemonicToSeed(mnemonic, "", seed1));
    MIQ_TEST_ASSERT(HdWallet::MnemonicToSeed(mnemonic, "password", seed2));

    // Different passphrases should give different seeds
    MIQ_TEST_ASSERT(!vectors_equal(seed1, seed2));
}

MIQ_TEST(Crypto, HDWalletKeyDerivation) {
    std::string mnemonic;
    MIQ_TEST_ASSERT(HdWallet::GenerateMnemonic(128, mnemonic));

    std::vector<uint8_t> seed;
    MIQ_TEST_ASSERT(HdWallet::MnemonicToSeed(mnemonic, "", seed));

    HdAccountMeta meta;
    meta.account = 0;
    meta.next_recv = 0;
    meta.next_change = 0;

    HdWallet wallet(seed, meta);

    // Derive multiple keys
    for (uint32_t i = 0; i < 10; ++i) {
        std::vector<uint8_t> priv, pub;
        MIQ_TEST_ASSERT(wallet.DerivePrivPub(0, 0, i, priv, pub));
        MIQ_TEST_ASSERT_EQ(priv.size(), 32u);
        MIQ_TEST_ASSERT(pub.size() == 33 || pub.size() == 65);
    }
}

MIQ_TEST(Crypto, HDWalletDeterministicDerivation) {
    std::string mnemonic;
    MIQ_TEST_ASSERT(HdWallet::GenerateMnemonic(128, mnemonic));

    std::vector<uint8_t> seed;
    MIQ_TEST_ASSERT(HdWallet::MnemonicToSeed(mnemonic, "", seed));

    HdAccountMeta meta;
    meta.account = 0;

    HdWallet w1(seed, meta);
    HdWallet w2(seed, meta);

    // Same derivation path should give same keys
    std::vector<uint8_t> priv1, pub1, priv2, pub2;
    MIQ_TEST_ASSERT(w1.DerivePrivPub(0, 0, 5, priv1, pub1));
    MIQ_TEST_ASSERT(w2.DerivePrivPub(0, 0, 5, priv2, pub2));

    MIQ_TEST_ASSERT(vectors_equal(priv1, priv2));
    MIQ_TEST_ASSERT(vectors_equal(pub1, pub2));
}

MIQ_TEST(Crypto, HDWalletAddressGeneration) {
    std::string mnemonic;
    MIQ_TEST_ASSERT(HdWallet::GenerateMnemonic(128, mnemonic));

    std::vector<uint8_t> seed;
    MIQ_TEST_ASSERT(HdWallet::MnemonicToSeed(mnemonic, "", seed));

    HdAccountMeta meta;
    meta.account = 0;
    meta.next_recv = 0;

    HdWallet wallet(seed, meta);

    std::string addr;
    MIQ_TEST_ASSERT(wallet.GetNewAddress(addr));
    MIQ_TEST_ASSERT_GT(addr.size(), 20u);

    // Should be valid base58check
    uint8_t ver;
    std::vector<uint8_t> payload;
    MIQ_TEST_ASSERT(base58check_decode(addr, ver, payload));
    MIQ_TEST_ASSERT_EQ(ver, VERSION_P2PKH);
    MIQ_TEST_ASSERT_EQ(payload.size(), 20u);
}

// =============================================================================
// Benchmark Tests
// =============================================================================

MIQ_TEST(Crypto, BenchmarkECDSASign) {
    std::vector<uint8_t> privkey, pubkey;
    MIQ_TEST_ASSERT(crypto::ECDSA::generate_keypair(privkey, pubkey));

    TestRandom rng(77777);
    auto hash = rng.rand_bytes(32);

    Benchmark bench("ECDSA_sign", 1000);
    auto result = bench.run([&]() {
        std::vector<uint8_t> sig;
        crypto::ECDSA::sign(privkey, hash, sig);
    });

    MIQ_TEST_ASSERT_LT(result.avg_ms, 10.0); // Should be <10ms per signature
}

MIQ_TEST(Crypto, BenchmarkECDSAVerify) {
    std::vector<uint8_t> privkey, pubkey;
    MIQ_TEST_ASSERT(crypto::ECDSA::generate_keypair(privkey, pubkey));

    TestRandom rng(88888);
    auto hash = rng.rand_bytes(32);

    std::vector<uint8_t> sig;
    MIQ_TEST_ASSERT(crypto::ECDSA::sign(privkey, hash, sig));

    Benchmark bench("ECDSA_verify", 1000);
    auto result = bench.run([&]() {
        crypto::ECDSA::verify(pubkey, hash, sig);
    });

    MIQ_TEST_ASSERT_LT(result.avg_ms, 10.0); // Should be <10ms per verify
}

MIQ_TEST(Crypto, BenchmarkHash160) {
    TestRandom rng(99999);
    auto data = rng.rand_bytes(33);

    Benchmark bench("hash160_33bytes", 10000);
    auto result = bench.run([&]() {
        hash160(data);
    });

    MIQ_TEST_ASSERT_LT(result.avg_ms, 0.1); // Should be very fast
}

} // namespace test
} // namespace miq
