// src/tools/derive_address.cpp
#include <vector>
#include <string>
#include <iostream>
#include <cstdlib>

#include "constants.h"
#include "crypto/ecdsa_iface.h"
#include "sha256.h"
#include "ripemd160.h"
#include "hash160.h"
#include "base58.h"

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char* end;
        unsigned long byte = strtoul(byteString.c_str(), &end, 16);
        if (*end != '\0') {
            // Invalid hex
            return {};
        }
        bytes.push_back(static_cast<uint8_t>(byte));
    }
    return bytes;
}

// Base58Check(P2PKH): ver || payload20 || checksum4 ; checksum = first 4 bytes of SHA256(SHA256(ver||payload))
static std::string b58check_p2pkh(uint8_t ver, const std::vector<uint8_t>& payload20) {
    std::vector<uint8_t> buf;
    buf.reserve(1 + payload20.size() + 4);
    buf.push_back(ver);
    buf.insert(buf.end(), payload20.begin(), payload20.end());

    auto d1 = miq::sha256(buf);
    auto d2 = miq::sha256(d1);
    buf.insert(buf.end(), d2.begin(), d2.begin() + 4);

    return miq::base58_encode(buf);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <private_key_hex>\n";
        return 1;
    }

    std::string priv_hex = argv[1];
    if (priv_hex.length() != 64) {
        std::cerr << "Private key must be 64 hex characters\n";
        return 1;
    }

    std::vector<uint8_t> priv = hex_to_bytes(priv_hex);
    if (priv.size() != 32) {
        std::cerr << "Invalid private key\n";
        return 1;
    }

    // Derive compressed pubkey
    std::vector<uint8_t> pub33;
    if (!miq::crypto::ECDSA::derive_pub(priv, pub33)) {
        std::cerr << "derive_pub failed\n";
        return 1;
    }

    // Hash160 of compressed pubkey → P2PKH
    auto pkh  = miq::hash160(pub33);
    auto addr = b58check_p2pkh(miq::VERSION_P2PKH, pkh);

    std::cout << "Address (P2PKH): " << addr << "\n";
    std::cout << "PrivateKey (hex): " << priv_hex << "\n";
    return 0;
}