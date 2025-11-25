# Miqrochain

**Version 1.0 Stable**

A production-ready, feature-complete blockchain implementation written in modern C++17.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](https://isocpp.org/)
[![CMake](https://img.shields.io/badge/CMake-3.16+-green.svg)](https://cmake.org/)

---

## Overview

Miqrochain is a high-performance blockchain node with full wallet support, advanced mining capabilities, and a professional graphical interface. Built with production-grade architecture, it features enterprise-level optimizations for reliability, security, and scalability.

**Key Highlights:**
- ✅ **Production-Ready:** Stable v1.0 release with comprehensive testing
- ✅ **Full-Featured Wallet:** Professional Qt GUI + powerful CLI with HD wallet support
- ✅ **Advanced Mining:** CPU + GPU (OpenCL) support with Stratum server
- ✅ **Modern Crypto:** SegWit, Taproot, BIP158 compact filters
- ✅ **Enterprise Performance:** Optimized for high throughput and global scale

---

## Quick Facts

| Component | Details |
|-----------|---------|
| **Network** | Mainnet (dual-stack IPv4/IPv6) |
| **P2P Port** | 9883 (TCP) |
| **RPC Port** | 9833 (JSON-RPC over HTTP) |
| **Currency** | MIQ (Miqro) |
| **Consensus** | Proof of Work |
| **Block Time** | Configurable via difficulty adjustment |
| **License** | Apache 2.0 |

---

## Table of Contents

- [Features](#features)
  - [Core Node](#core-node)
  - [Wallet](#wallet)
  - [Mining](#mining)
  - [Developer Tools](#developer-tools)
- [Components](#components)
- [Build Instructions](#build-instructions)
  - [Prerequisites](#prerequisites)
  - [Linux / Ubuntu](#linux--ubuntu)
  - [Windows (MSVC)](#windows-msvc)
  - [macOS](#macos)
  - [Build Options](#build-options)
- [Quick Start](#quick-start)
  - [Running a Full Node](#running-a-full-node)
  - [Using the Wallet](#using-the-wallet)
  - [Mining](#mining-1)
  - [RPC Examples](#rpc-examples)
- [Configuration](#configuration)
  - [Command-Line Flags](#command-line-flags)
  - [Environment Variables](#environment-variables)
- [Wallet Features](#wallet-features)
- [Mining Guide](#mining-guide)
- [API Reference](#api-reference)
- [Networking](#networking)
- [Data Storage](#data-storage)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Node

#### Networking & P2P
- **Dual-stack networking:** Full IPv4 and IPv6 support
- **Non-blocking I/O:** High-performance async socket operations
- **Advanced peer management:** Address manager with persistent storage
- **Anti-eclipse protection:** IP diversity requirements, group-based limits
- **NAT/UPnP/NAT-PMP:** Automatic port forwarding for home networks
- **DNS seeding:** Bootstrap from hardcoded DNS seeds
- **Peer scoring:** Reputation-based connection management

#### Synchronization
- **Headers-first sync:** Fast initial blockchain download
- **Automatic fallback:** By-index sync when headers stall
- **Parallel downloads:** Multiple concurrent block requests
- **Orphan handling:** Comprehensive orphan block management
- **Checkpoint validation:** AssumeValid for faster sync

#### Transaction Processing
- **Advanced mempool:** Fee-based prioritization with ancestor/descendant tracking
- **Rate limiting:** Per-peer bandwidth control
- **Trickle relay:** Privacy-enhanced transaction propagation
- **Fee filtering:** Minimum relay fee enforcement
- **Replace-by-fee (RBF):** Transaction replacement support
- **Compact blocks:** Bandwidth-efficient block relay

#### Storage & Performance
- **Database options:** LevelDB (default) or RocksDB
- **UTXO commitment:** Fast state validation
- **Signature caching:** 128K entry signature verification cache
- **Script caching:** 64K entry script execution cache
- **Bloom filters:** SPV client support (BIP37)
- **Compact block filters:** BIP158 for light clients

### Wallet

#### CLI Wallet (`miqwallet`)
- **HD wallet support:** Hierarchical Deterministic wallets (BIP32/BIP39)
- **Mnemonic seeds:** 12/24-word recovery phrases
- **Multiple addresses:** Generate unlimited receiving addresses
- **Transaction builder:** Create, sign, and broadcast transactions
- **Balance tracking:** Real-time balance updates
- **SPV mode:** Lightweight blockchain verification
- **Wallet encryption:** At-rest AES-256 encryption (optional)
- **Key management:** Import/export private keys
- **Professional UI:** Live animated dashboard with instant feedback

#### Qt GUI Wallet (`miqro-gui`)
- **Modern interface:** Professional Qt 6.4+ based GUI
- **Real-time updates:** Live balance and transaction monitoring
- **QR code support:** Easy address sharing
- **Transaction history:** Complete activity log with search/filter
- **Address book:** Manage contacts and labels
- **Integrated with miqrod:** Seamless node integration

#### Key Generation Tool (`miq-keygen`)
- **Standalone key generation:** Create keys offline
- **Multiple formats:** WIF, hex, address derivation
- **Batch generation:** Generate multiple keys at once
- **HD key derivation:** BIP32 path support

### Mining

#### CPU Mining
- **Multi-threaded:** Utilize all available CPU cores
- **Optimized hashing:** Fast SHA-256d implementation
- **Block template building:** Automatic transaction selection
- **Priority handling:** Fee-based transaction ordering

#### GPU Mining (OpenCL)
- **OpenCL support:** NVIDIA, AMD, Intel GPUs
- **Auto-detection:** Automatic platform/device discovery
- **Configurable intensity:** Balance between speed and stability
- **Fallback to CPU:** Graceful degradation if GPU unavailable

#### Mining Applications
- **`miqminer`:** Standalone mining application
- **`miqminer_rpc`:** RPC-based miner (connects to `miqrod`)
- **`setgenerate` RPC:** Built-in mining via JSON-RPC
- **Stratum server:** Mining pool protocol support

### Developer Tools

- **JSON-RPC API:** Comprehensive node control interface
- **Test suite:** Crypto, serialization, P2P, mempool tests
- **TLS proxy:** Secure RPC over HTTPS
- **Metrics export:** Performance monitoring
- **Debug logging:** Configurable verbosity levels

---

## Components

| Binary | Description | Use Case |
|--------|-------------|----------|
| **miqrod** | Full node daemon | Run a blockchain node, mine, provide RPC services |
| **miqwallet** | CLI wallet | Manage funds, create transactions, HD wallet operations |
| **miqro-gui** | Qt GUI wallet | User-friendly graphical wallet interface |
| **miq-keygen** | Key generation tool | Offline key generation, HD derivation |
| **miqminer** | Standalone miner | Solo mining with direct blockchain access |
| **miqminer_rpc** | RPC miner | Connect to remote node for mining |

---

## Build Instructions

### Prerequisites

- **CMake** ≥ 3.16
- **C++17 compiler:**
  - Linux/macOS: GCC ≥ 9 or Clang ≥ 10
  - Windows: Visual Studio 2019/2022 (MSVC)
- **OpenSSL** (libssl-dev)
- **LevelDB** (auto-fetched if not found) or RocksDB (optional)
- **Qt 6.4+** (optional, for GUI wallet)
- **OpenCL** (optional, for GPU mining)
- **miniupnpc** (optional, for UPnP support)

### Linux / Ubuntu

Tested on Ubuntu 20.04, 22.04, and 24.04.

```bash
# 1) Install dependencies
sudo apt update
sudo apt install -y build-essential cmake git libssl-dev

# Optional: For GPU mining
sudo apt install -y ocl-icd-opencl-dev

# Optional: For UPnP
sudo apt install -y libminiupnpc-dev

# 2) Clone the repository
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain

# 3) Configure and build (Release mode)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 4) Optional: Install system-wide
sudo cmake --install build
```

**Binaries will be in:** `build/miqrod`, `build/miqwallet`, etc.

### Windows (MSVC)

Requires Visual Studio 2019 or 2022 with "Desktop development with C++" workload.

```powershell
# Use "x64 Native Tools Command Prompt" or "Developer PowerShell for VS"

# 1) Clone
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain

# 2) Configure and build
cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j

# Binaries will be in: build\Release\
```

**OpenSSL on Windows:**
- Install from [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html)
- Or use vcpkg: `vcpkg install openssl:x64-windows`

**GPU Mining on Windows:**
- Install NVIDIA CUDA Toolkit or AMD APP SDK
- CMake will auto-detect OpenCL

### macOS

Tested on macOS 12+ (Apple Silicon and Intel).

```bash
# 1) Install Xcode Command Line Tools
xcode-select --install

# 2) Install CMake via Homebrew
brew install cmake openssl@3

# 3) Clone and build
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build -j$(sysctl -n hw.ncpu)
```

### Build Options

Configure the build with CMake options:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DMIQ_ENABLE_WALLET_ENC=ON \
  -DMIQ_ENABLE_UPNP=ON \
  -DMIQ_ENABLE_OPENCL=ON \
  -DMIQ_USE_ROCKSDB=OFF \
  -DMIQ_BUILD_TESTS=ON
```

| Option | Default | Description |
|--------|---------|-------------|
| `MIQ_ENABLE_WALLET_ENC` | OFF | Enable AES-256 wallet encryption |
| `MIQ_ENABLE_UPNP` | ON | Enable UPnP/NAT-PMP port forwarding |
| `MIQ_FETCH_MINIUPNPC` | OFF | Auto-download miniupnpc if missing |
| `MIQ_ENABLE_OPENCL` | ON | Enable GPU mining support |
| `MIQ_USE_ROCKSDB` | OFF | Use RocksDB instead of LevelDB |
| `MIQ_FETCH_LEVELDB` | ON | Auto-download LevelDB if missing |
| `MIQ_USE_LIBSECP` | ON | Use bitcoin-core/secp256k1 |
| `MIQ_BUILD_TESTS` | OFF | Build test suite |

---

## Quick Start

### Running a Full Node

```bash
# Create data directory
mkdir -p ~/miqrochain-data

# Run the node
./build/miqrod --datadir ~/miqrochain-data --p2p 9883 --rpc 9833
```

The node will:
1. Initialize blockchain database
2. Connect to DNS seeds
3. Discover and connect to peers
4. Synchronize the blockchain
5. Start accepting RPC commands

**Important:** Keep `--rpc` bound to `127.0.0.1` (default) unless you need remote access. If exposing RPC, use authentication, firewall rules, or TLS proxy.

### Using the Wallet

#### CLI Wallet

```bash
# Create a new HD wallet
./build/miqwallet create --name mywallet

# Display your mnemonic seed (WRITE THIS DOWN!)
./build/miqwallet seed --name mywallet

# Get a receiving address
./build/miqwallet address --name mywallet

# Check balance
./build/miqwallet balance --name mywallet --rpc http://127.0.0.1:9833

# Send transaction
./build/miqwallet send --name mywallet \
  --to <recipient-address> \
  --amount 10.5 \
  --rpc http://127.0.0.1:9833
```

#### GUI Wallet

```bash
# Navigate to GUI directory and build
cd gui/miqro_gui
cmake -B build -S . -DCMAKE_PREFIX_PATH="/path/to/Qt/6.x.x/<compiler>"
cmake --build build --config Release

# Run the GUI
./build/miqro-gui
```

The GUI features:
- Live animated dashboard
- Instant balance updates
- Transaction history with search
- QR code generation for receiving
- Address book management
- Professional splash screen

### Mining

#### Option 1: Built-in Mining (via RPC)

```bash
# Enable mining with 4 threads
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"setgenerate","params":[true, 4]}' \
  http://127.0.0.1:9833

# Check mining stats
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"getminerstats","params":[]}' \
  http://127.0.0.1:9833

# Disable mining
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"setgenerate","params":[false]}' \
  http://127.0.0.1:9833
```

#### Option 2: Standalone Miner (GPU + CPU)

```bash
# CPU mining (4 threads)
./build/miqminer --threads 4 --rpc http://127.0.0.1:9833

# GPU mining (with CPU fallback)
./build/miqminer --gpu --platform 0 --device 0 --rpc http://127.0.0.1:9833

# List OpenCL devices
./build/miqminer --list-devices
```

#### Option 3: RPC Miner

```bash
# Connect to node and mine
./build/miqminer_rpc --url http://127.0.0.1:9833 --threads 4
```

### RPC Examples

#### Get Blockchain Info

```bash
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:9833 | jq
```

Response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "chain": "main",
    "blocks": 12345,
    "headers": 12345,
    "bestblockhash": "00000000000000a1b2c3...",
    "difficulty": 1234567.89,
    "mediantime": 1732569600,
    "verificationprogress": 1.0,
    "chainwork": "00000000000000000000001234abcd",
    "pruned": false
  }
}
```

#### Get Block by Height

```bash
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblock","params":[1000]}' \
  http://127.0.0.1:9833 | jq
```

#### Submit Transaction

```bash
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"sendrawtransaction","params":["<hex-tx>"]}' \
  http://127.0.0.1:9833
```

---

## Configuration

### Command-Line Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--datadir <path>` | Data directory for chain state and logs | `--datadir ./data` |
| `--p2p <port>` | P2P listen port | `--p2p 9883` |
| `--rpc <port>` | RPC listen port | `--rpc 9833` |
| `--seed 1` | Enable seed mode (reduced outbound connections) | `--seed 1` |
| `--upnp 1` | Enable UPnP port forwarding | `--upnp 1` |
| `--loglevel <level>` | Set logging verbosity (0-5) | `--loglevel 3` |
| `--connect <ip:port>` | Connect to specific peer only | `--connect 192.168.1.100:9883` |
| `--addnode <ip:port>` | Add peer to connection list | `--addnode peer.example.com:9883` |
| `--maxconnections <n>` | Maximum number of connections | `--maxconnections 125` |

Run `./build/miqrod --help` for complete flag list.

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MIQ_IS_SEED` | Enable seed node mode | `MIQ_IS_SEED=1` |
| `MIQ_MIN_RELAY_FEE_RATE` | Minimum relay fee (miqr/kB) | `MIQ_MIN_RELAY_FEE_RATE=1000` |
| `MIQ_SELF_IP` | Mark self IPs (avoid self-connect) | `MIQ_SELF_IP=1.2.3.4,5.6.7.8` |

---

## Wallet Features

### Hierarchical Deterministic (HD) Wallets

Miqrochain implements BIP32/BIP39/BIP44 standards:

- **BIP39:** Mnemonic seed phrases (12 or 24 words)
- **BIP32:** Hierarchical key derivation
- **BIP44:** Multi-account hierarchy (`m/44'/0'/0'/0/0`)

### Security Features

- **Offline key generation:** Use `miq-keygen` on air-gapped system
- **Encrypted wallets:** Optional AES-256-CBC encryption
- **Seed phrase backup:** 12/24-word recovery mechanism
- **Multiple addresses:** Generate unlimited addresses from single seed
- **Watch-only wallets:** Monitor addresses without private keys

### Transaction Features

- **Manual coin control:** Select specific UTXOs
- **Fee estimation:** Automatic fee calculation
- **RBF support:** Replace-by-fee transaction replacement
- **Batch transactions:** Send to multiple recipients
- **SegWit support:** Lower fees with witness discounting

---

## Mining Guide

### CPU Mining Performance

Expected hashrates (SHA-256d):
- Modern CPU (8 cores): ~5-10 MH/s
- High-end CPU (16 cores): ~15-25 MH/s

### GPU Mining Performance

Approximate hashrates:
- NVIDIA GTX 1080 Ti: ~500-800 MH/s
- NVIDIA RTX 3080: ~1500-2000 MH/s
- AMD RX 6800 XT: ~1000-1500 MH/s

### Pool Mining (Stratum)

If you run a pool, enable Stratum server:

```cpp
// Configure in node
stratum_port = 9332
stratum_difficulty = 16
```

Miners connect:
```bash
./build/miqminer_rpc --stratum stratum+tcp://pool.example.com:9332 \
  --user wallet_address --password x
```

### Mining Best Practices

1. **Monitor temperature:** Keep GPUs under 75°C
2. **Stable overclocks:** Prioritize stability over max hashrate
3. **Power efficiency:** Optimize power limit for best MH/W
4. **Backup power:** Use UPS to prevent data corruption
5. **Pool failover:** Configure backup pools

---

## API Reference

### Core RPC Methods

#### Blockchain

- `getblockchaininfo` - Chain state info
- `getbestblockhash` - Latest block hash
- `getblock <hash|height>` - Block data by hash or height
- `getrawblock <hash|height>` - Raw block hex
- `getblockheader <hash|height>` - Block header only
- `getchaintips` - All known chain tips

#### Network

- `getnetworkinfo` - Network state and version
- `getpeerinfo` - Connected peer details
- `peers` - List active peers
- `addnode <ip:port> <add|remove>` - Manage connections
- `getconnectioncount` - Number of connections
- `ban <ip> <seconds>` - Ban peer temporarily
- `unban <ip>` - Remove ban
- `getbans` - List all bans

#### Mempool

- `getmempoolinfo` - Mempool statistics
- `getrawmempool` - All mempool transaction IDs
- `getmempoolentry <txid>` - Transaction details
- `gettxout <txid> <vout>` - UTXO information

#### Transactions

- `sendrawtransaction <hex>` - Broadcast signed transaction
- `getrawtransaction <txid>` - Get transaction data
- `decoderawtransaction <hex>` - Decode transaction hex
- `testmempoolaccept <hex>` - Test transaction validity

#### Mining

- `setgenerate <on> <threads>` - Enable/disable mining
- `getminerstats` - Mining statistics
- `getmininginfo` - Mining difficulty and network hashrate
- `getblocktemplate` - Template for block construction
- `submitblock <hex>` - Submit mined block

#### Utilities

- `validateaddress <address>` - Check address validity
- `estimatefee <blocks>` - Fee estimation
- `getdifficulty` - Current network difficulty
- `uptime` - Node uptime in seconds

### Example: Complete Transaction Flow

```bash
# 1. Get UTXO for an address (requires wallet)
curl -d '{"method":"listunspent","params":["<address>"]}' http://127.0.0.1:9833

# 2. Create raw transaction
curl -d '{"method":"createrawtransaction","params":[[{"txid":"abc..","vout":0}],[{"<dest>":10.5}]]}' \
  http://127.0.0.1:9833

# 3. Sign transaction (use miqwallet or RPC if wallet integrated)
./build/miqwallet sign --tx <raw-hex>

# 4. Broadcast
curl -d '{"method":"sendrawtransaction","params":["<signed-hex>"]}' http://127.0.0.1:9833
```

---

## Networking

### Port Configuration

| Port | Protocol | Purpose | Firewall |
|------|----------|---------|----------|
| 9883 | TCP | P2P networking | **Open** for inbound peers |
| 9833 | TCP | JSON-RPC | **Block** from internet (localhost only) |
| 9332 | TCP | Stratum (optional) | Open if running pool |

### Firewall Setup

#### Ubuntu (UFW)

```bash
# Allow P2P
sudo ufw allow 9883/tcp comment 'Miqrochain P2P'

# Block RPC from internet (allow only local)
sudo ufw deny 9833/tcp
sudo ufw allow from 127.0.0.1 to any port 9833 proto tcp

# Optional: Allow specific IP to RPC
sudo ufw allow from <trusted-ip> to any port 9833 proto tcp
```

#### Windows Firewall

```powershell
# Allow P2P inbound
New-NetFirewallRule -DisplayName "Miqrochain P2P" -Direction Inbound `
  -LocalPort 9883 -Protocol TCP -Action Allow

# Block RPC from network
New-NetFirewallRule -DisplayName "Miqrochain RPC Block" -Direction Inbound `
  -LocalPort 9833 -Protocol TCP -RemoteAddress Any -Action Block

# Allow RPC from localhost
New-NetFirewallRule -DisplayName "Miqrochain RPC Local" -Direction Inbound `
  -LocalPort 9833 -Protocol TCP -RemoteAddress 127.0.0.1 -Action Allow
```

See [FIREWALL.md](FIREWALL.md) for detailed instructions.

### NAT Traversal

If behind a router, enable UPnP:

```bash
./build/miqrod --datadir ./data --upnp 1
```

Or manually forward port 9883 (TCP) in your router admin panel.

### DNS Seeds

Hardcoded DNS seeds bootstrap initial peer discovery. If DNS seeds are unavailable, manually add nodes:

```bash
./build/miqrod --addnode seed1.miqrochain.org:9883 --addnode seed2.miqrochain.org:9883
```

---

## Data Storage

### Directory Structure

```
datadir/
├── blocks/          # Block data (*.dat files)
├── chainstate/      # UTXO set (LevelDB/RocksDB)
├── peers.dat        # Legacy peer addresses
├── peers2.dat       # Modern address manager state
├── bans.txt         # Banned peer IPs
├── wallet.dat       # Wallet keys (if integrated)
├── debug.log        # Node logs
└── miqrod.pid       # Process ID file
```

### Backup Recommendations

**Critical files:**
- `wallet.dat` - Contains private keys (**MUST BACKUP**)
- `mnemonic_seed.txt` - Seed phrase backup (**MOST IMPORTANT**)

**Optional files:**
- `peers.dat` / `peers2.dat` - Speeds up restart
- `bans.txt` - Ban list

**Not needed:**
- `blocks/` - Re-downloadable from network
- `chainstate/` - Rebuilt from blocks
- `debug.log` - Transient logs

### Pruning

Enable pruning to save disk space:

```bash
./build/miqrod --datadir ./data --prune=550
```

Keeps last 550 MB of blocks (~288 MB minimum).

---

## Security

### Wallet Security

1. **Backup seed phrase:** Write down 12/24 words on paper, store in safe
2. **Encrypt wallet:** Use `MIQ_ENABLE_WALLET_ENC=ON` during build
3. **Offline signing:** Generate unsigned TX on hot wallet, sign on cold wallet
4. **Verify addresses:** Always double-check recipient addresses
5. **Test with small amounts:** Send test transaction first

### Node Security

1. **Firewall RPC:** Never expose port 9833 to the internet
2. **Use TLS proxy:** For remote RPC access, use nginx/HAProxy with TLS
3. **Regular updates:** Keep node software up to date
4. **Monitor logs:** Watch for suspicious activity
5. **Rate limiting:** Configure OS-level rate limits for P2P port

### Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md) for responsible disclosure process.

**Contact:** security@miqrochain.org

---

## Troubleshooting

### Node Issues

**Problem:** No peers connecting

**Solution:**
- Check firewall allows port 9883
- Enable UPnP: `--upnp 1`
- Manually add nodes: `--addnode <ip:port>`
- Wait 5-10 minutes for DNS seeds

---

**Problem:** Slow synchronization

**Solution:**
- Ensure good internet connection (10+ Mbps)
- Increase connections: `--maxconnections 32`
- Check disk I/O (SSD recommended)
- Wait for automatic fallback from headers-first to by-index

---

**Problem:** High CPU usage

**Solution:**
- Normal during sync (signature verification)
- Consider lowering thread count if mining
- Check for orphan block processing

---

**Problem:** RPC connection refused

**Solution:**
- Verify node is running: `ps aux | grep miqrod`
- Check port: `netstat -an | grep 9833`
- Ensure calling from localhost
- Review logs: `tail -f ~/miqrochain-data/debug.log`

### Wallet Issues

**Problem:** Balance not updating

**Solution:**
- Wait for node to fully sync
- Check RPC connection: `curl http://127.0.0.1:9833`
- Verify wallet is scanning from correct block height
- Rescan blockchain: `./miqwallet rescan`

---

**Problem:** Transaction not confirming

**Solution:**
- Check mempool: `curl -d '{"method":"getrawmempool"}' http://127.0.0.1:9833`
- Verify sufficient fee
- Ensure inputs not already spent
- Wait for next block (may take time depending on network)

---

**Problem:** "Insufficient funds" error

**Solution:**
- Check actual balance: `./miqwallet balance`
- Account for fees (add extra MIQ for fee)
- Wait for pending transactions to confirm
- Check for dust outputs (very small UTXOs)

### Mining Issues

**Problem:** GPU not detected

**Solution:**
- Install latest GPU drivers
- On Linux: `sudo apt install ocl-icd-opencl-dev`
- Check OpenCL: `clinfo` (install `clinfo` package)
- Rebuild with `MIQ_ENABLE_OPENCL=ON`

---

**Problem:** Low hashrate

**Solution:**
- Check GPU load (should be ~100%)
- Increase work size/intensity
- Ensure proper cooling (thermal throttling)
- Update GPU drivers

---

**Problem:** Miner crashes

**Solution:**
- Reduce overclock settings
- Lower work intensity
- Check power supply adequacy
- Monitor GPU temperature
- Update OpenCL runtime

### Build Issues

**Problem:** OpenSSL not found

**Solution:**
- Ubuntu: `sudo apt install libssl-dev`
- macOS: `brew install openssl@3` and set `OPENSSL_ROOT_DIR`
- Windows: Install from [official site](https://slproweb.com/products/Win32OpenSSL.html)

---

**Problem:** LevelDB errors

**Solution:**
- Enable auto-fetch: `cmake -DMIQ_FETCH_LEVELDB=ON`
- Or install manually: `sudo apt install libleveldb-dev`

---

**Problem:** Qt not found (GUI)

**Solution:**
- Install Qt 6.4+: [qt.io/download](https://www.qt.io/download)
- Set `CMAKE_PREFIX_PATH=/path/to/Qt/6.x.x/<compiler>`
- Use Qt online installer (recommended)

---

## Contributing

We welcome contributions! Here's how to get started:

### Development Setup

```bash
# Clone with submodules
git clone --recursive https://github.com/takumichronen/miqrochain.git
cd miqrochain

# Create feature branch
git checkout -b feature/my-new-feature

# Build with tests
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DMIQ_BUILD_TESTS=ON
cmake --build build -j

# Run tests
cd build
ctest --output-on-failure
```

### Coding Standards

- **C++ Standard:** C++17
- **Formatting:** Consistent indentation (4 spaces)
- **Naming:**
  - Functions: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_SNAKE_CASE`
- **Comments:** Doxygen-style for public APIs
- **Error handling:** Use exceptions for exceptional cases, return codes for expected failures

### Pull Request Process

1. **Fork** the repository
2. **Create** feature branch from `main`
3. **Write** tests for new functionality
4. **Ensure** all tests pass
5. **Document** changes in commit messages
6. **Submit** PR with clear description

### Testing

```bash
# Run all tests
ctest --output-on-failure

# Run specific test
./build/test_crypto
./build/test_ser
```

### Reporting Issues

When reporting bugs, include:
- OS and version (e.g., Ubuntu 22.04, Windows 11, macOS 14)
- Compiler (GCC 11, MSVC 2022, Apple Clang 15)
- CMake version
- Build command used
- Full error log
- Steps to reproduce

### Areas for Contribution

- **Testing:** Unit tests, integration tests, fuzzing
- **Documentation:** Improve README, add tutorials
- **Features:** BIP implementations, optimizations
- **GUI:** UI improvements, themes
- **Mining:** Algorithm optimizations
- **Networking:** IPv6, Tor support enhancements

---

## License

**Apache License 2.0**

Copyright 2025 Miqrochain

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See [LICENSE](LICENSE) for full text.

---

## Additional Resources

- **Website:** https://miqrochain.org *(coming soon)*
- **Documentation:** https://docs.miqrochain.org *(coming soon)*
- **Block Explorer:** https://explorer.miqrochain.org *(coming soon)*
- **Discord:** https://discord.gg/miqrochain *(coming soon)*
- **Twitter:** [@miqrochain](https://twitter.com/miqrochain) *(coming soon)*

---

## Acknowledgments

Miqrochain is built on the shoulders of giants:

- **Bitcoin Core:** Protocol design and implementation patterns
- **LevelDB:** High-performance key-value storage (Google)
- **libsecp256k1:** Optimized elliptic curve cryptography (Bitcoin Core)
- **Qt Framework:** Cross-platform GUI toolkit
- **OpenSSL:** Cryptographic library
- **MicroECC:** Embedded elliptic curve library

Special thanks to all contributors and the open-source community.

---

**Happy mining and transacting! 🚀**

*For support, reach out at support@miqrochain.org*
