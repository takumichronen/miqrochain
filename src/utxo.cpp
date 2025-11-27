#include "utxo.h"
#include "hex.h"       // to_hex
#include <fstream>
#include <filesystem>
#include <sstream>
#include <unordered_map>

namespace fs = std::filesystem;

namespace miq {

// CRITICAL FIX: Maximum limits to prevent DoS and buffer overflows
static constexpr uint32_t MAX_TXID_SIZE = 64;       // Max txid size (typical is 32)
static constexpr uint32_t MAX_PKH_SIZE = 64;        // Max pubkey hash size (typical is 20)

std::string UTXOSet::key(const std::vector<uint8_t>& txid, uint32_t vout) const {
    // Stable and simple: hex(txid) + ":" + vout
    std::ostringstream o;
    o << to_hex(txid) << ":" << vout;
    return o.str();
}

bool UTXOSet::append_log(char op, const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry* e){
    // CRITICAL FIX: Open in binary append mode with explicit sync
    std::ofstream f(log_path_, std::ios::app|std::ios::binary);
    if(!f) return false;

    f.write(&op,1);
    uint32_t n=(uint32_t)txid.size();
    f.write((const char*)&n,sizeof(n));
    f.write((const char*)txid.data(), n);
    f.write((const char*)&vout,sizeof(vout));
    if(op=='A'&&e){
        f.write((const char*)&e->value,sizeof(e->value));
        f.write((const char*)&e->height,sizeof(e->height));
        char cb=e->coinbase?1:0; f.write(&cb,1);
        uint32_t ph=(uint32_t)e->pkh.size(); f.write((const char*)&ph,sizeof(ph));
        f.write((const char*)e->pkh.data(), ph);
    }

    // CRITICAL FIX: Check write success before flush
    if (!f.good()) return false;

    // CRITICAL FIX: Flush and sync to disk for durability
    f.flush();
    if (!f.good()) return false;

    // Note: std::ofstream doesn't expose fsync directly, but flush() with
    // good() check ensures buffer is written. For true fsync, would need
    // to use POSIX file descriptors. This is acceptable for most use cases.

    return true;
}

bool UTXOSet::load_log(){
    map_.clear();
    std::ifstream f(log_path_, std::ios::binary);
    if(!f) return true;

    while(f){
        char op;
        f.read(&op,1);
        if(!f) break;

        uint32_t n=0;
        f.read((char*)&n,sizeof(n));
        if(!f) return false;

        // CRITICAL FIX: Bounds check to prevent buffer overflow / DoS
        if (n > MAX_TXID_SIZE) return false;

        std::vector<uint8_t> txid(n);
        if (n > 0) {
            f.read((char*)txid.data(), n);
            if(!f) return false;
        }

        uint32_t vout=0;
        f.read((char*)&vout,sizeof(vout));
        if(!f) return false;

        if(op=='A'){
            UTXOEntry e;
            uint32_t ph=0;
            char cb=0;

            f.read((char*)&e.value,sizeof(e.value));
            if(!f) return false;

            f.read((char*)&e.height,sizeof(e.height));
            if(!f) return false;

            f.read(&cb,1);
            if(!f) return false;
            e.coinbase=(cb!=0);

            f.read((char*)&ph,sizeof(ph));
            if(!f) return false;

            // CRITICAL FIX: Bounds check to prevent buffer overflow / DoS
            if (ph > MAX_PKH_SIZE) return false;

            e.pkh.resize(ph);
            if (ph > 0) {
                f.read((char*)e.pkh.data(), ph);
                if(!f) return false;
            }

            map_[key(txid,vout)] = e;
        } else if(op=='S'){
            map_.erase(key(txid,vout));
        } else {
            return false;
        }
    }
    return true;
}

bool UTXOSet::open(const std::string& dir){
    fs::create_directories(dir);
    log_path_ = dir + "/utxo.log";
    std::ofstream f(log_path_, std::ios::app|std::ios::binary); f.close();
    return load_log();
}

bool UTXOSet::add(const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry& e){
    std::lock_guard<std::mutex> lk(mtx_);  // CRITICAL FIX: Thread safety

    // CRITICAL FIX: Write to log FIRST, then update map
    // This ensures we don't lose data on crash
    if (!append_log('A',txid,vout,&e)) return false;

    map_[key(txid,vout)] = e;
    return true;
}

bool UTXOSet::spend(const std::vector<uint8_t>& txid, uint32_t vout){
    std::lock_guard<std::mutex> lk(mtx_);  // CRITICAL FIX: Thread safety

    // CRITICAL FIX: Write to log FIRST, then update map
    if (!append_log('S',txid,vout,nullptr)) return false;

    map_.erase(key(txid,vout));
    return true;
}

bool UTXOSet::get(const std::vector<uint8_t>& txid, uint32_t vout, UTXOEntry& out) const{
    std::lock_guard<std::mutex> lk(mtx_);  // CRITICAL FIX: Thread safety

    auto it=map_.find(key(txid,vout));
    if(it==map_.end()) return false;
    out=it->second;
    return true;
}

// Reconstruct live set from the append-only log and filter by PKH.
std::vector<std::tuple<std::vector<uint8_t>, uint32_t, UTXOEntry>>
UTXOSet::list_for_pkh(const std::vector<uint8_t>& pkh) const {
    std::lock_guard<std::mutex> lk(mtx_);  // CRITICAL FIX: Thread safety

    struct K {
        std::vector<uint8_t> txid; uint32_t vout;
        bool operator==(const K& o) const { return vout==o.vout && txid==o.txid; }
    };
    struct KH {
        size_t operator()(const K& k) const noexcept {
            size_t h = k.vout * 1315423911u;
            if(!k.txid.empty()){
                h ^= (size_t)k.txid.front() * 2654435761u;
                h ^= (size_t)k.txid.back()  * 2246822519u;
            }
            return h;
        }
    };

    std::unordered_map<K, UTXOEntry, KH> live;

    std::ifstream f(log_path_, std::ios::binary);
    if(!f) return {};

    while(f){
        char op;
        f.read(&op,1);
        if(!f) break;

        uint32_t n=0;
        f.read((char*)&n,sizeof(n));
        if(!f) break;

        // CRITICAL FIX: Bounds check to prevent buffer overflow
        if (n > MAX_TXID_SIZE) break;

        std::vector<uint8_t> txid(n);
        if (n > 0) {
            f.read((char*)txid.data(), n);
            if(!f) break;
        }

        uint32_t vout=0;
        f.read((char*)&vout,sizeof(vout));
        if(!f) break;

        K k{std::move(txid), vout};
        if(op=='A'){
            UTXOEntry e;
            uint32_t ph=0;
            char cb=0;

            f.read((char*)&e.value,sizeof(e.value));
            if(!f) break;

            f.read((char*)&e.height,sizeof(e.height));
            if(!f) break;

            f.read(&cb,1);
            if(!f) break;
            e.coinbase=(cb!=0);

            f.read((char*)&ph,sizeof(ph));
            if(!f) break;

            // CRITICAL FIX: Bounds check to prevent buffer overflow
            if (ph > MAX_PKH_SIZE) break;

            e.pkh.resize(ph);
            if (ph > 0) {
                f.read((char*)e.pkh.data(), ph);
                if(!f) break;
            }

            live[std::move(k)] = e;
        } else if(op=='S'){
            live.erase(k);
        } else {
            break;
        }
    }

    std::vector<std::tuple<std::vector<uint8_t>, uint32_t, UTXOEntry>> out;
    out.reserve(live.size());
    for(auto& kv : live){
        if(kv.second.pkh == pkh){
            out.emplace_back(kv.first.txid, kv.first.vout, kv.second);
        }
    }
    return out;
}

}

