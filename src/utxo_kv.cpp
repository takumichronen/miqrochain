#include "utxo_kv.h"
#include <cstring>

namespace miq {

static inline void put_u32le(std::string& s, uint32_t x){
    char b[4];
    b[0]=char(x&0xff); b[1]=char((x>>8)&0xff); b[2]=char((x>>16)&0xff); b[3]=char((x>>24)&0xff);
    s.append(b,4);
}
static inline void put_u64le(std::string& s, uint64_t x){
    char b[8];
    for(int i=0;i<8;i++) b[i]=char((x>>(8*i))&0xff);
    s.append(b,8);
}
static inline uint64_t get_u64le(const char* p){ uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t(uint8_t(p[i]))<<(8*i)); return v; }

bool UTXOKV::open(const std::string& dir, std::string* err){
    return db_.open(dir + "/chainstate", err);
}

std::string UTXOKV::k_utxo(const std::vector<uint8_t>& txid, uint32_t vout){
    std::string k;
    k.reserve(1 + 32 + 4);
    k.push_back('u');
    k.append(reinterpret_cast<const char*>(txid.data()), txid.size());
    put_u32le(k, vout);
    return k;
}

std::string UTXOKV::ser_entry(const UTXOEntry& e){
    // CRITICAL FIX: height is uint64_t, store as 8 bytes not 4
    // value(8) | height(8) | coinbase(1) | pkh_len(1) | pkh
    std::string v;
    v.reserve(8+8+2+e.pkh.size());
    put_u64le(v, e.value);
    put_u64le(v, e.height);  // CRITICAL FIX: Use 64-bit for height
    v.push_back(e.coinbase ? '\x01' : '\x00');
    v.push_back(static_cast<char>(e.pkh.size()));
    if(!e.pkh.empty())
        v.append(reinterpret_cast<const char*>(e.pkh.data()), e.pkh.size());
    return v;
}

bool UTXOKV::deser_entry(const std::string& vbuf, UTXOEntry& e){
    // CRITICAL FIX: Updated to match 64-bit height format
    if(vbuf.size() < 8+8+2) return false;  // value(8) + height(8) + coinbase(1) + pkh_len(1)
    const char* p = vbuf.data();
    e.value = get_u64le(p); p+=8;
    e.height = get_u64le(p); p+=8;  // CRITICAL FIX: Read 64-bit height
    e.coinbase = (*p++ != 0);
    uint8_t n = uint8_t(*p++);
    if (size_t(p - vbuf.data()) + n != vbuf.size()) return false;
    e.pkh.assign(reinterpret_cast<const uint8_t*>(p), reinterpret_cast<const uint8_t*>(p)+n);
    return true;
}

bool UTXOKV::get(const std::vector<uint8_t>& txid, uint32_t vout, UTXOEntry& out) const{
    std::string v;
    if(!db_.get(k_utxo(txid, vout), v, nullptr)) return false;
    return deser_entry(v, out);
}

bool UTXOKV::add(const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry& e, std::string* err){
    return db_.put(k_utxo(txid, vout), ser_entry(e), /*sync=*/true, err);
}

bool UTXOKV::spend(const std::vector<uint8_t>& txid, uint32_t vout, std::string* err){
    return db_.del(k_utxo(txid, vout), /*sync=*/true, err);
}

void UTXOKV::Batch::add(const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry& e){
    b_.put(UTXOKV::k_utxo(txid, vout), UTXOKV::ser_entry(e));
}
void UTXOKV::Batch::spend(const std::vector<uint8_t>& txid, uint32_t vout){
    b_.del(UTXOKV::k_utxo(txid, vout));
}

// === NEW: tiny factory to create a batch (non-breaking convenience) ===
UTXOKV::Batch UTXOKV::make_batch(){
    return UTXOKV::Batch(*this);
}

}
