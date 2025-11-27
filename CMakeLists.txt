cmake_minimum_required(VERSION 3.16)

# Keep FetchContent current behavior
if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()

project(miqrochain_core C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(FetchContent)
find_package(PkgConfig QUIET)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# ---------------- Options ----------------
option(MIQ_ENABLE_WALLET_ENC "Enable wallet at-rest encryption" OFF)
option(MIQ_ENABLE_UPNP       "Enable UPnP/NAT-PMP (daemon only; auto-detect)" ON)
option(MIQ_FETCH_MINIUPNPC   "Auto-fetch miniupnpc if not found (needs network)" OFF)
option(MIQ_BUILD_TESTS       "Build tests" OFF)

option(MIQ_USE_ROCKSDB       "Use RocksDB instead of LevelDB"               OFF)
option(MIQ_FETCH_LEVELDB     "Auto-fetch LevelDB if missing"                ON)

option(MIQ_USE_LIBSECP "Use bitcoin-core/libsecp256k1 backend" ON)
set(MIQ_LIBSECP_TAG "master" CACHE STRING "bitcoin-core/secp256k1 tag/commit")

# NEW: GPU switch (auto-disables if headers/libs missing)
option(MIQ_ENABLE_OPENCL "Build miners with OpenCL GPU support" ON)

# ---------------- Warnings / Opt ----------------
if(MSVC)
  add_compile_options(/O2 /Ot /Oi /GL /GF /Gy /Zc:inline)
  add_link_options(/LTCG)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus)
  add_definitions(/D_CRT_SECURE_NO_WARNINGS)
  add_compile_definitions(_WIN32_WINNT=0x0600)
else()
  add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)
endif()

# ---------------- DB (LevelDB default) ----------------
set(MIQ_DB_TARGET "")
set(MIQ_DB_DEFINE "")

if(MIQ_USE_ROCKSDB)
  find_package(rocksdb QUIET)
  if(NOT rocksdb_FOUND)
    message(FATAL_ERROR "MIQ_USE_ROCKSDB=ON but RocksDB not found.")
  endif()
  set(MIQ_DB_TARGET RocksDB::rocksdb)
  set(MIQ_DB_DEFINE MIQ_USE_ROCKSDB=1)
else()
  find_package(LevelDB QUIET)
  if(LevelDB_FOUND)
    set(MIQ_DB_TARGET LevelDB::LevelDB)
  else()
    if(NOT MIQ_FETCH_LEVELDB)
      message(FATAL_ERROR "LevelDB not found. Install it or enable MIQ_FETCH_LEVELDB.")
    endif()
    FetchContent_Declare(
      leveldb_src
      GIT_REPOSITORY https://github.com/google/leveldb.git
      GIT_TAG        1.23
    )
    set(LEVELDB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(LEVELDB_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(leveldb_src)
    if(NOT TARGET LevelDB::LevelDB)
      add_library(LevelDB::LevelDB ALIAS leveldb)
    endif()
    if(NOT MSVC)
      target_compile_options(leveldb PRIVATE -Wno-unused-but-set-variable)
    endif()
    set(MIQ_DB_TARGET LevelDB::LevelDB)
  endif()
  set(MIQ_DB_DEFINE MIQ_USE_LEVELDB=1)
endif()

# ---------------- libsecp256k1 ----------------
set(MIQ_LIBSECP_TARGET "")
if(MIQ_USE_LIBSECP)
  find_package(secp256k1 CONFIG QUIET)
  if(secp256k1_FOUND)
    if(TARGET secp256k1::secp256k1)
      set(MIQ_LIBSECP_TARGET secp256k1::secp256k1)
    elseif(TARGET secp256k1)
      set(MIQ_LIBSECP_TARGET secp256k1)
    endif()
  endif()
  if(NOT MIQ_LIBSECP_TARGET)
    message(STATUS "Fetching bitcoin-core/secp256k1 @ ${MIQ_LIBSECP_TAG}")
    set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
      secp256k1_src
      GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
      GIT_TAG        ${MIQ_LIBSECP_TAG}
      GIT_PROGRESS   TRUE
    )
    FetchContent_MakeAvailable(secp256k1_src)
    if(TARGET secp256k1::secp256k1)
      set(MIQ_LIBSECP_TARGET secp256k1::secp256k1)
    elseif(TARGET secp256k1)
      set(MIQ_LIBSECP_TARGET secp256k1)
    else()
      message(FATAL_ERROR "Fetched secp256k1 but no target named 'secp256k1'")
    endif()
  endif()
  add_compile_definitions(MIQ_USE_LIBSECP256K1=1)
endif()

# ---------------- OpenCL detection (GPU) ----------------
# We require BOTH headers and library; otherwise we don't define MIQ_ENABLE_OPENCL for targets.
set(MIQ_HAVE_OPENCL 0)
set(MIQ_OPENCL_NOTE "")

if(MIQ_ENABLE_OPENCL)
  find_package(OpenCL QUIET)

  # Fallback to CUDA Toolkit hints on Windows
  if(NOT OpenCL_FOUND)
    if(DEFINED ENV{CUDA_PATH})
      set(_OPENCL_HINT_INC "$ENV{CUDA_PATH}/include")
      set(_OPENCL_HINT_LIB "$ENV{CUDA_PATH}/lib/x64")
    elseif(WIN32)
      set(_OPENCL_HINT_INC "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v13.0/include")
      set(_OPENCL_HINT_LIB "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v13.0/lib/x64")
    endif()
    find_path(OpenCL_INCLUDE_DIR CL/cl.h HINTS ${_OPENCL_HINT_INC})
    find_library(OpenCL_LIBRARY NAMES OpenCL OpenCL.lib HINTS ${_OPENCL_HINT_LIB})
    if(OpenCL_INCLUDE_DIR AND OpenCL_LIBRARY)
      add_library(OpenCL::OpenCL UNKNOWN IMPORTED)
      set_target_properties(OpenCL::OpenCL PROPERTIES
        IMPORTED_LOCATION "${OpenCL_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${OpenCL_INCLUDE_DIR}")
      set(OpenCL_FOUND TRUE)
      set(MIQ_OPENCL_NOTE " (via CUDA Toolkit hints)")
    endif()
  endif()

  # Verify headers actually compile; if not, disable.
  if(OpenCL_FOUND)
    include(CheckCXXSourceCompiles)
    # Try both header paths in one test.
    set(CMAKE_REQUIRED_INCLUDES "${OpenCL_INCLUDE_DIRS};${OpenCL_INCLUDE_DIR}")
    set(CMAKE_REQUIRED_LIBRARIES "${OpenCL_LIBRARIES};${OpenCL_LIBRARY}")
    check_cxx_source_compiles("
      #if defined(__APPLE__)
      # include <OpenCL/opencl.h>
      #else
      # include <CL/cl.h>
      #endif
      int main(){ return 0; }
    " MIQ__OPENCL_OK)
    if(MIQ__OPENCL_OK)
      set(MIQ_HAVE_OPENCL 1)
      message(STATUS \"OpenCL found${MIQ_OPENCL_NOTE}. GPU miner support ENABLED.\")
    else()
      message(WARNING \"OpenCL library detected but headers not usable. GPU miner support DISABLED.\")
    endif()
  else()
    message(STATUS \"OpenCL not found. GPU miner support DISABLED (CPU path only).\")
  endif()
else()
  message(STATUS \"MIQ_ENABLE_OPENCL=OFF. Building without GPU support.\")
endif()

# ---------------- Core sources (shared) ----------------
set(MIQ_CORE_SOURCES_NO_NAT
    src/hd_wallet.cpp
    src/hd_wallet.h
    src/bip39_words_en.h
    src/addrman.h
    src/addrman.cpp
    src/address.h src/address.cpp
    src/wallet_store.h src/wallet_store.cpp
    src/reindex_utxo.h
    src/reindex_utxo.cpp
    src/ensure_utxo_reindex.cpp
    src/constants.h
    src/config.h src/config.cpp
    src/log.h src/log.cpp
    src/util.h src/util.cpp
    src/sha256.h src/sha256.cpp
    src/hex.h src/hex.cpp
    src/base58.h src/base58.cpp
    src/base58check.h src/base58check.cpp
    src/ripemd160.h src/ripemd160.cpp
    src/hash160.h src/hash160.cpp
    src/merkle.h src/merkle.cpp
    src/serialize.h src/serialize.cpp
    src/json.h src/json.cpp
    src/tx.h src/tx.cpp
    src/block.h src/block.cpp
    src/difficulty.h src/difficulty.cpp
    src/storage.h src/storage.cpp
    src/utxo.h src/utxo.cpp
    src/kvdb.h src/kvdb.cpp
    src/utxo_kv.h src/utxo_kv.cpp
    src/mempool.h src/mempool.cpp
    src/hasher.h src/hasher.cpp
    src/lut.h src/lut.cpp
    src/blockindex.h src/blockindex.cpp
    src/chain.h src/chain.cpp
    src/miner.h src/miner.cpp
    src/netmsg.h src/netmsg.cpp
    src/p2p.h src/p2p.cpp
    src/http.h src/http.cpp
    src/rpc.h src/rpc.cpp
    src/crypto/ecdsa_iface.h
    src/crypto/ecdsa_libsecp256k1.cpp
    src/reorg_manager.h
    src/reorg_manager.cpp
    src/seeds.cpp
    src/mtp.h
    src/mtp.cpp
    src/ibd_monitor.h src/ibd_monitor.cpp
    src/wallet_encryptor.cpp
    src/crypto/secure_random.cpp
    src/stratum/stratum_server.h src/stratum/stratum_server.cpp
    src/filters/bloom.h src/filters/bloom.cpp
)

add_library(miqcore STATIC ${MIQ_CORE_SOURCES_NO_NAT})
target_include_directories(miqcore PUBLIC src ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(miqcore PUBLIC ${MIQ_DB_TARGET} OpenSSL::Crypto Threads::Threads)
if(MIQ_DB_DEFINE)
  target_compile_definitions(miqcore PUBLIC ${MIQ_DB_DEFINE})
endif()
if(MIQ_USE_LIBSECP)
  target_link_libraries(miqcore PUBLIC ${MIQ_LIBSECP_TARGET})
endif()
if(WIN32)
  target_link_libraries(miqcore PUBLIC Ws2_32)
endif()

# ---------------- miniupnpc (daemon only) ----------------
set(_HAVE_MINIUPNPC OFF)
set(_MINIUPNPC_INC "")
set(_MINIUPNPC_LIBS "")

if(MIQ_ENABLE_UPNP)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(MINIUPNPC QUIET miniupnpc)
    if(MINIUPNPC_FOUND)
      set(_MINIUPNPC_INC  ${MINIUPNPC_INCLUDE_DIRS})
      set(_MINIUPNPC_LIBS ${MINIUPNPC_LINK_LIBRARIES})
      set(_HAVE_MINIUPNPC ON)
    endif()
  endif()
  if(NOT _HAVE_MINIUPNPC)
    find_path(MINIUPNPC_INCLUDE_DIR miniupnpc/miniupnpc.h)
    find_library(MINIUPNPC_LIBRARY NAMES miniupnpc)
    if(MINIUPNPC_INCLUDE_DIR AND MINIUPNPC_LIBRARY)
      set(_MINIUPNPC_INC  ${MINIUPNPC_INCLUDE_DIR})
      set(_MINIUPNPC_LIBS ${MINIUPNPC_LIBRARY})
      set(_HAVE_MINIUPNPC ON)
    endif()
  endif()
  if(NOT _HAVE_MINIUPNPC AND MIQ_FETCH_MINIUPNPC)
    message(STATUS "miniupnpc not found; fetching (network required)")
    FetchContent_Declare(
      miniupnpc_src
      GIT_REPOSITORY https://github.com/miniupnp/miniupnpc.git
      GIT_TAG        master
      GIT_PROGRESS   TRUE
    )
    FetchContent_MakeAvailable(miniupnpc_src)
    if(TARGET miniupnpc)
      set(_MINIUPNPC_LIBS miniupnpc)
    elseif(TARGET libminiupnpc-static)
      set(_MINIUPNPC_LIBS libminiupnpc-static)
    elseif(TARGET libminiupnpc)
      set(_MINIUPNPC_LIBS libminiupnpc)
    endif()
    if(TARGET miniupnpc OR TARGET libminiupnpc-static OR TARGET libminiupnpc)
      set(_MINIUPNPC_INC "${miniupnpc_src_SOURCE_DIR}/include")
      set(_HAVE_MINIUPNPC ON)
    endif()
  endif()
  if(_HAVE_MINIUPNPC)
    message(STATUS "UPnP enabled for daemon (miniupnpc detected)")
  else()
    message(WARNING "UPnP requested but miniupnpc not available; daemon will build WITHOUT UPnP.")
  endif()
else()
  message(STATUS "UPnP disabled for daemon.")
endif()

# ---------------- Daemon ----------------
add_executable(miqrod
  src/main.cpp
  src/nat.cpp
  src/tls_proxy.h src/tls_proxy.cpp
)
target_link_libraries(miqrod PRIVATE miqcore OpenSSL::SSL)

if(_HAVE_MINIUPNPC)
  target_compile_definitions(miqrod PRIVATE MIQ_ENABLE_UPNP=1)
  if(_MINIUPNPC_INC)
    target_include_directories(miqrod PRIVATE ${_MINIUPNPC_INC})
  endif()
  if(_MINIUPNPC_LIBS)
    target_link_libraries(miqrod PRIVATE ${_MINIUPNPC_LIBS})
  endif()
else()
  message(STATUS "UPnP disabled for daemon (miniupnpc not found)")
endif()

if(WIN32)
  target_link_libraries(miqrod PRIVATE ws2_32 iphlpapi bcrypt)
  target_compile_definitions(miqrod PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

# ---------------- Wallet CLI ----------------
set(MIQ_P2P_LIGHT_SRC "")
foreach(cand IN ITEMS
        src/p2p_light.cpp
        src/wallet/p2p_light.cpp
        src/light/p2p_light.cpp)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${cand}")
    list(APPEND MIQ_P2P_LIGHT_SRC "${cand}")
  endif()
endforeach()

add_executable(miqwallet
  src/cli/miqwallet.cpp
  src/nat.cpp
  ${MIQ_P2P_LIGHT_SRC}
  src/wallet/spv_simple.cpp
  src/wallet/http_client.cpp
)
target_include_directories(miqwallet PRIVATE src ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(miqwallet PRIVATE miqcore)
if(WIN32)
  target_link_libraries(miqwallet PRIVATE ws2_32 bcrypt)
  target_compile_definitions(miqwallet PRIVATE WIN32_LEAN_AND_MEAN NOMINMX)
endif()
set_target_properties(miqwallet PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)

# ---------------- Key tool ----------------
add_executable(miq-keygen src/tools/miq_keygen.cpp)
target_include_directories(miq-keygen PRIVATE src)
target_link_libraries(miq-keygen PRIVATE miqcore)
if(WIN32)
  target_link_libraries(miq-keygen PRIVATE bcrypt)
endif()

# ---------------- Miner app (stand-alone) ----------------
set(MIQ_MINER_SRC "")
foreach(cand IN ITEMS
        src/tools/miqminer.cpp
        src/cli/miqminer.cpp
        src/miqminer.cpp
        src/miner_app.cpp
        src/apps/miqminer.cpp)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${cand}")
    set(MIQ_MINER_SRC "${cand}")
    break()
  endif()
endforeach()

if(MIQ_MINER_SRC)
  add_executable(miqminer ${MIQ_MINER_SRC})
  target_include_directories(miqminer PRIVATE src ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(miqminer PRIVATE miqcore)
  if(WIN32)
    target_link_libraries(miqminer PRIVATE ws2_32 bcrypt)
    target_compile_definitions(miqminer PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  endif()
  if(MIQ_HAVE_OPENCL)
    target_compile_definitions(miqminer PRIVATE MIQ_ENABLE_OPENCL=1)
    target_link_libraries(miqminer PRIVATE OpenCL::OpenCL)
  endif()
  set_target_properties(miqminer PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
  message(STATUS "Building miner app from ${MIQ_MINER_SRC}")
else()
  message(STATUS "Miner app source not found. Put it at src/tools/miqminer.cpp (or one of the probed paths) to build miqminer.")
endif()

# ---------------- Miner RPC app (talks to node RPC) ----------------
set(MIQ_MINER_RPC_SRC "")
foreach(cand IN ITEMS
        src/cli/miqminer_rpc.cpp
        src/tools/miqminer_rpc.cpp
        src/miqminer_rpc.cpp)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${cand}")
    set(MIQ_MINER_RPC_SRC "${cand}")
    break()
  endif()
endforeach()

if(MIQ_MINER_RPC_SRC)
  add_executable(miqminer_rpc ${MIQ_MINER_RPC_SRC})
  target_include_directories(miqminer_rpc PRIVATE src ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(miqminer_rpc PRIVATE miqcore)
  if(WIN32)
    target_link_libraries(miqminer_rpc PRIVATE ws2_32 bcrypt)
    target_compile_definitions(miqminer_rpc PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  endif()
  if(MIQ_HAVE_OPENCL)
    target_compile_definitions(miqminer_rpc PRIVATE MIQ_ENABLE_OPENCL=1)
    target_link_libraries(miqminer_rpc PRIVATE OpenCL::OpenCL)
  endif()
  set_target_properties(miqminer_rpc PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
  message(STATUS "Building miner RPC app from ${MIQ_MINER_RPC_SRC}")
else()
  message(STATUS "RPC miner source not found (src/cli/miqminer_rpc.cpp or similar). Skipping miqminer_rpc.")
endif()

# ---------------- Tests (optional) ----------------
if(MIQ_BUILD_TESTS)
  enable_testing()
  add_executable(test_crypto tests/test_crypto.cpp)
  target_include_directories(test_crypto PRIVATE src)
  target_link_libraries(test_crypto PRIVATE miqcore)
  if(WIN32)
    target_link_libraries(test_crypto PRIVATE Ws2_32)
  endif()
  add_test(NAME test_crypto COMMAND test_crypto)

  add_executable(test_ser tests/test_ser.cpp)
  target_include_directories(test_ser PRIVATE src)
  target_link_libraries(test_ser PRIVATE miqcore)
  add_test(NAME test_ser COMMAND test_ser)
endif()

# ---------------- Wallet encryption flag note ----------------
if(MIQ_ENABLE_WALLET_ENC)
  target_compile_definitions(miqcore PUBLIC MIQ_ENABLE_WALLET_ENC=1)
  message(STATUS "Wallet encryption: ENABLED (OpenSSL)")
else()
  message(STATUS "Wallet encryption: DISABLED (default)")
endif()
