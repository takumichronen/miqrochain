#include "http_client.h"

#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cerrno>

#ifdef _WIN32
  #ifndef NOMINMAX
  #define NOMINMAX 1
  #endif
  #define _WINSOCK_DEPRECATED_NO_WARNINGS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
  using sock_t = SOCKET;
  static bool wsa_inited = false;
  static void wsa_ensure(){
      if(!wsa_inited){
          WSADATA w;
          if (WSAStartup(MAKEWORD(2,2), &w) == 0) {
              wsa_inited = true;
          }
      }
  }
  #define SOCK_INVALID INVALID_SOCKET
  #define SOCK_ERROR(fd) ((fd) == INVALID_SOCKET)
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <arpa/inet.h>
  #include <poll.h>
  using sock_t = int;
  #define closesocket ::close
  #define SOCK_INVALID (-1)
  #define SOCK_ERROR(fd) ((fd) < 0)
#endif

namespace miq {

// =============================================================================
// BULLETPROOF HTTP CLIENT v1.0 - Production-grade HTTP with robust error handling
// =============================================================================static inline std::string lc(std::string s){

[[maybe_unused]] static inline std::string lc(std::string s){
    for(char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// IMPROVED: Set socket timeouts with validation
static bool set_timeout(sock_t fd, int ms){
    if (ms <= 0) ms = 5000;  // Default 5 second timeout
#ifdef _WIN32
    DWORD tv = (DWORD)ms;
    bool ok = (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) == 0);
    ok = ok && (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) == 0);
    return ok;
#else
    timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    bool ok = (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
    ok = ok && (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0);
    return ok;
#endif
}

// NEW: Set socket to non-blocking mode
static bool set_nonblocking(sock_t fd, bool enable) {
#ifdef _WIN32
    u_long mode = enable ? 1 : 0;
    return (ioctlsocket(fd, FIONBIO, &mode) == 0);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    if (enable) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    return (fcntl(fd, F_SETFL, flags) == 0);
#endif
}

// NEW: Connect with timeout using non-blocking socket
static bool connect_with_timeout(sock_t fd, const sockaddr* addr, socklen_t addrlen, int timeout_ms) {
    // Set non-blocking
    if (!set_nonblocking(fd, true)) {
        return false;
    }

    // Attempt connect
    int result = connect(fd, addr, addrlen);
    if (result == 0) {
        // Connected immediately
        set_nonblocking(fd, false);
        return true;
    }

#ifdef _WIN32
    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        return false;
    }
#else
    if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
        return false;
    }
#endif

    // Wait for connection with timeout
#ifdef _WIN32
    fd_set writefds, exceptfds;
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET(fd, &writefds);
    FD_SET(fd, &exceptfds);

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    result = select((int)(fd + 1), nullptr, &writefds, &exceptfds, &tv);
    if (result <= 0) {
        return false;  // Timeout or error
    }

    if (FD_ISSET(fd, &exceptfds)) {
        return false;  // Connection failed
    }
#else
    pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    result = poll(&pfd, 1, timeout_ms);
    if (result <= 0) {
        return false;  // Timeout or error
    }

    if (pfd.revents & (POLLERR | POLLHUP)) {
        return false;  // Connection failed
    }
#endif

    // Check if connection succeeded
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&error, &len) != 0 || error != 0) {
        return false;
    }

    // Set back to blocking mode
    set_nonblocking(fd, false);
    return true;
}

// IMPROVED: HTTP POST with robust connection handling and timeout
bool http_post(const std::string& host,
               uint16_t port,
               const std::string& path,
               const std::string& body,
               const std::vector<std::pair<std::string,std::string>>& headers,
               HttpResponse& out,
               int timeout_ms)
{
    // Initialize output
    out.code = 0;
    out.body.clear();
    out.headers.clear();

    // Validate inputs
    if (host.empty()) return false;
    if (timeout_ms <= 0) timeout_ms = 5000;

#ifdef _WIN32
    wsa_ensure();
#endif

    // DNS resolution
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portbuf[16];
    std::snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);

    addrinfo* res = nullptr;
    int dns_result = getaddrinfo(host.c_str(), portbuf, &hints, &res);
    if (dns_result != 0 || !res) {
        return false;  // DNS resolution failed
    }

    // Try each address until one succeeds
    sock_t fd = SOCK_INVALID;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (SOCK_ERROR(fd)) continue;

        // Enable TCP keepalive for long connections
        int keepalive = 1;
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));

        // Use non-blocking connect with timeout
        if (connect_with_timeout(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen, timeout_ms)) {
            // Set timeouts for send/recv after successful connect
            set_timeout(fd, timeout_ms);
            break;  // Connected successfully!
        }

        closesocket(fd);
        fd = SOCK_INVALID;
    }
    freeaddrinfo(res);

    if (SOCK_ERROR(fd)) {
        return false;  // All addresses failed
    }

    // Build HTTP request
    std::string req;
    req.reserve(512 + body.size());
    req += "POST " + (path.empty() ? std::string("/") : path) + " HTTP/1.1\r\n";
    req += "Host: " + host + ":" + std::to_string(port) + "\r\n";
    req += "Content-Type: application/json\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "Accept: application/json\r\n";
    req += "User-Agent: MIQWallet/1.0\r\n";

    for (const auto& h : headers) {
        req += h.first;
        req += ": ";
        req += h.second;
        req += "\r\n";
    }
    req += "Connection: close\r\n\r\n";
    req += body;

    // Send request with retry on EINTR
    const char* p = req.data();
    size_t left = req.size();
    int send_retries = 3;

    while (left > 0 && send_retries > 0) {
#ifdef _WIN32
        int n = send(fd, p, (int)left, 0);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                --send_retries;
                continue;
            }
            closesocket(fd);
            return false;
        }
#else
        ssize_t n = ::send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR) continue;  // Retry on interrupt
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                --send_retries;
                continue;
            }
            closesocket(fd);
            return false;
        }
#endif
        if (n <= 0) {
            closesocket(fd);
            return false;
        }
        p += n;
        left -= (size_t)n;
    }

    if (left > 0) {
        closesocket(fd);
        return false;  // Failed to send all data
    }

    // Receive response with buffer management
    std::string buf;
    buf.reserve(8192);
    char tmp[8192];
    int recv_retries = 3;
    bool recv_done = false;

    while (!recv_done && recv_retries > 0) {
#ifdef _WIN32
        int n = recv(fd, tmp, (int)sizeof(tmp), 0);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                --recv_retries;
                continue;
            }
            break;  // Other error, stop receiving
        }
#else
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n < 0) {
            if (errno == EINTR) continue;  // Retry on interrupt
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                --recv_retries;
                continue;
            }
            break;  // Other error, stop receiving
        }
#endif
        if (n == 0) {
            recv_done = true;  // Connection closed cleanly
            break;
        }
        buf.append(tmp, (size_t)n);

        // Safety: prevent unbounded memory growth
        if (buf.size() > 16 * 1024 * 1024) {  // 16MB limit
            break;
        }
    }
    closesocket(fd);

    // Parse HTTP response
    if (buf.empty()) return false;

    // Find status line
    size_t pos = buf.find("\r\n");
    if (pos == std::string::npos) return false;

    std::string status = buf.substr(0, pos);
    int code = 0;
    {
        size_t sp = status.find(' ');
        if (sp != std::string::npos) {
            code = std::atoi(status.c_str() + sp + 1);
        }
    }

    // Find header/body separator
    size_t hdr_end = buf.find("\r\n\r\n");
    if (hdr_end == std::string::npos) return false;

    // Parse headers
    std::map<std::string, std::string> hdrs;
    size_t cur = pos + 2;
    while (cur < hdr_end) {
        size_t nl = buf.find("\r\n", cur);
        if (nl == std::string::npos || nl > hdr_end) break;

        std::string line = buf.substr(cur, nl - cur);
        cur = nl + 2;

        size_t c = line.find(':');
        if (c != std::string::npos) {
            std::string k = line.substr(0, c);
            std::string v = line.substr(c + 1);
            // Trim whitespace
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(v.begin());
            while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.pop_back();
            // Lowercase header name
            std::transform(k.begin(), k.end(), k.begin(), [](unsigned char x) { return std::tolower(x); });
            hdrs[k] = v;
        }
    }

    // Extract body
    std::string body_out = buf.substr(hdr_end + 4);

    out.code = code;
    out.body = std::move(body_out);
    out.headers = std::move(hdrs);
    return true;
}

}
