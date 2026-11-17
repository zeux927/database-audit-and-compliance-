#include "authentication.h"
#include "audit.h"
#include "database.h"
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <map>
#include <mutex>
#include <random>

namespace Auth {

// ---------------------------------------------------------------- SHA-256
static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

std::string sha256(const std::string& data) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

    std::string msg = data;
    uint64_t bitLen = (uint64_t)data.size() * 8;
    msg += (char)0x80;
    while (msg.size() % 64 != 56) msg += (char)0;
    for (int i = 7; i >= 0; --i) msg += (char)((bitLen >> (i * 8)) & 0xff);

    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint32_t)(unsigned char)msg[off + i*4] << 24) | ((uint32_t)(unsigned char)msg[off + i*4+1] << 16) |
                   ((uint32_t)(unsigned char)msg[off + i*4+2] << 8) |  (uint32_t)(unsigned char)msg[off + i*4+3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19)  ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    char buf[65];
    for (int i = 0; i < 8; ++i) snprintf(buf + i*8, 9, "%08x", h[i]);
    return std::string(buf);
}

std::string hashPassword(const std::string& username, const std::string& password) {
    return sha256(username + ":" + password);   // username acts as a simple salt
}

// --------------------------------------------------------------- Defaults
const char* defaultPasswordFor(const std::string& username) {
    if (username == "admin")   return "admin123";
    if (username == "auditor") return "auditor123";
    if (username == "user1")   return "user123";
    return nullptr;
}

void seedDefaultUsers() {
    Rows r = g_db.query("SELECT COUNT(*) AS n FROM users");
    if (!r.empty() && r[0]["n"] != "0") return;
    const char* names[3] = {"admin", "auditor", "user1"};
    const char* roles[3] = {"admin", "auditor", "user"};
    for (int i = 0; i < 3; ++i)
        g_db.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                     {names[i], hashPassword(names[i], defaultPasswordFor(names[i])), roles[i]});
}

// --------------------------------------------------------------- Sessions
struct SessionData { Session s; time_t last; };
static std::map<std::string, SessionData> g_sessions;
static std::mutex g_mtx;
static const int IDLE_TIMEOUT_SEC = 30 * 60;
static const int MAX_FAILED = 3;

static std::string makeToken() {
    static std::random_device rd;
    std::mt19937_64 gen(rd());
    char b[40];
    snprintf(b, sizeof b, "%016llx%016llx", (unsigned long long)gen(), (unsigned long long)gen());
    return b;
}

std::string login(const std::string& username, const std::string& password,
                  const std::string& ip, std::string& msg, Session& out) {
    Rows r = g_db.query("SELECT role, password_hash, failed_attempts, locked FROM users WHERE username=?",
                        {username});
    if (r.empty()) {
        Audit::log(username, "", "LOGIN", "users", "", "Unknown username", "FAILURE", ip);
        msg = "Invalid username or password";
        return "";
    }
    const std::string role = r[0]["role"];
    if (r[0]["locked"] == "1") {
        Audit::log(username, role, "LOGIN", "users", "", "Account is locked", "DENIED", ip);
        msg = "Account locked after too many failed attempts. Ask an admin to unlock it.";
        return "";
    }
    if (hashPassword(username, password) != r[0]["password_hash"]) {
        int fails = std::stoi(r[0]["failed_attempts"]) + 1;
        bool lock = fails >= MAX_FAILED;
        g_db.execute("UPDATE users SET failed_attempts=?, locked=? WHERE username=?",
                     {std::to_string(fails), lock ? "1" : "0", username});
        Audit::log(username, role, "LOGIN", "users", "",
                   "Wrong password (attempt " + std::to_string(fails) + ")" + (lock ? " - ACCOUNT LOCKED" : ""),
                   "FAILURE", ip);
        msg = lock ? "Account locked after 3 failed attempts." : "Invalid username or password";
        return "";
    }
    g_db.execute("UPDATE users SET failed_attempts=0 WHERE username=?", {username});
    out = {username, role};
    std::string token = makeToken();
    { std::lock_guard<std::mutex> l(g_mtx); g_sessions[token] = {out, time(nullptr)}; }
    Audit::log(username, role, "LOGIN", "users", "", "Login successful", "SUCCESS", ip);
    return token;
}

bool validate(const std::string& token, Session& out) {
    std::lock_guard<std::mutex> l(g_mtx);
    auto it = g_sessions.find(token);
    if (it == g_sessions.end()) return false;
    time_t now = time(nullptr);
    if (now - it->second.last > IDLE_TIMEOUT_SEC) { g_sessions.erase(it); return false; }
    it->second.last = now;
    out = it->second.s;
    return true;
}

void logout(const std::string& token) {
    Session s;
    bool had = false;
    { std::lock_guard<std::mutex> l(g_mtx);
      auto it = g_sessions.find(token);
      if (it != g_sessions.end()) { s = it->second.s; had = true; g_sessions.erase(it); } }
    if (had) Audit::log(s.username, s.role, "LOGOUT", "users", "", "User logged out", "SUCCESS", "");
}

}
