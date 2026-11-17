#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <string>

struct Session {
    std::string username;
    std::string role;
};

namespace Auth {
    std::string sha256(const std::string& data);
    std::string hashPassword(const std::string& username, const std::string& password);

    void seedDefaultUsers();                       // creates admin/auditor/user1 on first run
    const char* defaultPasswordFor(const std::string& username);  // for the compliance check

    // Returns a session token on success, "" on failure (reason in msg).
    std::string login(const std::string& username, const std::string& password,
                      const std::string& ip, std::string& msg, Session& out);
    bool validate(const std::string& token, Session& out);   // also refreshes idle timer
    void logout(const std::string& token);
}

#endif
