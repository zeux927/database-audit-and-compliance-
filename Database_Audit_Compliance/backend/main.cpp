// Database Audit & Compliance - backend entry point
// Build : g++ -std=c++17 -O2 -o audit_server *.cpp -lsqlite3 -pthread
// Run   : ./audit_server            (from inside the backend/ folder)
// Open  : http://localhost:8080

#include "httplib.h"
#include "audit.h"
#include "authentication.h"
#include "database.h"
#include "operations.h"
#include <iostream>

static void send(httplib::Response& res, const Result& r) {
    res.status = r.status;
    res.set_content(r.body, "application/json");
}

static int toInt(const std::string& s, int def) {
    try { return s.empty() ? def : std::stoi(s); } catch (...) { return def; }
}

int main(int argc, char* argv[]) {
    const std::string root = (argc > 1) ? argv[1] : "..";   // project root

    if (!g_db.open(root + "/database/audit.db")) {
        std::cerr << "Cannot open database: " << g_db.lastError() << "\n";
        return 1;
    }
    if (!g_db.runScriptFile(root + "/database/audit.sql")) {
        std::cerr << "Cannot run audit.sql: " << g_db.lastError() << "\n";
        return 1;
    }
    Auth::seedDefaultUsers();

    httplib::Server svr;
    svr.set_mount_point("/", root + "/frontend");           // serves index.html, style.css, script.js

    // Reads the X-Auth-Token header; replies 401 if the session is missing/expired.
    auto guard = [](const httplib::Request& req, httplib::Response& res, Session& s) {
        if (Auth::validate(req.get_header_value("X-Auth-Token"), s)) return true;
        send(res, {401, msgJson(false, "Not logged in or session expired.")});
        return false;
    };
    auto P = [](const httplib::Request& req, const char* k) { return req.get_param_value(k); };

    // ---------------------------------------------------------- auth
    svr.Post("/api/login", [&](const httplib::Request& req, httplib::Response& res) {
        std::string msg; Session s;
        std::string token = Auth::login(P(req, "username"), P(req, "password"), req.remote_addr, msg, s);
        if (token.empty()) { send(res, {401, msgJson(false, msg)}); return; }
        send(res, {200, "{\"ok\":true,\"token\":\"" + token + "\",\"username\":\"" + jsonEscape(s.username) +
                        "\",\"role\":\"" + s.role + "\"}"});
    });
    svr.Post("/api/logout", [&](const httplib::Request& req, httplib::Response& res) {
        Auth::logout(req.get_header_value("X-Auth-Token"));
        send(res, {200, msgJson(true, "Logged out.")});
    });

    // ----------------------------------------------------- employees
    svr.Get("/api/employees", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::listEmployees(s, req.remote_addr, P(req, "search")));
    });
    svr.Post("/api/employees/add", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::addEmployee(s, req.remote_addr, P(req, "name"), P(req, "department"),
                                   P(req, "email"), P(req, "salary")));
    });
    svr.Post("/api/employees/update", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::updateEmployee(s, req.remote_addr, P(req, "id"), P(req, "name"), P(req, "department"),
                                      P(req, "email"), P(req, "salary")));
    });
    svr.Post("/api/employees/delete", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::deleteEmployee(s, req.remote_addr, P(req, "id")));
    });

    // ------------------------------------------- audit & compliance
    svr.Get("/api/audit", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::viewAudit(s, req.remote_addr, P(req, "user"), P(req, "action"),
                                 P(req, "status"), toInt(P(req, "limit"), 200)));
    });
    svr.Get("/api/changes", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::viewChanges(s, req.remote_addr, toInt(P(req, "limit"), 200)));
    });
    svr.Get("/api/compliance", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::compliance(s, req.remote_addr));
    });

    // ----------------------------------------------------------- users
    svr.Get("/api/users", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::listUsers(s, req.remote_addr));
    });
    svr.Post("/api/users/add", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::createUser(s, req.remote_addr, P(req, "username"), P(req, "password"), P(req, "role")));
    });
    svr.Post("/api/users/unlock", [&](const httplib::Request& req, httplib::Response& res) {
        Session s; if (!guard(req, res, s)) return;
        send(res, Ops::unlockUser(s, req.remote_addr, P(req, "username")));
    });

    std::cout << "Database Audit & Compliance server running.\n"
              << "Open  http://localhost:8080  in your browser (Ctrl+C to stop)\n";
    if (!svr.listen("127.0.0.1", 8080)) {
        std::cerr << "Could not start server - is port 8080 already in use?\n";
        return 1;
    }
    return 0;
}
