#include "audit.h"
#include "authentication.h"

namespace Audit {

void log(const std::string& user, const std::string& role, const std::string& action,
         const std::string& table, const std::string& recordId,
         const std::string& details, const std::string& status, const std::string& ip) {
    g_db.execute("INSERT INTO audit_log (username, role, action, table_name, record_id, details, status, ip_address) "
                 "VALUES (?,?,?,?,?,?,?,?)",
                 {user, role, action, table, recordId, details, status, ip});
}

Rows getLogs(const std::string& user, const std::string& action, const std::string& status, int limit) {
    std::string sql = "SELECT id, ts, username, role, action, table_name, record_id, details, status, ip_address "
                      "FROM audit_log WHERE 1=1";
    std::vector<std::string> p;
    if (!user.empty())   { sql += " AND username LIKE ?"; p.push_back("%" + user + "%"); }
    if (!action.empty()) { sql += " AND action = ?";      p.push_back(action); }
    if (!status.empty()) { sql += " AND status = ?";      p.push_back(status); }
    if (limit < 1 || limit > 1000) limit = 200;
    sql += " ORDER BY id DESC LIMIT " + std::to_string(limit);
    return g_db.query(sql, p);
}

Rows getDataChanges(int limit) {
    if (limit < 1 || limit > 1000) limit = 200;
    return g_db.query("SELECT id, ts, table_name, record_id, operation, old_value, new_value "
                      "FROM data_change_log ORDER BY id DESC LIMIT " + std::to_string(limit));
}

static Row mk(const std::string& check, const std::string& status, const std::string& detail) {
    return Row{{"check", check}, {"status", status}, {"detail", detail}};
}

static std::string joinRows(const Rows& r, const std::string& nameCol, const std::string& countCol) {
    std::string s;
    for (const auto& x : r) {
        if (!s.empty()) s += "; ";
        s += x.at(nameCol) + " (" + x.at(countCol) + ")";
    }
    return s;
}

Rows complianceReport() {
    Rows out;
    Rows r;

    // 1. Brute-force / repeated failed logins
    r = g_db.query("SELECT username, COUNT(*) AS c FROM audit_log "
                   "WHERE action='LOGIN' AND status='FAILURE' GROUP BY username HAVING c >= 3");
    out.push_back(r.empty() ? mk("Repeated failed logins", "PASS", "No account has 3 or more failed logins.")
                            : mk("Repeated failed logins", "FAIL", "Possible brute-force: " + joinRows(r, "username", "c")));

    // 2. Locked accounts
    r = g_db.query("SELECT username, failed_attempts AS c FROM users WHERE locked=1");
    out.push_back(r.empty() ? mk("Locked accounts", "PASS", "No locked accounts.")
                            : mk("Locked accounts", "WARN", "Locked: " + joinRows(r, "username", "c")));

    // 3. Unauthorized access attempts
    r = g_db.query("SELECT username, COUNT(*) AS c FROM audit_log WHERE status='DENIED' AND action!='LOGIN' GROUP BY username");
    out.push_back(r.empty() ? mk("Unauthorized access attempts", "PASS", "No permission violations recorded.")
                            : mk("Unauthorized access attempts", "WARN", "Denied actions: " + joinRows(r, "username", "c")));

    // 4. Bulk deletions
    r = g_db.query("SELECT username, COUNT(*) AS c FROM audit_log WHERE action='DELETE_EMPLOYEE' AND status='SUCCESS' "
                   "GROUP BY username HAVING c >= 3");
    out.push_back(r.empty() ? mk("Bulk deletions", "PASS", "No user deleted 3 or more records.")
                            : mk("Bulk deletions", "WARN", "Many deletions by: " + joinRows(r, "username", "c")));

    // 5. Large salary changes (> 20 %)
    r = g_db.query("SELECT username, COUNT(*) AS c FROM audit_log WHERE action='HIGH_SALARY_CHANGE' GROUP BY username");
    out.push_back(r.empty() ? mk("Large salary changes (>20%)", "PASS", "No suspicious salary changes.")
                            : mk("Large salary changes (>20%)", "WARN", "Review changes by: " + joinRows(r, "username", "c")));

    // 6. After-hours modifications (before 06:00 or after 22:00)
    r = g_db.query("SELECT username, COUNT(*) AS c FROM audit_log "
                   "WHERE action IN ('ADD_EMPLOYEE','UPDATE_EMPLOYEE','DELETE_EMPLOYEE') AND status='SUCCESS' "
                   "AND (time(ts) < '06:00:00' OR time(ts) >= '22:00:00') GROUP BY username");
    out.push_back(r.empty() ? mk("After-hours data changes", "PASS", "No changes outside 06:00-22:00.")
                            : mk("After-hours data changes", "WARN", "Changes outside working hours: " + joinRows(r, "username", "c")));

    // 7. Default passwords still in use
    Rows users = g_db.query("SELECT username, password_hash FROM users");
    std::string bad;
    for (const auto& u : users) {
        const char* def = Auth::defaultPasswordFor(u.at("username"));
        if (def && Auth::hashPassword(u.at("username"), def) == u.at("password_hash")) {
            if (!bad.empty()) bad += ", ";
            bad += u.at("username");
        }
    }
    out.push_back(bad.empty() ? mk("Default passwords", "PASS", "No account uses a default password.")
                              : mk("Default passwords", "FAIL", "Still using the default password: " + bad));

    // 8. Audit-log integrity (append-only triggers present + no missing IDs)
    r = g_db.query("SELECT COUNT(*) AS n FROM sqlite_master WHERE type='trigger' "
                   "AND name IN ('trg_audit_no_update','trg_audit_no_delete')");
    bool trig = !r.empty() && r[0]["n"] == "2";
    r = g_db.query("SELECT COUNT(*) AS n, IFNULL(MAX(id),0) AS m FROM audit_log");
    bool gaps = !r.empty() && r[0]["n"] != r[0]["m"];
    if (!trig)      out.push_back(mk("Audit-log integrity", "FAIL", "Append-only triggers are missing - the log can be tampered with."));
    else if (gaps)  out.push_back(mk("Audit-log integrity", "FAIL", "Gaps in audit_log IDs - entries may have been deleted."));
    else            out.push_back(mk("Audit-log integrity", "PASS", "Append-only triggers active and no gaps in log IDs."));

    return out;
}

}
