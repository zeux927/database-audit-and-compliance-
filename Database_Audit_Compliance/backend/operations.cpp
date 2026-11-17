#include "operations.h"
#include "audit.h"
#include "authorization.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>

// ------------------------------------------------------------ JSON helpers
std::string jsonEscape(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o += (char)c;
        }
    }
    return o;
}

std::string rowsToJson(const Rows& rows) {
    std::string o = "[";
    bool firstRow = true;
    for (const auto& r : rows) {
        if (!firstRow) o += ",";
        firstRow = false;
        o += "{";
        bool first = true;
        for (const auto& kv : r) {
            if (!first) o += ",";
            first = false;
            o += "\"" + jsonEscape(kv.first) + "\":\"" + jsonEscape(kv.second) + "\"";
        }
        o += "}";
    }
    return o + "]";
}

std::string msgJson(bool ok, const std::string& message) {
    return std::string("{\"ok\":") + (ok ? "true" : "false") + ",\"message\":\"" + jsonEscape(message) + "\"}";
}

static Result dataResult(const Rows& rows) {
    return {200, "{\"ok\":true,\"data\":" + rowsToJson(rows) + "}"};
}

// ----------------------------------------------------------------- helpers
// Returns true (and fills r) if the role is NOT allowed. The attempt is logged as DENIED.
static bool denied(const Session& s, const std::string& perm, const std::string& table,
                   const std::string& ip, Result& r) {
    if (Authz::isAllowed(s.role, perm)) return false;
    Audit::log(s.username, s.role, perm, table, "", "Permission denied for role '" + s.role + "'", "DENIED", ip);
    r = {403, msgJson(false, "Access denied: your role (" + s.role + ") cannot perform this action.")};
    return true;
}

static bool parseSalary(const std::string& txt, double& v) {
    char* end = nullptr;
    v = strtod(txt.c_str(), &end);
    return !txt.empty() && end && *end == '\0' && v >= 0 && std::isfinite(v);
}

static std::string validateEmployee(const std::string& name, const std::string& dept,
                                    const std::string& email, const std::string& salary, double& sal) {
    if (name.empty() || name.size() > 100) return "Name is required (max 100 characters).";
    if (dept.empty() || dept.size() > 50)  return "Department is required (max 50 characters).";
    if (email.find('@') == std::string::npos || email.size() > 100) return "A valid email is required.";
    if (!parseSalary(salary, sal)) return "Salary must be a non-negative number.";
    return "";
}

// =========================================================== EMPLOYEES
namespace Ops {

Result listEmployees(const Session& s, const std::string& ip, const std::string& search) {
    Result r;
    if (denied(s, "VIEW_EMPLOYEES", "employees", ip, r)) return r;
    Rows rows = g_db.query("SELECT id, name, department, email, salary FROM employees "
                           "WHERE name LIKE ? OR department LIKE ? ORDER BY id",
                           {"%" + search + "%", "%" + search + "%"});
    Audit::log(s.username, s.role, "VIEW_EMPLOYEES", "employees", "",
               "Viewed " + std::to_string(rows.size()) + " record(s)", "SUCCESS", ip);
    return dataResult(rows);
}

Result addEmployee(const Session& s, const std::string& ip, const std::string& name,
                   const std::string& dept, const std::string& email, const std::string& salary) {
    Result r;
    if (denied(s, "ADD_EMPLOYEE", "employees", ip, r)) return r;
    double sal;
    std::string err = validateEmployee(name, dept, email, salary, sal);
    if (!err.empty()) {
        Audit::log(s.username, s.role, "ADD_EMPLOYEE", "employees", "", "Validation failed: " + err, "FAILURE", ip);
        return {400, msgJson(false, err)};
    }
    long long id = 0;
    if (!g_db.execute("INSERT INTO employees (name, department, email, salary) VALUES (?,?,?,?)",
                      {name, dept, email, salary}, &id)) {
        Audit::log(s.username, s.role, "ADD_EMPLOYEE", "employees", "", "DB error: " + g_db.lastError(), "FAILURE", ip);
        return {400, msgJson(false, "Could not add employee (is the email already used?)")};
    }
    Audit::log(s.username, s.role, "ADD_EMPLOYEE", "employees", std::to_string(id),
               "Added " + name + " (" + dept + ", salary " + salary + ")", "SUCCESS", ip);
    return {200, msgJson(true, "Employee added.")};
}

Result updateEmployee(const Session& s, const std::string& ip, const std::string& id,
                      const std::string& name, const std::string& dept,
                      const std::string& email, const std::string& salary) {
    Result r;
    if (denied(s, "UPDATE_EMPLOYEE", "employees", ip, r)) return r;
    double sal;
    std::string err = validateEmployee(name, dept, email, salary, sal);
    if (!err.empty()) {
        Audit::log(s.username, s.role, "UPDATE_EMPLOYEE", "employees", id, "Validation failed: " + err, "FAILURE", ip);
        return {400, msgJson(false, err)};
    }
    Rows old = g_db.query("SELECT name, department, email, salary FROM employees WHERE id=?", {id});
    if (old.empty()) {
        Audit::log(s.username, s.role, "UPDATE_EMPLOYEE", "employees", id, "Record not found", "FAILURE", ip);
        return {404, msgJson(false, "Employee not found.")};
    }
    if (!g_db.execute("UPDATE employees SET name=?, department=?, email=?, salary=? WHERE id=?",
                      {name, dept, email, salary, id})) {
        Audit::log(s.username, s.role, "UPDATE_EMPLOYEE", "employees", id, "DB error: " + g_db.lastError(), "FAILURE", ip);
        return {400, msgJson(false, "Could not update employee (is the email already used?)")};
    }
    double oldSal = strtod(old[0]["salary"].c_str(), nullptr);
    Audit::log(s.username, s.role, "UPDATE_EMPLOYEE", "employees", id,
               "Updated " + old[0]["name"] + " (salary " + old[0]["salary"] + " -> " + salary + ")", "SUCCESS", ip);
    if (oldSal > 0 && std::fabs(sal - oldSal) / oldSal > 0.20)
        Audit::log(s.username, s.role, "HIGH_SALARY_CHANGE", "employees", id,
                   "Salary changed by more than 20%: " + old[0]["salary"] + " -> " + salary, "SUCCESS", ip);
    return {200, msgJson(true, "Employee updated.")};
}

Result deleteEmployee(const Session& s, const std::string& ip, const std::string& id) {
    Result r;
    if (denied(s, "DELETE_EMPLOYEE", "employees", ip, r)) return r;
    Rows old = g_db.query("SELECT name, department FROM employees WHERE id=?", {id});
    if (old.empty()) {
        Audit::log(s.username, s.role, "DELETE_EMPLOYEE", "employees", id, "Record not found", "FAILURE", ip);
        return {404, msgJson(false, "Employee not found.")};
    }
    if (!g_db.execute("DELETE FROM employees WHERE id=?", {id})) {
        Audit::log(s.username, s.role, "DELETE_EMPLOYEE", "employees", id, "DB error: " + g_db.lastError(), "FAILURE", ip);
        return {500, msgJson(false, "Delete failed.")};
    }
    Audit::log(s.username, s.role, "DELETE_EMPLOYEE", "employees", id,
               "Deleted " + old[0]["name"] + " (" + old[0]["department"] + ")", "SUCCESS", ip);
    return {200, msgJson(true, "Employee deleted.")};
}

// ======================================================= AUDIT / COMPLIANCE
Result viewAudit(const Session& s, const std::string& ip, const std::string& user,
                 const std::string& action, const std::string& status, int limit) {
    Result r;
    if (denied(s, "VIEW_AUDIT", "audit_log", ip, r)) return r;
    Rows rows = Audit::getLogs(user, action, status, limit);
    Audit::log(s.username, s.role, "VIEW_AUDIT", "audit_log", "", "Viewed audit log", "SUCCESS", ip);
    return dataResult(rows);
}

Result viewChanges(const Session& s, const std::string& ip, int limit) {
    Result r;
    if (denied(s, "VIEW_AUDIT", "data_change_log", ip, r)) return r;
    return dataResult(Audit::getDataChanges(limit));
}

Result compliance(const Session& s, const std::string& ip) {
    Result r;
    if (denied(s, "RUN_COMPLIANCE", "audit_log", ip, r)) return r;
    Rows rows = Audit::complianceReport();
    Audit::log(s.username, s.role, "RUN_COMPLIANCE", "audit_log", "", "Compliance report generated", "SUCCESS", ip);
    return dataResult(rows);
}

// ================================================================= USERS
Result listUsers(const Session& s, const std::string& ip) {
    Result r;
    if (denied(s, "MANAGE_USERS", "users", ip, r)) return r;
    return dataResult(g_db.query("SELECT id, username, role, failed_attempts, locked, created_at FROM users ORDER BY id"));
}

Result createUser(const Session& s, const std::string& ip, const std::string& username,
                  const std::string& password, const std::string& role) {
    Result r;
    if (denied(s, "MANAGE_USERS", "users", ip, r)) return r;
    std::string err;
    if (username.size() < 3 || username.size() > 30) err = "Username must be 3-30 characters.";
    for (char c : username) if (!isalnum((unsigned char)c) && c != '_') err = "Username may only contain letters, digits and _.";
    if (password.size() < 8) err = "Password must be at least 8 characters.";
    if (role != "admin" && role != "user" && role != "auditor") err = "Role must be admin, user or auditor.";
    if (!err.empty()) {
        Audit::log(s.username, s.role, "CREATE_USER", "users", "", "Validation failed: " + err, "FAILURE", ip);
        return {400, msgJson(false, err)};
    }
    long long id = 0;
    if (!g_db.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                      {username, Auth::hashPassword(username, password), role}, &id)) {
        Audit::log(s.username, s.role, "CREATE_USER", "users", "", "Username already exists: " + username, "FAILURE", ip);
        return {400, msgJson(false, "Username already exists.")};
    }
    Audit::log(s.username, s.role, "CREATE_USER", "users", std::to_string(id),
               "Created user '" + username + "' with role " + role, "SUCCESS", ip);   // never log passwords
    return {200, msgJson(true, "User created.")};
}

Result unlockUser(const Session& s, const std::string& ip, const std::string& username) {
    Result r;
    if (denied(s, "MANAGE_USERS", "users", ip, r)) return r;
    if (g_db.query("SELECT 1 FROM users WHERE username=?", {username}).empty())
        return {404, msgJson(false, "User not found.")};
    g_db.execute("UPDATE users SET locked=0, failed_attempts=0 WHERE username=?", {username});
    Audit::log(s.username, s.role, "UNLOCK_USER", "users", "", "Unlocked account '" + username + "'", "SUCCESS", ip);
    return {200, msgJson(true, "Account unlocked.")};
}

}
