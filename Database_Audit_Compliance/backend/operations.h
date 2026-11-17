#ifndef OPERATIONS_H
#define OPERATIONS_H

#include "authentication.h"
#include "database.h"
#include <string>

struct Result {
    int status;          // HTTP status code
    std::string body;    // JSON text
};

std::string jsonEscape(const std::string& s);
std::string rowsToJson(const Rows& rows);
std::string msgJson(bool ok, const std::string& message);

// Every operation: (1) checks the role's permission, (2) does the work,
// (3) writes an audit-log entry - whether it succeeded, failed or was denied.
namespace Ops {
    Result listEmployees (const Session& s, const std::string& ip, const std::string& search);
    Result addEmployee   (const Session& s, const std::string& ip, const std::string& name,
                          const std::string& dept, const std::string& email, const std::string& salary);
    Result updateEmployee(const Session& s, const std::string& ip, const std::string& id,
                          const std::string& name, const std::string& dept,
                          const std::string& email, const std::string& salary);
    Result deleteEmployee(const Session& s, const std::string& ip, const std::string& id);

    Result viewAudit  (const Session& s, const std::string& ip, const std::string& user,
                       const std::string& action, const std::string& status, int limit);
    Result viewChanges(const Session& s, const std::string& ip, int limit);
    Result compliance (const Session& s, const std::string& ip);

    Result listUsers (const Session& s, const std::string& ip);
    Result createUser(const Session& s, const std::string& ip, const std::string& username,
                      const std::string& password, const std::string& role);
    Result unlockUser(const Session& s, const std::string& ip, const std::string& username);
}

#endif
