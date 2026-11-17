#ifndef AUTHORIZATION_H
#define AUTHORIZATION_H

#include <string>

// Role-Based Access Control (RBAC).
//   admin   : everything
//   user    : view / add / update employees
//   auditor : view employees, read audit logs, run compliance checks (read-only)
namespace Authz {
    bool isAllowed(const std::string& role, const std::string& permission);
}

#endif
