#include "authorization.h"
#include <map>
#include <set>

namespace Authz {

bool isAllowed(const std::string& role, const std::string& permission) {
    static const std::map<std::string, std::set<std::string>> matrix = {
        {"admin",   {"VIEW_EMPLOYEES", "ADD_EMPLOYEE", "UPDATE_EMPLOYEE", "DELETE_EMPLOYEE",
                     "VIEW_AUDIT", "RUN_COMPLIANCE", "MANAGE_USERS"}},
        {"user",    {"VIEW_EMPLOYEES", "ADD_EMPLOYEE", "UPDATE_EMPLOYEE"}},
        {"auditor", {"VIEW_EMPLOYEES", "VIEW_AUDIT", "RUN_COMPLIANCE"}}
    };
    auto it = matrix.find(role);
    return it != matrix.end() && it->second.count(permission) > 0;
}

}
