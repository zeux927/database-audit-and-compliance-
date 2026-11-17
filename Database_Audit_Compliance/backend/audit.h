#ifndef AUDIT_H
#define AUDIT_H

#include "database.h"
#include <string>

namespace Audit {
    // Append one entry to the audit trail.
    void log(const std::string& user, const std::string& role, const std::string& action,
             const std::string& table, const std::string& recordId,
             const std::string& details, const std::string& status, const std::string& ip);

    Rows getLogs(const std::string& user, const std::string& action,
                 const std::string& status, int limit);
    Rows getDataChanges(int limit);

    // Runs the automated compliance checks. Each row: check, status (PASS/WARN/FAIL), detail.
    Rows complianceReport();
}

#endif
