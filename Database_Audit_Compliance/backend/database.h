#ifndef DATABASE_H
#define DATABASE_H

#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <sqlite3.h>

using Row  = std::map<std::string, std::string>;   // column name -> value
using Rows = std::vector<Row>;

// Thin, thread-safe wrapper around SQLite. All values are bound as
// parameters (?), which prevents SQL injection.
class Database {
public:
    ~Database();
    bool open(const std::string& path);
    bool runScriptFile(const std::string& path);                 // run audit.sql
    bool execute(const std::string& sql,
                 const std::vector<std::string>& params = {},
                 long long* insertId = nullptr);                 // INSERT/UPDATE/DELETE
    Rows query(const std::string& sql,
               const std::vector<std::string>& params = {});     // SELECT
    std::string lastError() const { return err_; }

private:
    sqlite3* db_ = nullptr;
    std::string err_;
    std::recursive_mutex mtx_;
};

extern Database g_db;   // one shared connection for the whole program

#endif
