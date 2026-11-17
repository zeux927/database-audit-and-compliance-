#include "database.h"
#include <fstream>
#include <sstream>

Database g_db;

Database::~Database() { if (db_) sqlite3_close(db_); }

bool Database::open(const std::string& path) {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
        err_ = sqlite3_errmsg(db_);
        return false;
    }
    sqlite3_busy_timeout(db_, 3000);
    sqlite3_exec(db_, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
    return true;
}

bool Database::runScriptFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) { err_ = "Cannot open SQL file: " + path; return false; }
    std::stringstream ss;
    ss << f.rdbuf();
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    char* e = nullptr;
    if (sqlite3_exec(db_, ss.str().c_str(), nullptr, nullptr, &e) != SQLITE_OK) {
        err_ = e ? e : "unknown error";
        sqlite3_free(e);
        return false;
    }
    return true;
}

static bool prepareAndBind(sqlite3* db, const std::string& sql,
                           const std::vector<std::string>& params,
                           sqlite3_stmt** st, std::string& err) {
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, st, nullptr) != SQLITE_OK) {
        err = sqlite3_errmsg(db);
        return false;
    }
    for (size_t i = 0; i < params.size(); ++i)
        sqlite3_bind_text(*st, (int)i + 1, params[i].c_str(), -1, SQLITE_TRANSIENT);
    return true;
}

bool Database::execute(const std::string& sql, const std::vector<std::string>& params,
                       long long* insertId) {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    sqlite3_stmt* st = nullptr;
    if (!prepareAndBind(db_, sql, params, &st, err_)) return false;
    int rc = sqlite3_step(st);
    bool ok = (rc == SQLITE_DONE || rc == SQLITE_ROW);
    if (!ok) err_ = sqlite3_errmsg(db_);
    else if (insertId) *insertId = sqlite3_last_insert_rowid(db_);
    sqlite3_finalize(st);
    return ok;
}

Rows Database::query(const std::string& sql, const std::vector<std::string>& params) {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    Rows out;
    sqlite3_stmt* st = nullptr;
    if (!prepareAndBind(db_, sql, params, &st, err_)) return out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        Row r;
        for (int i = 0; i < sqlite3_column_count(st); ++i) {
            const unsigned char* t = sqlite3_column_text(st, i);
            r[sqlite3_column_name(st, i)] = t ? reinterpret_cast<const char*>(t) : "";
        }
        out.push_back(r);
    }
    sqlite3_finalize(st);
    return out;
}
