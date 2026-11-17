-- =====================================================================
--  Database Audit & Compliance  -  schema (SQLite)
--  Safe to run many times (IF NOT EXISTS / INSERT OR IGNORE).
--  The C++ backend runs this file automatically at start-up.
-- =====================================================================
PRAGMA foreign_keys = ON;

-- 1. Application users (authentication + roles) -----------------------
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,                 -- SHA-256(username:password)
    role            TEXT    NOT NULL CHECK (role IN ('admin','user','auditor')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked          INTEGER NOT NULL DEFAULT 0,       -- 1 = locked after 3 bad logins
    created_at      TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 2. Business data that is being audited ------------------------------
CREATE TABLE IF NOT EXISTS employees (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    department  TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    salary      REAL NOT NULL CHECK (salary >= 0),
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 3. Activity audit log: WHO did WHAT, WHEN, from WHERE, and the RESULT
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    username    TEXT,
    role        TEXT,
    action      TEXT NOT NULL,
    table_name  TEXT,
    record_id   TEXT,
    details     TEXT,
    status      TEXT NOT NULL CHECK (status IN ('SUCCESS','FAILURE','DENIED')),
    ip_address  TEXT
);

-- 4. Data-change log filled by TRIGGERS (before / after values) --------
CREATE TABLE IF NOT EXISTS data_change_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    table_name  TEXT NOT NULL,
    record_id   INTEGER,
    operation   TEXT NOT NULL,                        -- INSERT / UPDATE / DELETE
    old_value   TEXT,
    new_value   TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_user   ON audit_log(username);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- 5. Sample data (ignored if it already exists) ------------------------
INSERT OR IGNORE INTO employees (name, department, email, salary) VALUES
 ('Aarav Sharma',  'IT',        'aarav@company.com',  65000),
 ('Priya Singh',   'HR',        'priya@company.com',  52000),
 ('Rohan Gupta',   'Finance',   'rohan@company.com',  72000),
 ('Sneha Patel',   'Marketing', 'sneha@company.com',  48000),
 ('Karan Mehta',   'IT',        'karan@company.com',  80000);

-- 6. TRIGGERS: record every change to employees, even raw SQL ones -----
CREATE TRIGGER IF NOT EXISTS trg_emp_insert AFTER INSERT ON employees
BEGIN
    INSERT INTO data_change_log (table_name, record_id, operation, old_value, new_value)
    VALUES ('employees', NEW.id, 'INSERT', NULL,
            NEW.name||' | '||NEW.department||' | '||NEW.email||' | '||NEW.salary);
END;

CREATE TRIGGER IF NOT EXISTS trg_emp_update AFTER UPDATE ON employees
BEGIN
    INSERT INTO data_change_log (table_name, record_id, operation, old_value, new_value)
    VALUES ('employees', NEW.id, 'UPDATE',
            OLD.name||' | '||OLD.department||' | '||OLD.email||' | '||OLD.salary,
            NEW.name||' | '||NEW.department||' | '||NEW.email||' | '||NEW.salary);
END;

CREATE TRIGGER IF NOT EXISTS trg_emp_delete AFTER DELETE ON employees
BEGIN
    INSERT INTO data_change_log (table_name, record_id, operation, old_value, new_value)
    VALUES ('employees', OLD.id, 'DELETE',
            OLD.name||' | '||OLD.department||' | '||OLD.email||' | '||OLD.salary, NULL);
END;

-- 7. TRIGGERS: make the logs tamper-proof (append-only) ----------------
CREATE TRIGGER IF NOT EXISTS trg_audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE not allowed'); END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: DELETE not allowed'); END;

CREATE TRIGGER IF NOT EXISTS trg_change_no_update BEFORE UPDATE ON data_change_log
BEGIN SELECT RAISE(ABORT, 'data_change_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_change_no_delete BEFORE DELETE ON data_change_log
BEGIN SELECT RAISE(ABORT, 'data_change_log is append-only'); END;
