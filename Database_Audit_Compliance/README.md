# Database Audit & Compliance

C++ backend (cpp-httplib + SQLite) + HTML/CSS/JS frontend.

## Build & run (Linux / macOS / WSL)
    sudo apt install g++ libsqlite3-dev        # Linux/WSL  (macOS: xcode-select --install)
    cd backend
    g++ -std=c++17 -O2 -o audit_server *.cpp -lsqlite3 -pthread
    ./audit_server
Open http://localhost:8080

## Demo accounts
admin / admin123   |   auditor / auditor123   |   user1 / user123
