/* Clean, single implementation for db functions */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include "db.h"
#include <sodium.h>

static sqlite3 *db = NULL;

/* Schema creation SQL */
static const char *schema_sql = 
    "CREATE TABLE IF NOT EXISTS accounts ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  username TEXT UNIQUE NOT NULL,"
    "  password TEXT NOT NULL,"
    "  whitelist TEXT,"
    "  ts_created INTEGER NOT NULL,"
    "  ts_updated INTEGER NOT NULL,"
    "  ts_seen INTEGER NOT NULL,"
    "  monthly_bandwidth INTEGER DEFAULT 0,"
    "  m_bytes_sent INTEGER DEFAULT 0,"
    "  m_bytes_received INTEGER DEFAULT 0,"
    "  total_bytes_sent INTEGER DEFAULT 0,"
    "  total_bytes_received INTEGER DEFAULT 0,"
    "  online INTEGER DEFAULT 0"
    ");"
    
    "CREATE TABLE IF NOT EXISTS connections ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  account_id INTEGER NOT NULL,"
    "  client_ip TEXT NOT NULL,"
    "  destination TEXT NOT NULL,"
    "  status TEXT NOT NULL,"
    "  bytes_sent INTEGER NOT NULL,"
    "  bytes_received INTEGER NOT NULL,"
    "  ts_timestamp INTEGER NOT NULL,"
    "  FOREIGN KEY(account_id) REFERENCES accounts(id)"
    ");";

int db_init(const char *dbpath) {
    int rc;
    char *err_msg = NULL;

    rc = sqlite3_open(dbpath, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        db = NULL;
        return rc;
    }

    /* initialize libsodium for password hashing */
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        sqlite3_close(db);
        db = NULL;
        return SQLITE_ERROR;
    }

    /* use WAL for better concurrency */
    rc = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        if (err_msg) sqlite3_free(err_msg);
        /* non-fatal */
    }

    rc = sqlite3_exec(db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (schema): %s\n", err_msg ? err_msg : "(null)");
        sqlite3_free(err_msg);
        sqlite3_close(db);
        db = NULL;
        return rc;
    }

    return SQLITE_OK;
}

sqlite3 *db_get_handle(void) {
    return db;
}

int db_stmt_prepare(const char *sql, sqlite3_stmt **stmt) {
    if (!db || !sql || !stmt) return SQLITE_ERROR;
    return sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
}

void db_cleanup(void) {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}

int db_account_create(const char *username, const char *password, int64_t monthly_bandwidth) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO accounts (username, password, monthly_bandwidth, ts_created, ts_updated, ts_seen) "
                      "VALUES (?, ?, ?, ?, ?, ?)";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        if (stmt) sqlite3_finalize(stmt);
        return rc;
    }

    time_t now = time(NULL);
    /* Hash the password with libsodium */
    char hashed[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hashed, password, strlen(password),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        sqlite3_finalize(stmt);
        return SQLITE_ERROR;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hashed, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, monthly_bandwidth);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

int db_account_auth(const char *username, const char *password) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT id, password FROM accounts WHERE username = ? LIMIT 1";
    int id = -1;

    if (!db) return -1;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *stored = sqlite3_column_text(stmt, 1);
        if (stored && password) {
            /* verify hash */
            if (crypto_pwhash_str_needs_rehash((const char*)stored,
                                               crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                               crypto_pwhash_MEMLIMIT_INTERACTIVE)) {
                /* stored hash uses weaker params, but we can still verify first */
            }
            if (crypto_pwhash_str_verify((const char*)stored, password, strlen(password)) == 0) {
                id = sqlite3_column_int(stmt, 0);
            } else {
                /* Fallback for older plaintext-stored passwords: compare directly and re-hash */
                if (strcmp((const char*)stored, password) == 0) {
                    /* re-hash and store new hash */
                    char newhash[crypto_pwhash_STRBYTES];
                    if (crypto_pwhash_str(newhash, password, strlen(password),
                                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                          crypto_pwhash_MEMLIMIT_INTERACTIVE) == 0) {
                        const char *update_sql = "UPDATE accounts SET password = ? WHERE id = ?";
                        sqlite3_stmt *update_stmt = NULL;
                        if (sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, NULL) == SQLITE_OK) {
                            sqlite3_bind_text(update_stmt, 1, newhash, -1, SQLITE_TRANSIENT);
                            sqlite3_bind_int(update_stmt, 2, sqlite3_column_int(stmt, 0));
                            sqlite3_step(update_stmt);
                            sqlite3_finalize(update_stmt);
                        }
                    }
                    id = sqlite3_column_int(stmt, 0);
                } else {
                    id = -1;
                }
            }
        }
    }
    sqlite3_finalize(stmt);

    if (id >= 0) {
        const char *update_sql = "UPDATE accounts SET ts_seen = ? WHERE id = ?";
        sqlite3_stmt *update_stmt = NULL;
        if (sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(update_stmt, 1, (sqlite3_int64)time(NULL));
            sqlite3_bind_int(update_stmt, 2, id);
            sqlite3_step(update_stmt);
            sqlite3_finalize(update_stmt);
        }
    }

    return id;
}

int db_account_update_bandwidth(int account_id, int64_t sent, int64_t received) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE accounts SET "
                      "m_bytes_sent = m_bytes_sent + ?, "
                      "m_bytes_received = m_bytes_received + ?, "
                      "total_bytes_sent = total_bytes_sent + ?, "
                      "total_bytes_received = total_bytes_received + ?, "
                      "ts_updated = ? "
                      "WHERE id = ?";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;

    sqlite3_bind_int64(stmt, 1, sent);
    sqlite3_bind_int64(stmt, 2, received);
    sqlite3_bind_int64(stmt, 3, sent);
    sqlite3_bind_int64(stmt, 4, received);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)time(NULL));
    sqlite3_bind_int(stmt, 6, account_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

static int check_ip_in_whitelist(const char *whitelist, const char *ip) {
    if (!whitelist || !*whitelist) return 0;
    char *wlist = strdup(whitelist);
    if (!wlist) return 0;
    char *saveptr;
    char *token = strtok_r(wlist, ",", &saveptr);
    int found = 0;

    while (token) {
        if (strcmp(token, ip) == 0) {
            found = 1;
            break;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    free(wlist);
    return found;
}

int db_account_check_whitelist(int account_id, union sockaddr_union *addr) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT whitelist FROM accounts WHERE id = ?";
    int allowed = 0;
    if (!db) return 0;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int(stmt, 1, account_id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *whitelist = sqlite3_column_text(stmt, 0);
        if (whitelist) {
            char ip[INET6_ADDRSTRLEN];
            void *addr_ptr = SOCKADDR_UNION_ADDRESS(addr);
            inet_ntop(SOCKADDR_UNION_AF(addr), addr_ptr, ip, sizeof(ip));
            allowed = check_ip_in_whitelist((const char*)whitelist, ip);
        }
    }

    sqlite3_finalize(stmt);
    return allowed;
}

int db_account_add_whitelist(int account_id, const char *ip) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE accounts SET whitelist = CASE "
                      "WHEN whitelist IS NULL OR whitelist = '' THEN ? "
                      "ELSE whitelist || ',' || ? END "
                      "WHERE id = ?";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, account_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

int db_log_connection(int account_id, const char *client_ip, const char *destination,
                     const char *status, int64_t bytes_sent, int64_t bytes_received) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO connections "
                     "(account_id, client_ip, destination, status, bytes_sent, bytes_received, ts_timestamp) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;

    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_text(stmt, 2, client_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, destination, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, bytes_sent);
    sqlite3_bind_int64(stmt, 6, bytes_received);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

int db_reset_monthly_stats(void) {
    const char *sql = "UPDATE accounts SET m_bytes_sent = 0, m_bytes_received = 0";
    char *err_msg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg ? err_msg : "(null)");
        sqlite3_free(err_msg);
    }
    return rc;
}