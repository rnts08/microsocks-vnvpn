#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sodium.h>
#include <sys/stat.h>
#include "db.h"

static void print_help(void) {
    fprintf(stderr,
        "MicroSocks Account Manager\n"
        "------------------------\n"
        "Usage: msadmin [options] command [args...]\n\n"
        "Options:\n"
        "  -d dbpath    Database path (default: microsocks.db)\n\n"
        "Commands:\n"
        "  add username password [monthly_bandwidth]\n"
        "    Create new account with optional monthly bandwidth limit (in bytes)\n"
        "    Example: msadmin add john secret123 1000000000\n\n"
        "  list\n"
        "    List all accounts and their usage\n\n"
            "  migrate [--only-plaintext|--rehash-needs] [--yes|-y] [user...]\n"
            "    Migrate plaintext passwords to Argon2id hashes or report hashes needing rehash. Defaults to --only-plaintext.\n"
            "  benchmark [N]\n"
            "    Run password-hash benchmark (N iterations, default 5)\n"
        "  show username\n"
        "    Show detailed account information\n\n"
        "  update username [field value ...]\n"
        "    Update account fields. Available fields:\n"
        "    - password\n"
        "    - monthly_bandwidth\n"
        "    Example: msadmin update john password newpass monthly_bandwidth 2000000000\n\n"
        "  delete username\n"
        "    Delete an account\n"
    );
    exit(1);
}

static void list_accounts(int csv_mode) {
    sqlite3_stmt *stmt;
    const char *sql = 
        "SELECT username, monthly_bandwidth, m_bytes_sent, m_bytes_received, "
        "total_bytes_sent, total_bytes_received, online, "
        "datetime(ts_created,'unixepoch') as created, "
        "datetime(ts_seen,'unixepoch') as last_seen "
        "FROM accounts ORDER BY username";
    
    int rc = sqlite3_prepare_v2(db_get_handle(), sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to query accounts: %s\n", sqlite3_errmsg(db_get_handle()));
        return;
    }

    if (csv_mode) {
     printf("username,monthly_quota_gb,monthly_used_gb,total_used_gb,last_seen\n");
    } else {
     printf("%-20s %-15s %-15s %-15s %s\n", 
         "Username", "Monthly Quota", "Monthly Used", "Total Used", "Last Seen");
     printf("%-20s %-15s %-15s %-15s %s\n",
         "--------", "------------", "-----------", "----------", "---------");
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *username = (const char*)sqlite3_column_text(stmt, 0);
        int64_t quota = sqlite3_column_int64(stmt, 1);
        int64_t m_sent = sqlite3_column_int64(stmt, 2);
        int64_t m_recv = sqlite3_column_int64(stmt, 3);
        int64_t t_sent = sqlite3_column_int64(stmt, 4);
        int64_t t_recv = sqlite3_column_int64(stmt, 5);
        const char *last_seen = (const char*)sqlite3_column_text(stmt, 8);

        char quota_str[32] = "unlimited";
        char monthly_str[32];
        char total_str[32];

        if (quota > 0) 
            snprintf(quota_str, sizeof(quota_str), "%.2f GB", quota / 1e9);
        
        snprintf(monthly_str, sizeof(monthly_str), "%.2f GB", (m_sent + m_recv) / 1e9);
        snprintf(total_str, sizeof(total_str), "%.2f GB", (t_sent + t_recv) / 1e9);

     if (csv_mode) {
         printf("%s,%.3f,%.3f,%.3f,%s\n", username,
             quota > 0 ? (double)quota/1e9 : 0.0,
             (double)(m_sent + m_recv)/1e9,
             (double)(t_sent + t_recv)/1e9,
             last_seen ? last_seen : "");
     } else {
         printf("%-20s %-15s %-15s %-15s %s\n",
             username, quota_str, monthly_str, total_str,
             last_seen ? last_seen : "never");
     }
    }

    sqlite3_finalize(stmt);
}

static int cmd_migrate(const char *dbpath, int argc, char **argv) {
    /* Migrate passwords. Modes:
       --only-plaintext   : Hash stored plaintext passwords (default)
       --rehash-needs     : Report accounts whose stored hashes need rehash (cannot rehash without plaintext)
       --yes, -y          : skip confirmation
       [usernames ...]    : optional list of usernames to restrict migration
    */
    int only_plain = 1; /* default */
    int rehash_needs = 0;
    int yes = 0;
    /* collect usernames from args (remaining after options) */
    const char **users = NULL;
    int users_count = 0;
    const char *logpath = NULL;
    const char *logdir = NULL;

    /* Allow an optional positional DB path as the first argument. If present, use it and shift argv. */
    if (argc > 0 && argv[0][0] != '-') {
        /* heuristic: if it contains a slash or ends with .db or the file exists, treat as db path */
        int looks_like_path = 0;
        if (strchr(argv[0], '/') != NULL) looks_like_path = 1;
        if (!looks_like_path && strstr(argv[0], ".db") != NULL) looks_like_path = 1;
        if (!looks_like_path) {
            struct stat st;
            if (stat(argv[0], &st) == 0) looks_like_path = 1;
        }
        if (looks_like_path) {
            dbpath = argv[0];
            /* shift */
            argv++; argc--; 
        }
    }

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--only-plaintext") == 0) { only_plain = 1; rehash_needs = 0; }
        else if (strcmp(argv[i], "--rehash-needs") == 0) { rehash_needs = 1; only_plain = 0; }
        else if (strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "-y") == 0) { yes = 1; }
        else if (strcmp(argv[i], "--log") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--log requires a path\n"); return 1; }
            logpath = argv[++i];
        } else if (strcmp(argv[i], "--log-dir") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--log-dir requires a directory path\n"); return 1; }
            logdir = argv[++i];
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown migrate option: %s\n", argv[i]);
            return 1;
        } else {
            /* treat as username; collect rest as usernames */
            users = (const char**)&argv[i];
            users_count = argc - i;
            break;
        }
    }

    if (!yes) {
        printf("About to run migration on DB: %s\n", dbpath);
        if (users_count > 0) {
            printf("Restricted to %d usernames.\n", users_count);
        } else {
            printf("Operating on all accounts.\n");
        }
        printf("Mode: %s\n", rehash_needs ? "rehash-needs (report only)" : "only-plaintext (hash plaintext to Argon2id)");
        printf("Proceed? (yes/no): ");
        char yn[8];
        if (!fgets(yn, sizeof yn, stdin)) return 1;
        if (strncmp(yn, "yes", 3) != 0) { printf("Aborted.\n"); return 1; }
    }

    /* open log file if requested */
    FILE *logf = NULL;
    char auto_logpath[PATH_MAX];
    if (logpath == NULL && logdir != NULL) {
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", &tm);
        snprintf(auto_logpath, sizeof(auto_logpath), "%s/migrate-%s.log", logdir, ts);
        logpath = auto_logpath;
    }
    if (logpath) {
        logf = fopen(logpath, "a");
        if (!logf) {
            fprintf(stderr, "Failed to open log file %s\n", logpath);
            return 1;
        }
        time_t now = time(NULL);
        char tbuf[64];
        struct tm tm2;
        localtime_r(&now, &tm2);
        strftime(tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", &tm2);
        fprintf(logf, "migration run: %s DB=%s mode=%s\n", tbuf, dbpath, rehash_needs ? "rehash-needs" : "only-plaintext");
        if (users_count > 0) {
            fprintf(logf, "restricted to %d usernames\n", users_count);
        }
        fflush(logf);
    }

    if (db_init(dbpath) != SQLITE_OK) {
        fprintf(stderr, "failed to open db %s\n", dbpath);
        return 1;
    }
    sqlite3 *h = db_get_handle();
    const char *sel = "SELECT id, username, password FROM accounts";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(h, sel, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare failed: %s\n", sqlite3_errmsg(h));
        db_cleanup();
        return 1;
    }
    const char *upd_sql = "UPDATE accounts SET password = ? WHERE id = ?";
    sqlite3_stmt *upd = NULL;
    if (only_plain) {
        if (sqlite3_prepare_v2(h, upd_sql, -1, &upd, NULL) != SQLITE_OK) {
            fprintf(stderr, "prepare update failed: %s\n", sqlite3_errmsg(h));
            sqlite3_finalize(stmt);
            db_cleanup();
            return 1;
        }
    }

    int migrated = 0;
    int reported = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *username = sqlite3_column_text(stmt, 1);
        const unsigned char *pw = sqlite3_column_text(stmt, 2);
        if (!pw) continue;
        const char *pwstr = (const char*)pw;
        const char *uname = username ? (const char*)username : "(null)";

        /* if specific users provided, skip others */
        if (users_count > 0) {
            int match = 0;
            for (int u = 0; u < users_count; u++) if (strcmp(uname, users[u]) == 0) { match = 1; break; }
            if (!match) continue;
        }

        if (only_plain) {
            if (strncmp(pwstr, "$argon2id$", 9) == 0) continue; /* already hashed */
            char newhash[crypto_pwhash_STRBYTES];
            if (crypto_pwhash_str(newhash, pwstr, strlen(pwstr), PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0) {
                fprintf(stderr, "failed to hash password for id=%d user=%s\n", id, uname);
                if (logf) fprintf(logf, "error: failed to hash id=%d user=%s\n", id, uname);
                continue;
            }
            sqlite3_reset(upd);
            sqlite3_bind_text(upd, 1, newhash, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(upd, 2, id);
            if (sqlite3_step(upd) != SQLITE_DONE) {
                fprintf(stderr, "failed to update password for id=%d: %s\n", id, sqlite3_errmsg(h));
                if (logf) fprintf(logf, "error: failed to update id=%d user=%s: %s\n", id, uname, sqlite3_errmsg(h));
            } else {
                migrated++;
                printf("migrated: id=%d user=%s\n", id, uname);
                if (logf) fprintf(logf, "migrated: id=%d user=%s\n", id, uname);
            }
        } else if (rehash_needs) {
            /* only report accounts that have Argon2 hashes and need rehash according to new params */
            if (strncmp(pwstr, "$argon2id$", 9) != 0) continue; /* cannot determine needs-rehash for plaintext */
            if (crypto_pwhash_str_needs_rehash(pwstr, PWHASH_OPSLIMIT, PWHASH_MEMLIMIT)) {
                reported++;
                printf("needs_rehash: id=%d user=%s\n", id, uname);
                if (logf) fprintf(logf, "needs_rehash: id=%d user=%s\n", id, uname);
            }
        }
    }
    if (only_plain && upd) sqlite3_finalize(upd);
    sqlite3_finalize(stmt);
    db_cleanup();
    if (only_plain) printf("migration completed, migrated %d accounts\n", migrated);
    if (only_plain && logf) fprintf(logf, "migration completed, migrated %d accounts\n", migrated);
    if (rehash_needs) printf("rehash report completed, %d accounts need rehash\n", reported);
    if (rehash_needs && logf) fprintf(logf, "rehash report completed, %d accounts need rehash\n", reported);
    if (logf) fclose(logf);
    return 0;
}

static int cmd_benchmark(const char *dbpath, int argc, char **argv) {
    int iterations = 5;
    if (argc >= 1) iterations = atoi(argv[0]);
    const char *pw = "benchmark-password";
    struct timespec t0, t1;
    if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) {
        perror("clock_gettime");
        return 1;
    }
    for (int i = 0; i < iterations; i++) {
        char hashed[crypto_pwhash_STRBYTES];
        if (crypto_pwhash_str(hashed, pw, strlen(pw), PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0) {
            fprintf(stderr, "hash failed at iteration %d\n", i);
            return 1;
        }
    }
    if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
        perror("clock_gettime");
        return 1;
    }
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec)/1e9;
    printf("Performed %d hashes in %.3f s (avg %.3f s/hash) with ops=%llu mem=%zu\n",
           iterations, elapsed, elapsed/iterations, (unsigned long long)PWHASH_OPSLIMIT, (size_t)PWHASH_MEMLIMIT);
    return 0;
}

static void show_account(const char *username) {
    sqlite3_stmt *stmt;
    const char *sql = 
        "SELECT id, password, whitelist, monthly_bandwidth, "
        "m_bytes_sent, m_bytes_received, "
        "total_bytes_sent, total_bytes_received, "
        "online, "
        "datetime(ts_created,'unixepoch') as created, "
        "datetime(ts_updated,'unixepoch') as updated, "
        "datetime(ts_seen,'unixepoch') as last_seen "
        "FROM accounts WHERE username = ?";
    
    int rc = sqlite3_prepare_v2(db_get_handle(), sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to query account: %s\n", sqlite3_errmsg(db_get_handle()));
        return;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char *whitelist = (const char*)sqlite3_column_text(stmt, 2);
        int64_t quota = sqlite3_column_int64(stmt, 3);
        int64_t m_sent = sqlite3_column_int64(stmt, 4);
        int64_t m_recv = sqlite3_column_int64(stmt, 5);
        int64_t t_sent = sqlite3_column_int64(stmt, 6);
        int64_t t_recv = sqlite3_column_int64(stmt, 7);
        int online = sqlite3_column_int(stmt, 8);
        const char *created = (const char*)sqlite3_column_text(stmt, 9);
        const char *updated = (const char*)sqlite3_column_text(stmt, 10);
        const char *last_seen = (const char*)sqlite3_column_text(stmt, 11);

        printf("Account Details for: %s (ID: %d)\n", username, id);
        printf("Created: %s\n", created);
        printf("Updated: %s\n", updated);
        printf("Last Seen: %s\n", last_seen ? last_seen : "never");
        printf("Monthly Bandwidth: %s\n", 
               quota > 0 ? "unlimited" : "unlimited");
        printf("Monthly Usage: %.2f GB sent, %.2f GB received\n",
               m_sent / 1e9, m_recv / 1e9);
        printf("Total Usage: %.2f GB sent, %.2f GB received\n",
               t_sent / 1e9, t_recv / 1e9);
        printf("Current Connections: %d\n", online);
        printf("Whitelisted IPs: %s\n", whitelist ? whitelist : "none");

        /* Show recent connections */
        printf("\nRecent Connections:\n");
        const char *conn_sql = 
            "SELECT datetime(ts_timestamp,'unixepoch') as ts, "
            "client_ip, destination, status, bytes_sent, bytes_received "
            "FROM connections "
            "WHERE account_id = ? "
            "ORDER BY ts_timestamp DESC LIMIT 5";
        
        sqlite3_stmt *conn_stmt;
        rc = sqlite3_prepare_v2(db_get_handle(), conn_sql, -1, &conn_stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(conn_stmt, 1, id);
            printf("%-19s %-15s %-30s %-10s %s\n",
                   "Timestamp", "Client IP", "Destination", "Status", "Transfer");
            while (sqlite3_step(conn_stmt) == SQLITE_ROW) {
                const char *ts = (const char*)sqlite3_column_text(conn_stmt, 0);
                const char *ip = (const char*)sqlite3_column_text(conn_stmt, 1);
                const char *dest = (const char*)sqlite3_column_text(conn_stmt, 2);
                const char *status = (const char*)sqlite3_column_text(conn_stmt, 3);
                int64_t sent = sqlite3_column_int64(conn_stmt, 4);
                int64_t recv = sqlite3_column_int64(conn_stmt, 5);
                
                printf("%-19s %-15s %-30s %-10s %.2fMB/%.2fMB\n",
                       ts, ip, dest, status, sent/1e6, recv/1e6);
            }
            sqlite3_finalize(conn_stmt);
        }
    } else {
        fprintf(stderr, "Account not found: %s\n", username);
    }

    sqlite3_finalize(stmt);
}

static int add_account(const char *username, const char *password, int64_t monthly_bandwidth) {
    return db_account_create(username, password, monthly_bandwidth);
}

static int delete_account(const char *username) {
    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM accounts WHERE username = ?";
    
    int rc = sqlite3_prepare_v2(db_get_handle(), sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to delete account: %s\n", sqlite3_errmsg(db_get_handle()));
        return rc;
    }
    
    return SQLITE_OK;
}

static int update_account(const char *username, int argc, char **argv) {
    if (argc % 2 != 0) {
        fprintf(stderr, "Error: update requires field/value pairs\n");
        return 1;
    }

    sqlite3_stmt *stmt;
    char *sql = NULL;
    size_t sql_size = 0;
    FILE *mem = open_memstream(&sql, &sql_size);
    
    fprintf(mem, "UPDATE accounts SET ");
    for (int i = 0; i < argc; i += 2) {
        const char *field = argv[i];
        if (i > 0) fprintf(mem, ",");
        
        if (strcmp(field, "password") == 0) {
            fprintf(mem, "password = ?");
        } else if (strcmp(field, "monthly_bandwidth") == 0) {
            fprintf(mem, "monthly_bandwidth = ?");
        } else {
            fprintf(stderr, "Unknown field: %s\n", field);
            fclose(mem);
            free(sql);
            return 1;
        }
    }
    fprintf(mem, ", ts_updated = ? WHERE username = ?");
    fclose(mem);

    int rc = sqlite3_prepare_v2(db_get_handle(), sql, -1, &stmt, NULL);
    free(sql);
    if (rc != SQLITE_OK) return rc;

    int param = 1;
    for (int i = 0; i < argc; i += 2) {
        const char *field = argv[i];
        const char *value = argv[i + 1];
        
        if (strcmp(field, "password") == 0) {
            /* hash password locally before storing */
            char hashed[crypto_pwhash_STRBYTES];
            if (crypto_pwhash_str(hashed, value, strlen(value),
                                  crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                  crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
                fprintf(stderr, "Failed to hash password\n");
                sqlite3_finalize(stmt);
                free(sql);
                return 1;
            }
            sqlite3_bind_text(stmt, param++, hashed, -1, SQLITE_TRANSIENT);
        } else if (strcmp(field, "monthly_bandwidth") == 0) {
            sqlite3_bind_int64(stmt, param++, atoll(value));
        }
    }
    
    sqlite3_bind_int64(stmt, param++, time(NULL));
    sqlite3_bind_text(stmt, param++, username, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to update account: %s\n", sqlite3_errmsg(db_get_handle()));
        return rc;
    }

    return SQLITE_OK;
}

int main(int argc, char **argv) {
    const char *dbpath = "microsocks.db";
    int arg = 1;

    if (argc < 2) {
        print_help();
        return 1;
    }

    int csv_mode = 0;
    /* Parse options */
    while (arg < argc && argv[arg][0] == '-') {
        if (strcmp(argv[arg], "-d") == 0) {
            if (++arg >= argc) {
                fprintf(stderr, "Error: -d requires database path\n");
                return 1;
            }
            dbpath = argv[arg++];
        } else if (strcmp(argv[arg], "-c") == 0 || strcmp(argv[arg], "--csv") == 0) {
            csv_mode = 1;
            arg++;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[arg]);
            return 1;
        }
    }

    if (arg >= argc) {
        print_help();
        return 1;
    }

    /* Initialize database */
    if (db_init(dbpath) != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", dbpath);
        return 1;
    }
    /* libsodium is initialized in db_init, but ensure it's available here too */
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed in msadmin\n");
        db_cleanup();
        return 1;
    }

    const char *cmd = argv[arg++];
    int rc = 0;

    if (strcmp(cmd, "list") == 0) {
        list_accounts(csv_mode);
    }
    else if (strcmp(cmd, "migrate") == 0) {
        rc = cmd_migrate(dbpath, argc - arg, argv + arg);
    }
    else if (strcmp(cmd, "benchmark") == 0) {
        rc = cmd_benchmark(dbpath, argc - arg, argv + arg);
    }
    else if (strcmp(cmd, "show") == 0) {
        if (arg >= argc) {
            fprintf(stderr, "Error: show requires username\n");
            rc = 1;
        } else {
            show_account(argv[arg]);
        }
    }
    else if (strcmp(cmd, "add") == 0) {
        if (arg + 1 >= argc) {
            fprintf(stderr, "Error: add requires username and password\n");
            rc = 1;
        } else {
            int64_t bw = 0;
            if (arg + 2 < argc) bw = atoll(argv[arg + 2]);
            rc = add_account(argv[arg], argv[arg + 1], bw);
            if (rc == SQLITE_OK)
                printf("Account created successfully\n");
            else
                fprintf(stderr, "Failed to create account\n");
        }
    }
    else if (strcmp(cmd, "delete") == 0) {
        if (arg >= argc) {
            fprintf(stderr, "Error: delete requires username\n");
            rc = 1;
        } else {
            const char *user = argv[arg];
            /* confirm if running interactively */
            if (isatty(fileno(stdin))) {
                char yn[8];
                printf("Are you sure you want to delete account '%s'? This cannot be undone. (yes/no): ", user);
                if (!fgets(yn, sizeof yn, stdin)) { rc = 1; }
                else {
                    if (strncmp(yn, "yes", 3) != 0) {
                        printf("Aborted.\n");
                        rc = 1;
                    } else {
                        rc = delete_account(user);
                        if (rc == SQLITE_OK) printf("Account deleted successfully\n");
                        else fprintf(stderr, "Failed to delete account\n");
                    }
                }
            } else {
                rc = delete_account(user);
                if (rc == SQLITE_OK) printf("Account deleted successfully\n");
                else fprintf(stderr, "Failed to delete account\n");
            }
        }
    }
    else if (strcmp(cmd, "update") == 0) {
        if (arg >= argc) {
            fprintf(stderr, "Error: update requires username\n");
            rc = 1;
        } else {
            const char *username = argv[arg++];
            rc = update_account(username, argc - arg, argv + arg);
            if (rc == SQLITE_OK)
                printf("Account updated successfully\n");
            else
                fprintf(stderr, "Failed to update account\n");
        }
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        rc = 1;
    }

    db_cleanup();
    return rc;
}