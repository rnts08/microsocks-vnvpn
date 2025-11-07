#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sodium.h>
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