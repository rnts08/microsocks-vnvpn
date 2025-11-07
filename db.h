#ifndef DB_H
#define DB_H

#include <sqlite3.h>
#include <time.h>
#include "server.h"

/* Database initialization and cleanup */
int db_init(const char *dbpath);
void db_cleanup(void);
sqlite3 *db_get_handle(void);  /* Get database handle for admin tool */

int db_stmt_prepare(const char *sql, sqlite3_stmt **stmt);
/* Account management */
struct account {
    int id;
    char username[64];
    char password[64];
    char whitelist[256];  /* comma-separated IPs */
    time_t ts_created;
    time_t ts_updated;
    time_t ts_seen;
    int64_t monthly_bandwidth;  /* limit in bytes, 0 for unlimited */
    int64_t m_bytes_sent;
    int64_t m_bytes_received;
    int64_t total_bytes_sent;
    int64_t total_bytes_received;
    int online;  /* current active connections */
};

/* Account operations */
int db_account_create(const char *username, const char *password, int64_t monthly_bandwidth);
int db_account_auth(const char *username, const char *password);
int db_account_update_bandwidth(int account_id, int64_t sent, int64_t received);
int db_account_check_whitelist(int account_id, union sockaddr_union *addr);
int db_account_add_whitelist(int account_id, const char *ip);

/* Connection logging */
int db_log_connection(int account_id, const char *client_ip, const char *destination,
                     const char *status, int64_t bytes_sent, int64_t bytes_received);

/* Monthly reset - call this periodically to reset monthly counters */
int db_reset_monthly_stats(void);

#endif /* DB_H */