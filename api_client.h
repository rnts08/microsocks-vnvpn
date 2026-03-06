#ifndef API_CLIENT_H
#define API_CLIENT_H

#include <stddef.h>
#include <stdint.h>

int api_client_init(const char *base_url, const char *token, int timeout_ms);
int api_authenticate(const char *username, const char *password, const char *client_ip, int *account_id);
int api_session_start(int account_id, const char *client_ip, const char *destination, int max_concurrent, char *reason, size_t reason_len);
int api_accounting_update(int account_id, int64_t bytes_sent, int64_t bytes_received);
int api_session_end(int account_id, const char *client_ip, const char *destination, const char *status,
                    int64_t bytes_sent, int64_t bytes_received, int online_tracked);

#endif
