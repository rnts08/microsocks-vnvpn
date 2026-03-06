#define _POSIX_C_SOURCE 200809L
#include "api_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <ctype.h>
#include <time.h>

struct api_cfg {
    char host[256];
    unsigned short port;
    char base_path[256];
    char token[256];
    int timeout_ms;
    int enabled;
};

static struct api_cfg g_api;

static int parse_base_url(const char *url) {
    if(!url) return -1;
    const char *p = strstr(url, "http://");
    if(p != url) return -1;
    p += 7;
    const char *slash = strchr(p, '/');
    char hostport[256];
    if(slash) {
        size_t n = (size_t)(slash - p);
        if(n >= sizeof(hostport)) return -1;
        memcpy(hostport, p, n);
        hostport[n] = '\0';
        snprintf(g_api.base_path, sizeof(g_api.base_path), "%s", slash);
    } else {
        snprintf(hostport, sizeof(hostport), "%s", p);
        snprintf(g_api.base_path, sizeof(g_api.base_path), "%s", "");
    }
    char *colon = strrchr(hostport, ':');
    if(colon) {
        *colon = '\0';
        long port = strtol(colon + 1, NULL, 10);
        if(port <= 0 || port > 65535) return -1;
        g_api.port = (unsigned short)port;
    } else {
        g_api.port = 80;
    }
    snprintf(g_api.host, sizeof(g_api.host), "%s", hostport);
    return (g_api.host[0] != '\0') ? 0 : -1;
}

int api_client_init(const char *base_url, const char *token, int timeout_ms) {
    memset(&g_api, 0, sizeof(g_api));
    if(parse_base_url(base_url) != 0) return -1;
    if(!token || !*token) return -1;
    snprintf(g_api.token, sizeof(g_api.token), "%s", token);
    g_api.timeout_ms = timeout_ms > 0 ? timeout_ms : 3000;
    g_api.enabled = 1;
    return 0;
}

static int connect_with_timeout(void) {
    struct addrinfo hints, *res = NULL, *it;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portbuf[8];
    snprintf(portbuf, sizeof(portbuf), "%u", g_api.port);
    if(getaddrinfo(g_api.host, portbuf, &hints, &res) != 0) return -1;

    int fd = -1;
    for(it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if(fd < 0) continue;
        struct timeval tv;
        tv.tv_sec = g_api.timeout_ms / 1000;
        tv.tv_usec = (g_api.timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if(connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int http_post_json(const char *endpoint, const char *json, int *status_code, char *body, size_t body_len) {
    if(!g_api.enabled) return -1;
    int fd = connect_with_timeout();
    if(fd < 0) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s%s", g_api.base_path, endpoint);

    char req[4096];
    int json_len = (int)strlen(json);
    int req_len = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Authorization: Bearer %s\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n\r\n"
        "%s",
        path, g_api.host, g_api.port, g_api.token, json_len, json);
    if(req_len <= 0 || req_len >= (int)sizeof(req)) { close(fd); return -1; }

    if(write(fd, req, (size_t)req_len) != req_len) { close(fd); return -1; }

    char resp[16384];
    ssize_t total = 0;
    while(total < (ssize_t)(sizeof(resp)-1)) {
        ssize_t n = read(fd, resp + total, sizeof(resp)-1 - (size_t)total);
        if(n <= 0) break;
        total += n;
    }
    close(fd);
    resp[total] = '\0';

    int code = 0;
    if(sscanf(resp, "HTTP/%*d.%*d %d", &code) != 1) return -1;
    if(status_code) *status_code = code;

    char *body_start = strstr(resp, "\r\n\r\n");
    if(!body_start) return -1;
    body_start += 4;
    if(body && body_len > 0) {
        snprintf(body, body_len, "%s", body_start);
    }
    return 0;
}

static int json_get_int(const char *json, const char *key, int *out) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if(!p) return -1;
    p += strlen(needle);
    while(*p && isspace((unsigned char)*p)) p++;
    *out = (int)strtol(p, NULL, 10);
    return 0;
}

static int json_get_string(const char *json, const char *key, char *out, size_t out_len) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *p = strstr(json, needle);
    if(!p) return -1;
    p += strlen(needle);
    size_t i = 0;
    while(*p && *p != '"' && i + 1 < out_len) out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

int api_authenticate(const char *username, const char *password, const char *client_ip, int *account_id) {
    char json[1024], body[2048];
    snprintf(json, sizeof(json),
        "{\"username\":\"%s\",\"password\":\"%s\",\"client_ip\":\"%s\"}",
        username, password, client_ip ? client_ip : "");
    int status = 0;
    if(http_post_json("/api/internal/socks/auth", json, &status, body, sizeof(body)) != 0) return -1;
    if(status != 200) return -1;
    if(strstr(body, "\"ok\":true") == NULL) return -1;
    if(account_id && json_get_int(body, "account_id", account_id) != 0) return -1;
    return 0;
}

int api_session_start(int account_id, const char *client_ip, const char *destination, int max_concurrent, char *reason, size_t reason_len) {
    char json[1024], body[2048];
    snprintf(json, sizeof(json),
        "{\"account_id\":%d,\"client_ip\":\"%s\",\"destination\":\"%s\",\"max_concurrent\":%d}",
        account_id, client_ip ? client_ip : "", destination ? destination : "", max_concurrent);
    int status = 0;
    if(http_post_json("/api/internal/socks/session/start", json, &status, body, sizeof(body)) != 0) return -1;
    if(status != 200 || strstr(body, "\"ok\":true") == NULL) {
        if(reason && reason_len) {
            if(json_get_string(body, "reason", reason, reason_len) != 0)
                snprintf(reason, reason_len, "%s", "session_start_failed");
        }
        return -1;
    }
    return 0;
}

int api_accounting_update(int account_id, int64_t bytes_sent, int64_t bytes_received) {
    char json[512], body[1024];
    snprintf(json, sizeof(json),
        "{\"account_id\":%d,\"bytes_sent\":%lld,\"bytes_received\":%lld}",
        account_id, (long long)bytes_sent, (long long)bytes_received);
    int status = 0;
    if(http_post_json("/api/internal/socks/accounting", json, &status, body, sizeof(body)) != 0) return -1;
    return (status == 200 && strstr(body, "\"ok\":true") != NULL) ? 0 : -1;
}

int api_session_end(int account_id, const char *client_ip, const char *destination, const char *status,
                    int64_t bytes_sent, int64_t bytes_received, int online_tracked) {
    char json[1024], body[1024];
    snprintf(json, sizeof(json),
        "{\"account_id\":%d,\"client_ip\":\"%s\",\"destination\":\"%s\",\"status\":\"%s\","
        "\"bytes_sent\":%lld,\"bytes_received\":%lld,\"online_tracked\":%d}",
        account_id, client_ip ? client_ip : "", destination ? destination : "", status ? status : "failed",
        (long long)bytes_sent, (long long)bytes_received, online_tracked ? 1 : 0);
    int code = 0;
    if(http_post_json("/api/internal/socks/session/end", json, &code, body, sizeof(body)) != 0) return -1;
    return (code == 200 && strstr(body, "\"ok\":true") != NULL) ? 0 : -1;
}
