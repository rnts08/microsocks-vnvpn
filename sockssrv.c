/*
   MicroSocks - multithreaded, small, efficient SOCKS5 server.

   Copyright (C) 2017 rofl0r.

   This is the successor of "rocksocks5", and it was written with
   different goals in mind:

   - prefer usage of standard libc functions over homegrown ones
   - no artificial limits
   - do not aim for minimal binary size, but for minimal source code size,
     and maximal readability, reusability, and extensibility.

   as a result of that, ipv4, dns, and ipv6 is supported out of the box
   and can use the same code, while rocksocks5 has several compile time
   defines to bring down the size of the resulting binary to extreme values
   like 10 KB static linked when only ipv4 support is enabled.

   still, if optimized for size, *this* program when static linked against musl
   libc is not even 50 KB. that's easily usable even on the cheapest routers.

*/

#define _GNU_SOURCE
#include <unistd.h>
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "server.h"
#include "sblist.h"
#include "db.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <libgen.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <inttypes.h>

/* timeout in microseconds on resource exhaustion to prevent excessive
   cpu usage. */
#ifndef FAILURE_TIMEOUT
#define FAILURE_TIMEOUT 64
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifdef PTHREAD_STACK_MIN
#define THREAD_STACK_SIZE MAX(16*1024, PTHREAD_STACK_MIN)
#else
#define THREAD_STACK_SIZE 64*1024
#endif

#if defined(__APPLE__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 64*1024
#elif defined(__GLIBC__) || defined(__FreeBSD__) || defined(__sun__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 32*1024
#elif defined(__OpenBSD__) && defined(__clang__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 32*1024
#endif

static int quiet;
static const struct server* server;
static union sockaddr_union bind_addr = {.v4.sin_family = AF_UNSPEC};

/* Configuration structure */
struct cfg {
	int quiet; /* 0 = verbose, 1 = quiet */
	char listenip[128];
	unsigned port;
	char dbpath[PATH_MAX];
	char logfile[PATH_MAX];
	int auth_fail_window_sec;
	int auth_fail_limit;
	int connect_rate_window_sec;
	int connect_rate_limit;
	int max_concurrent_per_account;
	int connections_retention_days;
	char metrics_listen[128];
	unsigned metrics_port;
};

struct metrics_state {
	pthread_mutex_t lock;
	uint64_t auth_failures_total;
	uint64_t active_sessions;
	uint64_t bytes_up_total;
	uint64_t bytes_down_total;
	uint64_t db_calls_total;
	uint64_t db_latency_usec_total;
	uint64_t db_latency_usec_max;
	time_t started_at;
};

static struct metrics_state g_metrics = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.started_at = 0,
};

static int metrics_server_enabled = 0;
static char metrics_listen_addr[128] = "127.0.0.1";
static unsigned metrics_listen_port = 0;

#define RL_MAX_ENTRIES 1024

struct rl_entry {
	char key[INET6_ADDRSTRLEN + 1];
	int count;
	time_t window_start;
};

static struct rl_entry auth_fail_rl[RL_MAX_ENTRIES];
static struct rl_entry connect_rl[RL_MAX_ENTRIES];
static pthread_mutex_t rl_lock = PTHREAD_MUTEX_INITIALIZER;

static int cfg_auth_fail_window_sec = 300;
static int cfg_auth_fail_limit = 10;
static int cfg_connect_rate_window_sec = 60;
static int cfg_connect_rate_limit = 60;
static int cfg_max_concurrent_per_account = 3;
static int cfg_connections_retention_days = 90;
static time_t last_connections_prune = 0;

/* Helper: trim whitespace in place */
static char *trim(char *s) {
	if(!s) return s;
	while(*s && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) s++;
	if(*s == '\0') return s;
	char *end = s + strlen(s) - 1;
	while(end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) *end-- = '\0';
	return s;
}

/* parse boolean-ish values */
static int parse_bool(const char *v) {
	if(!v) return 0;
	if(strcmp(v, "1") == 0) return 1;
	if(strcasecmp(v, "true") == 0) return 1;
	if(strcasecmp(v, "yes") == 0) return 1;
	return 0;
}

static int parse_int_default(const char *v, int def) {
	if(!v || !*v) return def;
	char *end = NULL;
	long x = strtol(v, &end, 10);
	if(end == v || *end != '\0') return def;
	if(x < 0) return def;
	if(x > INT_MAX) return def;
	return (int)x;
}

static uint64_t now_monotonic_usec(void) {
	struct timespec ts;
	if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
	return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
}

static uint64_t metrics_db_start(void) {
	return now_monotonic_usec();
}

static void metrics_db_finish(uint64_t started_usec) {
	if(started_usec == 0) return;
	uint64_t ended_usec = now_monotonic_usec();
	if(ended_usec < started_usec) return;
	uint64_t latency = ended_usec - started_usec;
	pthread_mutex_lock(&g_metrics.lock);
	g_metrics.db_calls_total++;
	g_metrics.db_latency_usec_total += latency;
	if(latency > g_metrics.db_latency_usec_max)
		g_metrics.db_latency_usec_max = latency;
	pthread_mutex_unlock(&g_metrics.lock);
}

static void metrics_auth_failure_inc(void) {
	pthread_mutex_lock(&g_metrics.lock);
	g_metrics.auth_failures_total++;
	pthread_mutex_unlock(&g_metrics.lock);
}

static void metrics_active_sessions_add(int delta) {
	pthread_mutex_lock(&g_metrics.lock);
	if(delta > 0) {
		g_metrics.active_sessions += (uint64_t)delta;
	} else if(delta < 0) {
		uint64_t sub = (uint64_t)(-delta);
		if(g_metrics.active_sessions > sub) g_metrics.active_sessions -= sub;
		else g_metrics.active_sessions = 0;
	}
	pthread_mutex_unlock(&g_metrics.lock);
}

static void metrics_add_connection_bytes(size_t up, size_t down) {
	pthread_mutex_lock(&g_metrics.lock);
	g_metrics.bytes_up_total += (uint64_t)up;
	g_metrics.bytes_down_total += (uint64_t)down;
	pthread_mutex_unlock(&g_metrics.lock);
}

static int metrics_build_text(char *out, size_t outlen) {
	uint64_t auth_failures_total, active_sessions, bytes_up_total, bytes_down_total;
	uint64_t db_calls_total, db_latency_usec_total, db_latency_usec_max;
	time_t started_at;
	pthread_mutex_lock(&g_metrics.lock);
	auth_failures_total = g_metrics.auth_failures_total;
	active_sessions = g_metrics.active_sessions;
	bytes_up_total = g_metrics.bytes_up_total;
	bytes_down_total = g_metrics.bytes_down_total;
	db_calls_total = g_metrics.db_calls_total;
	db_latency_usec_total = g_metrics.db_latency_usec_total;
	db_latency_usec_max = g_metrics.db_latency_usec_max;
	started_at = g_metrics.started_at;
	pthread_mutex_unlock(&g_metrics.lock);

	time_t now = time(NULL);
	double uptime = (started_at > 0 && now > started_at) ? (double)(now - started_at) : 1.0;
	double bytes_per_sec = ((double)bytes_up_total + (double)bytes_down_total) / uptime;
	double db_latency_avg_seconds = 0.0;
	if(db_calls_total > 0)
		db_latency_avg_seconds = ((double)db_latency_usec_total / 1000000.0) / (double)db_calls_total;

	return snprintf(out, outlen,
		"# HELP microsocks_auth_failures_total Total failed authentication attempts.\n"
		"# TYPE microsocks_auth_failures_total counter\n"
		"microsocks_auth_failures_total %" PRIu64 "\n"
		"# HELP microsocks_active_sessions Active authenticated proxy sessions.\n"
		"# TYPE microsocks_active_sessions gauge\n"
		"microsocks_active_sessions %" PRIu64 "\n"
		"# HELP microsocks_bytes_uploaded_total Total bytes uploaded from client to remote.\n"
		"# TYPE microsocks_bytes_uploaded_total counter\n"
		"microsocks_bytes_uploaded_total %" PRIu64 "\n"
		"# HELP microsocks_bytes_downloaded_total Total bytes downloaded from remote to client.\n"
		"# TYPE microsocks_bytes_downloaded_total counter\n"
		"microsocks_bytes_downloaded_total %" PRIu64 "\n"
		"# HELP microsocks_bytes_per_second Average bytes per second since process start.\n"
		"# TYPE microsocks_bytes_per_second gauge\n"
		"microsocks_bytes_per_second %.6f\n"
		"# HELP microsocks_db_calls_total Number of measured DB calls from server request path.\n"
		"# TYPE microsocks_db_calls_total counter\n"
		"microsocks_db_calls_total %" PRIu64 "\n"
		"# HELP microsocks_db_latency_seconds_avg Average measured DB latency in seconds.\n"
		"# TYPE microsocks_db_latency_seconds_avg gauge\n"
		"microsocks_db_latency_seconds_avg %.6f\n"
		"# HELP microsocks_db_latency_seconds_max Max measured DB latency in seconds.\n"
		"# TYPE microsocks_db_latency_seconds_max gauge\n"
		"microsocks_db_latency_seconds_max %.6f\n",
		auth_failures_total,
		active_sessions,
		bytes_up_total,
		bytes_down_total,
		bytes_per_sec,
		db_calls_total,
		db_latency_avg_seconds,
		(double)db_latency_usec_max / 1000000.0);
}

static void *metrics_server_thread(void *unused) {
	(void)unused;
	struct server ms;
	if(server_setup(&ms, metrics_listen_addr, (unsigned short)metrics_listen_port) != 0) {
		dprintf(2, "metrics server_setup failed on %s:%u\n", metrics_listen_addr, metrics_listen_port);
		return NULL;
	}

	for(;;) {
		struct client c;
		if(server_waitclient(&ms, &c) != 0) {
			usleep(FAILURE_TIMEOUT);
			continue;
		}
		char req[1024];
		ssize_t n = recv(c.fd, req, sizeof(req)-1, 0);
		if(n <= 0) {
			close(c.fd);
			continue;
		}
		req[n] = '\0';

		const char *response_404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnot found\n";
		const char *response_health = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
		if(strncmp(req, "GET /metrics", 12) == 0) {
			char body[4096];
			int blen = metrics_build_text(body, sizeof(body));
			if(blen < 0) blen = 0;
			char header[256];
			int hlen = snprintf(header, sizeof(header),
				"HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
				blen);
			write(c.fd, header, (size_t)hlen);
			if(blen > 0) write(c.fd, body, (size_t)blen);
		} else if(strncmp(req, "GET /healthz", 12) == 0 || strncmp(req, "GET /-/healthy", 14) == 0) {
			write(c.fd, response_health, strlen(response_health));
		} else {
			write(c.fd, response_404, strlen(response_404));
		}
		close(c.fd);
	}
	return NULL;
}

static struct rl_entry *rl_get_slot(struct rl_entry *table, const char *key) {
	unsigned long h = 5381;
	for(const unsigned char *p = (const unsigned char*)key; *p; ++p)
		h = ((h << 5) + h) + *p;
	int idx = (int)(h % RL_MAX_ENTRIES);
	for(int i = 0; i < RL_MAX_ENTRIES; ++i) {
		int pos = (idx + i) % RL_MAX_ENTRIES;
		if(table[pos].key[0] == '\0') {
			strncpy(table[pos].key, key, sizeof(table[pos].key)-1);
			table[pos].key[sizeof(table[pos].key)-1] = '\0';
			return &table[pos];
		}
		if(strcmp(table[pos].key, key) == 0)
			return &table[pos];
	}
	return &table[idx];
}

static int rl_consume(struct rl_entry *table, const char *key, int window_sec, int limit, int penalty_on_reject) {
	time_t now = time(NULL);
	int allowed = 1;
	if(limit <= 0 || window_sec <= 0) return 1;
	pthread_mutex_lock(&rl_lock);
	struct rl_entry *e = rl_get_slot(table, key);
	if(now - e->window_start >= window_sec || e->window_start == 0) {
		e->window_start = now;
		e->count = 0;
	}
	if(e->count >= limit) {
		allowed = 0;
		if(penalty_on_reject) e->count++;
	} else {
		e->count++;
	}
	pthread_mutex_unlock(&rl_lock);
	return allowed;
}

static void record_auth_failure(const char *client_ip) {
	if(!client_ip || !*client_ip) return;
	(void)rl_consume(auth_fail_rl, client_ip, cfg_auth_fail_window_sec, cfg_auth_fail_limit, 1);
}

static int auth_fail_rate_allowed(const char *client_ip) {
	if(!client_ip || !*client_ip) return 1;
	return rl_consume(auth_fail_rl, client_ip, cfg_auth_fail_window_sec, cfg_auth_fail_limit, 0);
}

static int connection_rate_allowed(const char *client_ip) {
	if(!client_ip || !*client_ip) return 1;
	return rl_consume(connect_rl, client_ip, cfg_connect_rate_window_sec, cfg_connect_rate_limit, 0);
}

/* Read a simple ini-style file with lines key = value (no sections). */
static void read_config_file(const char *path, struct cfg *cfg) {
	FILE *f = fopen(path, "r");
	if(!f) return; /* silently ignore if not present */
	char line[512];
	while(fgets(line, sizeof line, f)) {
		char *p = line;
		/* skip comments and empty lines */
		while(*p == ' ' || *p == '\t') p++;
		if(*p == '\0' || *p == '\n' || *p == '#' || *p == ';') continue;
		char *eq = strchr(p, '=');
		if(!eq) continue;
		*eq = '\0';
		char *key = trim(p);
		char *val = trim(eq + 1);
		/* remove inline comments */
		char *cpos = strpbrk(val, "#;");
		if(cpos) *cpos = '\0';
		val = trim(val);
		if(strcasecmp(key, "quiet") == 0) {
			cfg->quiet = parse_bool(val);
		} else if(strcasecmp(key, "listen") == 0) {
			strncpy(cfg->listenip, val, sizeof(cfg->listenip)-1);
			cfg->listenip[sizeof(cfg->listenip)-1] = '\0';
		} else if(strcasecmp(key, "port") == 0) {
			cfg->port = (unsigned)atoi(val);
        } else if(strcasecmp(key, "database") == 0) {
            strncpy(cfg->dbpath, val, sizeof(cfg->dbpath)-1);
            cfg->dbpath[sizeof(cfg->dbpath)-1] = '\0';
		} else if(strcasecmp(key, "logfile") == 0) {
            strncpy(cfg->logfile, val, sizeof(cfg->logfile)-1);
            cfg->logfile[sizeof(cfg->logfile)-1] = '\0';
		} else if(strcasecmp(key, "auth_fail_window_sec") == 0) {
			cfg->auth_fail_window_sec = parse_int_default(val, cfg->auth_fail_window_sec);
		} else if(strcasecmp(key, "auth_fail_limit") == 0) {
			cfg->auth_fail_limit = parse_int_default(val, cfg->auth_fail_limit);
		} else if(strcasecmp(key, "connect_rate_window_sec") == 0) {
			cfg->connect_rate_window_sec = parse_int_default(val, cfg->connect_rate_window_sec);
		} else if(strcasecmp(key, "connect_rate_limit") == 0) {
			cfg->connect_rate_limit = parse_int_default(val, cfg->connect_rate_limit);
		} else if(strcasecmp(key, "max_concurrent_per_account") == 0) {
			cfg->max_concurrent_per_account = parse_int_default(val, cfg->max_concurrent_per_account);
		} else if(strcasecmp(key, "connections_retention_days") == 0) {
			cfg->connections_retention_days = parse_int_default(val, cfg->connections_retention_days);
		} else if(strcasecmp(key, "metrics_listen") == 0) {
			strncpy(cfg->metrics_listen, val, sizeof(cfg->metrics_listen)-1);
			cfg->metrics_listen[sizeof(cfg->metrics_listen)-1] = '\0';
		} else if(strcasecmp(key, "metrics_port") == 0) {
			cfg->metrics_port = (unsigned)parse_int_default(val, (int)cfg->metrics_port);
        }
    }
    fclose(f);
}/* Determine default DB path: directory of binary + /microsocks.db. */
static void default_dbpath(char *out, size_t olen) {
	char exe[PATH_MAX] = {0};
	ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe)-1);
	if(n <= 0) {
		/* fallback to ./microsocks.db */
		strncpy(out, "microsocks.db", olen-1);
		out[olen-1] = '\0';
		return;
	}
	exe[n] = '\0';
	/* dirname may modify input, copy */
	char dir[PATH_MAX];
	strncpy(dir, exe, sizeof(dir)-1);
	dir[sizeof(dir)-1] = '\0';
	char *d = dirname(dir);
	if(!d) strncpy(out, "microsocks.db", olen-1);
	else snprintf(out, olen, "%s/microsocks.db", d);
}

enum socksstate {
	SS_1_CONNECTED,
	SS_2_NEED_AUTH, /* skipped if NO_AUTH method supported */
	SS_3_AUTHED,
};

enum authmethod {
	AM_NO_AUTH = 0,
	AM_GSSAPI = 1,
	AM_USERNAME = 2,
	AM_INVALID = 0xFF
};

enum errorcode {
	EC_SUCCESS = 0,
	EC_GENERAL_FAILURE = 1,
	EC_NOT_ALLOWED = 2,
	EC_NET_UNREACHABLE = 3,
	EC_HOST_UNREACHABLE = 4,
	EC_CONN_REFUSED = 5,
	EC_TTL_EXPIRED = 6,
	EC_COMMAND_NOT_SUPPORTED = 7,
	EC_ADDRESSTYPE_NOT_SUPPORTED = 8,
};

struct thread {
	pthread_t pt;
	struct client client;
	enum socksstate state;
	volatile int done;
	/* Database and accounting fields */
	int account_id;  /* -1 if not authenticated */
	char dest[256];
	size_t bytes_client_to_remote;
	size_t bytes_remote_to_client;
};

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to a configurable fd (default stderr=2). dprintf is used so we avoid
   heap allocations from printf inside threads. */
static int logfd = 2;
static char logfile_path[PATH_MAX] = "";

/* Reopen logfile (for rotation)
 * Signal handlers must use the signature void handler(int). We accept the
 * argument but ignore it when called directly (pass 0).
 */
static void reopen_logfile(int sig) {
    if(!logfile_path[0]) return; /* using stderr */
    
    /* Try to open in append mode */
    int new_fd = open(logfile_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if(new_fd == -1) {
        /* On failure, log to stderr and continue */
        dprintf(2, "Failed to open logfile %s: %s. Falling back to stderr.\n",
                logfile_path, strerror(errno));
        if(logfd != 2) close(logfd);
        logfd = 2;
        return;
    }
    
    /* Success - swap the fd */
    if(logfd != 2) close(logfd);
    logfd = new_fd;
}

/* Thread-safe logging with automatic fallback */
#define dolog(...) do { \
    if(!quiet) { \
        if(dprintf(logfd, __VA_ARGS__) < 0) { \
			/* On write failure, try to reopen once (call handler form with 0) */ \
			reopen_logfile(0); \
            /* Second attempt, this time to wherever logfd points */ \
            dprintf(logfd, __VA_ARGS__); \
        } \
    } \
} while(0)

#else
static void dolog(const char* fmt, ...) { }
#endif

static struct addrinfo* addr_choose(struct addrinfo* list, union sockaddr_union* bindaddr) {
	int af = SOCKADDR_UNION_AF(bindaddr);
	if(af == AF_UNSPEC) return list;
	struct addrinfo* p;
	for(p=list; p; p=p->ai_next)
		if(p->ai_family == af) return p;
	return list;
}

static int connect_socks_target(unsigned char *buf, size_t n, struct client *client, char *destbuf, size_t destlen) {
	if(n < 5) return -EC_GENERAL_FAILURE;
	if(buf[0] != 5) return -EC_GENERAL_FAILURE;
	if(buf[1] != 1) return -EC_COMMAND_NOT_SUPPORTED; /* we support only CONNECT method */
	if(buf[2] != 0) return -EC_GENERAL_FAILURE; /* malformed packet */

	int af = AF_INET;
	size_t minlen = 4 + 4 + 2, l;
	char namebuf[256];
	struct addrinfo* remote;

	switch(buf[3]) {
		case 4: /* ipv6 */
			af = AF_INET6;
			minlen = 4 + 2 + 16;
			/* fall through */
		case 1: /* ipv4 */
			if(n < minlen) return -EC_GENERAL_FAILURE;
			if(namebuf != inet_ntop(af, buf+4, namebuf, sizeof namebuf))
				return -EC_GENERAL_FAILURE; /* malformed or too long addr */
			break;
		case 3: /* dns name */
			l = buf[4];
			minlen = 4 + 2 + l + 1;
			if(n < 4 + 2 + l + 1) return -EC_GENERAL_FAILURE;
			memcpy(namebuf, buf+4+1, l);
			namebuf[l] = 0;
			break;
		default:
			return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
	unsigned short port;
	port = (buf[minlen-2] << 8) | buf[minlen-1];
	/* populate a human-readable destination for accounting/logging */
	if(destbuf && destlen) {
		snprintf(destbuf, destlen, "%s:%u", namebuf, port);
	}
	/* there's no suitable errorcode in rfc1928 for dns lookup failure */
	if(resolve(namebuf, port, &remote)) return -EC_GENERAL_FAILURE;
	struct addrinfo* raddr = addr_choose(remote, &bind_addr);
	int fd = socket(raddr->ai_family, SOCK_STREAM, 0);
	if(fd == -1) {
		eval_errno:
		if(fd != -1) close(fd);
		freeaddrinfo(remote);
		switch(errno) {
			case ETIMEDOUT:
				return -EC_TTL_EXPIRED;
			case EPROTOTYPE:
			case EPROTONOSUPPORT:
			case EAFNOSUPPORT:
				return -EC_ADDRESSTYPE_NOT_SUPPORTED;
			case ECONNREFUSED:
				return -EC_CONN_REFUSED;
			case ENETDOWN:
			case ENETUNREACH:
				return -EC_NET_UNREACHABLE;
			case EHOSTUNREACH:
				return -EC_HOST_UNREACHABLE;
			case EBADF:
			default:
			perror("socket/connect");
			return -EC_GENERAL_FAILURE;
		}
	}
	if(SOCKADDR_UNION_AF(&bind_addr) == raddr->ai_family &&
	   bindtoip(fd, &bind_addr) == -1)
		goto eval_errno;
	if(connect(fd, raddr->ai_addr, raddr->ai_addrlen) == -1)
		goto eval_errno;

	freeaddrinfo(remote);
	if(CONFIG_LOG) {
		char clientname[256];
		af = SOCKADDR_UNION_AF(&client->addr);
		void *ipdata = SOCKADDR_UNION_ADDRESS(&client->addr);
		inet_ntop(af, ipdata, clientname, sizeof clientname);
		dolog("client[%d] %s: connected to %s:%d\n", client->fd, clientname, namebuf, port);
	}
	return fd;
}

/* Check if an IP is in the account's whitelist
   Returns:
   1 = IP is allowed (either in whitelist or whitelist is empty)
   0 = IP is not in whitelist */
static int is_ip_allowed(int account_id, const char *client_ip) {
    union sockaddr_union sa;
    memset(&sa, 0, sizeof(sa));

    if(strchr(client_ip, ':')) {
        sa.v6.sin6_family = AF_INET6;
        if(inet_pton(AF_INET6, client_ip, &sa.v6.sin6_addr) != 1)
            return 0;
    } else {
        sa.v4.sin_family = AF_INET;
        if(inet_pton(AF_INET, client_ip, &sa.v4.sin_addr) != 1)
            return 0;
    }

    return db_account_check_whitelist(account_id, &sa);
}

static enum authmethod check_auth_method(unsigned char *buf, size_t n, struct client*client) {
	if(buf[0] != 5) return AM_INVALID;
	size_t idx = 1;
	if(idx >= n ) return AM_INVALID;
	int n_methods = buf[idx];
	idx++;
	int has_username = 0;
	while(idx < n && n_methods > 0) {
		if(buf[idx] == AM_USERNAME) has_username = 1;
		idx++;
		n_methods--;
	}
	/* Always require username/password auth if offered */
	if(has_username) return AM_USERNAME;
	/* Reject if no supported auth method */
	return AM_INVALID;
}

static void send_auth_response(int fd, int version, enum authmethod meth) {
	unsigned char buf[2];
	buf[0] = version;
	buf[1] = meth;
	write(fd, buf, 2);
}

static void send_error(int fd, enum errorcode ec) {
	/* position 4 contains ATYP, the address type, which is the same as used in the connect
	   request. we're lazy and return always IPV4 address type in errors. */
	char buf[10] = { 5, ec, 0, 1 /*AT_IPV4*/, 0,0,0,0, 0,0 };
	write(fd, buf, 10);
}

static void copyloop(int fd1, int fd2, size_t *bytes_fd1_to_fd2, size_t *bytes_fd2_to_fd1) {
	struct pollfd fds[2] = {
		[0] = {.fd = fd1, .events = POLLIN},
		[1] = {.fd = fd2, .events = POLLIN},
	};

	while(1) {
		/* inactive connections are reaped after 15 min to free resources.
		   usually programs send keep-alive packets so this should only happen
		   when a connection is really unused. */
		switch(poll(fds, 2, 60*15*1000)) {
			case 0:
				return;
			case -1:
				if(errno == EINTR || errno == EAGAIN) continue;
				else perror("poll");
				return;
		}
		int infd = (fds[0].revents & POLLIN) ? fd1 : fd2;
		int outfd = infd == fd2 ? fd1 : fd2;
		/* since the biggest stack consumer in the entire code is
		   libc's getaddrinfo(), we can safely use at least half the
		   available stacksize to improve throughput. */
		char buf[MIN(16*1024, THREAD_STACK_SIZE/2)];
		ssize_t sent = 0, n = read(infd, buf, sizeof buf);
		if(n <= 0) return;
		while(sent < n) {
			ssize_t m = write(outfd, buf+sent, n-sent);
			if(m < 0) return;
			sent += m;
		}
		/* update accounting counters */
		if(bytes_fd1_to_fd2 && bytes_fd2_to_fd1) {
			if(infd == fd1) *bytes_fd1_to_fd2 += (size_t)n;
			else *bytes_fd2_to_fd1 += (size_t)n;
		}
	}
}

static enum errorcode check_credentials(unsigned char* buf, size_t n, struct thread *t) {
	if(n < 5) return EC_GENERAL_FAILURE;
	if(buf[0] != 1) return EC_GENERAL_FAILURE;
	unsigned ulen, plen;
	ulen=buf[1];
	if(n < 2 + ulen + 2) return EC_GENERAL_FAILURE;
	plen=buf[2+ulen];
	if(n < 2 + ulen + 1 + plen) return EC_GENERAL_FAILURE;
	char user[256], pass[256];
	memcpy(user, buf+2, ulen);
	memcpy(pass, buf+2+ulen+1, plen);
	user[ulen] = 0;
	pass[plen] = 0;

	/* Get client IP for checks */
	char client_ip[INET6_ADDRSTRLEN];
	void *addr_ptr = SOCKADDR_UNION_ADDRESS(&t->client.addr);
	inet_ntop(SOCKADDR_UNION_AF(&t->client.addr), addr_ptr, client_ip, sizeof(client_ip));
	if(!auth_fail_rate_allowed(client_ip))
		return EC_NOT_ALLOWED;

	/* Use database authentication */
	{
		uint64_t db_started = metrics_db_start();
		t->account_id = db_account_auth(user, pass);
		metrics_db_finish(db_started);
	}
	if(t->account_id == -2) return EC_NOT_ALLOWED; /* account disabled */
	if(t->account_id >= 0) {
		/* Check whitelist */
		uint64_t wl_db_started = metrics_db_start();
		int wl_ok = is_ip_allowed(t->account_id, client_ip);
		metrics_db_finish(wl_db_started);
		if(!wl_ok) {
			record_auth_failure(client_ip);
			metrics_auth_failure_inc();
			return EC_NOT_ALLOWED;
		}
		
		/* Update last client IP */
		{
			uint64_t db_started = metrics_db_start();
			db_account_update_last_ip(t->account_id, client_ip);
			metrics_db_finish(db_started);
		}
		return EC_SUCCESS;
	}
	record_auth_failure(client_ip);
	metrics_auth_failure_inc();
	return EC_NOT_ALLOWED;
}

static int handshake(struct thread *t) {
	unsigned char buf[1024];
	ssize_t n;
	int ret;
	enum authmethod am;
	t->state = SS_1_CONNECTED;
	while((n = recv(t->client.fd, buf, sizeof buf, 0)) > 0) {
		switch(t->state) {
			case SS_1_CONNECTED:
				am = check_auth_method(buf, n, &t->client);
				if(am == AM_NO_AUTH) t->state = SS_3_AUTHED;
				else if (am == AM_USERNAME) t->state = SS_2_NEED_AUTH;
				send_auth_response(t->client.fd, 5, am);
				if(am == AM_INVALID) return -1;
				break;
			case SS_2_NEED_AUTH:
				ret = check_credentials(buf, n, t);
				send_auth_response(t->client.fd, 1, ret);
				if(ret != EC_SUCCESS)
					return -1;
				t->state = SS_3_AUTHED;
				break;
			case SS_3_AUTHED:
				ret = connect_socks_target(buf, n, &t->client, t->dest, sizeof t->dest);
				if(ret < 0) {
					send_error(t->client.fd, ret*-1);
					return -1;
				}
				send_error(t->client.fd, EC_SUCCESS);
				return ret;
		}
	}
	return -1;
}

static int account_monthly_quota_exceeded(int account_id) {
	sqlite3_stmt *stmt;
	const char *sql = "SELECT monthly_bandwidth, m_bytes_sent + m_bytes_received "
	                 "FROM accounts WHERE id = ?";
	if(db_stmt_prepare(sql, &stmt) != SQLITE_OK) return 0;
	sqlite3_bind_int(stmt, 1, account_id);
	int exceeded = 0;
	if(sqlite3_step(stmt) == SQLITE_ROW) {
		int64_t limit = sqlite3_column_int64(stmt, 0);
		int64_t used = sqlite3_column_int64(stmt, 1);
		if(limit > 0 && used >= limit) exceeded = 1;
	}
	sqlite3_finalize(stmt);
	return exceeded;
}

static void* clientthread(void *data) {
	struct thread *t = data;
	/* initialize accounting fields */
	t->bytes_client_to_remote = 0;
	t->bytes_remote_to_client = 0;
	t->dest[0] = 0;

	int remotefd = handshake(t);
	int online_tracked = 0;
	const char *connection_status = "failed";
	if(remotefd != -1 && t->account_id >= 0) {
		char client_ip[INET6_ADDRSTRLEN];
		void *ipdata = SOCKADDR_UNION_ADDRESS(&t->client.addr);
		inet_ntop(SOCKADDR_UNION_AF(&t->client.addr), ipdata, client_ip, sizeof(client_ip));

		if(!connection_rate_allowed(client_ip)) {
			connection_status = "rate_limited";
			close(remotefd);
			remotefd = -1;
		} else if(cfg_max_concurrent_per_account > 0) {
			uint64_t db_started = metrics_db_start();
			int online_now = db_account_get_online(t->account_id);
			metrics_db_finish(db_started);
			if(online_now >= cfg_max_concurrent_per_account) {
				connection_status = "max_concurrent_exceeded";
				close(remotefd);
				remotefd = -1;
			}
		}
	}
	if(remotefd != -1 && t->account_id >= 0) {
		uint64_t quota_db_started = metrics_db_start();
		int quota_exceeded = account_monthly_quota_exceeded(t->account_id);
		metrics_db_finish(quota_db_started);
		if(quota_exceeded) {
			if(CONFIG_LOG) {
				char clientname[256];
				int af = SOCKADDR_UNION_AF(&t->client.addr);
				void *ipdata = SOCKADDR_UNION_ADDRESS(&t->client.addr);
				inet_ntop(af, ipdata, clientname, sizeof clientname);
				dolog("account: %s -> %s: status=bandwidth_limit_exceeded\n", clientname,
					t->dest[0] ? t->dest : "-");
			}
			connection_status = "bandwidth_limit_exceeded";
			close(remotefd);
			remotefd = -1;
		} else {
			uint64_t db_started = metrics_db_start();
			int online_rc = db_account_update_online(t->account_id, +1);
			metrics_db_finish(db_started);
			if(online_rc == SQLITE_OK) {
				online_tracked = 1;
				metrics_active_sessions_add(+1);
			}
		}
	}
	if(remotefd != -1) {
		copyloop(t->client.fd, remotefd, &t->bytes_client_to_remote, &t->bytes_remote_to_client);
		close(remotefd);
		if(CONFIG_LOG) {
			char clientname[256];
			int af = SOCKADDR_UNION_AF(&t->client.addr);
			void *ipdata = SOCKADDR_UNION_ADDRESS(&t->client.addr);
			inet_ntop(af, ipdata, clientname, sizeof clientname);
			dolog("account: %s -> %s: status=success sent=%zu recv=%zu\n",
				 clientname, t->dest[0] ? t->dest : "-", t->bytes_client_to_remote, t->bytes_remote_to_client);
		}
		/* Update bandwidth usage */
		if(t->account_id >= 0) {
			uint64_t db_started = metrics_db_start();
			db_account_update_bandwidth(t->account_id, t->bytes_client_to_remote, t->bytes_remote_to_client);
			metrics_db_finish(db_started);
		}
		metrics_add_connection_bytes(t->bytes_client_to_remote, t->bytes_remote_to_client);
		connection_status = "success";
	} else {
		if(CONFIG_LOG) {
			char clientname[256];
			int af = SOCKADDR_UNION_AF(&t->client.addr);
			void *ipdata = SOCKADDR_UNION_ADDRESS(&t->client.addr);
			inet_ntop(af, ipdata, clientname, sizeof clientname);
			dolog("account: %s -> %s: status=failed sent=0 recv=0\n",
				 clientname, t->dest[0] ? t->dest : "-");
		}
	}

	/* Log connection to database */
	if (t->account_id >= 0) {
		char clientname[256];
		void *ipdata = SOCKADDR_UNION_ADDRESS(&t->client.addr);
		inet_ntop(SOCKADDR_UNION_AF(&t->client.addr), ipdata, clientname, sizeof clientname);
		uint64_t db_started = metrics_db_start();
		db_log_connection(t->account_id, clientname, t->dest[0] ? t->dest : "-",
						 connection_status,
						 t->bytes_client_to_remote, t->bytes_remote_to_client);
		metrics_db_finish(db_started);
		if(online_tracked) {
			uint64_t db_started = metrics_db_start();
			db_account_update_online(t->account_id, -1);
			metrics_db_finish(db_started);
			metrics_active_sessions_add(-1);
		}
	}

	close(t->client.fd);
	t->done = 1;
	return 0;
}

static int current_month_key(time_t now) {
	struct tm t;
	if(localtime_r(&now, &t) == NULL)
		return -1;
	return (t.tm_year + 1900) * 100 + (t.tm_mon + 1);
}

static void collect(sblist *threads) {
	size_t i;
	for(i=0;i<sblist_getsize(threads);) {
		struct thread* thread = *((struct thread**)sblist_get(threads, i));
		if(thread->done) {
			pthread_join(thread->pt, 0);
			sblist_delete(threads, i);
			free(thread);
		} else
			i++;
	}
}

/* Print effective configuration and exit */
static void print_config(const struct cfg *cfg) {
	printf("MicroSocks Configuration:\n"
		   "------------------\n"
		   "listen = %s\n"
		   "port = %u\n"
		   "quiet = %s\n"
		   "database = %s\n"
		   "logfile = %s\n"
		   "auth_fail_window_sec = %d\n"
		   "auth_fail_limit = %d\n"
		   "connect_rate_window_sec = %d\n"
		   "connect_rate_limit = %d\n"
		   "max_concurrent_per_account = %d\n"
		   "connections_retention_days = %d\n"
		   "metrics_listen = %s\n"
		   "metrics_port = %u\n",
		   cfg->listenip,
		   cfg->port,
		   cfg->quiet ? "true" : "false",
		   cfg->dbpath,
		   cfg->logfile[0] ? cfg->logfile : "(stderr)",
		   cfg->auth_fail_window_sec,
		   cfg->auth_fail_limit,
		   cfg->connect_rate_window_sec,
		   cfg->connect_rate_limit,
		   cfg->max_concurrent_per_account,
		   cfg->connections_retention_days,
		   cfg->metrics_listen,
		   cfg->metrics_port);
	exit(0);
}

static int usage(void) {
	dprintf(2,
		"MicroSocks SOCKS5 Server\n"
		"------------------------\n"
		"usage: microsocks [-f config] [-q] [-i listenip] [-p port] [-b bindaddr] [-d dbpath] [--print-config]\n"
		"\n"
		"Configuration: you can provide an INI-style config file (default: /etc/microsocks/microsocks.conf)\n"
		"via -f. The file supports simple key = value pairs (no sections):\n"
		"  quiet    = true|false    (disable logging)\n"
		"  listen   = <ip>          (listen address, e.g. 0.0.0.0)\n"
		"  port     = <port>        (listen port, e.g. 1080)\n"
		"  database = <path>        (sqlite DB path)\n"
		"  auth_fail_window_sec = <sec>\n"
		"  auth_fail_limit = <count>\n"
		"  connect_rate_window_sec = <sec>\n"
		"  connect_rate_limit = <count>\n"
		"  max_concurrent_per_account = <count>\n"
		"  connections_retention_days = <days>\n"
		"  metrics_listen = <ip>    (metrics HTTP bind address, default 127.0.0.1)\n"
		"  metrics_port = <port>    (metrics HTTP port, 0 disables endpoint)\n"
		"\n"
		"CLI flags override values in the config file. If no config is found, sane\n"
		"defaults are used: quiet=false, listen=0.0.0.0, port=1080, database is\n"
		"microsocks.db next to the server binary (fallback ./microsocks.db).\n"
		"\n"
		"option -f specifies a config file path (INI-style).\n"
		"option -q disables logging (overrides config quiet).\n"
		"option -b specifies which ip outgoing connections are bound to.\n"
		"option -i specifies the listen ip (overrides config listen).\n"
		"option -p specifies the port (overrides config port).\n"
		"option -d specifies the path to the SQLite database (overrides config database).\n"
		"\n"
		"Authentication is handled by the database. Create accounts with enabled=1\n"
		"and optionally set a whitelist of IPs in the accounts table. An empty\n"
		"whitelist allows connections from any IP address.\n"
	);
	return 1;
}

/* prevent username and password from showing up in top. */
/* zero_arg removed: command-line user/pass args are no longer supported; server
   authenticates exclusively against the database. */

int main(int argc, char** argv) {
	int ch;
	/* config handling */
	char config_path[PATH_MAX];
	/* default config file in /etc/microsocks */
	strncpy(config_path, "/etc/microsocks/microsocks.conf", sizeof(config_path)-1);
	config_path[sizeof(config_path)-1] = '\0';

	/* quick scan for -f to allow early config override (supports "-fpath" and "-f path") */
	for(int i=1;i<argc;i++) {
		if(strcmp(argv[i], "-f") == 0 && i+1 < argc) {
			strncpy(config_path, argv[i+1], sizeof(config_path)-1);
			config_path[sizeof(config_path)-1] = '\0';
			break;
		} else if(strncmp(argv[i], "-f", 2) == 0 && argv[i][2] != '\0') {
			strncpy(config_path, argv[i]+2, sizeof(config_path)-1);
			config_path[sizeof(config_path)-1] = '\0';
			break;
		}
	}

	struct cfg cfg;
	/* set sane defaults */
	cfg.quiet = 0; /* default: not quiet */
	strncpy(cfg.listenip, "0.0.0.0", sizeof(cfg.listenip)-1);
	cfg.listenip[sizeof(cfg.listenip)-1] = '\0';
	cfg.port = 1080;
	cfg.logfile[0] = '\0';
	cfg.auth_fail_window_sec = 300;
	cfg.auth_fail_limit = 10;
	cfg.connect_rate_window_sec = 60;
	cfg.connect_rate_limit = 60;
	cfg.max_concurrent_per_account = 3;
	cfg.connections_retention_days = 90;
	strncpy(cfg.metrics_listen, "127.0.0.1", sizeof(cfg.metrics_listen)-1);
	cfg.metrics_listen[sizeof(cfg.metrics_listen)-1] = '\0';
	cfg.metrics_port = 0;
	default_dbpath(cfg.dbpath, sizeof(cfg.dbpath));

	/* read config file if present */
	read_config_file(config_path, &cfg);

	/* apply config to runtime vars (can be overridden by CLI below) */
	quiet = cfg.quiet;
	char listenip_buf[128];
	strncpy(listenip_buf, cfg.listenip, sizeof(listenip_buf)-1);
	listenip_buf[sizeof(listenip_buf)-1] = '\0';
	char dbpath[PATH_MAX];
	strncpy(dbpath, cfg.dbpath, sizeof(dbpath)-1);
	dbpath[sizeof(dbpath)-1] = '\0';
	unsigned port = cfg.port;
	char logfile_cli[PATH_MAX] = "";

	/* parse CLI (overrides config). -f accepted and will re-read file. */
	optind = 1;
	
	/* Handle --print-config option first */
	for(int i=1; i<argc; i++) {
		if(strcmp(argv[i], "--print-config") == 0) {
			print_config(&cfg);
			/* never returns */
		}
	}
	
	while((ch = getopt(argc, argv, ":f:qb:i:p:d:L:")) != -1) {
		switch(ch) {
		case 'f':
				strncpy(config_path, optarg, sizeof(config_path)-1);
				config_path[sizeof(config_path)-1] = '\0';
				/* re-read */
				read_config_file(config_path, &cfg);
				/* re-apply */
				quiet = cfg.quiet;
				strncpy(listenip_buf, cfg.listenip, sizeof(listenip_buf)-1);
				listenip_buf[sizeof(listenip_buf)-1] = '\0';
				strncpy(dbpath, cfg.dbpath, sizeof(dbpath)-1);
				dbpath[sizeof(dbpath)-1] = '\0';
				port = cfg.port;
				break;
			case 'q':
				quiet = 1;
				break;
			case 'b':
				resolve_sa(optarg, 0, &bind_addr);
				break;
			case 'i':
				strncpy(listenip_buf, optarg, sizeof(listenip_buf)-1);
				listenip_buf[sizeof(listenip_buf)-1] = '\0';
				break;
			case 'd':
				strncpy(dbpath, optarg, sizeof(dbpath)-1);
				dbpath[sizeof(dbpath)-1] = '\0';
				break;
		case 'p':
			port = (unsigned)atoi(optarg);
			break;
		case 'L':
			strncpy(logfile_cli, optarg, sizeof(logfile_cli)-1);
			logfile_cli[sizeof(logfile_cli)-1] = '\0';
			break;
		case ':':
			dprintf(2, "error: option -%c requires an operand\n", optopt);
			/* fall through */
		case '?':
			return usage();
		}
	}
	const char *listenip = listenip_buf;
	cfg_auth_fail_window_sec = cfg.auth_fail_window_sec;
	cfg_auth_fail_limit = cfg.auth_fail_limit;
	cfg_connect_rate_window_sec = cfg.connect_rate_window_sec;
	cfg_connect_rate_limit = cfg.connect_rate_limit;
	cfg_max_concurrent_per_account = cfg.max_concurrent_per_account;
	cfg_connections_retention_days = cfg.connections_retention_days;
	strncpy(metrics_listen_addr, cfg.metrics_listen, sizeof(metrics_listen_addr)-1);
	metrics_listen_addr[sizeof(metrics_listen_addr)-1] = '\0';
	metrics_listen_port = cfg.metrics_port;
	metrics_server_enabled = (metrics_listen_port > 0);
	
	/* Setup signal handlers */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, reopen_logfile); /* Handle logfile rotation */

	/* Validate config values */
	if(port == 0 || port > 65535) {
		fprintf(stderr, "invalid port value: %u\n", port);
		return 1;
	}
	{
		struct addrinfo *ainfo = NULL;
		if(resolve(listenip, port, &ainfo) != 0) {
			fprintf(stderr, "invalid listen address: %s\n", listenip);
			return 1;
		}
		if(ainfo) freeaddrinfo(ainfo);
	}
	if(!dbpath[0]) {
		fprintf(stderr, "invalid database path\n");
		return 1;
	}
	if(metrics_server_enabled) {
		if(metrics_listen_port == 0 || metrics_listen_port > 65535) {
			fprintf(stderr, "invalid metrics port value: %u\n", metrics_listen_port);
			return 1;
		}
		struct addrinfo *minfo = NULL;
		if(resolve(metrics_listen_addr, (unsigned short)metrics_listen_port, &minfo) != 0) {
			fprintf(stderr, "invalid metrics listen address: %s\n", metrics_listen_addr);
			return 1;
		}
		if(minfo) freeaddrinfo(minfo);
	}

	/* Setup logfile if requested (CLI overrides config) */
	if(logfile_cli[0]) strncpy(cfg.logfile, logfile_cli, sizeof(cfg.logfile)-1);
	if(cfg.logfile[0]) {
		int fd = open(cfg.logfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if(fd == -1) {
			perror("opening logfile");
			return 1;
		}
		logfd = fd;
		strncpy(logfile_path, cfg.logfile, sizeof(logfile_path)-1);
		logfile_path[sizeof(logfile_path)-1] = '\0';
	} else {
		logfd = 2; /* stderr */
		logfile_path[0] = '\0';
	}

	/* Print effective configuration (if not quiet) */
	if(!quiet) {
		dolog("starting microsocks: listen=%s port=%u db=%s logfile=%s\n",
			listenip, port, dbpath, logfile_path[0] ? logfile_path : "stderr");
	}

	/* Initialize SQLite database */
	if(db_init(dbpath) != SQLITE_OK) {
		fprintf(stderr, "Failed to initialize database at %s\n", dbpath);
		return 1;
	}
	g_metrics.started_at = time(NULL);
	if(metrics_server_enabled) {
		pthread_t mt;
		if(pthread_create(&mt, NULL, metrics_server_thread, NULL) == 0) {
			pthread_detach(mt);
			dolog("metrics endpoint enabled on http://%s:%u/metrics\n", metrics_listen_addr, metrics_listen_port);
		} else {
			fprintf(stderr, "failed to start metrics thread\n");
		}
	}

	struct server s;
	sblist *threads = sblist_new(sizeof (struct thread*), 8);
	if(server_setup(&s, listenip, port)) {
		perror("server_setup");
		return 1;
	}
	server = &s;

	time_t now = time(NULL);
	int last_reset_month = current_month_key(now);

	while(1) {
		collect(threads);
		time_t loop_now = time(NULL);
		if(cfg_connections_retention_days > 0 && (last_connections_prune == 0 || loop_now - last_connections_prune >= 3600)) {
			uint64_t db_started = metrics_db_start();
			if(db_prune_connections_older_than_days(cfg_connections_retention_days) == SQLITE_OK) {
				metrics_db_finish(db_started);
				dolog("pruned connections older than %d days\n", cfg_connections_retention_days);
			} else {
				metrics_db_finish(db_started);
			}
			last_connections_prune = loop_now;
		}
		int month_key = current_month_key(time(NULL));
		if(last_reset_month != -1 && month_key != -1 && month_key != last_reset_month) {
			uint64_t db_started2 = metrics_db_start();
			if(db_reset_monthly_stats() == SQLITE_OK) {
				metrics_db_finish(db_started2);
				dolog("monthly bandwidth counters reset for month=%d\n", month_key);
			} else {
				metrics_db_finish(db_started2);
				dolog("failed to reset monthly bandwidth counters for month=%d\n", month_key);
			}
			last_reset_month = month_key;
		}
		struct client c;
		struct thread *curr = malloc(sizeof (struct thread));
		if(!curr) goto oom;
		memset(curr, 0, sizeof(struct thread));
		curr->account_id = -1; /* not authenticated by default */
		curr->done = 0;
		if(server_waitclient(&s, &c)) {
			dolog("failed to accept connection\n");
			free(curr);
			usleep(FAILURE_TIMEOUT);
			continue;
		}
		curr->client = c;
		if(!sblist_add(threads, &curr)) {
			close(curr->client.fd);
			free(curr);
			oom:
			dolog("rejecting connection due to OOM\n");
			usleep(FAILURE_TIMEOUT); /* prevent 100% CPU usage in OOM situation */
			continue;
		}
		pthread_attr_t *a = 0, attr;
		if(pthread_attr_init(&attr) == 0) {
			a = &attr;
			pthread_attr_setstacksize(a, THREAD_STACK_SIZE);
		}
		if(pthread_create(&curr->pt, a, clientthread, curr) != 0)
			dolog("pthread_create failed. OOM?\n");
		if(a) pthread_attr_destroy(&attr);
	}
}
