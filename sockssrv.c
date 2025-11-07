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
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
#define dolog(...) do { if(!quiet) dprintf(2, __VA_ARGS__); } while(0)
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
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT whitelist FROM accounts WHERE id = ?";
    int allowed = 0;
    sqlite3 *db = db_get_handle();

    if (!db) return 0;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int(stmt, 1, account_id);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *whitelist = (const char*)sqlite3_column_text(stmt, 0);
        if (!whitelist || !*whitelist) {
            allowed = 1; /* empty whitelist = allow all */
        } else {
            char *wlist = strdup(whitelist);
            if (wlist) {
                char *saveptr;
                char *token = strtok_r(wlist, ",", &saveptr);
                while (token) {
                    if (strcmp(token, client_ip) == 0) {
                        allowed = 1;
                        break;
                    }
                    token = strtok_r(NULL, ",", &saveptr);
                }
                free(wlist);
            }
        }
    }
    sqlite3_finalize(stmt);
    return allowed;
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

	/* Use database authentication */
	t->account_id = db_account_auth(user, pass);
	if(t->account_id == -2) return EC_NOT_ALLOWED; /* account disabled */
	if(t->account_id >= 0) {
		/* Check whitelist */
		if(!is_ip_allowed(t->account_id, client_ip)) 
			return EC_NOT_ALLOWED;
		
		/* Update last client IP */
		db_account_update_last_ip(t->account_id, client_ip);
		return EC_SUCCESS;
	}
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

static void* clientthread(void *data) {
	struct thread *t = data;
	/* initialize accounting fields */
	t->bytes_client_to_remote = 0;
	t->bytes_remote_to_client = 0;
	t->dest[0] = 0;

	/* Check account bandwidth limits */
	sqlite3_stmt *stmt;
	const char *sql = "SELECT monthly_bandwidth, m_bytes_sent + m_bytes_received "
	                 "FROM accounts WHERE id = ?";
	if (t->account_id >= 0 && db_stmt_prepare(sql, &stmt) == SQLITE_OK) {
		sqlite3_bind_int(stmt, 1, t->account_id);
		if (sqlite3_step(stmt) == SQLITE_ROW) {
			int64_t limit = sqlite3_column_int64(stmt, 0);
			int64_t used = sqlite3_column_int64(stmt, 1);
			sqlite3_finalize(stmt);
			if (limit > 0 && used >= limit) {
				if(CONFIG_LOG) {
					char clientname[256];
					int af = SOCKADDR_UNION_AF(&t->client.addr);
					void *ipdata = SOCKADDR_UNION_ADDRESS(&t->client.addr);
					inet_ntop(af, ipdata, clientname, sizeof clientname);
					dolog("account: %s -> %s: status=bandwidth_limit_exceeded\n", clientname, "-");
				}
				close(t->client.fd);
				t->done = 1;
				return NULL;
			}
		}
	}

	int remotefd = handshake(t);
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
		if(t->account_id >= 0)
			db_account_update_bandwidth(t->account_id, t->bytes_client_to_remote, t->bytes_remote_to_client);
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
		db_log_connection(t->account_id, clientname, t->dest[0] ? t->dest : "-",
						 remotefd != -1 ? "success" : "failed",
						 t->bytes_client_to_remote, t->bytes_remote_to_client);
	}

	close(t->client.fd);
	t->done = 1;
	return 0;
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

static int usage(void) {
	dprintf(2,
		"MicroSocks SOCKS5 Server\n"
		"------------------------\n"
		"usage: microsocks -q -i listenip -p port -b bindaddr -d dbpath\n"
		"all arguments are optional.\n"
		"by default listenip is 0.0.0.0 and port 1080.\n\n"
		"option -q disables logging.\n"
		"option -b specifies which ip outgoing connections are bound to\n"
		"option -d specifies the path to the SQLite database (default: microsocks.db)\n"
		"\n"
		"Authentication is handled by the database. Create accounts with enabled=1\n"
		"and optionally set a whitelist of IPs in the accounts table.\n"
		"An empty whitelist allows connections from any IP address.\n"
	);
	return 1;
}

/* prevent username and password from showing up in top. */
/* zero_arg removed: command-line user/pass args are no longer supported; server
   authenticates exclusively against the database. */

int main(int argc, char** argv) {
	int ch;
	const char *listenip = "0.0.0.0";
	const char *dbpath = "microsocks.db";
	unsigned port = 1080;
	while((ch = getopt(argc, argv, ":qb:i:p:d:")) != -1) {
		switch(ch) {
			case 'q':
				quiet = 1;
				break;
			case 'b':
				resolve_sa(optarg, 0, &bind_addr);
				break;
			case 'i':
				listenip = optarg;
				break;
			case 'd':
				dbpath = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case ':':
				dprintf(2, "error: option -%c requires an operand\n", optopt);
				/* fall through */
			case '?':
				return usage();
		}
	}
	signal(SIGPIPE, SIG_IGN);

	/* Initialize SQLite database */
	if(db_init(dbpath) != SQLITE_OK) {
		fprintf(stderr, "Failed to initialize database at %s\n", dbpath);
		return 1;
	}

	struct server s;
	sblist *threads = sblist_new(sizeof (struct thread*), 8);
	if(server_setup(&s, listenip, port)) {
		perror("server_setup");
		return 1;
	}
	server = &s;

	while(1) {
		collect(threads);
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
