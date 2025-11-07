MicroSocks - multithreaded, small, efficient SOCKS5 server
===========================================================

a SOCKS5 service that you can run on your remote boxes to tunnel connections
through them, if for some reason SSH doesn't cut it for you.

It's very lightweight, and very light on resources too:

for every client, a thread with a low stack size is spawned.
the main process basically doesn't consume any resources at all.

the only limits are the amount of file descriptors and the RAM.

It's also designed to be robust: it handles resource exhaustion
gracefully by simply denying new connections, instead of calling abort()
as most other programs do these days.

another plus is ease-of-use: no config file necessary, everything can be
done from the command line and doesn't even need any parameters for quick
setup.

History
-------

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

command line options
--------------------

    microsocks -q -i listenip -p port -b bindaddr -w wl -d dbpath

All arguments are optional. By default `listenip` is `0.0.0.0` and port `1080`.

- option `-q` disables logging.
- option `-b` specifies which IP outgoing connections are bound to.
- option `-w` allows specifying a comma-separated whitelist of IP addresses that may use the proxy without database authentication.
  e.g. `-w 127.0.0.1,192.168.1.100,::1` or just `-w 10.0.0.1`.
  To allow access ONLY to those IPs, choose an impossible-to-guess password for any DB accounts (or don't create accounts at all).

Authentication note (DB-based)
------------------------------

This build requires authentication against the bundled SQLite database. The server no longer accepts static `-u`/`-P` CLI credentials; instead, create accounts in the database or add client IPs to the whitelist with `-w`.

To create an initial database and add a user (plaintext passwords are accepted and will be re-hashed on first login):

    # Preferred: use the bundled admin tool to create accounts (creates DB/schema if missing)
    ./msadmin add alice secret123

    # Alternatively, the server will create the DB/schema automatically when started.
    # Start the server once to create the DB, then add an account with msadmin or sqlite3.

    # Example using sqlite3 to insert a plaintext account (msadmin is preferred):
    sqlite3 microsocks.db "INSERT INTO accounts (username, password, ts_created, ts_updated, ts_seen) VALUES ('alice', 'secret123', strftime('%s','now'), strftime('%s','now'), strftime('%s','now'));"

Before making schema changes or running migrations, back up your DB:

    cp microsocks.db microsocks.db.bak

After creating the account you can test authentication via curl (example):

    curl --socks5 alice:secret123@127.0.0.1:1080 https://example.com

Migration and password hashing
------------------------------

If you need to migrate plaintext passwords to Argon2id (libsodium), use the `msadmin` tool and the provided `scripts/migrate-run.sh` wrapper. That script will create a timestamped backup before running the migration. See `MIGRATION.md` for details.

Supported SOCKS5 Features
-------------------------

- authentication: none, password, one-time
- IPv4, IPv6, DNS
- TCP (no UDP at this time)

Troubleshooting
---------------

if you experience segfaults, try raising the `THREAD_STACK_SIZE` in sockssrv.c
for your platform in steps of 4KB.

if this fixes your issue please file a pull request.

microsocks uses the smallest safe thread stack size to minimize overall memory
usage.

Build note
----------

The project previously contained nonstandard `#pragma RcB2` directives in some
headers which produced warnings on modern compilers ("ignoring '#pragma RcB2'").
Those pragmas were project-specific build hints and are not supported by
standard compilers, so they were removed from `server.h` and `sblist.h` to
keep builds warning-free. If you rely on a custom build tool that used those
directives, restore them or adjust your toolchain accordingly.
