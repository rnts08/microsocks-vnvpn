<!--
Guidance for AI coding agents working on the MicroSocks repository.
Keep this file concise and specific to patterns discoverable in the codebase.
-->

# Copilot instructions — MicroSocks

Short summary
-------------
MicroSocks is a small, single-binary SOCKS5 server implemented in C (C99). The codebase is intentionally tiny and uses plain libc + pthreads. Key files:

- `sockssrv.c` — main server logic: accepts clients, per-client threads, SOCKS5 handshake, authentication, copy loop.
- `server.c` — socket setup and accept wrapper.
- `sblist.c`, `sblist.h` — small dynamic list utility used for thread and whitelist storage.
- `Makefile` / `install.sh` — build and install workflow.

Big-picture architecture (what to know)
-------------------------------------
- One process, multithreaded: the main thread listens (see `server_setup` in `server.c`) and spawns a pthread per client in `sockssrv.c`.
- `sockssrv.c` implements the SOCKS5 state machine (handshake, optional username/password auth, connect request handling), then relays data in `copyloop`.
- Outgoing DNS/address resolution uses `resolve()`/`getaddrinfo` (in `server.c`) and an address-family preference via `bind_addr` so the server can bind outgoing sockets to a specific address (`-b` option).
- Authentication: optional user/pass set with `-u`/`-P`. There is an "auth once" whitelist mechanism (`-1` / `-w`) that stores IPs in an `sblist` for later no-auth access.
- Logging uses `dprintf` and the `dolog` macro (controlled by `-q` quiet flag); logging intentionally avoids malloc/printf in hot paths.

Project-specific conventions and patterns
---------------------------------------
- Minimal C standard: code targets `-std=c99`, uses only libc/pthreads.
- Small, explicit error codes: SOCKS errors are mapped to `enum errorcode` and returned as numeric codes from helpers (see `connect_socks_target`).
- Resource exhaustion handling: on OOM or accept failure the server sleeps for `FAILURE_TIMEOUT` microseconds instead of aborting.
- Thread stack size is tuned via `THREAD_STACK_SIZE` in `sockssrv.c`. If you change per-thread stack behavior, adjust carefully and prefer platform-specific branches already present.
- Security detail: `zero_arg` is used to wipe password argv contents after copying them to internal storage — keep this if adding credential parsing.

Build / run / debug (practical commands)
---------------------------------------
- Build: `make` (uses `CFLAGS += -Wall -std=c99`).
- Install (atomic): `make install` -> calls `install.sh` which performs an atomic write.
- Run locally: `./microsocks -p 1080` (default listen `0.0.0.0:1080`).
- Run with auth once: `./microsocks -u myuser -P mypass -1` or with specific whitelist `-w 127.0.0.1`.
- If you get segfaults on some platforms, try increasing `THREAD_STACK_SIZE` in `sockssrv.c` (README mentions this as first troubleshooting step).

Files to inspect when making changes
-----------------------------------
- `sockssrv.c` — the main place for protocol/logic changes (handshake, auth, copyloop). Small changes here can affect threading and blocking behaviour.
- `server.c` — network setup, `resolve()`, `bindtoip()`, `server_setup()`.
- `sblist.*` — dynamic lists used for threads and whitelists; reuse for other in-memory lists.
- `Makefile` / `config.mak` — customize build flags or install paths here.

Examples (copy/paste friendly)
-----------------------------
- Start with username/password and allow localhost without auth once:
  `./microsocks -u admin -P secret -w 127.0.0.1`
- Bind outgoing connections to a specific local address:
  `./microsocks -b 10.0.0.5`

What not to change lightly
-------------------------
- Logging: the `dolog` macro and use of `dprintf(2, ...)` avoids heap allocations. Replacing it with something that mallocs may introduce races.
- Threading model: current design uses one pthread per client and `copyloop` blocks on `poll()`; changing to an evented model is a major design shift.
- Error-code-to-SOCKS mapping in `connect_socks_target` and `send_error` — keep RFC1928 behavior when editing.

If you add tests
---------------
- There are no tests in the repo. If you add tests, keep them minimal and self-contained; prefer small C test binaries or harness scripts invoked from `Makefile`.

If anything here is unclear or you want more examples (small refactor checklist, testing harness, or CI steps), tell me which part to expand.
