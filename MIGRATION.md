# Password hashing migration (Argon2id via libsodium)

This document explains how to migrate existing accounts from plaintext passwords to Argon2id hashes using the included admin tool `msadmin`.

## Prerequisites

- Install the libsodium development package (headers + library). Example on Debian/Ubuntu:

```sh
sudo apt-get install -y libsodium-dev
```

## Build

Build only the admin tool if you don't need the full server:

```sh
make msadmin
```

## Basic migration (safe)

Use the wrapper script which performs a timestamped backup of the DB and then runs the migration:

```sh
./scripts/migrate-run.sh /path/to/microsocks.db --only-plaintext
```

Options supported by `msadmin migrate` (and the wrapper accepts these and passes them through):

- `--only-plaintext` (default): hash stored plaintext passwords in-place to Argon2id.
- `--rehash-needs`: do not change data; report accounts whose Argon2id hashes should be rehashed under the current ops/memory parameters.
- `--yes` or `-y`: skip interactive confirmation (for automation / cron).
- `--log <path>`: append a text log of the migration run to the given file.
- `--log-dir <dir>`: create a timestamped log file inside the directory (e.g. `migrate-YYYYMMDD-HHMMSS.log`).
- positional DB path: `msadmin migrate /path/to/db ...` — you can pass the DB path as the first positional argument instead of using the wrapper.
- optional username list: provide usernames after the options to restrict migration to specific accounts.

Example (non-interactive with log dir):

```sh
./msadmin migrate /path/to/microsocks.db --only-plaintext --yes --log-dir /var/log/microsocks
```

## Installation note

The `Makefile` install target now installs the migration wrapper and the smoke test when you run `make install`:

```
scripts/migrate-run.sh -> $(bindir)/migrate-run
tests/migrate_smoketest.sh -> $(bindir)/migrate-smoketest
```

## Run a quick smoke test (local)

There is a smoke test that exercises non-interactive migration and logging. To run it locally after building `msadmin`:

```sh
./tests/migrate_smoketest.sh
```

## Notes on hashing parameters and rehashing

- The code uses libsodium's presets by default (MODERATE: `crypto_pwhash_OPSLIMIT_MODERATE` / `crypto_pwhash_MEMLIMIT_MODERATE`) — a balance for small/medium servers.
- For higher security, consider `crypto_pwhash_OPSLIMIT_SENSITIVE` / `crypto_pwhash_MEMLIMIT_SENSITIVE` after benchmarking.
- `--rehash-needs` reports accounts that would benefit from rehashing, but rehashing requires the plaintext password; you can obtain plaintexts via user logins or an out-of-band process and then re-run `msadmin update username password <new>` or use the `--only-plaintext` flow if the DB still contains plaintext values.

## Benchmarking

Measure hashing speed on your hardware to choose appropriate ops/memory values:

```sh
./msadmin benchmark 5
```

## Recommended workflow

1. Run `./msadmin migrate /path/to/db --rehash-needs` to see which accounts should be rehashed.
2. For accounts still storing plaintext, run the wrapper with `--only-plaintext` (or the app's login path will re-hash on successful login when plaintext is detected).
3. For operational runs use `--yes` and `--log-dir` to run non-interactively and keep a timestamped run log.

If you'd like the migration wrapper installed elsewhere (for example `$(prefix)/share/doc/microsocks`), tell me and I can change the `Makefile` to install it there instead of `$(bindir)`.
