# Deployment TODO and Fix List

## TODO (to make service fully deployable)

- [ ] Create a hardened production systemd unit (least privilege, filesystem restrictions, capability bounding).
- [ ] Document a full operational runbook (start/stop/reload, log rotation, backup/restore, incident response).
- [ ] Add automated integration tests for SOCKS5 auth, relay correctness, and accounting updates.
- [ ] Add concurrency/load testing and define supported capacity targets.
- [ ] Add migration/versioning strategy for schema evolution (with rollback plan).
- [ ] Define data retention policy and implement periodic cleanup for `connections`.
- [ ] Add monitoring/alerting integration (service health, auth failures, DB growth, error rates).
- [ ] Add containerization/deployment examples (Docker/Compose/Kubernetes optional).

## FIX list (identified code/product issues)

- [ ] Replace/augment CSV whitelist storage with normalized per-account whitelist table.
- [ ] Add anti-abuse controls: auth rate limiting, per-IP and per-account connection caps.
- [x] Enforce secure admin defaults (debug disabled by default; require non-default credentials/secrets unless `ALLOW_INSECURE_DEFAULTS=1`).
- [ ] Add pruning/archival utility for `connections` table to prevent unbounded growth.
