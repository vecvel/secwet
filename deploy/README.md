# Deploying the Secwet relay

Everything to run the relay in production lives in this folder. The server
needs nothing installed by hand: one workflow sets it up, another deploys every
change. The stack runs on a single small VPS and moves to bigger or several
servers without changes to the images.

```
deploy/
  compose.yml               Caddy (HTTPS) -> relay -> Postgres, plus backups
  caddy/Caddyfile           TLS, WebSockets, security headers, body size cap
  docker/relay.Dockerfile   relay image (distroless, non-root, read-only)
  docker/backup.Dockerfile  nightly encrypted pg_dump
  env.example               every setting, documented
  scripts/bootstrap.sh      one-time server hardening (idempotent)
  scripts/deploy.sh         pull, start, health check, roll back on failure
  scripts/backup.sh         backup loop and `now` for pre-deploy backups
../.github/workflows/
  deploy-relay.yml          build images, push to ghcr.io, deploy over SSH
  server-bootstrap.yml      run bootstrap.sh once as root
  relay-admin.yml           run `secwet-relay admin` (grant Pro, status, ...)
```

## What runs on the server

| Container | Role | Reachable from the internet |
|---|---|---|
| caddy | HTTPS with automatic Let's Encrypt certificates, WebSocket proxy | ports 80 and 443 only |
| relay | the Secwet relay, non-root, read-only filesystem, no capabilities | no, only through Caddy |
| postgres | the database, on a network with no internet route | no, never published |
| backup | nightly `pg_dump`, gzip, AES-256, optional off-server copy | no |

The server firewall allows only SSH, 80 and 443. SSH takes keys only, root
login is off, fail2ban bans repeated failures, and security updates install
automatically.

## First deploy

1. **Server.** Any VPS with Ubuntu 24.04 (22.04 and Debian 12 also work), 2 GB
   RAM or more. A Hetzner CX22 (about €4 a month) is plenty to start.
2. **DNS.** Point an A record (and AAAA if the server has IPv6) for the relay
   name, for example `relay.example.com`, at the server's IP.
3. **Deploy key.** On your computer:
   `ssh-keygen -t ed25519 -N "" -C secwet-deploy -f secwet-deploy`
4. **GitHub settings** (repository > Settings > Secrets and variables > Actions,
   in the `production` environment):

   | Kind | Name | Value |
   |---|---|---|
   | Variable | `RELAY_HOST` | server IP or host name |
   | Variable | `RELAY_DOMAIN` | `relay.example.com` |
   | Variable | `ACME_EMAIL` | email for certificate expiry notices |
   | Variable | `SSH_PORT` | optional, default 22 |
   | Variable | `RETENTION_DAYS`, `DEFAULT_DEVICE_LIMIT`, `BACKUP_KEEP_DAYS` | optional, defaults 30, 5, 14 |
   | Variable | `RCLONE_REMOTE` | optional off-server backup target, e.g. `b2:bucket/secwet` |
   | Secret | `DEPLOY_SSH_KEY` | contents of `secwet-deploy` (the private key) |
   | Secret | `POSTGRES_PASSWORD` | `openssl rand -base64 33` |
   | Secret | `BACKUP_PASSPHRASE` | `openssl rand -base64 33`; also keep a copy offline |
   | Secret | `RCLONE_CONF` | optional, rclone.conf for `RCLONE_REMOTE` |
   | Secret | `SERVER_ROOT_PASSWORD` | the provider's root password, for step 5 only |

5. **Bootstrap.** Actions > "Relay: bootstrap server" > Run, typing the
   `RELAY_HOST` value to confirm. Check the printed host key fingerprint
   against the provider's console. Then:
   - save the printed `known_hosts` line as the `SSH_KNOWN_HOSTS` secret
   - delete the `SERVER_ROOT_PASSWORD` secret (root login is now off)
6. **Deploy.** Actions > "Relay: deploy" > Run (later runs start on every push
   to `main` that touches the relay or this folder). It builds the images,
   backs up the database, rolls out, and waits for `/health`; if the new
   version is not healthy it goes back to the previous one.
7. **Check.** `curl https://relay.example.com/health` returns `{"status":"ok"}`.
   Point the apps at `https://relay.example.com` in Settings > Sync.

Add required reviewers to the `production` environment to approve each deploy.

## Everyday operations

- **Grant Pro, check a workspace:** Actions > "Relay: admin".
- **Logs:** `ssh deploy@server 'cd /opt/secwet && docker compose logs -f relay'`
- **Backups** are in the `backups` volume (and `RCLONE_REMOTE` when set). Restore
  steps are at the top of `scripts/backup.sh`. Test a restore before launch.
- **Roll back:** re-run "Relay: deploy" on an older commit.

## Local test run

```sh
docker build -f deploy/docker/relay.Dockerfile -t secwet-relay:local .
docker build -f deploy/docker/backup.Dockerfile -t secwet-backup:local .
cp deploy/env.example deploy/.env   # set RELAY_DOMAIN=localhost and the two images
touch deploy/rclone.conf
docker compose --env-file deploy/.env -f deploy/compose.yml up -d
curl -k https://localhost/health
```

`.env`, `.env.*` and `rclone.conf` are git-ignored here; never commit them.

## Scaling later

- **Bigger server:** change `RELAY_HOST` and run bootstrap and deploy again;
  restore the latest backup into the new database first.
- **Managed database:** change the relay's `DATABASE_URL` in `compose.yml` to
  the managed Postgres and remove the `postgres` and `backup` services (the
  provider takes over backups).
- **Several relay servers:** run the same image behind a load balancer with a
  shared managed Postgres. Live sync streams are per instance today, so this
  needs cross-instance notifications (Postgres LISTEN/NOTIFY) first.
