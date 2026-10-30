#!/usr/bin/env bash
# Rolls out the stack in this directory (run on the server by the deploy
# workflow, as the deploy user, from the app directory):
#   1. back up the database when it is already running
#   2. pull and start the images named in .env
#   3. wait for the relay's /health through the private network
#   4. on failure, go back to the previous .env and its images
#
# The workflow uploads compose.yml, caddy/, scripts/, a new .env and
# rclone.conf first. GHCR_USER / GHCR_TOKEN log in to the registry for
# private images.
set -euo pipefail
cd "$(dirname "$0")/.."

compose() { docker compose --env-file .env -f compose.yml "$@"; }

# The relay must run the image named in .env: a container left over from the
# previous release would pass the health check too.
relay_current() {
	want=$(grep '^RELAY_IMAGE=' .env | cut -d= -f2-)
	id=$(compose ps -q relay 2>/dev/null)
	[ -n "$id" ] && [ "$(docker inspect -f '{{.Config.Image}}' "$id")" = "$want" ]
}

relay_healthy() {
	relay_current || return 1
	for _ in $(seq 1 30); do
		if compose exec -T caddy wget -q -T 3 -O - http://relay:8080/health 2>/dev/null | grep -q '"ok"'; then
			return 0
		fi
		sleep 3
	done
	return 1
}

if [ -n "${GHCR_TOKEN:-}" ]; then
	echo "$GHCR_TOKEN" | docker login ghcr.io -u "${GHCR_USER:?GHCR_USER is required with GHCR_TOKEN}" --password-stdin >/dev/null
fi

chmod 0600 .env rclone.conf 2>/dev/null || true

if compose ps --status running --services 2>/dev/null | grep -qx postgres; then
	echo "deploy: backup before upgrade"
	compose run --rm --no-deps backup now
fi

# DEPLOY_SKIP_PULL=1 is for a local test run with images that exist only
# on this machine.
if [ "${DEPLOY_SKIP_PULL:-}" != "1" ]; then
	echo "deploy: pull"
	compose pull --quiet
fi

echo "deploy: start"
compose up -d --remove-orphans --wait --wait-timeout 120 || true

if relay_healthy; then
	cp .env .env.previous
	chmod 0600 .env.previous
	docker image prune -f --filter "until=168h" >/dev/null
	echo "deploy: healthy ($(grep '^RELAY_IMAGE=' .env | cut -d= -f2-))"
	exit 0
fi

echo "deploy: relay did not become healthy" >&2
compose logs --tail 80 relay >&2 || true
if [ -f .env.previous ]; then
	echo "deploy: rolling back to the previous release" >&2
	cp .env.previous .env
	compose up -d --remove-orphans
	relay_healthy && echo "deploy: previous release is back up" >&2
fi
exit 1
