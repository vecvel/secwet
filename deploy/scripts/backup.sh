#!/bin/sh
# Nightly encrypted Postgres backup, run by the `backup` service.
# Writes /backups/secwet-<UTC time>.sql.gz.enc (pg_dump | gzip | AES-256),
# copies it off the server when RCLONE_REMOTE is set, and deletes local
# backups older than BACKUP_KEEP_DAYS.
#
# Restore (on the server, from deploy/):
#   docker compose exec -T backup sh -c 'openssl enc -d -aes-256-cbc -pbkdf2 \
#     -iter 600000 -pass env:BACKUP_PASSPHRASE -in /backups/<file>' \
#     | gunzip | docker compose exec -T postgres psql -U secwet -d secwet_relay
set -eu

: "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is required}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
HOUR="${BACKUP_HOUR_UTC:-3}"

run_backup() {
	stamp=$(date -u +%Y%m%dT%H%M%SZ)
	out="/backups/secwet-${stamp}.sql.gz.enc"
	tmp="${out}.partial"
	pg_dump --no-owner --clean --if-exists \
		| gzip -9 \
		| openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 -pass env:BACKUP_PASSPHRASE -out "$tmp"
	mv "$tmp" "$out"
	echo "backup: wrote $(basename "$out") ($(wc -c <"$out") bytes)"
	if [ -n "${RCLONE_REMOTE:-}" ]; then
		rclone copy "$out" "$RCLONE_REMOTE" && echo "backup: copied to $RCLONE_REMOTE"
	fi
	find /backups -name 'secwet-*.sql.gz.enc' -mtime +"$KEEP_DAYS" -print -delete
}

# `backup.sh now` runs one backup and exits (used by deploy.sh before upgrades).
if [ "${1:-}" = "now" ]; then
	run_backup
	exit 0
fi

echo "backup: daily at ${HOUR}:00 UTC, keeping ${KEEP_DAYS} days"
while true; do
	now=$(date -u +%s)
	next=$(( (now / 86400) * 86400 + HOUR * 3600 ))
	[ "$next" -le "$now" ] && next=$((next + 86400))
	sleep $((next - now))
	run_backup || echo "backup: FAILED" >&2
done
