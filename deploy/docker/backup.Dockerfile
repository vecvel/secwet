# Nightly encrypted Postgres backups (deploy/scripts/backup.sh). Same Postgres
# major version as the database so pg_dump matches the server.
FROM postgres:17.6-alpine
RUN apk add --no-cache openssl rclone
COPY deploy/scripts/backup.sh /usr/local/bin/backup.sh
RUN chmod 0755 /usr/local/bin/backup.sh \
    && mkdir -p /backups && chown postgres:postgres /backups && chmod 0700 /backups
USER postgres
ENTRYPOINT ["/usr/local/bin/backup.sh"]
