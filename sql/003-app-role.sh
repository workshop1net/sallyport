#!/bin/bash
# Creates the limited database role that the Guacamole web application uses, so a
# compromise of the web application does not hand over a database superuser.
# Runs once at first database initialisation, after the schema scripts.
set -euo pipefail

: "${GUAC_APP_PASSWORD:?GUAC_APP_PASSWORD is not set}"

# The password is generated as hex by ./sallyport init, so it is safe to embed.
case "$GUAC_APP_PASSWORD" in
  *[!0-9a-f]*) echo "GUAC_APP_PASSWORD must be hex" >&2; exit 1 ;;
esac

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOF
CREATE ROLE guacamole_app LOGIN PASSWORD '${GUAC_APP_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO guacamole_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO guacamole_app;
EOF
