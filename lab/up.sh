#!/usr/bin/env bash
# Starts and seeds a lab instance: lab/up.sh <odoo-version> [port]
set -euo pipefail
version="${1:?odoo version}"
port="${2:-180${version}}"
cd "$(dirname "$0")"
export ODOO_VERSION="$version" LAB_PORT="$port"
project="oddoc-lab-$version"
dc() { docker compose -p "$project" -f compose.yml "$@"; }
acl=lab_acl_legacy
[ "$version" -ge 20 ] && acl=lab_acl_new
dc up -d db
dc run --rm --no-deps odoo odoo -d lab -i "base,mail,lab_broken,$acl" --stop-after-init --no-http \
  --db_host=db --db_user=odoo --db_password=odoo 2>&1 | grep -E " (ERROR|CRITICAL) " | tail -5 || true
dc run --rm -T --no-deps odoo odoo shell -d lab --no-http --db_host=db --db_user=odoo --db_password=odoo --log-level=warn < seed.py 2>&1 | grep -E "SEEDED|Error" | tail -3
dc exec -T db psql -U odoo -d lab -q -v ON_ERROR_STOP=1 < seed.sql >/dev/null
dc up -d odoo
echo "lab $version ready on http://127.0.0.1:$port"
