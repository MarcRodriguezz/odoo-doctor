#!/usr/bin/env bash
# End-to-end tests against real Odoo. Needs Docker and the labs: lab/up.sh 17; lab/up.sh 19; lab/up.sh 20
# Usage: tests/integration/run.sh <odoo-doctor binary> <linux binary for this Docker architecture>
set -uo pipefail
BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
LINUX_BIN="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
cd "$WORK"
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); echo "  ok    $1"; }
ko() { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
ids() { python3 -I -c "import json,sys;print(' '.join(f['id'] for f in json.load(open(sys.argv[1]))['findings']))" "$1"; }
expect_ids() { # file label id...
  local file=$1 label=$2; shift 2; local found; found=" $(ids "$file") "
  for id in "$@"; do case "$found" in *" $id "*) ok "$label finds $id";; *) ko "$label should find $id";; esac; done
}
refute_ids() {
  local file=$1 label=$2; shift 2; local found; found=" $(ids "$file") "
  for id in "$@"; do case "$found" in *" $id "*) ko "$label should not find $id";; *) ok "$label has no $id";; esac; done
}
layer() { python3 -I -c "import json,sys;print({l['layer']:l['state'] for l in json.load(open(sys.argv[1]))['layers']}[sys.argv[2]])" "$1" "$2"; }
expect_layer() { local got; got=$(layer "$1" "$2"); [ "$got" = "$3" ] && ok "$1: layer $2 is $3" || ko "$1: layer $2 is $got, expected $3"; }

COMMON="CFG001 CFG004 CFG006 CFG007 CFG008 CFG009 CSV001 PY001 PY002 PY003 PY004 PY005 PY006 PY007 PY008 PY009 PY010 PY011 PY012 SEC001 SEC003 SEC004 SEC008 SEC009 SEC010 SEC011 OPS003 PG010"

echo "== Docker, per Odoo version"
for v in 17 18 19 20; do
  "$BIN" --docker "oddoc-lab-$v-odoo-1" --no-html --json "d$v.json" --no-input >/dev/null 2>&1
  [ $? -eq 0 ] && ok "docker $v exits 0" || ko "docker $v exit code"
  expect_ids "d$v.json" "docker $v" $COMMON MOD002
  for l in config database postgres code logs host; do expect_layer "d$v.json" "$l" ran; done
  refute_ids "d$v.json" "docker $v (local address)" EXT001 EXT004 EXT011 EXT012
done
expect_ids d17.json "docker 17" EXT003 SEC015
refute_ids d18.json "docker 18" EXT003
refute_ids d19.json "docker 19" EXT003 UPG017
expect_ids d19.json "docker 19" UPG001 UPG019
expect_ids d20.json "docker 20" UPG001

echo "== Secrets never reach a report"
for f in d17.json d19.json d20.json; do
  for secret in 'lab-password' 'sk_live_51H' 'admin_passwd = admin'; do
    grep -q "$secret" "$f" && ko "$f contains $secret" || ok "$f has no '$secret'"
  done
done

echo "== Every SQL statement is read-only"
DBC=oddoc-lab-19-db-1
docker exec "$DBC" psql -U odoo -d lab -qc "ALTER SYSTEM SET log_statement='all'" -c "ALTER SYSTEM SET log_line_prefix='%a|'" -c "SELECT pg_reload_conf()" >/dev/null
sleep 1
BEFORE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"$BIN" --docker oddoc-lab-19-odoo-1 --no-html --no-input >/dev/null 2>&1
docker logs --since "$BEFORE" "$DBC" 2>&1 | grep '^odoo-doctor|' > statements.log
docker exec "$DBC" psql -U odoo -d lab -qc "ALTER SYSTEM RESET log_statement" -c "ALTER SYSTEM RESET log_line_prefix" -c "SELECT pg_reload_conf()" >/dev/null
TOTAL=$(wc -l < statements.log | tr -d ' ')
[ "$TOTAL" -gt 20 ] && ok "$TOTAL statements captured" || ko "only $TOTAL statements captured"
BAD=$(sed -E 's/^odoo-doctor\|LOG:  statement: //' statements.log | grep -vE '^(SELECT |SET |[[:space:]]*$)' | grep -cE '^(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|COPY|VACUUM|ANALYZE|REINDEX)' || true)
[ "$BAD" = "0" ] && ok "no write statements among them" || ko "$BAD write statements"
printf "SET default_transaction_read_only = on;\nCREATE TABLE should_fail(i int);\n" | docker exec -i "$DBC" psql -U odoo -d lab -q 2>&1 | grep -q 'read-only' && ok "PostgreSQL refuses writes in such a session" || ko "write was not refused"

echo "== Native install (package install in a container, no Docker visible to the tool)"
C=oddoc-lab-19-odoo-1
docker cp "$LINUX_BIN" "$C:/tmp/odoo-doctor" >/dev/null
docker exec "$C" sh -c 'cat > /tmp/native.conf <<EOC
[options]
admin_passwd = \$pbkdf2-sha512\$600000\$abc\$def
addons_path = /mnt/extra-addons
db_host = db
db_port = 5432
db_user = odoo
db_password = odoo
list_db = False
workers = 4
limit_memory_hard = 2684354560
limit_time_real = 120
proxy_mode = True
log_level = info
http_port = 8069
EOC
chmod 644 /tmp/native.conf'
docker exec -w /tmp "$C" /tmp/odoo-doctor --conf /tmp/native.conf --db lab --no-input --no-html --json /tmp/n.json >/dev/null 2>&1
docker cp "$C:/tmp/n.json" n.json >/dev/null
for l in config database postgres code host; do expect_layer n.json "$l" ran; done
expect_ids n.json native CFG009 CFG012 PY001 SEC001 UPG017
refute_ids n.json native CFG001 CFG002 CFG004 CFG006 CFG007 CFG008 CFG010 CFG013
docker exec -w /tmp "$C" /tmp/odoo-doctor --conf /tmp/native.conf --no-input --no-html --json /tmp/n2.json >/dev/null 2>&1
docker cp "$C:/tmp/n2.json" n2.json >/dev/null
[ "$(python3 -I -c "import json;print(json.load(open('n2.json'))['database'])")" = "lab" ] && ok "native finds the only database by itself" || ko "native database discovery"
docker exec "$C" rm -f /tmp/odoo-doctor /tmp/native.conf /tmp/n.json /tmp/n2.json

echo "== SSH and a simulated Odoo.sh build"
docker build -q -t oddoc-sshd -f "$ROOT/tests/integration/sshd.Dockerfile" "$ROOT/tests/integration" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f key
NET=oddoc-lab-19_default
docker rm -f oddoc-sshd >/dev/null 2>&1
docker run -d --name oddoc-sshd --network "$NET" -p 127.0.0.1:12222:22 oddoc-sshd >/dev/null
docker cp "$ROOT/lab/addons" oddoc-sshd:/tmp/addons >/dev/null
docker exec oddoc-sshd sh -c 'mkdir -p /home/odoo/.ssh /home/odoo/src /home/odoo/logs && mv /tmp/addons /home/odoo/src/user
printf "ODOO_STAGE=staging\nPGHOST=db\nPGUSER=odoo\nPGPASSWORD=odoo\nPGDATABASE=lab\n" > /home/odoo/.ssh/environment
printf "2026-11-05 10:00:00,123 42 ERROR lab odoo.http: boom 1\n%.0s" 1 2 3 4 5 6 > /home/odoo/logs/odoo.log'
docker cp key.pub oddoc-sshd:/home/odoo/.ssh/authorized_keys >/dev/null
docker exec oddoc-sshd sh -c 'chown -R odoo:odoo /home/odoo; chown root:odoo /home/odoo/.ssh/authorized_keys; chmod 700 /home/odoo/.ssh; chmod 640 /home/odoo/.ssh/authorized_keys'
cat > sshconfig <<EOC
Host labsh
  HostName 127.0.0.1
  Port 12222
  User odoo
  IdentityFile $WORK/key
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
EOC
mkdir shim; printf '#!/bin/sh\nexec /usr/bin/ssh -F %s/sshconfig "$@"\n' "$WORK" > shim/ssh; chmod +x shim/ssh
for i in 1 2 3 4 5 6 7 8; do PATH="$WORK/shim:$PATH" ssh labsh true 2>/dev/null && break; sleep 1; done
PATH="$WORK/shim:$PATH" "$BIN" --ssh labsh --no-html --json sh.json --no-input > sh.txt 2>&1
[ $? -eq 0 ] && ok "odoo.sh simulation exits 0" || { ko "odoo.sh simulation exit code"; tail -5 sh.txt; }
for l in database postgres code logs; do expect_layer sh.json "$l" ran; done
python3 -I - sh.json <<'P' && ok "odoo.sh is labelled and hides operator settings" || ko "odoo.sh label"
import json,sys
r=json.load(open(sys.argv[1]))
assert r['deployment'].startswith('Odoo.sh'), r['deployment']
assert r['database']=='lab', r['database']
assert not [f for f in r['findings'] if f['id'].startswith('CFG') or f['id'] in ('PG001','PG002','PG015')]
P
expect_ids sh.json odoo.sh PY001 SEC001 LOG001 UPG001
PATH="$WORK/shim:$PATH" "$BIN" --ssh nosuchhost.invalid --no-html --no-input >/dev/null 2>bad.txt
[ $? -eq 2 ] && ok "unreachable SSH host exits 2" || ko "unreachable SSH host exit code"
docker rm -f oddoc-sshd >/dev/null 2>&1

echo "== Docker on a remote host, through the SSH code path"
mkdir fakessh
cat > fakessh/ssh <<'EOS'
#!/bin/sh
# Runs the remote command locally, so the real quoting and nesting are exercised.
while [ $# -gt 1 ]; do case "$1" in -o) shift 2;; *) shift; break;; esac; done
exec sh -c "$1"
EOS
chmod +x fakessh/ssh
PATH="$WORK/fakessh:$PATH" "$BIN" --ssh fakehost --docker oddoc-lab-19-odoo-1 --no-html --json ds.json --no-input >/dev/null 2>&1
for l in config database postgres code logs; do expect_layer ds.json "$l" ran; done
expect_ids ds.json "docker over ssh" CFG001 PY001 SEC001
[ "$(ids d19.json | wc -w)" = "$(ids ds.json | wc -w)" ] && ok "docker over ssh finds the same as local docker" || ko "docker over ssh differs from local docker"

echo "== HTTPS with a bad certificate"
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days 5 -subj "/CN=localhost" 2>/dev/null
cat > nginx.conf <<'EOC'
events {}
http { server { listen 443 ssl; ssl_certificate /c/tls.crt; ssl_certificate_key /c/tls.key;
  location / { proxy_pass http://odoo:8069; proxy_set_header Host $host; } } }
EOC
docker rm -f oddoc-tls >/dev/null 2>&1
docker run -d --name oddoc-tls --network oddoc-lab-19_default --network-alias tlsproxy -p 127.0.0.1:18443:443 -v "$WORK/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$WORK:/c:ro" nginx:alpine >/dev/null
sleep 2
"$BIN" https://localhost:18443 --treat-as-public --no-port-probe --no-html --json tls.json --no-input >/dev/null 2>&1
expect_ids tls.json "bad TLS" EXT001 EXT006 EXT007 EXT008
refute_ids tls.json "bad TLS" EXT004
python3 -I -c "
import json;r=json.load(open('tls.json'));f=[x for x in r['findings'] if x['id']=='EXT007'][0]
assert f['severity']=='high',f" && ok "a certificate about to expire is high severity" || ko "certificate severity"
"$BIN" https://localhost:18443 --db lab --login admin --api-key x --treat-as-public --no-port-probe --no-html --json tlsapi.json --no-input >/dev/null 2>&1
docker rm -f oddoc-tls >/dev/null 2>&1
docker image rm nginx:alpine >/dev/null 2>&1
"$BIN" https://github.com --no-port-probe --no-html --json gh.json --no-input >/dev/null 2>&1
expect_ids gh.json "a valid site that is not Odoo" EXT013
refute_ids gh.json "a valid site that is not Odoo" EXT006 EXT004

echo "== From outside"
"$BIN" http://127.0.0.1:18019 --no-html --json e.json --no-input >/dev/null 2>&1
expect_layer e.json external partial
expect_layer e.json code skipped
"$BIN" http://127.0.0.1:18019 --treat-as-public --no-port-probe --no-html --json ep.json --no-input >/dev/null 2>&1
expect_ids ep.json "public view" EXT001 EXT002 EXT004
"$BIN" http://127.0.0.1:1 --no-html --no-input >/dev/null 2>&1
[ $? -eq 2 ] && ok "an unreachable site exits 2, and does not pretend to pass" || ko "unreachable site exit code"
"$BIN" http://127.0.0.1:18019 --db lab --login admin --api-key wrong --no-html --json badkey.json --no-input >/dev/null 2>&1
expect_layer badkey.json database skipped

echo "== Code only, and CI use"
"$BIN" --addons "$ROOT/lab/addons" --html r.html --json r.json --sarif r.sarif --target-version 20 --no-input >/dev/null 2>&1
[ $? -eq 0 ] && ok "code-only run exits 0" || ko "code-only exit code"
expect_ids r.json "code only" PY001 UPG001 UPG019
[ "$(grep -c 'lab_broken' r.html)" -gt 0 ] && ok "HTML report names the module" || ko "HTML report content"
python3 -I - r.sarif <<'P' && ok "SARIF is structurally valid" || ko "SARIF structure"
import json,sys
s=json.load(open(sys.argv[1])); run=s['runs'][0]
assert s['version']=='2.1.0' and run['results']
ids={r['id'] for r in run['tool']['driver']['rules']}
for r in run['results']:
    assert r['ruleId'] in ids
    assert r['locations'][0]['physicalLocation']['region']['startLine']>=1
    assert not r['locations'][0]['physicalLocation']['artifactLocation']['uri'].startswith('/')
P
"$BIN" --addons "$ROOT/lab/addons" --fail-on high --no-html --no-input >/dev/null 2>&1
[ $? -eq 1 ] && ok "--fail-on high exits 1" || ko "--fail-on exit code"
mkdir clean; printf "{'name': 'Clean', 'license': 'LGPL-3'}\n" > clean/__manifest__.py
"$BIN" --addons clean --fail-on low --no-html --no-input >/dev/null 2>&1
[ $? -eq 0 ] && ok "clean code passes --fail-on low" || ko "clean code exit code"
"$BIN" --addons clean --fail-on nonsense --no-html --no-input >/dev/null 2>&1
[ $? -eq 2 ] && ok "a bad --fail-on value exits 2" || ko "--fail-on validation"
"$BIN" --docker oddoc-lab-19-odoo-1 --redact --no-html --json red.json --no-input >/dev/null 2>&1
grep -q 'extra.admin1@example.com' red.json && ko "--redact leaves a login" || ok "--redact masks logins"
grep -q '"lab"' red.json && ko "--redact leaves the database name" || ok "--redact masks the database name"

cd /; rm -rf "$WORK"
echo; echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
