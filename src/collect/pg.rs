//! PostgreSQL health, from statistics views only. Query text is read only from
//! `pg_stat_statements`, where literal values have already been replaced by placeholders.
use super::sql::SqlClient;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct PgData {
    pub major: u32,
    pub version: String,
    pub settings: BTreeMap<String, String>,
    pub shared_buffers_mb: i64,
    pub is_superuser: bool,
    pub db_size_bytes: i64,
    pub connections: i64,
    pub max_connections: i64,
    pub cache_hit_pct: Option<f64>,
    pub long_transactions: Vec<LongTransaction>,
    pub blocked: i64,
    pub xid_age: i64,
    pub stats_age_days: Option<i64>,
    pub big_tables: Vec<TableStat>,
    pub dead_tables: Vec<TableStat>,
    pub seq_tables: Vec<TableStat>,
    pub fk_no_index: Vec<String>,
    pub unused_indexes: Vec<(String, i64)>,
    pub invalid_indexes: Vec<String>,
    pub slow_queries: Vec<SlowQuery>,
    pub has_stat_statements: bool,
    pub gaps: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LongTransaction {
    pub state: String,
    pub minutes: f64,
}

#[derive(Debug, Clone, Default)]
pub struct TableStat {
    pub name: String,
    pub bytes: i64,
    pub live: i64,
    pub dead: i64,
    pub seq_scan: i64,
    pub avg_seq_read: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SlowQuery {
    pub text: String,
    pub calls: i64,
    pub mean_ms: f64,
}

fn i(v: &Value, k: &str) -> i64 {
    v[k].as_i64()
        .or_else(|| v[k].as_f64().map(|f| f as i64))
        .unwrap_or(0)
}
fn f(v: &Value, k: &str) -> f64 {
    v[k].as_f64().unwrap_or(0.0)
}
fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").to_string()
}

fn table(v: &Value) -> TableStat {
    TableStat {
        name: s(v, "name"),
        bytes: i(v, "bytes"),
        live: i(v, "live"),
        dead: i(v, "dead"),
        seq_scan: i(v, "seq_scan"),
        avg_seq_read: i(v, "avg_seq_read"),
    }
}

const TABLE_COLUMNS: &str = "c.relname AS name, pg_total_relation_size(c.oid) AS bytes, s.n_live_tup AS live, s.n_dead_tup AS dead, \
    s.seq_scan, \
    CASE WHEN s.seq_scan > 0 THEN s.seq_tup_read / s.seq_scan ELSE 0 END AS avg_seq_read \
    FROM pg_stat_user_tables s JOIN pg_class c ON c.oid = s.relid";

pub fn collect(sql: &mut SqlClient) -> Result<PgData, String> {
    let mut data = PgData::default();
    let head = sql.one(
        "SELECT current_setting('server_version_num')::int / 10000 AS major, current_setting('server_version') AS version, \
           pg_database_size(current_database()) AS size, \
           (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser, \
           (SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend') AS connections, \
           current_setting('max_connections')::int AS max_connections, \
           current_setting('shared_buffers') AS shared_buffers, \
           (SELECT setting::bigint * 8 / 1024 FROM pg_settings WHERE name = 'shared_buffers') AS shared_buffers_mb",
    )?;
    data.major = i(&head, "major") as u32;
    data.version = s(&head, "version");
    data.db_size_bytes = i(&head, "size");
    data.is_superuser = head["superuser"].as_bool().unwrap_or(false);
    data.connections = i(&head, "connections");
    data.max_connections = i(&head, "max_connections");
    data.shared_buffers_mb = i(&head, "shared_buffers_mb");

    let record = |name: &str, r: Result<(), String>, gaps: &mut Vec<String>| {
        if let Err(e) = r {
            gaps.push(format!("{name}: {e}"));
        }
    };
    let mut gaps = Vec::new();
    let r = settings(sql, &mut data);
    record("settings", r, &mut gaps);
    let r = activity(sql, &mut data);
    record("activity", r, &mut gaps);
    let r = tables(sql, &mut data);
    record("tables", r, &mut gaps);
    let r = indexes(sql, &mut data);
    record("indexes", r, &mut gaps);
    let r = statements(sql, &mut data);
    record("pg_stat_statements", r, &mut gaps);
    data.gaps = gaps;
    Ok(data)
}

fn settings(sql: &mut SqlClient, data: &mut PgData) -> Result<(), String> {
    let rows = sql.rows(
        "SELECT name, setting FROM pg_settings WHERE name IN ('autovacuum', 'work_mem', 'effective_cache_size', 'maintenance_work_mem', 'idle_in_transaction_session_timeout')",
    )?;
    for r in rows {
        data.settings.insert(s(&r, "name"), s(&r, "setting"));
    }
    Ok(())
}

fn activity(sql: &mut SqlClient, data: &mut PgData) -> Result<(), String> {
    let rows = sql.rows(
        "SELECT state, extract(epoch FROM now() - xact_start) / 60.0 AS minutes FROM pg_stat_activity \
         WHERE datname = current_database() AND xact_start IS NOT NULL AND pid <> pg_backend_pid() \
         AND now() - xact_start > interval '5 minutes' AND backend_type = 'client backend' ORDER BY xact_start LIMIT 10",
    )?;
    data.long_transactions = rows
        .iter()
        .map(|r| LongTransaction {
            state: s(r, "state"),
            minutes: f(r, "minutes"),
        })
        .collect();
    let r = sql.one(
        "SELECT (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND cardinality(pg_blocking_pids(pid)) > 0) AS blocked, \
           (SELECT age(datfrozenxid) FROM pg_database WHERE datname = current_database()) AS xid_age, \
           (SELECT round(100.0 * blks_hit / nullif(blks_hit + blks_read, 0), 2)::float8 FROM pg_stat_database WHERE datname = current_database()) AS cache_hit, \
           (SELECT extract(day FROM now() - stats_reset)::int FROM pg_stat_database WHERE datname = current_database()) AS stats_age",
    )?;
    data.blocked = i(&r, "blocked");
    data.xid_age = i(&r, "xid_age");
    data.cache_hit_pct = r["cache_hit"].as_f64();
    data.stats_age_days = r["stats_age"].as_i64();
    Ok(())
}

fn tables(sql: &mut SqlClient, data: &mut PgData) -> Result<(), String> {
    let big = sql.rows(&format!(
        "SELECT {TABLE_COLUMNS} ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 8"
    ))?;
    data.big_tables = big.iter().map(table).collect();
    let dead = sql.rows(&format!(
        "SELECT {TABLE_COLUMNS} WHERE s.n_dead_tup > 10000 AND s.n_dead_tup > 0.2 * s.n_live_tup ORDER BY s.n_dead_tup DESC LIMIT 8"
    ))?;
    data.dead_tables = dead.iter().map(table).collect();
    let seq = sql.rows(&format!(
        "SELECT {TABLE_COLUMNS} WHERE s.n_live_tup > 50000 AND s.seq_scan > 3 AND s.seq_tup_read / s.seq_scan > 10000 \
         AND s.seq_scan > coalesce(s.idx_scan, 0) * 0.1 ORDER BY s.seq_tup_read DESC LIMIT 8"
    ))?;
    data.seq_tables = seq.iter().map(table).collect();
    Ok(())
}

fn indexes(sql: &mut SqlClient, data: &mut PgData) -> Result<(), String> {
    let unused = sql.rows(
        "SELECT i.indexrelname AS name, pg_relation_size(i.indexrelid) AS bytes FROM pg_stat_user_indexes i \
         JOIN pg_index x ON x.indexrelid = i.indexrelid \
         WHERE i.idx_scan = 0 AND NOT x.indisunique AND NOT x.indisprimary AND pg_relation_size(i.indexrelid) > 20 * 1024 * 1024 \
         ORDER BY bytes DESC LIMIT 10",
    )?;
    data.unused_indexes = unused
        .iter()
        .map(|r| (s(r, "name"), i(r, "bytes")))
        .collect();
    let invalid = sql.rows("SELECT c.relname AS name FROM pg_index x JOIN pg_class c ON c.oid = x.indexrelid WHERE NOT x.indisvalid")?;
    data.invalid_indexes = invalid.iter().map(|r| s(r, "name")).collect();
    let fks = sql.rows(
        "SELECT t.relname || '.' || a.attname AS name FROM pg_constraint c \
         JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace \
         JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = c.conkey[1] \
         WHERE c.contype = 'f' AND array_length(c.conkey, 1) = 1 AND n.nspname = 'public' AND t.reltuples > 50000 \
         AND a.attname NOT IN ('create_uid', 'write_uid') \
         AND NOT EXISTS (SELECT 1 FROM pg_index x WHERE x.indrelid = t.oid AND x.indisvalid AND x.indkey[0] = a.attnum) \
         ORDER BY t.reltuples DESC LIMIT 15",
    )?;
    data.fk_no_index = fks.iter().map(|r| s(r, "name")).collect();
    Ok(())
}

fn statements(sql: &mut SqlClient, data: &mut PgData) -> Result<(), String> {
    let present = sql.one(
        "SELECT count(*) > 0 AS present FROM pg_extension WHERE extname = 'pg_stat_statements'",
    )?;
    data.has_stat_statements = present["present"].as_bool().unwrap_or(false);
    if !data.has_stat_statements {
        return Ok(());
    }
    let time = if data.major >= 13 {
        ("mean_exec_time", "total_exec_time")
    } else {
        ("mean_time", "total_time")
    };
    let rows = sql.rows(&format!(
        "SELECT left(regexp_replace(query, '\\s+', ' ', 'g'), 200) AS text, calls, {} AS mean_ms \
         FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) \
         AND query NOT ILIKE '%pg_stat%' AND calls > 5 ORDER BY {} DESC LIMIT 5",
        time.0, time.1
    ))?;
    data.slow_queries = rows
        .iter()
        .map(|r| SlowQuery {
            text: s(r, "text"),
            calls: i(r, "calls"),
            mean_ms: f(r, "mean_ms"),
        })
        .collect();
    Ok(())
}
