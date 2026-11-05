//! Decides where Odoo is and what can be read from it, then runs the collectors.
use crate::cli::Cli;
use crate::code;
use crate::collect::conf::{self, OdooConf};
use crate::collect::sql::{DirectParams, SqlClient};
use crate::collect::{api, external, logs, odoo, pg, HostData, Snapshot};
use crate::model::Layer;
use crate::transport::{first_line, Transport};
use std::collections::HashMap;
use std::io::{IsTerminal, Write};

const LOG_LINES: &str = "20000";

fn say(message: &str) {
    anstream::eprintln!("\x1b[2m{message}\x1b[0m");
}

fn warn(message: &str) {
    anstream::eprintln!("\x1b[33m! {message}\x1b[0m");
}

fn can_prompt(cli: &Cli) -> bool {
    !cli.no_input && std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn ask(question: &str) -> Option<String> {
    eprint!("{question} ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok()?;
    let answer = line.trim().to_string();
    (!answer.is_empty()).then_some(answer)
}

fn choose(title: &str, options: &[String]) -> Option<String> {
    eprintln!("{title}");
    for (i, option) in options.iter().enumerate() {
        eprintln!("  {}) {option}", i + 1);
    }
    let answer = ask(&format!("Choose 1-{}:", options.len()))?;
    let index: usize = answer.parse().ok()?;
    options.get(index.checked_sub(1)?).cloned()
}

#[derive(Debug, Clone, Default)]
struct DockerContainer {
    name: String,
    image: String,
    ports: String,
    project: String,
}

fn list_containers(outer: &Transport) -> Vec<DockerContainer> {
    let Ok(out) = outer.run(&[
        "docker",
        "ps",
        "--format",
        "{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project\"}}",
    ]) else {
        return Vec::new();
    };
    if !out.success {
        return Vec::new();
    }
    out.text()
        .lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            Some(DockerContainer {
                name: f.next()?.to_string(),
                image: f.next()?.to_string(),
                ports: f.next().unwrap_or("").to_string(),
                project: f.next().unwrap_or("").to_string(),
            })
        })
        .collect()
}

fn is_postgres_image(image: &str) -> bool {
    let i = image.to_ascii_lowercase();
    i.contains("postgres")
        || i.contains("postgis")
        || i.contains("timescale")
        || i.contains("pgvector")
}

fn looks_like_odoo(c: &DockerContainer) -> bool {
    let image = c.image.to_ascii_lowercase();
    let name = c.name.to_ascii_lowercase();
    !is_postgres_image(&image)
        && (image.contains("odoo") || name.contains("odoo"))
        && !["pgadmin", "nginx", "traefik", "redis", "caddy"]
            .iter()
            .any(|x| image.contains(x))
}

/// `127.0.0.1:18019->8069/tcp, 8071-8072/tcp` -> `18019`.
fn published_http_port(ports: &str) -> Option<u16> {
    ports.split(',').find_map(|mapping| {
        let (left, right) = mapping.trim().split_once("->")?;
        if !right.starts_with("8069/") {
            return None;
        }
        left.rsplit(':').next()?.parse().ok()
    })
}

fn inspect_env(outer: &Transport, container: &str) -> HashMap<String, String> {
    let Ok(out) = outer.run(&[
        "docker",
        "inspect",
        "--format",
        "{{json .Config.Env}}",
        container,
    ]) else {
        return HashMap::new();
    };
    let values: Vec<String> = serde_json::from_slice(&out.stdout).unwrap_or_default();
    values
        .into_iter()
        .filter_map(|e| {
            e.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

const CONF_CANDIDATES: &[&str] = &[
    "/etc/odoo/odoo.conf",
    "/etc/odoo.conf",
    "/etc/odoo/odoo-server.conf",
    "/etc/odoo-server.conf",
    "/opt/odoo/odoo.conf",
    "/opt/odoo/odoo-server.conf",
    "/opt/odoo/conf/odoo.conf",
    "/home/odoo/.odoorc",
    "odoo.conf",
];

fn find_conf(transport: &Transport, explicit: Option<&str>) -> Option<(String, String)> {
    if let Some(path) = explicit {
        return transport
            .read_file(path)
            .map(|text| (path.to_string(), text));
    }
    let mut candidates: Vec<String> = Vec::new();
    if transport.is_local() {
        if let Ok(rc) = std::env::var("ODOO_RC") {
            candidates.push(rc);
        }
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            candidates.push(format!("{}/.odoorc", home.to_string_lossy()));
        }
        if cfg!(windows) {
            candidates.extend(windows_conf_candidates());
        }
    } else if let Ok(out) =
        transport.run(&["sh", "-c", "printf '%s\\n' \"$ODOO_RC\" \"$HOME/.odoorc\""])
    {
        candidates.extend(
            out.text()
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string),
        );
    }
    candidates.extend(CONF_CANDIDATES.iter().map(|s| s.to_string()));
    candidates.into_iter().find_map(|path| {
        let text = transport.read_file(&path)?;
        text.contains("[options]").then_some((path, text))
    })
}

/// The Windows installer uses `C:\Program Files\Odoo <version>\server\odoo.conf`.
fn windows_conf_candidates() -> Vec<String> {
    let mut found = Vec::new();
    for base in ["C:\\Program Files", "C:\\Program Files (x86)"] {
        let Ok(entries) = std::fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("odoo")
            {
                found.push(
                    entry
                        .path()
                        .join("server")
                        .join("odoo.conf")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    found
}

/// Where Odoo was found and how to reach each thing.
#[derive(Default)]
struct Plan {
    deployment: String,
    transport: Option<Transport>,
    conf: Option<OdooConf>,
    sql: Option<SqlClient>,
    sql_error: Option<String>,
    url: Option<String>,
    log_command: Option<Vec<String>>,
    log_file: Option<String>,
    log_label: String,
    managed: bool,
    code_roots: Vec<String>,
}

fn is_odoo_hosted(url: &str) -> bool {
    let (_, host, _) = external::split_url(url);
    host.ends_with(".odoo.com")
}

fn conf_with_perms(transport: &Transport, path: String, text: &str, check_perms: bool) -> OdooConf {
    let mut parsed = conf::parse(&path, text);
    if check_perms {
        parsed.world_readable = world_readable(transport, &path);
    }
    parsed
}

fn world_readable(transport: &Transport, path: &str) -> Option<bool> {
    #[cfg(unix)]
    if transport.is_local() {
        use std::os::unix::fs::PermissionsExt;
        return std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o004 != 0);
    }
    if !transport.has_posix_shell() {
        return None;
    }
    let out = transport.run(&["stat", "-c", "%a", path]).ok()?;
    if !out.success {
        return None;
    }
    let mode = out.text().trim().to_string();
    let others = mode.chars().last()?.to_digit(10)?;
    Some(others & 4 != 0)
}

fn plan_docker(cli: &Cli, outer: &Transport, plan: &mut Plan) -> Result<bool, String> {
    let containers = list_containers(outer);
    let requested = cli.docker.as_deref().filter(|n| !n.is_empty());
    let chosen = if let Some(name) = requested {
        containers
            .iter()
            .find(|c| c.name == name)
            .cloned()
            .ok_or_else(|| format!("no running container is named {name}"))?
    } else {
        let odoo: Vec<_> = containers
            .iter()
            .filter(|c| looks_like_odoo(c))
            .cloned()
            .collect();
        match odoo.len() {
            0 if cli.docker.is_some() => return Err("no running Odoo container found".to_string()),
            0 => return Ok(false),
            1 => odoo[0].clone(),
            _ => {
                let names: Vec<String> = odoo.iter().map(|c| c.name.clone()).collect();
                if !can_prompt(cli) {
                    return Err(format!(
                        "several Odoo containers are running: {}. Choose one with --docker NAME",
                        names.join(", ")
                    ));
                }
                let name = choose("Several Odoo containers are running:", &names)
                    .ok_or("no container chosen")?;
                odoo.into_iter()
                    .find(|c| c.name == name)
                    .ok_or("no container chosen")?
            }
        }
    };
    say(&format!("Found Odoo in container {}", chosen.name));
    let transport = Transport::docker(outer, &chosen.name);
    plan.deployment = match outer {
        Transport::Local => format!("Docker ({})", chosen.name),
        _ => format!("Docker over SSH ({})", chosen.name),
    };
    let env = inspect_env(outer, &chosen.name);
    if let Some((path, text)) = find_conf(&transport, cli.conf.as_deref()) {
        plan.conf = Some(conf_with_perms(&transport, path, &text, false));
    }
    if let Some(port) = published_http_port(&chosen.ports) {
        plan.url = Some(format!("http://127.0.0.1:{port}"));
    }
    plan.log_command = Some(vec![
        "docker".into(),
        "logs".into(),
        "--tail".into(),
        LOG_LINES.into(),
        chosen.name.clone(),
    ]);
    plan.log_label = format!("docker logs {}", chosen.name);

    let conf_value = |key: &str| {
        plan.conf
            .as_ref()
            .and_then(|c| c.get(key))
            .map(str::to_string)
    };
    let db_user = env
        .get("USER")
        .cloned()
        .or_else(|| conf_value("db_user"))
        .unwrap_or_else(|| "odoo".into());
    let db_host = env.get("HOST").cloned().or_else(|| conf_value("db_host"));
    let db_port = env.get("PORT").cloned().or_else(|| conf_value("db_port"));
    let db_password = env
        .get("PASSWORD")
        .cloned()
        .or_else(|| plan.conf.as_ref().and_then(|c| c.db_password.clone()));

    let db_container = containers
        .iter()
        .find(|c| {
            is_postgres_image(&c.image) && !chosen.project.is_empty() && c.project == chosen.project
        })
        .or_else(|| {
            containers.iter().find(|c| {
                is_postgres_image(&c.image) && db_host.as_deref() == Some(c.name.as_str())
            })
        });
    plan.sql = Some(if let Some(db) = db_container {
        // Inside the database container, the official image trusts local connections.
        SqlClient::Psql {
            transport: Transport::docker(outer, &db.name),
            args: vec!["-U".into(), db_user],
            password: None,
            database: "postgres".into(),
        }
    } else {
        // An external database: the official Odoo image ships psql, so connect from there.
        let mut args = vec!["-U".to_string(), db_user];
        if let Some(host) = &db_host {
            args.extend(["-h".to_string(), host.clone()]);
        }
        if let Some(port) = &db_port {
            args.extend(["-p".to_string(), port.clone()]);
        }
        let exec = Transport::Docker {
            outer: Box::new(outer.clone()),
            container: chosen.name.clone(),
            env: vec!["PGPASSWORD".into()],
        };
        SqlClient::Psql {
            transport: exec,
            args,
            password: db_password,
            database: "postgres".into(),
        }
    });
    plan.transport = Some(transport);
    Ok(true)
}

fn plan_odoo_sh(outer: &Transport, plan: &mut Plan) -> bool {
    let Ok(out) = outer.run(&["sh", "-c", "printf '%s' \"$ODOO_STAGE\""]) else {
        return false;
    };
    let stage = out.text();
    if !out.success || stage.trim().is_empty() {
        return false;
    }
    say(&format!("Found an Odoo.sh {} build", stage.trim()));
    plan.deployment = format!("Odoo.sh ({})", stage.trim());
    plan.managed = true;
    plan.log_file = Some("logs/odoo.log".to_string());
    plan.log_label = "~/logs/odoo.log".to_string();
    plan.code_roots = vec!["src/user".to_string()];
    plan.sql = Some(SqlClient::Psql {
        transport: outer.clone(),
        args: vec![],
        password: None,
        database: String::new(),
    });
    plan.transport = Some(outer.clone());
    true
}

fn plan_native(cli: &Cli, outer: &Transport, plan: &mut Plan) -> bool {
    let Some((path, text)) = find_conf(outer, cli.conf.as_deref()) else {
        return false;
    };
    say(&format!("Found Odoo configuration at {path}"));
    plan.deployment = if outer.is_local() {
        "Native install".to_string()
    } else {
        "Native install over SSH".to_string()
    };
    let parsed = conf_with_perms(outer, path, &text, true);
    let port = parsed
        .int("http_port")
        .or_else(|| parsed.int("xmlrpc_port"))
        .unwrap_or(8069);
    plan.url = Some(format!("http://127.0.0.1:{port}"));
    if let Some(file) = parsed.get("logfile") {
        plan.log_file = Some(file.to_string());
        plan.log_label = file.to_string();
    } else if outer.has_posix_shell() {
        plan.log_command = Some(vec![
            "journalctl".into(),
            "-u".into(),
            "odoo".into(),
            "-n".into(),
            LOG_LINES.into(),
            "--no-pager".into(),
            "-o".into(),
            "cat".into(),
        ]);
        plan.log_label = "journalctl -u odoo".to_string();
    }
    let host = parsed.get("db_host").map(str::to_string);
    let port = parsed.int("db_port").map(|p| p as u16);
    let user = parsed.get("db_user").map(str::to_string);
    let password = parsed.db_password.clone();
    let sslmode = parsed.get("db_sslmode").map(str::to_string);
    if outer.is_local() {
        let params = DirectParams {
            host,
            port,
            user,
            password,
            sslmode,
            database: "postgres".into(),
        };
        match SqlClient::direct(params) {
            Ok(client) => plan.sql = Some(client),
            Err(e) => plan.sql_error = Some(e),
        }
    } else {
        let mut args = Vec::new();
        if let Some(user) = user {
            args.extend(["-U".to_string(), user]);
        }
        if let Some(host) = host {
            args.extend(["-h".to_string(), host]);
        }
        if let Some(port) = port {
            args.extend(["-p".to_string(), port.to_string()]);
        }
        // Over SSH, peer or trust authentication is usual: secrets are not sent in commands.
        plan.sql = Some(SqlClient::Psql {
            transport: outer.clone(),
            args,
            password: None,
            database: "postgres".into(),
        });
    }
    plan.conf = Some(parsed);
    plan.transport = Some(outer.clone());
    true
}

fn list_databases(sql: &mut SqlClient) -> Result<Vec<String>, String> {
    let rows = sql.rows("SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate AND datname NOT IN ('postgres', 'template0', 'template1') ORDER BY datname")?;
    let names: Vec<String> = rows
        .iter()
        .filter_map(|r| r["datname"].as_str().map(str::to_string))
        .collect();
    let mut odoo_dbs = Vec::new();
    for name in names {
        // A database we cannot open is not one we can audit, so it is simply left out.
        if let Ok(mut client) = sql.with_database(&name) {
            if client.has_table("ir_module_module") {
                odoo_dbs.push(name);
            }
        }
    }
    Ok(odoo_dbs)
}

fn pick_database(
    cli: &Cli,
    plan: &Plan,
    sql: &mut SqlClient,
    snapshot: &mut Snapshot,
) -> Result<Option<String>, String> {
    if let Some(db) = &cli.db {
        return Ok(Some(db.clone()));
    }
    if sql.database().is_empty() {
        return Ok(None); // Odoo.sh: `psql` already points at the right database.
    }
    let found = list_databases(sql)?;
    snapshot.db_count = Some(found.len());
    if let Some(name) = plan.conf.as_ref().and_then(|c| c.get("db_name")) {
        let names: Vec<&str> = name.split(',').map(str::trim).collect();
        if names.len() == 1 && found.iter().any(|f| f == names[0]) {
            return Ok(Some(names[0].to_string()));
        }
    }
    match found.len() {
        0 => Err("no Odoo database found on this server".to_string()),
        1 => Ok(found.into_iter().next()),
        _ if can_prompt(cli) => choose("This server has several Odoo databases:", &found)
            .map(Some)
            .ok_or_else(|| "no database chosen".to_string()),
        _ => Err(format!(
            "several Odoo databases: {}. Choose one with --db NAME",
            found.join(", ")
        )),
    }
}

fn read_logs(plan: &Plan, outer: &Transport) -> Option<Result<logs::LogData, String>> {
    let label = plan.log_label.clone();
    if let Some(argv) = &plan.log_command {
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        return Some(match outer.run(&refs) {
            Ok(out) if out.success => {
                // `docker logs` sends the container's stderr to stderr, and Odoo logs there.
                let text = format!("{}\n{}", out.text(), out.stderr);
                Ok(logs::analyze(&label, &text))
            }
            Ok(out) => Err(first_line(&out.stderr)),
            Err(e) => Err(e),
        });
    }
    let file = plan.log_file.as_ref()?;
    let transport = plan.transport.as_ref()?;
    if transport.is_local() {
        return Some(read_local_tail(file).map(|text| logs::analyze(&label, &text)));
    }
    Some(match transport.run(&["tail", "-n", LOG_LINES, file]) {
        Ok(out) if out.success => Ok(logs::analyze(&label, &out.text())),
        Ok(out) => Err(first_line(&out.stderr)),
        Err(e) => Err(e),
    })
}

fn read_local_tail(path: &str) -> Result<String, String> {
    use std::io::{Read, Seek, SeekFrom};
    const LIMIT: u64 = 8 * 1024 * 1024;
    let mut file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    file.seek(SeekFrom::Start(size.saturating_sub(LIMIT)))
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_host(plan: &Plan) -> Option<HostData> {
    let transport = plan.transport.as_ref()?;
    if !transport.has_posix_shell() {
        return None;
    }
    let path = plan
        .conf
        .as_ref()
        .and_then(|c| c.get("data_dir"))
        .unwrap_or(".")
        .to_string();
    let out = transport.run(&["df", "-P", &path]).ok()?;
    if !out.success {
        return None;
    }
    let text = out.text();
    let last = text.lines().last()?;
    let used = last
        .split_whitespace()
        .find(|w| w.ends_with('%'))?
        .trim_end_matches('%')
        .parse()
        .ok()?;
    Some(HostData {
        disk_used_pct: Some(used),
        disk_path: path,
    })
}

fn gather_code(cli: &Cli, plan: &Plan, snapshot: &mut Snapshot) {
    let (roots, complete, transport) = if !cli.addons.is_empty() {
        (cli.addons.clone(), false, Transport::Local)
    } else if let Some(transport) = plan.transport.clone() {
        let mut roots = plan.code_roots.clone();
        let mut complete = !roots.is_empty();
        if let Some(c) = &plan.conf {
            let configured: Vec<String> = c.addons_paths();
            complete = complete || !configured.is_empty();
            for path in configured {
                let last = path
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !code::is_core_path(&path) && last != "enterprise" && !roots.contains(&path) {
                    roots.push(path);
                }
            }
        }
        (roots, complete, transport)
    } else {
        (Vec::new(), false, Transport::Local)
    };
    if roots.is_empty() {
        let reason = if plan.transport.is_some() {
            "no custom addons path found. Use --addons DIR".to_string()
        } else {
            "no access to the source code. Use --ssh, --docker or --addons DIR".to_string()
        };
        snapshot.skipped.push((Layer::Code, reason));
        return;
    }
    say(&format!("Analyzing custom modules in {}", roots.join(", ")));
    snapshot.code = Some(code::collect(
        &transport,
        &roots,
        cli.include_vendor,
        complete,
    ));
}

/// Runs the audit. An error here means there was nothing at all to audit.
pub fn run(cli: &Cli) -> Result<Snapshot, String> {
    let mut snapshot = Snapshot {
        target_major: cli.target_version,
        ..Snapshot::default()
    };
    let outer = match &cli.ssh {
        Some(host) => Transport::Ssh { host: host.clone() },
        None => Transport::Local,
    };
    let mut plan = Plan {
        url: cli.url.clone(),
        ..Plan::default()
    };
    let code_only = !cli.addons.is_empty()
        && cli.url.is_none()
        && cli.ssh.is_none()
        && cli.docker.is_none()
        && cli.pg.is_none()
        && cli.conf.is_none();
    // An address alone means "audit that site". Nothing local should end up in that report.
    let explore = !code_only
        && (cli.url.is_none() || cli.ssh.is_some() || cli.docker.is_some() || cli.conf.is_some());
    let explicit_url = cli.url.clone();
    if explore {
        if cli.ssh.is_some() {
            let probe = outer
                .run(&["true"])
                .map_err(|e| format!("cannot run ssh: {e}"))?;
            if !probe.success {
                return Err(format!(
                    "cannot connect to {}: {}",
                    outer.describe(),
                    first_line(&probe.stderr)
                ));
            }
        }
        let mut found = false;
        if cli.docker.is_some() {
            found = plan_docker(cli, &outer, &mut plan)?;
        }
        if !found && cli.conf.is_none() {
            found = plan_odoo_sh(&outer, &mut plan);
        }
        if !found && cli.conf.is_some() {
            found = plan_native(cli, &outer, &mut plan);
            if !found {
                return Err(format!("cannot read {}", cli.conf.as_deref().unwrap_or("")));
            }
        }
        if !found {
            found = plan_native(cli, &outer, &mut plan);
        }
        if !found {
            found = plan_docker(cli, &outer, &mut plan)?;
        }
        if !found && cli.pg.is_none() && cli.url.is_none() {
            if cli.ssh.is_some() {
                return Err(format!(
                    "no Odoo found on {}. Try --conf PATH or --docker NAME",
                    outer.describe()
                ));
            }
            if can_prompt(cli) {
                eprintln!("No Odoo found on this machine.");
                plan.url = ask("Address of the Odoo site to audit (or Enter to quit):");
            }
            if plan.url.is_none() {
                return Err("no Odoo found on this machine. Pass an address: odoo-doctor https://erp.example.com".to_string());
            }
        }
    }
    if explicit_url.is_some() {
        plan.url.clone_from(&explicit_url);
    }
    if let Some(url) = &cli.pg {
        let params = SqlClient::parse_url(url)?;
        match SqlClient::direct(DirectParams {
            database: if params.database.is_empty() {
                "postgres".into()
            } else {
                params.database.clone()
            },
            ..params
        }) {
            Ok(client) => {
                plan.sql = Some(client);
                plan.sql_error = None;
                snapshot.pg_role_is_odoos = false;
            }
            Err(e) => plan.sql_error = Some(e),
        }
    }

    // Database layers.
    let mut major_from_db = None;
    if let Some(sql) = plan.sql.as_mut() {
        match pick_database(cli, &plan_view(&plan.conf), sql, &mut snapshot) {
            Ok(choice) => {
                let client = match &choice {
                    Some(db) if db != sql.database() => sql.with_database(db),
                    _ => Err(String::new()),
                };
                let target = match client {
                    Ok(c) => {
                        *sql = c;
                        sql
                    }
                    Err(e) if !e.is_empty() => {
                        plan.sql_error = Some(e);
                        snapshot
                            .skipped
                            .push((Layer::Database, plan.sql_error.clone().unwrap_or_default()));
                        finish_without_sql(cli, &mut plan, &mut snapshot, &outer);
                        return Ok(snapshot);
                    }
                    Err(_) => sql,
                };
                say(&format!("Reading the database with {}", target.describe()));
                match odoo::from_sql(target) {
                    Ok(data) => {
                        major_from_db = data.major;
                        snapshot.database = Some(if target.database().is_empty() {
                            target
                                .one("SELECT current_database() AS db")
                                .ok()
                                .and_then(|v| v["db"].as_str().map(str::to_string))
                                .unwrap_or_default()
                        } else {
                            target.database().to_string()
                        });
                        // Prefer the public address over the local one, so exposure checks see what users see.
                        if explicit_url.is_none() {
                            if let Some(public) = data.params.get("web.base.url") {
                                let (_, host, _) = external::split_url(public);
                                if !external::is_loopback(&host)
                                    && external::collect(public, false, false)
                                        .server_serie
                                        .is_some()
                                {
                                    plan.url = Some(public.clone());
                                }
                            }
                        }
                        snapshot.odoo = Some(data);
                    }
                    Err(e) => snapshot.skipped.push((Layer::Database, e)),
                }
                match pg::collect(target) {
                    Ok(data) => snapshot.pg = Some(data),
                    Err(e) => snapshot.skipped.push((Layer::Postgres, e)),
                }
            }
            Err(e) => {
                warn(&e);
                snapshot.skipped.push((Layer::Database, e.clone()));
                snapshot.skipped.push((Layer::Postgres, e));
            }
        }
    } else if let Some(error) = &plan.sql_error {
        warn(&format!("Cannot connect to PostgreSQL: {error}"));
        let message = format!("cannot connect to PostgreSQL: {error}");
        snapshot.skipped.push((Layer::Postgres, message.clone()));
        snapshot.skipped.push((Layer::Database, message));
    }
    finish(cli, &mut plan, &mut snapshot, &outer, major_from_db);
    Ok(snapshot)
}

/// `pick_database` only needs the configuration, and this avoids borrowing all of `Plan` twice.
fn plan_view(conf: &Option<OdooConf>) -> Plan {
    Plan {
        conf: conf.clone(),
        ..Plan::default()
    }
}

fn finish_without_sql(cli: &Cli, plan: &mut Plan, snapshot: &mut Snapshot, outer: &Transport) {
    finish(cli, plan, snapshot, outer, None);
}

fn finish(
    cli: &Cli,
    plan: &mut Plan,
    snapshot: &mut Snapshot,
    outer: &Transport,
    major_from_db: Option<u32>,
) {
    snapshot.conf = plan.conf.clone();
    // External layer.
    if let Some(url) = &plan.url {
        say(&format!("Checking {url} from outside"));
        let data = external::collect(url, cli.treat_as_public, !cli.no_port_probe);
        if let Some(error) = &data.error {
            warn(&format!("Could not reach {url}: {}", first_line(error)));
        }
        if is_odoo_hosted(url) {
            plan.managed = true;
            if plan.deployment.is_empty() {
                plan.deployment = "Hosted by Odoo (Odoo Online or Odoo.sh)".to_string();
            }
        }
        snapshot.external = Some(data);
    } else if !cli.addons.is_empty() && plan.transport.is_none() {
        snapshot
            .skipped
            .push((Layer::External, "no address given".to_string()));
    } else {
        snapshot.skipped.push((
            Layer::External,
            "no address known. Pass the site's URL".to_string(),
        ));
    }
    // The API runs only when SQL did not provide the data.
    if snapshot.odoo.is_none() {
        run_api(cli, plan, snapshot, major_from_db);
    }
    if snapshot.conf.is_none() {
        let reason = if plan.managed {
            "managed by Odoo"
        } else {
            "no access to odoo.conf. Use --ssh, --docker or --conf"
        };
        snapshot.skipped.push((Layer::Config, reason.to_string()));
    }
    if snapshot.pg.is_none() && !snapshot.skipped.iter().any(|(l, _)| *l == Layer::Postgres) {
        snapshot.skipped.push((
            Layer::Postgres,
            "no database access. Use --pg, --ssh or --docker".to_string(),
        ));
    }
    if snapshot.odoo.is_none() && !snapshot.skipped.iter().any(|(l, _)| *l == Layer::Database) {
        snapshot.skipped.push((
            Layer::Database,
            "no database or API access. Use --pg, --ssh, --docker or --api-key".to_string(),
        ));
    }
    gather_code(cli, plan, snapshot);
    // Logs and disk.
    match read_logs(plan, outer) {
        Some(Ok(data)) => snapshot.logs = Some(data),
        Some(Err(e)) => snapshot.skipped.push((Layer::Logs, e)),
        None => snapshot
            .skipped
            .push((Layer::Logs, "no access to server logs".to_string())),
    }
    snapshot.host = read_host(plan);
    if snapshot.host.is_none() {
        let reason = if plan
            .transport
            .as_ref()
            .is_some_and(|t| !t.has_posix_shell())
        {
            "disk check is not available on Windows yet"
        } else {
            "no shell access to the server"
        };
        snapshot.skipped.push((Layer::Host, reason.to_string()));
    }
    if plan.deployment.is_empty() {
        plan.deployment = if !cli.addons.is_empty() && plan.url.is_none() {
            "Source code only".to_string()
        } else {
            "Remote site".to_string()
        };
    }
    snapshot.deployment = plan.deployment.clone();
    snapshot.managed = plan.managed;
}

fn run_api(cli: &Cli, plan: &Plan, snapshot: &mut Snapshot, major: Option<u32>) {
    let Some(key) = &cli.api_key else {
        if let Some(url) = &plan.url {
            if cli.login.is_some() {
                snapshot.skipped.push((
                    Layer::Database,
                    format!("--login was given without --api-key for {url}"),
                ));
            }
        }
        return;
    };
    let Some(url) = &plan.url else {
        snapshot.skipped.push((
            Layer::Database,
            "--api-key needs the site's address".to_string(),
        ));
        return;
    };
    let Some(login) = &cli.login else {
        snapshot
            .skipped
            .push((Layer::Database, "--api-key also needs --login".to_string()));
        return;
    };
    let major = major.or_else(|| {
        snapshot
            .external
            .as_ref()
            .and_then(|e| e.server_serie.as_deref())
            .and_then(odoo::major_of)
    });
    let database = cli
        .db
        .clone()
        .or_else(|| {
            snapshot
                .external
                .as_ref()
                .and_then(|e| e.db_list.as_ref())
                .filter(|l| l.len() == 1)
                .map(|l| l[0].clone())
        })
        .or_else(|| hosted_db_name(url));
    let Some(database) = database else {
        snapshot.skipped.push((
            Layer::Database,
            "the API needs the database name. Use --db NAME".to_string(),
        ));
        return;
    };
    say("Reading data through the Odoo API");
    let result = api::ApiClient::new(url, &database, login, key, major)
        .and_then(|client| api::collect(&client));
    match result {
        Ok(data) => {
            snapshot.database = Some(database);
            snapshot.odoo = Some(data);
        }
        Err(e) => {
            warn(&format!("API access failed: {e}"));
            snapshot
                .skipped
                .push((Layer::Database, format!("API access failed: {e}")));
        }
    }
}

/// On Odoo Online, the database is named after the subdomain.
fn hosted_db_name(url: &str) -> Option<String> {
    let (_, host, _) = external::split_url(url);
    host.strip_suffix(".odoo.com")
        .filter(|n| !n.contains('.'))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_published_odoo_port() {
        assert_eq!(
            published_http_port("127.0.0.1:18019->8069/tcp, 8071-8072/tcp"),
            Some(18019)
        );
        assert_eq!(
            published_http_port("0.0.0.0:8069->8069/tcp, [::]:8069->8069/tcp"),
            Some(8069)
        );
        assert_eq!(published_http_port("8069/tcp"), None);
        assert_eq!(published_http_port(""), None);
    }

    #[test]
    fn recognizes_odoo_containers_only() {
        let c = |name: &str, image: &str| DockerContainer {
            name: name.into(),
            image: image.into(),
            ..DockerContainer::default()
        };
        assert!(looks_like_odoo(&c("web", "odoo:19")));
        assert!(looks_like_odoo(&c("odoo19-app", "acme/erp:1")));
        assert!(!looks_like_odoo(&c("odoo19-db", "postgres:16")));
        assert!(!looks_like_odoo(&c("odoo-proxy", "nginx:1")));
        assert!(!looks_like_odoo(&c("web", "nginx:1")));
    }

    #[test]
    fn derives_the_hosted_database_name() {
        assert_eq!(
            hosted_db_name("https://acme.odoo.com").as_deref(),
            Some("acme")
        );
        assert_eq!(hosted_db_name("https://acme-main-123.dev.odoo.com"), None);
        assert_eq!(hosted_db_name("https://erp.acme.com"), None);
    }
}
