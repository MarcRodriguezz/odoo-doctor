// Full-stack prototype: everything odoo-doctor's binary must link.
use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    url: String,
    #[arg(long)]
    pg: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = Args::parse();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let resp = ureq::get(&a.url).call()?;
    let status = resp.status().as_u16();
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let cfg = rustls::ClientConfig::builder().with_root_certificates(Arc::new(roots)).with_no_client_auth();
    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(cfg);
    let mut pg = postgres::Client::connect(&a.pg, tls)?;
    let v: String = pg.query_one("select version()", &[])?.get(0);
    let parsed = ruff_python_parser::parse_module("def f():\n    return 1\n")?;
    let out = serde_json::json!({"http": status, "pg": &v[..15], "stmts": parsed.syntax().body.len()});
    let env = minijinja::Environment::new();
    let html = env.render_str("<pre>{{ o }}</pre>\n", minijinja::context! { o => out.to_string() })?;
    print!("{html}");
    Ok(())
}
