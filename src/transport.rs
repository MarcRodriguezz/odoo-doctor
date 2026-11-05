//! Runs read-only commands where Odoo lives: this machine, a container, or over SSH.
//!
//! Remote access reuses the `docker` and `ssh` clients already on the machine, so odoo-doctor
//! inherits the user's SSH keys and Docker contexts and has no credentials of its own.
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Local,
    Ssh {
        host: String,
    },
    Docker {
        outer: Box<Transport>,
        container: String,
        env: Vec<String>,
    },
}

const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);

impl Transport {
    pub fn is_local(&self) -> bool {
        matches!(self, Transport::Local)
    }

    /// True when commands can run through a POSIX shell. A local Windows machine cannot.
    pub fn has_posix_shell(&self) -> bool {
        match self {
            Transport::Local => cfg!(unix),
            _ => true,
        }
    }

    pub fn docker(outer: &Transport, container: &str) -> Transport {
        Transport::Docker {
            outer: Box::new(outer.clone()),
            container: container.to_string(),
            env: vec![],
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Transport::Local => "this machine".to_string(),
            Transport::Ssh { host } => format!("ssh {host}"),
            Transport::Docker {
                outer, container, ..
            } => match **outer {
                Transport::Local => format!("container {container}"),
                _ => format!("container {container} via {}", outer.describe()),
            },
        }
    }

    /// Builds the argv that runs `argv` on this transport.
    pub fn build(&self, argv: &[String], stdin: bool) -> Vec<String> {
        match self {
            Transport::Local => argv.to_vec(),
            Transport::Ssh { host } => {
                let mut out = vec![
                    "ssh".to_string(),
                    "-o".to_string(),
                    "BatchMode=yes".to_string(),
                    "-o".to_string(),
                    "ConnectTimeout=15".to_string(),
                    host.clone(),
                ];
                out.push(
                    argv.iter()
                        .map(|a| shell_quote(a))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                out
            }
            Transport::Docker {
                outer,
                container,
                env,
            } => {
                let mut out = vec!["docker".to_string(), "exec".to_string()];
                if stdin {
                    out.push("-i".to_string());
                }
                for e in env {
                    // `-e NAME` copies from the client environment, so values stay out of argv.
                    out.push("-e".to_string());
                    out.push(e.clone());
                }
                out.push(container.clone());
                out.extend(argv.iter().cloned());
                outer.build(&out, stdin)
            }
        }
    }

    pub fn run(&self, argv: &[&str]) -> Result<Output, String> {
        self.run_with(argv, None, &[])
    }

    pub fn run_with(
        &self,
        argv: &[&str],
        stdin: Option<&str>,
        envs: &[(&str, &str)],
    ) -> Result<Output, String> {
        let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let full = self.build(&owned, stdin.is_some());
        let (program, rest) = full.split_first().ok_or("empty command")?;
        let mut command = Command::new(program);
        command
            .args(rest)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in envs {
            command.env(key, value);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot run `{program}`: {e}"))?;
        if let Some(text) = stdin {
            if let Some(mut pipe) = child.stdin.take() {
                let text = text.to_string();
                std::thread::spawn(move || {
                    let _ = pipe.write_all(text.as_bytes());
                });
            }
        }
        // Drain both pipes on threads: a full pipe would otherwise deadlock the child.
        let mut out_pipe = child.stdout.take().ok_or("no stdout")?;
        let mut err_pipe = child.stderr.take().ok_or("no stderr")?;
        let out_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out_pipe.read_to_end(&mut buf);
            buf
        });
        let err_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err_pipe.read_to_end(&mut buf);
            buf
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(status) => break status,
                None if started.elapsed() > COMMAND_TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "`{program}` timed out after {}s",
                        COMMAND_TIMEOUT.as_secs()
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        let stdout = out_thread.join().unwrap_or_default();
        let stderr = err_thread.join().unwrap_or_default();
        Ok(Output {
            success: status.success(),
            stdout,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    pub fn read_file(&self, path: &str) -> Option<String> {
        if self.is_local() {
            return std::fs::read(path)
                .ok()
                .map(|b| String::from_utf8_lossy(&b).into_owned());
        }
        let out = self.run(&["cat", path]).ok()?;
        out.success
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Streams `tar` from the target, skipping files the analysis never reads.
    pub fn read_tree(&self, path: &str) -> Result<Vec<u8>, String> {
        let out = self.run(&[
            "tar",
            "cf",
            "-",
            "--exclude=.git",
            "--exclude=static",
            "--exclude=i18n",
            "--exclude=__pycache__",
            "--exclude=node_modules",
            "--exclude=_vendor",
            "--exclude=*.pyc",
            "-C",
            path,
            ".",
        ])?;
        if !out.success && out.stdout.is_empty() {
            return Err(first_line(&out.stderr));
        }
        Ok(out.stdout)
    }
}

pub struct Output {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl Output {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

pub fn first_line(text: &str) -> String {
    text.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("unknown error")
        .trim()
        .chars()
        .take(240)
        .collect()
}

/// Single-quotes a value for the remote POSIX shell that ssh runs it under.
pub fn shell_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,@%+".contains(c));
    if safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| i.to_string()).collect()
    }

    #[test]
    fn quoting_keeps_simple_words_and_escapes_the_rest() {
        assert_eq!(shell_quote("psql"), "psql");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn docker_builds_exec_and_never_puts_values_in_argv() {
        let t = Transport::Docker {
            outer: Box::new(Transport::Local),
            container: "odoo1".into(),
            env: vec!["PGPASSWORD".into()],
        };
        assert_eq!(
            t.build(&s(&["psql", "-At"]), true),
            s(&[
                "docker",
                "exec",
                "-i",
                "-e",
                "PGPASSWORD",
                "odoo1",
                "psql",
                "-At"
            ])
        );
    }

    #[test]
    fn docker_over_ssh_nests_and_quotes() {
        let t = Transport::docker(&Transport::Ssh { host: "srv".into() }, "odoo1");
        let argv = t.build(&s(&["cat", "/a b"]), false);
        assert_eq!(
            &argv[..5],
            &s(&["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"])[..]
        );
        assert_eq!(argv[5], "srv");
        assert_eq!(argv[6], "docker exec odoo1 cat '/a b'");
    }

    #[cfg(unix)]
    #[test]
    fn large_output_does_not_deadlock() {
        let out = Transport::Local
            .run(&[
                "sh",
                "-c",
                "yes x | head -c 2000000; yes y | head -c 200000 >&2",
            ])
            .unwrap();
        assert!(out.success);
        assert_eq!(out.stdout.len(), 2_000_000);
    }
}
