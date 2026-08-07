//! Non-plaintext password resolution (`pgpass`)
//!
//! Two mechanisms let `NodeConfig.password` avoid holding a secret in
//! plaintext directly inside the YAML config file:
//!
//! 1. `${ENV_VAR}` placeholder substitution: if the `password` field's
//!    value contains one or more `${NAME}` placeholders, each is replaced
//!    with the value of the process environment variable `NAME`. This
//!    lets the actual secret live in the environment (e.g. injected by a
//!    secrets manager, systemd `EnvironmentFile=`, or a Kubernetes Secret
//!    mounted as an env var) rather than in the file on disk.
//! 2. `.pgpass`-format lookup: if `password` is omitted entirely from the
//!    config, it is looked up from a `.pgpass`-format file using the same
//!    file location and matching rules libpq uses: the `PGPASSFILE`
//!    environment variable if set, otherwise `~/.pgpass`; each line has
//!    the form `hostname:port:database:username:password`, `*` matches
//!    any value in a field, and `:`/`\` inside a field are escaped with a
//!    leading `\`.
//!
//! Note: as of this writing, `pool::conn::establish_connection` and
//! `health::checker::WireProtocolHealthProbe` only perform `trust`
//! (passwordless) authentication against the backend -- see the
//! limitation documented on `WireProtocolHealthProbe`. Resolving a
//! password here does not yet make the proxy actually send it to the
//! backend; this module exists so operators can keep `NodeConfig` free of
//! plaintext secrets today, ready for when password-based backend
//! authentication (e.g. SCRAM) is implemented.

use std::collections::HashMap;
use std::path::PathBuf;

/// Errors resolving a password via either mechanism.
#[derive(Debug, thiserror::Error)]
pub enum PgPassError {
    #[error("environment variable '{0}' referenced in config (as ${{{0}}}) is not set")]
    EnvVarNotSet(String),

    #[error("failed to read pgpass file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Replaces every `${NAME}` placeholder in `input` with the value of the
/// environment variable `NAME`. Returns `input` unchanged (no allocation
/// beyond the initial clone) if it contains no placeholders. Fails if any
/// referenced variable is not set, rather than silently substituting an
/// empty string -- a missing variable is almost certainly a deployment
/// mistake, not an intentionally empty password.
pub fn substitute_env_placeholders(input: &str) -> Result<String, PgPassError> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find("${") {
        let Some(end_offset) = rest[start..].find('}') else {
            // Unterminated placeholder: treat the rest of the string as
            // literal text rather than erroring, since `${` on its own is
            // valid in a password.
            out.push_str(rest);
            return Ok(out);
        };
        let end = start + end_offset;
        let var_name = &rest[start + 2..end];

        out.push_str(&rest[..start]);
        if var_name.is_empty() {
            // "${}" is not a valid placeholder; keep it literal.
            out.push_str("${}");
        } else {
            let value = std::env::var(var_name)
                .map_err(|_| PgPassError::EnvVarNotSet(var_name.to_string()))?;
            out.push_str(&value);
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// A single parsed `.pgpass` entry. `*` in any field (other than
/// `password`) matches any value for that field.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PgPassEntry {
    host: String,
    port: String,
    database: String,
    username: String,
    password: String,
}

impl PgPassEntry {
    fn matches(&self, host: &str, port: u16, database: &str, username: &str) -> bool {
        field_matches(&self.host, host)
            && field_matches(&self.port, &port.to_string())
            && field_matches(&self.database, database)
            && field_matches(&self.username, username)
    }
}

fn field_matches(pattern: &str, value: &str) -> bool {
    pattern == "*" || pattern == value
}

/// Splits a single `.pgpass` line into its 5 colon-separated fields,
/// honoring `\:` and `\\` escapes within a field. Returns `None` if the
/// line does not have exactly 5 fields (malformed lines are skipped
/// rather than causing the whole file to fail to parse).
fn split_pgpass_line(line: &str) -> Option<[String; 5]> {
    let mut fields: Vec<String> = Vec::with_capacity(5);
    let mut current = String::new();
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(&next) = chars.peek() {
                    if next == ':' || next == '\\' {
                        current.push(next);
                        chars.next();
                        continue;
                    }
                }
                current.push('\\');
            }
            ':' => {
                fields.push(std::mem::take(&mut current));
            }
            other => current.push(other),
        }
    }
    fields.push(current);

    fields.try_into().ok()
}

/// Parses the full contents of a `.pgpass`-format file, skipping blank
/// lines and lines starting with `#` (comments), matching libpq's own
/// parsing rules.
fn parse_pgpass_contents(contents: &str) -> Vec<PgPassEntry> {
    contents
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .filter_map(split_pgpass_line)
        .map(|[host, port, database, username, password]| PgPassEntry {
            host,
            port,
            database,
            username,
            password,
        })
        .collect()
}

/// Resolves the `.pgpass` file path following libpq's lookup order: the
/// `PGPASSFILE` environment variable if set, otherwise `~/.pgpass` (using
/// the `HOME` environment variable; Windows' `%APPDATA%\postgresql\pgpass.conf`
/// convention is not currently supported).
fn pgpass_file_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PGPASSFILE") {
        return Some(PathBuf::from(path));
    }
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".pgpass"))
}

/// Looks up a password for `(host, port, database, username)` from the
/// `.pgpass`-format file (see `pgpass_file_path`). Returns `Ok(None)` if
/// no pgpass file location could be determined, the file does not exist,
/// or no entry matches -- all of these are normal "no password configured
/// this way" outcomes, not errors. Returns `Err` only for a genuine I/O
/// failure reading a file that does exist (e.g. permission denied).
pub fn resolve_password_from_pgpass(
    host: &str,
    port: u16,
    database: &str,
    username: &str,
) -> Result<Option<String>, PgPassError> {
    let Some(path) = pgpass_file_path() else {
        return Ok(None);
    };

    // libpq-compatible permission check: on Unix, the .pgpass file must
    // not be world-or-group readable (mode & 0o077 must be 0), otherwise
    // it is silently ignored. This prevents accidental exposure of secrets.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(&path) {
            Ok(meta) => {
                let mode = meta.mode();
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:04o}", mode & 0o7777),
                        "ignoring .pgpass file: permissions are too open (must be 0600 or stricter)"
                    );
                    return Ok(None);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(PgPassError::Io {
                    path: path.display().to_string(),
                    source,
                })
            }
        }
    }

    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(PgPassError::Io {
                path: path.display().to_string(),
                source,
            })
        }
    };

    let entries = parse_pgpass_contents(&contents);
    Ok(entries
        .iter()
        .find(|e| e.matches(host, port, database, username))
        .map(|e| e.password.clone()))
}

/// Test-only helper retained for potential future use (e.g. testing
/// multiple simultaneous env var substitutions against a caller-supplied
/// map instead of the real process environment). Not currently wired into
/// any public API.
#[allow(dead_code)]
fn substitute_from_map(input: &str, vars: &HashMap<String, String>) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        let end_offset = rest[start..].find('}')?;
        let end = start + end_offset;
        let var_name = &rest[start + 2..end];
        out.push_str(&rest[..start]);
        out.push_str(vars.get(var_name)?);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared env-var serialization lock (same instance used by config::tests).
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::config::tests::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    // -----------------------------------------------------------------
    // substitute_env_placeholders
    // -----------------------------------------------------------------

    #[test]
    fn substitutes_single_placeholder() {
        std::env::set_var("TRIDENT_TEST_PW", "s3cret");
        let result = substitute_env_placeholders("${TRIDENT_TEST_PW}").unwrap();
        assert_eq!(result, "s3cret");
        std::env::remove_var("TRIDENT_TEST_PW");
    }

    #[test]
    fn substitutes_placeholder_embedded_in_larger_string() {
        std::env::set_var("TRIDENT_TEST_PW2", "abc");
        let result = substitute_env_placeholders("prefix-${TRIDENT_TEST_PW2}-suffix").unwrap();
        assert_eq!(result, "prefix-abc-suffix");
        std::env::remove_var("TRIDENT_TEST_PW2");
    }

    #[test]
    fn substitutes_multiple_placeholders() {
        std::env::set_var("TRIDENT_TEST_A", "AA");
        std::env::set_var("TRIDENT_TEST_B", "BB");
        let result = substitute_env_placeholders("${TRIDENT_TEST_A}-${TRIDENT_TEST_B}").unwrap();
        assert_eq!(result, "AA-BB");
        std::env::remove_var("TRIDENT_TEST_A");
        std::env::remove_var("TRIDENT_TEST_B");
    }

    #[test]
    fn plain_string_without_placeholders_is_unchanged() {
        let result = substitute_env_placeholders("plain-password").unwrap();
        assert_eq!(result, "plain-password");
    }

    #[test]
    fn missing_env_var_is_an_error() {
        std::env::remove_var("TRIDENT_TEST_MISSING_VAR");
        let result = substitute_env_placeholders("${TRIDENT_TEST_MISSING_VAR}");
        assert!(
            matches!(result, Err(PgPassError::EnvVarNotSet(name)) if name == "TRIDENT_TEST_MISSING_VAR")
        );
    }

    #[test]
    fn unterminated_placeholder_is_kept_literal() {
        let result = substitute_env_placeholders("abc${unterminated").unwrap();
        assert_eq!(result, "abc${unterminated");
    }

    // -----------------------------------------------------------------
    // pgpass parsing / matching
    // -----------------------------------------------------------------

    #[test]
    fn parses_simple_pgpass_line() {
        let entries = parse_pgpass_contents("10.0.1.10:5432:mydb:proxy_user:s3cret\n");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].matches("10.0.1.10", 5432, "mydb", "proxy_user"));
        assert_eq!(entries[0].password, "s3cret");
    }

    #[test]
    fn wildcard_fields_match_anything() {
        let entries = parse_pgpass_contents("*:*:*:*:wildcard-pw\n");
        assert!(entries[0].matches("any-host", 1234, "any-db", "any-user"));
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let entries = parse_pgpass_contents("# comment\n\n10.0.1.10:5432:mydb:proxy_user:pw\n");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn skips_malformed_lines_with_wrong_field_count() {
        let entries =
            parse_pgpass_contents("only:four:fields:here\n10.0.1.10:5432:mydb:proxy_user:pw\n");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn handles_escaped_colon_and_backslash_in_password() {
        let line = r"10.0.1.10:5432:mydb:proxy_user:pa\:ss\\word".to_owned() + "\n";
        let entries = parse_pgpass_contents(&line);
        assert_eq!(entries[0].password, r"pa:ss\word");
    }

    #[test]
    fn first_matching_entry_wins() {
        let entries = parse_pgpass_contents(
            "10.0.1.10:5432:mydb:proxy_user:first\n10.0.1.10:5432:mydb:proxy_user:second\n",
        );
        let found = entries
            .iter()
            .find(|e| e.matches("10.0.1.10", 5432, "mydb", "proxy_user"))
            .map(|e| e.password.clone());
        assert_eq!(found, Some("first".to_string()));
    }

    #[test]
    fn no_match_returns_none() {
        let entries = parse_pgpass_contents("10.0.1.10:5432:mydb:proxy_user:pw\n");
        assert!(!entries[0].matches("other-host", 5432, "mydb", "proxy_user"));
    }

    // -----------------------------------------------------------------
    // resolve_password_from_pgpass (file-based, using PGPASSFILE so tests
    // don't touch the real ~/.pgpass)
    // -----------------------------------------------------------------

    #[test]
    fn resolves_password_from_pgpassfile_env_override() {
        let _guard = env_lock();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("trident-test-pgpass-{}.conf", std::process::id()));
        std::fs::write(&path, "10.0.1.10:5432:mydb:proxy_user:from-pgpass\n").unwrap();

        // Set restrictive permissions as required by the permission check.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        std::env::set_var("PGPASSFILE", &path);
        let result = resolve_password_from_pgpass("10.0.1.10", 5432, "mydb", "proxy_user").unwrap();
        std::env::remove_var("PGPASSFILE");
        let _ = std::fs::remove_file(&path);

        assert_eq!(result, Some("from-pgpass".to_string()));
    }

    #[test]
    fn missing_pgpassfile_returns_none_not_error() {
        let _guard = env_lock();
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "trident-test-pgpass-missing-{}.conf",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path); // ensure it does not exist

        std::env::set_var("PGPASSFILE", &path);
        let result = resolve_password_from_pgpass("host", 5432, "db", "user").unwrap();
        std::env::remove_var("PGPASSFILE");

        assert_eq!(result, None);
    }

    #[test]
    fn no_matching_entry_returns_none() {
        let _guard = env_lock();
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "trident-test-pgpass-nomatch-{}.conf",
            std::process::id()
        ));
        std::fs::write(&path, "other-host:5432:otherdb:otheruser:pw\n").unwrap();

        std::env::set_var("PGPASSFILE", &path);
        let result = resolve_password_from_pgpass("10.0.1.10", 5432, "mydb", "proxy_user").unwrap();
        std::env::remove_var("PGPASSFILE");
        let _ = std::fs::remove_file(&path);

        assert_eq!(result, None);
    }
}
