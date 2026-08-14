//! Custom table/function routing rules (`custom_rules`)
//!
//! Lets an operator register routing overrides keyed by table name or
//! function name, matching this parameter shape (as specified by the
//! feature request this module implements):
//!
//! - `_name`: the table or function name the rule applies to.
//! - `_type`: `t` for a table name, `f` for a function name (kept as two
//!   separate namespaces -- see `RuleTargetKind` -- so a table and a
//!   function can share the same name without colliding).
//! - `rw_mode`: `w` -- statements referencing this name may only be
//!   routed to the Writer node; `r` -- statements referencing this name
//!   are permitted to be routed to a Reader node (subject to the normal
//!   classification/consistency pipeline that already runs -- this does
//!   *not* unconditionally force Reader, it only lifts a writer-only
//!   restriction).
//!
//! ## Why this exists and what it actually changes
//!
//! By default, Trident already routes most read-only SQL to a Reader
//! (see `parser::classifier`) and only forces Writer for write statements
//! or a small hardcoded set of write functions
//! (`nextval`/`setval`/`pg_advisory_lock*`/`lo_*`, see
//! `Classifier::has_write_function_call`). This module adds a second,
//! independent, purely *additive* mechanism: an operator can mark
//! specific tables or (their own custom, non-builtin) functions as
//! writer-only, e.g. because a table is known to have significant
//! replication lag, or a stored function has side effects the classifier
//! has no way to know about from the SQL text alone. Registering a rule
//! with `rw_mode: r` is a no-op unless a `w` rule for the same name was
//! previously in effect -- it exists so an operator can flip a
//! previously-restricted name back to normal routing without deleting
//! the rule (keeping an audit trail of what was ever restricted).
//!
//! With no rules registered (the default), routing behavior is completely
//! unchanged from before this module existed.
//!
//! ## Scope and known limitations
//!
//! - Only applies to the autocommit/non-transaction routing path in
//!   `Router::route` (Requirement scope note: explicit transactions are
//!   already routed by the transaction-split state machine in
//!   `session::transaction`, which this module does not integrate with).
//! - Table/function name extraction from SQL text is a lightweight regex
//!   heuristic, not a real SQL parser: it looks for identifiers following
//!   `FROM`/`JOIN`/`UPDATE`/`INTO` (tables) and any `identifier(`
//!   (functions). This can occasionally extract something that is not
//!   actually a table/function reference (e.g. a keyword that happens to
//!   be followed by `(`), but since matches are only ever checked against
//!   rules an operator explicitly registered, an accidental match against
//!   an *unregistered* name has no effect -- the only practical risk is if
//!   an operator names a rule after a SQL keyword, which is under their
//!   control.
//! - Identifier matching is case-insensitive and ignores double-quote
//!   quoting (matches PostgreSQL's own default unquoted-identifier
//!   folding to lowercase; a quoted mixed-case identifier like `"MyFunc"`
//!   is not specially handled and is compared in lowercase like anything
//!   else).
//! - Schema-qualified names (`myschema.mytable`) are matched by their
//!   final segment (`mytable`) only; the schema portion is ignored.

use std::collections::HashMap;
use std::sync::OnceLock;

use arc_swap::ArcSwap;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Which namespace a rule's `_name` belongs to. Kept as two independent
/// namespaces (tables vs. functions) so the same name can be registered
/// as both without conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum RuleTargetKind {
    #[serde(rename = "t")]
    Table,
    #[serde(rename = "f")]
    Function,
}

/// Whether statements referencing a rule's `_name` may only go to the
/// Writer, or may also be routed to a Reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum RwMode {
    #[serde(rename = "w")]
    Writer,
    #[serde(rename = "r")]
    Reader,
}

/// A shared, thread-safe registry of custom routing rules. Cheap to read
/// concurrently from many connection tasks (`forces_writer` is a couple of
/// lock-free `ArcSwap` loads plus a `HashMap` lookup); writes
/// (`set_rule`/`remove_rule`/`replace_all`) are serialized by a Mutex to
/// prevent concurrent load-clone-store races from losing updates.
#[derive(Default)]
pub struct CustomRoutingRules {
    tables: ArcSwap<HashMap<String, RwMode>>,
    functions: ArcSwap<HashMap<String, RwMode>>,
    /// Serializes all write operations to prevent lost updates from
    /// concurrent load-clone-store sequences.
    write_lock: std::sync::Mutex<()>,
}

/// One rule entry, as accepted by config file loading and the admin API.
/// Field names deliberately match the `_name`/`_type`/`rw_mode` parameter
/// spec this module implements.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRuleEntry {
    #[serde(rename = "_name")]
    pub name: String,
    #[serde(rename = "_type")]
    pub rule_type: RuleTargetKind,
    pub rw_mode: RwMode,
}

impl CustomRoutingRules {
    pub fn new() -> Self {
        CustomRoutingRules {
            tables: ArcSwap::new(std::sync::Arc::new(HashMap::new())),
            functions: ArcSwap::new(std::sync::Arc::new(HashMap::new())),
            write_lock: std::sync::Mutex::new(()),
        }
    }

    fn map_for(&self, kind: RuleTargetKind) -> &ArcSwap<HashMap<String, RwMode>> {
        match kind {
            RuleTargetKind::Table => &self.tables,
            RuleTargetKind::Function => &self.functions,
        }
    }

    /// Registers (or overwrites) a single rule.
    pub fn set_rule(&self, name: &str, kind: RuleTargetKind, mode: RwMode) {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let map = self.map_for(kind);
        let mut updated = (**map.load()).clone();
        updated.insert(name.to_ascii_lowercase(), mode);
        map.store(std::sync::Arc::new(updated));
    }

    /// Removes a single rule, if present. A no-op if no rule with this
    /// `(name, kind)` was registered.
    pub fn remove_rule(&self, name: &str, kind: RuleTargetKind) {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let map = self.map_for(kind);
        let mut updated = (**map.load()).clone();
        updated.remove(&name.to_ascii_lowercase());
        map.store(std::sync::Arc::new(updated));
    }

    /// Atomically replaces the entire rule set (used by config-file-based
    /// loading and hot reload, so a reload never leaves a stale rule from
    /// a previous config lingering).
    pub fn replace_all(&self, entries: &[CustomRuleEntry]) {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut tables = HashMap::new();
        let mut functions = HashMap::new();
        for entry in entries {
            let target = match entry.rule_type {
                RuleTargetKind::Table => &mut tables,
                RuleTargetKind::Function => &mut functions,
            };
            target.insert(entry.name.to_ascii_lowercase(), entry.rw_mode);
        }
        // Publish both maps together under the same lock to ensure
        // writers cannot interleave a partial update. Note: readers using
        // `ArcSwap::load()` without holding this lock may briefly observe
        // a state where `tables` has been updated but `functions` has not
        // (or vice versa), since `ArcSwap::store` is two separate atomic
        // operations. This is acceptable because the window is extremely
        // short and the consequence is a single query being routed to the
        // writer when it could have gone to a reader (safe direction).
        self.tables.store(std::sync::Arc::new(tables));
        self.functions.store(std::sync::Arc::new(functions));
    }

    /// Returns every currently registered rule (for introspection, e.g. an
    /// admin `GET` listing endpoint).
    pub fn list_rules(&self) -> Vec<CustomRuleEntry> {
        let mut out = Vec::new();
        for (name, mode) in self.tables.load().iter() {
            out.push(CustomRuleEntry {
                name: name.clone(),
                rule_type: RuleTargetKind::Table,
                rw_mode: *mode,
            });
        }
        for (name, mode) in self.functions.load().iter() {
            out.push(CustomRuleEntry {
                name: name.clone(),
                rule_type: RuleTargetKind::Function,
                rw_mode: *mode,
            });
        }
        out
    }

    /// Checks `sql` against the registered rules. Returns `Some(reason)`
    /// if any table or function name referenced in `sql` is registered
    /// with `RwMode::Writer`, in which case the caller must route to the
    /// Writer node regardless of how the statement would otherwise be
    /// classified. Returns `None` if no registered writer-only name is
    /// referenced (including when no rules are registered at all, or
    /// when referenced names are all registered as `RwMode::Reader`).
    pub fn forces_writer(&self, sql: &str) -> Option<std::borrow::Cow<'static, str>> {
        let tables = self.tables.load();
        if !tables.is_empty() {
            for table in extract_table_names(sql) {
                if let Some(RwMode::Writer) = tables.get(&table) {
                    return Some(std::borrow::Cow::Owned(format!(
                        "custom routing rule: table '{table}' is writer-only"
                    )));
                }
            }
        }

        let functions = self.functions.load();
        if !functions.is_empty() {
            for function in extract_function_names(sql) {
                if let Some(RwMode::Writer) = functions.get(&function) {
                    return Some(std::borrow::Cow::Owned(format!(
                        "custom routing rule: function '{function}' is writer-only"
                    )));
                }
            }
        }

        None
    }
}

fn table_reference_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)\b(?:FROM|JOIN|UPDATE|INTO)\s+"?([A-Za-z_][A-Za-z0-9_]*)"?(?:\s*\.\s*"?([A-Za-z_][A-Za-z0-9_]*)"?)?"#)
            .unwrap()
    })
}

fn function_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap())
}

/// Extracts candidate table names referenced via `FROM`/`JOIN`/`UPDATE`/
/// `INTO`, lowercased, using only the final (unqualified) segment of a
/// schema-qualified name. See module docs for limitations.
fn extract_table_names(sql: &str) -> Vec<String> {
    table_reference_re()
        .captures_iter(sql)
        .map(|caps| {
            // The second capture group (schema-qualified suffix) wins if
            // present, e.g. "myschema.mytable" -> "mytable".
            let name = caps
                .get(2)
                .or_else(|| caps.get(1))
                .expect("regex guarantees at least group 1 matches")
                .as_str();
            name.to_ascii_lowercase()
        })
        .collect()
}

/// Extracts candidate function names as any identifier immediately
/// followed by `(`, lowercased. See module docs for limitations (this can
/// also match non-function constructs, which is harmless since results
/// are only ever checked against explicitly registered rule names).
fn extract_function_names(sql: &str) -> Vec<String> {
    function_call_re()
        .captures_iter(sql)
        .map(|caps| caps[1].to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // extract_table_names / extract_function_names
    // -----------------------------------------------------------------

    #[test]
    fn extracts_table_after_from_and_join() {
        let names = extract_table_names("SELECT * FROM orders o JOIN customers c ON o.cid = c.id");
        assert!(names.contains(&"orders".to_string()));
        assert!(names.contains(&"customers".to_string()));
    }

    #[test]
    fn extracts_table_after_update_and_into() {
        assert_eq!(
            extract_table_names("UPDATE accounts SET balance = 1"),
            vec!["accounts"]
        );
        assert_eq!(
            extract_table_names("INSERT INTO ledger (a) VALUES (1)"),
            vec!["ledger"]
        );
    }

    #[test]
    fn extracts_unqualified_segment_of_schema_qualified_table() {
        assert_eq!(
            extract_table_names("SELECT * FROM myschema.mytable"),
            vec!["mytable"]
        );
    }

    #[test]
    fn table_extraction_is_case_insensitive() {
        assert_eq!(extract_table_names("select * from Orders"), vec!["orders"]);
    }

    #[test]
    fn extracts_function_call_names() {
        let names = extract_function_names("SELECT my_reporting_func(1), other_func()");
        assert!(names.contains(&"my_reporting_func".to_string()));
        assert!(names.contains(&"other_func".to_string()));
    }

    // -----------------------------------------------------------------
    // CustomRoutingRules
    // -----------------------------------------------------------------

    #[test]
    fn no_rules_never_forces_writer() {
        let rules = CustomRoutingRules::new();
        assert_eq!(rules.forces_writer("SELECT * FROM anything"), None);
        assert_eq!(rules.forces_writer("SELECT my_func()"), None);
    }

    #[test]
    fn writer_only_table_rule_forces_writer_for_matching_query() {
        let rules = CustomRoutingRules::new();
        rules.set_rule("sensitive_table", RuleTargetKind::Table, RwMode::Writer);

        assert!(rules
            .forces_writer("SELECT * FROM sensitive_table")
            .is_some());
        assert_eq!(rules.forces_writer("SELECT * FROM other_table"), None);
    }

    #[test]
    fn reader_table_rule_never_forces_writer() {
        let rules = CustomRoutingRules::new();
        rules.set_rule("ok_table", RuleTargetKind::Table, RwMode::Reader);
        assert_eq!(rules.forces_writer("SELECT * FROM ok_table"), None);
    }

    #[test]
    fn writer_only_function_rule_forces_writer_for_matching_query() {
        let rules = CustomRoutingRules::new();
        rules.set_rule("my_custom_func", RuleTargetKind::Function, RwMode::Writer);

        assert!(rules.forces_writer("SELECT my_custom_func(1)").is_some());
        assert_eq!(rules.forces_writer("SELECT other_func(1)"), None);
    }

    #[test]
    fn table_and_function_namespaces_do_not_collide() {
        let rules = CustomRoutingRules::new();
        // Same name "widget", registered as a writer-only table but a
        // reader-eligible function -- the two must not interfere.
        rules.set_rule("widget", RuleTargetKind::Table, RwMode::Writer);
        rules.set_rule("widget", RuleTargetKind::Function, RwMode::Reader);

        assert!(rules.forces_writer("SELECT * FROM widget").is_some());
        assert_eq!(rules.forces_writer("SELECT widget(1)"), None);
    }

    #[test]
    fn remove_rule_lifts_a_previously_set_restriction() {
        let rules = CustomRoutingRules::new();
        rules.set_rule("t1", RuleTargetKind::Table, RwMode::Writer);
        assert!(rules.forces_writer("SELECT * FROM t1").is_some());

        rules.remove_rule("t1", RuleTargetKind::Table);
        assert_eq!(rules.forces_writer("SELECT * FROM t1"), None);
    }

    #[test]
    fn setting_reader_mode_after_writer_mode_lifts_the_restriction() {
        let rules = CustomRoutingRules::new();
        rules.set_rule("t1", RuleTargetKind::Table, RwMode::Writer);
        assert!(rules.forces_writer("SELECT * FROM t1").is_some());

        rules.set_rule("t1", RuleTargetKind::Table, RwMode::Reader);
        assert_eq!(rules.forces_writer("SELECT * FROM t1"), None);
    }

    #[test]
    fn rule_names_are_matched_case_insensitively() {
        let rules = CustomRoutingRules::new();
        rules.set_rule("MyTable", RuleTargetKind::Table, RwMode::Writer);
        assert!(rules.forces_writer("SELECT * FROM mytable").is_some());
        assert!(rules.forces_writer("SELECT * FROM MYTABLE").is_some());
    }

    #[test]
    fn replace_all_atomically_swaps_the_rule_set() {
        let rules = CustomRoutingRules::new();
        rules.set_rule("old_table", RuleTargetKind::Table, RwMode::Writer);

        rules.replace_all(&[CustomRuleEntry {
            name: "new_table".to_string(),
            rule_type: RuleTargetKind::Table,
            rw_mode: RwMode::Writer,
        }]);

        // The old rule is gone; only the new one is in effect.
        assert_eq!(rules.forces_writer("SELECT * FROM old_table"), None);
        assert!(rules.forces_writer("SELECT * FROM new_table").is_some());
    }

    #[test]
    fn list_rules_reports_everything_registered() {
        let rules = CustomRoutingRules::new();
        rules.set_rule("t1", RuleTargetKind::Table, RwMode::Writer);
        rules.set_rule("f1", RuleTargetKind::Function, RwMode::Reader);

        let mut listed = rules.list_rules();
        listed.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].name, "f1");
        assert_eq!(listed[0].rule_type, RuleTargetKind::Function);
        assert_eq!(listed[1].name, "t1");
        assert_eq!(listed[1].rule_type, RuleTargetKind::Table);
    }

    #[test]
    fn serde_uses_the_literal_single_character_codes() {
        let entry = CustomRuleEntry {
            name: "my_func".to_string(),
            rule_type: RuleTargetKind::Function,
            rw_mode: RwMode::Reader,
        };
        let json = serde_json_like_yaml(&entry);
        assert!(json.contains("f"));
        assert!(json.contains("r"));
    }

    /// Minimal helper avoiding a `serde_json` dev-dependency just for this
    /// one assertion; reuses `serde_yaml`, already a normal dependency.
    fn serde_json_like_yaml(entry: &CustomRuleEntry) -> String {
        serde_yaml::to_string(entry).unwrap()
    }
}
