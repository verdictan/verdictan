// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use crate::gateway::ground_truth::{authority_rank, compute_verification_hash, SourceType};
use chrono::{DateTime, Utc};
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::Path;
use tracing::warn;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GraphEntityKey {
    pub entity_type: String,
    pub entity_name: String,
}

impl GraphEntityKey {
    pub fn new(entity_type: impl Into<String>, entity_name: impl Into<String>) -> Self {
        Self {
            entity_type: entity_type.into(),
            entity_name: entity_name.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphNodeCandidate {
    pub key: GraphEntityKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub properties: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphEdgeCandidate {
    pub source: GraphEntityKey,
    pub target: GraphEntityKey,
    pub relationship_type: String,
    pub properties: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GraphExtraction {
    pub nodes: Vec<GraphNodeCandidate>,
    pub edges: Vec<GraphEdgeCandidate>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SourceFileGraphInput {
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub path: String,
    pub contents: String,
    pub captured_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolResultGraphInput {
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub tool_name: String,
    pub arguments: Value,
    pub output: Value,
    pub captured_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphNodeUpsert {
    pub entity_type: String,
    pub entity_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub properties: Value,
    pub source_type: String,
    pub source_ref: Value,
    pub verification_hash: String,
    pub confidence_score: f64,
    pub last_verified: String,
    pub authority_rank: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_addressable_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphEdgeUpsert {
    pub source_entity_type: String,
    pub source_entity_name: String,
    pub target_entity_type: String,
    pub target_entity_name: String,
    pub relationship_type: String,
    pub properties: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub source_type: String,
    pub source_ref: Value,
    pub verification_hash: String,
    pub confidence_score: f64,
    pub last_verified: String,
    pub authority_rank: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_addressable_ref: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GraphUpsertPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub nodes: Vec<GraphNodeUpsert>,
    pub edges: Vec<GraphEdgeUpsert>,
    pub warnings: Vec<String>,
}

pub fn extract_from_source_file(input: &SourceFileGraphInput) -> GraphExtraction {
    let mut accumulator = GraphAccumulator::new(input.repo.clone(), input.branch.clone());
    let extension = Path::new(&input.path)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    let supported = match extension.as_deref() {
        Some("rs") => {
            parse_rust_source(&input.path, &input.contents, &mut accumulator);
            true
        }
        Some("ts") | Some("tsx") | Some("js") | Some("jsx") => {
            parse_typescript_source(&input.path, &input.contents, &mut accumulator);
            true
        }
        Some("py") => {
            parse_python_source(&input.path, &input.contents, &mut accumulator);
            true
        }
        Some("sql") => {
            parse_sql_source(&input.path, &input.contents, &mut accumulator);
            true
        }
        _ => {
            accumulator.warn(format!(
                "graph_populator skipped unsupported source file {}",
                input.path
            ));
            false
        }
    };

    if supported && accumulator.is_empty() {
        accumulator.warn(format!(
            "graph_populator extracted no graph entities from {}",
            input.path
        ));
    }

    accumulator.finish()
}

pub fn prepare_source_file_upsert_payload(input: &SourceFileGraphInput) -> GraphUpsertPayload {
    let extraction = extract_from_source_file(input);
    let source_ref = json!({
        "reference_kind": "repository_file",
        "repo": input.repo,
        "branch": input.branch,
        "commit": input.commit,
        "path": input.path,
    });
    let content_addressable_ref = input
        .commit
        .as_ref()
        .map(|commit| format!("{commit}:{}", input.path));
    prepare_upsert_payload(
        extraction,
        input.repo.clone(),
        input.branch.clone(),
        SourceType::Code,
        source_ref,
        compute_verification_hash(input.contents.as_bytes()),
        input.captured_at,
        content_addressable_ref,
    )
}

pub fn extract_from_tool_result(input: &ToolResultGraphInput) -> GraphExtraction {
    let mut accumulator = GraphAccumulator::new(input.repo.clone(), input.branch.clone());
    if extract_schema_from_json(&input.output, &mut accumulator) {
        return accumulator.finish();
    }

    if let Some(text) = extract_schema_text(&input.output) {
        let lowered = text.to_ascii_lowercase();
        if lowered.contains("create table") {
            parse_sql_source(&input.tool_name, text, &mut accumulator);
        } else if text.trim_start().starts_with("Table \"") {
            parse_postgres_describe_output(text, &mut accumulator);
        } else {
            accumulator.warn(format!(
                "graph_populator skipped non-schema tool output from {}",
                input.tool_name
            ));
        }
    } else {
        accumulator.warn(format!(
            "graph_populator skipped unsupported tool output from {}",
            input.tool_name
        ));
    }

    if accumulator.is_empty() {
        accumulator.warn(format!(
            "graph_populator extracted no graph entities from tool output {}",
            input.tool_name
        ));
    }

    accumulator.finish()
}

pub fn prepare_tool_result_upsert_payload(input: &ToolResultGraphInput) -> GraphUpsertPayload {
    let extraction = extract_from_tool_result(input);
    let source_ref = json!({
        "reference_kind": "tool_result",
        "tool_name": input.tool_name,
        "arguments": input.arguments,
        "captured_at": input.captured_at.to_rfc3339(),
        "repo": input.repo,
        "branch": input.branch,
    });
    prepare_upsert_payload(
        extraction,
        input.repo.clone(),
        input.branch.clone(),
        SourceType::Database,
        source_ref,
        compute_verification_hash(&tool_output_bytes(&input.output)),
        input.captured_at,
        None,
    )
}

fn prepare_upsert_payload(
    extraction: GraphExtraction,
    repo: Option<String>,
    branch: Option<String>,
    source_type: SourceType,
    source_ref: Value,
    verification_hash: String,
    captured_at: DateTime<Utc>,
    content_addressable_ref: Option<String>,
) -> GraphUpsertPayload {
    let authority = authority_rank(Some(source_type), Some("verified"), Some(1.0));
    let last_verified = captured_at.to_rfc3339();
    let source_type_string = source_type.as_str().to_string();

    GraphUpsertPayload {
        repo: repo.clone(),
        branch: branch.clone(),
        nodes: extraction
            .nodes
            .into_iter()
            .map(|node| GraphNodeUpsert {
                entity_type: node.key.entity_type,
                entity_name: node.key.entity_name,
                repo: node.repo,
                branch: node.branch,
                properties: node.properties,
                source_type: source_type_string.clone(),
                source_ref: source_ref.clone(),
                verification_hash: verification_hash.clone(),
                confidence_score: 1.0,
                last_verified: last_verified.clone(),
                authority_rank: authority,
                content_addressable_ref: content_addressable_ref.clone(),
            })
            .collect(),
        edges: extraction
            .edges
            .into_iter()
            .map(|edge| GraphEdgeUpsert {
                source_entity_type: edge.source.entity_type,
                source_entity_name: edge.source.entity_name,
                target_entity_type: edge.target.entity_type,
                target_entity_name: edge.target.entity_name,
                relationship_type: edge.relationship_type,
                properties: edge.properties,
                repo: repo.clone(),
                branch: branch.clone(),
                source_type: source_type_string.clone(),
                source_ref: source_ref.clone(),
                verification_hash: verification_hash.clone(),
                confidence_score: 1.0,
                last_verified: last_verified.clone(),
                authority_rank: authority,
                content_addressable_ref: content_addressable_ref.clone(),
            })
            .collect(),
        warnings: extraction.warnings,
    }
}

struct GraphAccumulator {
    repo: Option<String>,
    branch: Option<String>,
    nodes: BTreeMap<GraphEntityKey, Map<String, Value>>,
    edges: BTreeMap<(GraphEntityKey, GraphEntityKey, String), Map<String, Value>>,
    warnings: Vec<String>,
}

impl GraphAccumulator {
    fn new(repo: Option<String>, branch: Option<String>) -> Self {
        Self {
            repo,
            branch,
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }

    fn add_node(&mut self, key: GraphEntityKey, properties: Map<String, Value>) {
        let entry = self.nodes.entry(key).or_default();
        merge_properties(entry, properties);
    }

    fn add_edge(
        &mut self,
        source: GraphEntityKey,
        target: GraphEntityKey,
        relationship_type: impl Into<String>,
        properties: Map<String, Value>,
    ) {
        let relationship_type = relationship_type.into();
        let entry = self
            .edges
            .entry((source, target, relationship_type))
            .or_default();
        merge_properties(entry, properties);
    }

    fn warn(&mut self, message: String) {
        warn!("{message}");
        self.warnings.push(message);
    }

    fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.edges.is_empty()
    }

    fn finish(self) -> GraphExtraction {
        let GraphAccumulator {
            repo,
            branch,
            nodes,
            edges,
            warnings,
        } = self;
        GraphExtraction {
            nodes: nodes
                .into_iter()
                .map(|(key, properties)| GraphNodeCandidate {
                    key,
                    repo: repo.clone(),
                    branch: branch.clone(),
                    properties: Value::Object(properties),
                })
                .collect(),
            edges: edges
                .into_iter()
                .map(
                    |((source, target, relationship_type), properties)| GraphEdgeCandidate {
                        source,
                        target,
                        relationship_type,
                        properties: Value::Object(properties),
                    },
                )
                .collect(),
            warnings,
        }
    }
}

fn parse_rust_source(path: &str, contents: &str, accumulator: &mut GraphAccumulator) {
    let module_key = GraphEntityKey::new("module", path.to_string());
    accumulator.add_node(
        module_key.clone(),
        object_from_value(json!({
            "language": "rust",
            "path": path,
        })),
    );

    let import_regex = Regex::new(r"^(?:pub(?:\([^)]*\))?\s+)?use\s+([^;]+);").ok();
    let function_regex =
        Regex::new(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
            .ok();
    let struct_regex =
        Regex::new(r"^(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)").ok();
    let enum_regex = Regex::new(r"^(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*)").ok();
    let trait_regex =
        Regex::new(r"^(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_][A-Za-z0-9_]*)").ok();

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if let Some(target) = captures_first(&import_regex, line) {
            let imported_module = GraphEntityKey::new("module", target.clone());
            accumulator.add_node(
                imported_module.clone(),
                object_from_value(json!({
                    "language": "rust",
                    "module": target,
                })),
            );
            accumulator.add_edge(
                module_key.clone(),
                imported_module,
                "imports",
                object_from_value(json!({
                    "line": line_index + 1,
                })),
            );
        }

        if let Some(name) = captures_first(&function_regex, line) {
            accumulator.add_node(
                GraphEntityKey::new("function", name),
                object_from_value(json!({
                    "language": "rust",
                    "path": path,
                })),
            );
        }
        if let Some(name) = captures_first(&struct_regex, line) {
            accumulator.add_node(
                GraphEntityKey::new("type", name),
                object_from_value(json!({
                    "kind": "struct",
                    "language": "rust",
                    "path": path,
                })),
            );
        }
        if let Some(name) = captures_first(&enum_regex, line) {
            accumulator.add_node(
                GraphEntityKey::new("type", name),
                object_from_value(json!({
                    "kind": "enum",
                    "language": "rust",
                    "path": path,
                })),
            );
        }
        if let Some(name) = captures_first(&trait_regex, line) {
            accumulator.add_node(
                GraphEntityKey::new("type", name),
                object_from_value(json!({
                    "kind": "trait",
                    "language": "rust",
                    "path": path,
                })),
            );
        }
    }
}

fn parse_typescript_source(path: &str, contents: &str, accumulator: &mut GraphAccumulator) {
    let module_key = GraphEntityKey::new("module", path.to_string());
    accumulator.add_node(
        module_key.clone(),
        object_from_value(json!({
            "language": "typescript",
            "path": path,
        })),
    );

    let import_regex = Regex::new(r#"^import\s+.*?\s+from\s+["']([^"']+)["']"#).ok();
    let side_effect_import_regex = Regex::new(r#"^import\s+["']([^"']+)["']"#).ok();
    let function_regex =
        Regex::new(r"^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(").ok();
    let class_regex = Regex::new(r"^(?:export\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)").ok();
    let interface_regex = Regex::new(r"^(?:export\s+)?interface\s+([A-Za-z_][A-Za-z0-9_]*)").ok();
    let type_alias_regex = Regex::new(r"^(?:export\s+)?type\s+([A-Za-z_][A-Za-z0-9_]*)\s*=").ok();
    let endpoint_regex = Regex::new(
        r#"\b(?:router|app)\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']\s*,\s*([A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .ok();

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        let imported = captures_first(&import_regex, line)
            .or_else(|| captures_first(&side_effect_import_regex, line));
        if let Some(target) = imported {
            let imported_module = GraphEntityKey::new("module", target.clone());
            accumulator.add_node(
                imported_module.clone(),
                object_from_value(json!({
                    "language": "typescript",
                    "module": target,
                })),
            );
            accumulator.add_edge(
                module_key.clone(),
                imported_module,
                "imports",
                object_from_value(json!({
                    "line": line_index + 1,
                })),
            );
        }

        if let Some(name) = captures_first(&function_regex, line) {
            accumulator.add_node(
                GraphEntityKey::new("function", name),
                object_from_value(json!({
                    "language": "typescript",
                    "path": path,
                })),
            );
        }
        if let Some(name) = captures_first(&class_regex, line) {
            accumulator.add_node(
                GraphEntityKey::new("type", name),
                object_from_value(json!({
                    "kind": "class",
                    "language": "typescript",
                    "path": path,
                })),
            );
        }
        if let Some(name) = captures_first(&interface_regex, line) {
            accumulator.add_node(
                GraphEntityKey::new("type", name),
                object_from_value(json!({
                    "kind": "interface",
                    "language": "typescript",
                    "path": path,
                })),
            );
        }
        if let Some(name) = captures_first(&type_alias_regex, line) {
            accumulator.add_node(
                GraphEntityKey::new("type", name),
                object_from_value(json!({
                    "kind": "type_alias",
                    "language": "typescript",
                    "path": path,
                })),
            );
        }
        if let Some(captures) = captures(&endpoint_regex, line) {
            let method = captures
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let route = captures
                .get(2)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let handler = captures
                .get(3)
                .map(|value| value.as_str())
                .unwrap_or_default();
            if !method.is_empty() && !route.is_empty() && !handler.is_empty() {
                let endpoint_key =
                    GraphEntityKey::new("endpoint", format!("{} {}", method.to_uppercase(), route));
                let function_key = GraphEntityKey::new("function", handler.to_string());
                accumulator.add_node(
                    endpoint_key.clone(),
                    object_from_value(json!({
                        "method": method.to_uppercase(),
                        "path": route,
                        "language": "typescript",
                    })),
                );
                accumulator.add_edge(
                    endpoint_key,
                    function_key,
                    "endpoint_uses_handler",
                    object_from_value(json!({
                        "line": line_index + 1,
                    })),
                );
            }
        }
    }
}

fn parse_python_source(path: &str, contents: &str, accumulator: &mut GraphAccumulator) {
    let module_key = GraphEntityKey::new("module", path.to_string());
    accumulator.add_node(
        module_key.clone(),
        object_from_value(json!({
            "language": "python",
            "path": path,
        })),
    );

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if let Some(imported) = parse_python_import_target(line) {
            let imported_module = GraphEntityKey::new("module", imported.clone());
            accumulator.add_node(
                imported_module.clone(),
                object_from_value(json!({
                    "language": "python",
                    "module": imported,
                })),
            );
            accumulator.add_edge(
                module_key.clone(),
                imported_module,
                "imports",
                object_from_value(json!({
                    "line": line_index + 1,
                })),
            );
        }

        if let Some(name) = parse_python_definition(line, "def ") {
            accumulator.add_node(
                GraphEntityKey::new("function", name),
                object_from_value(json!({
                    "language": "python",
                    "path": path,
                })),
            );
        }
        if let Some(name) = parse_python_definition(line, "class ") {
            accumulator.add_node(
                GraphEntityKey::new("type", name),
                object_from_value(json!({
                    "kind": "class",
                    "language": "python",
                    "path": path,
                })),
            );
        }
    }
}

fn parse_sql_source(path: &str, contents: &str, accumulator: &mut GraphAccumulator) {
    let mut current_block = Vec::new();
    let mut inside_create_table = false;

    for raw_line in contents.lines() {
        let trimmed = raw_line.trim();
        let lowered = trimmed.to_ascii_lowercase();
        if lowered.starts_with("create table") {
            inside_create_table = true;
            current_block.clear();
        }
        if inside_create_table {
            current_block.push(trimmed.to_string());
            if trimmed.ends_with(");") || trimmed == ")" {
                parse_create_table_block(path, &current_block.join("\n"), accumulator);
                current_block.clear();
                inside_create_table = false;
            }
        }
    }
}

fn parse_postgres_describe_output(text: &str, accumulator: &mut GraphAccumulator) {
    let mut table_name: Option<String> = None;
    let mut in_columns = false;
    let mut in_foreign_keys = false;

    for raw_line in text.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.starts_with("Table \"") {
            table_name = parse_quoted_table_name(trimmed);
            if let Some(name) = table_name.clone() {
                let (schema, simple_name) = split_schema_and_name(&name);
                accumulator.add_node(
                    GraphEntityKey::new("table", name.clone()),
                    object_from_value(json!({
                        "schema": schema,
                        "table": simple_name,
                    })),
                );
            }
            continue;
        }
        if trimmed.starts_with("Column |") || trimmed.starts_with("Column  |") {
            in_columns = true;
            in_foreign_keys = false;
            continue;
        }
        if trimmed.starts_with("Foreign-key constraints:") {
            in_columns = false;
            in_foreign_keys = true;
            continue;
        }
        if trimmed.starts_with("Indexes:")
            || trimmed.starts_with("Check constraints:")
            || trimmed.starts_with("Referenced by:")
        {
            in_columns = false;
            in_foreign_keys = false;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("---") {
            continue;
        }

        if in_columns {
            if let Some(table_name) = table_name.clone() {
                parse_postgres_column_row(&table_name, trimmed, accumulator);
            }
            continue;
        }
        if in_foreign_keys {
            if let Some(table_name) = table_name.clone() {
                parse_postgres_foreign_key_row(&table_name, trimmed, accumulator);
            }
        }
    }
}

fn parse_create_table_block(_path: &str, block: &str, accumulator: &mut GraphAccumulator) {
    let mut lines = block.lines();
    let Some(header) = lines.next() else {
        return;
    };
    let Some(table_name) = parse_create_table_name(header) else {
        return;
    };

    let (schema, simple_name) = split_schema_and_name(&table_name);
    let table_key = GraphEntityKey::new("table", table_name.clone());
    accumulator.add_node(
        table_key.clone(),
        object_from_value(json!({
            "schema": schema,
            "table": simple_name,
        })),
    );

    for raw_line in lines {
        let trimmed = raw_line
            .trim()
            .trim_end_matches(',')
            .trim_end_matches(';')
            .trim();
        if trimmed.is_empty() || trimmed == ")" {
            continue;
        }

        let lowered = trimmed.to_ascii_lowercase();
        if lowered.starts_with("primary key")
            || lowered.starts_with("unique")
            || lowered.starts_with("check")
        {
            continue;
        }
        if lowered.starts_with("constraint") || lowered.starts_with("foreign key") {
            parse_sql_foreign_key_line(&table_name, trimmed, accumulator);
            continue;
        }

        let Some(column_name) = parse_column_name(trimmed) else {
            continue;
        };
        let data_type = parse_column_type(trimmed);
        let column_key = GraphEntityKey::new("column", format!("{table_name}.{column_name}"));
        accumulator.add_node(
            column_key.clone(),
            object_from_value(json!({
                "table": table_name,
                "column": column_name,
                "data_type": data_type,
            })),
        );
        accumulator.add_edge(
            table_key.clone(),
            column_key.clone(),
            "table_has_column",
            object_from_value(json!({
                "column": column_name,
            })),
        );

        if let Some((referenced_table, referenced_column)) = parse_reference_target(trimmed) {
            let target_key =
                GraphEntityKey::new("column", format!("{referenced_table}.{referenced_column}"));
            accumulator.add_node(
                GraphEntityKey::new("table", referenced_table.clone()),
                object_from_value(json!({
                    "table": referenced_table,
                })),
            );
            accumulator.add_node(
                target_key.clone(),
                object_from_value(json!({
                    "table": referenced_table,
                    "column": referenced_column,
                })),
            );
            accumulator.add_edge(
                column_key,
                target_key,
                "column_references",
                object_from_value(json!({
                    "source_column": column_name,
                })),
            );
        }
    }
}

fn parse_postgres_column_row(table_name: &str, row: &str, accumulator: &mut GraphAccumulator) {
    let mut parts = row.split('|').map(str::trim);
    let Some(column_name) = parts.next().and_then(non_empty_owned) else {
        return;
    };
    if column_name == "Column" {
        return;
    }
    let data_type = parts.next().and_then(non_empty_owned);
    let column_key = GraphEntityKey::new("column", format!("{table_name}.{column_name}"));
    accumulator.add_node(
        column_key.clone(),
        object_from_value(json!({
            "table": table_name,
            "column": column_name,
            "data_type": data_type,
        })),
    );
    accumulator.add_edge(
        GraphEntityKey::new("table", table_name.to_string()),
        column_key,
        "table_has_column",
        object_from_value(json!({
            "column": column_name,
        })),
    );
}

fn parse_postgres_foreign_key_row(table_name: &str, row: &str, accumulator: &mut GraphAccumulator) {
    let Some(source_column) = parse_foreign_key_source_column(row) else {
        return;
    };
    let Some((referenced_table, referenced_column)) = parse_reference_target(row) else {
        return;
    };
    let source_key = GraphEntityKey::new("column", format!("{table_name}.{source_column}"));
    let target_key =
        GraphEntityKey::new("column", format!("{referenced_table}.{referenced_column}"));
    accumulator.add_node(
        GraphEntityKey::new("table", referenced_table.clone()),
        object_from_value(json!({
            "table": referenced_table,
        })),
    );
    accumulator.add_node(
        target_key.clone(),
        object_from_value(json!({
            "table": referenced_table,
            "column": referenced_column,
        })),
    );
    accumulator.add_edge(
        source_key,
        target_key,
        "column_references",
        object_from_value(json!({
            "source_column": source_column,
        })),
    );
}

fn parse_sql_foreign_key_line(table_name: &str, line: &str, accumulator: &mut GraphAccumulator) {
    let Some(source_column) = parse_foreign_key_source_column(line) else {
        return;
    };
    let Some((referenced_table, referenced_column)) = parse_reference_target(line) else {
        return;
    };
    let source_key = GraphEntityKey::new("column", format!("{table_name}.{source_column}"));
    let target_key =
        GraphEntityKey::new("column", format!("{referenced_table}.{referenced_column}"));
    accumulator.add_node(
        GraphEntityKey::new("table", referenced_table.clone()),
        object_from_value(json!({
            "table": referenced_table,
        })),
    );
    accumulator.add_node(
        target_key.clone(),
        object_from_value(json!({
            "table": referenced_table,
            "column": referenced_column,
        })),
    );
    accumulator.add_edge(
        source_key,
        target_key,
        "column_references",
        object_from_value(json!({
            "source_column": source_column,
        })),
    );
}

fn extract_schema_from_json(value: &Value, accumulator: &mut GraphAccumulator) -> bool {
    if let Some(tables) = value.get("tables").and_then(Value::as_array) {
        for table in tables {
            extract_table_from_json(table, accumulator);
        }
        return true;
    }

    let has_columns = value.get("columns").and_then(Value::as_array).is_some();
    let has_table_name = json_string_any(value, &["table", "table_name", "name"]).is_some();
    if has_columns && has_table_name {
        extract_table_from_json(value, accumulator);
        return true;
    }

    false
}

fn extract_table_from_json(value: &Value, accumulator: &mut GraphAccumulator) {
    let Some(base_table_name) = json_string_any(value, &["table", "table_name", "name"]) else {
        return;
    };
    let table_name = if base_table_name.contains('.') {
        base_table_name.clone()
    } else if let Some(schema) = value.get("schema").and_then(Value::as_str) {
        format!("{}.{}", normalize_identifier(schema), base_table_name)
    } else {
        base_table_name.clone()
    };
    let (schema, simple_name) = split_schema_and_name(&table_name);
    let table_key = GraphEntityKey::new("table", table_name.clone());
    accumulator.add_node(
        table_key.clone(),
        object_from_value(json!({
            "schema": schema,
            "table": simple_name,
        })),
    );

    if let Some(columns) = value.get("columns").and_then(Value::as_array) {
        for column in columns {
            let Some(column_name) = json_string_any(column, &["name", "column"]) else {
                continue;
            };
            let column_key = GraphEntityKey::new("column", format!("{table_name}.{column_name}"));
            accumulator.add_node(
                column_key.clone(),
                object_from_value(json!({
                    "table": table_name,
                    "column": column_name,
                    "data_type": json_string_any(column, &["type", "data_type"]),
                    "nullable": column.get("nullable").cloned().unwrap_or(Value::Null),
                })),
            );
            accumulator.add_edge(
                table_key.clone(),
                column_key.clone(),
                "table_has_column",
                object_from_value(json!({
                    "column": column_name,
                })),
            );
        }
    }

    if let Some(foreign_keys) = value.get("foreign_keys").and_then(Value::as_array) {
        for foreign_key in foreign_keys {
            let Some(source_column) =
                json_string_any(foreign_key, &["column", "source_column", "column_name"])
            else {
                continue;
            };
            let referenced_table =
                json_string_any(foreign_key, &["references_table", "target_table", "table"])
                    .or_else(|| {
                        foreign_key
                            .get("references")
                            .and_then(|nested| json_string_any(nested, &["table", "target_table"]))
                    });
            let referenced_column = json_string_any(
                foreign_key,
                &["references_column", "target_column", "column"],
            )
            .or_else(|| {
                foreign_key
                    .get("references")
                    .and_then(|nested| json_string_any(nested, &["column", "target_column"]))
            });

            let (Some(referenced_table), Some(referenced_column)) =
                (referenced_table, referenced_column)
            else {
                continue;
            };

            let referenced_table = if referenced_table.contains('.') {
                referenced_table
            } else {
                normalize_identifier(&referenced_table)
            };
            let source_key = GraphEntityKey::new("column", format!("{table_name}.{source_column}"));
            let target_key =
                GraphEntityKey::new("column", format!("{referenced_table}.{referenced_column}"));
            accumulator.add_node(
                GraphEntityKey::new("table", referenced_table.clone()),
                object_from_value(json!({
                    "table": referenced_table,
                })),
            );
            accumulator.add_node(
                target_key.clone(),
                object_from_value(json!({
                    "table": referenced_table,
                    "column": referenced_column,
                })),
            );
            accumulator.add_edge(
                source_key,
                target_key,
                "column_references",
                object_from_value(json!({
                    "source_column": source_column,
                })),
            );
        }
    }
}

fn extract_schema_text(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("ddl").and_then(Value::as_str))
        .or_else(|| value.get("schema").and_then(Value::as_str))
        .or_else(|| value.get("output").and_then(Value::as_str))
        .or_else(|| value.get("content").and_then(Value::as_str))
}

fn tool_output_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::String(text) => text.as_bytes().to_vec(),
        _ => canonicalize_json(value).to_string().into_bytes(),
    }
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(left, _)| *left);
            let mut normalized = Map::new();
            for (key, value) in entries {
                normalized.insert(key.clone(), canonicalize_json(value));
            }
            Value::Object(normalized)
        }
        _ => value.clone(),
    }
}

fn captures<'a>(regex: &'a Option<Regex>, value: &'a str) -> Option<regex_lite::Captures<'a>> {
    regex.as_ref().and_then(|regex| regex.captures(value))
}

fn captures_first(regex: &Option<Regex>, value: &str) -> Option<String> {
    captures(regex, value)
        .and_then(|captures| captures.get(1).map(|capture| capture.as_str().to_string()))
}

fn parse_python_import_target(line: &str) -> Option<String> {
    if let Some(rest) = line.strip_prefix("from ") {
        let module = rest.split_whitespace().next()?;
        return non_empty_owned(module);
    }
    if let Some(rest) = line.strip_prefix("import ") {
        let module = rest.split(',').next()?.trim();
        return non_empty_owned(module);
    }
    None
}

fn parse_python_definition(line: &str, prefix: &str) -> Option<String> {
    let rest = line.strip_prefix(prefix)?;
    let name = rest
        .split(['(', ':'])
        .next()
        .map(str::trim)
        .and_then(non_empty_owned)?;
    Some(name)
}

fn parse_create_table_name(header: &str) -> Option<String> {
    let lowered = header.to_ascii_lowercase();
    let start = lowered.find("create table")?;
    let mut name = header[start + "create table".len()..].trim();
    if name.to_ascii_lowercase().starts_with("if not exists") {
        name = name["if not exists".len()..].trim();
    }
    name = name.trim_end_matches('(').trim();
    non_empty_owned(normalize_identifier(name).as_str())
}

fn parse_quoted_table_name(line: &str) -> Option<String> {
    let first_quote = line.find('"')?;
    let rest = &line[first_quote + 1..];
    let second_quote = rest.find('"')?;
    non_empty_owned(&rest[..second_quote])
}

fn parse_column_name(line: &str) -> Option<String> {
    let name = line.split_whitespace().next()?;
    non_empty_owned(normalize_identifier(name).as_str())
}

fn parse_column_type(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let _ = parts.next()?;
    parts.next().and_then(non_empty_owned)
}

fn parse_foreign_key_source_column(line: &str) -> Option<String> {
    let lowered = line.to_ascii_lowercase();
    let index = lowered.find("foreign key")?;
    let rest = line[index + "foreign key".len()..].trim();
    let open_paren = rest.find('(')?;
    let after_open = &rest[open_paren + 1..];
    let close_paren = after_open.find(')')?;
    non_empty_owned(normalize_identifier(&after_open[..close_paren]).as_str())
}

fn parse_reference_target(line: &str) -> Option<(String, String)> {
    let lowered = line.to_ascii_lowercase();
    let index = lowered.find("references")?;
    let rest = line[index + "references".len()..].trim();
    let open_paren = rest.find('(')?;
    let table_name = normalize_identifier(&rest[..open_paren]);
    let after_open = &rest[open_paren + 1..];
    let close_paren = after_open.find(')')?;
    let column_name = normalize_identifier(&after_open[..close_paren]);
    Some((table_name, column_name))
}

fn split_schema_and_name(value: &str) -> (Option<String>, String) {
    match value.rsplit_once('.') {
        Some((schema, name)) => (
            non_empty_owned(normalize_identifier(schema).as_str()),
            normalize_identifier(name),
        ),
        None => (None, normalize_identifier(value)),
    }
}

fn json_string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .and_then(non_empty_owned)
}

fn normalize_identifier(value: &str) -> String {
    value
        .trim()
        .trim_matches(|character| matches!(character, '"' | '\'' | '`' | '[' | ']'))
        .trim_end_matches(',')
        .trim()
        .to_string()
}

fn non_empty_owned(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn merge_properties(target: &mut Map<String, Value>, incoming: Map<String, Value>) {
    for (key, value) in incoming {
        if matches!(target.get(&key), None | Some(Value::Null)) {
            target.insert(key, value);
        }
    }
}

fn object_from_value(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}
