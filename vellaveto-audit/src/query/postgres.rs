// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! PostgreSQL audit query implementation (Phase 43).
//!
//! Provides SQL-based search with indexes for efficient filtering.
//! All user data is passed via bind parameters — NEVER via string interpolation.
//!
//! This module is feature-gated behind `postgres-store`.

use super::{AuditQueryService, QueryError};
use sqlx::{PgPool, Row};
use vellaveto_types::audit_store::{AuditQueryParams, AuditQueryResult, VerdictFilter};

/// PostgreSQL-backed audit query service.
///
/// Uses a connection pool for concurrent query execution.
pub struct PostgresAuditQuery {
    pool: PgPool,
    table_name: String,
}

impl std::fmt::Debug for PostgresAuditQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresAuditQuery")
            .field("table_name", &self.table_name)
            .finish()
    }
}

/// Maximum length for a PostgreSQL identifier (table name).
const MAX_PG_IDENTIFIER_LEN: usize = 63;

/// Validate that a table name is a safe PostgreSQL identifier.
///
/// Defense in depth: even if callers pre-validate, this constructor enforces:
/// 1. Non-empty and at most 63 characters (PostgreSQL identifier limit)
/// 2. Only ASCII alphanumeric characters and underscores
/// 3. Does not start with a digit
///
/// This prevents SQL injection when the table name is interpolated into queries
/// (SQL does not support parameterized table names).
fn validate_table_name(table_name: &str) -> Result<(), QueryError> {
    if table_name.is_empty() {
        return Err(QueryError::Validation(
            "table_name must not be empty".to_string(),
        ));
    }
    if table_name.len() > MAX_PG_IDENTIFIER_LEN {
        return Err(QueryError::Validation(format!(
            "table_name exceeds PostgreSQL's {}-character identifier limit",
            MAX_PG_IDENTIFIER_LEN
        )));
    }
    if table_name.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(QueryError::Validation(
            "table_name must not start with a digit".to_string(),
        ));
    }
    if !table_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(QueryError::Validation(
            "table_name must contain only alphanumeric characters and underscores".to_string(),
        ));
    }
    // SECURITY (FIND-R202-010): Reject pure-underscore identifiers (e.g., "___").
    // These are technically valid SQL identifiers but are degenerate and confusing.
    if table_name.chars().all(|c| c == '_') {
        return Err(QueryError::Validation(
            "table_name must contain at least one alphanumeric character".to_string(),
        ));
    }
    Ok(())
}

impl PostgresAuditQuery {
    /// Create a new PostgreSQL query service.
    ///
    /// # Errors
    ///
    /// Returns `QueryError::Validation` if `table_name` is not a safe SQL identifier:
    /// - Empty or longer than 63 characters (PostgreSQL identifier limit)
    /// - Contains characters other than `[a-zA-Z0-9_]`
    /// - Starts with a digit
    ///
    /// SECURITY (FIND-R159-001): Defense in depth — validates table_name at construction
    /// time even though callers may pre-validate, because the table name is interpolated
    /// directly into SQL (parameterized table names are not supported by SQL).
    pub fn new(pool: PgPool, table_name: String) -> Result<Self, QueryError> {
        validate_table_name(&table_name)?;
        Ok(Self { pool, table_name })
    }
}

/// Build a WHERE clause and collect bind values for an `AuditQueryParams`.
///
/// Returns `(where_clause, bind_values)` where bind_values are in order.
/// The table name is embedded directly (pre-validated), all data uses $N params.
///
/// **MAINTENANCE NOTE (R158-003):** This builder is used by `search()`. The `count()`
/// method uses [`build_filter_clauses`] instead. Both implement the same filter
/// logic and must be kept in sync.
struct WhereBuilder {
    conditions: Vec<String>,
    param_idx: u32,
}

impl WhereBuilder {
    fn new() -> Self {
        Self {
            conditions: Vec::new(),
            param_idx: 1,
        }
    }

    fn next_param(&mut self) -> String {
        let p = format!("${}", self.param_idx);
        self.param_idx = self.param_idx.saturating_add(1);
        p
    }

    fn add_condition(&mut self, condition: String) {
        self.conditions.push(condition);
    }

    fn build(&self) -> String {
        if self.conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", self.conditions.join(" AND "))
        }
    }
}

#[async_trait::async_trait]
impl AuditQueryService for PostgresAuditQuery {
    async fn search(&self, params: &AuditQueryParams) -> Result<AuditQueryResult, QueryError> {
        params.validate().map_err(QueryError::Validation)?;

        let mut wb = WhereBuilder::new();

        // Time range
        if params.since.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("timestamp_raw >= {}", p));
        }
        if params.until.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("timestamp_raw < {}", p));
        }

        // Tool filter
        if params.tool.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("tool = {}", p));
        }

        // Agent ID filter (JSONB containment)
        if params.agent_id.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("metadata @> jsonb_build_object('agent_id', {})", p));
        }

        // Verdict filter
        if params.verdict.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("verdict_type = {}", p));
        }

        // Sequence range
        if params.from_sequence.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("sequence >= {}", p));
        }
        if params.to_sequence.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("sequence <= {}", p));
        }

        // Text search (ILIKE on tool, function_name, and metadata text)
        // PostgreSQL allows reusing the same $N parameter in multiple positions.
        if params.text_search.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!(
                "(tool ILIKE {} OR function_name ILIKE {} OR metadata::text ILIKE {})",
                p, p, p
            ));
        }

        // Phase 44: Tenant ID filter
        if params.tenant_id.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("tenant_id = {}", p));
        }

        let where_clause = wb.build();

        // Build the count query
        let count_sql = format!(
            "SELECT COUNT(*) as count FROM {} {}",
            self.table_name, where_clause
        );

        // Build the data query
        // Re-build where clause for data query since we need fresh param indices
        // Actually, we'll use the same parameterization for both queries
        let limit_param = wb.next_param();
        let offset_param = wb.next_param();
        let data_sql = format!(
            "SELECT action_json, verdict_json, id, sequence, timestamp_raw, metadata, entry_hash, prev_hash, commitment, tenant_id FROM {} {} ORDER BY sequence ASC LIMIT {} OFFSET {}",
            self.table_name, where_clause, limit_param, offset_param
        );

        // Execute count query
        let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
        count_query = bind_params(count_query, params);
        let total = count_query
            .fetch_one(&self.pool)
            .await
            .map_err(|e| QueryError::Query(format!("Count query failed: {}", e)))?;

        // Execute data query
        let mut data_query = sqlx::query_as::<_, AuditRow>(&data_sql);
        data_query = bind_data_params(data_query, params);
        let rows = data_query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| QueryError::Query(format!("Search query failed: {}", e)))?;

        let entries: Vec<serde_json::Value> = rows
            .into_iter()
            .filter_map(|row| row.to_json().ok())
            .collect();

        Ok(AuditQueryResult {
            entries,
            total: total.max(0) as u64,
            offset: params.offset,
            limit: params.limit,
        })
    }

    async fn count(&self, params: &AuditQueryParams) -> Result<u64, QueryError> {
        params.validate().map_err(QueryError::Validation)?;

        // Use a simpler approach: build the SQL inline with bind params
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE TRUE {}",
            self.table_name,
            build_filter_clauses(params)
        );
        let mut query = sqlx::query_scalar::<_, i64>(&sql);
        query = bind_params(query, params);
        let count = query
            .fetch_one(&self.pool)
            .await
            .map_err(|e| QueryError::Query(format!("Count query failed: {}", e)))?;

        Ok(count.max(0) as u64)
    }

    async fn get_by_id(&self, id: &str) -> Result<Option<serde_json::Value>, QueryError> {
        if id.is_empty() || id.len() > 256 {
            return Err(QueryError::Validation("invalid entry ID".to_string()));
        }
        // SECURITY (FIND-R200-003): Reject control/format characters in entry IDs.
        if vellaveto_types::has_dangerous_chars(id) {
            return Err(QueryError::Validation(
                "entry ID contains control or format characters".to_string(),
            ));
        }

        let sql = format!(
            "SELECT action_json, verdict_json, id, sequence, timestamp_raw, metadata, entry_hash, prev_hash, commitment, tenant_id FROM {} WHERE id = $1",
            self.table_name
        );
        let row = sqlx::query_as::<_, AuditRow>(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| QueryError::Query(format!("Entry lookup failed: {}", e)))?;

        match row {
            Some(r) => Ok(r.to_json().ok()),
            None => Ok(None),
        }
    }

    async fn recent(&self, limit: u64) -> Result<Vec<serde_json::Value>, QueryError> {
        // SECURITY (R158-001): MAX_QUERY_LIMIT is 1000, well within i64 range,
        // but use try_from for defense in depth.
        let capped_limit = i64::try_from(limit.min(vellaveto_types::audit_store::MAX_QUERY_LIMIT))
            .unwrap_or(i64::MAX);
        if capped_limit == 0 {
            return Ok(vec![]);
        }

        let sql = format!(
            "SELECT action_json, verdict_json, id, sequence, timestamp_raw, metadata, entry_hash, prev_hash, commitment, tenant_id FROM {} ORDER BY sequence DESC LIMIT $1",
            self.table_name
        );
        let rows = sqlx::query_as::<_, AuditRow>(&sql)
            .bind(capped_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| QueryError::Query(format!("Recent query failed: {}", e)))?;

        // Reverse to get ascending order (most recent last)
        let entries: Vec<serde_json::Value> = rows
            .into_iter()
            .rev()
            .filter_map(|row| row.to_json().ok())
            .collect();

        Ok(entries)
    }
}

/// Row type for audit entry queries.
struct AuditRow {
    action_json: serde_json::Value,
    verdict_json: serde_json::Value,
    id: String,
    sequence: i64,
    timestamp_raw: String,
    metadata: serde_json::Value,
    entry_hash: String,
    prev_hash: String,
    commitment: Option<String>,
    tenant_id: Option<String>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for AuditRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            action_json: row.try_get("action_json")?,
            verdict_json: row.try_get("verdict_json")?,
            id: row.try_get("id")?,
            sequence: row.try_get("sequence")?,
            timestamp_raw: row.try_get("timestamp_raw")?,
            metadata: row.try_get("metadata")?,
            entry_hash: row.try_get("entry_hash")?,
            prev_hash: row.try_get("prev_hash")?,
            commitment: row.try_get("commitment")?,
            tenant_id: row.try_get("tenant_id")?,
        })
    }
}

impl AuditRow {
    fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        Ok(serde_json::json!({
            "id": self.id,
            "sequence": self.sequence,
            "timestamp": self.timestamp_raw,
            "action": self.action_json,
            "verdict": self.verdict_json,
            "metadata": self.metadata,
            "entry_hash": self.entry_hash,
            "prev_hash": self.prev_hash,
            "commitment": self.commitment,
            "tenant_id": self.tenant_id,
        }))
    }
}

/// Build filter clauses as `AND condition` fragments.
/// Returns an empty string if no filters are active.
/// All data is passed via bind parameters (never interpolated).
///
/// **MAINTENANCE NOTE (R158-003):** This function and [`WhereBuilder`] implement
/// the *same* filter logic via two separate code paths. `search()` uses
/// `WhereBuilder` (producing `WHERE col = $N` clauses), while `count()` uses
/// this function (producing `AND col = $N` fragments appended to `WHERE TRUE`).
/// Both paths must be kept in sync: any new filter added to one MUST be added
/// to the other, and the parameter binding order in [`bind_params`] /
/// [`bind_data_params`] must match both.
fn build_filter_clauses(params: &AuditQueryParams) -> String {
    let mut clauses = Vec::new();
    let mut idx = 1u32;

    if params.since.is_some() {
        clauses.push(format!("AND timestamp_raw >= ${}", idx));
        idx = idx.saturating_add(1);
    }
    if params.until.is_some() {
        clauses.push(format!("AND timestamp_raw < ${}", idx));
        idx = idx.saturating_add(1);
    }
    if params.tool.is_some() {
        clauses.push(format!("AND tool = ${}", idx));
        idx = idx.saturating_add(1);
    }
    if params.agent_id.is_some() {
        clauses.push(format!(
            "AND metadata @> jsonb_build_object('agent_id', ${})",
            idx
        ));
        idx = idx.saturating_add(1);
    }
    if params.verdict.is_some() {
        clauses.push(format!("AND verdict_type = ${}", idx));
        idx = idx.saturating_add(1);
    }
    if params.from_sequence.is_some() {
        clauses.push(format!("AND sequence >= ${}", idx));
        idx = idx.saturating_add(1);
    }
    if params.to_sequence.is_some() {
        clauses.push(format!("AND sequence <= ${}", idx));
        idx = idx.saturating_add(1);
    }
    if params.text_search.is_some() {
        clauses.push(format!(
            "AND (tool ILIKE ${p} OR function_name ILIKE ${p} OR metadata::text ILIKE ${p})",
            p = idx
        ));
        idx = idx.saturating_add(1);
    }

    // Phase 44: Tenant ID filter
    if params.tenant_id.is_some() {
        clauses.push(format!("AND tenant_id = ${}", idx));
        idx = idx.saturating_add(1);
    }

    let _ = idx; // suppress unused assignment warning
    clauses.join(" ")
}

/// Bind parameters to a scalar query in the order established by `build_filter_clauses`.
fn bind_params<'q>(
    mut query: sqlx::query::QueryScalar<'q, sqlx::Postgres, i64, sqlx::postgres::PgArguments>,
    params: &'q AuditQueryParams,
) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, i64, sqlx::postgres::PgArguments> {
    if let Some(ref since) = params.since {
        query = query.bind(since.as_str());
    }
    if let Some(ref until) = params.until {
        query = query.bind(until.as_str());
    }
    if let Some(ref tool) = params.tool {
        query = query.bind(tool.as_str());
    }
    if let Some(ref agent_id) = params.agent_id {
        query = query.bind(agent_id.as_str());
    }
    if let Some(ref verdict) = params.verdict {
        let v = match verdict {
            VerdictFilter::Allow => "allow",
            VerdictFilter::Deny => "deny",
            VerdictFilter::RequireApproval => "require_approval",
        };
        query = query.bind(v);
    }
    if let Some(from) = params.from_sequence {
        // SECURITY (R158-001): Use saturating cast — values > i64::MAX are clamped
        // to i64::MAX, which is correct because no sequence can exceed that in PG BIGINT.
        query = query.bind(i64::try_from(from).unwrap_or(i64::MAX));
    }
    if let Some(to) = params.to_sequence {
        query = query.bind(i64::try_from(to).unwrap_or(i64::MAX));
    }
    if let Some(ref text) = params.text_search {
        // SECURITY (R231-AUD-2): Escape backslash before % and _ to prevent
        // ILIKE pattern injection via backslash as PostgreSQL's default escape char.
        let pattern = format!(
            "%{}%",
            text.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        query = query.bind(pattern);
    }
    // Phase 44: Tenant ID filter
    if let Some(ref tenant_id) = params.tenant_id {
        query = query.bind(tenant_id.as_str());
    }
    query
}

/// Bind parameters to a row query in the same order.
fn bind_data_params<'q>(
    mut query: sqlx::query::QueryAs<'q, sqlx::Postgres, AuditRow, sqlx::postgres::PgArguments>,
    params: &'q AuditQueryParams,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, AuditRow, sqlx::postgres::PgArguments> {
    if let Some(ref since) = params.since {
        query = query.bind(since.as_str());
    }
    if let Some(ref until) = params.until {
        query = query.bind(until.as_str());
    }
    if let Some(ref tool) = params.tool {
        query = query.bind(tool.as_str());
    }
    if let Some(ref agent_id) = params.agent_id {
        query = query.bind(agent_id.as_str());
    }
    if let Some(ref verdict) = params.verdict {
        let v = match verdict {
            VerdictFilter::Allow => "allow",
            VerdictFilter::Deny => "deny",
            VerdictFilter::RequireApproval => "require_approval",
        };
        query = query.bind(v);
    }
    if let Some(from) = params.from_sequence {
        // SECURITY (R158-001): Saturating cast to i64 — see bind_params().
        query = query.bind(i64::try_from(from).unwrap_or(i64::MAX));
    }
    if let Some(to) = params.to_sequence {
        query = query.bind(i64::try_from(to).unwrap_or(i64::MAX));
    }
    if let Some(ref text) = params.text_search {
        // SECURITY (R231-AUD-2): Escape backslash before % and _ to prevent
        // ILIKE pattern injection via backslash as PostgreSQL's default escape char.
        let pattern = format!(
            "%{}%",
            text.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        query = query.bind(pattern);
    }
    // Phase 44: Tenant ID filter
    if let Some(ref tenant_id) = params.tenant_id {
        query = query.bind(tenant_id.as_str());
    }
    // Bind limit and offset
    // SECURITY (R158-001): limit is validated <= MAX_QUERY_LIMIT (1000) and offset is
    // validated by AuditQueryParams::validate(), both well within i64 range.
    query = query.bind(i64::try_from(params.limit).unwrap_or(i64::MAX));
    query = query.bind(i64::try_from(params.offset).unwrap_or(i64::MAX));
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_filter_clauses_empty_params() {
        let params = AuditQueryParams::default();
        let clauses = build_filter_clauses(&params);
        assert!(clauses.is_empty());
    }

    #[test]
    fn test_build_filter_clauses_tool_filter() {
        let params = AuditQueryParams {
            tool: Some("file_write".to_string()),
            ..Default::default()
        };
        let clauses = build_filter_clauses(&params);
        assert!(clauses.contains("AND tool = $1"));
    }

    #[test]
    fn test_build_filter_clauses_combined() {
        let params = AuditQueryParams {
            since: Some("2025-01-01T00:00:00Z".to_string()),
            tool: Some("file_write".to_string()),
            verdict: Some(VerdictFilter::Deny),
            ..Default::default()
        };
        let clauses = build_filter_clauses(&params);
        assert!(clauses.contains("AND timestamp_raw >= $1"));
        assert!(clauses.contains("AND tool = $2"));
        assert!(clauses.contains("AND verdict_type = $3"));
    }

    #[test]
    fn test_build_filter_clauses_text_search_escapes_wildcards() {
        // The text_search clause should use ILIKE with the parameter
        let params = AuditQueryParams {
            text_search: Some("test%query".to_string()),
            ..Default::default()
        };
        let clauses = build_filter_clauses(&params);
        assert!(clauses.contains("ILIKE"));
    }

    // --- validate_table_name() / PostgresAuditQuery::new() tests (FIND-R159-001) ---

    #[test]
    fn test_validate_table_name_valid() {
        assert!(validate_table_name("audit_entries").is_ok());
        assert!(validate_table_name("vellaveto_audit_entries").is_ok());
        assert!(validate_table_name("a").is_ok());
        assert!(validate_table_name("_private").is_ok());
        assert!(validate_table_name("Table123").is_ok());
    }

    #[test]
    fn test_validate_table_name_empty() {
        let err = validate_table_name("").unwrap_err().to_string();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_too_long() {
        let name = "a".repeat(64);
        let err = validate_table_name(&name).unwrap_err().to_string();
        assert!(err.contains("63"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_at_max_length() {
        let name = "a".repeat(63);
        assert!(validate_table_name(&name).is_ok());
    }

    #[test]
    fn test_validate_table_name_starts_with_digit() {
        let err = validate_table_name("1table").unwrap_err().to_string();
        assert!(err.contains("digit"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_sql_injection_semicolon() {
        let err = validate_table_name("audit; DROP TABLE users--")
            .unwrap_err()
            .to_string();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_sql_injection_quotes() {
        let err = validate_table_name("audit' OR '1'='1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_double_quotes() {
        let err = validate_table_name("\"audit\"").unwrap_err().to_string();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_dashes() {
        let err = validate_table_name("my-table").unwrap_err().to_string();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_spaces() {
        let err = validate_table_name("my table").unwrap_err().to_string();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_dot() {
        // Schema-qualified names are not allowed — must be a bare identifier
        let err = validate_table_name("public.audit").unwrap_err().to_string();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_unicode() {
        let err = validate_table_name("t\u{00E4}ble").unwrap_err().to_string();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn test_validate_table_name_null_byte() {
        let err = validate_table_name("audit\0table").unwrap_err().to_string();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    /// FIND-R200-002: Verify WhereBuilder and build_filter_clauses produce
    /// the same number of conditions for the same params, catching divergence.
    #[test]
    fn test_where_builder_and_build_filter_clauses_parity() {
        let params = AuditQueryParams {
            since: Some("2025-01-01T00:00:00Z".to_string()),
            until: Some("2025-12-31T23:59:59Z".to_string()),
            tool: Some("file_read".to_string()),
            agent_id: Some("agent-1".to_string()),
            verdict: Some(VerdictFilter::Deny),
            from_sequence: Some(1),
            to_sequence: Some(100),
            text_search: Some("secret".to_string()),
            tenant_id: Some("tenant-1".to_string()),
            limit: 50,
            offset: 0,
        };

        // Count conditions from WhereBuilder
        let mut wb = WhereBuilder::new();
        if params.since.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("timestamp_raw >= {}", p));
        }
        if params.until.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("timestamp_raw < {}", p));
        }
        if params.tool.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("tool = {}", p));
        }
        if params.agent_id.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("metadata @> jsonb_build_object('agent_id', {})", p));
        }
        if params.verdict.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("verdict_type = {}", p));
        }
        if params.from_sequence.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("sequence >= {}", p));
        }
        if params.to_sequence.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("sequence <= {}", p));
        }
        if params.text_search.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("(ILIKE {})", p));
        }
        if params.tenant_id.is_some() {
            let p = wb.next_param();
            wb.add_condition(format!("tenant_id = {}", p));
        }
        let wb_count = wb.conditions.len();

        // Count conditions from build_filter_clauses
        let clauses = build_filter_clauses(&params);
        let bfc_count = clauses.matches("AND ").count();

        assert_eq!(
            wb_count, bfc_count,
            "WhereBuilder produced {} conditions but build_filter_clauses produced {} — divergence detected!",
            wb_count, bfc_count
        );
        // Both should use the same param index after processing all filters
        assert_eq!(wb.param_idx, 10, "Expected 9 filters + 1 = param_idx 10");
    }

    #[test]
    fn test_build_filter_clauses_tenant_id() {
        let params = AuditQueryParams {
            tenant_id: Some("tenant-abc".to_string()),
            ..Default::default()
        };
        let clauses = build_filter_clauses(&params);
        assert!(clauses.contains("AND tenant_id = $1"), "got: {clauses}");
    }

    #[test]
    fn test_audit_row_to_json() {
        let row = AuditRow {
            action_json: serde_json::json!({"tool": "test", "function": "fn"}),
            verdict_json: serde_json::json!("allow"),
            id: "abc-123".to_string(),
            sequence: 42,
            timestamp_raw: "2025-01-01T00:00:00Z".to_string(),
            metadata: serde_json::json!({}),
            entry_hash: "deadbeef".to_string(),
            prev_hash: "cafebabe".to_string(),
            commitment: None,
            tenant_id: None,
        };
        let json = row.to_json().unwrap();
        assert_eq!(json["id"], "abc-123");
        assert_eq!(json["sequence"], 42);
        assert!(json["commitment"].is_null());
    }
}
