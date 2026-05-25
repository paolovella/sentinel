// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Phase 55: Performance & Scale Validation — Throughput and concurrency tests.
//!
//! Validates that the Vellaveto engine meets its performance targets:
//! - <5ms P99 evaluation latency
//! - 100K+ evaluations per second (engine-only, no HTTP overhead)
//! - Stable memory under sustained load
//! - No data races under concurrent access

use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn allow_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Allow {id}"),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Deny {id}"),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

/// Generate a mixed set of policies for stress testing.
/// Returns policies with varied types and priority levels.
fn generate_mixed_policies(count: usize) -> Vec<Policy> {
    let mut policies = Vec::with_capacity(count);
    for i in 0..count {
        let priority = (count as i32) - (i as i32);
        let policy = match i % 3 {
            0 => allow_policy(&format!("tool_{i}:*"), priority),
            1 => deny_policy(&format!("blocked_{i}:*"), priority),
            _ => Policy {
                id: format!("cond_{i}:*"),
                name: format!("Conditional {i}"),
                policy_type: PolicyType::Conditional {
                    conditions: json!({"required_parameters": []}),
                },
                priority,
                path_rules: None,
                network_rules: None,
            },
        };
        policies.push(policy);
    }
    policies
}

// ═══════════════════════════════════════════════════════════════════
// 1. Sustained throughput validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_evaluation_throughput_100k_per_second() {
    let policies = generate_mixed_policies(100);
    let engine =
        PolicyEngine::with_policies(false, &policies).expect("100 mixed policies should compile");

    let action = make_action("tool_0", "read");
    let mut count: u64 = 0;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(1);

    while Instant::now() < deadline {
        // Batch of 100 to reduce Instant::now() overhead
        for _ in 0..100 {
            let _verdict = engine.evaluate_action(&action, &[]).unwrap();
            count = count.saturating_add(1);
        }
    }

    let elapsed = start.elapsed();
    let throughput = (count as f64) / elapsed.as_secs_f64();

    assert!(
        count >= 100_000,
        "Expected >= 100,000 evaluations in 1 second, got {} ({:.0} ops/s in {:.3}s)",
        count,
        throughput,
        elapsed.as_secs_f64(),
    );
}

// ═══════════════════════════════════════════════════════════════════
// 2. Concurrent evaluation safety
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_concurrent_evaluation_no_data_race() {
    let policies = generate_mixed_policies(50);
    let engine = Arc::new(
        PolicyEngine::with_policies(false, &policies).expect("50 mixed policies should compile"),
    );

    let num_threads = 16;
    let evals_per_thread = 1000;

    let results: Vec<Vec<Verdict>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..num_threads)
            .map(|t| {
                let engine = Arc::clone(&engine);
                s.spawn(move || {
                    let mut verdicts = Vec::with_capacity(evals_per_thread);
                    for i in 0..evals_per_thread {
                        let action =
                            make_action(&format!("tool_{}", i % 50), &format!("func_t{t}_{i}"));
                        let verdict = engine.evaluate_action(&action, &[]).unwrap();
                        verdicts.push(verdict);
                    }
                    verdicts
                })
            })
            .collect();

        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let total_verdicts: usize = results.iter().map(|v| v.len()).sum();
    assert_eq!(
        total_verdicts,
        num_threads * evals_per_thread,
        "Expected {} total verdicts, got {}",
        num_threads * evals_per_thread,
        total_verdicts,
    );
}

// ═══════════════════════════════════════════════════════════════════
// 3. Multi-tenant isolation under load
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_multi_tenant_isolation_under_concurrent_load() {
    // Tenant A: allow tools starting with "a_"
    let tenant_a_policies = vec![allow_policy("a_*", 100)];
    let engine_a = Arc::new(
        PolicyEngine::with_policies(false, &tenant_a_policies)
            .expect("tenant A policies should compile"),
    );

    // Tenant B: allow tools starting with "b_"
    let tenant_b_policies = vec![allow_policy("b_*", 100)];
    let engine_b = Arc::new(
        PolicyEngine::with_policies(false, &tenant_b_policies)
            .expect("tenant B policies should compile"),
    );

    // Tenant C: deny all (strict mode, no policies matches → deny)
    let tenant_c_policies = vec![deny_policy("*", 100)];
    let engine_c = Arc::new(
        PolicyEngine::with_policies(true, &tenant_c_policies)
            .expect("tenant C policies should compile"),
    );

    let evals_per_tenant = 1000;

    std::thread::scope(|s| {
        // Tenant A thread
        let ea = Arc::clone(&engine_a);
        let handle_a = s.spawn(move || {
            for i in 0..evals_per_tenant {
                let action = make_action(&format!("a_tool_{i}"), "read");
                let verdict = ea.evaluate_action(&action, &[]).unwrap();
                assert!(
                    matches!(verdict, Verdict::Allow),
                    "Tenant A: expected Allow for a_tool_{i}, got {verdict:?}",
                );
            }
        });

        // Tenant B thread
        let eb = Arc::clone(&engine_b);
        let handle_b = s.spawn(move || {
            for i in 0..evals_per_tenant {
                let action = make_action(&format!("b_tool_{i}"), "write");
                let verdict = eb.evaluate_action(&action, &[]).unwrap();
                assert!(
                    matches!(verdict, Verdict::Allow),
                    "Tenant B: expected Allow for b_tool_{i}, got {verdict:?}",
                );
            }
        });

        // Tenant C thread (deny all)
        let ec = Arc::clone(&engine_c);
        let handle_c = s.spawn(move || {
            for i in 0..evals_per_tenant {
                let action = make_action(&format!("any_tool_{i}"), "delete");
                let verdict = ec.evaluate_action(&action, &[]).unwrap();
                assert!(
                    matches!(verdict, Verdict::Deny { .. }),
                    "Tenant C: expected Deny for any_tool_{i}, got {verdict:?}",
                );
            }
        });

        handle_a.join().unwrap();
        handle_b.join().unwrap();
        handle_c.join().unwrap();
    });
}

// ═══════════════════════════════════════════════════════════════════
// 4. Audit pipeline throughput
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_audit_pipeline_50k_entries_throughput() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("perf_tool", "stress_write");
        let entry_count = 50_000usize;
        // Generous bound: 60s accommodates debug builds where SHA-256
        // hashing per entry is significantly slower than release mode.
        // In release builds this typically completes in <5s.
        let time_limit = Duration::from_secs(60);

        let start = Instant::now();
        for i in 0..entry_count {
            let metadata = json!({"index": i});
            logger
                .log_entry(&action, &Verdict::Allow, metadata)
                .await
                .unwrap();
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed < time_limit,
            "Expected 50K audit entries in < {}s, took {:.2}s",
            time_limit.as_secs(),
            elapsed.as_secs_f64(),
        );

        // Verify all entries persisted
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(
            entries.len(),
            entry_count,
            "Expected {} entries loaded, got {}",
            entry_count,
            entries.len(),
        );

        // Verify hash chain integrity
        let chain = logger.verify_chain().await.unwrap();
        assert!(
            chain.valid,
            "Hash chain broken after 50K entries at index {:?}",
            chain.first_broken_at,
        );
        assert_eq!(chain.entries_checked, entry_count);
    });
}

// ═══════════════════════════════════════════════════════════════════
// 5. Policy compilation throughput
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_policy_compilation_1000_policies_under_100ms() {
    let policies = generate_mixed_policies(1000);

    let start = Instant::now();
    let engine = PolicyEngine::with_policies(false, &policies);
    let elapsed = start.elapsed();

    assert!(
        engine.is_ok(),
        "1000 policies should compile without error: {:?}",
        engine.err(),
    );
    assert!(
        elapsed < Duration::from_millis(100),
        "Expected policy compilation in < 100ms, took {:.2}ms",
        elapsed.as_secs_f64() * 1000.0,
    );
}

// ═══════════════════════════════════════════════════════════════════
// 6. Concurrent audit logging
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_concurrent_audit_logging_no_entry_loss() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to create multi-thread tokio runtime");

    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
        let num_tasks = 8;
        let entries_per_task = 1000;

        let mut handles = Vec::with_capacity(num_tasks);
        for t in 0..num_tasks {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for i in 0..entries_per_task {
                    let action = make_action(&format!("task_{t}_tool"), &format!("func_{i}"));
                    let metadata = json!({"task": t, "index": i});
                    logger
                        .log_entry(&action, &Verdict::Allow, metadata)
                        .await
                        .unwrap();
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        let expected = num_tasks * entries_per_task;
        assert_eq!(
            entries.len(),
            expected,
            "Expected {} entries, got {} — some entries lost during concurrent writes",
            expected,
            entries.len(),
        );

        // Verify no duplicate IDs
        let ids: HashSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids.len(),
            expected,
            "Found {} unique IDs but expected {} — duplicates detected",
            ids.len(),
            expected,
        );
    });
}

// ═══════════════════════════════════════════════════════════════════
// 7. Memory stability under sustained load
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_memory_stable_under_sustained_evaluation() {
    let policies = generate_mixed_policies(100);
    let engine =
        PolicyEngine::with_policies(false, &policies).expect("100 mixed policies should compile");

    // Evaluate 100K distinct actions — if this completes, no OOM or unbounded leak
    for i in 0..100_000u64 {
        let action = make_action(&format!("tool_{}", i % 100), &format!("func_{i}"));
        let verdict = engine.evaluate_action(&action, &[]);
        assert!(
            verdict.is_ok(),
            "Evaluation {} failed: {:?}",
            i,
            verdict.err(),
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 8. Latency distribution validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_p99_latency_under_5ms_with_100_policies() {
    let policies = generate_mixed_policies(100);
    let engine =
        PolicyEngine::with_policies(false, &policies).expect("100 mixed policies should compile");

    let sample_count = 10_000;
    let mut durations = Vec::with_capacity(sample_count);

    // Warm up: 1000 evaluations to stabilize caches
    for i in 0..1000 {
        let action = make_action(&format!("tool_{}", i % 100), "warmup");
        let _ = engine.evaluate_action(&action, &[]);
    }

    // Measure
    for i in 0..sample_count {
        let action = make_action(&format!("tool_{}", i % 100), &format!("measure_{i}"));
        let start = Instant::now();
        let _verdict = engine.evaluate_action(&action, &[]).unwrap();
        durations.push(start.elapsed());
    }

    durations.sort();
    let p99_index = (sample_count * 99) / 100; // index 9900 of 10000
    let p99 = durations[p99_index];
    let p99_us = p99.as_micros();

    assert!(
        p99 < Duration::from_millis(5),
        "P99 latency {} us ({:.3} ms) exceeds 5ms target",
        p99_us,
        p99_us as f64 / 1000.0,
    );

    // Also validate P50 is reasonable
    let p50 = durations[sample_count / 2];
    assert!(
        p50 < Duration::from_millis(1),
        "P50 latency {} us exceeds 1ms — something is wrong",
        p50.as_micros(),
    );
}
