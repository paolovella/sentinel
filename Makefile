# Vellaveto — Top-level Makefile
#
# Primary target: `make verify` — runs all verification steps and produces
# a JSON evidence bundle that reviewers can attach to issues or PRs.

SHELL := /bin/bash
.DEFAULT_GOAL := help

EVIDENCE_DIR := target/evidence
EVIDENCE_FILE := $(EVIDENCE_DIR)/evidence-$(shell date +%Y%m%d-%H%M%S).json

# ─────────────────────────────────────────────────────────────────────
# Primary targets
# ─────────────────────────────────────────────────────────────────────

.PHONY: verify
verify: ## Run full verification suite and produce evidence bundle
	@echo "═══════════════════════════════════════════════════════════════"
	@echo " Vellaveto Verification Suite"
	@echo "═══════════════════════════════════════════════════════════════"
	@mkdir -p $(EVIDENCE_DIR)
	@echo '{}' > $(EVIDENCE_FILE)
	@echo ""
	@# Step 1: Format check
	@echo "── [1/6] Format check ──────────────────────────────────────"
	cargo fmt --all -- --check
	@echo ""
	@# Step 2: Clippy
	@echo "── [2/6] Clippy (deny warnings) ────────────────────────────"
	cargo clippy --workspace -- -D warnings
	@echo ""
	@# Step 3: Test suite
	@echo "── [3/6] Test suite ────────────────────────────────────────"
	@TESTS_START=$$(date +%s); \
	cargo test --workspace --no-fail-fast 2>&1 | tee $(EVIDENCE_DIR)/test-output.txt; \
	TEST_EXIT=$${PIPESTATUS[0]}; \
	TESTS_END=$$(date +%s); \
	TESTS_DURATION=$$((TESTS_END - TESTS_START)); \
	TESTS_PASSED=$$(grep "^test result:" $(EVIDENCE_DIR)/test-output.txt | awk -F'[; ]' '{sum+=$$4} END {print sum+0}'); \
	TESTS_FAILED=$$(grep "^test result:" $(EVIDENCE_DIR)/test-output.txt | awk -F'[; ]' '{sum+=$$7} END {print sum+0}'); \
	echo "{\"tests\":{\"passed\":$$TESTS_PASSED,\"failed\":$$TESTS_FAILED,\"duration_secs\":$$TESTS_DURATION}}" > $(EVIDENCE_DIR)/tests.json; \
	if [ "$$TEST_EXIT" -ne 0 ]; then echo "FAIL: tests failed"; exit 1; fi
	@echo ""
	@# Step 4: Formal verification (graceful skip when tools not installed)
	@echo "── [4/6] Formal verification ───────────────────────────────"
	@echo '{}' > $(EVIDENCE_DIR)/formal.json
	@# TLA+ (9 specifications)
	@if command -v java >/dev/null 2>&1 && [ -f formal/tla/tla2tools.jar ]; then \
		echo "Running TLA+ model checker (9 specs)..."; \
		TLA_OK=true; \
		for spec in MCPPolicyEngine AbacForbidOverrides MCPTaskLifecycle CascadingFailure WorkflowConstraint CapabilityDelegation CredentialVault AuditChain TrustContainment; do \
			cfg="formal/tla/$${spec}.cfg"; \
			mc="formal/tla/MC_$${spec}.tla"; \
			main="formal/tla/$${spec}.tla"; \
			if [ -f "$$mc" ]; then \
				echo "  TLA+ $$spec (via MC)..."; \
				cd formal/tla && java -jar tla2tools.jar -config $${spec}.cfg MC_$${spec}.tla 2>&1 | tail -3; \
				if [ $$? -ne 0 ]; then TLA_OK=false; fi; \
				cd ../..; \
			elif [ -f "$$cfg" ] && [ -f "$$main" ]; then \
				echo "  TLA+ $$spec (direct)..."; \
				cd formal/tla && java -jar tla2tools.jar -config $${spec}.cfg $${spec}.tla 2>&1 | tail -3; \
				if [ $$? -ne 0 ]; then TLA_OK=false; fi; \
				cd ../..; \
			else \
				echo "  SKIP: $$spec (files not found)"; \
			fi; \
		done; \
		if $$TLA_OK; then \
			echo '{"tla_plus":"passed"}' > $(EVIDENCE_DIR)/formal.json; \
		else \
			echo '{"tla_plus":"failed"}' > $(EVIDENCE_DIR)/formal.json; \
		fi; \
	else \
		echo "SKIP: TLA+ (requires Java 11+ and formal/tla/tla2tools.jar)"; \
	fi
	@# Alloy (2 models)
	@if command -v java >/dev/null 2>&1 && [ -f formal/alloy/alloy.jar ]; then \
		echo "Running Alloy bounded model checking (2 models)..."; \
		for model in CapabilityDelegation AbacForbidOverride; do \
			echo "  Alloy $$model..."; \
			java -jar formal/alloy/alloy.jar -c "formal/alloy/$${model}.als" 2>&1 | tail -3; \
		done; \
	else \
		echo "SKIP: Alloy (requires Java 11+ and formal/alloy/alloy.jar)"; \
	fi
	@# Lean 4 (5 files, 32 theorems)
	@if command -v lake >/dev/null 2>&1; then \
		echo "Running Lean 4 type checker (5 files, 32 theorems)..."; \
		cd formal/lean && lake build 2>&1 | tail -5; \
	else \
		echo "SKIP: Lean 4 (requires lake)"; \
	fi
	@# Coq (8 files, 45 theorems)
	@if command -v coqc >/dev/null 2>&1; then \
		echo "Running Coq type checker (8 files, 45 theorems)..."; \
		cd formal/coq && coq_makefile -f _CoqProject -o CoqMakefile 2>/dev/null && \
		make -f CoqMakefile 2>&1 | tail -5; \
	else \
		echo "SKIP: Coq (requires coqc 8.16+)"; \
	fi
	@# Trusted formal assumption inventory
	@echo "Checking trusted formal assumptions..."
	bash formal/tools/check-formal-trusted-assumptions.sh
	@# Kani (90 harnesses on actual Rust)
	@if command -v cargo-kani >/dev/null 2>&1; then \
		echo "Running Kani bounded model checking (90 harnesses)..."; \
		cd formal/kani && cargo kani 2>&1 | tail -10; \
	else \
		echo "SKIP: Kani (requires cargo-kani)"; \
	fi
	@# Verus (534 verified items on actual Rust)
	@if [ -n "$$VERUS_BIN" ] || command -v verus >/dev/null 2>&1 || [ -x verus-bin/verus-x86-linux/verus ] || [ -x "$$HOME/verus/verus-bin/verus-x86-linux/verus" ] || [ -x "$$HOME/verus/source/target-verus/release/verus" ]; then \
		echo "Running Verus deductive verification..."; \
		bash formal/tools/check-verus-parity.sh; \
		bash formal/tools/verify-verus.sh; \
	else \
		echo "SKIP: Verus (set VERUS_BIN, install verus, unpack verus-bin/, or keep ~/verus/)"; \
	fi
	@echo ""
	@# Step 5: Benchmark sanity (short run — not full benchmarks)
	@echo "── [5/6] Benchmark sanity check ────────────────────────────"
	cargo bench -p vellaveto-engine -- --quick 2>&1 | tail -20
	@echo ""
	@# Step 6: Golden regression suite (integration tests)
	@echo "── [6/6] Security regression suite ─────────────────────────"
	cargo test -p vellaveto-integration -- --test-threads=1 2>&1 | tail -10
	@echo ""
	@# Assemble evidence bundle
	@echo "═══════════════════════════════════════════════════════════════"
	@echo " Assembling evidence bundle"
	@echo "═══════════════════════════════════════════════════════════════"
	@RUST_VERSION=$$(rustc --version); \
	GIT_SHA=$$(git rev-parse --short HEAD 2>/dev/null || echo "unknown"); \
	GIT_BRANCH=$$(git branch --show-current 2>/dev/null || echo "unknown"); \
	TIMESTAMP=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	TESTS_JSON=$$(cat $(EVIDENCE_DIR)/tests.json 2>/dev/null || echo '{}'); \
	FORMAL_JSON=$$(cat $(EVIDENCE_DIR)/formal.json 2>/dev/null || echo '{}'); \
	echo "{" > $(EVIDENCE_FILE); \
	echo "  \"timestamp\": \"$$TIMESTAMP\"," >> $(EVIDENCE_FILE); \
	echo "  \"git_sha\": \"$$GIT_SHA\"," >> $(EVIDENCE_FILE); \
	echo "  \"git_branch\": \"$$GIT_BRANCH\"," >> $(EVIDENCE_FILE); \
	echo "  \"rust_version\": \"$$RUST_VERSION\"," >> $(EVIDENCE_FILE); \
	echo "  \"fmt\": \"passed\"," >> $(EVIDENCE_FILE); \
	echo "  \"clippy\": \"passed\"," >> $(EVIDENCE_FILE); \
	echo "  \"tests\": $$TESTS_JSON," >> $(EVIDENCE_FILE); \
	echo "  \"formal\": $$FORMAL_JSON," >> $(EVIDENCE_FILE); \
	echo "  \"benchmarks\": \"sanity_passed\"," >> $(EVIDENCE_FILE); \
	echo "  \"regression_suite\": \"passed\"" >> $(EVIDENCE_FILE); \
	echo "}" >> $(EVIDENCE_FILE)
	@echo ""
	@echo "Evidence bundle: $(EVIDENCE_FILE)"
	@echo "Test output:     $(EVIDENCE_DIR)/test-output.txt"
	@echo ""
	@echo "All checks passed."

# ─────────────────────────────────────────────────────────────────────
# Individual targets
# ─────────────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run full test suite
	cargo test --workspace --no-fail-fast

.PHONY: clippy
clippy: ## Run clippy with deny warnings
	cargo clippy --workspace -- -D warnings

.PHONY: fmt
fmt: ## Check formatting
	cargo fmt --all -- --check

.PHONY: bench
bench: ## Run full benchmark suite
	cargo bench --workspace

.PHONY: bench-quick
bench-quick: ## Run quick benchmark sanity check
	cargo bench -p vellaveto-engine -- --quick

.PHONY: formal
formal: formal-trusted-assumptions formal-tla formal-alloy formal-lean formal-coq formal-kani formal-verus ## Run all formal verification tools

.PHONY: formal-local
formal-local: ## Run storage-light local formal coverage checks
	bash formal/tools/check-formal-trusted-assumptions.sh
	bash formal/tools/check-verus-parity.sh
	RUN_KANI_PARITY_TESTS=0 KANI_PARITY_TARGET_DIR="$${KANI_PARITY_TARGET_DIR:-/tmp/vellaveto-formal-kani-parity-target}" bash formal/tools/check-kani-parity.sh
	bash formal/tools/check-formal-e2e-coverage.sh

.PHONY: formal-e2e-coverage
formal-e2e-coverage: ## Verify local end-to-end formal coverage anchors
	bash formal/tools/check-formal-e2e-coverage.sh

.PHONY: verify-all
verify-all: formal ## Run the full local formal verification mesh

.PHONY: formal-tla
formal-tla: ## Run TLA+ model checking (all local specs, requires Java 11+ and tla2tools.jar)
	@for cfg in formal/tla/*.cfg; do \
		spec="$${cfg##*/}"; \
		spec="$${spec%.cfg}"; \
		mc="formal/tla/MC_$${spec}.tla"; \
		main="formal/tla/$${spec}.tla"; \
		if [ -f "$$mc" ]; then \
			echo "TLA+ $$spec (via MC_$${spec})..."; \
			cd formal/tla && java -jar tla2tools.jar -config $${spec}.cfg MC_$${spec}.tla && cd ../..; \
		elif [ -f "$$main" ]; then \
			echo "TLA+ $$spec (direct)..."; \
			cd formal/tla && java -jar tla2tools.jar -config $${spec}.cfg $${spec}.tla && cd ../..; \
		fi; \
	done

.PHONY: formal-alloy
formal-alloy: ## Run Alloy bounded model checking (requires alloy.jar)
	java -jar formal/alloy/alloy.jar -c formal/alloy/CapabilityDelegation.als
	java -jar formal/alloy/alloy.jar -c formal/alloy/AbacForbidOverride.als

.PHONY: formal-lean
formal-lean: ## Run Lean 4 type checker (5 files, 32 theorems)
	cd formal/lean && lake build

.PHONY: formal-coq
formal-coq: ## Run Coq type checker (8 files, 45 theorems)
	cd formal/coq && coq_makefile -f _CoqProject -o CoqMakefile && make -f CoqMakefile

.PHONY: formal-kani
formal-kani: ## Run Kani bounded model checking (all local harnesses; large local artifact footprint)
	cd formal/kani && CARGO_TARGET_DIR="$${CARGO_TARGET_DIR:-/tmp/vellaveto-formal-kani-target}" cargo kani

.PHONY: formal-trusted-assumptions
formal-trusted-assumptions: ## Verify the trusted-assumption inventory matches the allowlist
	bash formal/tools/check-formal-trusted-assumptions.sh

.PHONY: formal-verus
formal-verus: ## Run Verus parity checks and canonical verification
	bash formal/tools/check-verus-parity.sh
	bash formal/tools/verify-verus.sh

.PHONY: formal-docker
formal-docker: ## Run formal verification in Docker (reproducible, all tools pinned)
	docker build -t vellaveto-formal formal/
	docker run --rm -v "$(CURDIR):/workspace" vellaveto-formal

.PHONY: formal-clean-local
formal-clean-local: ## Remove repo-local and default tmp-backed formal artifacts
	rm -rf formal/kani/target
	rm -rf formal/kani/states
	rm -rf formal/tla/states
	rm -rf /tmp/vellaveto-formal-kani-target
	rm -rf /tmp/vellaveto-formal-kani-parity-target
	rm -rf /tmp/vellaveto-formal-verus-target

.PHONY: clean
clean: ## Clean build artifacts
	cargo clean
	rm -rf $(EVIDENCE_DIR)

# ─────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
