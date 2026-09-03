.PHONY: help check fmt fmt-check clippy clippy-production test test-default test-doc \
        test-distributed test-otlp test-embedding-external \
        cli-e2e cli-e2e-inventory cli-e2e-in-process cli-e2e-process \
        ci-check-cli-e2e coverage-clean coverage-test coverage-report coverage-check \
        runtime-payload runtime-payload-verify runtime-payload-test runtime-image \
        runtime-image-verify deny spdx-check third-party-check \
        ci-check ci-check-fast ci-check-fmt ci-check-clippy-all-targets \
        ci-check-clippy-production ci-check-compile ci-check-test-default \
        ci-check-test-distributed ci-check-test-otlp \
        ci-check-test-embedding-external ci-check-doc ci-check-deny \
        ci-check-spdx ci-check-third-party

CARGO ?= cargo
NEXTEST ?= cargo nextest
COVERAGE_TOOLCHAIN ?= nightly-2026-08-30
CLIPPY ?= cargo clippy
CLI_TARGET ?= x86_64-unknown-linux-gnu
CLI_DIST_BINARY ?= target/$(CLI_TARGET)/dist/verdictan
CLI_PAYLOAD_DIR ?= dist-payload/cli

CI_CARGO_HOME ?= /mnt/Work/verdictan/cargo
CI_RUSTUP_HOME ?= /mnt/Work/verdictan/rustup
CI_CARGO_TARGET_DIR ?= /mnt/Work/verdictan/target
CI_ENV = CARGO_HOME=$(CI_CARGO_HOME) \
         RUSTUP_HOME=$(CI_RUSTUP_HOME) \
         CARGO_TARGET_DIR=$(CI_CARGO_TARGET_DIR) \
         CARGO_TERM_COLOR=always \
         RUSTFLAGS=-Dwarnings \
         CARGO_PROFILE_TEST_DEBUG=0

help:
	@echo "Verdictan CLI development commands"
	@echo ""
	@echo "  make check              cargo check --tests"
	@echo "  make fmt                cargo fmt"
	@echo "  make fmt-check          cargo fmt --check"
	@echo "  make clippy             cargo clippy --all-targets -- -D warnings"
	@echo "  make clippy-production  cargo clippy for isolated feature lanes"
	@echo "  make test-default       nextest with default features (all optional features on)"
	@echo "  make test-doc           cargo test --doc"
	@echo "  make test-distributed   nextest with distributed only (--no-default-features)"
	@echo "  make test-otlp          nextest with otlp only (--no-default-features)"
	@echo "  make test-embedding-external  nextest with embedding-external only (--no-default-features)"
	@echo "  make deny               cargo deny check"
	@echo "  make spdx-check         verify SPDX headers in src/"
	@echo "  make third-party-check  verify THIRD_PARTY_NOTICES.md"
	@echo "  make runtime-payload    pack a prebuilt cargo-dist Linux binary"
	@echo "  make runtime-payload-verify  verify the payload manifest and hashes"
	@echo "  make runtime-image      assemble the verified payload without Cargo"
	@echo ""
	@echo "Jenkins CI mirror:"
	@echo "  make ci-check           full CI sequence: fmt, clippy matrix, nextest ci profile"
	@echo "                          lanes, doc tests, deny, SPDX, third-party notices"
	@echo "  make ci-check-fast      compatibility alias for ci-check"
	@echo "  Excludes: gitleaks secret scan (self-hosted CI only), DCO (PR only)"

check:
	$(CARGO) check --tests

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

clippy:
	$(CLIPPY) --all-targets -- -D warnings

clippy-production:
	$(CLIPPY) --no-default-features --features distributed -- -D warnings
	$(CLIPPY) --no-default-features --features otlp -- -D warnings
	$(CLIPPY) --no-default-features --features embedding-external -- -D warnings

test-default:
	$(NEXTEST) run --profile fast

test-doc:
	$(CARGO) test --doc

test-distributed:
	$(NEXTEST) run --profile fast --no-default-features --features distributed

test-otlp:
	$(NEXTEST) run --profile fast --no-default-features --features otlp

test-embedding-external:
	$(NEXTEST) run --profile fast --no-default-features --features embedding-external

cli-e2e-inventory:
	mkdir -p reports/quality
	$(NEXTEST) list --color never > reports/quality/nextest-inventory.txt
	ruby ci/scripts/verify_cli_e2e_matrix.rb fixtures/cli-e2e/command-matrix.yaml reports/quality/nextest-inventory.txt
	$(NEXTEST) run --profile ci -E 'test(/^cli_e2e_tests::cli_e2e_inventory/)'

cli-e2e-in-process:
	$(NEXTEST) run --profile ci -E 'test(/^cli_e2e_tests::cli_e2e_in_process/)'

cli-e2e-process:
	@target_dir="$${CARGO_TARGET_DIR:-target}"; \
	case "$$target_dir" in /*) ;; *) target_dir="$$(pwd)/$$target_dir" ;; esac; \
	e2e_target_dir="$$target_dir/cli-e2e"; \
	RUSTFLAGS="$${RUSTFLAGS:+$$RUSTFLAGS }--cfg verdictan_cli_e2e" \
		CARGO_TARGET_DIR="$$e2e_target_dir" $(CARGO) build --bin verdictan --bin verdictan-update; \
	VERDICTAN_E2E_BIN="$$e2e_target_dir/debug/verdictan" \
	VERDICTAN_E2E_UPDATE_BIN="$$e2e_target_dir/debug/verdictan-update" \
		$(NEXTEST) run --profile ci -E 'test(/^cli_e2e_tests::cli_e2e_process/)'
	mkdir -p reports/quality
	@report=""; \
	for root in "$${CARGO_TARGET_DIR:-target}" target; do \
	  if test -d "$$root/nextest"; then \
	    report="$$(find "$$root/nextest" -type f -path '*/target/nextest/ci/cli-junit.xml' -print -quit)"; \
	  fi; \
	  test -z "$$report" || break; \
	done; \
	test -n "$$report"; \
	cp "$$report" reports/quality/junit.xml

cli-e2e: ci-check-cli-e2e

ci-check-cli-e2e:
	mkdir -p reports/quality
	$(NEXTEST) list --color never > reports/quality/nextest-inventory.txt
	ruby ci/scripts/verify_cli_e2e_matrix.rb fixtures/cli-e2e/command-matrix.yaml reports/quality/nextest-inventory.txt
	@target_dir="$${CARGO_TARGET_DIR:-target}"; \
	case "$$target_dir" in /*) ;; *) target_dir="$$(pwd)/$$target_dir" ;; esac; \
	e2e_target_dir="$$target_dir/cli-e2e"; \
	RUSTFLAGS="$${RUSTFLAGS:+$$RUSTFLAGS }--cfg verdictan_cli_e2e" \
		CARGO_TARGET_DIR="$$e2e_target_dir" $(CARGO) build --bin verdictan --bin verdictan-update; \
	VERDICTAN_E2E_BIN="$$e2e_target_dir/debug/verdictan" \
	VERDICTAN_E2E_UPDATE_BIN="$$e2e_target_dir/debug/verdictan-update" \
		$(NEXTEST) run --profile ci
	mkdir -p reports/quality
	@report=""; \
	for root in "$${CARGO_TARGET_DIR:-target}" target; do \
	  if test -d "$$root/nextest"; then \
	    report="$$(find "$$root/nextest" -type f -path '*/target/nextest/ci/cli-junit.xml' -print -quit)"; \
	  fi; \
	  test -z "$$report" || break; \
	done; \
	test -n "$$report"; \
	cp "$$report" reports/quality/junit.xml

coverage-clean:
	$(CARGO) +$(COVERAGE_TOOLCHAIN) llvm-cov clean --workspace
	rm -rf reports/quality

coverage-test: coverage-clean
	$(CARGO) +$(COVERAGE_TOOLCHAIN) llvm-cov nextest --branch --no-report --profile fast
	$(CARGO) +$(COVERAGE_TOOLCHAIN) llvm-cov nextest --branch --no-report --profile fast --no-default-features --features distributed
	$(CARGO) +$(COVERAGE_TOOLCHAIN) llvm-cov nextest --branch --no-report --profile fast --no-default-features --features otlp
	$(CARGO) +$(COVERAGE_TOOLCHAIN) llvm-cov nextest --branch --no-report --profile fast --no-default-features --features embedding-external
	$(MAKE) cli-e2e

coverage-report:
	mkdir -p reports/quality
	rm -rf reports/quality/html reports/quality/coverage-html
	$(CARGO) +$(COVERAGE_TOOLCHAIN) llvm-cov report --branch --cobertura --output-path reports/quality/coverage.xml
	ruby ci/scripts/normalize_cobertura.rb --self-test
	ruby ci/scripts/normalize_cobertura.rb reports/quality/coverage.xml
	$(CARGO) +$(COVERAGE_TOOLCHAIN) llvm-cov report --branch --lcov --output-path reports/quality/lcov.info
	$(CARGO) +$(COVERAGE_TOOLCHAIN) llvm-cov report --branch --json --output-path reports/quality/coverage-summary.json
	$(CARGO) +$(COVERAGE_TOOLCHAIN) llvm-cov report --branch --html --output-dir reports/quality
	mv reports/quality/html reports/quality/coverage-html

coverage-check: coverage-test coverage-report

deny:
	cargo deny check

spdx-check:
	bash ci/scripts/check_spdx_headers.sh

third-party-check:
	bash ci/scripts/check_third_party_notices.sh

runtime-payload:
	@set -eu; \
	  : "$${SOURCE_SHA:?SOURCE_SHA is required}"; \
	  : "$${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"; \
	  : "$${BUILD_INPUT_DIGEST:?BUILD_INPUT_DIGEST is required}"; \
	  : "$${TOOLCHAIN_ID:?TOOLCHAIN_ID is required}"; \
	  : "$${BUILDER_ID:?BUILDER_ID is required}"; \
	  : "$${INVOCATION_ID:?INVOCATION_ID is required}"; \
	  python3 ci/scripts/runtime_payload.py pack \
	    --repo-root . \
	    --binary "$(CLI_DIST_BINARY)" \
	    --output "$(CLI_PAYLOAD_DIR)" \
	    --target "$(CLI_TARGET)" \
	    --source-sha "$$SOURCE_SHA" \
	    --source-date-epoch "$$SOURCE_DATE_EPOCH" \
	    --build-input-digest "$$BUILD_INPUT_DIGEST" \
	    --toolchain "$$TOOLCHAIN_ID" \
	    --runtime-base "debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171" \
	    --builder-id "$$BUILDER_ID" \
	    --invocation-id "$$INVOCATION_ID"

runtime-payload-verify:
	python3 ci/scripts/runtime_payload.py verify "$(CLI_PAYLOAD_DIR)"

runtime-payload-test:
	python3 ci/scripts/runtime_payload.py self-test

runtime-image: runtime-payload-verify
	@set -eu; : "$${IMAGE:?IMAGE is required}"; \
	  docker build --load --file Dockerfile.hosted \
	    --build-arg CLI_PAYLOAD_DIR="$(CLI_PAYLOAD_DIR)" \
	    --tag "$$IMAGE" .

runtime-image-verify: runtime-payload-verify
	python3 ci/scripts/runtime_payload.py verify-image \
	  --image "$${IMAGE:?IMAGE is required}" \
	  "$(CLI_PAYLOAD_DIR)"

# --- Jenkins CI mirror ------------------------------------------------------

ci-check: ci-check-fmt ci-check-clippy-all-targets ci-check-clippy-production ci-check-compile \
	ci-check-test-default ci-check-test-distributed ci-check-test-otlp \
	ci-check-test-embedding-external \
	ci-check-doc ci-check-deny ci-check-spdx ci-check-third-party

ci-check-fast: ci-check

ci-check-fmt:
	$(CI_ENV) $(CARGO) fmt --check

ci-check-clippy-all-targets:
	$(CI_ENV) $(CLIPPY) --all-targets -- -D warnings

ci-check-clippy-production:
	$(CI_ENV) $(CLIPPY) --no-default-features --features distributed -- -D warnings
	$(CI_ENV) $(CLIPPY) --no-default-features --features otlp -- -D warnings
	$(CI_ENV) $(CLIPPY) --no-default-features --features embedding-external -- -D warnings

ci-check-compile:
	$(CI_ENV) $(CARGO) check --tests

ci-check-test-default:
	$(CI_ENV) $(NEXTEST) run --profile ci-default

ci-check-test-distributed:
	$(CI_ENV) $(NEXTEST) run --profile ci-distributed --no-default-features --features distributed

ci-check-test-otlp:
	$(CI_ENV) $(NEXTEST) run --profile ci-otlp --no-default-features --features otlp

ci-check-test-embedding-external:
	$(CI_ENV) $(NEXTEST) run --profile ci-embedding-external --no-default-features --features embedding-external

ci-check-doc:
	$(CI_ENV) $(CARGO) test --doc

ci-check-deny:
	$(CI_ENV) cargo deny --all-features check

ci-check-spdx:
	bash ci/scripts/check_spdx_headers.sh

ci-check-third-party:
	$(CI_ENV) bash ci/scripts/check_third_party_notices.sh
