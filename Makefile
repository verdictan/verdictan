.PHONY: help check fmt fmt-check clippy clippy-production test test-default test-doc \
        test-distributed test-otlp test-embedding-external test-all-features \
        cli-e2e cli-e2e-inventory cli-e2e-in-process cli-e2e-process \
        ci-check-cli-e2e coverage-clean coverage-test coverage-report coverage-check \
        test-unix deny spdx-check third-party-check \
        ci-check ci-check-fast ci-check-fmt ci-check-clippy-all-targets \
        ci-check-clippy-production ci-check-test-default ci-check-test-distributed \
        ci-check-test-otlp ci-check-test-embedding-external ci-check-test-all-features \
        ci-check-test-unix ci-check-doc ci-check-deny ci-check-spdx ci-check-third-party

CARGO ?= cargo
NEXTEST ?= cargo nextest
COVERAGE_TOOLCHAIN ?= nightly-2026-08-30
CLIPPY ?= cargo clippy

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
	@echo "  make clippy-production  cargo clippy without --all-targets (default + isolated lanes)"
	@echo "  make test-default       nextest with default features (all optional features on)"
	@echo "  make test-doc           cargo test --doc"
	@echo "  make test-distributed   nextest with distributed only (--no-default-features)"
	@echo "  make test-otlp          nextest with otlp only (--no-default-features)"
	@echo "  make test-embedding-external  nextest with embedding-external only (--no-default-features)"
	@echo "  make test-all-features  nextest with --all-features (same as default today)"
	@echo "  make test-unix          alias for test-default on Unix hosts"
	@echo "  make deny               cargo deny check"
	@echo "  make spdx-check         verify SPDX headers in src/"
	@echo "  make third-party-check  verify THIRD_PARTY_NOTICES.md"
	@echo ""
	@echo "Jenkins CI mirror:"
	@echo "  make ci-check           full CI sequence: fmt, clippy matrix, nextest ci profile"
	@echo "                          lanes, doc tests, deny, SPDX, third-party notices"
	@echo "  make ci-check-fast      same as ci-check but skips redundant all-features lane"
	@echo "                          nextest lanes"
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
	$(CLIPPY) -- -D warnings
	$(CLIPPY) --no-default-features --features distributed -- -D warnings
	$(CLIPPY) --no-default-features --features otlp -- -D warnings
	$(CLIPPY) --no-default-features --features embedding-external -- -D warnings

test-default: check
	$(NEXTEST) run --profile fast

test-doc:
	$(CARGO) test --doc

test-distributed:
	$(NEXTEST) run --profile fast --no-default-features --features distributed

test-otlp:
	$(NEXTEST) run --profile fast --no-default-features --features otlp

test-embedding-external:
	$(NEXTEST) run --profile fast --no-default-features --features embedding-external

test-all-features:
	$(NEXTEST) run --profile fast --all-features

test-unix: test-default

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

# --- Jenkins CI mirror ------------------------------------------------------

ci-check: ci-check-fmt ci-check-clippy-all-targets ci-check-clippy-production \
	ci-check-test-default ci-check-test-distributed ci-check-test-otlp \
	ci-check-test-embedding-external ci-check-test-all-features ci-check-test-unix \
	ci-check-doc ci-check-deny ci-check-spdx ci-check-third-party

ci-check-fast: ci-check-fmt ci-check-clippy-all-targets ci-check-clippy-production \
	ci-check-test-default ci-check-test-distributed ci-check-test-otlp \
	ci-check-test-embedding-external ci-check-doc ci-check-deny ci-check-spdx \
	ci-check-third-party

ci-check-fmt:
	$(CI_ENV) $(CARGO) fmt --check

ci-check-clippy-all-targets:
	$(CI_ENV) $(CLIPPY) --all-targets -- -D warnings

ci-check-clippy-production:
	$(CI_ENV) $(CLIPPY) -- -D warnings
	$(CI_ENV) $(CLIPPY) --no-default-features --features distributed -- -D warnings
	$(CI_ENV) $(CLIPPY) --no-default-features --features otlp -- -D warnings
	$(CI_ENV) $(CLIPPY) --no-default-features --features embedding-external -- -D warnings

ci-check-test-default:
	$(CI_ENV) $(CARGO) check --tests
	$(CI_ENV) $(NEXTEST) run --profile ci-default

ci-check-test-distributed:
	$(CI_ENV) $(CARGO) check --tests
	$(CI_ENV) $(NEXTEST) run --profile ci-distributed --no-default-features --features distributed

ci-check-test-otlp:
	$(CI_ENV) $(CARGO) check --tests
	$(CI_ENV) $(NEXTEST) run --profile ci-otlp --no-default-features --features otlp

ci-check-test-embedding-external:
	$(CI_ENV) $(CARGO) check --tests
	$(CI_ENV) $(NEXTEST) run --profile ci-embedding-external --no-default-features --features embedding-external

ci-check-test-all-features:
	$(CI_ENV) $(CARGO) check --tests
	$(CI_ENV) $(NEXTEST) run --profile ci-all-features --all-features

ci-check-test-unix:
	$(CI_ENV) $(CARGO) check --tests
	$(CI_ENV) $(NEXTEST) run --profile ci

ci-check-doc:
	$(CI_ENV) $(CARGO) test --doc

ci-check-deny:
	$(CI_ENV) cargo deny --all-features check

ci-check-spdx:
	bash ci/scripts/check_spdx_headers.sh

ci-check-third-party:
	$(CI_ENV) bash ci/scripts/check_third_party_notices.sh
