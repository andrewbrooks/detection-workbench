# Standard tasks. Everything runs through uv, so there is nothing to activate.
.DEFAULT_GOAL := help
UV ?= uv

.PHONY: help setup lint format typecheck test integration check secrets audit-deps build

help: ## List the available tasks
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

setup: ## Install locked dependencies and enable the pre-commit hook
	$(UV) sync --locked
	git config core.hooksPath .githooks

lint: ## Lint and check formatting (what CI runs)
	$(UV) run --no-sync ruff check .
	$(UV) run --no-sync ruff format --check .

format: ## Format the code in place
	$(UV) run --no-sync ruff format .

typecheck: ## Type-check src/ with mypy
	$(UV) run --no-sync mypy src

test: ## Unit and parser tests (no Snort or Docker needed)
	$(UV) run --no-sync pytest -q

integration: ## Integration tests (needs Docker or native Snort 3)
	DW_INTEGRATION=1 $(UV) run --no-sync pytest -q tests/integration

check: lint typecheck test ## Everything CI checks except the integration tests

secrets: ## Scan the repository history for secrets
	gitleaks detect --redact --no-banner

audit-deps: ## Check locked dependencies for known vulnerabilities
	$(UV) audit --preview-features audit-command

build: ## Build the wheel and sdist into dist/
	$(UV) build
