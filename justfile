# oxidized-skills justfile
# Install just: https://github.com/casey/just

default: fmt lint test

# Format code
fmt:
    cargo fmt

# Check formatting without modifying files
fmt-check:
    cargo fmt --check

# Run clippy (deny warnings, matching CI)
lint:
    cargo clippy -- -D warnings

# Run all tests
test:
    cargo test

# Run fmt-check + lint + test (mirrors CI)
ci: fmt-check lint test

# Install the git pre-commit hook
install-hooks:
    cp .githooks/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    @echo "pre-commit hook installed"

# Audit the bundled test fixtures (quick smoke-test of all scanners)
audit:
    cargo run -- audit tests/fixtures/

# List all built-in rules with severity and description
list-rules:
    cargo run -- list-rules

# Check which external scanner tools are available on this machine
check-tools:
    cargo run -- check-tools

# Explain a specific rule (usage: just explain bash/CAT-A1)
explain rule_id:
    cargo run -- explain {{rule_id}}

# ── Docker ────────────────────────────────────────────────────────────────────

# Build the dev image (native arch, all tools — fastest local build on any machine)
# Usage: just docker-dev-build
docker-dev-build:
    docker build -f Dockerfile.dev -t oxidized-skills:dev .

# Build the slim image (~8 MB, core scanners only, scratch base)
docker-build:
    docker build -t oxidized-skills:slim .

# Build the full image (~50 MB, adds shellcheck + gitleaks, debian-slim base)
docker-build-full:
    docker build -f Dockerfile.full -t oxidized-skills:full .

# Build all Docker images
docker-build-all: docker-build docker-build-full

# Print the on-disk size of all Docker images
docker-size:
    docker images --filter "reference=oxidized-skills" --format "table {{{{.Repository}}\t{{{{.Tag}}\t{{{{.Size}}"
