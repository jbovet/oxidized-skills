# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
#
# Compiles a fully static binary using the musl libc target so the final image
# can use `scratch` (zero OS layer) and stay under ~10 MB.
#
# Supports both amd64 (x86_64) and arm64 (aarch64) host builders — the musl
# target is selected automatically from the builder's native architecture.
#
# Layer-caching trick: copy Cargo manifests first and compile a stub main.rs to
# cache the slow dependency compilation step.  Real source is copied afterward
# so that changing application code does not bust the dependency layer.
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1.93.1-slim-bookworm AS builder

# musl-tools provides the musl-gcc wrapper required by the musl target.
# ca-certificates is copied into the scratch image so TLS roots are available.
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Select the correct musl Rust target for the builder's native architecture.
# On amd64 hosts: x86_64-unknown-linux-musl
# On arm64 hosts: aarch64-unknown-linux-musl
RUN case "$(uname -m)" in \
      x86_64)  echo "x86_64-unknown-linux-musl"  > /musl-target ;; \
      aarch64) echo "aarch64-unknown-linux-musl" > /musl-target ;; \
      *)        echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;; \
    esac && \
    rustup target add "$(cat /musl-target)"

WORKDIR /build

# ── dependency caching layer ──────────────────────────────────────────────────
# Copy only the manifest files and build a dummy binary.  Docker will reuse
# this layer on subsequent builds as long as Cargo.toml / Cargo.lock are unchanged.
COPY Cargo.toml Cargo.lock ./
RUN MUSL_TARGET="$(cat /musl-target)" && \
    mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    cargo build --release --target "$MUSL_TARGET" && \
    rm -rf src \
           "target/${MUSL_TARGET}/release/oxidized-skills" \
           "target/${MUSL_TARGET}/release/deps/oxidized_skills"*

# ── real build ────────────────────────────────────────────────────────────────
COPY src ./src
RUN MUSL_TARGET="$(cat /musl-target)" && \
    cargo build --release --target "$MUSL_TARGET"

# Strip debug symbols — reduces binary from ~12 MB to ~5–7 MB.
RUN MUSL_TARGET="$(cat /musl-target)" && \
    strip "target/${MUSL_TARGET}/release/oxidized-skills" && \
    cp "target/${MUSL_TARGET}/release/oxidized-skills" /oxidized-skills

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime (scratch — zero OS layer)
#
# Contains only:
#   • the static binary
#   • TLS CA certificates (copied from the builder)
#
# Final image size: ~8 MB
# Core scanners (bash_patterns, prompt, package_install, frontmatter) are fully
# functional.  External tool scanners (shellcheck, gitleaks, semgrep) are
# auto-skipped because the tools are not present.  Use Dockerfile.full if you
# need those scanners.
# ─────────────────────────────────────────────────────────────────────────────
FROM scratch

# TLS roots — required if any future code path makes outbound HTTPS calls.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /oxidized-skills /oxidized-skills

ENTRYPOINT ["/oxidized-skills"]
