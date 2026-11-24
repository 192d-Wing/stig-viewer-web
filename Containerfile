# Production image for stig-viewer-web: the backend plus the release wasm
# frontend, served same-origin by the backend (STIG_STATIC_DIR). Three stages:
#
#   frontend  rust:slim-trixie       builds the wasm bundle with Trunk (UBI ships
#                                    no wasm32 std; the output is OS-independent)
#   backend   ubi10/ubi              builds the Rust backend with Red Hat's rust
#                                    RPMs, on the same glibc as the runtime
#   runtime   ubi10/ubi-micro        binary + static files only, no RUN steps
#
# Build (podman; --format docker keeps the HEALTHCHECK, OCI images drop it):
#   podman build --format docker -t stig-viewer-web:dev -f Containerfile .
#   podman build --format docker --build-arg CRYPTO=fips -t stig-viewer-web:dev-fips -f Containerfile .
#
# Refresh the pinned digests. Each pin is the multi-arch image INDEX digest (not
# a per-architecture manifest, which would break builds on the other arch):
#   curl -sSI -H 'Accept: application/vnd.oci.image.index.v1+json' \
#     https://registry.access.redhat.com/v2/ubi10/ubi/manifests/latest | grep -i docker-content-digest
#   (same with ubi10/ubi-micro; for the rust image use the Docker Hub token flow
#    against registry-1.docker.io/v2/library/rust/manifests/<tag>)
# then confirm with `podman manifest inspect <ref>@<digest>` that amd64 and
# arm64 are both listed.
#
# Dependabot is not configured for this file (its docker ecosystem is documented
# for files named Dockerfile). All three base digests, including the
# rust:<ver>-slim-trixie one, are refreshed by hand with the command above
# (for rust: curl -sSI -H 'Accept: application/vnd.oci.image.index.v1+json'
# -H "Authorization: Bearer $TOKEN" \
# https://registry-1.docker.io/v2/library/rust/manifests/<tag>, token from
# https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/rust:pull).
#
# Iron Bank / hardened bases: `podman login registry1.dso.mil`, then pass
#   --build-arg BACKEND_BUILD_BASE=<registry1 ubi10 path>@sha256:...
#   --build-arg RUNTIME_BASE=<registry1 ubi10-micro path>@sha256:...
# The paths are the operator's to fill in. This only swaps base images; it is
# not an Iron Bank submission (that is a separate offline pipeline).
#
# Migrations: `<image> migrate` runs them as the owner role (docs/deployment.md).

ARG BACKEND_BUILD_BASE=registry.access.redhat.com/ubi10/ubi@sha256:87ceab8634a53a36c75a8ba7282f09f11c46ab3e8906db6c6d2b3cd2a7dc4f4e
ARG RUNTIME_BASE=registry.access.redhat.com/ubi10/ubi-micro@sha256:2ad0f98cb13160c4773c945ef93f88b25831c7f27cd3780d72a7e78b210ea72b

# ---- frontend -------------------------------------------------------------
FROM rust:1.100.0-slim-trixie@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS frontend

ARG TRUNK_VERSION=0.22.1
# SHA-256 of trunk-<arch>-unknown-linux-musl.tar.gz for TRUNK_VERSION. Recompute
# from the release assets when bumping TRUNK_VERSION.
ARG TRUNK_SHA256_X86_64=a1fe5cd6b053f5a76f66b598d296022a7f06f56def6013cc16cd6897d53f5363
ARG TRUNK_SHA256_AARCH64=8c84a939aaf48bbdac2d78195c932adb319e610fb2cbf791bae07b2660cf3e46
# wasm-bindgen-cli must equal the wasm-bindgen version in frontend/Cargo.lock.
# Asset names: wasm-bindgen-<ver>-x86_64-unknown-linux-musl / -aarch64-unknown-linux-gnu.
ARG WASM_BINDGEN_VERSION=0.2.130
ARG WASM_BINDGEN_SHA256_X86_64=9687f3bb551b9f66f37ed32a40d7913a00f7962db653054e56857bc306c3227f
ARG WASM_BINDGEN_SHA256_AARCH64=cc8dd8e90aa9111758168d30c63a14b7f0276997d9d60d3e160a1fb5e7d3b919
# Binaryen (wasm-opt), the version Trunk 0.22.1 fetches itself.
# Asset names: binaryen-<ver>-x86_64-linux / -aarch64-linux.
ARG BINARYEN_VERSION=version_131
ARG BINARYEN_SHA256_X86_64=b5bf1f0eaf17c63ee588ff7a5954dc8f6ce2c26989051c66f24dfe9ece3e46db
ARG BINARYEN_SHA256_AARCH64=ba991f677edd9a21d2bc96c0144bc8ac5b112d4d98a3eb266e075e22e557df2a
# Empty = same origin: every request is relative and connect-src is 'self'.
ARG API_URL=""

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown

RUN set -eu; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64) want="$TRUNK_SHA256_X86_64" ;; \
        aarch64) want="$TRUNK_SHA256_AARCH64" ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL -o /tmp/trunk.tar.gz \
        "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-${arch}-unknown-linux-musl.tar.gz"; \
    echo "${want}  /tmp/trunk.tar.gz" | sha256sum -c -; \
    tar -xz -C /usr/local/bin -f /tmp/trunk.tar.gz trunk; \
    rm /tmp/trunk.tar.gz

# wasm-bindgen and wasm-opt, checksum-verified like Trunk, so Trunk finds them
# on PATH and the build below runs offline (nothing is fetched unverified).
RUN set -eu; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64) wb_triple=x86_64-unknown-linux-musl; wb_sha="$WASM_BINDGEN_SHA256_X86_64"; bin_sha="$BINARYEN_SHA256_X86_64" ;; \
        aarch64) wb_triple=aarch64-unknown-linux-gnu; wb_sha="$WASM_BINDGEN_SHA256_AARCH64"; bin_sha="$BINARYEN_SHA256_AARCH64" ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    wb="wasm-bindgen-${WASM_BINDGEN_VERSION}-${wb_triple}"; \
    curl --proto '=https' --tlsv1.2 -fsSL -o /tmp/wb.tar.gz \
        "https://github.com/rustwasm/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/${wb}.tar.gz"; \
    echo "${wb_sha}  /tmp/wb.tar.gz" | sha256sum -c -; \
    tar -xz -C /usr/local/bin --strip-components=1 -f /tmp/wb.tar.gz "${wb}/wasm-bindgen"; \
    bn="binaryen-${BINARYEN_VERSION}"; \
    curl --proto '=https' --tlsv1.2 -fsSL -o /tmp/bn.tar.gz \
        "https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/${bn}-${arch}-linux.tar.gz"; \
    echo "${bin_sha}  /tmp/bn.tar.gz" | sha256sum -c -; \
    tar -xz -C /usr/local/bin --strip-components=2 -f /tmp/bn.tar.gz "${bn}/bin/wasm-opt"; \
    rm /tmp/wb.tar.gz /tmp/bn.tar.gz; \
    wasm-bindgen --version; wasm-opt --version

WORKDIR /src/frontend
COPY frontend/ ./
RUN TRUNK_OFFLINE=true API_URL="$API_URL" trunk build --release --locked --dist /out/static

# ---- backend --------------------------------------------------------------
FROM ${BACKEND_BUILD_BASE} AS backend

# The Rust version is whatever UBI AppStream ships at build time (the base
# digest does not pin dnf content); the MSRV check below catches a downgrade.
RUN dnf -y install --nodocs --setopt=install_weak_deps=0 \
        rust cargo cmake clang clang-devel golang perl make gcc \
    && dnf clean all

# Declared after the dnf layer so changing them does not rebuild it.
# non-fips: default features. fips: AWS-LC-FIPS (see docs/deployment.md).
ARG CRYPTO=non-fips
# Optional cap on parallel rustc jobs for small build machines.
ARG CARGO_BUILD_JOBS=

WORKDIR /src/backend
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/src ./src
COPY backend/migrations ./migrations
COPY backend/stig-sources.toml ./

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/src/backend/target \
    set -eu; \
    have="$(rustc --version | awk '{print $2}')"; \
    need="$(sed -n 's/^rust-version *= *"\([0-9.]*\)".*/\1/p' Cargo.toml)"; \
    echo "rustc ${have}, MSRV ${need}"; \
    [ -n "$need" ]; \
    [ "$(printf '%s\n%s\n' "$need" "$have" | sort -V | head -n1)" = "$need" ]; \
    case "$CRYPTO" in \
        non-fips) features="" ;; \
        fips) features="--no-default-features --features fips" ;; \
        *) echo "CRYPTO must be non-fips or fips, got: $CRYPTO" >&2; exit 1 ;; \
    esac; \
    # shellcheck disable=SC2086
    cargo build --release --locked ${CARGO_BUILD_JOBS:+--jobs "$CARGO_BUILD_JOBS"} $features; \
    mkdir -p /out/data; \
    # Toolchain record, shipped as /app/BUILD-INFO (a LABEL cannot take RUN output).
    { echo "crypto=$CRYPTO"; \
      echo "rustc=$(rustc --version)"; echo "cargo=$(cargo --version)"; \
      echo "gcc=$(gcc --version | head -n1)"; echo "clang=$(clang --version | head -n1)"; \
      echo "go=$(go version)"; \
      grep -A1 -E '^name = "(aws-lc-rs|aws-lc-sys|aws-lc-fips-sys)"$' Cargo.lock \
        | grep -v '^--' | paste -sd' ' | sed 's/name = //g; s/version = /=/g; s/" "/ /g' | tr -d '"' ; \
    } > /out/BUILD-INFO; \
    cat /out/BUILD-INFO; \
    cp target/release/stig-viewer-backend /out/stig-viewer-backend; \
    # Only libc, libm, libgcc_s and the loader may be linked dynamically.
    ldd /out/stig-viewer-backend; \
    extra="$(ldd /out/stig-viewer-backend | awk '{print $1}' | grep -Ev '^(linux-vdso|libc\.so|libm\.so|libgcc_s\.so)|/?ld-linux' || true)"; \
    if [ -n "$extra" ]; then echo "unexpected shared libraries: $extra" >&2; exit 1; fi

# ---- runtime --------------------------------------------------------------
FROM ${RUNTIME_BASE} AS runtime

ARG CRYPTO=non-fips
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="stig-viewer-web" \
      org.opencontainers.image.description="STIG Viewer backend with the release web frontend" \
      org.opencontainers.image.revision="${VCS_REF}" \
      io.stig-viewer-web.crypto="${CRYPTO}"

COPY --from=backend /out/stig-viewer-backend /usr/local/bin/stig-viewer-backend
# load_sources() reads stig-sources.toml relative to the working directory.
COPY --from=backend /src/backend/stig-sources.toml /app/stig-sources.toml
COPY --from=frontend /out/static /app/static
# Compiler and crypto-library versions the binary was built with.
COPY --from=backend /out/BUILD-INFO /app/BUILD-INFO
# The only writable path: STIG JSON, drafts, attachments, audit archive.
# Group 0 writable so an arbitrary uid with gid 0 (OpenShift) works too.
COPY --from=backend --chown=1001:0 --chmod=0770 /out/data /data

WORKDIR /app
USER 1001:0

ENV PORT=8080 \
    DATA_DIR=/data \
    STIG_STATIC_DIR=/app/static \
    STIG_ENV=production

EXPOSE 8080
VOLUME /data
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/stig-viewer-backend", "healthcheck"]

# Exec form so SIGTERM reaches the process.
ENTRYPOINT ["/usr/local/bin/stig-viewer-backend"]
