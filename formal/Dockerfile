# formal/Dockerfile — Reproducible formal verification environment
#
# Pins every tool to the exact version used in CI so that proofs are
# byte-for-byte reproducible regardless of the host.
#
# Build:
#   docker build -t vellaveto-formal formal/
#
# Run (full mesh):
#   docker run --rm -v "$(pwd):/workspace" vellaveto-formal
#
# Run (single toolchain):
#   docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-verus
#   docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-kani
#   docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-tla
#   docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-alloy
#   docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-lean
#   docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-coq
#   docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-trusted-assumptions

FROM ubuntu:24.04@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9

# ── Version pins (must match .github/workflows/formal-verification.yml) ──

ENV VERUS_VERSION="0.2026.03.01.25809cb"
ENV VERUS_SHA256="2af942e6919b203b1732d1176817abd09e66fe890fc8021a4aa8e2aac7f7cbb1"
ENV KANI_VERSION="0.67.0"
ENV TLA_VERSION="v1.7.4"
ENV TLA_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
ENV ALLOY_VERSION="6.2.0"
ENV ALLOY_SHA256="6b8c1cb5bc93bedfc7c61435c4e1ab6e688a242dc702a394628d9a9801edb78d"
ENV ELAN_VERSION="v4.2.0"
ENV ELAN_SHA256="620db834935d0da55ac9cda207b2e370e8034061cbb0228af5eb6c14b02f0c0c"
ENV RUSTUP_INIT_SHA256="17247e4bcacf6027ec2e11c79a72c494c9af69ac8d1abcc1b271fa4375a106c2"
ENV RUST_WORKSPACE_TOOLCHAIN="1.94.0"
ENV RUST_VERUS_TOOLCHAIN="1.93.1"

# ── System packages ──

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        coq \
        curl \
        git \
        libssl-dev \
        openjdk-21-jre-headless \
        pkg-config \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Rust (workspace toolchain + Verus toolchain) ──

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh \
    && echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init.sh" | sha256sum -c - \
    && sh /tmp/rustup-init.sh -y --default-toolchain "${RUST_WORKSPACE_TOOLCHAIN}" \
    && rm /tmp/rustup-init.sh \
    && /root/.cargo/bin/rustup install "${RUST_VERUS_TOOLCHAIN}-x86_64-unknown-linux-gnu" \
    && /root/.cargo/bin/rustup component add rustfmt clippy \
        --toolchain "${RUST_WORKSPACE_TOOLCHAIN}-x86_64-unknown-linux-gnu"

ENV PATH="/root/.cargo/bin:${PATH}"

# ── Verus (SHA256-verified binary release) ──

RUN curl -fsSL --retry 3 --retry-delay 2 -o /tmp/verus.zip \
        "https://github.com/verus-lang/verus/releases/download/release/${VERUS_VERSION}/verus-${VERUS_VERSION}-x86-linux.zip" \
    && echo "${VERUS_SHA256}  /tmp/verus.zip" | sha256sum -c - \
    && unzip -q /tmp/verus.zip -d /opt/verus \
    && chmod +x /opt/verus/verus-x86-linux/verus /opt/verus/verus-x86-linux/cargo-verus \
    && rm /tmp/verus.zip

ENV VERUS_BIN="/opt/verus/verus-x86-linux/verus"
ENV CARGO_VERUS_BIN="/opt/verus/verus-x86-linux/cargo-verus"

# ── Kani ──

RUN cargo install --locked kani-verifier --version "${KANI_VERSION}" \
    && cargo kani setup

# ── TLA+ (SHA256-verified tla2tools.jar) ──

RUN mkdir -p /opt/tla \
    && curl -fsSL --retry 3 --retry-delay 2 -o /opt/tla/tla2tools.jar \
        "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar" \
    && echo "${TLA_SHA256}  /opt/tla/tla2tools.jar" | sha256sum -c -

# ── Alloy Analyzer (SHA256-verified jar) ──

RUN mkdir -p /opt/alloy \
    && curl -fsSL --retry 3 --retry-delay 2 -o /opt/alloy/alloy.jar \
        "https://github.com/AlloyTools/org.alloytools.alloy/releases/download/v${ALLOY_VERSION}/org.alloytools.alloy.dist.jar" \
    && echo "${ALLOY_SHA256}  /opt/alloy/alloy.jar" | sha256sum -c -

ENV ALLOY_JAR="/opt/alloy/alloy.jar"

# ── Lean 4 (via elan, SHA256-verified) ──

RUN curl -fsSL --retry 3 --retry-delay 2 -o /tmp/elan.tar.gz \
        "https://github.com/leanprover/elan/releases/download/${ELAN_VERSION}/elan-x86_64-unknown-linux-gnu.tar.gz" \
    && echo "${ELAN_SHA256}  /tmp/elan.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/elan.tar.gz -C /tmp \
    && /tmp/elan-init -y --default-toolchain none \
    && rm /tmp/elan.tar.gz /tmp/elan-init

ENV PATH="/root/.elan/bin:${PATH}"

# ── Entrypoint ──

WORKDIR /workspace

COPY tools/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["make", "formal"]
