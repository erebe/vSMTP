# syntax=docker/dockerfile:1
ARG REDHAT_VERSION
FROM redhat/${REDHAT_VERSION}

RUN dnf install -y gcc git

# Install Rust unattended.
# https://github.com/rust-lang/rustup/issues/297#issuecomment-444818896
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install desired targets.
RUN rustup target add x86_64-unknown-linux-gnu
RUN rustup target add aarch64-unknown-linux-gnu

# Get vSMTP.
RUN git clone -b main --single-branch https://github.com/viridIT/vSMTP.git
WORKDIR /vSMTP

# Install packager.
RUN cargo install cargo-generate-rpm

# Package the app.
RUN cargo build --workspace --release --target x86_64-unknown-linux-gnu
RUN cargo generate-rpm --package src/vsmtp/vsmtp-core --target x86_64-unknown-linux-gnu

# FIXME: need to find the right linker to use for aarch64.
## RUN cargo build --workspace --release --target aarch64-unknown-linux-gnu --config target.aarch64-unknown-linux-gnu.linker=\"lld\"
## RUN cargo generate-rpm --package src/vsmtp/vsmtp-core --target aarch64-unknown-linux-gnu
