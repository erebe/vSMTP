FROM rust:1.60 AS builder
RUN apt update && \
    apt install -y pkg-config build-essential libssl-dev libgsasl7-dev libsasl2-2 sasl2-bin libclang-dev && \
    apt clean && \
    rm rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY Cargo.toml .
COPY Cargo.lock .
COPY ./src ./src
RUN cargo build --all --release

# copy the compiled binary into a slim(er) image
# although unfortunately we will still need to install basically all of the same runtime dependencies
FROM debian:bullseye-slim
RUN apt update && \
    apt install -y adduser pkg-config build-essential libssl-dev libgsasl7-dev libsasl2-2 sasl2-bin libclang-dev && \
    apt clean && \
    rm rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# copy the compiled binaries from the builder image
COPY --from=builder /target/release/vsmtp /usr/sbin/vsmtp
COPY --from=builder /target/release/vqueue /usr/sbin/vqueue

# create the vsmtp user
RUN adduser --system --shell /usr/sbin/nologin --no-create-home --group \
    --disabled-password --disabled-login --no-create-home --home /noexistent vsmtp
# create the log, spool, and data directories
RUN mkdir /var/log/vsmtp/ && chown vsmtp:vsmtp /var/log/vsmtp/ && chmod 755 /var/log/vsmtp/
RUN mkdir /var/spool/vsmtp/ && chown vsmtp:vsmtp /var/spool/vsmtp/ && chmod 755 /var/spool/vsmtp/
RUN mkdir /etc/vsmtp/ && chown vsmtp:vsmtp /etc/vsmtp/ && chmod 755 /etc/vsmtp/
# create the minimal configuration
RUN echo "version_requirement = \">=1.0.0\"" > /etc/vsmtp/vsmtp.toml && \
    chown vsmtp:vsmtp /etc/vsmtp/vsmtp.toml && \
    chmod 664 /etc/vsmtp/vsmtp.toml

USER vsmtp
EXPOSE 25
ENTRYPOINT ["vsmtp"]
# stop the container from forking and dying instantly, can be overridden
CMD ["--no-daemon", "-c", "/etc/vsmtp/vsmtp.toml"]