# syntax=docker/dockerfile:1
FROM rust:alpine as build
ARG TARGETPLATFORM

RUN apk update && apk add git
RUN git clone -b develop --single-branch https://github.com/viridIT/vSMTP.git
WORKDIR /vSMTP

# Add dependencies
RUN apk update && apk add musl-dev

# Run cargo
RUN cargo install --force cargo-strip
RUN cargo build --all --release
RUN cargo strip

# Copy the binaries to a slimer image
FROM alpine

RUN apk update && apk add cyrus-sasl

RUN adduser -D -H vsmtp

RUN mkdir /var/log/vsmtp/ && chown vsmtp:vsmtp /var/log/vsmtp/ && chmod 755 /var/log/vsmtp/
RUN mkdir /var/spool/vsmtp/ && chown vsmtp:vsmtp /var/spool/vsmtp/ && chmod 755 /var/spool/vsmtp/
RUN mkdir /etc/vsmtp/ && chown vsmtp:vsmtp /etc/vsmtp/ && chmod 755 /etc/vsmtp/

COPY --from=build vSMTP/target/release/vsmtp /usr/sbin/vsmtp
COPY --from=build vSMTP/target/release/vqueue /usr/sbin/vqueue
COPY --from=build vSMTP/examples/config/minimal.toml /etc/vsmtp/vsmtp.toml

EXPOSE 25/tcp 465/tcp 587/tcp
