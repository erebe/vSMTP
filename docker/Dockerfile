# syntax=docker/dockerfile:1
FROM rust:alpine as build

RUN apk update && apk add git

ARG VSMTP_BRANCH=main
RUN git clone -b $VSMTP_BRANCH --single-branch https://github.com/viridIT/vSMTP.git
WORKDIR /vSMTP

# Add dependencies
RUN apk update && apk add musl-dev

ENV RUSTFLAGS="-C target-feature=-crt-static"

# Run cargo
RUN cargo install --force cargo-strip
RUN cargo build --all --release
RUN cargo strip

# Copy the binaries to a slimer image
FROM alpine

RUN apk upgrade --no-cache && apk add --no-cache libgcc

RUN adduser -D -H vsmtp

RUN mkdir /var/log/vsmtp/ && chown vsmtp:vsmtp /var/log/vsmtp/ && chmod 755 /var/log/vsmtp/
RUN mkdir /var/spool/vsmtp/ && chown vsmtp:vsmtp /var/spool/vsmtp/ && chmod 755 /var/spool/vsmtp/
RUN mkdir /etc/vsmtp/ && chown vsmtp:vsmtp /etc/vsmtp/ && chmod 755 /etc/vsmtp/

COPY --from=build vSMTP/target/release/vsmtp /usr/sbin/vsmtp
COPY --from=build vSMTP/target/release/vqueue /usr/sbin/vqueue
COPY --from=build vSMTP/target/release/*.so /usr/lib/vsmtp/

# Update configuration.
RUN mkdir -p /etc/vsmtp/
RUN ln -s /usr/lib/vsmtp/ /etc/vsmtp/plugins
COPY --from=build vSMTP/examples/config/minimal.vsl /etc/vsmtp/vsmtp.vsl

RUN vsmtp --version

EXPOSE 25/tcp 465/tcp 587/tcp

CMD ["vsmtp", "-c", "/etc/vsmtp/vsmtp.vsl", "--no-daemon", "--stdout"]
