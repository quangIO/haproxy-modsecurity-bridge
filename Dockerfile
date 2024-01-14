FROM rust:slim as builder
    MAINTAINER Quang Luong <quang@nyu.edu>

RUN apt update && apt install -y haproxy clang libmodsecurity-dev

ENV HOME=/home/root

WORKDIR $HOME/app

ADD src src
ADD Cargo.lock .
ADD Cargo.toml .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/home/root/app/target \
    cargo build --release && cp target/release/*.so .

FROM haproxy:2.9
ENTRYPOINT ["docker-entrypoint.sh"]
USER haproxy
WORKDIR /var/lib/haproxy

COPY haproxy.lua /var/lib/haproxy
COPY --from=builder /home/root/app/libhaproxy_modsecurity.so /var/lib/haproxy

CMD ["haproxy", "-f", "/usr/etc/haproxy.cfg"]
