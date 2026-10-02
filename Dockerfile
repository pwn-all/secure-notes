FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    certbot \
    util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 secnote \
    && useradd --uid 65532 --gid 65532 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin secnote
WORKDIR /app
COPY --from=builder /build/target/release/secure_notes ./
COPY website ./website
COPY scripts/docker-entrypoint.sh ./entrypoint.sh
RUN chmod +x entrypoint.sh
EXPOSE 80 443
ENTRYPOINT ["./entrypoint.sh"]
