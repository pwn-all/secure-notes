FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    certbot \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/target/release/secure_notes ./
COPY website ./website
COPY scripts/docker-entrypoint.sh ./entrypoint.sh
RUN chmod +x entrypoint.sh
EXPOSE 80 443
ENTRYPOINT ["./entrypoint.sh"]
