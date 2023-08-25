FROM rust:1.72 as builder

ENV PKG_CONFIG_ALLOW_CROSS=1
ENV RUSTFLAGS="-Ctarget-cpu=x86-64 -Ctarget-feature=+sse,+sse2,+sse3,+sse4.1,+sse4.2,+avx,+avx2,+fma,+aes,+sha"

WORKDIR /usr/src/identity
COPY . .
RUN cargo install --path .

FROM gcr.io/distroless/cc-debian11

LABEL homepage="https://tarkov-database.com"
LABEL repository="https://github.com/tarkov-database/identity"
LABEL maintainer="Markus Wiegand <mail@morphy2k.dev>"

LABEL org.opencontainers.image.source="https://github.com/tarkov-database/identity"

EXPOSE 8080

COPY --from=builder /usr/local/cargo/bin/identity /usr/local/bin/identity

CMD ["identity"]