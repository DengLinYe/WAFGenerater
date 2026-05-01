FROM docker.m.daocloud.io/library/caddy:builder AS builder
ENV GOPROXY=https://goproxy.cn,direct
RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2

FROM docker.m.daocloud.io/library/caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
