FROM caddy:2-builder AS builder

COPY . /src/caddy-mcp
RUN xcaddy build \
    --with github.com/venkatkrishnas/caddy-mcp=/src/caddy-mcp

FROM caddy:2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

EXPOSE 443 443/udp 4443/udp 2019
