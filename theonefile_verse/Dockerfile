FROM oven/bun:1.3.10-alpine@sha256:32f1fcccb1523960b254c4f80973bee1a910d60be000a45c20c9129a1efcffee
WORKDIR /app
RUN apk add --no-cache su-exec iputils bind-tools samba-client avahi-tools net-snmp-tools
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY src ./src
COPY public/index.html public/theonefile.html public/collab.js public/collab.css public/collab-init.js public/collab-save-hook.js public/landing.js public/admin-dashboard.js public/admin-auth.js public/admin-pages.js public/qrcode.min.js public/dompurify.min.js ./public/
COPY entrypoint.sh ./
RUN mkdir -p /app/data/rooms /app/data/backups /app/public && \
    addgroup -S appgroup && adduser -S appuser -G appgroup && \
    chown -R appuser:appgroup /app && \
    chmod +x /app/entrypoint.sh
EXPOSE 10101
ENTRYPOINT ["/app/entrypoint.sh"]
