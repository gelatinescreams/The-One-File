FROM oven/bun:alpine
WORKDIR /app
RUN apk add --no-cache su-exec
COPY package.json ./
RUN bun install --production
COPY src ./src
COPY public/index.html public/theonefile.html public/collab.js public/collab.css public/collab-init.js public/collab-save-hook.js public/landing.js public/admin-dashboard.js public/admin-auth.js public/admin-pages.js public/qrcode.min.js ./public/
COPY entrypoint.sh ./
RUN mkdir -p /app/data/rooms /app/data/backups /app/public && \
    addgroup -S appgroup && adduser -S appuser -G appgroup && \
    chown -R appuser:appgroup /app && \
    chmod +x /app/entrypoint.sh
EXPOSE 10101
ENTRYPOINT ["/app/entrypoint.sh"]
