FROM oven/bun:1-alpine
WORKDIR /app
COPY package.json ./
RUN bun install --production
COPY src ./src
COPY public/index.html public/collab.js public/collab.css ./public/
RUN mkdir -p /app/data/rooms /app/data/backups /app/public
EXPOSE 10101
CMD ["bun", "run", "src/index.ts"]
