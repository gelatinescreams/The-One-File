FROM oven/bun:1-alpine
WORKDIR /app
COPY package.json ./
RUN bun install --production
COPY src ./src
COPY public/index.html public/collab.js public/collab.css ./public/
RUN mkdir -p /app/data/rooms /app/public
EXPOSE 3000
CMD ["bun", "run", "src/index.ts"]
