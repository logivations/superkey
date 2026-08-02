FROM node:20-alpine

WORKDIR /app

# Install build dependencies for better-sqlite3 and git for SSH configs
RUN apk add --no-cache python3 make g++ git

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application code
COPY src ./src
COPY public ./public

# Restricted-servers policy (committed to git on purpose: changing it is
# traceable, unlike DB edits)
COPY restricted-servers.json ./restricted-servers.json

# Create data directory for SQLite database
RUN mkdir -p /data

# Environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV DB_PATH=/data/superkey.db

# Expose port
EXPOSE 3000

# Start the application
CMD ["node", "src/server.js"]
