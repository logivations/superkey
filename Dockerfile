FROM node:20-alpine

WORKDIR /app

# Install build dependencies for better-sqlite3
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application code
COPY src ./src
COPY public ./public

# Create data directory for SQLite database
RUN mkdir -p /data

# Environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV DB_PATH=/data/superkey.db
ENV EXPORT_PATH=/data/keys

# Expose port
EXPOSE 3000

# Start the application
CMD ["node", "src/server.js"]
