# Dockerfile for Frontend Service (React + Vite)
FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY frontend/package*.json ./
RUN npm install

# Copy application source code
COPY frontend/ ./

# Expose Vite server port
EXPOSE 5173

# Start Vite dev/preview server bound to all interfaces
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
