# Use Python base image
FROM python:3.10-slim

# Set the working directory for the app
WORKDIR /app

# Copy application code
COPY . .

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    librocksdb-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Node.js (latest LTS version)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install the required Node.js libraries
RUN npm install @noble/post-quantum js-sha3 bs58

# Set environment variables
ENV WALLET_PASSWORD=your_wallet_password
ENV ROCKSDB_PATH=/app/db

# Expose the ports
EXPOSE 8080/tcp  
EXPOSE 8332/tcp  
EXPOSE 8001/udp  
EXPOSE 8002/tcp 

# Copy entrypoint
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/app/docker-entrypoint.sh"]
