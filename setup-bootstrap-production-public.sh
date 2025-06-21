#!/bin/bash

# qBTC Bootstrap Server Production Setup Script - Public Dashboard Version
# This script sets up a production bootstrap server with publicly viewable (but locked down) Grafana

set -e

echo "======================================================"
echo "qBTC Bootstrap Server Production Setup - Public Grafana"
echo "======================================================"
echo ""

# Check if running as root (needed for certbot)
if [ "$EUID" -ne 0 ]; then 
   echo "This script needs to run as root for SSL certificate setup"
   echo "Please run: sudo ./setup-bootstrap-production-public.sh"
   exit 1
fi

# Get domain name
if [ -z "$1" ]; then
    echo "Usage: sudo ./setup-bootstrap-production-public.sh <your-domain.com> [email@example.com]"
    echo "Example: sudo ./setup-bootstrap-production-public.sh monitoring.example.com admin@example.com"
    exit 1
fi

DOMAIN=$1
EMAIL=${2:-"admin@$DOMAIN"}

echo "Setting up for domain: $DOMAIN"
echo "Using email: $EMAIL"
echo ""

# Generate secure random passwords
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Install required packages
echo "Installing required packages..."
apt-get update -qq
apt-get install -y certbot curl docker.io docker-compose

# Create non-root user if needed
SETUP_USER=${SUDO_USER:-qbtc}
if [ "$SETUP_USER" = "root" ]; then
    SETUP_USER="qbtc"
    if ! id "$SETUP_USER" &>/dev/null; then
        echo "Creating user $SETUP_USER..."
        adduser --disabled-password --gecos "" $SETUP_USER
        usermod -aG docker $SETUP_USER
    fi
fi

# Switch to project directory
PROJECT_DIR="/home/$SETUP_USER/qBTC-core"
if [ ! -d "$PROJECT_DIR" ]; then
    echo "Error: $PROJECT_DIR not found!"
    echo "Please clone the repository first:"
    echo "  su - $SETUP_USER"
    echo "  git clone https://github.com/bitcoinqs/qBTC-core.git"
    exit 1
fi

cd "$PROJECT_DIR"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file with secure passwords..."
    
    BOOTSTRAP_WALLET_PASSWORD=$(generate_password)
    GRAFANA_ADMIN_PASSWORD=$(generate_password)
    REDIS_PASSWORD=$(generate_password)
    
    cat > .env << EOF
# Production configuration - SAVE THESE PASSWORDS!
BOOTSTRAP_WALLET_PASSWORD=$BOOTSTRAP_WALLET_PASSWORD
ADMIN_ADDRESS=bqs1YourAdminAddressHere
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=$GRAFANA_ADMIN_PASSWORD
GRAFANA_DOMAIN=$DOMAIN
REDIS_PASSWORD=$REDIS_PASSWORD
EOF
    
    chown $SETUP_USER:$SETUP_USER .env
    chmod 600 .env
    
    echo ""
    echo "IMPORTANT: Save these passwords in a secure location!"
    echo "=================================================="
    echo "Bootstrap Wallet Password: $BOOTSTRAP_WALLET_PASSWORD"
    echo "Grafana Admin Password: $GRAFANA_ADMIN_PASSWORD"
    echo "Redis Password: $REDIS_PASSWORD"
    echo "=================================================="
    echo ""
    echo "These have been saved to .env file"
    echo ""
else
    echo "Using existing .env file..."
    source .env
fi

# Create required directories
echo "Creating required directories..."
sudo -u $SETUP_USER mkdir -p logs
sudo -u $SETUP_USER mkdir -p monitoring/nginx/ssl
sudo -u $SETUP_USER mkdir -p monitoring/grafana/provisioning
sudo -u $SETUP_USER mkdir -p monitoring/grafana/dashboards

# Get SSL certificate from Let's Encrypt
echo "Obtaining SSL certificate from Let's Encrypt..."
certbot certonly --standalone --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN" || {
    echo "Failed to obtain SSL certificate. Using self-signed certificate instead..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout monitoring/nginx/ssl/key.pem \
        -out monitoring/nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=qBTC/CN=$DOMAIN"
}

# Copy SSL certificates
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "Copying Let's Encrypt certificates..."
    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" monitoring/nginx/ssl/cert.pem
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" monitoring/nginx/ssl/key.pem
fi

chown -R $SETUP_USER:$SETUP_USER monitoring/nginx/ssl
chmod 600 monitoring/nginx/ssl/key.pem

# Update Redis config
if [ -f config/redis.conf ]; then
    echo "Updating Redis configuration..."
    sed -i.bak "s/requirepass \"\"/requirepass \"$REDIS_PASSWORD\"/" config/redis.conf
    sed -i "s/bind 0.0.0.0/bind 127.0.0.1/" config/redis.conf
fi

# Create production nginx config WITHOUT basic auth
echo "Creating nginx configuration (no basic auth)..."
cat > monitoring/nginx/nginx-prod-public.conf << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none';" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate limiting - more aggressive for public access
    limit_req_zone \$binary_remote_addr zone=grafana_limit:10m rate=5r/s;
    limit_req_status 429;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Logging
    access_log /var/log/nginx/access.log;

    # Hide nginx version
    server_tokens off;

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name $DOMAIN;
        return 301 https://\$host\$request_uri;
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name $DOMAIN;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        # NO BASIC AUTH - Public access

        # Stricter rate limiting for public access
        limit_req zone=grafana_limit burst=10 nodelay;

        # Only allow GET/HEAD methods for public viewers
        if (\$request_method !~ ^(GET|HEAD)$) {
            return 405;
        }

        # Grafana proxy - READ ONLY paths
        location / {
            # Block all admin/edit paths
            if (\$uri ~* ^/(api/admin|api/datasources|api/plugins|api/users|api/orgs|api/annotations|api/alerts|api/dashboards/db|api/dashboards/import|api/dashboards/home|admin|profile|org|datasources|plugins|apikeys|teams)) {
                return 403;
            }

            proxy_pass http://grafana:3000;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            
            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;

            # Prevent any POST/PUT/DELETE operations
            proxy_read_only on;
        }

        # Explicitly block sensitive endpoints
        location ~ ^/(api/admin|api/datasources|api/plugins|api/users|api/orgs|login|logout|profile|org/|admin) {
            return 403;
        }

        # Allow only dashboard viewing
        location ~ ^/(d/|public/|api/dashboards/uid/|api/health) {
            proxy_pass http://grafana:3000;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
}
EOF

# Create docker-compose with public Grafana settings
echo "Creating docker-compose with public Grafana settings..."
cat > docker-compose.bootstrap-public.yml << 'EOFDOCKER'
version: '3.8'

services:
  # Production Bootstrap node
  bootstrap:
    build: .
    container_name: qbtc-bootstrap-prod
    environment:
      WALLET_PASSWORD: ${BOOTSTRAP_WALLET_PASSWORD}
      WALLET_FILE: "bootstrap.json"
      DISABLE_NAT_TRAVERSAL: "false"
      ROCKSDB_PATH: "/app/db"
      # Production security configuration
      RATE_LIMIT_ENABLED: "true"
      DDOS_PROTECTION_ENABLED: "true"
      ADMIN_ADDRESS: ${ADMIN_ADDRESS}
      ATTACK_PATTERN_DETECTION: "true"
      BOT_DETECTION_ENABLED: "true"
      PEER_REPUTATION_ENABLED: "true"
      SECURITY_LOGGING_ENABLED: "true"
      # Redis configuration
      USE_REDIS: "true"
      REDIS_URL: "redis://redis:6379/0"
      # Rate limits (requests per minute)
      RATE_LIMIT_WORKER: "10"
      RATE_LIMIT_BALANCE: "100"
      RATE_LIMIT_TRANSACTIONS: "50"
      RATE_LIMIT_DEFAULT: "60"
    command: ["--bootstrap", "--dht-port", "8001", "--gossip-port", "8002"]
    ports:
      - "8080:8080"     # Web API
      - "8332:8332"     # RPC
      - "8001:8001/udp" # DHT UDP
      - "8002:8002"     # Gossip TCP
    volumes:
      - bootstrap-data:/app/db
      - ./logs:/var/log/qbtc
    depends_on:
      - redis
    networks:
      - qbtc-network
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Redis for rate limiting and caching
  redis:
    image: redis:7-alpine
    container_name: qbtc-redis-prod
    volumes:
      - redis-data:/data
      - ./config/redis.conf:/usr/local/etc/redis/redis.conf:ro
    command: redis-server /usr/local/etc/redis/redis.conf
    networks:
      - qbtc-network
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=50m

  # Prometheus for metrics collection
  prometheus:
    image: prom/prometheus:latest
    container_name: qbtc-prometheus-prod
    volumes:
      - ./monitoring/prometheus-bootstrap.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=720h'
      - '--web.enable-lifecycle'
      - '--web.listen-address=:9090'
    networks:
      - qbtc-network
    restart: unless-stopped
    depends_on:
      - bootstrap

  # Grafana for visualization - PUBLIC ACCESS CONFIGURATION
  grafana:
    image: grafana/grafana:latest
    container_name: qbtc-grafana-prod
    environment:
      # Admin settings (for backend access only)
      - GF_SECURITY_ADMIN_USER=${GRAFANA_ADMIN_USER}
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
      
      # Public access configuration
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_NAME=Public
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
      - GF_AUTH_BASIC_ENABLED=false
      - GF_AUTH_DISABLE_LOGIN_FORM=false  # Keep login form for admin access
      - GF_AUTH_DISABLE_SIGNOUT_MENU=true
      
      # Disable all user management for public
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_USERS_ALLOW_ORG_CREATE=false
      - GF_USERS_AUTO_ASSIGN_ORG=true
      - GF_USERS_AUTO_ASSIGN_ORG_ROLE=Viewer
      
      # Security hardening
      - GF_SECURITY_DISABLE_GRAVATAR=true
      - GF_SECURITY_COOKIE_SECURE=true
      - GF_SECURITY_COOKIE_SAMESITE=strict
      - GF_SECURITY_STRICT_TRANSPORT_SECURITY=true
      - GF_SECURITY_STRICT_TRANSPORT_SECURITY_MAX_AGE_SECONDS=86400
      - GF_SECURITY_STRICT_TRANSPORT_SECURITY_PRELOAD=true
      - GF_SECURITY_STRICT_TRANSPORT_SECURITY_SUBDOMAINS=true
      - GF_SECURITY_X_CONTENT_TYPE_OPTIONS=true
      - GF_SECURITY_X_XSS_PROTECTION=true
      - GF_SECURITY_CONTENT_SECURITY_POLICY=true
      
      # Disable features that could be abused
      - GF_EXPLORE_ENABLED=false
      - GF_USERS_VIEWERS_CAN_EDIT=false
      - GF_DISABLE_SANITIZE_HTML=false
      - GF_PANELS_DISABLE_ANIMATIONS=false
      - GF_DASHBOARDS_MIN_REFRESH_INTERVAL=10s
      - GF_USERS_DEFAULT_PERMISSIONS=Viewer
      
      # Performance
      - GF_DATABASE_WAL=true
      - GF_DATABASE_CACHE_MODE=shared
      
      # Server settings
      - GF_SERVER_ROOT_URL=https://${GRAFANA_DOMAIN}/
      - GF_SERVER_ENABLE_GZIP=true
      
      # Home dashboard
      - GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/qbtc-overview.json
    volumes:
      - grafana-data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning:ro
      - ./monitoring/grafana/dashboards:/var/lib/grafana/dashboards:ro
    networks:
      - qbtc-network
    restart: unless-stopped
    depends_on:
      - prometheus

  # Nginx reverse proxy for secure public access
  nginx:
    image: nginx:alpine
    container_name: qbtc-nginx-prod
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./monitoring/nginx/nginx-prod-public.conf:/etc/nginx/nginx.conf:ro
      - ./monitoring/nginx/ssl:/etc/nginx/ssl:ro
    networks:
      - qbtc-network
    restart: unless-stopped
    depends_on:
      - grafana
    security_opt:
      - no-new-privileges:true

volumes:
  bootstrap-data:
  redis-data:
  prometheus-data:
  grafana-data:

networks:
  qbtc-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/16
EOFDOCKER

chown $SETUP_USER:$SETUP_USER docker-compose.bootstrap-public.yml
chown $SETUP_USER:$SETUP_USER monitoring/nginx/nginx-prod-public.conf

# Setup auto-renewal for SSL certificates
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "Setting up SSL auto-renewal..."
    cat > /etc/cron.daily/renew-qbtc-ssl << EOF
#!/bin/bash
certbot renew --quiet
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$PROJECT_DIR/monitoring/nginx/ssl/cert.pem"
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$PROJECT_DIR/monitoring/nginx/ssl/key.pem"
    chown $SETUP_USER:$SETUP_USER "$PROJECT_DIR/monitoring/nginx/ssl/"*
    chmod 600 "$PROJECT_DIR/monitoring/nginx/ssl/key.pem"
    cd "$PROJECT_DIR" && docker-compose -f docker-compose.bootstrap-public.yml restart nginx
fi
EOF
    chmod +x /etc/cron.daily/renew-qbtc-ssl
fi

# Configure firewall
echo "Configuring firewall..."
ufw --force enable
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS
ufw allow 8080/tcp # API
ufw allow 8332/tcp # RPC
ufw allow 8001/udp # DHT
ufw allow 8002/tcp # Gossip

# Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/qbtc-bootstrap.service << EOF
[Unit]
Description=qBTC Bootstrap Server
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=$SETUP_USER
Group=$SETUP_USER
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/docker-compose -f docker-compose.bootstrap-public.yml up
ExecStop=/usr/bin/docker-compose -f docker-compose.bootstrap-public.yml down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable qbtc-bootstrap.service

# Final setup as non-root user
echo "Finalizing setup..."
cd "$PROJECT_DIR"
chown -R $SETUP_USER:$SETUP_USER .

# Start the services
echo "Starting qBTC Bootstrap Server..."
sudo -u $SETUP_USER docker-compose -f docker-compose.bootstrap-public.yml pull
systemctl start qbtc-bootstrap.service

echo ""
echo "=============================================="
echo "Production Setup Complete! 🎉"
echo "=============================================="
echo ""
echo "Your bootstrap server is now running with PUBLIC Grafana access!"
echo ""
echo "Access points:"
echo "  - API: https://$DOMAIN:8080"
echo "  - RPC: https://$DOMAIN:8332"
echo "  - Public Dashboard: https://$DOMAIN (no login required)"
echo ""
echo "Admin access:"
echo "  - Grafana admin: https://$DOMAIN/login"
echo "  - Username: admin"
echo "  - Password: $GRAFANA_ADMIN_PASSWORD"
echo ""
echo "Service management:"
echo "  - Status: systemctl status qbtc-bootstrap"
echo "  - Logs: journalctl -u qbtc-bootstrap -f"
echo "  - Stop: systemctl stop qbtc-bootstrap"
echo "  - Start: systemctl start qbtc-bootstrap"
echo ""
echo "IMPORTANT:"
echo "1. Update ADMIN_ADDRESS in .env with your actual admin wallet address"
echo "2. Save the admin password shown above for backend access"
echo "3. The dashboard is now publicly viewable but read-only"
echo "4. Monitor logs for any suspicious activity"
echo ""