#!/bin/bash

# CraigyBabyJ Fileserver - Portainer Setup Script
# Sets up Portainer for easy Docker management

set -e

echo "🛩️  CraigyBabyJ Fileserver - Portainer Setup"
echo "==========================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    echo "✅ Docker installed"
else
    echo "✅ Docker already installed"
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null; then
    echo "🔧 Installing Docker Compose..."
    sudo apt install -y docker-compose-plugin
    echo "✅ Docker Compose installed"
else
    echo "✅ Docker Compose already installed"
fi

# Create Portainer volume
echo "📁 Creating Portainer data volume..."
sudo docker volume create portainer_data

# Install and start Portainer
echo "🎛️  Installing Portainer..."
sudo docker run -d \
  --name portainer \
  --restart unless-stopped \
  -p 8000:8000 \
  -p 9443:9443 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce:latest

echo "✅ Portainer installed and running!"

# Create application directory
echo "📁 Creating application directory..."
sudo mkdir -p /opt/craigybabyj-fileserver/data/uploads
sudo chmod 755 /opt/craigybabyj-fileserver/data/uploads

# Create docker-compose file for Portainer deployment
echo "📝 Creating docker-compose file for Portainer..."
sudo tee /opt/craigybabyj-fileserver/docker-compose.portainer.yml > /dev/null <<EOF
version: '3.8'

services:
  craigybabyj-fileserver:
    image: ghcr.io/craigybabyj/craigybabyj-fileserver:v1.0.1
    container_name: craigybabyj-fileserver
    restart: unless-stopped
    ports:
      - "5000:5000"
    volumes:
      - /opt/craigybabyj-fileserver/data:/app/data
    environment:
      - FLASK_ENV=production
      - UPLOAD_FOLDER=/app/data/uploads
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  nginx:
    image: nginx:alpine
    container_name: craigybabyj-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - craigybabyj-fileserver
    logging:
      driver: "json-file"
      options:
        max-size: "5m"
        max-file: "3"

volumes:
  app_data:
    driver: local

networks:
  default:
    name: craigybabyj-network
EOF

echo "✅ Docker Compose file created!"

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo ""
echo "🎛️  Portainer Web UI:"
echo "   https://$SERVER_IP:9443"
echo "   http://$SERVER_IP:8000"
echo ""
echo "🛩️  CraigyBabyJ Fileserver will be available at:"
echo "   http://$SERVER_IP:5000"
echo ""
echo "📋 Next Steps:"
echo "1. Open Portainer in your browser"
echo "2. Create admin account"
echo "3. Go to 'Stacks' and create new stack"
echo "4. Copy the docker-compose.portainer.yml content"
echo "5. Deploy the stack"
echo ""
echo "📁 Files created:"
echo "   /opt/craigybabyj-fileserver/docker-compose.portainer.yml"
echo ""
echo "🔧 Manual deployment (alternative):"
echo "   cd /opt/craigybabyj-fileserver"
echo "   sudo docker-compose -f docker-compose.portainer.yml up -d"