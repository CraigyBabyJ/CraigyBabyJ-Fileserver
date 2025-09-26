#!/bin/bash

# CraigyBabyJ Fileserver - Ubuntu 24 Deployment Script
# Run this script on your Ubuntu server

set -e

echo "🛩️  #FlyWithCraig Aviation Cargo Hub - Server Deployment"
echo "=================================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt update
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo systemctl enable docker
    sudo systemctl start docker
    sudo usermod -aG docker $USER
    echo "✅ Docker installed successfully!"
else
    echo "✅ Docker already installed"
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null; then
    echo "🔧 Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo "✅ Docker Compose installed!"
else
    echo "✅ Docker Compose already installed"
fi

# Create application directory
APP_DIR="/opt/craigybabyj-fileserver"
echo "📁 Creating application directory: $APP_DIR"
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR

# Clone or update repository
if [ -d "$APP_DIR/.git" ]; then
    echo "🔄 Updating existing repository..."
    cd $APP_DIR
    git pull origin main
else
    echo "📥 Cloning repository..."
    git clone https://github.com/CraigyBabyJ/CraigyBabyJ-Fileserver.git $APP_DIR
    cd $APP_DIR
fi

# Create production environment file
echo "⚙️  Setting up environment configuration..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "📝 Please edit .env file with your production settings:"
    echo "   - Set SECRET_KEY to a secure random string"
    echo "   - Configure ADMIN_USERNAME and ADMIN_PASSWORD"
    echo "   - Set UPLOAD_FOLDER path"
    echo "   - Configure any other settings as needed"
    echo ""
    read -p "Press Enter to continue after editing .env file..."
fi

# Create data directories
echo "📂 Creating data directories..."
mkdir -p data/uploads
mkdir -p data/logs
sudo chown -R $USER:$USER data/

# Pull latest Docker image
echo "🐳 Pulling latest Docker image..."
docker pull ghcr.io/craigybabyj/craigybabyj-fileserver:latest

# Stop existing container if running
echo "🛑 Stopping existing containers..."
docker-compose down || true

# Start the application
echo "🚀 Starting CraigyBabyJ Fileserver..."
docker-compose up -d

# Wait for container to start
echo "⏳ Waiting for application to start..."
sleep 10

# Check if container is running
if docker-compose ps | grep -q "Up"; then
    echo "✅ Application started successfully!"
    echo ""
    echo "🌐 Your fileserver is now running at:"
    echo "   - Local: http://localhost:5000"
    echo "   - Network: http://$(hostname -I | awk '{print $1}'):5000"
    echo ""
    echo "🔐 Admin Panel: http://your-server-ip:5000/admin"
    echo ""
    echo "📋 Useful commands:"
    echo "   - View logs: docker-compose logs -f"
    echo "   - Stop: docker-compose down"
    echo "   - Restart: docker-compose restart"
    echo "   - Update: git pull && docker-compose pull && docker-compose up -d"
else
    echo "❌ Failed to start application. Check logs with: docker-compose logs"
    exit 1
fi

echo ""
echo "🎉 Deployment completed successfully!"
echo "✈️  Fly safe with CraigyBabyJ Fileserver!"