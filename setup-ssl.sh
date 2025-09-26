#!/bin/bash

# CraigyBabyJ Fileserver SSL Setup Script
# This script sets up Let's Encrypt SSL certificates and deploys the SSL-enabled stack

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   print_status "Please run as a regular user with sudo privileges"
   exit 1
fi

# Get domain name and email
echo "🔐 CraigyBabyJ Fileserver SSL Setup"
echo "=================================="
echo

read -p "Enter your domain name (e.g., files.yourdomain.com): " DOMAIN_NAME
read -p "Enter your email address for Let's Encrypt: " EMAIL

if [[ -z "$DOMAIN_NAME" || -z "$EMAIL" ]]; then
    print_error "Domain name and email are required"
    exit 1
fi

print_status "Setting up SSL for domain: $DOMAIN_NAME"
print_status "Email: $EMAIL"

# Stop existing containers
print_status "Stopping existing containers..."
sudo docker stop craigybabyj-fileserver 2>/dev/null || true
sudo docker rm craigybabyj-fileserver 2>/dev/null || true

# Create necessary directories
print_status "Creating SSL directories..."
sudo mkdir -p /opt/craigybabyj-fileserver/{certbot/conf,certbot/www}
sudo mkdir -p /opt/craigybabyj-fileserver/data
sudo mkdir -p /mnt/storage/uploads

# Set permissions
sudo chown -R 1000:1000 /opt/craigybabyj-fileserver/data
sudo chown -R 1000:1000 /mnt/storage/uploads
sudo chmod -R 755 /opt/craigybabyj-fileserver/data
sudo chmod -R 755 /mnt/storage/uploads

# Copy files to deployment directory
print_status "Copying configuration files..."
sudo cp docker-compose.ssl.yml /opt/craigybabyj-fileserver/
sudo cp nginx-ssl.conf /opt/craigybabyj-fileserver/

# Update nginx config with actual domain name
print_status "Updating Nginx configuration with domain name..."
sudo sed -i "s/DOMAIN_NAME/$DOMAIN_NAME/g" /opt/craigybabyj-fileserver/nginx-ssl.conf

# Create temporary nginx config for initial certificate request
print_status "Creating temporary Nginx config for certificate generation..."
sudo tee /opt/craigybabyj-fileserver/nginx-temp.conf > /dev/null << EOF
events {
    worker_connections 1024;
}

http {
    server {
        listen 80;
        server_name $DOMAIN_NAME;
        
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }
        
        location / {
            return 200 'SSL setup in progress...';
            add_header Content-Type text/plain;
        }
    }
}
EOF

# Start temporary nginx for certificate generation
print_status "Starting temporary Nginx for certificate generation..."
sudo docker run -d --name nginx-temp \
    -p 80:80 \
    -v /opt/craigybabyj-fileserver/nginx-temp.conf:/etc/nginx/nginx.conf:ro \
    -v /opt/craigybabyj-fileserver/certbot/www:/var/www/certbot:ro \
    nginx:alpine

# Wait a moment for nginx to start
sleep 5

# Generate SSL certificate
print_status "Generating Let's Encrypt certificate..."
sudo docker run --rm \
    -v /opt/craigybabyj-fileserver/certbot/conf:/etc/letsencrypt \
    -v /opt/craigybabyj-fileserver/certbot/www:/var/www/certbot \
    certbot/certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email $EMAIL \
    --agree-tos \
    --no-eff-email \
    -d $DOMAIN_NAME

# Stop temporary nginx
print_status "Stopping temporary Nginx..."
sudo docker stop nginx-temp
sudo docker rm nginx-temp

# Check if certificate was generated
if [[ ! -f "/opt/craigybabyj-fileserver/certbot/conf/live/$DOMAIN_NAME/fullchain.pem" ]]; then
    print_error "Certificate generation failed!"
    exit 1
fi

print_success "SSL certificate generated successfully!"

# Deploy the SSL-enabled stack
print_status "Deploying SSL-enabled stack..."
cd /opt/craigybabyj-fileserver
sudo docker-compose -f docker-compose.ssl.yml up -d

# Wait for services to start
print_status "Waiting for services to start..."
sleep 10

# Test the deployment
print_status "Testing deployment..."
if curl -f -k https://$DOMAIN_NAME/health >/dev/null 2>&1; then
    print_success "HTTPS is working!"
else
    print_warning "HTTPS test failed, but services may still be starting..."
fi

# Display final information
echo
print_success "🎉 SSL setup completed!"
echo "=================================="
echo "Your CraigyBabyJ Fileserver is now available at:"
echo "  • HTTPS: https://$DOMAIN_NAME"
echo "  • HTTP:  http://$DOMAIN_NAME (redirects to HTTPS)"
echo
echo "SSL Certificate Details:"
echo "  • Domain: $DOMAIN_NAME"
echo "  • Email: $EMAIL"
echo "  • Auto-renewal: Enabled (every 12 hours)"
echo
echo "Management Commands:"
echo "  • View logs: sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.ssl.yml logs"
echo "  • Restart: sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.ssl.yml restart"
echo "  • Stop: sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.ssl.yml down"
echo
print_status "Setup complete! 🚀"