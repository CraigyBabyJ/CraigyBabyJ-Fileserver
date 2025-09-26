#!/bin/bash

# CraigyBabyJ Fileserver Porkbun SSL Setup Script
# This script sets up the fileserver with Porkbun SSL certificates

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

echo "🔐 CraigyBabyJ Fileserver Porkbun SSL Setup"
echo "=========================================="
echo

print_status "This script will set up your fileserver with Porkbun SSL certificates"
print_warning "Make sure you have downloaded your SSL certificate files from Porkbun!"
echo

# Check if SSL files exist
SSL_DIR="./ssl"
if [[ ! -d "$SSL_DIR" ]]; then
    print_error "SSL directory not found!"
    echo
    echo "Please create an 'ssl' directory and place your Porkbun certificate files:"
    echo "  • craigybabyj.com.crt (your certificate)"
    echo "  • craigybabyj.com.key (your private key)"
    echo "  • ca-bundle.crt (certificate authority bundle)"
    echo
    echo "Steps to get your certificates from Porkbun:"
    echo "1. Log into your Porkbun account"
    echo "2. Go to SSL certificates"
    echo "3. Download the certificate package"
    echo "4. Extract and place the files in ./ssl/ directory"
    exit 1
fi

# Check for required certificate files
CERT_FILE="$SSL_DIR/craigybabyj.com.crt"
KEY_FILE="$SSL_DIR/craigybabyj.com.key"
CA_BUNDLE="$SSL_DIR/ca-bundle.crt"

missing_files=()
[[ ! -f "$CERT_FILE" ]] && missing_files+=("craigybabyj.com.crt")
[[ ! -f "$KEY_FILE" ]] && missing_files+=("craigybabyj.com.key")
[[ ! -f "$CA_BUNDLE" ]] && missing_files+=("ca-bundle.crt")

if [[ ${#missing_files[@]} -gt 0 ]]; then
    print_error "Missing SSL certificate files:"
    for file in "${missing_files[@]}"; do
        echo "  • $file"
    done
    echo
    echo "Please place all certificate files in the ./ssl/ directory"
    exit 1
fi

print_success "All SSL certificate files found!"

# Stop existing containers
print_status "Stopping existing containers..."
sudo docker stop craigybabyj-fileserver 2>/dev/null || true
sudo docker rm craigybabyj-fileserver 2>/dev/null || true
sudo docker stop craigybabyj-nginx 2>/dev/null || true
sudo docker rm craigybabyj-nginx 2>/dev/null || true

# Create necessary directories
print_status "Creating deployment directories..."
sudo mkdir -p /opt/craigybabyj-fileserver/{ssl,data}
sudo mkdir -p /mnt/storage/uploads

# Set permissions
sudo chown -R 1000:1000 /opt/craigybabyj-fileserver/data
sudo chown -R 1000:1000 /mnt/storage/uploads
sudo chmod -R 755 /opt/craigybabyj-fileserver/data
sudo chmod -R 755 /mnt/storage/uploads

# Copy SSL certificates
print_status "Copying SSL certificates..."
sudo cp "$CERT_FILE" /opt/craigybabyj-fileserver/ssl/
sudo cp "$KEY_FILE" /opt/craigybabyj-fileserver/ssl/
sudo cp "$CA_BUNDLE" /opt/craigybabyj-fileserver/ssl/

# Set proper permissions for SSL files
sudo chmod 644 /opt/craigybabyj-fileserver/ssl/craigybabyj.com.crt
sudo chmod 600 /opt/craigybabyj-fileserver/ssl/craigybabyj.com.key
sudo chmod 644 /opt/craigybabyj-fileserver/ssl/ca-bundle.crt

# Copy configuration files
print_status "Copying configuration files..."
sudo cp docker-compose.porkbun-ssl.yml /opt/craigybabyj-fileserver/
sudo cp nginx-porkbun.conf /opt/craigybabyj-fileserver/

# Deploy the SSL-enabled stack
print_status "Deploying SSL-enabled stack with Porkbun certificates..."
cd /opt/craigybabyj-fileserver
sudo docker-compose -f docker-compose.porkbun-ssl.yml up -d

# Wait for services to start
print_status "Waiting for services to start..."
sleep 15

# Test the deployment
print_status "Testing deployment..."
if curl -f -k https://craigybabyj.com/health >/dev/null 2>&1; then
    print_success "HTTPS is working!"
elif curl -f http://localhost:5000/health >/dev/null 2>&1; then
    print_warning "Fileserver is running but HTTPS may need DNS propagation"
else
    print_warning "Services may still be starting..."
fi

# Display final information
echo
print_success "🎉 Porkbun SSL setup completed!"
echo "=========================================="
echo "Your CraigyBabyJ Fileserver is now available at:"
echo "  • HTTPS: https://craigybabyj.com"
echo "  • HTTP:  http://craigybabyj.com (redirects to HTTPS)"
echo
echo "SSL Certificate Details:"
echo "  • Domain: craigybabyj.com"
echo "  • Provider: Porkbun"
echo "  • Certificate: /opt/craigybabyj-fileserver/ssl/craigybabyj.com.crt"
echo
echo "Management Commands:"
echo "  • View logs: sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml logs"
echo "  • Restart: sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml restart"
echo "  • Stop: sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml down"
echo
echo "Next Steps:"
echo "  • Make sure craigybabyj.com points to your server IP"
echo "  • Test the site: https://craigybabyj.com"
echo "  • Set up firewall rules for ports 80 and 443"
echo
print_status "Setup complete! 🚀"