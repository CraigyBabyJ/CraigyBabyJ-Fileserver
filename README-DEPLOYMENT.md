# 🛩️ CraigyBabyJ Fileserver - Ubuntu 24 Deployment Guide

Complete deployment guide for setting up the CraigyBabyJ Fileserver on Ubuntu 24 headless server.

## 📋 Prerequisites

- Ubuntu 24.04 LTS server
- SSH access with sudo privileges
- Domain name (optional, for SSL)
- At least 2GB RAM and 10GB disk space

## 🚀 Quick Deployment

### Option 1: Automated Script (Recommended)

```bash
# Download and run the deployment script
wget https://raw.githubusercontent.com/your-repo/deploy-ubuntu.sh
chmod +x deploy-ubuntu.sh
sudo ./deploy-ubuntu.sh
```

### Option 2: Manual Deployment

Follow the steps below for manual deployment.

## 📦 Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y curl wget git unzip

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install -y docker-compose-plugin

# Reboot to apply Docker group changes
sudo reboot
```

## 📁 Step 2: Application Setup

```bash
# Create application directory
sudo mkdir -p /opt/craigybabyj-fileserver
cd /opt/craigybabyj-fileserver

# Clone repository (replace with your repo URL)
sudo git clone https://github.com/your-username/craigybabyj-fileserver.git .

# Create data directories
sudo mkdir -p data/uploads data/temp
sudo chmod 755 data/uploads data/temp

# Set up environment variables
sudo cp .env.example .env
sudo nano .env  # Edit configuration as needed
```

## 🐳 Step 3: Docker Deployment

```bash
# Pull the latest image
sudo docker pull ghcr.io/craigybabyj/craigybabyj-fileserver:v1.0.1

# Start services using production compose file
sudo docker-compose -f docker-compose.prod.yml up -d

# Check status
sudo docker-compose -f docker-compose.prod.yml ps
```

## 🔧 Step 4: System Service Setup

```bash
# Copy systemd service file
sudo cp craigybabyj-fileserver.service /etc/systemd/system/

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable craigybabyj-fileserver
sudo systemctl start craigybabyj-fileserver

# Check status
sudo systemctl status craigybabyj-fileserver
```

## 🌐 Step 5: Nginx Reverse Proxy (Optional)

```bash
# Install Nginx
sudo apt install -y nginx

# Copy configuration
sudo cp nginx/nginx.conf /etc/nginx/sites-available/craigybabyj-fileserver
sudo ln -s /etc/nginx/sites-available/craigybabyj-fileserver /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
sudo systemctl enable nginx
```

## 🔒 Step 6: SSL Setup (Optional)

### Using Let's Encrypt (Recommended)

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d yourdomain.com

# Auto-renewal is set up automatically
```

### Using Custom Certificates

```bash
# Copy your certificates
sudo mkdir -p /opt/craigybabyj-fileserver/nginx/ssl
sudo cp your-cert.pem /opt/craigybabyj-fileserver/nginx/ssl/cert.pem
sudo cp your-key.pem /opt/craigybabyj-fileserver/nginx/ssl/key.pem
sudo chmod 600 /opt/craigybabyj-fileserver/nginx/ssl/*
```

## 📊 Step 7: Monitoring & Backup Setup

```bash
# Make scripts executable
sudo chmod +x scripts/*.sh

# Set up automated jobs
sudo ./scripts/setup-cron.sh

# Test backup manually
sudo ./scripts/backup.sh

# Test monitoring
sudo ./scripts/monitor.sh
```

## 🔥 Firewall Configuration

```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow ssh

# Allow HTTP/HTTPS
sudo ufw allow 80
sudo ufw allow 443

# Allow application port (if not using Nginx)
sudo ufw allow 5000

# Check status
sudo ufw status
```

## 📋 Verification

### Check Services

```bash
# Check Docker containers
sudo docker-compose -f docker-compose.prod.yml ps

# Check systemd service
sudo systemctl status craigybabyj-fileserver

# Check Nginx (if used)
sudo systemctl status nginx

# Check application logs
sudo docker-compose -f docker-compose.prod.yml logs -f
```

### Test Application

```bash
# Health check
curl http://localhost:5000/health

# Upload test (if accessible)
curl -F "file=@test.txt" http://localhost:5000/upload
```

## 🛠️ Management Commands

### Application Management

```bash
# Start services
sudo systemctl start craigybabyj-fileserver

# Stop services
sudo systemctl stop craigybabyj-fileserver

# Restart services
sudo systemctl restart craigybabyj-fileserver

# View logs
sudo journalctl -u craigybabyj-fileserver -f
```

### Docker Management

```bash
# View containers
sudo docker-compose -f docker-compose.prod.yml ps

# View logs
sudo docker-compose -f docker-compose.prod.yml logs -f

# Update application
sudo docker-compose -f docker-compose.prod.yml pull
sudo docker-compose -f docker-compose.prod.yml up -d

# Clean up old images
sudo docker system prune -f
```

### Backup Management

```bash
# Manual backup
sudo /opt/craigybabyj-fileserver/scripts/backup.sh

# View backups
ls -la /opt/backups/craigybabyj-fileserver/

# Restore from backup
cd /opt/craigybabyj-fileserver
sudo tar -xzf /opt/backups/craigybabyj-fileserver/fileserver_backup_YYYYMMDD_HHMMSS.tar.gz
```

## 🔍 Troubleshooting

### Common Issues

1. **Docker permission denied**
   ```bash
   sudo usermod -aG docker $USER
   # Then logout and login again
   ```

2. **Port already in use**
   ```bash
   sudo netstat -tulpn | grep :5000
   sudo systemctl stop apache2  # If Apache is running
   ```

3. **SSL certificate issues**
   ```bash
   sudo certbot renew --dry-run
   sudo nginx -t
   ```

4. **Application not starting**
   ```bash
   sudo docker-compose -f docker-compose.prod.yml logs
   sudo systemctl status craigybabyj-fileserver
   ```

### Log Locations

- Application logs: `sudo docker-compose logs`
- System service logs: `sudo journalctl -u craigybabyj-fileserver`
- Nginx logs: `/var/log/nginx/`
- Backup logs: `/var/log/craigybabyj-backup.log`
- Monitor logs: `/var/log/craigybabyj-monitor.log`

## 📞 Support

For issues and support:
- Check the logs first
- Run the monitoring script: `sudo ./scripts/monitor.sh`
- Review the troubleshooting section above

## 🔄 Updates

To update the application:

```bash
cd /opt/craigybabyj-fileserver
sudo git pull
sudo docker-compose -f docker-compose.prod.yml pull
sudo docker-compose -f docker-compose.prod.yml up -d
```

---

🛩️ **CraigyBabyJ Fileserver** - Deployed and ready to fly! ✈️