# CraigyBabyJ-Fileserver - Deployment Guide

## Quick Start Checklist ✅

Before deploying, ensure you have:
- [ ] Updated `.env` with `PRODUCTION_MODE=true`
- [ ] Changed `SITE_PASSWORD` to something secure
- [ ] Domain pointing to your server (craigybabyj.asuscomm.com)
- [ ] Ports 80 and 443 open in firewall

## Development vs Production

### Development (Current Windows Setup)
```bash
# Run directly with Python (current setup)
python app.py

# OR run with Docker for testing
docker-compose -f docker-compose.dev.yml up -d
```

### Production (Ubuntu Server)
```bash
# Full production setup with nginx + SSL
docker-compose up -d
```

## Option 1: Docker Deployment (Recommended)

### 1. Install Docker and Docker Compose
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Log out and back in for group changes
```

### 2. Deploy Application
```bash
# Create deployment directory
sudo mkdir -p /opt/craigybabyj-fileserver
sudo chown $USER:$USER /opt/craigybabyj-fileserver
cd /opt/craigybabyj-fileserver

# Copy your application files here
# Make sure .env file has PRODUCTION_MODE=true

# Build and start containers
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs -f
```

### 3. SSL Certificate Setup
```bash
# Install certbot
sudo apt install certbot

# Stop nginx container temporarily
docker-compose stop nginx

# Get SSL certificate
sudo certbot certonly --standalone -d craigybabyj.asuscomm.com

# Create SSL directory and copy certificates
sudo mkdir -p /opt/flywithcraig/ssl
sudo cp /etc/letsencrypt/live/craigybabyj.asuscomm.com/fullchain.pem /opt/flywithcraig/ssl/
sudo cp /etc/letsencrypt/live/craigybabyj.asuscomm.com/privkey.pem /opt/flywithcraig/ssl/
sudo chown -R $USER:$USER /opt/flywithcraig/ssl

# Restart containers
docker-compose up -d
```

### 4. Auto-renewal Setup
```bash
# Create renewal script
sudo tee /etc/cron.d/certbot-renewal << EOF
0 12 * * * root certbot renew --quiet --deploy-hook "cp /etc/letsencrypt/live/craigybabyj.asuscomm.com/*.pem /opt/flywithcraig/ssl/ && docker-compose -f /opt/flywithcraig/docker-compose.yml restart nginx"
EOF
```

## Option 2: Traditional Deployment

### 1. System Setup
```bash
# Install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip python3-venv nginx certbot python3-certbot-nginx fail2ban

# Create application directory
sudo mkdir -p /var/www/flywithcraig
sudo chown $USER:$USER /var/www/flywithcraig
cd /var/www/flywithcraig

# Copy application files
# Upload your app files here

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Systemd Service
```bash
# Copy service file
sudo cp flywithcraig.service /etc/systemd/system/

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable flywithcraig
sudo systemctl start flywithcraig

# Check status
sudo systemctl status flywithcraig
```

### 3. Configure Nginx
```bash
# Remove default nginx config
sudo rm /etc/nginx/sites-enabled/default

# Copy our nginx config
sudo cp nginx.conf /etc/nginx/sites-available/flywithcraig
sudo ln -s /etc/nginx/sites-available/flywithcraig /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Get SSL certificate
sudo certbot --nginx -d craigybabyj.asuscomm.com

# Start nginx
sudo systemctl restart nginx
sudo systemctl enable nginx
```

## Security Setup

### 1. Configure Fail2ban
```bash
# Create jail for our app
sudo tee /etc/fail2ban/jail.d/flywithcraig.conf << EOF
[flywithcraig]
enabled = true
port = http,https
filter = flywithcraig
logpath = /var/www/flywithcraig/logs/login_attempts.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

# Create filter
sudo tee /etc/fail2ban/filter.d/flywithcraig.conf << EOF
[Definition]
failregex = ^.*Failed login attempt from <HOST>.*$
ignoreregex =
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
```

### 2. Firewall Setup
```bash
# Configure UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

## Monitoring and Maintenance

### Docker Commands
```bash
# View logs
docker-compose logs -f app
docker-compose logs -f nginx

# Restart services
docker-compose restart app
docker-compose restart nginx

# Update application
docker-compose down
# Update files
docker-compose build --no-cache
docker-compose up -d
```

### Traditional Commands
```bash
# View logs
sudo journalctl -u flywithcraig -f
sudo tail -f /var/log/nginx/access.log

# Restart services
sudo systemctl restart flywithcraig
sudo systemctl restart nginx

# Update application
sudo systemctl stop flywithcraig
# Update files
sudo systemctl start flywithcraig
```

## Troubleshooting

### Common Issues
1. **Port already in use**: Check if another service is using port 80/443
2. **SSL certificate issues**: Ensure domain points to your server
3. **Permission errors**: Check file ownership and permissions
4. **Upload failures**: Verify upload directory permissions and disk space

### Log Locations
- Docker: `docker-compose logs`
- Application: `/var/www/flywithcraig/logs/`
- Nginx: `/var/log/nginx/`
- System: `sudo journalctl -u flywithcraig`

## Environment Variables
Ensure your `.env` file contains:
```
PRODUCTION_MODE=true
SECRET_KEY=your-32-character-secret-key
SITE_PASSWORD=your-site-password
```

## Backup Strategy
- Backup `/var/www/flywithcraig/data/users.json`
- Backup `/var/www/flywithcraig/uploads/` directory
- Backup SSL certificates from `/etc/letsencrypt/`