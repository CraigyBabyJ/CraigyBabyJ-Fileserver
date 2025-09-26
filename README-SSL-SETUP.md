# SSL Setup with Porkbun Certificates

This guide will help you set up HTTPS for your CraigyBabyJ Fileserver using SSL certificates from Porkbun.

## Prerequisites

1. **Domain Registration**: You should have registered `craigybabyj.com` with Porkbun
2. **SSL Certificate**: Download your SSL certificate package from Porkbun
3. **DNS Configuration**: Point your domain to your server's IP address
4. **Server Access**: SSH access to your Ubuntu server

## Step 1: Download SSL Certificates from Porkbun

1. Log into your Porkbun account
2. Navigate to your domain management
3. Go to SSL certificates section
4. Download the certificate package (usually a ZIP file)
5. Extract the files - you should have:
   - `craigybabyj.com.crt` (your certificate)
   - `craigybabyj.com.key` (your private key)
   - `ca-bundle.crt` (certificate authority bundle)

## Step 2: Prepare SSL Files on Server

On your Ubuntu server, create the SSL directory and upload your certificates:

```bash
# Create SSL directory
mkdir -p ssl

# Upload your certificate files to the ssl/ directory
# You can use scp, sftp, or any file transfer method
# The files should be:
# - ssl/craigybabyj.com.crt
# - ssl/craigybabyj.com.key
# - ssl/ca-bundle.crt
```

## Step 3: Deploy with SSL

Run the automated setup script:

```bash
# Make the script executable
chmod +x setup-porkbun-ssl.sh

# Run the setup script
./setup-porkbun-ssl.sh
```

The script will:
- Verify all SSL certificate files are present
- Stop any existing containers
- Create necessary directories with proper permissions
- Copy SSL certificates to secure locations
- Deploy the SSL-enabled Docker Compose stack
- Test the deployment

## Step 4: Verify SSL Setup

After deployment, test your HTTPS setup:

```bash
# Test HTTPS connectivity
curl -I https://craigybabyj.com/health

# Check SSL certificate details
openssl s_client -connect craigybabyj.com:443 -servername craigybabyj.com < /dev/null

# View container logs
sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml logs
```

## Configuration Files

### docker-compose.porkbun-ssl.yml
Complete Docker Compose configuration with:
- CraigyBabyJ Fileserver container
- Nginx reverse proxy with SSL
- Proper volume mappings for certificates and data
- Health checks and networking

### nginx-porkbun.conf
Nginx configuration featuring:
- HTTP to HTTPS redirection
- SSL/TLS security settings
- Security headers (HSTS, CSP, etc.)
- Rate limiting for uploads
- Proper proxy configuration

## Security Features

- **TLS 1.2/1.3**: Modern encryption protocols
- **HSTS**: HTTP Strict Transport Security
- **Security Headers**: X-Frame-Options, CSP, etc.
- **Rate Limiting**: Protection against abuse
- **Secure Certificate Storage**: Proper file permissions

## Troubleshooting

### SSL Certificate Issues
```bash
# Check certificate validity
openssl x509 -in ssl/craigybabyj.com.crt -text -noout

# Verify certificate chain
openssl verify -CAfile ssl/ca-bundle.crt ssl/craigybabyj.com.crt
```

### Container Issues
```bash
# Check container status
sudo docker ps

# View detailed logs
sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml logs nginx
sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml logs craigybabyj-fileserver
```

### DNS Issues
```bash
# Check DNS resolution
nslookup craigybabyj.com
dig craigybabyj.com A
```

## Management Commands

```bash
# View logs
sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml logs

# Restart services
sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml restart

# Stop services
sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml down

# Update and restart
sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml pull
sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml up -d
```

## Firewall Configuration

Make sure your firewall allows HTTPS traffic:

```bash
# Ubuntu/Debian with ufw
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# CentOS/RHEL with firewalld
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## Certificate Renewal

Porkbun SSL certificates typically have a 1-year validity. To renew:

1. Download new certificates from Porkbun before expiration
2. Replace the files in the `ssl/` directory
3. Run the setup script again or manually copy to `/opt/craigybabyj-fileserver/ssl/`
4. Restart the nginx container:
   ```bash
   sudo docker-compose -f /opt/craigybabyj-fileserver/docker-compose.porkbun-ssl.yml restart nginx
   ```

## Support

If you encounter issues:
1. Check the container logs
2. Verify DNS configuration
3. Test certificate validity
4. Ensure firewall allows HTTPS traffic
5. Check that your domain points to the correct IP address