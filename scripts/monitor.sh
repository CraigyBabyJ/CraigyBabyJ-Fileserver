#!/bin/bash

# CraigyBabyJ Fileserver - Monitoring Script
# Checks system health and sends alerts if needed

set -e

# Configuration
APP_DIR="/opt/craigybabyj-fileserver"
LOG_FILE="/var/log/craigybabyj-monitor.log"
ALERT_EMAIL="admin@yourdomain.com"  # Configure your email
WEBHOOK_URL=""  # Optional: Slack/Discord webhook

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Alert function
send_alert() {
    local message="$1"
    local severity="$2"
    
    log "ALERT [$severity]: $message"
    
    # Email alert (requires mailutils)
    if command -v mail &> /dev/null && [ -n "$ALERT_EMAIL" ]; then
        echo "$message" | mail -s "CraigyBabyJ Fileserver Alert [$severity]" "$ALERT_EMAIL"
    fi
    
    # Webhook alert (optional)
    if [ -n "$WEBHOOK_URL" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚨 CraigyBabyJ Fileserver Alert [$severity]: $message\"}" \
            "$WEBHOOK_URL" 2>/dev/null || true
    fi
}

echo "🛩️  CraigyBabyJ Fileserver Health Check"
echo "======================================"

cd "$APP_DIR"

# Check if Docker is running
if ! systemctl is-active --quiet docker; then
    send_alert "Docker service is not running!" "CRITICAL"
    exit 1
fi

# Check if containers are running
if ! docker-compose ps | grep -q "Up"; then
    send_alert "Fileserver containers are not running!" "CRITICAL"
    echo -e "${RED}❌ Containers not running${NC}"
    docker-compose ps
    exit 1
else
    echo -e "${GREEN}✅ Containers running${NC}"
fi

# Check application health endpoint
if curl -f -s http://localhost:5000/health > /dev/null; then
    echo -e "${GREEN}✅ Application responding${NC}"
else
    send_alert "Application health check failed!" "WARNING"
    echo -e "${YELLOW}⚠️  Application not responding${NC}"
fi

# Check disk space
DISK_USAGE=$(df /opt | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    send_alert "Disk usage is at ${DISK_USAGE}%!" "WARNING"
    echo -e "${YELLOW}⚠️  High disk usage: ${DISK_USAGE}%${NC}"
elif [ "$DISK_USAGE" -gt 95 ]; then
    send_alert "Critical disk usage: ${DISK_USAGE}%!" "CRITICAL"
    echo -e "${RED}❌ Critical disk usage: ${DISK_USAGE}%${NC}"
else
    echo -e "${GREEN}✅ Disk usage: ${DISK_USAGE}%${NC}"
fi

# Check memory usage
MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
if [ "$MEMORY_USAGE" -gt 90 ]; then
    send_alert "High memory usage: ${MEMORY_USAGE}%!" "WARNING"
    echo -e "${YELLOW}⚠️  High memory usage: ${MEMORY_USAGE}%${NC}"
else
    echo -e "${GREEN}✅ Memory usage: ${MEMORY_USAGE}%${NC}"
fi

# Check container logs for errors
ERROR_COUNT=$(docker-compose logs --tail=100 2>/dev/null | grep -i "error\|exception\|failed" | wc -l)
if [ "$ERROR_COUNT" -gt 10 ]; then
    send_alert "High error count in logs: $ERROR_COUNT errors in last 100 lines!" "WARNING"
    echo -e "${YELLOW}⚠️  High error count: $ERROR_COUNT${NC}"
else
    echo -e "${GREEN}✅ Error count: $ERROR_COUNT${NC}"
fi

# Check SSL certificate expiry (if using HTTPS)
if [ -f "nginx/ssl/cert.pem" ]; then
    CERT_EXPIRY=$(openssl x509 -enddate -noout -in nginx/ssl/cert.pem | cut -d= -f2)
    CERT_EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s)
    CURRENT_EPOCH=$(date +%s)
    DAYS_UNTIL_EXPIRY=$(( (CERT_EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))
    
    if [ "$DAYS_UNTIL_EXPIRY" -lt 30 ]; then
        send_alert "SSL certificate expires in $DAYS_UNTIL_EXPIRY days!" "WARNING"
        echo -e "${YELLOW}⚠️  SSL cert expires in: $DAYS_UNTIL_EXPIRY days${NC}"
    else
        echo -e "${GREEN}✅ SSL cert expires in: $DAYS_UNTIL_EXPIRY days${NC}"
    fi
fi

# Check upload directory size
UPLOAD_SIZE=$(du -sh data/uploads 2>/dev/null | cut -f1 || echo "0")
echo -e "${GREEN}📊 Upload directory size: $UPLOAD_SIZE${NC}"

# Check recent activity
RECENT_UPLOADS=$(find data/uploads -type f -mtime -1 2>/dev/null | wc -l || echo "0")
echo -e "${GREEN}📈 Recent uploads (24h): $RECENT_UPLOADS${NC}"

log "Health check completed successfully"
echo -e "${GREEN}🎉 Health check completed!${NC}"