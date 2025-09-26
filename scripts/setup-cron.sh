#!/bin/bash

# CraigyBabyJ Fileserver - Cron Setup Script
# Sets up automated backup and monitoring jobs

set -e

APP_DIR="/opt/craigybabyj-fileserver"
SCRIPTS_DIR="$APP_DIR/scripts"

echo "🛩️  Setting up automated jobs for CraigyBabyJ Fileserver"
echo "======================================================="

# Make scripts executable
chmod +x "$SCRIPTS_DIR/backup.sh"
chmod +x "$SCRIPTS_DIR/monitor.sh"

echo "✅ Made scripts executable"

# Create cron jobs
echo "📅 Setting up cron jobs..."

# Backup: Daily at 2 AM
BACKUP_CRON="0 2 * * * $SCRIPTS_DIR/backup.sh >> /var/log/craigybabyj-backup.log 2>&1"

# Monitor: Every 5 minutes
MONITOR_CRON="*/5 * * * * $SCRIPTS_DIR/monitor.sh >> /var/log/craigybabyj-monitor.log 2>&1"

# Add to crontab
(crontab -l 2>/dev/null || echo "") | grep -v "craigybabyj" | {
    cat
    echo "# CraigyBabyJ Fileserver automated jobs"
    echo "$BACKUP_CRON"
    echo "$MONITOR_CRON"
} | crontab -

echo "✅ Cron jobs added:"
echo "   - Backup: Daily at 2:00 AM"
echo "   - Monitor: Every 5 minutes"

# Create log files with proper permissions
touch /var/log/craigybabyj-backup.log
touch /var/log/craigybabyj-monitor.log
chmod 644 /var/log/craigybabyj-*.log

echo "✅ Log files created"

# Show current crontab
echo "📋 Current cron jobs:"
crontab -l | grep -A 3 "CraigyBabyJ"

echo "🎉 Cron setup completed!"
echo ""
echo "📝 To view logs:"
echo "   Backup logs:  tail -f /var/log/craigybabyj-backup.log"
echo "   Monitor logs: tail -f /var/log/craigybabyj-monitor.log"
echo ""
echo "🔧 To modify cron jobs: crontab -e"