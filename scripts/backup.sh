#!/bin/bash

# CraigyBabyJ Fileserver - Backup Script
# Creates backups of uploads, configuration, and database

set -e

# Configuration
APP_DIR="/opt/craigybabyj-fileserver"
BACKUP_DIR="/opt/backups/craigybabyj-fileserver"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="fileserver_backup_$DATE"
RETENTION_DAYS=30

echo "🛩️  CraigyBabyJ Fileserver Backup - $DATE"
echo "============================================"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup archive
echo "📦 Creating backup archive..."
cd "$APP_DIR"

tar -czf "$BACKUP_DIR/$BACKUP_NAME.tar.gz" \
    --exclude='*.log' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='node_modules' \
    data/ \
    .env \
    docker-compose*.yml \
    nginx/ \
    *.service

echo "✅ Backup created: $BACKUP_DIR/$BACKUP_NAME.tar.gz"

# Calculate backup size
BACKUP_SIZE=$(du -h "$BACKUP_DIR/$BACKUP_NAME.tar.gz" | cut -f1)
echo "📊 Backup size: $BACKUP_SIZE"

# Clean old backups
echo "🧹 Cleaning old backups (older than $RETENTION_DAYS days)..."
find "$BACKUP_DIR" -name "fileserver_backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete

# List current backups
echo "📋 Current backups:"
ls -lh "$BACKUP_DIR"/fileserver_backup_*.tar.gz 2>/dev/null || echo "No backups found"

echo "✅ Backup completed successfully!"

# Optional: Upload to cloud storage (uncomment and configure as needed)
# echo "☁️  Uploading to cloud storage..."
# aws s3 cp "$BACKUP_DIR/$BACKUP_NAME.tar.gz" s3://your-backup-bucket/fileserver/
# echo "✅ Cloud upload completed!"

echo "🎉 Backup process finished!"