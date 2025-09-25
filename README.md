# CraigyBabyJ-Fileserver 🚀

A production-ready Flask-based file upload server with user management, authentication, and Docker deployment support.

## ✨ Features

- 🔐 **Secure Authentication** - Password-protected access with rate limiting
- 👥 **User Management** - Admin panel for user creation and management
- 📁 **File Organization** - User-specific upload directories
- 🐳 **Docker Ready** - Full containerization with nginx reverse proxy
- 🔒 **SSL Support** - HTTPS with Let's Encrypt integration
- 🛡️ **Security Headers** - XSS protection, CSRF prevention, security headers
- 📊 **Health Monitoring** - Built-in health checks and logging
- ⚡ **Rate Limiting** - Protection against brute force attacks
- 🎨 **Modern UI** - Clean, responsive web interface

## 🚀 Quick Start

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/craigybabyj/CraigyBabyJ-Fileserver.git
   cd CraigyBabyJ-Fileserver
   ```

2. **Set up environment**
   ```bash
   # Copy environment template
   cp .env.example .env
   
   # Edit .env with your settings
   # Change SITE_PASSWORD and SECRET_KEY
   ```

3. **Run with Python**
   ```bash
   pip install -r requirements.txt
   python app.py
   ```

4. **Or run with Docker (recommended)**
   ```bash
   # Development mode with live reloading
   docker-compose -f docker-compose.dev.yml up -d
   
   # Production mode
   docker-compose up -d
   ```

### Production Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for complete Ubuntu server deployment instructions.

## 📋 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SITE_PASSWORD` | Main login password | `changeme123` |
| `SECRET_KEY` | Flask secret key | `your-secret-key-here` |
| `PRODUCTION_MODE` | Enable production mode | `false` |
| `FLASK_HOST` | Flask host binding | `0.0.0.0` |
| `FLASK_PORT` | Flask port | `5000` |
| `MAX_UPLOAD_SIZE` | Max file size (MB) | `500` |
| `LOGIN_RATE_LIMIT` | Login attempts per minute | `5` |

## 🏗️ Project Structure

```
CraigyBabyJ-Fileserver/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env                  # Environment variables
├── Dockerfile            # Docker container definition
├── docker-compose.yml    # Production Docker setup
├── docker-compose.dev.yml # Development Docker setup
├── nginx.conf            # Nginx reverse proxy config
├── templates/            # HTML templates
│   ├── login.html
│   ├── upload.html
│   └── admin_users.html
├── data/                 # Application data
│   └── users.json
├── uploads/              # User uploaded files
└── logs/                 # Application logs
```

## 🔧 API Endpoints

- `GET /` - Main upload interface
- `POST /login` - User authentication
- `POST /upload` - File upload endpoint
- `GET /admin/users` - User management (admin only)
- `POST /admin/create_user` - Create new user
- `GET /health` - Health check endpoint

## 🐳 Docker Commands

```bash
# Development
docker-compose -f docker-compose.dev.yml up -d    # Start dev environment
docker-compose -f docker-compose.dev.yml down     # Stop dev environment

# Production
docker-compose up -d                               # Start production
docker-compose down                                # Stop production
docker-compose logs -f app                        # View app logs
docker-compose exec app bash                      # Access container

# Build
docker build -t craigybabyj-fileserver .                  # Build image
```

## 🛡️ Security Features

- **Authentication**: Password-based login system
- **Rate Limiting**: Prevents brute force attacks
- **CSRF Protection**: Cross-site request forgery prevention
- **Security Headers**: XSS, clickjacking, and content type protection
- **SSL/TLS**: HTTPS encryption with Let's Encrypt
- **Container Security**: Non-root user, minimal attack surface
- **Input Validation**: File type and size restrictions

## 📝 License 

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

**Note**: This license restricts commercial use. The software is free for personal, educational, and non-commercial purposes. Any derivative works must also be licensed under GPL v3.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

If you encounter any issues or have questions, please open an issue on GitHub.

## 🎯 Roadmap

- [ ] Multi-file upload support
- [ ] File sharing with expiration links
- [ ] Advanced user permissions
- [ ] File preview functionality
- [ ] API key authentication
- [ ] Webhook notifications

A simple, secure file upload website that allows friends to upload files with no size limits. Features drag-and-drop functionality and password protection.

## Features

- 🔐 Simple password authentication (stored in .env file)
- 📁 Drag and drop file uploads
- 📊 No file size limits
- 🎨 Modern, responsive web interface
- 🖥️ Cross-platform (Windows & Linux)
- 📱 Mobile-friendly design
- ⚡ Real-time upload progress
- 🔄 Multiple file uploads

## Quick Setup

### 1. Install Python Dependencies

**Windows:**
```bash
pip install -r requirements.txt
```

**Linux:**
```bash
pip3 install -r requirements.txt
```

### 2. Configure Password

Edit the `.env` file and change the password:
```
SITE_PASSWORD=your_secure_password_here
```

### 3. Run the Server

**Windows:**
```bash
python app.py
```

**Linux:**
```bash
python3 app.py
```

The server will start on `http://localhost:5000`

## Usage

1. **Access the site**: Go to `http://your-server-ip:5000` in a web browser
2. **Login**: Enter the password you set in the `.env` file
3. **Upload files**: 
   - Drag and drop files onto the upload area, OR
   - Click "Browse Files" to select files manually
   - Multiple files can be uploaded at once

## File Storage

- Uploaded files are stored in the `uploads/` folder
- Files are automatically renamed with timestamps to prevent conflicts
- Original filenames are preserved in the display

## Network Access

### For Local Network Access:
The server runs on `0.0.0.0:5000` by default, making it accessible from other devices on your network.

**Find your IP address:**

**Windows:**
```bash
ipconfig
```

**Linux:**
```bash
ip addr show
```

Then share `http://YOUR_IP_ADDRESS:5000` with your friends.

### For Internet Access (Linux Server):
If running on a Linux server, make sure:
1. Port 5000 is open in your firewall
2. Your router forwards port 5000 to your server
3. Use your public IP address or domain name

## Security Notes

- Change the default password in `.env` before sharing with friends
- The `.env` file should never be shared publicly
- Consider using HTTPS in production environments
- Files are stored locally - ensure you have enough disk space

## Customization

### Change Upload Directory
Edit `app.py` and modify the `UPLOAD_FOLDER` variable:
```python
UPLOAD_FOLDER = 'your_custom_folder'
```

### Change Port
Edit `app.py` and modify the port in the last line:
```python
app.run(host='0.0.0.0', port=8080, debug=True)
```

## Troubleshooting

### "Permission Denied" errors
Make sure the script has write permissions to create the `uploads/` folder.

### Can't access from other devices
- Check your firewall settings
- Ensure you're using the correct IP address
- Try disabling Windows Defender Firewall temporarily for testing

### Large file uploads failing
- Check available disk space
- Some browsers may have limits on very large files (>2GB)

## File Structure
```
messyuploadserver/
├── app.py              # Main Flask application
├── .env                # Password configuration
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── templates/         # HTML templates
│   ├── login.html     # Login page
│   └── upload.html    # Upload interface
└── uploads/           # Uploaded files (created automatically)
```

## Support

This is a simple file upload server designed for friends and small groups. For production use, consider additional security measures and proper web server deployment.
