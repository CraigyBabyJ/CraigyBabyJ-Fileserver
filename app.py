import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, abort
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import datetime
import mimetypes
import re
from functools import wraps
import time
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import json
import hashlib
import hmac

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))

# Security Configuration
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB file size limit

# Allowed file extensions (whitelist)
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'zip', '7z', 'rar', 'tar', 'gz',
    'mp3', 'wav', 'mp4', 'avi', 'mkv', 'mov',
    'scs', 'json', 'xml', 'csv'
}

# Rate limiting storage
request_counts = {}
RATE_LIMIT_REQUESTS = 10  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds

# Session timeout (30 minutes)
SESSION_TIMEOUT = 30 * 60

# CSRF token storage
csrf_tokens = {}

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Create data directory for user storage
os.makedirs('data', exist_ok=True)

# User management
USERS_FILE = 'data/users.json'

# Analytics storage file
ANALYTICS_FILE = 'data/analytics.json'

def load_analytics():
    """Load analytics data from file"""
    try:
        if os.path.exists(ANALYTICS_FILE):
            with open(ANALYTICS_FILE, 'r') as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError):
        pass
    
    # Return default structure
    return {
        'downloads': {},  # filename -> {count, last_download, users: []}
        'uploads': {},    # filename -> {count, upload_date, user}
        'user_activity': {}  # username -> {downloads: [], uploads: [], last_activity}
    }

def save_analytics(analytics_data):
    """Save analytics data to file"""
    try:
        with open(ANALYTICS_FILE, 'w') as f:
            json.dump(analytics_data, f, indent=2, default=str)
    except IOError:
        pass

def track_download(filename, username, folder=''):
    """Track file download for analytics"""
    analytics = load_analytics()
    current_time = datetime.datetime.now().isoformat()
    
    # Track file downloads
    file_key = f"{folder}/{filename}" if folder else filename
    if file_key not in analytics['downloads']:
        analytics['downloads'][file_key] = {
            'count': 0,
            'last_download': None,
            'users': []
        }
    
    analytics['downloads'][file_key]['count'] += 1
    analytics['downloads'][file_key]['last_download'] = current_time
    
    # Track unique users who downloaded this file
    if username not in analytics['downloads'][file_key]['users']:
        analytics['downloads'][file_key]['users'].append(username)
    
    # Track user activity
    if username not in analytics['user_activity']:
        analytics['user_activity'][username] = {
            'downloads': [],
            'uploads': [],
            'last_activity': None
        }
    
    analytics['user_activity'][username]['downloads'].append({
        'file': file_key,
        'timestamp': current_time
    })
    analytics['user_activity'][username]['last_activity'] = current_time
    
    # Keep only last 100 downloads per user to prevent excessive data
    if len(analytics['user_activity'][username]['downloads']) > 100:
        analytics['user_activity'][username]['downloads'] = analytics['user_activity'][username]['downloads'][-100:]
    
    save_analytics(analytics)

def track_upload(filename, username, folder=''):
    """Track file upload for analytics"""
    analytics = load_analytics()
    current_time = datetime.datetime.now().isoformat()
    
    # Track file uploads
    file_key = f"{folder}/{filename}" if folder else filename
    analytics['uploads'][file_key] = {
        'count': analytics['uploads'].get(file_key, {}).get('count', 0) + 1,
        'upload_date': current_time,
        'user': username
    }
    
    # Track user activity
    if username not in analytics['user_activity']:
        analytics['user_activity'][username] = {
            'downloads': [],
            'uploads': [],
            'last_activity': None
        }
    
    analytics['user_activity'][username]['uploads'].append({
        'file': file_key,
        'timestamp': current_time
    })
    analytics['user_activity'][username]['last_activity'] = current_time
    
    # Keep only last 100 uploads per user to prevent excessive data
    if len(analytics['user_activity'][username]['uploads']) > 100:
        analytics['user_activity'][username]['uploads'] = analytics['user_activity'][username]['uploads'][-100:]
    
    save_analytics(analytics)

def load_users():
    """Load users from JSON file"""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    return {}

def save_users(users):
    """Save users to JSON file"""
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def hash_password(password):
    """Hash a password using PBKDF2 with SHA256"""
    import base64
    salt = os.urandom(32)  # 32 bytes = 256 bits
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    # Encode as base64 for storage
    return base64.b64encode(salt + pwdhash).decode('utf-8')

def verify_password(stored_password, provided_password):
    """Verify a stored password against provided password"""
    import base64
    try:
        # Decode from base64
        stored_data = base64.b64decode(stored_password.encode('utf-8'))
        salt = stored_data[:32]
        stored_hash = stored_data[32:]
        pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return pwdhash == stored_hash
    except:
        return False

def create_user(username, password, is_admin=False):
    """Create a new user"""
    users = load_users()
    if username in users:
        return False, "User already exists"
    
    users[username] = {
        'password_hash': hash_password(password),
        'is_admin': is_admin,
        'created_at': datetime.datetime.now().isoformat(),
        'last_login': None
    }
    save_users(users)
    return True, "User created successfully"

def authenticate_user(username, password):
    """Authenticate a user"""
    users = load_users()
    if username not in users:
        return False, None
    
    user = users[username]
    if verify_password(user['password_hash'], password):
        # Update last login
        user['last_login'] = datetime.datetime.now().isoformat()
        users[username] = user
        save_users(users)
        return True, user
    return False, None

def is_admin(username):
    """Check if user is admin"""
    users = load_users()
    return users.get(username, {}).get('is_admin', False)

# Initialize with default admin user if no users exist
def initialize_default_admin():
    """Create default admin user if no users exist"""
    users = load_users()
    if not users:
        # Create default admin user
        admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
        create_user('admin', admin_password, is_admin=True)
        print(f"Default admin user created: admin / {admin_password}")

# Initialize default admin
initialize_default_admin()

# Configure logging for login attempts
login_logger = logging.getLogger('login_attempts')
login_logger.setLevel(logging.INFO)

# Create rotating file handler for login logs (max 10MB, keep 5 backup files)
login_handler = RotatingFileHandler('logs/login_attempts.log', maxBytes=10*1024*1024, backupCount=5)
login_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
login_handler.setFormatter(login_formatter)
login_logger.addHandler(login_handler)

def get_client_ip():
    """Get the real client IP address, considering proxies"""
    if request.headers.get('X-Forwarded-For'):
        # Handle multiple IPs in X-Forwarded-For header
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def log_login_attempt(ip_address, success, username=None, user_agent=None):
    """Log login attempts with IP address and other details"""
    status = "SUCCESS" if success else "FAILED"
    user_agent = user_agent or request.headers.get('User-Agent', 'Unknown')
    
    log_message = f"IP: {ip_address} | Status: {status} | User-Agent: {user_agent}"
    if username:
        log_message += f" | Username: {username}"
    
    if success:
        login_logger.info(f"LOGIN {status} - {log_message}")
    else:
        login_logger.warning(f"LOGIN {status} - {log_message}")

def require_admin():
    """Decorator to require admin privileges"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('authenticated'):
                return redirect(url_for('login'))
            
            username = session.get('username')
            if not username or not is_admin(username):
                flash('Admin privileges required.', 'error')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_csrf_token():
    """Generate a CSRF token for the current session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    if 'csrf_token' not in session:
        return False
    return session['csrf_token'] == token

def csrf_protect():
    """CSRF protection decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == 'POST':
                # Check for CSRF token in form data or JSON
                token = None
                if request.is_json:
                    data = request.get_json()
                    token = data.get('csrf_token') if data else None
                else:
                    token = request.form.get('csrf_token')
                
                if not token or not validate_csrf_token(token):
                    return jsonify({'error': 'CSRF token validation failed'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Security helper functions
def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def rate_limit():
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
            current_time = time.time()
            
            # Clean old entries
            for ip in list(request_counts.keys()):
                request_counts[ip] = [req_time for req_time in request_counts[ip] 
                                    if current_time - req_time < RATE_LIMIT_WINDOW]
                if not request_counts[ip]:
                    del request_counts[ip]
            
            # Check rate limit
            if client_ip in request_counts:
                if len(request_counts[client_ip]) >= RATE_LIMIT_REQUESTS:
                    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
                request_counts[client_ip].append(current_time)
            else:
                request_counts[client_ip] = [current_time]
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_session_timeout():
    """Check if session has timed out"""
    if 'authenticated' in session and 'login_time' in session:
        if time.time() - session['login_time'] > SESSION_TIMEOUT:
            session.clear()
            return False
    return True

def validate_folder_name(folder_name):
    """Validate folder name for security"""
    if not folder_name:
        return True  # Empty folder name is allowed (root)
    
    # Check for dangerous patterns
    if '..' in folder_name or '/' in folder_name or '\\' in folder_name:
        return False
    
    # Only allow alphanumeric, spaces, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9\s\-_]+$', folder_name):
        return False
    
    # Limit length
    if len(folder_name) > 50:
        return False
    
    return True

# Password from environment variable
SITE_PASSWORD = os.getenv('SITE_PASSWORD', 'defaultpassword123')

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return response

@app.route('/')
def index():
    if not check_session_timeout() or 'authenticated' not in session:
        return redirect(url_for('login'))
    csrf_token = generate_csrf_token()
    return render_template('upload.html', csrf_token=csrf_token)

@app.route('/login', methods=['GET', 'POST'])
@rate_limit()
def login():
    client_ip = get_client_ip()
    
    if request.method == 'POST':
        # Validate CSRF token for POST requests
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not validate_csrf_token(csrf_token):
            flash('Security validation failed. Please try again.', 'error')
            return render_template('login.html', csrf_token=generate_csrf_token())
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            log_login_attempt(client_ip, success=False, username=username)
            flash('Username and password are required.', 'error')
            return render_template('login.html', csrf_token=generate_csrf_token())
        
        # Try new user system first
        success, user_data = authenticate_user(username, password)
        if success:
            session['authenticated'] = True
            session['username'] = username
            session['is_admin'] = user_data.get('is_admin', False)
            session['login_time'] = time.time()
            
            # Log successful login
            log_login_attempt(client_ip, success=True, username=username)
            
            return redirect(url_for('index'))
        else:
            # Fallback to old password system for backward compatibility
            if password == SITE_PASSWORD:
                session['authenticated'] = True
                session['username'] = 'legacy_user'
                session['is_admin'] = True  # Legacy users are admin
                session['login_time'] = time.time()
                
                # Log successful login
                log_login_attempt(client_ip, success=True, username='legacy_user')
                
                return redirect(url_for('index'))
            else:
                # Log failed login attempt
                log_login_attempt(client_ip, success=False, username=username)
                
                flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@rate_limit()
@csrf_protect()
def upload_file():
    if not check_session_timeout() or 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get the current folder from the request
    current_folder = request.form.get('folder', '').strip()
    
    # Validate folder name
    if not validate_folder_name(current_folder):
        return jsonify({'error': 'Invalid folder name'}), 400
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Validate file type
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    if file:
        # Create filename with timestamp to avoid conflicts
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + secure_filename(file.filename)
        
        # Determine the upload path based on current folder
        if current_folder:
            # Security: prevent directory traversal
            safe_folder = secure_filename(current_folder)
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_folder)
            os.makedirs(upload_path, exist_ok=True)
            filepath = os.path.join(upload_path, filename)
        else:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(filepath)
            file_size = os.path.getsize(filepath)
            
            # Track upload analytics
            username = session.get('username', 'anonymous')
            track_upload(filename, username, current_folder)
            
            return jsonify({
                'success': True, 
                'filename': filename,
                'size': file_size,
                'message': f'File "{file.filename}" uploaded successfully!'
            })
        except Exception as e:
            return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/files')
@rate_limit()
def list_files():
    if not check_session_timeout() or 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get folder from query parameter
    folder = request.args.get('folder', '')
    
    # Validate folder name
    if not validate_folder_name(folder):
        return jsonify({'error': 'Invalid folder name'}), 400
    
    # Security: prevent directory traversal
    if folder:
        folder = secure_filename(folder)
    
    # Determine the current directory
    if folder:
        current_dir = os.path.join(app.config['UPLOAD_FOLDER'], folder)
    else:
        current_dir = app.config['UPLOAD_FOLDER']
    
    if not os.path.exists(current_dir):
        return jsonify({'error': 'Folder not found'}), 404
    
    files = []
    folders = []
    
    for item in os.listdir(current_dir):
        item_path = os.path.join(current_dir, item)
        
        if os.path.isdir(item_path):
            # It's a folder
            folder_stat = os.stat(item_path)
            folders.append({
                'name': item,
                'type': 'folder',
                'modified': datetime.datetime.fromtimestamp(folder_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'path': os.path.join(folder, item) if folder else item
            })
        elif os.path.isfile(item_path):
            # It's a file
            file_stat = os.stat(item_path)
            download_path = os.path.join(folder, item) if folder else item
            files.append({
                'name': item,
                'type': 'file',
                'size': file_stat.st_size,
                'modified': datetime.datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })
    
    # Sort folders first, then files, both by name
    folders.sort(key=lambda x: x['name'].lower())
    files.sort(key=lambda x: x['name'].lower())
    
    # Combine folders and files into a single list
    all_items = folders + files
    
    return jsonify({
        'files': all_items,
        'current_folder': folder,
        'parent_folder': os.path.dirname(folder) if folder else None
    })

@app.route('/create_folder', methods=['POST'])
@rate_limit()
@csrf_protect()
def create_folder():
    if not check_session_timeout() or 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Folder name is required'}), 400
    
    folder_name = data['name'].strip()
    current_folder = data.get('currentFolder', '').strip()
    
    # Validate folder names
    if not validate_folder_name(folder_name):
        return jsonify({'error': 'Invalid folder name. Use only letters, numbers, spaces, hyphens, and underscores.'}), 400
    
    if not validate_folder_name(current_folder):
        return jsonify({'error': 'Invalid current folder name'}), 400
    
    # Security: prevent directory traversal and use secure filename
    safe_folder_name = secure_filename(folder_name)
    if not safe_folder_name:
        return jsonify({'error': 'Invalid folder name'}), 400
    
    # Determine the base path
    if current_folder:
        safe_current_folder = secure_filename(current_folder)
        base_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_current_folder)
    else:
        base_path = app.config['UPLOAD_FOLDER']
    
    folder_path = os.path.join(base_path, safe_folder_name)
    
    if os.path.exists(folder_path):
        return jsonify({'error': 'Folder already exists'}), 400
    
    try:
        os.makedirs(folder_path, exist_ok=False)
        return jsonify({'success': True, 'message': f'Folder "{folder_name}" created successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to create folder: {str(e)}'}), 500

@app.route('/rename_folder', methods=['POST'])
@rate_limit()
@csrf_protect()
def rename_folder():
    if not check_session_timeout() or 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    if not data or 'old_name' not in data or 'new_name' not in data:
        return jsonify({'error': 'Both old and new folder names are required'}), 400
    
    old_name = data['old_name'].strip()
    new_name = data['new_name'].strip()
    current_folder = data.get('currentFolder', '').strip()
    
    # Validate folder names
    if not validate_folder_name(old_name) or not validate_folder_name(new_name):
        return jsonify({'error': 'Invalid folder name. Use only letters, numbers, spaces, hyphens, and underscores.'}), 400
    
    if not validate_folder_name(current_folder):
        return jsonify({'error': 'Invalid current folder name'}), 400
    
    # Security: prevent directory traversal and use secure filename
    safe_old_name = secure_filename(old_name)
    safe_new_name = secure_filename(new_name)
    
    if not safe_old_name or not safe_new_name:
        return jsonify({'error': 'Invalid folder name'}), 400
    
    # Determine the base path
    if current_folder:
        safe_current_folder = secure_filename(current_folder)
        base_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_current_folder)
    else:
        base_path = app.config['UPLOAD_FOLDER']
    
    old_path = os.path.join(base_path, safe_old_name)
    new_path = os.path.join(base_path, safe_new_name)
    
    if not os.path.exists(old_path):
        return jsonify({'error': 'Folder not found'}), 404
    
    if os.path.exists(new_path):
        return jsonify({'error': 'A folder with the new name already exists'}), 400
    
    try:
        os.rename(old_path, new_path)
        return jsonify({'success': True, 'message': f'Folder renamed from "{old_name}" to "{new_name}"'})
    except Exception as e:
        return jsonify({'error': f'Failed to rename folder: {str(e)}'}), 500

@app.route('/download/<filename>')
@rate_limit()
def download_file(filename):
    if not check_session_timeout() or 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get folder from query parameter
    folder = request.args.get('folder', '')
    
    # Validate folder name
    if not validate_folder_name(folder):
        return jsonify({'error': 'Invalid folder name'}), 400
    
    # Security: prevent directory traversal
    safe_filename = secure_filename(filename)
    if not safe_filename:
        abort(404)
    
    # Determine the file path
    if folder:
        safe_folder = secure_filename(folder)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_folder, safe_filename)
    else:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        abort(404)
    
    # Get the original filename (remove timestamp prefix if present)
    original_filename = filename
    if '_' in filename:
        parts = filename.split('_', 2)
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
            original_filename = parts[2]
    
    # Track download analytics
    username = session.get('username', 'anonymous')
    track_download(filename, username, folder)
    
    return send_file(file_path, as_attachment=True, download_name=original_filename)

@app.route('/delete/<filename>', methods=['POST'])
@rate_limit()
@csrf_protect()
def delete_file(filename):
    if not check_session_timeout() or 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get folder from query parameter
    folder = request.args.get('folder', '')
    
    # Validate folder name
    if not validate_folder_name(folder):
        return jsonify({'error': 'Invalid folder name'}), 400
    
    # Security: prevent directory traversal
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return jsonify({'error': 'Invalid filename'}), 400
    
    # Determine the file path
    if folder:
        safe_folder = secure_filename(folder)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_folder, safe_filename)
    else:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        os.remove(file_path)
        return jsonify({'success': True, 'message': f'File "{filename}" deleted successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to delete file: {str(e)}'}), 500

@app.route('/admin/users')
@rate_limit()
@require_admin()
def admin_users():
    """Admin interface for user management"""
    users = load_users()
    csrf_token = generate_csrf_token()
    return render_template('admin_users.html', users=users, csrf_token=csrf_token)

@app.route('/admin/users/create', methods=['POST'])
@rate_limit()
@csrf_protect()
@require_admin()
def create_user_route():
    """Create a new user"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    is_admin = request.form.get('is_admin') == 'on'
    
    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('admin_users'))
    
    success, message = create_user(username, password, is_admin)
    if success:
        flash(f'User "{username}" created successfully.', 'success')
    else:
        flash(message, 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<username>', methods=['POST'])
@rate_limit()
@csrf_protect()
@require_admin()
def delete_user_route(username):
    """Delete a user"""
    if username == session.get('username'):
        flash('Cannot delete your own account.', 'error')
        return redirect(url_for('admin_users'))
    
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        flash(f'User "{username}" deleted successfully.', 'success')
    else:
        flash('User not found.', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle-admin/<username>', methods=['POST'])
@rate_limit()
@csrf_protect()
@require_admin()
def toggle_admin_route(username):
    """Toggle admin status of a user"""
    if username == session.get('username'):
        flash('Cannot modify your own admin status.', 'error')
        return redirect(url_for('admin_users'))
    
    users = load_users()
    if username in users:
        users[username]['is_admin'] = not users[username].get('is_admin', False)
        save_users(users)
        status = 'admin' if users[username]['is_admin'] else 'regular user'
        flash(f'User "{username}" is now a {status}.', 'success')
    else:
        flash('User not found.', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/reset-password/<username>', methods=['POST'])
@rate_limit()
@csrf_protect()
@require_admin()
def reset_password_route(username):
    """Reset user password"""
    new_password = request.form.get('new_password', '')
    
    if not new_password:
        flash('New password is required.', 'error')
        return redirect(url_for('admin_users'))
    
    users = load_users()
    if username in users:
        users[username]['password_hash'] = hash_password(new_password)
        save_users(users)
        flash(f'Password reset for user "{username}".', 'success')
    else:
        flash('User not found.', 'error')
    
    return redirect(url_for('admin_users'))

import secrets
import string

def generate_secure_password(length=12):
    """Generate a secure random password"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

@app.route('/admin/generate-password')
@rate_limit()
@require_admin()
def generate_password():
    """Generate a secure password and return it as JSON"""
    password = generate_secure_password()
    password_hash = hash_password(password)
    return jsonify({
        'password': password,
        'hash': password_hash
    })

@app.route('/admin/analytics')
@rate_limit()
@require_admin()
def admin_analytics():
    analytics_data = load_analytics()
    
    # Calculate total stats
    total_downloads = sum(data.get('count', 0) for data in analytics_data.get('downloads', {}).values())
    total_uploads = sum(data.get('count', 0) for data in analytics_data.get('uploads', {}).values())
    
    # Get unique users from user_activity
    unique_users = len(analytics_data.get('user_activity', {}))
    
    # Get unique files from downloads and uploads
    unique_files = set()
    unique_files.update(analytics_data.get('downloads', {}).keys())
    unique_files.update(analytics_data.get('uploads', {}).keys())
    
    # Calculate download counts
    download_counts = {}
    for filename, data in analytics_data.get('downloads', {}).items():
        download_counts[filename] = data.get('count', 0)
    
    top_downloads = sorted(download_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Calculate upload counts
    upload_counts = {}
    for filename, data in analytics_data.get('uploads', {}).items():
        upload_counts[filename] = data.get('count', 0)
    
    top_uploads = sorted(upload_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Get recent activity from user activity data
    recent_activity = []
    for username, user_data in analytics_data.get('user_activity', {}).items():
        # Add recent downloads
        for download in user_data.get('downloads', [])[-25:]:
            recent_activity.append({
                'type': 'download',
                'filename': download.get('file', ''),
                'username': username,
                'timestamp': download.get('timestamp', ''),
                'folder': ''
            })
        
        # Add recent uploads
        for upload in user_data.get('uploads', [])[-25:]:
            recent_activity.append({
                'type': 'upload',
                'filename': upload.get('file', ''),
                'username': username,
                'timestamp': upload.get('timestamp', ''),
                'folder': ''
            })
    
    # Sort by timestamp (newest first)
    recent_activity.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    recent_activity = recent_activity[:50]
    
    # User activity summary
    user_activity = {}
    for username, user_data in analytics_data.get('user_activity', {}).items():
        user_activity[username] = {
            'downloads': len(user_data.get('downloads', [])),
            'uploads': len(user_data.get('uploads', [])),
            'last_activity': user_data.get('last_activity', '')
        }
    
    return render_template('admin_analytics.html',
                         total_downloads=total_downloads,
                         total_uploads=total_uploads,
                         unique_users=unique_users,
                         unique_files=len(unique_files),
                         top_downloads=top_downloads,
                         top_uploads=top_uploads,
                         recent_activity=recent_activity,
                         user_activity=user_activity,
                         csrf_token=generate_csrf_token())

if __name__ == '__main__':
    print(f"Upload folder: {os.path.abspath(UPLOAD_FOLDER)}")
    print(f"Site password: {SITE_PASSWORD}")
    
    # Check if we're in production mode
    is_production = os.getenv('PRODUCTION_MODE', 'false').lower() == 'true'
    debug_mode = not is_production
    
    if is_production:
        print("Running in PRODUCTION mode - Debug disabled")
    else:
        print("Running in DEVELOPMENT mode - Debug enabled")
    
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)