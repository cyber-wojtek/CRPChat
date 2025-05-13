import eventlet
eventlet.monkey_patch()
import os
import json
import time
import secrets
import logging
from datetime import datetime

import redis
from flask import Flask, render_template, request, redirect, url_for, make_response, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room

# Import custom modules
from database import DatabaseManager
from email_service import EmailService

# Basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# App configuration
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Redis configuration
redis_client = redis.Redis(
    host=os.environ.get('REDIS_HOST', 'localhost'),
    port=int(os.environ.get('REDIS_PORT', 6379)),
    password=os.environ.get('REDIS_PASSWORD'),
    decode_responses=True
)

# SocketIO with simpler config
socketio = SocketIO(
    app, 
    async_mode='eventlet',
    message_queue=f"redis://{redis_client.connection_pool.connection_kwargs['host']}:{redis_client.connection_pool.connection_kwargs['port']}",
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False
)

# Initialize services
db = DatabaseManager()
db.initialize_db()
email_service = EmailService(
    smtp_host="smtp.gmail.com",
    smtp_port=587,
    username="crpchat.live@gmail.com",
    password=os.environ.get('SMTP_PASSWORD')
)

# Configuration
MAX_HISTORY = 1000
RATE_LIMIT = 10
RATE_WINDOW = 60
SESSION_EXPIRE = 30 * 24 * 60 * 60

# Helper functions
def get_current_user():
    session_token = request.cookies.get('session_token')
    if not session_token:
        return None
    
    user_id = redis_client.get(f"session:{session_token}")
    if not user_id:
        return None
    
    redis_client.expire(f"session:{session_token}", SESSION_EXPIRE)
    user = db.get_user_by_id(int(user_id))
    return user if user and user['verified'] else None

def create_session(user_id):
    session_token = secrets.token_hex(32)
    redis_client.setex(f"session:{session_token}", SESSION_EXPIRE, user_id)
    redis_client.sadd("active_users", user_id)
    return session_token

def invalidate_session(session_token):
    user_id = redis_client.get(f"session:{session_token}")
    redis_client.delete(f"session:{session_token}")
    if user_id:
        other_sessions = redis_client.keys(f"session:*")
        if not any(redis_client.get(s) == user_id for s in other_sessions):
            redis_client.srem("active_users", user_id)

def check_rate_limit(ip):
    key = f"rate_limit:{ip}"
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, RATE_WINDOW)
    return count <= RATE_LIMIT

def get_rate_limit_info(ip):
    key = f"rate_limit:{ip}"
    count = int(redis_client.get(key) or 0)
    if count >= RATE_LIMIT:
        ttl = redis_client.ttl(key)
        return 0, ttl if ttl > 0 else 0
    return RATE_LIMIT - count, 0

def save_message(message_data):
    timestamp = int(time.time() * 1000)
    redis_client.zadd("chat:history", {json.dumps(message_data): timestamp})
    total = redis_client.zcard("chat:history")
    if total > MAX_HISTORY:
        redis_client.zremrangebyrank("chat:history", 0, total - MAX_HISTORY - 1)

def get_chat_history():
    messages = redis_client.zrange("chat:history", 0, -1)
    return [json.loads(msg) for msg in messages]

# Authentication decorator
def login_required(f):
    def decorated_function(*args, **kwargs):
        if get_current_user() is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Routes
@app.route('/')
@login_required
def index():
    user = get_current_user()
    active_users = redis_client.scard("active_users")
    if user:
        user['ip'] = request.remote_addr
        redis_client.sadd("active_users", user['id'])
    else:
        user = None
        flash("You must be logged in to access this page", 'warning')
        return redirect(url_for('login'))
    # Get chat history
    return render_template('index.html', user=user, active_users=active_users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not all([email, username, password, confirm_password]):
            flash("All fields are required", 'warning')
            return render_template('register.html')
        
        if password != confirm_password:
            flash("Passwords do not match", 'warning')
            return render_template('register.html')
        
        if not (3 <= len(username) <= 20):
            flash("Username must be between 3 and 20 characters", 'warning')
            return render_template('register.html')
        
        # Create user
        user_id = db.create_user(email, username, password)
        if isinstance(user_id, dict) and 'error' in user_id:
            flash(user_id['error'], 'error')
            return render_template('register.html')
        
        # Send verification email
        verification_code = db.create_verification_code(user_id)
        try:
            email_service.send_verification_email(email, verification_code, username)
        except Exception as e:
            logger.error(f"Failed to send verification email: {e}")
            flash("Account created but failed to send verification email", 'warning')
        
        return redirect(url_for('verify', user_id=user_id))
    
    return render_template('register.html')

@app.route('/verify/<int:user_id>', methods=['GET', 'POST'])
def verify(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        flash("User not found", 'error')
        return redirect(url_for('login'))
    
    if user['verified']:
        flash("Email already verified", 'success')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        if not code:
            flash("Verification code is required", 'warning')
            return render_template('verify.html', user_id=user_id)
        
        if db.verify_code(user_id, code):
            flash("Email verified successfully", 'success')
            return redirect(url_for('login'))
        else:
            flash("Invalid or expired verification code", 'error')
    
    return render_template('verify.html', user_id=user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = get_current_user()
    if user:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([email, password]):
            flash("Email and password are required")
            return render_template('login.html')
        
        user = db.authenticate_user(email, password)
        if not user:
            flash("Invalid email or password")
            return render_template('login.html')
        
        if not user['verified']:
            flash("Please verify your email first")
            return redirect(url_for('verify', user_id=user['id']))
        
        session_token = create_session(user['id'])
        response = make_response(redirect(url_for('index')))
        response.set_cookie('session_token', session_token, max_age=SESSION_EXPIRE, httponly=True)
        return response
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session_token = request.cookies.get('session_token')
    if session_token:
        invalidate_session(session_token)
    
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('session_token')
    return response

@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    return render_template('profile.html', user=user)

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    return jsonify({
        "active_users": redis_client.scard("active_users"),
        "total_messages": redis_client.zcard("chat:history")
    })

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    user = get_current_user()
    if not user:
        return False
    join_room(f"user_{user['id']}")
    logger.info(f"Socket connected: {user['username']}")

@socketio.on('disconnect')
def handle_disconnect():
    user = get_current_user()
    if user:
        leave_room(f"user_{user['id']}")
        logger.info(f"Socket disconnected: {user['username']}")

@socketio.on('join')
def handle_join():
    user = get_current_user()
    if not user:
        emit('unauthorized', {'message': 'You must be logged in'})
        return
    
    # Send chat history
    chat_history = get_chat_history()
    for msg in chat_history:
        # Mask IP for privacy
        ip_parts = msg['ip'].split('.')
        masked_msg = dict(msg)
        masked_msg['ip'] = f"{ip_parts[0]}.{ip_parts[1]}.***.***"
        emit('message', masked_msg)
    
    # Send active user count
    emit('active_users', {'count': redis_client.scard("active_users")})

@socketio.on('request_rate_limit')
def handle_request_ratelimit():
    user = get_current_user()
    if not user:
        emit('unauthorized', {'message': 'You must be logged in'})
        return
    
    ip = request.remote_addr
    remaining_messages, remaining_time = get_rate_limit_info(ip)
    
    if remaining_time > 0:
        emit('rate_limit', str(remaining_time))
    else:
        emit('until_rate_limit', str(remaining_messages))

@socketio.on('send_message')
def handle_send(data):
    ip = request.remote_addr
    user = get_current_user()
    
    if not user:
        emit('unauthorized', {'message': 'You must be logged in'})
        return
    
    if not check_rate_limit(ip):
        _, remaining_time = get_rate_limit_info(ip)
        emit('rate_limit', str(remaining_time))
        return
    
    message = data.get('message', '').strip()
    if not message or len(message) > 2000:
        emit('invalid_message', 'Invalid message length')
        return
    
    # Create message data
    message_data = {
        "user_id": user['id'],
        "username": user['username'],
        "message": message,
        "ip": ip,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Save to database and Redis
    try:
        db.save_message(message_data["user_id"], message_data["username"], 
                       message_data["message"], message_data["ip"])
        save_message(message_data.copy())
    except Exception as e:
        logger.error(f"Failed to save message: {e}")
        emit('invalid_message', 'Failed to save message')
        return
    
    # Send rate limit info
    remaining_messages, _ = get_rate_limit_info(ip)
    emit('until_rate_limit', str(remaining_messages))
    
    # Mask IP and broadcast
    ip_parts = message_data['ip'].split('.')
    message_data['ip'] = f"{ip_parts[0]}.{ip_parts[1]}.***.***"
    socketio.emit('message', message_data)

@app.route('/health')
def health_check():
    try:
        redis_client.ping()
        db.check_connection()
        return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting chat server on http://0.0.0.0:2137")
    # with https support 
    
    socketio.run(app, host='127.0.0.1', port=2137, debug=False)
