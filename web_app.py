from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_socketio import SocketIO, emit
import threading
import time
import os
from datetime import datetime
import authsystem
from bot import getStock, getinviteCode, checkInvite, Booster, remove
import secrets
import hashlib
import uuid
import json
from datetime import datetime
import sys

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")

# Load configuration
with open('config/config.json', 'r') as f:
    config = json.load(f)

def load_users():
    """Load users from file"""
    try:
        with open('data/users.json', 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    """Save users to file"""
    os.makedirs('data', exist_ok=True)
    with open('data/users.json', 'w') as f:
        json.dump(users, f, indent=4)

def hash_password(password):
    """Hash password with salt"""
    salt = uuid.uuid4().hex
    return hashlib.sha256((salt + password).encode()).hexdigest() + ':' + salt

def verify_password(hashed_password, user_password):
    """Verify password"""
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256((salt + user_password).encode()).hexdigest()

def load_stock_data():
    """Load current stock data"""
    try:
        stock_1m = len(open("data/1m.txt", "r").readlines())
        stock_3m = len(open("data/3m.txt", "r").readlines())
    except:
        stock_1m = stock_3m = 0

    return {
        '1m_tokens': stock_1m,
        '3m_tokens': stock_3m,
        '1m_boosts': stock_1m * 2,
        '3m_boosts': stock_3m * 2
    }

def load_keys_stats():
    """Load key statistics"""
    try:
        with open("data/keys/keys.json", "r") as f:
            keys = json.load(f)

        stats = {
            'total_keys': len(keys),
            '1m_keys': len([k for k in keys if k['month'] == 1]),
            '3m_keys': len([k for k in keys if k['month'] == 3]),
            'amount_breakdown': {}
        }

        for key in keys:
            amount = key['amount']
            if amount not in stats['amount_breakdown']:
                stats['amount_breakdown'][amount] = {'1m': 0, '3m': 0}
            stats['amount_breakdown'][amount][f"{key['month']}m"] += 1

        return stats
    except:
        return {'total_keys': 0, '1m_keys': 0, '3m_keys': 0, 'amount_breakdown': {}}

@app.route('/')
def welcome():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    
    # Load stock and keys data for welcome page
    stock_data = load_stock_data()
    keys_stats = load_keys_stats()
    
    return render_template('welcome.html', stock=stock_data, keys=keys_stats)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    stock_data = load_stock_data()
    keys_stats = load_keys_stats()
    user = session.get('username', 'Guest')
    is_admin = session.get('is_admin', False)

    return render_template('dashboard.html', 
                         stock=stock_data, 
                         keys=keys_stats, 
                         user=user, 
                         is_admin=is_admin)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        users = load_users()

        if username in users and verify_password(users[username]['password'], password):
            session['logged_in'] = True
            session['username'] = username
            session['is_admin'] = users[username].get('is_admin', False)
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        users = load_users()

        if username in users:
            flash('Username already exists', 'error')
            return render_template('register.html')

        # Create new user
        users[username] = {
            'password': hash_password(password),
            'is_admin': False,
            'created_at': datetime.now().isoformat(),
            'keys_used': [],
            'total_boosts': 0
        }

        save_users(users)
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

# Boost page removed for security - only key redemption allowed

@app.route('/redeem')
def redeem_page():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('redeem.html')

@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    users = load_users()
    username = session.get('username')
    user_data = users.get(username, {})

    return render_template('profile.html', user_data=user_data, username=username)

@app.route('/admin')
def admin_page():
    if not session.get('logged_in') or not session.get('is_admin'):
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))

    stock_data = load_stock_data()
    keys_stats = load_keys_stats()
    users = load_users()

    # Get recent boost logs
    try:
        with open("data/output/success.txt", "r") as f:
            success_count = len(f.readlines())
    except:
        success_count = 0

    try:
        with open("data/output/failed_boosts.txt", "r") as f:
            failed_count = len(f.readlines())
    except:
        failed_count = 0

    return render_template('admin.html', 
                         stock=stock_data, 
                         keys=keys_stats,
                         success_count=success_count,
                         failed_count=failed_count,
                         users=users,
                         total_users=len(users))

@app.route('/api/stock')
def api_stock():
    return jsonify(load_stock_data())

# Boost API removed for security - only key redemption allowed

@app.route('/api/redeem', methods=['POST'])
def api_redeem():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Login required'})

    data = request.get_json()
    key = data.get('key')
    invite = data.get('invite')

    try:
        with open("data/keys/keys.json", "r") as f:
            keys = json.load(f)

        key_info = None
        for k in keys:
            if k['key'] == key:
                key_info = k
                break

        if not key_info:
            return jsonify({'success': False, 'error': 'Invalid key'})

        amount = key_info['amount']
        months = key_info['month']

        invite_code = getinviteCode(invite)
        invite_data = checkInvite(invite_code)

        if not invite_data:
            return jsonify({'success': False, 'error': 'Invalid invite'})

        filename = f"data/{months}m.txt"
        tokens_stock = getStock(filename)
        required_stock = amount // 2

        if required_stock > len(tokens_stock):
            return jsonify({'success': False, 'error': 'Not enough stock'})

        # Get tokens and boost
        tokens = []
        for x in range(required_stock):
            tokens.append(tokens_stock[x])
            remove(tokens_stock[x], filename)

        booster = Booster()
        start_time = time.time()
        status = booster.thread(invite_code, tokens, invite_data)
        time_taken = round(time.time() - start_time, 2)

        # Remove key from available keys
        updated_keys = [k for k in keys if k['key'] != key]
        with open("data/keys/keys.json", "w") as f:
            json.dump(updated_keys, f, indent=4)

        # Update user stats
        users = load_users()
        username = session.get('username')
        if username in users:
            users[username]['keys_used'].append({
                'key': key,
                'amount': amount,
                'months': months,
                'date': datetime.now().isoformat(),
                'successful_boosts': len(status['success']) * 2
            })
            users[username]['total_boosts'] += len(status['success']) * 2
            save_users(users)

        # Add to used keys
        try:
            with open("data/keys/used_keys.json", "r") as f:
                used_keys = json.load(f)
        except:
            used_keys = []

        used_keys.append({
            "key": key,
            "month": months,
            "amount": amount,
            "invite": invite,
            "user": username,
            "successful": len(status['success']),
            "failed": len(status['failed']),
            "time_taken": time_taken,
            "date": datetime.now().isoformat()
        })

        with open("data/keys/used_keys.json", "w") as f:
            json.dump(used_keys, f, indent=4)

        return jsonify({
            'success': True,
            'successful_boosts': len(status['success']) * 2,
            'failed_boosts': len(status['failed']) * 2,
            'captcha_boosts': len(status['captcha']) * 2,
            'time_taken': time_taken
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/check_key', methods=['POST'])
def api_check_key():
    data = request.get_json()
    key = data.get('key')

    try:
        with open("data/keys/keys.json", "r") as f:
            keys = json.load(f)

        for k in keys:
            if k['key'] == key:
                return jsonify({
                    'success': True,
                    'key_info': {
                        'month': k['month'],
                        'amount': k['amount'],
                        'valid': True
                    }
                })

        return jsonify({'success': False, 'error': 'Key not found'})

    except:
        return jsonify({'success': False, 'error': 'Error checking key'})

@app.route('/api/admin/create_keys', methods=['POST'])
def api_create_keys():
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Admin access required'})

    data = request.get_json()
    month = int(data.get('month'))
    amount = int(data.get('amount'))
    quantity = int(data.get('quantity'))

    keys = authsystem.load_keys_from_file("data/keys/keys.json")
    authsystem.generate_key(keys, month, amount, quantity, "data/keys/keys.json")

    return jsonify({'success': True, 'message': f'Created {quantity} keys'})

@app.route('/api/admin/restock', methods=['POST'])
def api_restock():
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Admin access required'})

    data = request.get_json()
    duration = int(data.get('duration'))
    tokens = data.get('tokens').split('\n')

    filename = f"data/{duration}m.txt"

    with open(filename, "a") as f:
        for token in tokens:
            if token.strip():
                f.write(token.strip() + "\n")

    return jsonify({'success': True, 'message': f'Added {len([t for t in tokens if t.strip()])} tokens'})

@app.route('/api/admin/manage_user', methods=['POST'])
def api_manage_user():
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Admin access required'})

    data = request.get_json()
    action = data.get('action')
    username = data.get('username')

    users = load_users()

    if action == 'make_admin':
        if username in users:
            users[username]['is_admin'] = True
            save_users(users)
            return jsonify({'success': True, 'message': f'{username} is now an admin'})

    elif action == 'remove_admin':
        if username in users:
            users[username]['is_admin'] = False
            save_users(users)
            return jsonify({'success': True, 'message': f'{username} admin privileges removed'})

    elif action == 'delete_user':
        if username in users:
            del users[username]
            save_users(users)
            return jsonify({'success': True, 'message': f'{username} deleted'})

    return jsonify({'success': False, 'error': 'Invalid action or user not found'})

# Real-time stock updates
def background_stock_update():
    while True:
        time.sleep(10)  # Update every 10 seconds
        stock_data = load_stock_data()
        socketio.emit('stock_update', stock_data, broadcast=True)

@socketio.on('connect')
def handle_connect():
    emit('stock_update', load_stock_data())

# Error handling for file operations
@app.errorhandler(IOError)
def handle_io_error(e):
    """Handle file-related errors"""
    flash(f"File error: {e}", 'error')
    return render_template('error.html', error=str(e)), 500

@app.errorhandler(json.JSONDecodeError)
def handle_json_decode_error(e):
    """Handle JSON decoding errors"""
    flash(f"JSON decode error: {e}", 'error')
    return render_template('error.html', error=str(e)), 400

@app.errorhandler(Exception)
def handle_generic_error(e):
    """Handle unexpected errors"""
    flash(f"An unexpected error occurred: {e}", 'error')
    return render_template('error.html', error=str(e)), 500

if __name__ == '__main__':
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    os.makedirs('data/keys', exist_ok=True)

    # Start background thread for stock updates
    stock_thread = threading.Thread(target=background_stock_update)
    stock_thread.daemon = True
    stock_thread.start()

    socketio.run(app, host='0.0.0.0', port=5000, debug=True)