from dotenv import load_dotenv
load_dotenv()
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, flash
from flask_cors import CORS
import requests
import os
import sqlite3
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from itsdangerous import URLSafeTimedSerializer


app = Flask(__name__)

# Enable CORS for all origins (for development purposes)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# App config for auth and mail
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')#Use environment variable
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

db = SQLAlchemy(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# User model (with new fields for profile editing)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6), nullable=True) # Store OTP temporarily
    otp_expiration = db.Column(db.DateTime, nullable=True) # OTP expiration time
    name = db.Column(db.String(100), nullable=True) # New field for user's full name
    username = db.Column(db.String(100), unique=True, nullable=True) # New field for username

# NEW: Alert model for price alerts
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coin_id = db.Column(db.String(50), nullable=False) # e.g., 'bitcoin', 'ethereum'
    alert_price = db.Column(db.Float, nullable=False) # The target price for the alert
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    triggered_at = db.Column(db.DateTime, nullable=True) # Timestamp when the alert was triggered
    is_active = db.Column(db.Boolean, default=True) # Whether the alert is still active/monitoring

    user = db.relationship('User', backref='alerts')

# Initialize database
with app.app_context():
    # It's important to drop existing tables and recreate if you change model structure
    # For development, uncomment db.drop_all() if you encounter schema mismatch issues.
    # In production, use Flask-Migrate for schema changes.
    # db.drop_all() 
    db.create_all()

# ------------------ Utility Functions ------------------
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(email, otp):
    msg = Message('Your OTP Verification Code', recipients=[email])
    msg.body = f'Your OTP code is {otp}. It will expire in 10 minutes.'
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send OTP email to {email}: {e}")
        return False

# Placeholder for background price checking and alert sending (needs separate worker)
def check_and_send_alerts():
    """
    This function represents the logic that a background worker
    (e.g., a Celery task, APScheduler, or cron job) would run periodically.
    It's illustrative and not actively called by the Flask web server itself.
    """
    print("Checking for price alerts...")
    active_alerts = Alert.query.filter_by(is_active=True, triggered_at=None).all()

    if not active_alerts:
        print("No active alerts to check.")
        return

    # Collect unique coin_ids to fetch prices for
    coin_ids_to_check = list(set([alert.coin_id for alert in active_alerts]))
    
    current_prices = {}
    try:
        response = requests.get(
            f"https://api.coingecko.com/api/v3/simple/price",
            params={"ids": ",".join(coin_ids_to_check), "vs_currencies": "usd"}
        )
        response.raise_for_status()
        price_data = response.json()
        current_prices = {coin_id: data['usd'] for coin_id, data in price_data.items()}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching current prices for alerts: {e}")
        return

    for alert in active_alerts:
        current_price = current_prices.get(alert.coin_id)
        if current_price is None:
            print(f"Could not get current price for {alert.coin_id}")
            continue

        # Check if alert condition is met (e.g., price reaches or exceeds alert_price)
        if current_price >= alert.alert_price: # Or if current_price <= alert_price for a 'fall below' alert
            try:
                # Send email to the user who set the alert
                user_email = alert.user.email
                msg = Message(f"Crypto Price Alert: {alert.coin_id.capitalize()} reached ${alert.alert_price}!", recipients=[user_email])
                msg.body = (
                    f"Hi {alert.user.name or alert.user.email.split('@')[0]},\n\n"
                    f"Your alert for {alert.coin_id.capitalize()} at ${alert.alert_price:.2f} has been triggered!\n"
                    f"Current price: ${current_price:.2f}\n\n"
                    f"Regards,\nCryptoTracker Team"
                )
                mail.send(msg)
                
                alert.triggered_at = datetime.utcnow()
                alert.is_active = False # Deactivate alert after sending
                db.session.commit()
                print(f"Alert triggered and email sent for {alert.coin_id} to {user_email}")

            except Exception as e:
                print(f"Failed to send alert email for {alert.coin_id} to {user_email}: {e}")
                db.session.rollback() # Rollback if email fails
        else:
            print(f"Alert for {alert.coin_id} at ${alert.alert_price} not yet triggered (current: ${current_price})")


# ------------------ Auth API Endpoints ------------------

# User Registration API endpoint
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email')
    password = data.get('password')

    if not email:
        return jsonify({'error': 'Email is required'}), 400
    if not password:
        return jsonify({'error': 'Password is required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400

    hashed_pw = generate_password_hash(password) # Hash the password
    otp = generate_otp()
    otp_expiration = datetime.now() + timedelta(minutes=10)

    # Initialize name and username from email for new registrations
    default_name = email.split('@')[0].replace('.', ' ').title()
    default_username = email.split('@')[0] # Using email prefix as default username
    
    # Check if default username is already taken (unlikely, but good practice)
    if User.query.filter_by(username=default_username).first():
        default_username += ''.join(random.choices(string.digits, k=4)) # Add random suffix if taken

    user = User(email=email, password=hashed_pw, otp=otp, otp_expiration=otp_expiration,
                name=default_name, username=default_username)
    db.session.add(user)
    db.session.commit()

    # Send OTP via email
    if not send_otp_email(email, otp):
        db.session.rollback()
        return jsonify({'error': 'Failed to send OTP email. Please try again later.'}), 500

    return jsonify({'message': 'Registered successfully. Please check your email for the OTP.'}), 200

# OTP Verification API endpoint
@app.route('/api/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'error': 'Email and OTP are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.otp != otp:
        return jsonify({'error': 'Invalid OTP'}), 400

    if user.otp_expiration is None or datetime.now() > user.otp_expiration:
        return jsonify({'error': 'OTP expired'}), 400

    user.is_verified = True
    user.otp = None
    user.otp_expiration = None
    db.session.commit()

    return jsonify({'message': 'Email verified successfully!'})

# Resend OTP API endpoint
@app.route('/api/resend_otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Generate a new OTP and expiration
    new_otp = generate_otp()
    new_otp_expiration = datetime.now() + timedelta(minutes=10)

    user.otp = new_otp
    user.otp_expiration = new_otp_expiration
    db.session.commit()

    if not send_otp_email(email, new_otp):
        db.session.rollback()
        return jsonify({'error': 'Failed to resend OTP email. Please try again later.'}), 500

    return jsonify({'message': 'New OTP sent to your email.'})


# Login API endpoint
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return '', 200 # Handle preflight CORS

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Use SQLAlchemy to query the user
    user = User.query.filter_by(email=email).first()

    if user:
        if not user.is_verified:
            # If the user is not verified, return an error and suggest OTP resend
            return jsonify({'error': 'Email not verified. Please verify your email using the OTP sent to you.',
                            'action': 'verify_required'}), 403

        if check_password_hash(user.password, password):
            session['user'] = {'id': user.id, 'email': user.email}
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    else:
        return jsonify({'error': 'User not found'}), 404

# NEW API ENDPOINT FOR PROFILE UPDATE
@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user']['id']
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found in session context'}), 404
    
    data = request.get_json()
    name = data.get('name')
    username = data.get('username')
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not name or not username:
        return jsonify({'error': 'Name and username cannot be empty.'}), 400

    # Check if username is already taken by another user
    if user.username != username:
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken.'}), 400

    # Update name and username
    user.name = name
    user.username = username

    # Handle password change if new_password is provided
    if new_password:
        if not current_password:
            return jsonify({'error': 'Current password is required to change password.'}), 400
        
        if not check_password_hash(user.password, current_password):
            return jsonify({'error': 'Incorrect current password.'}), 401
        
        user.password = generate_password_hash(new_password)
    
    db.session.commit()
    # Update session with new name/username if changed, so template can reflect immediately
    session['user']['name'] = user.name
    session['user']['username'] = user.username
    return jsonify({'message': 'Profile updated successfully!'}), 200

# NEW: API endpoint to subscribe for price alerts
@app.route('/api/alerts/subscribe', methods=['POST'])
def subscribe_alert():
    if 'user' not in session:
        return jsonify({'error': 'Authentication required to set alerts.'}), 401

    user_id = session['user']['id']
    data = request.get_json()
    
    coin_id = data.get('coin_id')
    alert_price = data.get('alert_price')

    if not coin_id or not alert_price or not isinstance(alert_price, (int, float)):
        return jsonify({'error': 'Invalid coin ID or alert price provided.'}), 400

    # Optional: Check if an identical alert already exists for this user/coin/price
    existing_alert = Alert.query.filter_by(
        user_id=user_id,
        coin_id=coin_id,
        alert_price=alert_price,
        is_active=True # Check for active alerts
    ).first()

    if existing_alert:
        return jsonify({'message': 'Alert with this price already exists for this coin.'}), 200 # Or 409 Conflict

    try:
        new_alert = Alert(user_id=user_id, coin_id=coin_id, alert_price=alert_price)
        db.session.add(new_alert)
        db.session.commit()
        return jsonify({'message': f'Alert set for {coin_id.capitalize()} at ${alert_price:.2f}.'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to set alert.', 'details': str(e)}), 500


# ------------------ HTML Page Routes ------------------
# These routes render the HTML pages for user interaction

@app.route('/')
def index():
    return render_template('index.html') 

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/verify_otp')
def verify_otp_page():
    return render_template('verify_otp.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/trends')
def trends_page():
    return render_template('trends.html')

@app.route('/home')
def home_page():
    return render_template('home.html')

@app.route('/news')
def news_page():
    return render_template('news.html')

@app.route('/learn')
def learn_page():
    return render_template('learn.html')

@app.route('/paper_trading') # Assuming you have a paper_trading.html
def paper_trading_page():
    return render_template('paper_trading.html')

@app.route('/profile')
def profile():
    if 'user' not in session:
        flash('You must be logged in to view your profile.', 'warning')
        return redirect(url_for('login_page'))

    user_email = session['user']['email']
    # Fetch the full user object to pass name and username
    user_obj = User.query.get(session['user']['id'])
    if user_obj:
        return render_template('profile.html', email=user_obj.email, name=user_obj.name, username=user_obj.username)
    return render_template('profile.html', email=user_email, name="N/A", username="N/A") # Fallback if user_obj not found

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login_page'))

# ------------------ Crypto Market Routes (UNCHANGED) ------------------
@app.route('/api/cryptos', methods=['GET'])
def get_cryptos():
    try:
        response = requests.get(
            f"https://api.coingecko.com/api/v3/coins/markets",
            params={
                "vs_currency": "usd",
                "order": "market_cap_desc",
                "per_page": 250,
                "page": 1,
                "sparkline": False
            }
        )
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to fetch cryptocurrency data", "details": str(e)}), 500

@app.route('/api/cryptos/<coin_id>/trends', methods=['GET'])
def get_coin_trends(coin_id):
    days = request.args.get('days', '7')
    try:
        response = requests.get(
            f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart",
            params={"vs_currency": "usd", "days": days}
        )
        response.raise_for_status()
        return jsonify({"prices": response.json()['prices']}) # Only return prices array
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to fetch trends", "details": str(e)}), 500

@app.route('/api/cryptos/news', methods=['GET'])
def get_crypto_news():
    query = request.args.get('query', 'cryptocurrency')
    try:
        response = requests.get(
            "https://newsapi.org/v2/everything",
            params={
                "q": query,
                "apiKey": "f0451add1cef4011ba36a98b6d92ce0a", # Replace with your NEWS API Key
                "pageSize": 10,
                "sortBy": "publishedAt"
            }
        )
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to fetch news", "details": str(e)}), 500

# ------------------ Paper Trading Routes (UNCHANGED) ------------------

user_data = {
    "balance": 10000,
    "portfolio": {},
    "trade_history": []
}

@app.route('/api/balance', methods=['GET'])
def get_balance():
    return jsonify({"balance": user_data["balance"]})

@app.route('/api/portfolio', methods=['GET'])
def get_portfolio():
    return jsonify({
        "portfolio": {
            coin: data["amount"] for coin, data in user_data["portfolio"].items()
        }
    })

@app.route('/api/history', methods=['GET'])
def get_trade_history():
    return jsonify({
        "history": user_data["trade_history"]
    })

@app.route('/api/trade', methods=['POST'])
def place_trade():
    data = request.json
    coin_id = data.get("coin_id")
    amount = float(data.get("amount", 0))
    trade_type = data.get("type")

    if not coin_id or amount <= 0 or trade_type not in ["buy", "sell"]:
        return jsonify({"error": "Invalid trade data"}), 400

    try:
        response = requests.get(
            f"https://api.coingecko.com/api/v3/simple/price",
            params={"ids": coin_id, "vs_currencies": "usd"}
        )
        response.raise_for_status()
        price = response.json()[coin_id]["usd"]
    except Exception as e:
        return jsonify({"error": "Failed to fetch price", "details": str(e)}), 500

    total_value = amount * price

    if trade_type == "buy":
        if user_data["balance"] < total_value:
            return jsonify({"error": "Insufficient balance"}), 400

        user_data["balance"] -= total_value

        if coin_id not in user_data["portfolio"]:
            user_data["portfolio"][coin_id] = {"amount": 0, "avg_price": 0}

        current = user_data["portfolio"][coin_id]
        total_cost = current["amount"] * current["avg_price"] + total_value
        new_amount = current["amount"] + amount
        user_data["portfolio"][coin_id] = {
            "amount": new_amount,
            "avg_price": total_cost / new_amount
        }

    elif trade_type == "sell":
        if coin_id not in user_data["portfolio"] or user_data["portfolio"][coin_id]["amount"] < amount:
            return jsonify({"error": "Insufficient holdings"}), 400

        user_data["balance"] += total_value
        user_data["portfolio"][coin_id]["amount"] -= amount

        if user_data["portfolio"][coin_id]["amount"] == 0:
            del user_data["portfolio"][coin_id]

    user_data["trade_history"].append({
        "type": trade_type,
        "coin": coin_id,
        "amount": amount,
        "price": price,
        "total": total_value,
        "timestamp": datetime.now().isoformat()
    })

    return jsonify({
        "message": "Trade successful",
        "balance": user_data["balance"],
        "portfolio": {
            coin: data["amount"] for coin, data in user_data["portfolio"].items()
        }
    })

@app.route('/api/status')
def status():
    return jsonify({"status": "API is running"})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)