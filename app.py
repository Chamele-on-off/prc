import os
import json
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# =============================================
# Самописная JSON база данных
# =============================================
class JSONDatabase:
    def __init__(self, filename='database.json'):
        self.filename = filename
        self.data = self._load_data()
    
    def _load_data(self):
        if not os.path.exists(self.filename):
            default_data = {
                'users': [],
                'transactions': [],
                'payment_details': [],
                'requests': [],
                'disputes': [],
                'wallets': [],
                'exchange_rates': [],
                'notifications': [],
                'activity_log': []
            }
            self._save_data(default_data)
            return default_data
        
        with open(self.filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _save_data(self, data=None):
        with open(self.filename, 'w', encoding='utf-8') as f:
            json.dump(data or self.data, f, ensure_ascii=False, indent=2)
    
    def _get_next_id(self, collection_name):
        if not self.data[collection_name]:
            return 1
        return max(item['id'] for item in self.data[collection_name]) + 1
    
    def get_user_by_username(self, username):
        for user in self.data['users']:
            if user['username'] == username:
                return user
        return None
    
    def get_user_by_id(self, user_id):
        for user in self.data['users']:
            if user['id'] == user_id:
                return user
        return None
    
    def add_user(self, username, password, role, contact_info='', settings=None):
        if self.get_user_by_username(username):
            raise ValueError('Username already exists')
        
        user = {
            'id': self._get_next_id('users'),
            'username': username,
            'password': hashlib.sha256(password.encode()).hexdigest(),
            'role': role,
            'contact_info': contact_info,
            'settings': settings or {},
            'status': 'active',
            'last_login': None,
            'ip_address': None,
            'registration_date': datetime.now().isoformat(),
            'tg_notification_id': None
        }
        self.data['users'].append(user)
        self._save_data()
        return user
    
    def verify_user(self, username, password):
        user = self.get_user_by_username(username)
        if not user:
            return None
        if user['password'] != hashlib.sha256(password.encode()).hexdigest():
            return None
        return user
    
    def update_user_login(self, user_id, ip_address):
        for user in self.data['users']:
            if user['id'] == user_id:
                user['last_login'] = datetime.now().isoformat()
                user['ip_address'] = ip_address
                self._save_data()
                return True
        return False
    
    def get_balance(self, user_id):
        rub = sum(w['balance'] for w in self.data['wallets'] 
                if w['user_id'] == user_id and w['type'] == 'RUB')
        usdt = sum(w['balance'] for w in self.data['wallets'] 
                 if w['user_id'] == user_id and w['type'] == 'USDT')
        return {'RUB': rub, 'USDT': usdt}
    
    def create_wallet(self, user_id, currency, initial_balance=0):
        wallet = {
            'id': self._get_next_id('wallets'),
            'address': f"{currency}_{user_id}_{hashlib.sha256(str(datetime.now().timestamp().encode()).hexdigest()[:10]}",
            'user_id': user_id,
            'type': currency,
            'balance': initial_balance,
            'is_available': True,
            'last_used': datetime.now().isoformat()
        }
        self.data['wallets'].append(wallet)
        self._save_data()
        return wallet
    
    def log_activity(self, user_id, action, details="", ip_address=None):
        log = {
            'id': self._get_next_id('activity_log'),
            'user_id': user_id,
            'action': action,
            'details': details,
            'ip_address': ip_address or request.remote_addr,
            'timestamp': datetime.now().isoformat()
        }
        self.data['activity_log'].append(log)
        self._save_data()
    
    def send_notification(self, user_id, notification_type, message):
        notification = {
            'id': self._get_next_id('notifications'),
            'user_id': user_id,
            'type': notification_type,
            'message': message,
            'is_read': False,
            'timestamp': datetime.now().isoformat()
        }
        self.data['notifications'].append(notification)
        self._save_data()
    
    def get_current_rate(self):
        if not self.data['exchange_rates']:
            return None
        latest_rate = max(self.data['exchange_rates'], key=lambda x: x['timestamp'])
        return {
            "base": latest_rate['rate'],
            "trader_in": latest_rate['rate'] * (1 + latest_rate['trader_markup']/100),
            "trader_out": latest_rate['rate'] * (1 - latest_rate['platform_markup']/100),
            "platform": latest_rate['rate'],
            "trader_markup": latest_rate['trader_markup'],
            "platform_markup": latest_rate['platform_markup']
        }
    
    def add_exchange_rate(self, base_currency, target_currency, rate, trader_markup, platform_markup):
        rate_entry = {
            'id': self._get_next_id('exchange_rates'),
            'base_currency': base_currency,
            'target_currency': target_currency,
            'rate': rate,
            'trader_markup': trader_markup,
            'platform_markup': platform_markup,
            'timestamp': datetime.now().isoformat()
        }
        self.data['exchange_rates'].append(rate_entry)
        self._save_data()
        return rate_entry

# Инициализация базы данных
db = JSONDatabase()

# =============================================
# Вспомогательные функции
# =============================================
def init_test_data():
    # Добавляем администратора
    db.add_user("admin", "admin123", "admin", "admin@example.com")
    
    # Добавляем тестового трейдера
    trader_settings = {
        "rate_in": 5.0,
        "rate_out": 2.0,
        "deposit": 1000.0,
        "work_method": "cards",
        "trc20_wallet": "TXYZ1234567890",
        "working_hours": "09:00-21:00",
        "insurance_deposit": 500.0,
        "payment_methods": ["SBP", "C2C"],
        "notifications": ["PUSH", "TG"]
    }
    db.add_user("trader1", "trader123", "trader", "trader1@example.com", trader_settings)
    
    # Добавляем тестового мерчанта
    merchant_settings = {
        "rate_in": 1.0,
        "rate_out": 1.0,
        "website": "https://example.com",
        "payment_methods": ["card", "crypto"],
        "trc20_wallet": "TXYZ0987654321",
        "priority": "high",
        "traffic_type": "gambling",
        "contact_person": "John Doe",
        "contact_phone": "+1234567890"
    }
    db.add_user("merchant1", "merchant123", "merchant", "merchant1@example.com", merchant_settings)
    
    # Устанавливаем курс валют
    db.add_exchange_rate("USDT", "RUB", 100.0, 5.0, 2.0)
    
    # Создаем кошельки для пользователей
    traders = [u for u in db.data['users'] if u['role'] == 'trader']
    for trader in traders:
        db.create_wallet(trader['id'], 'USDT', 1000.0)
        db.create_wallet(trader['id'], 'RUB', 0.0)
    
    merchants = [u for u in db.data['users'] if u['role'] == 'merchant']
    for merchant in merchants:
        db.create_wallet(merchant['id'], 'USDT', 0.0)
        db.create_wallet(merchant['id'], 'RUB', 0.0)

# =============================================
# Основные маршруты
# =============================================
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    
    if user['role'] == 'admin':
        return redirect(url_for('admin_panel'))
    elif user['role'] == 'trader':
        return redirect(url_for('trader_panel'))
    elif user['role'] == 'merchant':
        return redirect(url_for('merchant_panel'))
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error='Заполните все поля')
        
        user = db.verify_user(username, password)
        
        if not user:
            return render_template('login.html', error='Неверный логин или пароль')
        
        if user['status'] != 'active':
            return render_template('login.html', error='Ваш аккаунт деактивирован')
        
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['username'] = user['username']
        
        db.update_user_login(user['id'], request.remote_addr)
        db.log_activity(user['id'], 'login', f"Успешный вход в систему с IP {request.remote_addr}")
        
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        db.log_activity(session['user_id'], 'logout', "Выход из системы")
    session.clear()
    return redirect(url_for('login'))

# =============================================
# Админ панель
# =============================================
@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Статистика
    stats = {
        "traders": len([u for u in db.data['users'] if u['role'] == 'trader']),
        "merchants": len([u for u in db.data['users'] if u['role'] == 'merchant']),
        "active_traders": len([u for u in db.data['users'] if u['role'] == 'trader' and u['status'] == 'active']),
        "active_merchants": len([u for u in db.data['users'] if u['role'] == 'merchant' and u['status'] == 'active']),
        "today_volume": sum(t['amount'] for t in db.data['transactions'] 
                           if t['type'] == 'payment' and 
                           datetime.fromisoformat(t['timestamp']).date() == datetime.now().date()),
        "disputes": len([d for d in db.data['disputes'] if d['status'] == 'open']),
        "active_requests": len([r for r in db.data['requests'] if r['status'] == 'pending']),
        "active_tokens": len(set(pd['user_id'] for pd in db.data['payment_details'] if pd['is_active']))
    }
    
    # Последние транзакции
    transactions = sorted(db.data['transactions'], key=lambda x: x['timestamp'], reverse=True)[:10]
    for t in transactions:
        user = db.get_user_by_id(t['user_id'])
        t['username'] = user['username'] if user else 'Unknown'
    
    # Последние заявки
    requests = sorted(db.data['requests'], key=lambda x: x['timestamp'], reverse=True)[:10]
    for r in requests:
        user = db.get_user_by_id(r['user_id'])
        r['username'] = user['username'] if user else 'Unknown'
    
    # Курс валют
    exchange_rate = db.get_current_rate()
    
    db.log_activity(user_id, 'admin_panel_view', "Просмотр панели администратора")
    return render_template(
        'admin.html',
        stats=stats,
        transactions=transactions,
        requests=requests,
        exchange_rate=exchange_rate
    )

# API для админ-панели
@app.route('/api/admin/users')
def admin_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    role = request.args.get('role')
    users = db.data['users']
    
    if role in ['trader', 'merchant', 'admin']:
        users = [u for u in users if u['role'] == role]
    
    # Возвращаем только необходимые поля
    result = [{
        'id': u['id'],
        'username': u['username'],
        'role': u['role'],
        'contact_info': u['contact_info'],
        'status': u['status'],
        'last_login': u['last_login']
    } for u in users]
    
    return jsonify(result)

@app.route('/api/admin/user/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
def admin_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = session['user_id']
    user = db.get_user_by_id(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if request.method == 'GET':
        return jsonify({
            "id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "contact_info": user['contact_info'],
            "settings": user['settings'],
            "status": user['status']
        })
    
    elif request.method == 'PUT':
        data = request.json
        
        for u in db.data['users']:
            if u['id'] == user_id:
                if 'contact_info' in data:
                    u['contact_info'] = data['contact_info']
                if 'settings' in data:
                    u['settings'] = data['settings']
                if 'status' in data:
                    u['status'] = data['status']
                break
        
        db._save_data()
        db.log_activity(admin_id, 'user_update', f"Обновление пользователя ID {user_id}")
        return jsonify({"status": "success"})
    
    elif request.method == 'DELETE':
        db.data['users'] = [u for u in db.data['users'] if u['id'] != user_id]
        db._save_data()
        db.log_activity(admin_id, 'user_delete', f"Удаление пользователя ID {user_id}")
        return jsonify({"status": "success"})

@app.route('/api/admin/create_user', methods=['POST'])
def admin_create_user():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = session['user_id']
    data = request.json
    
    required_fields = ['username', 'password', 'role']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        user = db.add_user(
            data['username'],
            data['password'],
            data['role'],
            data.get('contact_info', ''),
            data.get('settings', {})
        )
        
        db.log_activity(admin_id, 'user_create', f"Создание пользователя {data['username']}")
        return jsonify({"status": "success", "user_id": user['id']})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/admin/transactions')
def admin_transactions():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    page = int(request.args.get('page', 1))
    limit = 20
    offset = (page - 1) * limit
    
    transactions = sorted(db.data['transactions'], key=lambda x: x['timestamp'], reverse=True)[offset:offset+limit]
    
    for t in transactions:
        user = db.get_user_by_id(t['user_id'])
        t['username'] = user['username'] if user else 'Unknown'
    
    return jsonify(transactions)

@app.route('/api/admin/update_rate', methods=['POST'])
def admin_update_rate():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = session['user_id']
    data = request.json
    
    db.add_exchange_rate(
        "USDT",
        "RUB",
        data['rate'],
        data['trader_markup'],
        data['platform_markup']
    )
    
    db.log_activity(admin_id, 'rate_update', f"Обновление курса: {data['rate']} RUB за USDT")
    return jsonify({"status": "success", "new_rate": db.get_current_rate()})

# =============================================
# Панель трейдера
# =============================================
@app.route('/trader')
def trader_panel():
    if 'user_id' not in session or session.get('role') != 'trader':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    balance = db.get_balance(user_id)
    rate = db.get_current_rate()
    
    # Активные заявки
    active_requests = [r for r in db.data['requests'] 
                      if r['trader_id'] == user_id and r['status'] in ['pending', 'processing']]
    active_requests = sorted(active_requests, key=lambda x: x['timestamp'], reverse=True)[:10]
    
    for r in active_requests:
        merchant = db.get_user_by_id(r['merchant_id'])
        r['merchant'] = merchant['username'] if merchant else 'Unknown'
    
    # Реквизиты
    payment_details = [pd for pd in db.data['payment_details'] if pd['user_id'] == user_id]
    payment_details = sorted(payment_details, key=lambda x: (not x['is_active'], x['created_at']), reverse=True)
    
    # Статистика трейдера
    user_requests = [r for r in db.data['requests'] if r['trader_id'] == user_id]
    today = datetime.now().date()
    
    stats = {
        "today_requests": len([r for r in user_requests 
                             if datetime.fromisoformat(r['timestamp']).date() == today]),
        "today_amount": sum(r['amount'] for r in user_requests 
                           if datetime.fromisoformat(r['timestamp']).date() == today and 
                           r['status'] == 'completed'),
        "conversion_rate": (len([r for r in user_requests if r['status'] == 'completed']) / len(user_requests) * 100 
                           if user_requests else 0),
        "disputes": len([d for d in db.data['disputes'] if d['user_id'] == user_id and d['status'] == 'open'])
    }
    
    # Настройки трейдера
    user = db.get_user_by_id(user_id)
    settings = user.get('settings', {}) if user else {}
    
    db.log_activity(user_id, 'trader_panel_view', "Просмотр панели трейдера")
    return render_template(
        'trader.html',
        balance=balance,
        rate=rate,
        active_requests=active_requests,
        payment_details=payment_details,
        stats=stats,
        settings=settings
    )

# =============================================
# Панель мерчанта
# =============================================
@app.route('/merchant')
def merchant_panel():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    balance = db.get_balance(user_id)
    rate = db.get_current_rate()
    
    # Последние транзакции
    transactions = [t for t in db.data['transactions'] 
                   if t['user_id'] == user_id or t['merchant_id'] == user_id]
    transactions = sorted(transactions, key=lambda x: x['timestamp'], reverse=True)[:10]
    
    # Последние заявки
    requests = [r for r in db.data['requests'] if r['merchant_id'] == user_id]
    requests = sorted(requests, key=lambda x: x['timestamp'], reverse=True)[:10]
    
    for r in requests:
        trader = db.get_user_by_id(r['trader_id'])
        r['trader'] = trader['username'] if trader else 'Unknown'
    
    # Статистика мерчанта
    today = datetime.now().date()
    stats = {
        "today_volume": sum(t['amount'] for t in transactions 
                        if datetime.fromisoformat(t['timestamp']).date() == today),
        "total_volume": sum(t['amount'] for t in transactions),
        "conversion_rate": (len([r for r in requests if r['status'] == 'completed']) / len(requests) * 100 
                           if requests else 0),
        "active_requests": len([r for r in requests if r['status'] == 'pending'])
    }
    
    # Настройки мерчанта
    user = db.get_user_by_id(user_id)
    settings = user.get('settings', {}) if user else {}
    
    db.log_activity(user_id, 'merchant_panel_view', "Просмотр панели мерчанта")
    return render_template(
        'merchant.html',
        balance=balance,
        rate=rate,
        transactions=transactions,
        requests=requests,
        stats=stats,
        settings=settings
    )

# =============================================
# Общие API для всех пользователей
# =============================================
@app.route('/api/current_user')
def current_user():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    user = db.get_user_by_id(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "id": user['id'],
        "username": user['username'],
        "role": user['role'],
        "contact_info": user['contact_info'],
        "settings": user['settings']
    })

# =============================================
# Запуск приложения
# =============================================
if __name__ == '__main__':
    # Инициализация тестовых данных при первом запуске
    if not db.data['users']:
        init_test_data()
        print("Initial test data created")
    
    app.run(debug=True, host='0.0.0.0', port=5000)