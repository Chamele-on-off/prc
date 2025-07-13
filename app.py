import os
import json
import hashlib
import time
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
            'address': f"{currency}_{user_id}_{hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]}",
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
        return log
    
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
        return notification
    
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
    
    def add_request(self, request_type, amount, currency, user_id, trader_id=None, merchant_id=None, status='pending', details=None):
        request_data = {
            'id': self._get_next_id('requests'),
            'type': request_type,
            'amount': amount,
            'currency': currency,
            'user_id': user_id,
            'trader_id': trader_id,
            'merchant_id': merchant_id,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'expiry_time': (datetime.now() + timedelta(minutes=15)).isoformat(),
            'details': details or {},
            'conversion_rate': None,
            'priority': 0
        }
        self.data['requests'].append(request_data)
        self._save_data()
        return request_data
    
    def update_request(self, request_id, updates):
        for req in self.data['requests']:
            if req['id'] == request_id:
                req.update(updates)
                req['timestamp'] = datetime.now().isoformat()
                self._save_data()
                return req
        return None
    
    def add_transaction(self, transaction_type, amount, currency, user_id, trader_id=None, merchant_id=None, status='pending', details=None):
        transaction = {
            'id': self._get_next_id('transactions'),
            'type': transaction_type,
            'amount': amount,
            'currency': currency,
            'user_id': user_id,
            'trader_id': trader_id,
            'merchant_id': merchant_id,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'details': details or {},
            'proof': None
        }
        self.data['transactions'].append(transaction)
        self._save_data()
        return transaction
    
    def add_payment_detail(self, user_id, detail_type, details, is_active=True, min_amount=0, max_amount=1000000, bank_name=None, notification_type='PUSH'):
        payment_detail = {
            'id': self._get_next_id('payment_details'),
            'user_id': user_id,
            'type': detail_type,
            'details': details,
            'is_active': is_active,
            'min_amount': min_amount,
            'max_amount': max_amount,
            'bank_name': bank_name,
            'notification_type': notification_type,
            'created_at': datetime.now().isoformat()
        }
        self.data['payment_details'].append(payment_detail)
        self._save_data()
        return payment_detail
    
    def add_dispute(self, request_id, user_id, status='open', details=None, resolution=None):
        dispute = {
            'id': self._get_next_id('disputes'),
            'request_id': request_id,
            'user_id': user_id,
            'admin_id': None,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'details': details or {},
            'resolution': resolution
        }
        self.data['disputes'].append(dispute)
        self._save_data()
        return dispute
    
    def update_wallet_balance(self, user_id, currency, amount):
        wallet = next((w for w in self.data['wallets'] 
                     if w['user_id'] == user_id and w['type'] == currency), None)
        if not wallet:
            wallet = self.create_wallet(user_id, currency, 0)
        
        wallet['balance'] += amount
        wallet['last_used'] = datetime.now().isoformat()
        self._save_data()
        return wallet

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

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'pdf', 'png', 'jpg', 'jpeg'}

# =============================================
# Основные маршруты
# =============================================
@app.route('/')
def index():
    print("Session data:", session)  # Отладочный вывод
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login")
        return redirect(url_for('login'))
    
    user = db.get_user_by_id(session['user_id'])
    if not user:
        print("User not found in DB, clearing session")
        session.clear()
        return redirect(url_for('login'))
    
    print(f"User {user['username']} logged in, role: {user['role']}")
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
        username = request.form['username']  # Более строгий вариант
        password = request.form['password']
        
        user = db.verify_user(username, password)
        if user:
            session['user_id'] = user['id']
            print(f"User {username} logged in successfully")  # Отладочный вывод
            return redirect(url_for('index'))
        else:
            print(f"Failed login attempt for {username}")  # Отладочный вывод
            return render_template('login.html', error='Неверные данные'), 401
    
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

@app.route('/api/admin/requests')
def admin_requests():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    status = request.args.get('status')
    requests = db.data['requests']
    
    if status in ['pending', 'processing', 'completed', 'disputed']:
        requests = [r for r in requests if r['status'] == status]
    
    # Добавляем информацию о пользователях
    result = []
    for r in requests[:50]:  # Ограничиваем 50 записями
        user = db.get_user_by_id(r['user_id'])
        trader = db.get_user_by_id(r['trader_id']) if r['trader_id'] else None
        merchant = db.get_user_by_id(r['merchant_id']) if r['merchant_id'] else None
        
        result.append({
            'id': r['id'],
            'type': r['type'],
            'amount': r['amount'],
            'currency': r['currency'],
            'status': r['status'],
            'timestamp': r['timestamp'],
            'user': user['username'] if user else None,
            'trader': trader['username'] if trader else None,
            'merchant': merchant['username'] if merchant else None
        })
    
    return jsonify(result)

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

@app.route('/api/admin/disputes')
def admin_disputes():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    status = request.args.get('status', 'open')
    disputes = [d for d in db.data['disputes'] if d['status'] == status]
    
    result = []
    for d in disputes:
        req = next((r for r in db.data['requests'] if r['id'] == d['request_id']), None)
        if not req:
            continue
            
        user = db.get_user_by_id(d['user_id'])
        trader = db.get_user_by_id(req['trader_id']) if req['trader_id'] else None
        merchant = db.get_user_by_id(req['merchant_id']) if req['merchant_id'] else None
        
        result.append({
            'id': d['id'],
            'status': d['status'],
            'timestamp': d['timestamp'],
            'amount': req['amount'],
            'currency': req['currency'],
            'user': user['username'] if user else None,
            'trader': trader['username'] if trader else None,
            'merchant': merchant['username'] if merchant else None,
            'details': d['details']
        })
    
    return jsonify(result)

@app.route('/api/admin/resolve_dispute/<int:dispute_id>', methods=['POST'])
def admin_resolve_dispute(dispute_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = session['user_id']
    data = request.json
    
    dispute = next((d for d in db.data['disputes'] if d['id'] == dispute_id), None)
    if not dispute:
        return jsonify({"error": "Dispute not found"}), 404
    
    dispute['status'] = 'resolved'
    dispute['resolution'] = data.get('resolution')
    dispute['admin_id'] = admin_id
    db._save_data()
    
    # Обновляем статус заявки
    request_id = dispute['request_id']
    for req in db.data['requests']:
        if req['id'] == request_id:
            req['status'] = 'completed'
            break
    
    db._save_data()
    db.log_activity(admin_id, 'dispute_resolve', f"Разрешение диспута ID {dispute_id}")
    return jsonify({"status": "success"})

@app.route('/api/admin/block_trader/<int:trader_id>', methods=['POST'])
def admin_block_trader(trader_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = session['user_id']
    reason = request.json.get('reason', 'Нарушение правил')
    
    trader = db.get_user_by_id(trader_id)
    if not trader or trader['role'] != 'trader':
        return jsonify({"error": "Trader not found"}), 404
    
    # Обновляем статус трейдера
    for user in db.data['users']:
        if user['id'] == trader_id:
            user['status'] = 'blocked'
            break
    
    # Отменяем все активные заявки этого трейдера
    for req in db.data['requests']:
        if req['trader_id'] == trader_id and req['status'] in ['pending', 'processing']:
            req['status'] = 'canceled'
    
    db._save_data()
    db.log_activity(admin_id, 'trader_block', f"Блокировка трейдера ID {trader_id}. Причина: {reason}")
    db.send_notification(trader_id, 'system', f"Ваш аккаунт заблокирован. Причина: {reason}")
    return jsonify({"status": "success"})

@app.route('/api/admin/reports')
def admin_reports():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    report_type = request.args.get('type', 'daily')
    now = datetime.now()
    
    if report_type == 'daily':
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = now.replace(hour=23, minute=59, second=59, microsecond=999999)
    elif report_type == 'weekly':
        start_date = now - timedelta(days=now.weekday())
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = start_date + timedelta(days=6)
        end_date = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)
    else:  # monthly
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_date = (start_date + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        end_date = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)
    
    # Фильтруем транзакции по дате
    transactions = [
        t for t in db.data['transactions']
        if start_date <= datetime.fromisoformat(t['timestamp']) <= end_date
    ]
    
    # Объем операций
    total_amount = sum(t['amount'] for t in transactions)
    total_count = len(transactions)
    completed_amount = sum(t['amount'] for t in transactions if t['status'] == 'completed')
    completed_count = len([t for t in transactions if t['status'] == 'completed'])
    
    # Конверсия по трейдерам
    traders_conversion = []
    traders = [u for u in db.data['users'] if u['role'] == 'trader']
    
    for trader in traders:
        trader_requests = [
            r for r in db.data['requests']
            if r['trader_id'] == trader['id'] and 
            start_date <= datetime.fromisoformat(r['timestamp']) <= end_date
        ]
        
        total = len(trader_requests)
        completed = len([r for r in trader_requests if r['status'] == 'completed'])
        conversion = (completed / total * 100) if total > 0 else 0
        
        traders_conversion.append({
            'id': trader['id'],
            'username': trader['username'],
            'total_requests': total,
            'completed_requests': completed,
            'conversion_rate': round(conversion, 2)
        })
    
    # Статистика по мерчантам
    merchants_stats = []
    merchants = [u for u in db.data['users'] if u['role'] == 'merchant']
    
    for merchant in merchants:
        merchant_requests = [
            r for r in db.data['requests']
            if r['merchant_id'] == merchant['id'] and 
            start_date <= datetime.fromisoformat(r['timestamp']) <= end_date
        ]
        
        total = len(merchant_requests)
        total_amount = sum(r['amount'] for r in merchant_requests)
        completed_amount = sum(r['amount'] for r in merchant_requests if r['status'] == 'completed')
        
        merchants_stats.append({
            'id': merchant['id'],
            'username': merchant['username'],
            'total_requests': total,
            'total_amount': total_amount,
            'completed_amount': completed_amount
        })
    
    return jsonify({
        "period": {
            "start": start_date.isoformat(),
            "end": end_date.isoformat(),
            "type": report_type
        },
        "volume": {
            "total_amount": total_amount,
            "total_count": total_count,
            "completed_amount": completed_amount,
            "completed_count": completed_count,
            "conversion_rate": round((completed_count / total_count * 100) if total_count > 0 else 0, 2)
        },
        "traders_conversion": traders_conversion,
        "merchants_stats": merchants_stats
    })

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
        r['details'] = json.loads(r['details']) if isinstance(r['details'], str) else r['details']
    
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

@app.route('/api/trader/requests')
def trader_requests():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    status = request.args.get('status')
    
    requests = [r for r in db.data['requests'] if r['trader_id'] == user_id]
    
    if status in ['pending', 'processing', 'completed', 'disputed']:
        requests = [r for r in requests if r['status'] == status]
    
    # Добавляем информацию о мерчантах
    result = []
    for r in requests[:50]:  # Ограничиваем 50 записями
        merchant = db.get_user_by_id(r['merchant_id']) if r['merchant_id'] else None
        
        result.append({
            'id': r['id'],
            'type': r['type'],
            'amount': r['amount'],
            'currency': r['currency'],
            'status': r['status'],
            'timestamp': r['timestamp'],
            'expiry_time': r['expiry_time'],
            'merchant': merchant['username'] if merchant else None,
            'details': r['details']
        })
    
    return jsonify(result)

@app.route('/api/trader/request/<int:request_id>', methods=['GET', 'PUT'])
def trader_request(request_id):
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    
    if request.method == 'GET':
        req = next((r for r in db.data['requests'] 
                  if r['id'] == request_id and r['trader_id'] == user_id), None)
        if not req:
            return jsonify({"error": "Request not found"}), 404
        
        merchant = db.get_user_by_id(req['merchant_id']) if req['merchant_id'] else None
        
        return jsonify({
            'id': req['id'],
            'type': req['type'],
            'amount': req['amount'],
            'currency': req['currency'],
            'status': req['status'],
            'timestamp': req['timestamp'],
            'expiry_time': req['expiry_time'],
            'details': req['details'],
            'merchant': merchant['username'] if merchant else None
        })
    
    elif request.method == 'PUT':
        data = request.json
        action = data.get('action')
        
        req = next((r for r in db.data['requests'] if r['id'] == request_id), None)
        if not req:
            return jsonify({"error": "Request not found"}), 404
        
        if action == 'accept':
            if req['status'] != 'pending':
                return jsonify({"error": "Request already processed"}), 400
            
            req['status'] = 'processing'
            req['trader_id'] = user_id
            db._save_data()
            
            db.log_activity(user_id, 'request_accept', f"Принятие заявки ID {request_id}")
            db.send_notification(
                req['user_id'],
                'request',
                f"Ваша заявка #{request_id} принята трейдером"
            )
            return jsonify({"status": "success"})
        
        elif action == 'complete':
            if req['trader_id'] != user_id or req['status'] != 'processing':
                return jsonify({"error": "Request not found or not in processing"}), 404
            
            req['status'] = 'completed'
            db._save_data()
            
            # Обновляем балансы
            if req['type'] == 'in':  # Депозит
                db.update_wallet_balance(user_id, req['currency'], req['amount'])
                
                # Создаем транзакцию
                db.add_transaction(
                    'payment',
                    req['amount'],
                    req['currency'],
                    req['user_id'],
                    user_id,
                    req['merchant_id'],
                    'completed',
                    {'request_id': request_id}
                )
            else:  # Выплата
                rate = db.get_current_rate()
                usdt_amount = req['amount'] / rate['trader_out']
                
                db.update_wallet_balance(user_id, 'USDT', usdt_amount)
                
                # Создаем транзакцию
                db.add_transaction(
                    'payout',
                    usdt_amount,
                    'USDT',
                    req['user_id'],
                    user_id,
                    req['merchant_id'],
                    'completed',
                    {'request_id': request_id, 'original_amount': req['amount']}
                )
            
            db.log_activity(user_id, 'request_complete', f"Завершение заявки ID {request_id}")
            db.send_notification(
                req['user_id'],
                'request',
                f"Ваша заявка #{request_id} успешно завершена"
            )
            return jsonify({
                "status": "success",
                "new_balance": db.get_balance(user_id)
            })
        
        elif action == 'dispute':
            req['status'] = 'disputed'
            db._save_data()
            
            db.add_dispute(
                request_id,
                user_id,
                'open',
                {'reason': data.get('reason', 'Не указана')}
            )
            
            db.log_activity(user_id, 'request_dispute', f"Создание диспута по заявке ID {request_id}")
            db.send_notification(
                req['user_id'],
                'dispute',
                f"Создан диспут по заявке #{request_id}"
            )
            return jsonify({"status": "success"})
        
        return jsonify({"error": "Invalid action"}), 400

@app.route('/api/trader/payment_details', methods=['GET', 'POST'])
def trader_payment_details():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    
    if request.method == 'GET':
        details = [pd for pd in db.data['payment_details'] if pd['user_id'] == user_id]
        details = sorted(details, key=lambda x: (not x['is_active'], x['created_at']), reverse=True)
        return jsonify(details)
    
    elif request.method == 'POST':
        data = request.json
        
        if not all(key in data for key in ['type', 'details', 'bank_name']):
            return jsonify({"error": "Missing required fields"}), 400
        
        try:
            payment_detail = db.add_payment_detail(
                user_id,
                data['type'],
                data['details'],
                data.get('is_active', True),
                data.get('min_amount', 0),
                data.get('max_amount', 1000000),
                data['bank_name'],
                data.get('notification_type', 'PUSH')
            )
            
            db.log_activity(user_id, 'payment_detail_add', "Добавление новых реквизитов")
            return jsonify({"status": "success", "detail": payment_detail})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route('/api/trader/payment_detail/<int:detail_id>', methods=['PUT', 'DELETE'])
def trader_payment_detail(detail_id):
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    
    # Проверяем, что реквизиты принадлежат этому пользователю
    detail = next((pd for pd in db.data['payment_details'] 
                 if pd['id'] == detail_id and pd['user_id'] == user_id), None)
    if not detail:
        return jsonify({"error": "Payment detail not found"}), 404
    
    if request.method == 'PUT':
        data = request.json
        
        updates = {}
        if 'is_active' in data:
            updates['is_active'] = data['is_active']
        if 'min_amount' in data:
            updates['min_amount'] = data['min_amount']
        if 'max_amount' in data:
            updates['max_amount'] = data['max_amount']
        if 'notification_type' in data:
            updates['notification_type'] = data['notification_type']
        
        if not updates:
            return jsonify({"error": "No fields to update"}), 400
        
        detail.update(updates)
        db._save_data()
        
        db.log_activity(user_id, 'payment_detail_update', f"Обновление реквизитов ID {detail_id}")
        return jsonify({"status": "success"})
    
    elif request.method == 'DELETE':
        db.data['payment_details'] = [pd for pd in db.data['payment_details'] 
                                    if pd['id'] != detail_id or pd['user_id'] != user_id]
        db._save_data()
        
        db.log_activity(user_id, 'payment_detail_delete', f"Удаление реквизитов ID {detail_id}")
        return jsonify({"status": "success"})

@app.route('/api/trader/deposit', methods=['POST'])
def trader_deposit():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    data = request.json
    amount = float(data['amount'])
    
    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400
    
    # В реальной системе здесь должна быть интеграция с криптокошельками
    wallet = next((w for w in db.data['wallets'] 
                 if w['user_id'] == user_id and w['type'] == 'USDT'), None)
    
    if not wallet:
        wallet = db.create_wallet(user_id, 'USDT', amount)
    else:
        wallet['balance'] += amount
        wallet['last_used'] = datetime.now().isoformat()
    
    db._save_data()
    
    # Создаем запись о транзакции
    db.add_transaction(
        'deposit',
        amount,
        'USDT',
        user_id,
        None,
        None,
        'completed',
        {'method': 'manual', 'wallet': wallet['address']}
    )
    
    db.log_activity(user_id, 'balance_deposit', f"Пополнение баланса на {amount} USDT")
    return jsonify({
        "status": "success",
        "new_balance": db.get_balance(user_id),
        "wallet": wallet['address']
    })

@app.route('/api/trader/withdraw', methods=['POST'])
def trader_withdraw():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    data = request.json
    amount = float(data['amount'])
    wallet = data.get('wallet')
    
    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400
    
    # Проверяем достаточность баланса
    balance = db.get_balance(user_id)['USDT']
    if balance < amount:
        return jsonify({"error": "Insufficient balance"}), 400
    
    # Уменьшаем баланс
    usdt_wallet = next((w for w in db.data['wallets'] 
                       if w['user_id'] == user_id and w['type'] == 'USDT'), None)
    if usdt_wallet:
        usdt_wallet['balance'] -= amount
        usdt_wallet['last_used'] = datetime.now().isoformat()
    
    db._save_data()
    
    # Создаем запись о транзакции
    db.add_transaction(
        'withdraw',
        amount,
        'USDT',
        user_id,
        None,
        None,
        'pending',
        {'wallet': wallet, 'method': 'manual'}
    )
    
    db.log_activity(user_id, 'balance_withdraw', f"Запрос на вывод {amount} USDT")
    db.send_notification(
        user_id,
        'system',
        f"Запрос на вывод {amount} USDT обрабатывается"
    )
    return jsonify({
        "status": "success",
        "new_balance": db.get_balance(user_id)
    })

@app.route('/api/trader/upload_proof', methods=['POST'])
def trader_upload_proof():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    request_id = request.form.get('request_id')
    
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{user_id}_{request_id}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Сохраняем ссылку на файл в базе данных
        req = next((r for r in db.data['requests'] if r['id'] == int(request_id)), None)
        if req:
            if isinstance(req['details'], str):
                req['details'] = json.loads(req['details'])
            req['details']['proof'] = filename
            db._save_data()
        
        db.log_activity(user_id, 'proof_upload', f"Загрузка подтверждения для заявки ID {request_id}")
        return jsonify({"status": "success", "filename": filename})
    
    return jsonify({"error": "Invalid file type"}), 400

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/trader/notifications')
def trader_notifications():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    unread_only = request.args.get('unread_only', 'false') == 'true'
    
    notifications = [n for n in db.data['notifications'] if n['user_id'] == user_id]
    
    if unread_only:
        notifications = [n for n in notifications if not n['is_read']]
    
    notifications = sorted(notifications, key=lambda x: x['timestamp'], reverse=True)[:50]
    return jsonify(notifications)

@app.route('/api/trader/mark_notification_read/<int:notification_id>', methods=['POST'])
def trader_mark_notification_read(notification_id):
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    
    notification = next((n for n in db.data['notifications'] 
                       if n['id'] == notification_id and n['user_id'] == user_id), None)
    if notification:
        notification['is_read'] = True
        db._save_data()
    
    return jsonify({"status": "success"})

@app.route('/api/trader/update_settings', methods=['POST'])
def trader_update_settings():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    data = request.json
    
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Обновляем настройки
    user['settings'] = {**user.get('settings', {}), **data}
    db._save_data()
    
    db.log_activity(user_id, 'settings_update', "Обновление настроек трейдера")
    return jsonify({"status": "success", "settings": user['settings']})

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
        r['details'] = json.loads(r['details']) if isinstance(r['details'], str) else r['details']
    
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

@app.route('/api/merchant/transactions')
def merchant_transactions():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    page = int(request.args.get('page', 1))
    limit = 20
    offset = (page - 1) * limit
    
    transactions = [t for t in db.data['transactions'] 
                   if t['user_id'] == user_id or t['merchant_id'] == user_id]
    transactions = sorted(transactions, key=lambda x: x['timestamp'], reverse=True)[offset:offset+limit]
    
    return jsonify(transactions)

@app.route('/api/merchant/requests')
def merchant_requests():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    status = request.args.get('status')
    
    requests = [r for r in db.data['requests'] if r['merchant_id'] == user_id]
    
    if status in ['pending', 'processing', 'completed', 'disputed']:
        requests = [r for r in requests if r['status'] == status]
    
    # Добавляем информацию о трейдерах
    result = []
    for r in requests[:50]:  # Ограничиваем 50 записями
        trader = db.get_user_by_id(r['trader_id']) if r['trader_id'] else None
        
        result.append({
            'id': r['id'],
            'type': r['type'],
            'amount': r['amount'],
            'currency': r['currency'],
            'status': r['status'],
            'timestamp': r['timestamp'],
            'trader': trader['username'] if trader else None,
            'details': r['details']
        })
    
    return jsonify(result)

@app.route('/api/merchant/create_payment', methods=['POST'])
def merchant_create_payment():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    data = request.json
    amount = float(data['amount'])
    currency = data.get('currency', 'RUB')
    payment_type = data['type']  # in or out
    
    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400
    
    # Выбираем случайного активного трейдера
    traders = [u for u in db.data['users'] 
              if u['role'] == 'trader' and u['status'] == 'active']
    if not traders:
        return jsonify({"error": "No available traders"}), 400
    
    trader = traders[0]  # В реальной системе здесь должна быть логика выбора
    
    # Создаем заявку
    request_data = db.add_request(
        payment_type,
        amount,
        currency,
        user_id,
        trader['id'],
        user_id,
        'pending',
        {
            "trader_rate": trader['settings'].get('rate_in' if payment_type == 'in' else 'rate_out', 1.0),
            "merchant_id": user_id,
            "created_at": datetime.now().isoformat()
        }
    )
    
    # Отправляем уведомление трейдеру
    db.send_notification(
        trader['id'],
        'request',
        f"Новая заявка #{request_data['id']} на сумму {amount} {currency}"
    )
    
    db.log_activity(user_id, 'payment_request_create', f"Создание заявки ID {request_data['id']}")
    return jsonify({
        "status": "success",
        "request_id": request_data['id'],
        "trader_id": trader['id'],
        "expiry_time": request_data['expiry_time']
    })

@app.route('/api/merchant/disputes')
def merchant_disputes():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    
    disputes = []
    for d in db.data['disputes']:
        req = next((r for r in db.data['requests'] 
                   if r['id'] == d['request_id'] and r['merchant_id'] == user_id), None)
        if req:
            trader = db.get_user_by_id(req['trader_id']) if req['trader_id'] else None
            disputes.append({
                'id': d['id'],
                'status': d['status'],
                'timestamp': d['timestamp'],
                'amount': req['amount'],
                'currency': req['currency'],
                'trader': trader['username'] if trader else None,
                'details': d['details']
            })
    
    disputes = sorted(disputes, key=lambda x: x['timestamp'], reverse=True)
    return jsonify(disputes)

@app.route('/api/merchant/update_settings', methods=['POST'])
def merchant_update_settings():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    data = request.json
    
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Обновляем настройки
    user['settings'] = {**user.get('settings', {}), **data}
    db._save_data()
    
    db.log_activity(user_id, 'settings_update', "Обновление настроек мерчанта")
    return jsonify({"status": "success", "settings": user['settings']})

@app.route('/api/merchant/notifications')
def merchant_notifications():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    unread_only = request.args.get('unread_only', 'false') == 'true'
    
    notifications = [n for n in db.data['notifications'] if n['user_id'] == user_id]
    
    if unread_only:
        notifications = [n for n in notifications if not n['is_read']]
    
    notifications = sorted(notifications, key=lambda x: x['timestamp'], reverse=True)[:50]
    return jsonify(notifications)

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

@app.route('/api/activity_log')
def user_activity_log():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    limit = int(request.args.get('limit', 50))
    
    activities = [a for a in db.data['activity_log'] if a['user_id'] == user_id]
    activities = sorted(activities, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    return jsonify(activities)

# =============================================
# Запуск приложения
# =============================================
if __name__ == '__main__':
    # Инициализация тестовых данных при первом запуске
    if not db.data['users']:
        init_test_data()
        print("Initial test data created")
    
    app.run(debug=True, host='0.0.0.0', port=5000)