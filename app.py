from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
import sqlite3
import json
import time
from datetime import datetime, timedelta
import hashlib
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# =============================================
# Самописная база данных
# =============================================
class SimpleDB:
    def __init__(self):
        self.conn = sqlite3.connect('processing.db', check_same_thread=False)
        self._init_db()
    
    def _init_db(self):
        cursor = self.conn.cursor()
        
        # Пользователи
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,  # admin, trader, merchant
            contact_info TEXT,
            settings TEXT,  # JSON with role-specific settings
            status TEXT DEFAULT 'active',
            last_login TEXT,
            ip_address TEXT,
            registration_date TEXT DEFAULT CURRENT_TIMESTAMP,
            tg_notification_id TEXT
        )''')
        
        # Транзакции
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,  # deposit, withdraw, payment
            amount REAL,
            currency TEXT,
            user_id INTEGER,
            trader_id INTEGER,
            merchant_id INTEGER,
            status TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            details TEXT,  # JSON with transaction details
            proof TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(trader_id) REFERENCES users(id),
            FOREIGN KEY(merchant_id) REFERENCES users(id)
        )''')
        
        # Реквизиты
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS payment_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT,  # card, wallet, etc.
            details TEXT,  # JSON with payment details
            is_active INTEGER DEFAULT 1,
            min_amount REAL DEFAULT 0,
            max_amount REAL DEFAULT 1000000,
            bank_name TEXT,
            notification_type TEXT DEFAULT 'PUSH',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        
        # Заявки
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,  # in, out
            amount REAL,
            currency TEXT,
            user_id INTEGER,
            trader_id INTEGER,
            merchant_id INTEGER,
            status TEXT DEFAULT 'pending',  # pending, processing, completed, disputed
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            expiry_time TEXT,
            details TEXT,  # JSON with request details
            conversion_rate REAL,
            priority INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(trader_id) REFERENCES users(id),
            FOREIGN KEY(merchant_id) REFERENCES users(id)
        )''')
        
        # Диспуты
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS disputes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER,
            user_id INTEGER,
            admin_id INTEGER,
            status TEXT DEFAULT 'open',  # open, in_progress, resolved
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            resolution TEXT,
            FOREIGN KEY(request_id) REFERENCES requests(id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(admin_id) REFERENCES users(id)
        )''')
        
        # Кошельки
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT,
            user_id INTEGER,
            type TEXT,  # USDT, RUB, etc.
            balance REAL DEFAULT 0,
            is_available INTEGER DEFAULT 1,
            last_used TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        
        # Курсы валют
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS exchange_rates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            base_currency TEXT,
            target_currency TEXT,
            rate REAL,
            trader_markup REAL,
            platform_markup REAL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Уведомления
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT,  # request, dispute, system
            message TEXT,
            is_read INTEGER DEFAULT 0,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        
        # Логи действий
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        
        self.conn.commit()
    
    def execute(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        self.conn.commit()
        return cursor
    
    def fetch_one(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchone()
    
    def fetch_all(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

db = SimpleDB()

# =============================================
# Вспомогательные функции
# =============================================
def init_test_data():
    # Добавляем администратора
    db.execute(
        "INSERT INTO users (username, password, role, contact_info) VALUES (?, ?, ?, ?)",
        ("admin", hashlib.sha256("admin123".encode()).hexdigest(), "admin", "admin@example.com")
    )
    
    # Добавляем тестового трейдера
    trader_settings = json.dumps({
        "rate_in": 5.0,
        "rate_out": 2.0,
        "deposit": 1000.0,
        "work_method": "cards",
        "trc20_wallet": "TXYZ1234567890",
        "working_hours": "09:00-21:00",
        "insurance_deposit": 500.0,
        "payment_methods": ["SBP", "C2C"],
        "notifications": ["PUSH", "TG"]
    })
    db.execute(
        "INSERT INTO users (username, password, role, settings, contact_info) VALUES (?, ?, ?, ?, ?)",
        ("trader1", hashlib.sha256("trader123".encode()).hexdigest(), "trader", trader_settings, "trader1@example.com")
    )
    
    # Добавляем тестового мерчанта
    merchant_settings = json.dumps({
        "rate_in": 1.0,
        "rate_out": 1.0,
        "website": "https://example.com",
        "payment_methods": ["card", "crypto"],
        "trc20_wallet": "TXYZ0987654321",
        "priority": "high",
        "traffic_type": "gambling",
        "contact_person": "John Doe",
        "contact_phone": "+1234567890"
    })
    db.execute(
        "INSERT INTO users (username, password, role, settings, contact_info) VALUES (?, ?, ?, ?, ?)",
        ("merchant1", hashlib.sha256("merchant123".encode()).hexdigest(), "merchant", merchant_settings, "merchant1@example.com")
    )
    
    # Устанавливаем курс валют
    db.execute(
        "INSERT INTO exchange_rates (base_currency, target_currency, rate, trader_markup, platform_markup) VALUES (?, ?, ?, ?, ?)",
        ("USDT", "RUB", 100.0, 5.0, 2.0)
    )
    
    # Создаем кошельки для пользователей
    traders = db.fetch_all("SELECT id FROM users WHERE role = 'trader'")
    for trader in traders:
        create_wallet(trader[0], 'USDT', 1000.0)
        create_wallet(trader[0], 'RUB', 0.0)
    
    merchants = db.fetch_all("SELECT id FROM users WHERE role = 'merchant'")
    for merchant in merchants:
        create_wallet(merchant[0], 'USDT', 0.0)
        create_wallet(merchant[0], 'RUB', 0.0)

def get_current_rate():
    rate = db.fetch_one(
        "SELECT rate, trader_markup, platform_markup FROM exchange_rates ORDER BY timestamp DESC LIMIT 1"
    )
    if rate:
        return {
            "base": rate[0],
            "trader_in": rate[0] * (1 + rate[1]/100),
            "trader_out": rate[0] * (1 - rate[2]/100),
            "platform": rate[0],
            "trader_markup": rate[1],
            "platform_markup": rate[2]
        }
    return None

def get_user_balance(user_id):
    rub = db.fetch_one("SELECT SUM(balance) FROM wallets WHERE user_id = ? AND type = 'RUB'", (user_id,))[0] or 0
    usdt = db.fetch_one("SELECT SUM(balance) FROM wallets WHERE user_id = ? AND type = 'USDT'", (user_id,))[0] or 0
    return {"RUB": rub, "USDT": usdt}

def create_wallet(user_id, currency, initial_balance=0):
    address = f"{currency}_{user_id}_{hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]}"
    db.execute(
        "INSERT INTO wallets (address, user_id, type, balance, is_available) VALUES (?, ?, ?, ?, ?)",
        (address, user_id, currency, initial_balance, 1)
    )
    return address

def log_activity(user_id, action, details=""):
    db.execute(
        "INSERT INTO activity_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
        (user_id, action, details, request.remote_addr)
    )

def send_notification(user_id, notification_type, message):
    db.execute(
        "INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)",
        (user_id, notification_type, message)
    )

def get_user_role(user_id):
    user = db.fetch_one("SELECT role FROM users WHERE id = ?", (user_id,))
    return user[0] if user else None

# =============================================
# Основные маршруты
# =============================================
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.fetch_one("SELECT role FROM users WHERE id = ?", (session['user_id'],))
    if not user:
        return redirect(url_for('login'))
    
    if user[0] == 'admin':
        return redirect(url_for('admin_panel'))
    elif user[0] == 'trader':
        return redirect(url_for('trader_panel'))
    elif user[0] == 'merchant':
        return redirect(url_for('merchant_panel'))
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error='Заполните все поля')
        
        user = db.fetch_one(
            "SELECT id, password, role, status FROM users WHERE username = ?",
            (username,)
        )
        
        if not user or user[1] != hashlib.sha256(password.encode()).hexdigest():
            return render_template('login.html', error='Неверный логин или пароль')
        
        if user[3] != 'active':
            return render_template('login.html', error='Ваш аккаунт деактивирован')
        
        session['user_id'] = user[0]
        session['role'] = user[2]
        session['username'] = username
        
        db.execute(
            "UPDATE users SET last_login = ?, ip_address = ? WHERE id = ?",
            (datetime.now().isoformat(), request.remote_addr, user[0])
        )
        
        log_activity(user[0], 'login', f"Успешный вход в систему с IP {request.remote_addr}")
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'logout', "Выход из системы")
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
        "traders": db.fetch_one("SELECT COUNT(*) FROM users WHERE role = 'trader'")[0],
        "merchants": db.fetch_one("SELECT COUNT(*) FROM users WHERE role = 'merchant'")[0],
        "active_traders": db.fetch_one("SELECT COUNT(*) FROM users WHERE role = 'trader' AND status = 'active'")[0],
        "active_merchants": db.fetch_one("SELECT COUNT(*) FROM users WHERE role = 'merchant' AND status = 'active'")[0],
        "today_volume": db.fetch_one(
            "SELECT SUM(amount) FROM transactions WHERE date(timestamp) = date('now') AND type = 'payment'"
        )[0] or 0,
        "disputes": db.fetch_one("SELECT COUNT(*) FROM disputes WHERE status = 'open'")[0],
        "active_requests": db.fetch_one("SELECT COUNT(*) FROM requests WHERE status = 'pending'")[0],
        "active_tokens": db.fetch_one("SELECT COUNT(DISTINCT user_id) FROM payment_details WHERE is_active = 1")[0]
    }
    
    # Последние транзакции
    transactions = db.fetch_all(
        "SELECT t.id, t.type, t.amount, t.currency, t.status, t.timestamp, u.username "
        "FROM transactions t JOIN users u ON t.user_id = u.id "
        "ORDER BY t.timestamp DESC LIMIT 10"
    )
    
    # Последние заявки
    requests = db.fetch_all(
        "SELECT r.id, r.type, r.amount, r.currency, r.status, r.timestamp, u.username "
        "FROM requests r JOIN users u ON r.user_id = u.id "
        "ORDER BY r.timestamp DESC LIMIT 10"
    )
    
    # Курс валют
    exchange_rate = get_current_rate()
    
    log_activity(user_id, 'admin_panel_view', "Просмотр панели администратора")
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
    query = "SELECT id, username, role, contact_info, status, last_login FROM users"
    params = ()
    
    if role in ['trader', 'merchant', 'admin']:
        query += " WHERE role = ?"
        params = (role,)
    
    users = db.fetch_all(query, params)
    return jsonify([dict(zip(
        ['id', 'username', 'role', 'contact_info', 'status', 'last_login'],
        u
    )) for u in users])

@app.route('/api/admin/user/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
def admin_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = session['user_id']
    
    if request.method == 'GET':
        user = db.fetch_one(
            "SELECT id, username, role, contact_info, settings, status FROM users WHERE id = ?",
            (user_id,)
        )
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "id": user[0],
            "username": user[1],
            "role": user[2],
            "contact_info": user[3],
            "settings": json.loads(user[4]) if user[4] else {},
            "status": user[5]
        })
    
    elif request.method == 'PUT':
        data = request.json
        settings = json.dumps(data.get('settings', {}))
        
        db.execute(
            "UPDATE users SET contact_info = ?, settings = ?, status = ? WHERE id = ?",
            (data.get('contact_info'), settings, data.get('status'), user_id)
        )
        
        log_activity(admin_id, 'user_update', f"Обновление пользователя ID {user_id}")
        return jsonify({"status": "success"})
    
    elif request.method == 'DELETE':
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        log_activity(admin_id, 'user_delete', f"Удаление пользователя ID {user_id}")
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
        db.execute(
            "INSERT INTO users (username, password, role, contact_info, settings) VALUES (?, ?, ?, ?, ?)",
            (
                data['username'],
                hashlib.sha256(data['password'].encode()).hexdigest(),
                data['role'],
                data.get('contact_info', ''),
                json.dumps(data.get('settings', {}))
            )
        )
        
        log_activity(admin_id, 'user_create', f"Создание пользователя {data['username']}")
        return jsonify({"status": "success"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400

@app.route('/api/admin/transactions')
def admin_transactions():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    page = int(request.args.get('page', 1))
    limit = 20
    offset = (page - 1) * limit
    
    transactions = db.fetch_all(
        "SELECT t.id, t.type, t.amount, t.currency, t.status, t.timestamp, u.username, t.details "
        "FROM transactions t JOIN users u ON t.user_id = u.id "
        "ORDER BY t.timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset)
    )
    
    return jsonify([dict(zip(
        ['id', 'type', 'amount', 'currency', 'status', 'timestamp', 'username', 'details'],
        [*t[:7], json.loads(t[7]) if t[7] else {}]
    )) for t in transactions])

@app.route('/api/admin/requests')
def admin_requests():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    status = request.args.get('status')
    query = """
        SELECT r.id, r.type, r.amount, r.currency, r.status, r.timestamp, u.username, t.username, m.username 
        FROM requests r 
        JOIN users u ON r.user_id = u.id 
        LEFT JOIN users t ON r.trader_id = t.id 
        LEFT JOIN users m ON r.merchant_id = m.id
    """
    params = ()
    
    if status in ['pending', 'processing', 'completed', 'disputed']:
        query += " WHERE r.status = ?"
        params = (status,)
    
    query += " ORDER BY r.timestamp DESC LIMIT 50"
    
    requests = db.fetch_all(query, params)
    return jsonify([dict(zip(
        ['id', 'type', 'amount', 'currency', 'status', 'timestamp', 'user', 'trader', 'merchant'],
        r
    )) for r in requests])

@app.route('/api/admin/update_rate', methods=['POST'])
def admin_update_rate():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = session['user_id']
    data = request.json
    
    db.execute(
        "INSERT INTO exchange_rates (base_currency, target_currency, rate, trader_markup, platform_markup) VALUES (?, ?, ?, ?, ?)",
        ("USDT", "RUB", data['rate'], data['trader_markup'], data['platform_markup'])
    )
    
    log_activity(admin_id, 'rate_update', f"Обновление курса: {data['rate']} RUB за USDT")
    return jsonify({"status": "success", "new_rate": get_current_rate()})

@app.route('/api/admin/disputes')
def admin_disputes():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    status = request.args.get('status', 'open')
    disputes = db.fetch_all(
        """
        SELECT d.id, d.status, d.timestamp, r.amount, r.currency, 
               u.username as user, t.username as trader, m.username as merchant
        FROM disputes d
        JOIN requests r ON d.request_id = r.id
        JOIN users u ON d.user_id = u.id
        LEFT JOIN users t ON r.trader_id = t.id
        LEFT JOIN users m ON r.merchant_id = m.id
        WHERE d.status = ?
        ORDER BY d.timestamp DESC
        """,
        (status,)
    )
    
    return jsonify([dict(zip(
        ['id', 'status', 'timestamp', 'amount', 'currency', 'user', 'trader', 'merchant'],
        d
    )) for d in disputes])

@app.route('/api/admin/resolve_dispute/<int:dispute_id>', methods=['POST'])
def admin_resolve_dispute(dispute_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = session['user_id']
    data = request.json
    
    db.execute(
        "UPDATE disputes SET status = 'resolved', resolution = ?, admin_id = ? WHERE id = ?",
        (data['resolution'], admin_id, dispute_id)
    )
    
    # Получаем request_id для обновления статуса заявки
    request_id = db.fetch_one("SELECT request_id FROM disputes WHERE id = ?", (dispute_id,))[0]
    db.execute("UPDATE requests SET status = 'completed' WHERE id = ?", (request_id,))
    
    log_activity(admin_id, 'dispute_resolve', f"Разрешение диспута ID {dispute_id}")
    return jsonify({"status": "success"})

@app.route('/api/admin/block_trader/<int:trader_id>', methods=['POST'])
def admin_block_trader(trader_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = session['user_id']
    reason = request.json.get('reason', 'Нарушение правил')
    
    db.execute(
        "UPDATE users SET status = 'blocked' WHERE id = ? AND role = 'trader'",
        (trader_id,)
    )
    
    # Отменяем все активные заявки этого трейдера
    db.execute(
        "UPDATE requests SET status = 'canceled' WHERE trader_id = ? AND status IN ('pending', 'processing')",
        (trader_id,)
    )
    
    log_activity(admin_id, 'trader_block', f"Блокировка трейдера ID {trader_id}. Причина: {reason}")
    send_notification(trader_id, 'system', f"Ваш аккаунт заблокирован. Причина: {reason}")
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
    
    # Объем операций
    volume = db.fetch_one(
        """
        SELECT SUM(amount), COUNT(*), 
               SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END),
               SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END)
        FROM transactions
        WHERE timestamp BETWEEN ? AND ?
        """,
        (start_date.isoformat(), end_date.isoformat())
    )
    
    # Конверсия по трейдерам
    traders_conversion = db.fetch_all(
        """
        SELECT u.id, u.username, 
               COUNT(r.id) as total_requests,
               SUM(CASE WHEN r.status = 'completed' THEN 1 ELSE 0 END) as completed_requests,
               CASE WHEN COUNT(r.id) > 0 
                    THEN ROUND(SUM(CASE WHEN r.status = 'completed' THEN 1 ELSE 0 END) * 100.0 / COUNT(r.id), 2)
                    ELSE 0 END as conversion_rate
        FROM users u
        LEFT JOIN requests r ON u.id = r.trader_id AND r.timestamp BETWEEN ? AND ?
        WHERE u.role = 'trader'
        GROUP BY u.id, u.username
        ORDER BY conversion_rate DESC
        """,
        (start_date.isoformat(), end_date.isoformat())
    )
    
    # Статистика по мерчантам
    merchants_stats = db.fetch_all(
        """
        SELECT u.id, u.username, 
               COUNT(r.id) as total_requests,
               SUM(r.amount) as total_amount,
               SUM(CASE WHEN r.status = 'completed' THEN r.amount ELSE 0 END) as completed_amount
        FROM users u
        LEFT JOIN requests r ON u.id = r.merchant_id AND r.timestamp BETWEEN ? AND ?
        WHERE u.role = 'merchant'
        GROUP BY u.id, u.username
        ORDER BY total_amount DESC
        """,
        (start_date.isoformat(), end_date.isoformat())
    )
    
    return jsonify({
        "period": {
            "start": start_date.isoformat(),
            "end": end_date.isoformat(),
            "type": report_type
        },
        "volume": {
            "total_amount": volume[0] or 0,
            "total_count": volume[1] or 0,
            "completed_amount": volume[2] or 0,
            "completed_count": volume[3] or 0,
            "conversion_rate": round((volume[3] / volume[1] * 100) if volume[1] > 0 else 0, 2)
        },
        "traders_conversion": [dict(zip(
            ['id', 'username', 'total_requests', 'completed_requests', 'conversion_rate'],
            t
        )) for t in traders_conversion],
        "merchants_stats": [dict(zip(
            ['id', 'username', 'total_requests', 'total_amount', 'completed_amount'],
            m
        )) for m in merchants_stats]
    })

# =============================================
# Панель трейдера
# =============================================
@app.route('/trader')
def trader_panel():
    if 'user_id' not in session or session.get('role') != 'trader':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    balance = get_user_balance(user_id)
    rate = get_current_rate()
    
    # Активные заявки
    active_requests = db.fetch_all(
        """
        SELECT r.id, r.type, r.amount, r.currency, r.status, r.timestamp, r.expiry_time, 
               m.username as merchant, r.details
        FROM requests r
        LEFT JOIN users m ON r.merchant_id = m.id
        WHERE r.trader_id = ? AND r.status IN ('pending', 'processing')
        ORDER BY r.timestamp DESC
        LIMIT 10
        """,
        (user_id,)
    )
    
    # Реквизиты
    payment_details = db.fetch_all(
        """
        SELECT id, type, details, is_active, min_amount, max_amount, bank_name, notification_type
        FROM payment_details
        WHERE user_id = ?
        ORDER BY is_active DESC, created_at DESC
        """,
        (user_id,)
    )
    
    # Статистика трейдера
    stats = {
        "today_requests": db.fetch_one(
            "SELECT COUNT(*) FROM requests WHERE trader_id = ? AND date(timestamp) = date('now')",
            (user_id,)
        )[0] or 0,
        "today_amount": db.fetch_one(
            "SELECT SUM(amount) FROM requests WHERE trader_id = ? AND date(timestamp) = date('now') AND status = 'completed'",
            (user_id,)
        )[0] or 0,
        "conversion_rate": db.fetch_one(
            """
            SELECT 
                CASE WHEN COUNT(*) > 0 
                     THEN ROUND(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2)
                     ELSE 0 END
            FROM requests
            WHERE trader_id = ?
            """,
            (user_id,)
        )[0] or 0,
        "disputes": db.fetch_one(
            "SELECT COUNT(*) FROM disputes WHERE user_id = ? AND status = 'open'",
            (user_id,)
        )[0] or 0
    }
    
    # Настройки трейдера
    trader_settings = db.fetch_one(
        "SELECT settings FROM users WHERE id = ?",
        (user_id,)
    )
    settings = json.loads(trader_settings[0]) if trader_settings and trader_settings[0] else {}
    
    log_activity(user_id, 'trader_panel_view', "Просмотр панели трейдера")
    return render_template(
        'trader.html',
        balance=balance,
        rate=rate,
        active_requests=active_requests,
        payment_details=payment_details,
        stats=stats,
        settings=settings
    )

# API для панели трейдера
@app.route('/api/trader/requests')
def trader_requests():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    status = request.args.get('status')
    
    query = """
        SELECT r.id, r.type, r.amount, r.currency, r.status, r.timestamp, r.expiry_time, 
               m.username as merchant, r.details
        FROM requests r
        LEFT JOIN users m ON r.merchant_id = m.id
        WHERE r.trader_id = ?
    """
    params = [user_id]
    
    if status in ['pending', 'processing', 'completed', 'disputed']:
        query += " AND r.status = ?"
        params.append(status)
    
    query += " ORDER BY r.timestamp DESC LIMIT 50"
    
    requests = db.fetch_all(query, params)
    return jsonify([dict(zip(
        ['id', 'type', 'amount', 'currency', 'status', 'timestamp', 'expiry_time', 'merchant', 'details'],
        [*r[:8], json.loads(r[8]) if r[8] else {}]
    )) for r in requests])

@app.route('/api/trader/request/<int:request_id>', methods=['GET', 'PUT'])
def trader_request(request_id):
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    
    if request.method == 'GET':
        req = db.fetch_one(
            """
            SELECT r.id, r.type, r.amount, r.currency, r.status, r.timestamp, r.expiry_time, 
                   r.details, m.username as merchant
            FROM requests r
            LEFT JOIN users m ON r.merchant_id = m.id
            WHERE r.id = ? AND r.trader_id = ?
            """,
            (request_id, user_id)
        )
        if not req:
            return jsonify({"error": "Request not found"}), 404
        
        return jsonify(dict(zip(
            ['id', 'type', 'amount', 'currency', 'status', 'timestamp', 'expiry_time', 'details', 'merchant'],
            [*req[:8], json.loads(req[7]) if req[7] else {}, req[8]]
        )))
    
    elif request.method == 'PUT':
        data = request.json
        action = data.get('action')
        
        if action == 'accept':
            # Проверяем, что заявка еще не принята другим трейдером
            current_status = db.fetch_one(
                "SELECT status FROM requests WHERE id = ?",
                (request_id,)
            )[0]
            
            if current_status != 'pending':
                return jsonify({"error": "Request already processed"}), 400
            
            db.execute(
                "UPDATE requests SET status = 'processing', trader_id = ? WHERE id = ?",
                (user_id, request_id)
            )
            
            log_activity(user_id, 'request_accept', f"Принятие заявки ID {request_id}")
            send_notification(
                db.fetch_one("SELECT user_id FROM requests WHERE id = ?", (request_id,))[0],
                'request',
                f"Ваша заявка #{request_id} принята трейдером"
            )
            return jsonify({"status": "success"})
        
        elif action == 'complete':
            # Проверяем, что заявка принадлежит этому трейдеру
            req = db.fetch_one(
                "SELECT id FROM requests WHERE id = ? AND trader_id = ? AND status = 'processing'",
                (request_id, user_id)
            )
            if not req:
                return jsonify({"error": "Request not found or not in processing"}), 404
            
            # В реальной системе здесь должна быть проверка подтверждения платежа (чек и т.д.)
            db.execute(
                "UPDATE requests SET status = 'completed' WHERE id = ?",
                (request_id,)
            )
            
            # Обновляем балансы
            request_data = db.fetch_one(
                "SELECT type, amount, currency, user_id FROM requests WHERE id = ?",
                (request_id,)
            )
            
            if request_data[0] == 'in':  # Депозит
                # Трейдер получает рубли на баланс
                db.execute(
                    "UPDATE wallets SET balance = balance + ? WHERE user_id = ? AND type = ?",
                    (request_data[1], user_id, request_data[2])
                )
                
                # Создаем запись о транзакции
                db.execute(
                    """
                    INSERT INTO transactions 
                    (type, amount, currency, user_id, trader_id, status, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        'payment',
                        request_data[1],
                        request_data[2],
                        request_data[3],
                        user_id,
                        'completed',
                        json.dumps({"request_id": request_id})
                    )
                )
            else:  # Выплата
                # Трейдер получает USDT на баланс с учетом своего процента
                rate = get_current_rate()
                usdt_amount = request_data[1] / rate['trader_out']
                
                db.execute(
                    "UPDATE wallets SET balance = balance + ? WHERE user_id = ? AND type = 'USDT'",
                    (usdt_amount, user_id)
                )
                
                # Создаем запись о транзакции
                db.execute(
                    """
                    INSERT INTO transactions 
                    (type, amount, currency, user_id, trader_id, status, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        'payout',
                        usdt_amount,
                        'USDT',
                        request_data[3],
                        user_id,
                        'completed',
                        json.dumps({"request_id": request_id, "original_amount": request_data[1]})
                    )
                )
            
            log_activity(user_id, 'request_complete', f"Завершение заявки ID {request_id}")
            send_notification(
                request_data[3],
                'request',
                f"Ваша заявка #{request_id} успешно завершена"
            )
            return jsonify({"status": "success", "new_balance": get_user_balance(user_id)})
        
        elif action == 'dispute':
            db.execute(
                "UPDATE requests SET status = 'disputed' WHERE id = ? AND trader_id = ?",
                (request_id, user_id)
            )
            
            db.execute(
                """
                INSERT INTO disputes 
                (request_id, user_id, status, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    request_id,
                    user_id,
                    'open',
                    json.dumps({"reason": data.get('reason', 'Не указана')})
                )
            )
            
            log_activity(user_id, 'request_dispute', f"Создание диспута по заявке ID {request_id}")
            send_notification(
                db.fetch_one("SELECT user_id FROM requests WHERE id = ?", (request_id,))[0],
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
        details = db.fetch_all(
            """
            SELECT id, type, details, is_active, min_amount, max_amount, bank_name, notification_type
            FROM payment_details
            WHERE user_id = ?
            ORDER BY is_active DESC, created_at DESC
            """,
            (user_id,)
        )
        return jsonify([dict(zip(
            ['id', 'type', 'details', 'is_active', 'min_amount', 'max_amount', 'bank_name', 'notification_type'],
            [*d[:2], json.loads(d[2]) if d[2] else {}, *d[3:]]
        )) for d in details])
    
    elif request.method == 'POST':
        data = request.json
        
        # Валидация данных
        if not all(key in data for key in ['type', 'details', 'bank_name']):
            return jsonify({"error": "Missing required fields"}), 400
        
        try:
            db.execute(
                """
                INSERT INTO payment_details 
                (user_id, type, details, is_active, min_amount, max_amount, bank_name, notification_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    data['type'],
                    json.dumps(data['details']),
                    data.get('is_active', 1),
                    data.get('min_amount', 0),
                    data.get('max_amount', 1000000),
                    data['bank_name'],
                    data.get('notification_type', 'PUSH')
                )
            )
            
            log_activity(user_id, 'payment_detail_add', "Добавление новых реквизитов")
            return jsonify({"status": "success"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route('/api/trader/payment_detail/<int:detail_id>', methods=['PUT', 'DELETE'])
def trader_payment_detail(detail_id):
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    
    # Проверяем, что реквизиты принадлежат этому пользователю
    detail = db.fetch_one(
        "SELECT id FROM payment_details WHERE id = ? AND user_id = ?",
        (detail_id, user_id)
    )
    if not detail:
        return jsonify({"error": "Payment detail not found"}), 404
    
    if request.method == 'PUT':
        data = request.json
        
        updates = []
        params = []
        
        if 'is_active' in data:
            updates.append("is_active = ?")
            params.append(data['is_active'])
        
        if 'min_amount' in data:
            updates.append("min_amount = ?")
            params.append(data['min_amount'])
        
        if 'max_amount' in data:
            updates.append("max_amount = ?")
            params.append(data['max_amount'])
        
        if 'notification_type' in data:
            updates.append("notification_type = ?")
            params.append(data['notification_type'])
        
        if not updates:
            return jsonify({"error": "No fields to update"}), 400
        
        query = f"UPDATE payment_details SET {', '.join(updates)} WHERE id = ?"
        params.append(detail_id)
        
        db.execute(query, params)
        
        log_activity(user_id, 'payment_detail_update', f"Обновление реквизитов ID {detail_id}")
        return jsonify({"status": "success"})
    
    elif request.method == 'DELETE':
        db.execute(
            "DELETE FROM payment_details WHERE id = ? AND user_id = ?",
            (detail_id, user_id)
        )
        
        log_activity(user_id, 'payment_detail_delete', f"Удаление реквизитов ID {detail_id}")
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
    # В этой упрощенной версии просто добавляем баланс
    
    wallet = db.fetch_one(
        "SELECT address FROM wallets WHERE user_id = ? AND type = 'USDT' LIMIT 1",
        (user_id,)
    )
    
    if not wallet:
        wallet_address = create_wallet(user_id, 'USDT', amount)
    else:
        wallet_address = wallet[0]
        db.execute(
            "UPDATE wallets SET balance = balance + ? WHERE address = ?",
            (amount, wallet_address)
        )
    
    # Создаем запись о транзакции
    db.execute(
        """
        INSERT INTO transactions 
        (type, amount, currency, user_id, status, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            'deposit',
            amount,
            'USDT',
            user_id,
            'completed',
            json.dumps({"method": "manual", "wallet": wallet_address})
        )
    )
    
    log_activity(user_id, 'balance_deposit', f"Пополнение баланса на {amount} USDT")
    return jsonify({
        "status": "success",
        "new_balance": get_user_balance(user_id),
        "wallet": wallet_address
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
    balance = get_user_balance(user_id)['USDT']
    if balance < amount:
        return jsonify({"error": "Insufficient balance"}), 400
    
    # В реальной системе здесь должна быть интеграция с криптокошельками
    # В этой упрощенной версии просто уменьшаем баланс
    
    db.execute(
        "UPDATE wallets SET balance = balance - ? WHERE user_id = ? AND type = 'USDT'",
        (amount, user_id)
    )
    
    # Создаем запись о транзакции
    db.execute(
        """
        INSERT INTO transactions 
        (type, amount, currency, user_id, status, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            'withdraw',
            amount,
            'USDT',
            user_id,
            'pending',  # В реальной системе статус будет меняться после подтверждения
            json.dumps({"wallet": wallet, "method": "manual"})
        )
    )
    
    log_activity(user_id, 'balance_withdraw', f"Запрос на вывод {amount} USDT")
    send_notification(
        user_id,
        'system',
        f"Запрос на вывод {amount} USDT обрабатывается"
    )
    return jsonify({
        "status": "success",
        "new_balance": get_user_balance(user_id)
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
        db.execute(
            "UPDATE requests SET details = json_set(details, '$.proof', ?) WHERE id = ?",
            (filename, request_id)
        )
        
        log_activity(user_id, 'proof_upload', f"Загрузка подтверждения для заявки ID {request_id}")
        return jsonify({"status": "success", "filename": filename})
    
    return jsonify({"error": "Invalid file type"}), 400

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'pdf', 'png', 'jpg', 'jpeg'}

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/trader/notifications')
def trader_notifications():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    unread_only = request.args.get('unread_only', 'false') == 'true'
    
    query = "SELECT id, type, message, is_read, timestamp FROM notifications WHERE user_id = ?"
    params = [user_id]
    
    if unread_only:
        query += " AND is_read = 0"
    
    query += " ORDER BY timestamp DESC LIMIT 50"
    
    notifications = db.fetch_all(query, params)
    return jsonify([dict(zip(
        ['id', 'type', 'message', 'is_read', 'timestamp'],
        n
    )) for n in notifications])

@app.route('/api/trader/mark_notification_read/<int:notification_id>', methods=['POST'])
def trader_mark_notification_read(notification_id):
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    
    db.execute(
        "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
        (notification_id, user_id)
    )
    
    return jsonify({"status": "success"})

@app.route('/api/trader/update_settings', methods=['POST'])
def trader_update_settings():
    if 'user_id' not in session or session.get('role') != 'trader':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    data = request.json
    
    # Получаем текущие настройки
    current_settings = db.fetch_one(
        "SELECT settings FROM users WHERE id = ?",
        (user_id,)
    )
    settings = json.loads(current_settings[0]) if current_settings and current_settings[0] else {}
    
    # Обновляем настройки
    for key, value in data.items():
        settings[key] = value
    
    db.execute(
        "UPDATE users SET settings = ? WHERE id = ?",
        (json.dumps(settings), user_id)
    )
    
    log_activity(user_id, 'settings_update', "Обновление настроек трейдера")
    return jsonify({"status": "success", "settings": settings})

# =============================================
# Панель мерчанта
# =============================================
@app.route('/merchant')
def merchant_panel():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    balance = get_user_balance(user_id)
    rate = get_current_rate()
    
    # Последние транзакции
    transactions = db.fetch_all(
        """
        SELECT t.id, t.type, t.amount, t.currency, t.status, t.timestamp, t.details
        FROM transactions t
        WHERE t.user_id = ? OR t.merchant_id = ?
        ORDER BY t.timestamp DESC
        LIMIT 10
        """,
        (user_id, user_id)
    )
    
    # Последние заявки
    requests = db.fetch_all(
        """
        SELECT r.id, r.type, r.amount, r.currency, r.status, r.timestamp, 
               t.username as trader, r.details
        FROM requests r
        LEFT JOIN users t ON r.trader_id = t.id
        WHERE r.merchant_id = ?
        ORDER BY r.timestamp DESC
        LIMIT 10
        """,
        (user_id,)
    )
    
    # Статистика мерчанта
    stats = {
        "today_volume": db.fetch_one(
            """
            SELECT SUM(amount) 
            FROM transactions 
            WHERE (user_id = ? OR merchant_id = ?) 
              AND date(timestamp) = date('now')
            """,
            (user_id, user_id)
        )[0] or 0,
        "total_volume": db.fetch_one(
            """
            SELECT SUM(amount) 
            FROM transactions 
            WHERE user_id = ? OR merchant_id = ?
            """,
            (user_id, user_id)
        )[0] or 0,
        "conversion_rate": db.fetch_one(
            """
            SELECT 
                CASE WHEN COUNT(*) > 0 
                     THEN ROUND(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2)
                     ELSE 0 END
            FROM requests
            WHERE merchant_id = ?
            """,
            (user_id,)
        )[0] or 0,
        "active_requests": db.fetch_one(
            "SELECT COUNT(*) FROM requests WHERE merchant_id = ? AND status = 'pending'",
            (user_id,)
        )[0] or 0
    }
    
    # Настройки мерчанта
    merchant_settings = db.fetch_one(
        "SELECT settings FROM users WHERE id = ?",
        (user_id,)
    )
    settings = json.loads(merchant_settings[0]) if merchant_settings and merchant_settings[0] else {}
    
    log_activity(user_id, 'merchant_panel_view', "Просмотр панели мерчанта")
    return render_template(
        'merchant.html',
        balance=balance,
        rate=rate,
        transactions=transactions,
        requests=requests,
        stats=stats,
        settings=settings
    )

# API для панели мерчанта
@app.route('/api/merchant/transactions')
def merchant_transactions():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    page = int(request.args.get('page', 1))
    limit = 20
    offset = (page - 1) * limit
    
    transactions = db.fetch_all(
        """
        SELECT t.id, t.type, t.amount, t.currency, t.status, t.timestamp, t.details
        FROM transactions t
        WHERE t.user_id = ? OR t.merchant_id = ?
        ORDER BY t.timestamp DESC
        LIMIT ? OFFSET ?
        """,
        (user_id, user_id, limit, offset)
    )
    
    return jsonify([dict(zip(
        ['id', 'type', 'amount', 'currency', 'status', 'timestamp', 'details'],
        [*t[:6], json.loads(t[6]) if t[6] else {}]
    )) for t in transactions])

@app.route('/api/merchant/requests')
def merchant_requests():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    status = request.args.get('status')
    
    query = """
        SELECT r.id, r.type, r.amount, r.currency, r.status, r.timestamp, 
               t.username as trader, r.details
        FROM requests r
        LEFT JOIN users t ON r.trader_id = t.id
        WHERE r.merchant_id = ?
    """
    params = [user_id]
    
    if status in ['pending', 'processing', 'completed', 'disputed']:
        query += " AND r.status = ?"
        params.append(status)
    
    query += " ORDER BY r.timestamp DESC LIMIT 50"
    
    requests = db.fetch_all(query, params)
    return jsonify([dict(zip(
        ['id', 'type', 'amount', 'currency', 'status', 'timestamp', 'trader', 'details'],
        [*r[:7], json.loads(r[7]) if r[7] else {}]
    )) for r in requests])

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
    
    # В реальной системе здесь будет логика выбора трейдера по приоритетам
    # В этой упрощенной версии выбираем случайного активного трейдера
    trader = db.fetch_one(
        """
        SELECT u.id, json_extract(u.settings, '$.rate_in') as rate_in, 
               json_extract(u.settings, '$.rate_out') as rate_out
        FROM users u
        WHERE u.role = 'trader' AND u.status = 'active'
        ORDER BY RANDOM()
        LIMIT 1
        """,
    )
    
    if not trader:
        return jsonify({"error": "No available traders"}), 400
    
    trader_id = trader[0]
    trader_rate = float(trader[1] if payment_type == 'in' else trader[2])
    
    # Создаем заявку
    request_id = db.execute(
        """
        INSERT INTO requests 
        (type, amount, currency, user_id, trader_id, merchant_id, status, expiry_time, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payment_type,
            amount,
            currency,
            user_id,
            trader_id,
            user_id,
            "pending",
            (datetime.now() + timedelta(minutes=15)).isoformat(),
            json.dumps({
                "trader_rate": trader_rate,
                "merchant_id": user_id,
                "created_at": datetime.now().isoformat()
            })
        )
    ).lastrowid
    
    # Отправляем уведомление трейдеру
    send_notification(
        trader_id,
        'request',
        f"Новая заявка #{request_id} на сумму {amount} {currency}"
    )
    
    log_activity(user_id, 'payment_request_create', f"Создание заявки ID {request_id}")
    return jsonify({
        "status": "success",
        "request_id": request_id,
        "trader_id": trader_id,
        "expiry_time": (datetime.now() + timedelta(minutes=15)).isoformat()
    })

@app.route('/api/merchant/disputes')
def merchant_disputes():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    
    disputes = db.fetch_all(
        """
        SELECT d.id, d.status, d.timestamp, r.amount, r.currency, 
               t.username as trader, d.details
        FROM disputes d
        JOIN requests r ON d.request_id = r.id
        LEFT JOIN users t ON r.trader_id = t.id
        WHERE r.merchant_id = ?
        ORDER BY d.timestamp DESC
        """,
        (user_id,)
    )
    
    return jsonify([dict(zip(
        ['id', 'status', 'timestamp', 'amount', 'currency', 'trader', 'details'],
        [*d[:6], json.loads(d[6]) if d[6] else {}]
    )) for d in disputes])

@app.route('/api/merchant/update_settings', methods=['POST'])
def merchant_update_settings():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    data = request.json
    
    # Получаем текущие настройки
    current_settings = db.fetch_one(
        "SELECT settings FROM users WHERE id = ?",
        (user_id,)
    )
    settings = json.loads(current_settings[0]) if current_settings and current_settings[0] else {}
    
    # Обновляем настройки
    for key, value in data.items():
        settings[key] = value
    
    db.execute(
        "UPDATE users SET settings = ? WHERE id = ?",
        (json.dumps(settings), user_id)
    )
    
    log_activity(user_id, 'settings_update', "Обновление настроек мерчанта")
    return jsonify({"status": "success", "settings": settings})

@app.route('/api/merchant/notifications')
def merchant_notifications():
    if 'user_id' not in session or session.get('role') != 'merchant':
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    unread_only = request.args.get('unread_only', 'false') == 'true'
    
    query = "SELECT id, type, message, is_read, timestamp FROM notifications WHERE user_id = ?"
    params = [user_id]
    
    if unread_only:
        query += " AND is_read = 0"
    
    query += " ORDER BY timestamp DESC LIMIT 50"
    
    notifications = db.fetch_all(query, params)
    return jsonify([dict(zip(
        ['id', 'type', 'message', 'is_read', 'timestamp'],
        n
    )) for n in notifications])

# =============================================
# Общие API для всех пользователей
# =============================================
@app.route('/api/current_user')
def current_user():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    user = db.fetch_one(
        "SELECT id, username, role, contact_info, settings FROM users WHERE id = ?",
        (user_id,)
    )
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "id": user[0],
        "username": user[1],
        "role": user[2],
        "contact_info": user[3],
        "settings": json.loads(user[4]) if user[4] else {}
    })

@app.route('/api/activity_log')
def user_activity_log():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    limit = int(request.args.get('limit', 50))
    
    activities = db.fetch_all(
        "SELECT action, details, timestamp FROM activity_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
        (user_id, limit)
    )
    
    return jsonify([dict(zip(
        ['action', 'details', 'timestamp'],
        a
    )) for a in activities])

# =============================================
# Запуск приложения
# =============================================
if __name__ == '__main__':
    # Инициализация тестовых данных при первом запуске
    if not db.fetch_one("SELECT 1 FROM users LIMIT 1"):
        init_test_data()
        print("Initial test data created")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
