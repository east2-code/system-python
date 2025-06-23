import os
import socket
import threading
import logging
import uuid
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import webbrowser
import pytz

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://system-text:123456@localhost/license_manager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24).hex()

db = SQLAlchemy(app)

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("license_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('LicenseManager')

FERNET_KEY_FILE = 'fernet.key'
if os.path.exists(FERNET_KEY_FILE):
    with open(FERNET_KEY_FILE, 'rb') as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(FERNET_KEY_FILE, 'wb') as f:
        f.write(ENCRYPTION_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY)
logger.info("Using encryption key from file.")

CHINA_TZ = pytz.timezone("Asia/Shanghai")
UTC = pytz.utc

def to_china(dt):
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = UTC.localize(dt)
    return dt.astimezone(CHINA_TZ).strftime('%Y-%m-%d %H:%M:%S')

# 登录信息（只允许一个管理员）
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # 请自行修改为安全密码！

# 数据库模型
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120))
    company = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Software(db.Model):
    __tablename__ = 'software'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    version = db.Column(db.String(50), nullable=False)

class License(db.Model):
    __tablename__ = 'licenses'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    software_id = db.Column(db.Integer, db.ForeignKey('software.id'), nullable=False)
    hardware_id = db.Column(db.Text, nullable=False)
    session_id = db.Column(db.Text)
    license_key = db.Column(db.String(100), unique=True, nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    user = db.relationship('User', backref='licenses')
    software = db.relationship('Software', backref='licenses')

class LicenseHistory(db.Model):
    __tablename__ = 'license_history'
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey('licenses.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

# 辅助函数
def encrypt_data(data):
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise

def decrypt_data(encrypted_data):
    try:
        decrypted = cipher_suite.decrypt(encrypted_data.encode())
        return decrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return "DECRYPTION_ERROR"

def generate_license_key(user_id, hardware_id):
    unique_str = f"{user_id}-{hardware_id}-{datetime.utcnow().timestamp()}"
    return hashlib.sha256(unique_str.encode()).hexdigest()[:20].upper()

def log_license_action(license_id, action, details=""):
    try:
        history = LicenseHistory(
            license_id=license_id,
            action=action,
            details=details
        )
        db.session.add(history)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log history: {str(e)}")
        db.session.rollback()

# 登录相关
@app.before_request
def require_login():
    if request.path.startswith('/static/'):
        return
    if request.path.startswith('/api/'):
        return
    if request.endpoint in ['login', 'logout']:
        return
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("logged_in"):
            return redirect(url_for("index"))
        return render_template("login.html")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['logged_in'] = True
        session['username'] = ADMIN_USERNAME
        return redirect(url_for("index"))
    else:
        flash("用户名或密码错误", "danger")
        return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))

# API 路由（和你原来一样，全部保留）
@app.route('/api/licenses', methods=['POST'])
def create_license():
    try:
        data = request.get_json()
        logger.info(f"Creating license for user: {data.get('username')}, software: {data.get('software_name')}")
        required_fields = ['username', 'software_name', 'hardware_id']
        if not all(data.get(field) for field in required_fields):
            return jsonify({'error': '缺少必要字段: 用户名、软件名或硬件ID'}), 400
        user = User.query.filter_by(username=data['username']).first()
        if not user:
            user = User(
                username=data['username'],
                email=data.get('email'),
                company=data.get('company')
            )
            db.session.add(user)
            db.session.commit()
        software = Software.query.filter_by(name=data['software_name']).first()
        if not software:
            return jsonify({'error': '软件不存在，请联系管理员添加'}), 404
        expires_days = int(data.get('expiry_days', 365))
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        encrypted_hw_id = encrypt_data(data['hardware_id'])
        license_key = generate_license_key(user.id, data['hardware_id'])
        new_license = License(
            user_id=user.id,
            software_id=software.id,
            hardware_id=encrypted_hw_id,
            session_id=data.get('session_id'),
            license_key=license_key,
            expires_at=expires_at
        )
        db.session.add(new_license)
        db.session.commit()
        logger.info(f"License created successfully: ID={new_license.id}")
        log_license_action(new_license.id, "CREATED", f"为 {user.username} 生成 {software.name} 授权")
        return jsonify({
            'license_key': new_license.license_key,
            'expires_at': to_china(new_license.expires_at),
            'license_id': new_license.id,
            'generated_at': to_china(new_license.generated_at),
            'server_ip': socket.gethostbyname(socket.gethostname())
        }), 201
    except Exception as e:
        logger.error(f"Error creating license: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误', 'details': str(e)}), 500

@app.route('/api/licenses/renew/<int:license_id>', methods=['PUT'])
def renew_license(license_id):
    try:
        logger.info(f"Renewing license: {license_id}")
        license = License.query.get(license_id)
        if not license:
            return jsonify({'error': '授权不存在'}), 404
        expires_days = int(request.json.get('expiry_days', 365))
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        decrypted_hw_id = decrypt_data(license.hardware_id)
        new_license_key = generate_license_key(license.user_id, decrypted_hw_id)
        new_license = License(
            user_id=license.user_id,
            software_id=license.software_id,
            hardware_id=license.hardware_id,
            session_id=license.session_id,
            license_key=new_license_key,
            expires_at=expires_at
        )
        license.is_active = False
        db.session.add(new_license)
        db.session.commit()
        logger.info(f"License renewed: old={license_id}, new={new_license.id}")
        log_license_action(license.id, "RENEWED", f"生成新授权码: {new_license.license_key}")
        return jsonify({
            'new_license_key': new_license.license_key,
            'expires_at': to_china(new_license.expires_at),
            'generated_at': to_china(new_license.generated_at)
        })
    except Exception as e:
        logger.error(f"Error renewing license: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/licenses/deactivate/<int:license_id>', methods=['PUT'])
def deactivate_license(license_id):
    try:
        license = License.query.get(license_id)
        if not license:
            return jsonify({'error': '授权不存在'}), 404
        license.is_active = False
        db.session.commit()
        log_license_action(license.id, "DEACTIVATED", "手动停用授权")
        return jsonify({'message': '授权已停用'})
    except Exception as e:
        logger.error(f"Error deactivating license: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/licenses/<int:license_id>', methods=['DELETE'])
def delete_license(license_id):
    try:
        license = License.query.get(license_id)
        if not license:
            return jsonify({'error': '授权不存在'}), 404
        LicenseHistory.query.filter_by(license_id=license_id).delete()
        db.session.delete(license)
        db.session.commit()
        return jsonify({'message': '授权已删除'})
    except Exception as e:
        logger.error(f"Error deleting license: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/licenses/history/<int:license_id>', methods=['GET'])
def get_license_history(license_id):
    try:
        history = LicenseHistory.query.filter_by(license_id=license_id).order_by(LicenseHistory.performed_at.desc()).all()
        return jsonify({
            'history': [{
                'action': record.action,
                'performed_at': to_china(record.performed_at),
                'details': record.details
            } for record in history]
        })
    except Exception as e:
        logger.error(f"Error fetching license history: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/licenses/<username>', methods=['GET'])
def get_user_licenses(username):
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': '用户不存在'}), 404
        licenses = []
        for license in user.licenses:
            try:
                decrypted_hw_id = decrypt_data(license.hardware_id)
            except:
                decrypted_hw_id = "解密失败"
            now = datetime.utcnow()
            time_diff = license.expires_at - now
            days_remaining = time_diff.days
            if time_diff.seconds > 0:
                days_remaining += 1
            licenses.append({
                'id': license.id,
                'software': license.software.name,
                'version': license.software.version,
                'hardware_id': decrypted_hw_id,
                'session_id': license.session_id,
                'license_key': license.license_key,
                'generated_at': to_china(license.generated_at),
                'expires_at': to_china(license.expires_at),
                'is_active': license.is_active,
                'days_remaining': max(0, days_remaining)
            })
        return jsonify({'username': user.username, 'licenses': licenses})
    except Exception as e:
        logger.error(f"Error fetching user licenses: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/all-licenses', methods=['GET'])
def get_all_licenses():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        licenses = License.query.order_by(License.generated_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False)
        result = []
        for license in licenses.items:
            try:
                decrypted_hw_id = decrypt_data(license.hardware_id)
            except:
                decrypted_hw_id = "解密失败"
            now = datetime.utcnow()
            time_diff = license.expires_at - now
            days_remaining = time_diff.days
            if time_diff.seconds > 0:
                days_remaining += 1
            result.append({
                'id': license.id,
                'username': license.user.username,
                'software': license.software.name,
                'version': license.software.version,
                'hardware_id': decrypted_hw_id,
                'session_id': license.session_id,
                'license_key': license.license_key,
                'generated_at': to_china(license.generated_at),
                'expires_at': to_china(license.expires_at),
                'is_active': license.is_active,
                'days_remaining': max(0, days_remaining)
            })
        return jsonify({
            'licenses': result,
            'page': page,
            'per_page': per_page,
            'total_pages': licenses.pages,
            'total_items': licenses.total
        })
    except Exception as e:
        logger.error(f"Error fetching all licenses: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/validate', methods=['POST'])
def validate_license():
    try:
        data = request.json
        license = License.query.filter_by(license_key=data['license_key']).first()
        if not license:
            return jsonify({'valid': False, 'error': '无效的授权码'}), 404
        try:
            decrypted_hw_id = decrypt_data(license.hardware_id)
            if decrypted_hw_id != data['hardware_id']:
                return jsonify({'valid': False, 'error': '硬件ID不匹配'}), 403
        except Exception as e:
            return jsonify({'valid': False, 'error': '解密失败'}), 500
        if not license.is_active:
            return jsonify({'valid': False, 'error': '授权已停用'}), 403
        if datetime.utcnow() > license.expires_at:
            return jsonify({'valid': False, 'error': '授权已过期'}), 403
        return jsonify({
            'valid': True,
            'expires_at': to_china(license.expires_at),
            'username': license.user.username,
            'software': license.software.name
        })
    except Exception as e:
        logger.error(f"Error validating license: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/server-info', methods=['GET'])
def get_server_info():
    return jsonify({
        'ip': socket.gethostbyname(socket.gethostname()),
        'port': 5000
    })

@app.route('/api/software', methods=['GET'])
def get_all_software():
    try:
        software_list = Software.query.all()
        return jsonify({
            'software': [{
                'id': sw.id,
                'name': sw.name,
                'version': sw.version
            } for sw in software_list]
        })
    except Exception as e:
        logger.error(f"Error fetching software: {str(e)}")
        return jsonify({'error': '服务器内部极错误'}), 500

@app.route('/api/software', methods=['POST'])
def create_software():
    try:
        data = request.get_json()
        if not data.get('name') or not data.get('version'):
            return jsonify({'error': '缺少软件名称或版本号'}), 400
        existing = Software.query.filter_by(name=data['name']).first()
        if existing:
            return jsonify({'error': '软件名称已存在'}), 400
        new_software = Software(
            name=data['name'],
            version=data['version']
        )
        db.session.add(new_software)
        db.session.commit()
        return jsonify({
            'id': new_software.id,
            'name': new_software.name,
            'version': new_software.version
        }), 201
    except Exception as e:
        logger.error(f"Error creating software: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/software/<int:software_id>', methods=['DELETE'])
def delete_software(software_id):
    try:
        software = Software.query.get(software_id)
        if not software:
            return jsonify({'error': '软件不存在'}), 404
        licenses = License.query.filter_by(software_id=software_id).count()
        if licenses > 0:
            return jsonify({'error': '无法删除，该软件已有授权记录'}), 400
        db.session.delete(software)
        db.session.commit()
        return jsonify({'message': '软件已删除'})
    except Exception as e:
        logger.error(f"Error deleting software: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/license-detail/<int:license_id>', methods=['GET'])
def get_license_detail(license_id):
    try:
        license = License.query.get(license_id)
        if not license:
            return jsonify({'error': '授权不存在'}), 404
        try:
            decrypted_hw_id = decrypt_data(license.hardware_id)
        except:
            decrypted_hw_id = "解密失败"
        return jsonify({
            'id': license.id,
            'license_key': license.license_key,
            'generated_at': to_china(license.generated_at),
            'expires_at': to_china(license.expires_at),
            'is_active': license.is_active,
            'hardware_id': decrypted_hw_id,
            'session_id': license.session_id,
            'user': {
                'id': license.user.id,
                'username': license.user.username,
                'email': license.user.email,
                'company': license.user.company
            },
            'software': {
                'id': license.software.id,
                'name': license.software.name,
                'version': license.software.version
            }
        })
    except Exception as e:
        logger.error(f"Error fetching license detail: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/license-by-key/<license_key>', methods=['GET'])
def get_license_by_key(license_key):
    try:
        license = License.query.filter_by(license_key=license_key).first()
        if not license:
            return jsonify({'error': '授权不存在'}), 404
        try:
            decrypted_hw_id = decrypt_data(license.hardware_id)
        except:
            decrypted_hw_id = "解密失败"
        now = datetime.utcnow()
        time_diff = license.expires_at - now
        days_remaining = time_diff.days
        if time_diff.seconds > 0:
            days_remaining += 1
        return jsonify({
            'id': license.id,
            'username': license.user.username,
            'software': license.software.name,
            'version': license.software.version,
            'hardware_id': decrypted_hw_id,
            'session_id': license.session_id,
            'license_key': license.license_key,
            'generated_at': to_china(license.generated_at),
            'expires_at': to_china(license.expires_at),
            'is_active': license.is_active,
            'days_remaining': max(0, days_remaining)
        })
    except Exception as e:
        logger.error(f"Error fetching license by key: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/', methods=['GET'])
def index():
    return render_template('admin.html', admin_username=session.get("username", "管理员"))

def open_browser():
    webbrowser.open("http://localhost:5000")

if __name__ == '__main__':
    logger.info("Starting license manager server")
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created/updated")
            default_software = [
                {'name': '数据分析工具', 'version': '1.2.3'},
                {'name': '图像编辑软件', 'version': '2.5.0'},
                {'name': '文档管理系统', 'version': '3.1.1'}
            ]
            for sw in default_software:
                if not Software.query.filter_by(name=sw['name']).first():
                    new_sw = Software(name=sw['name'], version=sw['version'])
                    db.session.add(new_sw)
            db.session.commit()
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")
    try:
        if not os.environ.get("WERKZEUG_RUN_MAIN") == "true":
            threading.Timer(1.5, open_browser).start()
    except Exception as e:
        logger.error(f"Failed to open browser: {str(e)}")
    app.run(debug=True, host='0.0.0.0', port=5000)