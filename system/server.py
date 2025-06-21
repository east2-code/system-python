import os
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import hashlib
from cryptography.fernet import Fernet
import logging
import socket

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://system-text:123456@localhost/license_manager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'
db = SQLAlchemy(app)

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('LicenseManager')

# 获取本机IP地址
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.error(f"无法获取IP地址: {str(e)}")
        return "localhost"

# 加密密钥 - 在实际生产环境中应安全存储
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)
logger.info(f"Generated encryption key: {ENCRYPTION_KEY.decode()}")
logger.info(f"服务器IP: {get_local_ip()}")

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

# 加密函数
def encrypt_data(data):
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise

def decrypt_data(encrypted_data):
    try:
        decrypted = cipher_suite.decrypt(encrypted_data.encode())
        return decrypted.decode('utf-8')  # 确保使用UTF-8解码
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return "DECRYPTION_ERROR"

# 生成唯一授权码
def generate_license_key(user_id, hardware_id):
    unique_str = f"{user_id}-{hardware_id}-{datetime.utcnow().timestamp()}"
    return hashlib.sha256(unique_str.encode()).hexdigest()[:20].upper()

# 记录历史
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

# API端点
@app.route('/api/licenses', methods=['POST'])
def create_license():
    try:
        data = request.json
        logger.info(f"Creating license for user: {data.get('username')}, software: {data.get('software_name')}")
        
        # 检查必要字段
        if not data.get('username') or not data.get('software_name') or not data.get('hardware_id'):
            return jsonify({'error': '缺少必要字段: 用户名、软件名或硬件ID'}), 400
        
        user = User.query.filter_by(username=data['username']).first()
        if not user:
            logger.info(f"Creating new user: {data['username']}")
            user = User(
                username=data['username'], 
                email=data.get('email'),
                company=data.get('company')
            )
            db.session.add(user)
            db.session.commit()
        
        software = Software.query.filter_by(name=data['software_name']).first()
        if not software:
            logger.warning(f"Software not found: {data['software_name']}")
            return jsonify({'error': '软件不存在，请联系管理员添加'}), 404
        
        # 设置有效期
        expires_days = int(data.get('expiry_days', 365))  # 默认1年
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        # 加密硬件ID
        logger.info(f"Encrypting hardware ID: {data['hardware_id']}")
        encrypted_hw_id = encrypt_data(data['hardware_id'])
        
        # 生成授权码
        license_key = generate_license_key(user.id, data['hardware_id'])
        logger.info(f"Generated license key: {license_key}")
        
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
        log_license_action(new_license.id, "CREATED", 
                          f"为 {user.username} 生成 {software.name} 授权")
        
        return jsonify({
            'license_key': new_license.license_key,
            'expires_at': new_license.expires_at.isoformat(),
            'license_id': new_license.id,
            'server_ip': get_local_ip()  # 返回服务器IP给客户端
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating license: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误', 'details': str(e)}), 500

@app.route('/api/licenses/<username>', methods=['GET'])
def get_user_licenses(username):
    try:
        logger.info(f"Fetching licenses for user: {username}")
        user = User.query.filter_by(username=username).first()
        if not user:
            logger.warning(f"User not found: {username}")
            return jsonify({'error': '用户不存在'}), 404
        
        licenses = []
        for license in user.licenses:
            # 解密硬件ID
            try:
                decrypted_hw_id = decrypt_data(license.hardware_id)
            except:
                decrypted_hw_id = "解密失败"
            
            # 计算剩余天数（修复时区问题）
            now = datetime.utcnow()
            days_remaining = (license.expires_at - now).days
            if (license.expires_at - now).seconds > 0:
                days_remaining += 1
            
            licenses.append({
                'id': license.id,
                'software': license.software.name,
                'version': license.software.version,
                'hardware_id': decrypted_hw_id,
                'session_id': license.session_id,
                'license_key': license.license_key,
                'generated_at': license.generated_at.isoformat(),
                'expires_at': license.expires_at.isoformat(),
                'is_active': license.is_active,
                'days_remaining': days_remaining
            })
        
        logger.info(f"Found {len(licenses)} licenses for user: {username}")
        return jsonify({'username': user.username, 'licenses': licenses})
    
    except Exception as e:
        logger.error(f"Error fetching user licenses: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

# 获取所有授权记录
@app.route('/api/all-licenses', methods=['GET'])
def get_all_licenses():
    try:
        logger.info("Fetching all licenses")
        # 获取最近的100条授权记录
        licenses = License.query.order_by(License.generated_at.desc()).limit(100).all()
        
        result = []
        for license in licenses:
            # 解密硬件ID
            try:
                decrypted_hw_id = decrypt_data(license.hardware_id)
            except:
                decrypted_hw_id = "解密失败"
            
            # 计算剩余天数（修复时区问题）
            now = datetime.utcnow()
            days_remaining = (license.expires_at - now).days
            if (license.expires_at - now).seconds > 0:
                days_remaining += 1
            
            result.append({
                'id': license.id,
                'username': license.user.username,
                'software': license.software.name,
                'version': license.software.version,
                'hardware_id': decrypted_hw_id,
                'session_id': license.session_id,
                'license_key': license.license_key,
                'generated_at': license.generated_at.isoformat(),
                'expires_at': license.expires_at.isoformat(),
                'is_active': license.is_active,
                'days_remaining': days_remaining
            })
        
        logger.info(f"Found {len(result)} licenses")
        return jsonify({'licenses': result})
    
    except Exception as e:
        logger.error(f"Error fetching all licenses: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/licenses/renew/<int:license_id>', methods=['PUT'])
def renew_license(license_id):
    try:
        logger.info(f"Renewing license: {license_id}")
        license = License.query.get(license_id)
        if not license:
            logger.warning(f"License not found: {license_id}")
            return jsonify({'error': '授权不存在'}), 404
        
        # 禁用旧许可证
        license.is_active = False
        
        # 创建新许可证
        expires_days = int(request.json.get('expiry_days', 365))
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        # 生成新授权码
        new_license_key = generate_license_key(license.user_id, license.hardware_id)
        logger.info(f"Generated new license key: {new_license_key}")
        
        new_license = License(
            user_id=license.user_id,
            software_id=license.software_id,
            hardware_id=license.hardware_id,
            session_id=license.session_id,
            license_key=new_license_key,
            expires_at=expires_at
        )
        
        db.session.add(new_license)
        db.session.commit()
        
        logger.info(f"License renewed: old={license_id}, new={new_license.id}")
        log_license_action(license.id, "RENEWED", 
                          f"生成新授权码: {new_license.license_key}")
        
        return jsonify({
            'new_license_key': new_license.license_key,
            'expires_at': new_license.expires_at.isoformat()
        })
    
    except Exception as e:
        logger.error(f"Error renewing license: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/licenses/deactivate/<int:license_id>', methods=['PUT'])
def deactivate_license(license_id):
    try:
        logger.info(f"Deactivating license: {license_id}")
        license = License.query.get(license_id)
        if not license:
            logger.warning(f"License not found: {license_id}")
            return jsonify({'error': '授权不存在'}), 404
        
        license.is_active = False
        db.session.commit()
        
        logger.info(f"License deactivated: {license_id}")
        log_license_action(license.id, "DEACTIVATED", "手动停用授权")
        
        return jsonify({'message': '授权已停用'})
    
    except Exception as e:
        logger.error(f"Error deactivating license: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500

# 删除授权
@app.route('/api/licenses/<int:license_id>', methods=['DELETE'])
def delete_license(license_id):
    try:
        logger.info(f"Deleting license: {license_id}")
        license = License.query.get(license_id)
        if not license:
            logger.warning(f"License not found: {license_id}")
            return jsonify({'error': '授权不存在'}), 404
        
        # 删除关联的历史记录
        LicenseHistory.query.filter_by(license_id=license_id).delete()
        
        # 删除授权
        db.session.delete(license)
        db.session.commit()
        
        logger.info(f"License deleted: {license_id}")
        return jsonify({'message': '授权已删除'})
    
    except Exception as e:
        logger.error(f"Error deleting license: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/licenses/history/<int:license_id>', methods=['GET'])
def get_license_history(license_id):
    try:
        logger.info(f"Fetching history for license: {license_id}")
        history = LicenseHistory.query.filter_by(license_id=license_id).order_by(LicenseHistory.performed_at.desc()).all()
        
        history_list = []
        for record in history:
            history_list.append({
                'action': record.action,
                'performed_at': record.performed_at.isoformat(),
                'details': record.details
            })
        
        logger.info(f"Found {len(history_list)} history records for license: {license_id}")
        return jsonify({'history': history_list})
    
    except Exception as e:
        logger.error(f"Error fetching license history: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/validate', methods=['POST'])
def validate_license():
    try:
        data = request.json
        logger.info(f"Validating license: {data.get('license_key')}")
        license = License.query.filter_by(license_key=data['license_key']).first()
        
        if not license:
            logger.warning(f"Invalid license key: {data.get('license_key')}")
            return jsonify({'valid': False, 'error': '无效的授权码'}), 404
        
        # 验证硬件ID
        try:
            decrypted_hw_id = decrypt_data(license.hardware_id)
            if decrypted_hw_id != data['hardware_id']:
                logger.warning(f"Hardware mismatch for license: {license.id}")
                return jsonify({'valid': False, 'error': '硬件ID不匹配'}), 403
        except:
            logger.error(f"Decryption error for license: {license.id}")
            return jsonify({'valid': False, 'error': '解密失败'}), 500
        
        if not license.is_active:
            logger.warning(f"License deactivated: {license.id}")
            return jsonify({'valid': False, 'error': '授权已停用'}), 403
        
        # 使用UTC时间比较
        current_utc = datetime.utcnow()
        if current_utc > license.expires_at:
            logger.warning(f"License expired: {license.id}")
            return jsonify({'valid': False, 'error': '授权已过期'}), 403
        
        logger.info(f"License valid: {license.id}")
        return jsonify({
            'valid': True,
            'expires_at': license.expires_at.isoformat() + 'Z',  # 标记为UTC时间
            'username': license.user.username,
            'software': license.software.name
        })
    
    except Exception as e:
        logger.error(f"Error validating license: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/software', methods=['GET'])
def get_software_list():
    try:
        logger.info("Fetching software list")
        software = Software.query.all()
        software_list = [{'id': sw.id, 'name': sw.name, 'version': sw.version} for sw in software]
        logger.info(f"Found {len(software_list)} software items")
        return jsonify({'software': software_list})
    
    except Exception as e:
        logger.error(f"Error fetching software list: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/software', methods=['POST'])
def create_software():
    try:
        data = request.json
        logger.info(f"Creating software: {data.get('name')} v{data.get('version')}")
        if not data.get('name') or not data.get('version'):
            logger.warning("Software creation failed: missing name or version")
            return jsonify({'error': '软件名称和版本不能为空'}), 400
        
        # 检查软件是否已存在
        existing = Software.query.filter_by(name=data['name']).first()
        if existing:
            logger.warning(f"Software already exists: {data['name']}")
            return jsonify({'error': '软件名称已存在'}), 400
        
        new_software = Software(
            name=data['name'],
            version=data['version']
        )
        
        db.session.add(new_software)
        db.session.commit()
        logger.info(f"Software created: ID={new_software.id}")
        
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
        logger.info(f"Deleting software: {software_id}")
        software = Software.query.get(software_id)
        if not software:
            logger.warning(f"Software not found: {software_id}")
            return jsonify({'error': '软件不存在'}), 404
        
        # 检查是否有授权关联
        licenses = License.query.filter_by(software_id=software_id).count()
        if licenses > 0:
            logger.warning(f"Cannot delete software: {licenses} licenses associated")
            return jsonify({'error': '存在关联授权，无法删除'}), 400
        
        db.session.delete(software)
        db.session.commit()
        logger.info(f"Software deleted: ID={software_id}")
        
        return jsonify({'message': '软件已删除'})
    
    except Exception as e:
        logger.error(f"Error deleting software: {str(e)}")
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/license-detail/<int:license_id>', methods=['GET'])
def get_license_detail(license_id):
    try:
        logger.info(f"Fetching license detail: {license_id}")
        license = License.query.get(license_id)
        if not license:
            logger.warning(f"License not found: {license_id}")
            return jsonify({'error': '授权不存在'}), 404
        
        try:
            decrypted_hw_id = decrypt_data(license.hardware_id)
        except:
            decrypted_hw_id = "解密失败"
        
        logger.info(f"License detail retrieved: {license_id}")
        return jsonify({
            'id': license.id,
            'user': {
                'username': license.user.username,
                'email': license.user.email,
                'company': license.user.company
            },
            'software': {
                'name': license.software.name,
                'version': license.software.version
            },
            'hardware_id': decrypted_hw_id,
            'session_id': license.session_id,
            'license_key': license.license_key,
            'generated_at': license.generated_at.isoformat(),
            'expires_at': license.expires_at.isoformat(),
            'is_active': license.is_active
        })
    
    except Exception as e:
        logger.error(f"Error fetching license detail: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/license-by-key/<license_key>', methods=['GET'])
def get_license_by_key(license_key):
    try:
        logger.info(f"Fetching license by key: {license_key}")
        license = License.query.filter_by(license_key=license_key).first()
        if not license:
            logger.warning(f"License not found by key: {license_key}")
            return jsonify({'error': '授权不存在'}), 404
        
        try:
            decrypted_hw_id = decrypt_data(license.hardware_id)
        except:
            decrypted_hw_id = "解密失败"
        
        logger.info(f"License found by key: {license.id}")
        return jsonify({
            'id': license.id,
            'user': {
                'username': license.user.username,
                'email': license.user.email,
                'company': license.user.company
            },
            'software': {
                'name': license.software.name,
                'version': license.software.version
            },
            'hardware_id': decrypted_hw_id,
            'session_id': license.session_id,
            'license_key': license.license_key,
            'generated_at': license.generated_at.isoformat(),
            'expires_at': license.expires_at.isoformat(),
            'is_active': license.is_active
        })
    
    except Exception as e:
        logger.error(f"Error fetching license by key: {str(e)}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/server-info', methods=['GET'])
def get_server_info():
    return jsonify({
        'ip': get_local_ip(),
        'port': 5000
    })

@app.route('/', methods=['GET'])
def index():
    return render_template('admin.html')

if __name__ == '__main__':
    logger.info("Starting license manager server")
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created/updated")
            
            # 添加默认软件（如果不存在）
            default_software = [
                {'name': '数据分析工具', 'version': '1.2.3'},
                {'name': '图像编辑软件', 'version': '2.5.0'},
                {'name': '文档管理系统', 'version': '3.1.1'}
            ]
            
            for sw in default_software:
                if not Software.query.filter_by(name=sw['name']).first():
                    new_sw = Software(name=sw['name'], version=sw['version'])
                    db.session.add(new_sw)
                    logger.info(f"Added default software: {sw['name']}")
            
            db.session.commit()
            
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")
    
    # 获取本机IP并打印
    server_ip = get_local_ip()
    logger.info(f"服务器运行在: http://{server_ip}:5000")
    logger.info(f"管理界面: http://{server_ip}:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)