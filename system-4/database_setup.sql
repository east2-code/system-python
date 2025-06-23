CREATE DATABASE license_manager;
CREATE USER 'system-text'@'localhost' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON license_manager.* TO 'system-text'@'localhost';
FLUSH PRIVILEGES;

USE license_manager;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120),
    company VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE software (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    version VARCHAR(50) NOT NULL
);

-- 修改 hardware_id 字段为 TEXT 类型
CREATE TABLE licenses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    software_id INT NOT NULL,
    hardware_id TEXT NOT NULL,  -- 改为 TEXT 类型
    session_id TEXT,
    license_key VARCHAR(100) NOT NULL UNIQUE,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE
);

CREATE TABLE license_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    license_id INT NOT NULL,
    action VARCHAR(50) NOT NULL,
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT,
    FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
);

-- 添加默认软件记录（3个示例软件）
INSERT INTO software (name, version) VALUES
('数据分析工具', '1.2.3'),
('图像编辑软件', '2.5.0'),
('文档管理系统', '3.1.1');