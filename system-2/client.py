import requests
import socket
import json

# 假设服务器地址
SERVER_URL = "http://localhost:5000"

def get_license_key(hardware_id):
    """
    根据硬件ID从服务器获取授权码
    """
    data = {
        "username": "test_user",
        "software_name": "test_software",
        "hardware_id": hardware_id,
        "expiry_days": 365
    }
    response = requests.post(f"{SERVER_URL}/api/licenses", json=data)
    if response.status_code == 201:
        return response.json().get("license_key")
    else:
        print(f"获取授权码失败: {response.json().get('error')}")
        return None

def validate_license(license_key, hardware_id):
    """
    验证授权码是否有效
    """
    data = {
        "license_key": license_key,
        "hardware_id": hardware_id
    }
    response = requests.post(f"{SERVER_URL}/api/validate", json=data)
    return response.json()

def main():
    # 获取硬件ID，这里简单使用主机名作为示例
    hardware_id = socket.gethostname()
    license_key = get_license_key(hardware_id)
    if license_key:
        result = validate_license(license_key, hardware_id)
        if result.get("valid"):
            print("授权码验证成功，可以激活软件。")
        else:
            print(f"授权码验证失败: {result.get('error')}")

if __name__ == "__main__":
    main()