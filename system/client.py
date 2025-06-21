import requests
import hashlib
import uuid
import psutil
import json
from datetime import datetime
import socket
import re
import os
import sys
import time

def get_hardware_id():
    """生成基于硬件的唯一ID"""
    identifiers = []
    
    # CPU信息
    try:
        cpu_info = psutil.cpu_freq()
        if cpu_info:
            identifiers.append(str(cpu_info.current))
    except:
        pass
    
    # 磁盘信息
    try:
        disk_info = psutil.disk_partitions()
        if disk_info:
            identifiers.append(disk_info[0].device)
    except:
        pass
    
    # MAC地址
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                       for elements in range(0,8*6,8)][::-1])
        identifiers.append(mac)
    except:
        pass
    
    # 使用所有可用标识符生成哈希
    combined = "-".join(identifiers)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]

def get_server_info():
    """尝试获取服务器信息"""
    # 默认服务器地址
    default_server = "http://localhost:5000"
    
    # 尝试从配置文件获取
    try:
        with open('server_config.json', 'r') as f:
            config = json.load(f)
            return config.get('server_url', default_server)
    except:
        pass
    
    # 尝试自动发现服务器
    try:
        # 获取本机IP地址
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # 尝试常见端口
        ports = [5000, 8000, 8080]
        for port in ports:
            url = f"http://{local_ip}:{port}/api/server-info"
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    return f"http://{local_ip}:{port}"
            except:
                continue
    except:
        pass
    
    return default_server

def validate_license(license_key, server_url=None):
    hardware_id = get_hardware_id()
    
    # 如果没有提供服务器URL，尝试获取
    if not server_url:
        server_url = get_server_info()
    
    # 确保URL格式正确
    if not server_url.startswith("http://") and not server_url.startswith("https://"):
        server_url = "http://" + server_url
    if server_url.endswith("/"):
        server_url = server_url[:-1]
    
    validate_url = f"{server_url}/api/validate"
    
    try:
        response = requests.post(
            validate_url,
            json={'license_key': license_key, 'hardware_id': hardware_id},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return True, data, server_url
        else:
            try:
                error_data = response.json()
                error_msg = error_data.get('error', 'Invalid license')
            except:
                error_msg = f"服务器错误: {response.status_code}"
            return False, error_msg, server_url
    except requests.exceptions.ConnectionError as e:
        return False, f"无法连接到服务器: {str(e)}", server_url
    except requests.exceptions.Timeout as e:
        return False, f"连接超时: {str(e)}", server_url
    except Exception as e:
        return False, f"连接错误: {str(e)}", server_url

def save_license_info(license_key, user_info, server_url):
    """保存授权信息到本地"""
    license_data = {
        'license_key': license_key,
        'user': user_info,
        'server_url': server_url,
        'saved_at': datetime.now().isoformat(),
        'hardware_id': get_hardware_id()  # 保存硬件ID用于验证
    }
    with open('license.json', 'w') as f:
        json.dump(license_data, f)
    
    # 保存服务器配置
    server_config = {'server_url': server_url}
    with open('server_config.json', 'w') as f:
        json.dump(server_config, f)

def load_license_info():
    """从本地加载授权信息"""
    try:
        if not os.path.exists('license.json'):
            return None
            
        with open('license.json', 'r') as f:
            license_data = json.load(f)
            
            # 检查硬件ID是否匹配
            current_hw_id = get_hardware_id()
            saved_hw_id = license_data.get('hardware_id', '')
            
            if saved_hw_id and current_hw_id != saved_hw_id:
                print(f"⚠️ 警告: 硬件ID不匹配 (当前: {current_hw_id}, 保存: {saved_hw_id})")
                print("可能是不同设备，需要重新授权")
                return None
                
            return license_data
    except:
        return None

def run_application():
    """示例应用程序"""
    print("\n" + "=" * 50)
    print("欢迎使用示例软件 - 文本分析工具")
    print("=" * 50)
    
    while True:
        print("\n功能菜单:")
        print("1. 统计文本字数")
        print("2. 查找关键词出现次数")
        print("3. 文本摘要")
        print("4. 退出")
        
        choice = input("\n请选择功能 (1-4): ")
        
        if choice == '1':
            text = input("请输入文本: ")
            print(f"文本字数: {len(text)}")
        elif choice == '2':
            text = input("请输入文本: ")
            keyword = input("请输入关键词: ")
            count = text.count(keyword)
            print(f"关键词 '{keyword}' 出现了 {count} 次")
        elif choice == '3':
            text = input("请输入文本: ")
            if len(text) > 100:
                summary = text[:100] + "..."
                print(f"文本摘要: {summary}")
            else:
                print("文本太短，无需摘要")
        elif choice == '4':
            print("感谢使用，再见！")
            break
        else:
            print("无效选择，请重试")

# 在软件启动时调用
def main():
    # 每次运行都需要重新输入授权码
    print("\n" + "=" * 50)
    print("软件授权验证")
    print("=" * 50)
    
    hardware_id = get_hardware_id()
    print(f"\n您的硬件ID: {hardware_id}")
    print("请将此ID提供给软件供应商以获取授权码")
    
    # 显示服务器信息
    server_url = get_server_info()
    print(f"\n当前使用的服务器: {server_url}")
    print("如果连接失败，请按以下格式输入服务器地址: IP地址:端口 (例如: 192.168.1.100:5000)")
    
    while True:
        # 允许用户输入服务器地址
        server_input = input("\n输入服务器地址 (直接回车使用当前设置): ").strip()
        if server_input:
            # 验证输入格式
            if re.match(r"^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$", server_input):
                server_url = "http://" + server_input
                print(f"使用服务器: {server_url}")
            else:
                print("无效的服务器地址格式，请使用 IP地址:端口 格式")
                continue
        
        license_key = input("请输入您的授权码 (输入'exit'退出): ")
        if license_key.lower() == 'exit':
            return
        
        print(f"验证授权码 ({server_url})...")
        valid, result, server_url = validate_license(license_key, server_url)
        if valid:
            # 正确处理UTC时间字符串
            expires_at_str = result['expires_at'].replace('Z', '+00:00')
            expires_at = datetime.fromisoformat(expires_at_str)
            
            # 计算本地时间
            local_expires = expires_at.astimezone()
            days_remaining = (local_expires - datetime.now().astimezone()).days
            
            save_license_info(license_key, {
                'username': result['username'],
                'software': result['software'],
                'expires_at': result['expires_at']
            }, server_url)
            
            print(f"\n授权成功! 欢迎使用 {result['software']}")
            print(f"授权到期日: {local_expires.strftime('%Y-%m-%d %H:%M:%S')} ({days_remaining}天后到期)")
            
            run_application()
            return
        else:
            print(f"\n授权失败: {result}")
            print("可能的原因:")
            print("1. 服务器未启动 - 请确保服务器正在运行")
            print("2. 服务器地址错误 - 请检查输入的服务器地址")
            print("3. 授权码无效 - 请确认输入的授权码正确")
            print("4. 硬件ID不匹配 - 请确保在原始设备上使用")
            print("-" * 50)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序已退出")
    except Exception as e:
        print(f"发生错误: {str(e)}")
        print("程序将在5秒后退出...")
        time.sleep(5)