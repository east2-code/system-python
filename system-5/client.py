import requests
import uuid
import platform
import hashlib
import os
import sys
import time
import subprocess

API_BASE = "http://localhost:5000/api"

def get_hardware_id():
    """
    获取本机硬件ID。优先尝试主板、CPU序列号，如果不可用则用 uuid.getnode()。
    不依赖任何第三方库，兼容Win/Linux/Mac。
    """
    raw = ""
    try:
        if platform.system() == "Windows":
            def runwmic(cmd):
                try:
                    return subprocess.check_output(f"wmic {cmd}", shell=True).decode("utf-8", errors="ignore").split("\n")[1].strip()
                except Exception:
                    return ""
            mb = runwmic("baseboard get serialnumber")
            cpu = runwmic("cpu get processorid")
            disk = runwmic("diskdrive get serialnumber")
            raw = mb + cpu + disk
        elif platform.system() == "Linux":
            def readfile(path):
                try:
                    with open(path) as f:
                        return f.read().strip()
                except Exception:
                    return ""
            mb = readfile("/sys/class/dmi/id/board_serial")
            cpu = ""
            try:
                with open("/proc/cpuinfo") as f:
                    for line in f:
                        if "Serial" in line or "serial" in line:
                            cpu = line.split(":")[-1].strip()
                            break
            except Exception:
                pass
            raw = mb + cpu
        elif platform.system() == "Darwin":
            try:
                raw = subprocess.check_output(
                    "ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID",
                    shell=True
                ).decode(errors="ignore")
            except Exception:
                raw = platform.node()
        else:
            raw = platform.node()
    except Exception:
        raw = platform.node()
    if not raw or len(raw) < 8:
        # 兜底用 uuid
        raw = str(uuid.getnode())
    hardware_id = hashlib.sha256(raw.encode("utf-8")).hexdigest().upper()
    return hardware_id

def validate_license(hardware_id, license_key):
    url = f"{API_BASE}/validate"
    data = {
        "hardware_id": hardware_id,
        "license_key": license_key
    }
    try:
        resp = requests.post(url, json=data, timeout=10)
        if resp.status_code == 200:
            result = resp.json()
            if result.get("valid"):
                print(f"[激活成功] 用户: {result['username']} | 软件: {result['software']} | 到期: {result['expires_at']}")
                return True
            else:
                print(f"[激活失败] {result.get('error', '未知错误')}")
                return False
        else:
            result = resp.json()
            print(f"[激活失败] {result.get('error', '未知错误')}")
            return False
    except Exception as e:
        print("[网络异常]", str(e))
        return False

def main():
    print("=== 授权码测试程序 ===")
    hardware_id = get_hardware_id()
    print(f"本机硬件ID（请复制此ID到系统后台生成授权码）：\n{hardware_id}\n")
    print("请将上方硬件ID复制到授权管理后台生成授权码。")
    license_key = input("请输入系统后台分配的授权码: ").strip()
    if not license_key:
        print("授权码不能为空")
        sys.exit(1)
    print("\n正在验证授权码...\n")
    valid = validate_license(hardware_id, license_key)
    if valid:
        print("\n你可以正常使用该软件。")
        print("正在监听授权码状态（每30秒自动检测一次）...\n")
        try:
            while True:
                time.sleep(30)
                print("[定时检测] 正在重新验证授权码...")
                if not validate_license(hardware_id, license_key):
                    print("授权已失效或被停用，程序即将退出。")
                    break
        except KeyboardInterrupt:
            print("\n已退出检测。")
    else:
        print("授权验证未通过，请检查授权码或联系管理员。")

if __name__ == "__main__":
    main()