#!/usr/bin/env python3
import os
import subprocess
import psutil
import sys
import shutil
import re
import glob
import requests
import tempfile
import textwrap
import zipfile
import time
from pathlib import Path
from OpenSSL import crypto
from requests.exceptions import ConnectionError

ANDROID_SDK = os.path.expanduser("~/Library/Android/sdk")
ADB_PATH = os.path.join(ANDROID_SDK, "platform-tools", "adb")
EMULATOR_PATH = os.path.join(ANDROID_SDK, "emulator", "emulator")
ROOTAVD_DIR = os.path.join(ANDROID_SDK, "rootAVD")

if not os.path.exists(ADB_PATH):
    print(f"\033[91mADB không tìm thấy tại: {ADB_PATH}\033[0m")
    print("Vui lòng kiểm tra Android Studio đã cài đặt platform-tools chưa.")
    sys.exit(1)
logo = r"""
\033[0m\033[38;5;39m
    ╔══════════════════════════════════════════════════════╗
    ║  🛡️  ANDROID SECURITY AUTOMATION TOOLKIT  🛡️         ║
    ║     Frida • Burp • Root • SSL Bypass • Forensics    ║
    ╚══════════════════════════════════════════════════════╝
\033[0m\033[38;5;242m              Mobile Penetration Testing Suite
                   Version: 1.0 (macOS)
\033[0m"""
print(logo)

def run_adb(cmd, capture=False, text=True, input=None):
    full_cmd = [ADB_PATH] + cmd
    try:
        result = subprocess.run(
            full_cmd,
            capture_output=capture,
            text=text,
            input=input,
            check=True
        )
        return result.stdout.strip() if capture else None
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() if e.stderr else ""
        out = e.stdout.strip() if e.stdout else ""
        print(f"\033[91mADB Error: {err or out}\033[0m")
        return out if capture else None

def is_device_connected():
    output = run_adb(['get-state'], capture=True)
    return output == 'device'

def get_device_arch():
    abi = run_adb(['shell', 'getprop', 'ro.product.cpu.abi'], capture=True).strip()

    mapping = {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86": "x86",
        "x86_64": "x86_64"
    }

    return mapping.get(abi, "arm64")

def is_tool_installed(tool):
    return shutil.which(tool) is not None

def install_tool_pip(tool):
    subprocess.run([sys.executable, '-m', 'pip', 'install', tool], check=True)

def check_root_status():
    """Kiểm tra thiết bị đã root chưa"""
    # Check if adb shell already runs as root
    result = run_adb(['shell', 'id'], capture=True)
    if result and 'uid=0' in result:
        print("\033[1;32m✓ ADB đang chạy ở chế độ root\033[0m")
        print(f"  {result}")
        return True

    su_paths = [
        '/sbin/su',
        '/system/xbin/su',
        '/system/bin/su',
        '/data/adb/magisk/su',
        '/data/local/tmp/su',
    ]

    for su_path in su_paths:
        result = run_adb(['shell', su_path, '-c', 'id'], capture=True)
        if result and 'uid=0' in result:
            print(f"\033[1;32m✓ Thiết bị đã có quyền ROOT (su: {su_path})\033[0m")
            print(f"  {result}")
            return True

    print("\033[93m✗ Thiết bị chưa ROOT\033[0m")
    return False

def get_avd_info():
    """Lấy thông tin AVD đang chạy"""
    try:
        # Lấy Android API level
        api_level = run_adb(['shell', 'getprop', 'ro.build.version.sdk'], capture=True)
        
        # Lấy tên AVD
        avd_name = run_adb(['emu', 'avd', 'name'], capture=True)
        
        # Lấy architecture
        arch = get_device_arch()
        
        return {
            'api_level': int(api_level) if api_level else 0,
            'avd_name': avd_name or "Unknown",
            'arch': arch
        }
    except Exception as e:
        print(f"\033[93mKhông thể lấy thông tin AVD: {e}\033[0m")
        return None

def download_magisk(version="27.0"):
    """Tải Magisk APK"""
    print(f"\n[+] Đang tải Magisk v{version}...")
    
    magisk_url = f"https://github.com/topjohnwu/Magisk/releases/download/v{version}/Magisk-v{version}.apk"
    magisk_file = f"/tmp/Magisk-v{version}.apk"
    
    if os.path.exists(magisk_file):
        print("    ✓ Magisk đã có sẵn")
        return magisk_file
    
    try:
        response = requests.get(magisk_url, stream=True, timeout=30)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 8192
        
        with open(magisk_file, 'wb') as f:
            downloaded = 0
            for chunk in response.iter_content(chunk_size=block_size):
                downloaded += len(chunk)
                f.write(chunk)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    print(f"\r    Downloading: {percent:.1f}%", end='', flush=True)
        
        print("\n    ✓ Tải thành công!")
        return magisk_file
        
    except Exception as e:
        print(f"\n\033[91m✗ Lỗi tải Magisk: {e}\033[0m")
        return None

def find_ramdisk_img(api_level, arch):
    """Find ramdisk.img for the current AVD in SDK system-images"""
    search_patterns = [
        os.path.join(ANDROID_SDK, "system-images", f"android-{api_level}", "*", arch, "ramdisk.img"),
        os.path.join(ANDROID_SDK, "system-images", f"android-{api_level}", "*", "*", "ramdisk.img"),
    ]
    for pattern in search_patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return None


def setup_rootavd():
    """Download rootAVD tool from GitLab if not present"""
    rootavd_sh = os.path.join(ROOTAVD_DIR, "rootAVD.sh")
    if os.path.isdir(ROOTAVD_DIR) and os.path.isfile(rootavd_sh):
        print("    ✓ rootAVD đã có sẵn")
        return True

    print("    → Đang tải rootAVD từ GitLab...")
    try:
        result = subprocess.run(
            ['git', 'clone', 'https://gitlab.com/newbit/rootAVD.git', ROOTAVD_DIR],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            os.chmod(rootavd_sh, 0o755)
            print("    ✓ Tải rootAVD thành công!")
            return True
        print(f"    ✗ Lỗi clone: {result.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        print("    ✗ Timeout khi tải rootAVD (>2 phút)")
        return False
    except Exception as e:
        print(f"    ✗ Lỗi: {e}")
        return False


def create_su_binary():
    """Create a working su wrapper in /data/local/tmp for tool compatibility"""
    su_script = textwrap.dedent('''\
        #!/system/bin/sh
        uid=""
        cmd=""
        while [ $# -gt 0 ]; do
            case "$1" in
                -c) shift; cmd="$*"; break ;;
                --) shift; break ;;
                [0-9]*) uid="$1"; shift ;;
                *) break ;;
            esac
        done
        if [ -n "$cmd" ]; then
            exec /system/bin/sh -c "$cmd"
        elif [ $# -gt 0 ]; then
            exec /system/bin/sh -c "$*"
        else
            exec /system/bin/sh
        fi
    ''')

    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.sh') as f:
        f.write(su_script)
        tmp = f.name

    try:
        run_adb(['push', tmp, '/data/local/tmp/su'])
        run_adb(['shell', 'chmod', '755', '/data/local/tmp/su'])
        for dest in ['/data/adb/magisk', '/system/xbin']:
            run_adb(['shell', 'mkdir', '-p', dest], capture=True)
            run_adb(['shell', 'cp', '/data/local/tmp/su', f'{dest}/su'], capture=True)
            run_adb(['shell', 'chmod', '755', f'{dest}/su'], capture=True)
    finally:
        os.unlink(tmp)


def root_via_adb_root(avd_info):
    """Root AVD via adb root — works on userdebug/eng builds (Google APIs images)"""
    print("[1/3] Restart ADB với quyền root...")

    result = run_adb(['root'], capture=True)
    if result and 'cannot run as root' in result:
        print(f"    ✗ {result}")
        print("    → Fallback sang rootAVD method...\n")
        return root_via_rootavd(avd_info)

    time.sleep(3)
    run_adb(['wait-for-device'], capture=True)

    test = run_adb(['shell', 'id'], capture=True)
    if not test or 'uid=0' not in test:
        print("    ✗ adb root không thành công")
        print("    → Fallback sang rootAVD method...\n")
        return root_via_rootavd(avd_info)

    print("    ✓ ADB đang chạy với quyền root!")

    print("\n[2/3] Tạo su binary cho tool compatibility...")
    create_su_binary()
    print("    ✓ su binary đã tạo!")

    print("\n[3/3] Cài đặt Magisk APK...")
    magisk_apk = download_magisk("27.0")
    if magisk_apk:
        run_adb(['install', '-r', magisk_apk])
        print("    ✓ Magisk APK đã cài!")

    print_root_success("adb root")
    return True


def root_via_rootavd(avd_info):
    """Root AVD via rootAVD — patches ramdisk.img with Magisk (works on production builds)"""
    if not avd_info:
        print("\033[91m✗ Không có thông tin AVD!\033[0m")
        return False

    print("[1/3] Chuẩn bị rootAVD tool...")
    if not setup_rootavd():
        show_root_troubleshooting()
        return False

    print("\n[2/3] Tìm ramdisk.img...")
    api = avd_info['api_level']
    arch = avd_info['arch']
    ramdisk = find_ramdisk_img(api, arch)

    if not ramdisk:
        print(f"    ✗ Không tìm thấy ramdisk.img cho API {api}/{arch}")
        all_ramdisks = glob.glob(os.path.join(ANDROID_SDK, "system-images", "*", "*", "*", "ramdisk.img"))
        if all_ramdisks:
            print("\n    Ramdisk images có sẵn trong SDK:")
            for r in all_ramdisks:
                print(f"      → {os.path.relpath(r, ANDROID_SDK)}")
        show_root_troubleshooting()
        return False

    rel_ramdisk = os.path.relpath(ramdisk, ANDROID_SDK)
    print(f"    ✓ Found: {rel_ramdisk}")

    print("\n[3/3] Patch ramdisk với Magisk (rootAVD)...")
    print("    ⏳ Quá trình này có thể mất 1-3 phút...\n")

    try:
        env = {**os.environ, 'ANDROID_HOME': ANDROID_SDK, 'ANDROID_SDK_ROOT': ANDROID_SDK}
        process = subprocess.run(
            ['bash', 'rootAVD.sh', ramdisk],
            cwd=ROOTAVD_DIR, timeout=300, env=env
        )

        if process.returncode != 0:
            print("\n    ✗ rootAVD patch thất bại!")
            print("\n    Thử chạy thủ công:")
            print(f"      cd {ROOTAVD_DIR}")
            print(f"      ./rootAVD.sh {ramdisk}")
            show_root_troubleshooting()
            return False

    except subprocess.TimeoutExpired:
        print("\n    ✗ rootAVD timeout (>5 phút)")
        return False
    except Exception as e:
        print(f"\n    ✗ Lỗi: {e}")
        show_root_troubleshooting()
        return False

    print("\n    ✓ Ramdisk đã được patch với Magisk!")

    avd_name = avd_info['avd_name'].split('\n')[0].strip()
    print(f"\n    ⚠ Cần restart emulator (cold boot) để kích hoạt root")
    restart = input(f"\n    Restart AVD '{avd_name}' ngay? [Y/n]: ").strip()

    if restart.lower() == 'n':
        print(f"\n    → Restart thủ công:")
        print(f"      {EMULATOR_PATH} -avd {avd_name} -no-snapshot-load")
        print("    → Sau đó chạy lại kiểm tra root (option 2)")
        return True

    print("\n    → Tắt emulator...")
    run_adb(['emu', 'kill'])
    time.sleep(5)

    print(f"    → Khởi động AVD: {avd_name} (cold boot)...")
    subprocess.Popen(
        [EMULATOR_PATH, '-avd', avd_name, '-no-snapshot-load'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    print("    → Chờ thiết bị khởi động...")
    for i in range(24):
        time.sleep(5)
        try:
            boot = run_adb(['shell', 'getprop', 'sys.boot_completed'], capture=True)
            if boot and boot.strip() == '1':
                print("    ✓ Thiết bị đã khởi động!")
                break
        except Exception:
            pass
        print(f"    ⏳ Đang chờ... ({(i+1)*5}s)")
    else:
        print("    ⚠ Timeout chờ thiết bị (>2 phút)")
        print("    → Chờ boot xong rồi chạy lại kiểm tra root")
        return False

    time.sleep(5)

    if check_root_status():
        print_root_success("rootAVD + Magisk")
        return True

    print("\n\033[1;33m⚠ Root setup xong nhưng chưa verify được\033[0m")
    print("    → Mở app Magisk trên thiết bị")
    print("    → Nếu Magisk yêu cầu setup thêm, làm theo hướng dẫn")
    print("    → Sau đó chạy lại kiểm tra root (option 2)")
    return False


def auto_root_avd():
    """Auto root AVD — detects build type and uses the appropriate method"""
    print("\n" + "="*60)
    print("\033[1;36m         AUTO ROOT AVD WITH MAGISK\033[0m")
    print("="*60)

    if not is_device_connected():
        print("\033[91m✗ Không tìm thấy thiết bị!\033[0m")
        return False

    if check_root_status():
        print("\n\033[1;32m✓ Thiết bị đã ROOT rồi! Không cần làm gì thêm.\033[0m")
        return True

    avd_info = get_avd_info()
    if avd_info:
        print(f"\n[INFO] AVD: {avd_info['avd_name']}")
        print(f"[INFO] API Level: {avd_info['api_level']}")
        print(f"[INFO] Architecture: {avd_info['arch']}")

    build_type = run_adb(['shell', 'getprop', 'ro.build.type'], capture=True) or ""
    build_tags = run_adb(['shell', 'getprop', 'ro.build.tags'], capture=True) or ""
    is_production = (build_type == 'user' and 'release-keys' in build_tags)

    print(f"\n[INFO] Build type: {build_type}")
    print(f"[INFO] Build tags: {build_tags}")

    if is_production:
        print("\n\033[1;33m[!] Production build detected (Google Play image)\033[0m")
        print("    → adb root không khả dụng trên image này")
        print("    → Sử dụng rootAVD để patch ramdisk với Magisk\n")
        return root_via_rootavd(avd_info)
    else:
        print("\n\033[1;32m[✓] Userdebug/eng build detected\033[0m")
        print("    → Root qua adb root\n")
        return root_via_adb_root(avd_info)


def print_root_success(method=""):
    """Print root success banner"""
    print("\n" + "="*60)
    print(f"\033[1;32m     ✓✓✓ ROOT THÀNH CÔNG! ({method}) ✓✓✓\033[0m")
    print("="*60)
    print("\n\033[1;36mCách sử dụng:\033[0m")
    print("  • adb shell su -c '<command>'")
    print("  • adb shell /data/local/tmp/su -c '<command>'")
    print("  • Frida: frida -U -f <package>")
    if 'rootAVD' in method:
        print("\n\033[1;33m⚠ Lưu ý:\033[0m")
        print("  • Root persist qua reboot (ramdisk đã patch)")
        print("  • Mở Magisk app để quản lý root permissions")
    else:
        print("\n\033[1;33m⚠ Lưu ý:\033[0m")
        print("  • Cần chạy 'adb root' mỗi khi restart emulator")
        print("  • Hoặc chạy lại option 1 để setup lại")


def show_root_troubleshooting():
    """Hiển thị hướng dẫn troubleshooting"""
    print("\n" + "="*60)
    print("\033[1;33m         HƯỚNG DẪN KHẮC PHỤC\033[0m")
    print("="*60)
    print("\n\033[1;36m1. AVD Image không phù hợp:\033[0m")
    print("   → Tạo AVD mới với: Google APIs (KHÔNG phải Google Play)")
    print("   → Target: Android 9-13 (API 28-33) root dễ nhất")
    print("   → Hardware: x86_64 hoặc arm64-v8a")

    print("\n\033[1;36m2. rootAVD thủ công:\033[0m")
    print(f"   → cd {ROOTAVD_DIR}")
    print("   → ./rootAVD.sh <path/to/ramdisk.img>")
    print("   → Restart emulator với cold boot")

    print("\n\033[1;36m3. Alternative emulators:\033[0m")
    print("   → Genymotion: Hỗ trợ root tốt nhất")
    print("   → Nox Player / LDPlayer: Root có sẵn")

    print("\n\033[1;36m4. Workaround cho Frida (không cần root):\033[0m")
    print("   → frida -U --no-pause -f <app>  (debuggable apps)")
    print("   → objection -g <app> explore")
    print("="*60)


def burpsuite_cacert():
    """Cài Burp CA cert với tmpfs overlay - Đúng cách"""
    
    print("\n" + "="*60)
    print("\033[1;36m   INSTALL BURP SUITE CA CERTIFICATE\033[0m")
    print("="*60)
    
    # Input IP và PORT từ user
    print("\n\033[1;33m📡 Burp Suite Proxy Configuration:\033[0m")
    
    burp_ip = input("\033[38;5;208mIP Burp [enter -> 127.0.0.1]: \033[0m").strip()
    if not burp_ip:
        burp_ip = "127.0.0.1"
    
    burp_port = input("\033[38;5;208mPORT Burp [enter -> 8080]: \033[0m").strip()
    if not burp_port:
        burp_port = "8080"
    
    cert_url = f"http://{burp_ip}:{burp_port}/cert"
    
    print(f"\n\033[1;32m✓ Sử dụng Burp Proxy: {burp_ip}:{burp_port}\033[0m")
    print(f"  URL: {cert_url}\n")
    try:
        # Step 1: Tải cert từ Burp
        print("\n[1/6] Đang tải chứng chỉ từ Burp Suite...")
        r = requests.get(cert_url, timeout=10, verify=False)
        r.raise_for_status()
        print("    ✓ Đã tải cert (DER format)")
        
        # Step 2: Convert DER → PEM
        print("\n[2/6] Convert DER → PEM...")
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, r.content)
        pem_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        
        # Step 3: Tính subject_hash_old (OpenSSL old format)
        print("\n[3/6] Tính subject hash (OpenSSL old format)...")
        temp_pem = "/tmp/burp_temp.pem"
        with open(temp_pem, "wb") as f:
            f.write(pem_data)
        
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-inform', 'PEM', '-subject_hash_old', '-in', temp_pem],
                capture_output=True,
                text=True,
                check=True
            )
            subj_hash = result.stdout.strip().split('\n')[0]
            print(f"    ✓ Subject hash: {subj_hash}")
        except subprocess.CalledProcessError:
            print("    ⚠ openssl không khả dụng, dùng fallback...")
            subj_hash = format(cert.get_subject().hash(), '08x')
        finally:
            os.remove(temp_pem)
        
        cert_filename = f"{subj_hash}.0"
        
        # Lưu cert với tên đúng
        with open(cert_filename, "wb") as f:
            f.write(pem_data)
        print(f"    ✓ Cert file: {cert_filename}")
        
        # Step 4: Push cert lên device
        print(f"\n[4/6] Push {cert_filename} lên thiết bị...")
        run_adb(['push', cert_filename, '/sdcard/'])
        print("    ✓ Đã push lên /sdcard/")
        
        # Clean up local file
        os.remove(cert_filename)
        
        # Step 5: Cài đặt cert với tmpfs overlay
        print("\n[5/6] Cài đặt cert với tmpfs overlay...")
        
        # Tạo shell script theo đúng phương pháp
        install_script = f'''#!/system/bin/sh
set -e

echo "=== BURP SUITE CA INSTALLATION ==="
echo ""

# Step 1: Copy existing certificates to temp location
echo "[1/5] Backup existing system certificates..."
mkdir -p /data/local/tmp/cacerts
cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/
CERT_COUNT=$(ls -1 /data/local/tmp/cacerts/ | wc -l)
echo "    → Backed up $CERT_COUNT certificates"

# Step 2: Create an in-memory mount (tmpfs)
echo "[2/5] Create tmpfs overlay..."
mount -t tmpfs tmpfs /system/etc/security/cacerts

# Step 3: Copy existing certs back into tmpfs mount
echo "[3/5] Restore system certificates to tmpfs..."
mv /data/local/tmp/cacerts/* /system/etc/security/cacerts/
echo "    → Restored $CERT_COUNT certificates"

# Step 4: Copy Burp certificate
echo "[4/5] Install Burp CA certificate..."
cp /sdcard/{cert_filename} /system/etc/security/cacerts/
echo "    → Added {cert_filename}"

# Step 5: Update perms & SELinux context labels
echo "[5/5] Fix permissions and SELinux context..."
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

# Verify installation
TOTAL=$(ls -1 /system/etc/security/cacerts/ | wc -l)
echo ""
echo "✅ INSTALLATION COMPLETE!"
echo "   → Total certificates: $TOTAL"
echo "   → Burp CA: {cert_filename}"

# Check if Burp cert exists
if [ -f "/system/etc/security/cacerts/{cert_filename}" ]; then
    echo "   → Status: ✓ VERIFIED"
    ls -la /system/etc/security/cacerts/{cert_filename}
else
    echo "   → Status: ✗ FAILED"
    exit 1
fi

echo ""
echo "⚠ NOTE: Certificate will be lost after reboot"
echo "   Run this script again after each reboot"
'''
        
        # Push và chạy script
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.sh') as f:
            f.write(install_script)
            script_path = f.name
        
        run_adb(['push', script_path, '/data/local/tmp/install_burp.sh'])
        run_adb(['shell', 'chmod', '755', '/data/local/tmp/install_burp.sh'])
        os.unlink(script_path)
        
        print("    → Executing installation script...")
        
        # Chạy script với su
        result = run_adb(['shell', 'su', '0', 'sh /data/local/tmp/install_burp.sh'], capture=True)
        if result:
            print(result)
        
        # Step 6: Verify installation
        print("\n[6/6] Kiểm tra kết quả...")
        
        # Check file exists
        verify = run_adb(['shell', 'su', '0', f'ls -la /system/etc/security/cacerts/{cert_filename}'], capture=True)
        
        # Count total certs
        total = run_adb(['shell', 'su', '0', 'ls /system/etc/security/cacerts/ | wc -l'], capture=True)
        
        if verify and cert_filename in verify:
            print("\n" + "="*60)
            print("\033[1;32m     ✓✓✓ CÀI ĐẶT THÀNH CÔNG! ✓✓✓\033[0m")
            print("="*60)
            print(f"\n📊 Thống kê:")
            print(f"   • Tổng số certificates: {total.strip() if total else 'unknown'}")
            print(f"   • Burp CA: {cert_filename}")
            print(f"\n📁 File info:")
            print(f"   {verify.strip()}")
            
            print("\n\033[1;36m📱 Verify trên thiết bị:\033[0m")
            print("   Settings > Security > Trusted credentials > System")
            print("   Tìm: PortSwigger CA")
            
            print("\n\033[1;36m🔧 Configure Burp Proxy:\033[0m")
            print("   1. Vào Settings > Network & Internet > Private DNS")
            print("   2. Chọn: Off (để dùng manual proxy)")
            print("   3. Settings > Network > Wi-Fi > Long press > Modify network")
            print("   4. Advanced > Proxy: Manual")
            print("   5. Hostname: 192.168.89.243, Port: 8080")
            
            print("\n\033[1;36m🎯 Test SSL Interception:\033[0m")
            print("   1. Mở Chrome/App bất kỳ")
            print("   2. Browse đến HTTPS site (vd: https://google.com)")
            print("   3. Check Burp > Proxy > HTTP history")
            print("   4. Bạn sẽ thấy decrypted HTTPS traffic! 🎉")
            
            print("\n\033[1;33m⚠ LƯU Ý QUAN TRỌNG:\033[0m")
            print("   • Cert dùng tmpfs overlay → MẤT khi reboot")
            print("   • Ưu điểm: Không modify system partition (an toàn)")
            print("   • Sau khi reboot: Chạy lại option 7 (mất ~5 giây)")
            print("   • Xóa cert: Chỉ cần reboot thiết bị")
            
            return True
        else:
            print("\n\033[91m✗ INSTALLATION FAILED\033[0m")
            print("Cert không tìm thấy trong /system/etc/security/cacerts/")
            print("\n🔍 Troubleshooting:")
            print("1. Kiểm tra root: adb shell su 0 id")
            print("2. Xem script log:")
            print("   adb shell su 0 'sh /data/local/tmp/install_burp.sh'")
            print("3. Check mount points:")
            print("   adb shell su 0 'mount | grep cacerts'")
            print("4. Manual install:")
            print("   adb shell")
            print("   su")
            print("   sh /data/local/tmp/install_burp.sh")
            return False
            
    except Exception as e:
        print(f"\n\033[91m✗ Lỗi: {e}\033[0m")
        import traceback
        traceback.print_exc()
        return False

 
def open_adb_shell():
    print("\x1b[1;32mMở shell ADB (gõ 'exit' để thoát)\x1b[0m")
    os.system(f"{ADB_PATH} shell")

def frida_server_install():
    if not is_tool_installed("frida"):
        print("Frida-tools chưa cài!")
        return

    print("Đang kiểm tra phiên bản Frida...")
    version = subprocess.check_output(["frida", "--version"], text=True).strip()
    print(f"Frida version: {version}")

    arch = get_device_arch().split("-")[0]
    print(f"Kiến trúc thiết bị: {arch}")
    
    url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch}.xz"
    print(f"Tải: {url}")

    run_adb(['shell', 'mkdir', '-p', '/data/local/tmp'])
    
    # Tải về local trước
    local_file = f"/tmp/frida-server-{version}-android-{arch}.xz"
    print("Đang tải frida-server...")
    
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(local_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        # Giải nén trên macOS
        import lzma
        with lzma.open(local_file, 'rb') as compressed:
            with open(local_file.replace('.xz', ''), 'wb') as decompressed:
                decompressed.write(compressed.read())
        
        # Kiểm tra file đã tải có phải là executable không
        file_info = subprocess.check_output(
            ["file", local_file.replace(".xz", "")],
            text=True
        )

        print("Binary info:", file_info)

        if "ELF" not in file_info:
            print("❌ File không phải ELF binary!")
            return

        if "aarch64" not in file_info and "ARM aarch64" not in file_info:
            print("❌ Kiến trúc binary không đúng!")
            return

        print("✓ Frida binary hợp lệ")
        
        # Push lên thiết bị
        run_adb(['push', local_file.replace('.xz', ''), '/data/local/tmp/frida-server'])
        run_adb(['shell', 'chmod', '755', '/data/local/tmp/frida-server'])
        
        os.remove(local_file)
        os.remove(local_file.replace('.xz', ''))
        
        print("\x1b[1;32mFrida Server đã cài xong!\x1b[0m")
        
    except Exception as e:
        print(f"\033[91mLỗi: {e}\033[0m")

def run_frida_server():
    print("\x1b[1;32mKhởi chạy Frida Server...\x1b[0m")
    print("Dùng: \033[38;5;208mfrida-ps -Uai\033[0m để liệt kê app")
    
    # Kill process cũ nếu có
    run_adb(['shell', 'su', '0', 'killall', 'frida-server'], capture=True)
    
    # Chạy frida-server
    # subprocess.Popen([ADB_PATH, 'shell', 'su', '0', '/data/local/tmp/frida-server &'])
    run_adb(['shell','su','0','nohup','/data/local/tmp/frida-server','>','/dev/null','2>&1','&'])
    time.sleep(2)
    print("✓ Frida Server đang chạy!")
    
    time.sleep(2)

    check = run_adb(['shell','netstat','-tulpn'],capture=True)

    if check and "27042" in check:
        print("✓ Frida server running on port 27042")
    else:
        print("❌ Frida server failed to start")

def remove_bloatware():
    print("Xóa bloatware (cần root)...")
    run_adb(['root'])
    run_adb(['remount'])
    pkgs = [
        "com.android.printspooler",
        "com.android.wallpaperbackup",
        "com.google.android.apps.photos",
        # thêm nếu cần
    ]
    for pkg in pkgs:
        run_adb(['shell', 'pm', 'uninstall', pkg])
    print("Hoàn tất!")

def display_main_menu():
    print("\n\033[93mChọn chức năng:\033[0m")
    print("1. Windows Tools (macOS: Python Tools)")
    print("2. Thiết bị Android (ADB)")
    print("3. Frida Tools")
    print("4. Thoát")
    print("\033[91mLưu ý: Chọn Frida khi server đang chạy.\033[0m\n")

def display_adb_menu():
    print("\n\033[93mChức năng thiết bị:\033[0m")
    print("1. \033[1;36m🔓 AUTO ROOT AVD (Magisk)\033[0m")
    print("2. Kiểm tra trạng thái ROOT")
    print("3. Xóa bloatware")
    print("4. Cài Frida Server")
    print("5. Chạy Frida Server")
    print("6. Mở ADB Shell")
    print("7. Cài chứng chỉ Burp")
    print("8. Quay lại")
    print("\033[91mRoot AVD trước khi dùng các tính năng khác!\033[0m\n")

def display_frida_menu():
    print("\n\033[93mFrida Tools:\033[0m")
    print("1. Liệt kê ứng dụng")
    print("2. Bypass SSL Pinning")
    print("3. Bypass Root Check")
    print("4. Bypass cả hai")
    print("5. Quay lại")
    print("\033[92mCustom: frida -U -l script.js -f com.example.app\033[0m\n")

def run_frida_command(option):
    if option == "1":
        os.system("frida-ps -Uai")
    elif option in ["2", "3", "4"]:
        pkg = input("\033[38;5;208mNhập package name: \033[0m").strip()
        scripts = {
            "2": "SSL-BYE.js",
            "3": "ROOTER.js",
            "4": "PintooR.js"
        }
        script_path = f"./Fripts/{scripts[option]}"
        if os.path.exists(script_path):
            os.system(f"frida -U -l {script_path} -f {pkg}")
        else:
            print(f"Không tìm thấy script: {script_path}")
    else:
        print("Lựa chọn không hợp lệ.")

# === MAIN ===
if __name__ == "__main__":
    if not is_device_connected():
        print("\033[91mKhông tìm thấy thiết bị! Kiểm tra USB Debugging hoặc emulator.\033[0m")
        sys.exit(1)

    print(f"\x1b[1;32mThiết bị đã kết nối: {run_adb(['get-serialno'], capture=True)}\x1b[0m")

    while True:
        display_main_menu()
        choice = input("\033[38;5;208mNhập lựa chọn: \033[0m").strip()

        if choice == "1":
            while True:
                print("\n\033[93mCài công cụ Python:\033[0m")
                print("1. Frida")
                print("2. Objection")
                print("3. reFlutter")
                print("4. Quay lại")
                t = input("Chọn: ")
                if t == "1":
                    install_tool_pip("frida-tools==12.3.0") if not is_tool_installed("frida") else print("Frida đã cài.")
                elif t == "2":
                    install_tool_pip("objection") if not is_tool_installed("objection") else print("Objection đã cài.")
                elif t == "3":
                    install_tool_pip("reFlutter") if not is_tool_installed("reflutter") else print("reFlutter đã cài.")
                elif t == "4":
                    break

        elif choice == "2":
            while True:
                display_adb_menu()
                c = input("Chọn: ").strip()
                if c == "8": 
                    break
                elif c == "1": 
                    auto_root_avd()
                elif c == "2":
                    check_root_status()
                elif c == "3": 
                    remove_bloatware()
                elif c == "4": 
                    frida_server_install()
                elif c == "5": 
                    run_frida_server()
                elif c == "6": 
                    open_adb_shell()
                elif c == "7": 
                    burpsuite_cacert()

        elif choice == "3":
            while True:
                display_frida_menu()
                f = input("Chọn: ").strip()
                if f == "5": break
                run_frida_command(f)

        elif choice == "4":
            print("\033[91mThoát...\033[0m")
            break
        else:
            print("\033[91mLựa chọn không hợp lệ!\033[0m")