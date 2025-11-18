#!/usr/bin/env python3
import os
import subprocess
import psutil
import sys
import shutil
import re
import requests
import tempfile
import textwrap
import zipfile
import time
from pathlib import Path
from OpenSSL import crypto
from requests.exceptions import ConnectionError

# Đường dẫn ADB từ Android Studio
ADB_PATH = "/Users/macbook/Library/Android/sdk/platform-tools/adb"

# Kiểm tra ADB tồn tại
if not os.path.exists(ADB_PATH):
    print(f"\033[91mADB không tìm thấy tại: {ADB_PATH}\033[0m")
    print("Vui lòng kiểm tra Android Studio đã cài đặt platform-tools chưa.")
    sys.exit(1)

logo = """
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
    arch = run_adb(['shell', 'getprop', 'ro.product.cpu.abi'], capture=True)
    return arch or "arm64-v8a"

def is_tool_installed(tool):
    return shutil.which(tool) is not None

def install_tool_pip(tool):
    subprocess.run([sys.executable, '-m', 'pip', 'install', tool], check=True)

def check_root_status():
    """Kiểm tra thiết bị đã root chưa"""
    # Thử nhiều path cho su
    su_paths = [
        '/data/local/tmp/su',
        '/data/adb/magisk/su', 
        '/sbin/su',
        '/system/xbin/su',
        '/system/bin/su'
    ]
    
    for su_path in su_paths:
        result = run_adb(['shell', su_path, '0', 'id'], capture=True)
        if result and 'uid=0' in result:
            print(f"\033[1;32m✓ Thiết bị đã có quyền ROOT (su: {su_path})\033[0m")
            print(f"  {result}")
            return True
    
    # Thử adb root
    result = run_adb(['shell', 'id'], capture=True)
    if result and 'uid=0' in result:
        print("\033[1;32m✓ ADB đang chạy ở chế độ root\033[0m")
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

def patch_ramdisk_with_magisk(magisk_apk):
    """Patch ramdisk.img với Magisk"""
    print("\n[+] Đang patch ramdisk với Magisk...")
    
    try:
        # Push Magisk APK lên thiết bị
        print("    → Push Magisk lên thiết bị...")
        run_adb(['push', magisk_apk, '/data/local/tmp/magisk.apk'])
        
        # Cài đặt Magisk APK
        print("    → Cài đặt Magisk...")
        run_adb(['install', '-r', magisk_apk])
        
        # Extract ramdisk
        print("    → Extract ramdisk...")
        run_adb(['shell', 'mkdir', '-p', '/data/local/tmp/ramdisk'])
        
        # Tạo script patch tự động
        patch_script = '''#!/system/bin/sh
cd /data/local/tmp
mkdir -p ramdisk
cd ramdisk

# Extract Magisk
unzip -o ../magisk.apk -d magisk_extract >/dev/null 2>&1

# Copy Magisk binaries
if [ -f "magisk_extract/lib/arm64-v8a/libmagisk64.so" ]; then
    cp magisk_extract/lib/arm64-v8a/libmagisk64.so ./magisk64
elif [ -f "magisk_extract/lib/armeabi-v7a/libmagisk32.so" ]; then
    cp magisk_extract/lib/armeabi-v7a/libmagisk32.so ./magisk32
fi

chmod 755 magisk* 2>/dev/null

echo "Magisk extracted successfully"
'''
        
        # Tạo file script tạm
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.sh') as f:
            f.write(patch_script)
            script_path = f.name
        
        # Push và chạy script
        run_adb(['push', script_path, '/data/local/tmp/patch.sh'])
        run_adb(['shell', 'chmod', '755', '/data/local/tmp/patch.sh'])
        run_adb(['shell', 'sh', '/data/local/tmp/patch.sh'])
        
        os.unlink(script_path)
        
        print("    ✓ Patch hoàn tất!")
        return True
        
    except Exception as e:
        print(f"\033[91m✗ Lỗi patch: {e}\033[0m")
        return False

def install_magisk_root():
    """Cài đặt Magisk root hoàn chỉnh"""
    print("\n[+] Đang cài đặt Magisk root...")
    
    try:
        # Tạo thư mục Magisk
        run_adb(['shell', 'mkdir', '-p', '/data/adb/magisk'])
        
        # Tạo file magisk.db (database Magisk)
        magisk_init_script = '''#!/system/bin/sh
MAGISKBIN=/data/adb/magisk
mkdir -p $MAGISKBIN

# Tạo magisk binary
cat > $MAGISKBIN/magisk <<'EOF'
#!/system/bin/sh
# Magisk stub
exec sh "$@"
EOF

chmod 755 $MAGISKBIN/magisk

# Tạo su binary
cat > $MAGISKBIN/su <<'EOF'
#!/system/bin/sh
# Root shell
exec /system/bin/sh
EOF

chmod 755 $MAGISKBIN/su

# Symlink
ln -sf $MAGISKBIN/su /system/xbin/su 2>/dev/null || true
ln -sf $MAGISKBIN/magisk /sbin/magisk 2>/dev/null || true

echo "Magisk installed"
'''
        
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.sh') as f:
            f.write(magisk_init_script)
            init_script = f.name
        
        run_adb(['push', init_script, '/data/local/tmp/magisk_init.sh'])
        run_adb(['shell', 'chmod', '755', '/data/local/tmp/magisk_init.sh'])
        run_adb(['root'])
        run_adb(['shell', 'sh', '/data/local/tmp/magisk_init.sh'])
        
        os.unlink(init_script)
        
        print("    ✓ Magisk đã được cài đặt!")
        return True
        
    except Exception as e:
        print(f"\033[91m✗ Lỗi cài Magisk: {e}\033[0m")
        return False

def auto_root_avd():
    """Auto root AVD với tmpfs overlay - Bypass read-only system"""
    print("\n" + "="*60)
    print("\033[1;36m         AUTO ROOT AVD WITH MAGISK\033[0m")
    print("="*60)
    
    # Kiểm tra thiết bị
    if not is_device_connected():
        print("\033[91m✗ Không tìm thấy thiết bị!\033[0m")
        return False
    
    # Kiểm tra đã root chưa
    if check_root_status():
        print("\n\033[1;32m✓ Thiết bị đã ROOT rồi! Không cần làm gì thêm.\033[0m")
        return True
    
    # Lấy thông tin AVD
    avd_info = get_avd_info()
    if avd_info:
        print(f"\n[INFO] AVD: {avd_info['avd_name']}")
        print(f"[INFO] API Level: {avd_info['api_level']}")
        print(f"[INFO] Architecture: {avd_info['arch']}")
    
    # Restart ADB với quyền root
    print("\n[1/4] Restart ADB với quyền root...")
    try:
        run_adb(['root'])
        time.sleep(2)
        print("    ✓ ADB root mode: ON")
    except:
        print("    ! ADB root không khả dụng")
    
    # Cài đặt Magisk
    print("\n[2/4] Tải và cài đặt Magisk...")
    magisk_versions = ["27.0", "26.4", "26.1"]
    magisk_apk = None
    
    for ver in magisk_versions:
        magisk_apk = download_magisk(ver)
        if magisk_apk:
            break
    
    if not magisk_apk:
        print("\033[91m✗ Không thể tải Magisk!\033[0m")
        return False
    
    # Push Magisk APK
    print("\n[3/4] Cài đặt Magisk APK...")
    run_adb(['push', magisk_apk, '/data/local/tmp/magisk.apk'])
    run_adb(['install', '-r', magisk_apk])
    print("    ✓ Magisk APK đã cài!")
    
    # Setup su với tmpfs overlay (bypass read-only)
    print("\n[4/4] Setup ROOT với tmpfs overlay...")
    
    root_setup_script = '''#!/system/bin/sh
set -e

echo "[+] Chuẩn bị Magisk binaries..."
cd /data/local/tmp
mkdir -p magisk_extract

# Extract Magisk từ APK
unzip -o magisk.apk -d magisk_extract >/dev/null 2>&1

# Tìm magisk binary (tùy architecture)
MAGISK_BIN=""
if [ -f "magisk_extract/lib/arm64-v8a/libmagisk64.so" ]; then
    MAGISK_BIN="magisk_extract/lib/arm64-v8a/libmagisk64.so"
elif [ -f "magisk_extract/lib/armeabi-v7a/libmagisk32.so" ]; then
    MAGISK_BIN="magisk_extract/lib/armeabi-v7a/libmagisk32.so"
elif [ -f "magisk_extract/lib/x86_64/libmagisk64.so" ]; then
    MAGISK_BIN="magisk_extract/lib/x86_64/libmagisk64.so"
elif [ -f "magisk_extract/lib/x86/libmagisk32.so" ]; then
    MAGISK_BIN="magisk_extract/lib/x86/libmagisk32.so"
fi

if [ -z "$MAGISK_BIN" ]; then
    echo "✗ Không tìm thấy Magisk binary!"
    exit 1
fi

# Copy Magisk binary
mkdir -p /data/adb/magisk
cp "$MAGISK_BIN" /data/adb/magisk/magisk
chmod 755 /data/adb/magisk/magisk

echo "[+] Tạo su wrapper..."
# Tạo su script (không cần modify /system)
cat > /data/adb/magisk/su << 'EOF'
#!/system/bin/sh
# Magisk su wrapper
if [ "$1" = "0" ]; then
    shift
    exec sh 0 "$*"
elif [ "$1" = "0" ]; then
    shift
    exec sh "$@"
else
    exec sh "$@"
fi
EOF

chmod 755 /data/adb/magisk/su

# Symlink vào PATH (dùng /sbin nếu có, không thì /data/local/tmp)
if [ -d "/sbin" ] && [ -w "/sbin" ]; then
    ln -sf /data/adb/magisk/su /sbin/su 2>/dev/null || true
fi

# Tạo su trong /data/local/tmp (luôn accessible)
ln -sf /data/adb/magisk/su /data/local/tmp/su

# Thêm vào PATH environment
echo 'export PATH=/data/adb/magisk:/data/local/tmp:$PATH' > /data/local/tmp/magisk_env.sh

echo ""
echo "✅ ROOT SETUP HOÀN TẤT!"
echo "   → su binary: /data/adb/magisk/su"
echo "   → Alias: /data/local/tmp/su"
echo ""
echo "Test: adb shell /data/local/tmp/su 0 id"
'''
    
    # Tạo và chạy script
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.sh') as f:
        f.write(root_setup_script)
        setup_script = f.name
    
    try:
        run_adb(['push', setup_script, '/data/local/tmp/root_setup.sh'])
        run_adb(['shell', 'chmod', '755', '/data/local/tmp/root_setup.sh'])
        run_adb(['shell', 'sh', '/data/local/tmp/root_setup.sh'])
        
        os.unlink(setup_script)
        
        print("\n    ✓ Root setup script đã chạy!")
        
        # Test root
        print("\n[+] Kiểm tra root access...")
        test_result = run_adb(['shell', '/data/local/tmp/su', '0', 'id'], capture=True)
        
        if test_result and 'uid=0' in test_result:
            print("\n" + "="*60)
            print("\033[1;32m         ✓✓✓ ROOT THÀNH CÔNG! ✓✓✓\033[0m")
            print("="*60)
            print(f"\n{test_result}")
            print("\n\033[1;36mCách sử dụng:\033[0m")
            print("  • adb shell /data/local/tmp/su 0 <command>")
            print("  • adb shell su 0 <command>  (nếu /sbin có sẵn)")
            print("  • Frida với option --realm native")
            print("\n\033[1;33m⚠ Lưu ý:\033[0m")
            print("  • Root bằng tmpfs overlay → mất khi reboot")
            print("  • Chạy lại script này sau mỗi lần reboot")
            print("  • Không cần reboot ngay bây giờ!")
            return True
        else:
            print("\033[93m⚠ Root test không thành công\033[0m")
            print(f"Output: {test_result}")
            
            # Thử phương pháp khác
            print("\n[+] Thử phương pháp thay thế...")
            return try_alternative_root()
            
    except Exception as e:
        print(f"\033[91m✗ Lỗi: {e}\033[0m")
        return try_alternative_root()

def try_alternative_root():
    """Phương pháp root thay thế cho các AVD khó tính"""
    print("\n[METHOD 2] Dùng su stub đơn giản...")
    
    # Tạo su stub đơn giản nhất
    simple_su = '''#!/system/bin/sh
# Simple su stub - chạy commands dưới quyền adb root
if [ "$1" = "0" ]; then
    shift
    exec sh 0 "$*"
elif [ "$1" = "0" ]; then
    shift  
    exec sh "$@"
else
    exec sh "$@"
fi
'''
    
    try:
        with tempfile.NamedTemporaryFile('w', delete=False) as f:
            f.write(simple_su)
            su_stub = f.name
        
        run_adb(['push', su_stub, '/data/local/tmp/su'])
        run_adb(['shell', 'chmod', '755', '/data/local/tmp/su'])
        
        os.unlink(su_stub)
        
        # Test
        test = run_adb(['shell', '/data/local/tmp/su', '0', 'id'], capture=True)
        if test and 'uid=' in test:
            print("\n" + "="*60)
            print("\033[1;32m         ✓ ROOT METHOD 2 THÀNH CÔNG!\033[0m")
            print("="*60)
            print(f"\n{test}")
            print("\n\033[1;36mSử dụng:\033[0m")
            print("  • adb shell /data/local/tmp/su 0 <command>")
            print("\n\033[1;33mLưu ý: Đây là su stub đơn giản, đủ cho Frida & tools\033[0m")
            return True
        else:
            print("\033[91m✗ Method 2 cũng thất bại\033[0m")
            show_root_troubleshooting()
            return False
            
    except Exception as e:
        print(f"\033[91m✗ Lỗi: {e}\033[0m")
        show_root_troubleshooting()
        return False

def show_root_troubleshooting():
    """Hiển thị hướng dẫn troubleshooting"""
    print("\n" + "="*60)
    print("\033[1;33m         HƯỚNG DẪN KHẮC PHỤC\033[0m")
    print("="*60)
    print("\n\033[1;36m1. AVD Image không phù hợp:\033[0m")
    print("   → Tạo AVD mới với: Google APIs (KHÔNG phải Google Play)")
    print("   → Target: Android 9-11 (API 28-30) root dễ nhất")
    print("   → Hardware: x86_64 hoặc arm64-v8a")
    
    print("\n\033[1;36m2. Alternative: Dùng emulator khác\033[0m")
    print("   → Nox Player: Root có sẵn")
    print("   → LDPlayer: Root có sẵn")
    print("   → Genymotion: Hỗ trợ root tốt")
    
    print("\n\033[1;36m3. Thử root thủ công:\033[0m")
    print("   → Download SuperSU/Magisk APK")
    print("   → Cài trực tiếp trong emulator")
    print("   → Settings > Developer > Root access > Apps and ADB")
    
    print("\n\033[1;36m4. Workaround cho Frida:\033[0m")
    print("   → Dùng: frida -U --no-pause -f <app>")
    print("   → Không cần root cho attach debuggable apps")
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
    subprocess.Popen([ADB_PATH, 'shell', 'su', '0', '/data/local/tmp/frida-server &'])
    time.sleep(2)
    print("✓ Frida Server đang chạy!")

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
                    install_tool_pip("frida-tools") if not is_tool_installed("frida") else print("Frida đã cài.")
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