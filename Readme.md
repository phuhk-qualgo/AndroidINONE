# AndroidINONE

AndroidINONE là một bộ công cụ tự động hóa bảo mật Android (macOS) dành cho mobile pentesting, hỗ trợ: root AVD bằng Magisk/tmpfs overlay, cài Burp CA tạm thời, cài/chạy Frida server và bypass SSL/Root checks bằng các script Frida.

## Nội dung chính
- Script chính: [AndroidINONE.py](AndroidINONE.py) — thao tác ADB, root AVD, cài Frida, cài Burp CA.
  - Các hàm chính: [`run_adb`](AndroidINONE.py), [`auto_root_avd`](AndroidINONE.py), [`burpsuite_cacert`](AndroidINONE.py), [`frida_server_install`](AndroidINONE.py), [`run_frida_command`](AndroidINONE.py), [`check_root_status`](AndroidINONE.py), [`get_avd_info`](AndroidINONE.py)
- Yêu cầu: [requirements.txt](requirements.txt)
- Frida scripts (bypass / tiện ích):
  - [Fripts/PintooR.js](Fripts/PintooR.js)
  - [Fripts/ROOTER.js](Fripts/ROOTER.js)
  - [Fripts/SSL-BYE.js](Fripts/SSL-BYE.js)

## Yêu cầu trước khi chạy
- macOS, Python 3.x
- Android SDK platform-tools (ADB). ADB path mặc định trong script: `/Users/macbook/Library/Android/sdk/platform-tools/adb`
- Cài Python packages:
```bash
python3 -m pip install -r requirements.txt
```

## Cách dùng nhanh
1. Kết nối thiết bị/emulator với USB Debugging bật hoặc chạy AVD.
2. Chạy tool:
```bash
python3 AndroidINONE.py
```
3. Dùng menu để:
- Auto root AVD: chọn option gọi [`auto_root_avd`](AndroidINONE.py)
- Cài Burp CA tạm: chọn option gọi [`burpsuite_cacert`](AndroidINONE.py)
- Cài/Chạy Frida server: [`frida_server_install`](AndroidINONE.py) / menu Frida
- Chạy Frida bypass scripts: menu Frida sử dụng [`run_frida_command`](AndroidINONE.py) (sẽ load các file trong [Fripts/](Fripts/))

## Lưu ý quan trọng
- Nhiều thao tác (root, mount tmpfs, install cert) chỉ tạm thời và sẽ mất sau reboot.
- Sử dụng công cụ cho mục đích hợp pháp, trong phạm vi kiểm thử được phép.
- Đọc kỹ log và troubleshooting trong script nếu thao tác thất bại.

## Tham khảo file & hàm
- Script chính: [AndroidINONE.py](AndroidINONE.py)
- Phụ trợ: [requirements.txt](requirements.txt)
- Frida scripts: [Fripts/PintooR.js](Fripts/PintooR.js), [Fripts/ROOTER.js](Fripts/ROOTER.js), [Fripts/SSL-BYE.js](Fripts/SSL-BYE.js)

## Ghi chú dev
- Đường ADB được hardcode; chỉnh `ADB_PATH` trong [AndroidINONE.py](AndroidINONE.py) nếu cần.
- Các hàm xử lý chính nằm trong file: [`run_adb`](AndroidINONE.py), [`check_root_status`](AndroidINONE.py), [`get_avd_info`](AndroidINONE.py), [`auto_root_avd`](AndroidINONE.py), [`burpsuite_cacert`](AndroidINONE.py), [`frida_server_install`](AndroidINONE.py).