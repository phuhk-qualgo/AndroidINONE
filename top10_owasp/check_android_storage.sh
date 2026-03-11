#!/bin/bash
PACKAGE="com.qualgo.kchat"   # thay bằng package name thật
echo "=== Kiểm tra MASVS-STORAGE cho $PACKAGE ==="

echo -e "\n1. Backup có chứa sensitive data? (MASVS-STORAGE-2 - Testing Backups)"
adb shell pm dump $PACKAGE | grep -i "allowBackup\|android:allowBackup"
adb backup -f backup.ab -apk $PACKAGE   # thử backup → sau đó convert ab → tar và kiểm tra
# hoặc dùng android-backup-extractor để extract và grep sensitive strings

echo -e "\n2. Logcat có leak sensitive data? (Testing Logs for Sensitive Data)"
adb logcat | grep -i -E "password|token|api_key|secret|auth|pin|otp|credit|card" &  # chạy background, tương tác app

echo -e "\n3. Tìm sensitive strings trong APK (static) (SharedPrefs, SQLite, files)"
# Decompile hoặc dùng MobSF
strings app.apk | grep -i -E "password|token|key|secret|bearer|auth" > strings_sensitive.txt
jadx app.apk -d decompiled  # rồi grep trong decompiled/
grep -r -i "password\|token\|secret\|key" decompiled/

echo -e "\n4. Kiểm tra SharedPreferences có cleartext (MASVS-STORAGE-1)"
adb shell "run-as $PACKAGE cat /data/data/$PACKAGE/shared_prefs/*.xml" 2>/dev/null | grep -i "password\|token\|key"

echo -e "\n5. Kiểm tra file trong /data/data/$PACKAGE (Internal Storage)"
adb shell "run-as $PACKAGE ls -la /data/data/$PACKAGE/files /data/data/$PACKAGE/databases"
adb shell "run-as $PACKAGE cat /data/data/$PACKAGE/databases/*.db" | strings | grep -i "pass\|token"

echo -e "\n6. External Storage leak?"
adb shell "ls -la /sdcard/Android/data/$PACKAGE" 2>/dev/null
adb shell "find /sdcard/ -name '*${PACKAGE}*'" 2>/dev/null

echo -e "\n7. Keyboard cache? (thường disable bằng android:importantForAutofill)"
# Static: grep AndroidManifest.xml hoặc source code cho text fields

echo -e "\n8. Memory dump với Frida (tìm sensitive in runtime)"
# Ví dụ: objection -g $PACKAGE explore --startup-command "android sslpinning disable"
objection -n $PACKAGE explore --startup-command "memory dump all"  # rồi grep trong dump
grep -r -i "password\|token\|key" ./objection_data/memory_dumps/
echo -e "\n=== Kết thúc kiểm tra MASVS-STORAGE cho $PACKAGE ==="