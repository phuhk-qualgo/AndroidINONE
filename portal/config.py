import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PORTAL_DIR = Path(__file__).resolve().parent

ANDROID_SDK = os.path.expanduser("~/Library/Android/sdk")
ADB_PATH = os.path.join(ANDROID_SDK, "platform-tools", "adb")
EMULATOR_PATH = os.path.join(ANDROID_SDK, "emulator", "emulator")
AAPT2_PATH = os.path.join(ANDROID_SDK, "build-tools")

FRIPTS_DIR = BASE_DIR / "Fripts"
FRIDUMP_DIR = BASE_DIR / "fridump"
MEDUSA_DIR = BASE_DIR / "medusa"
SEMGREP_DIR = BASE_DIR / "semgrep-android"
OWASP_DIR = BASE_DIR / "top10_owasp"
REPORTS_DIR = BASE_DIR / "reports"
UPLOADS_DIR = BASE_DIR / "uploads"
DB_PATH = BASE_DIR / "androidinone.db"

for d in [REPORTS_DIR, UPLOADS_DIR]:
    d.mkdir(exist_ok=True)

FRIDA_SCRIPTS = {
    "ssl_bypass": FRIPTS_DIR / "SSL-BYE.js",
    "root_bypass": FRIPTS_DIR / "ROOTER.js",
    "combined_bypass": FRIPTS_DIR / "PintooR.js",
    "dex_dump": FRIPTS_DIR / "dex_dump.js",
    "hook_list": FRIPTS_DIR / "hook_list.js",
    "hunter_hooks": FRIPTS_DIR / "hunter_hooks.js",
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff1744",
    "HIGH": "#ff5722",
    "MEDIUM": "#ff9800",
    "LOW": "#ffc107",
    "INFO": "#2196f3",
}

PORTAL_HOST = "0.0.0.0"
PORTAL_PORT = 1337
