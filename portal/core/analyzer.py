"""APK Analyzer – static analysis: manifest parsing, DEX scanning, secrets detection, permissions audit."""

import os
import re
import struct
import zipfile
import hashlib
import tempfile
from dataclasses import dataclass, field
from typing import Optional
from xml.etree import ElementTree as ET


ANDROID_NS = "http://schemas.android.com/apk/res/android"

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.SEND_SMS", "android.permission.READ_SMS",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.BODY_SENSORS", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
}

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"[Aa][Ww][Ss].{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Firebase URL": r"https://[\w-]+\.firebaseio\.com",
    "Firebase API Key": r"(?i)(firebase|fcm).{0,20}(key|api|token).{0,10}['\"][A-Za-z0-9_\-]{20,}['\"]",
    "Generic API Key": r"(?i)(api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    "Generic Token": r"(?i)(token|secret|password|passwd|pwd)\s*[=:]\s*['\"][^\s'\"]{8,}['\"]",
    "Generic Secret": r"(?i)(secret|private_key|client_secret)\s*[=:]\s*['\"][^\s'\"]{8,}['\"]",
    "Private Key PEM": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Base64 JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Hardcoded IP": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "URL with Credentials": r"https?://[^/\s:]+:[^/\s@]+@[^/\s]+",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "Telegram Bot Token": r"\d{5,}:AA[0-9A-Za-z\-_]{33}",
    "Stripe Key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
    "Square OAuth": r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Azure Storage Key": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "MongoDB URI": r"mongodb(\+srv)?://[^\s\"']+",
}

INSECURE_CODE_PATTERNS = {
    "WebView JavaScript enabled": r"setJavaScriptEnabled\s*\(\s*true\s*\)",
    "WebView addJavascriptInterface": r"addJavascriptInterface\s*\(",
    "Insecure WebViewClient": r"onReceivedSslError.*proceed",
    "World readable/writable": r"MODE_WORLD_(READABLE|WRITABLE)",
    "Hardcoded AES key": r"SecretKeySpec\s*\(",
    "Weak hash (MD5)": r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']\s*\)",
    "Weak hash (SHA1)": r"MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']\s*\)",
    "SQL raw query": r"rawQuery\s*\(|execSQL\s*\(",
    "Dynamic DEX loading": r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader",
    "Reflection usage": r"Class\.forName\s*\(|\.getDeclaredMethod\s*\(",
    "Clipboard access": r"ClipboardManager|setPrimaryClip",
    "Logging sensitive data": r"Log\.(d|v|i|w|e)\s*\(",
    "Backup enabled": r"android:allowBackup\s*=\s*[\"']true[\"']",
    "Debuggable": r"android:debuggable\s*=\s*[\"']true[\"']",
    "Cleartext traffic": r"android:usesCleartextTraffic\s*=\s*[\"']true[\"']",
    "Exported component": r"android:exported\s*=\s*[\"']true[\"']",
    "Intent scheme URL": r"intent://",
    "JavaScript bridge": r"@JavascriptInterface",
    "Root detection": r"(?i)(su|supersu|superuser|magisk|rootbeer)",
    "Emulator detection": r"(?i)(goldfish|ranchu|generic.*sdk|emulator|genymotion)",
}


@dataclass
class Finding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    location: str = ""
    evidence: str = ""
    recommendation: str = ""
    cvss: float = 0.0


@dataclass
class ManifestInfo:
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: list = field(default_factory=list)
    activities: list = field(default_factory=list)
    services: list = field(default_factory=list)
    receivers: list = field(default_factory=list)
    providers: list = field(default_factory=list)
    exported_components: list = field(default_factory=list)
    deeplinks: list = field(default_factory=list)
    allow_backup: bool = False
    debuggable: bool = False
    cleartext_traffic: bool = False
    network_security_config: str = ""
    raw_xml: str = ""


@dataclass
class AnalysisResult:
    apk_path: str
    package: str = ""
    sha256: str = ""
    file_size: int = 0
    manifest: Optional[ManifestInfo] = None
    findings: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    dex_classes: list = field(default_factory=list)
    dex_strings: list = field(default_factory=list)
    certificates: list = field(default_factory=list)


class APKAnalyzer:

    def __init__(self):
        pass

    def analyze(self, apk_path: str) -> AnalysisResult:
        result = AnalysisResult(apk_path=apk_path)

        if not os.path.exists(apk_path):
            result.findings.append(Finding(
                severity="CRITICAL", category="Error",
                title="APK not found", description=f"File not found: {apk_path}"
            ))
            return result

        result.file_size = os.path.getsize(apk_path)
        result.sha256 = self._sha256(apk_path)

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                try:
                    result.manifest = self._parse_manifest(zf)
                except Exception as e:
                    result.findings.append(Finding(
                        severity="INFO", category="Parser",
                        title="Manifest parsing partial failure",
                        description=f"Binary XML decode issue: {e}",
                    ))
                    result.manifest = ManifestInfo()

                if result.manifest:
                    result.package = result.manifest.package
                    try:
                        self._audit_manifest(result)
                    except Exception:
                        pass

                try:
                    self._scan_dex_files(zf, result)
                except Exception:
                    pass
                try:
                    self._scan_resources(zf, result)
                except Exception:
                    pass
                try:
                    self._check_certificates(zf, result)
                except Exception:
                    pass
                try:
                    self._check_file_structure(zf, result)
                except Exception:
                    pass

        except zipfile.BadZipFile:
            result.findings.append(Finding(
                severity="CRITICAL", category="Error",
                title="Invalid APK", description="File is not a valid ZIP/APK"
            ))
        except Exception as e:
            result.findings.append(Finding(
                severity="INFO", category="Error",
                title="Analysis error", description=str(e),
            ))

        return result

    def _sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _parse_manifest(self, zf: zipfile.ZipFile) -> Optional[ManifestInfo]:
        if "AndroidManifest.xml" not in zf.namelist():
            return None

        raw = zf.read("AndroidManifest.xml")
        xml_text = self._decode_binary_xml(raw)
        if not xml_text:
            return None

        info = ManifestInfo(raw_xml=xml_text)

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            info.raw_xml = xml_text
            return info

        info.package = root.get("package", "")
        info.version_name = root.get(f"{{{ANDROID_NS}}}versionName", "")
        info.version_code = root.get(f"{{{ANDROID_NS}}}versionCode", "")

        app = root.find("application")
        if app is not None:
            info.allow_backup = app.get(f"{{{ANDROID_NS}}}allowBackup", "true").lower() == "true"
            info.debuggable = app.get(f"{{{ANDROID_NS}}}debuggable", "false").lower() == "true"
            info.cleartext_traffic = app.get(f"{{{ANDROID_NS}}}usesCleartextTraffic", "false").lower() == "true"
            info.network_security_config = app.get(f"{{{ANDROID_NS}}}networkSecurityConfig", "")

            for act in app.findall("activity") + app.findall("activity-alias"):
                name = act.get(f"{{{ANDROID_NS}}}name", "")
                exported = act.get(f"{{{ANDROID_NS}}}exported", "")
                has_filter = len(act.findall("intent-filter")) > 0
                is_exported = exported == "true" or (exported == "" and has_filter)
                info.activities.append({"name": name, "exported": is_exported})
                if is_exported:
                    info.exported_components.append({"type": "activity", "name": name})
                for intent_filter in act.findall("intent-filter"):
                    for data in intent_filter.findall("data"):
                        scheme = data.get(f"{{{ANDROID_NS}}}scheme", "")
                        host = data.get(f"{{{ANDROID_NS}}}host", "")
                        path = data.get(f"{{{ANDROID_NS}}}path", "")
                        if scheme:
                            info.deeplinks.append(f"{scheme}://{host}{path}")

            for svc in app.findall("service"):
                name = svc.get(f"{{{ANDROID_NS}}}name", "")
                exported = svc.get(f"{{{ANDROID_NS}}}exported", "false") == "true"
                info.services.append({"name": name, "exported": exported})
                if exported:
                    info.exported_components.append({"type": "service", "name": name})

            for rcv in app.findall("receiver"):
                name = rcv.get(f"{{{ANDROID_NS}}}name", "")
                exported = rcv.get(f"{{{ANDROID_NS}}}exported", "")
                has_filter = len(rcv.findall("intent-filter")) > 0
                is_exported = exported == "true" or (exported == "" and has_filter)
                info.receivers.append({"name": name, "exported": is_exported})
                if is_exported:
                    info.exported_components.append({"type": "receiver", "name": name})

            for prov in app.findall("provider"):
                name = prov.get(f"{{{ANDROID_NS}}}name", "")
                auth = prov.get(f"{{{ANDROID_NS}}}authorities", "")
                exported = prov.get(f"{{{ANDROID_NS}}}exported", "false") == "true"
                grant_uri = prov.get(f"{{{ANDROID_NS}}}grantUriPermissions", "false") == "true"
                info.providers.append({
                    "name": name, "authorities": auth,
                    "exported": exported, "grantUriPermissions": grant_uri,
                })
                if exported:
                    info.exported_components.append({"type": "provider", "name": name, "authorities": auth})

        for perm in root.findall("uses-permission"):
            name = perm.get(f"{{{ANDROID_NS}}}name", "")
            if name:
                info.permissions.append(name)

        return info

    def _decode_binary_xml(self, data: bytes) -> Optional[str]:
        """Attempt to decode binary Android XML. Falls back to raw decode."""
        if data[:4] == b"<?xm" or data[:5] == b"<?xml":
            return data.decode("utf-8", errors="replace")

        try:
            from xml.etree.ElementTree import Element, SubElement, tostring

            idx = data.find(b"<?xml")
            if idx > 0:
                return data[idx:].decode("utf-8", errors="replace")

            text = data.decode("utf-8", errors="replace")
            if "<manifest" in text:
                start = text.find("<manifest")
                return text[start:]

        except Exception:
            pass

        printable = "".join(
            chr(b) if 32 <= b < 127 else " " for b in data
        )
        tags = re.findall(r"<[^>]+>", printable)
        if tags:
            return "\n".join(tags)

        return None

    def _audit_manifest(self, result: AnalysisResult):
        m = result.manifest
        if not m:
            return

        if m.allow_backup:
            result.findings.append(Finding(
                severity="HIGH", category="Data Storage",
                title="Application backup enabled",
                description="android:allowBackup=true allows data extraction via adb backup",
                location="AndroidManifest.xml",
                recommendation="Set android:allowBackup=\"false\" or implement BackupAgent",
                cvss=6.5,
            ))

        if m.debuggable:
            result.findings.append(Finding(
                severity="CRITICAL", category="Code Quality",
                title="Application is debuggable",
                description="android:debuggable=true allows attaching debugger and extracting data",
                location="AndroidManifest.xml",
                recommendation="Remove android:debuggable or set to false in release builds",
                cvss=9.0,
            ))

        if m.cleartext_traffic:
            result.findings.append(Finding(
                severity="HIGH", category="Network Security",
                title="Cleartext traffic allowed",
                description="android:usesCleartextTraffic=true allows HTTP connections",
                location="AndroidManifest.xml",
                recommendation="Set usesCleartextTraffic=\"false\" and use HTTPS",
                cvss=7.0,
            ))

        if not m.network_security_config:
            result.findings.append(Finding(
                severity="MEDIUM", category="Network Security",
                title="No Network Security Config",
                description="App does not define a networkSecurityConfig",
                location="AndroidManifest.xml",
                recommendation="Add a network_security_config.xml to restrict CA certificates",
                cvss=4.0,
            ))

        for comp in m.exported_components:
            sev = "HIGH" if comp["type"] in ("provider", "service") else "MEDIUM"
            result.findings.append(Finding(
                severity=sev, category="Exposed Components",
                title=f"Exported {comp['type']}: {comp['name']}",
                description=f"Component is exported and accessible to other apps",
                location="AndroidManifest.xml",
                recommendation="Set android:exported=\"false\" or add permission requirements",
                cvss=6.0 if sev == "HIGH" else 4.5,
            ))

        dangerous = [p for p in m.permissions if p in DANGEROUS_PERMISSIONS]
        if dangerous:
            result.findings.append(Finding(
                severity="MEDIUM", category="Permissions",
                title=f"{len(dangerous)} dangerous permissions requested",
                description="Dangerous permissions: " + ", ".join(dangerous),
                location="AndroidManifest.xml",
                recommendation="Review if all dangerous permissions are necessary",
                cvss=3.5,
            ))

        if m.target_sdk and m.target_sdk < 30:
            result.findings.append(Finding(
                severity="MEDIUM", category="Configuration",
                title=f"Low targetSdkVersion ({m.target_sdk})",
                description="Targeting old SDK misses security improvements",
                location="AndroidManifest.xml",
                recommendation="Update targetSdkVersion to latest stable",
                cvss=4.0,
            ))

        if m.min_sdk and m.min_sdk < 24:
            result.findings.append(Finding(
                severity="LOW", category="Configuration",
                title=f"Low minSdkVersion ({m.min_sdk})",
                description="Supporting old Android versions may expose to known vulnerabilities",
                location="AndroidManifest.xml",
                recommendation="Consider raising minSdkVersion to 24+",
            ))

        for dl in m.deeplinks:
            if dl.startswith("http://"):
                result.findings.append(Finding(
                    severity="HIGH", category="Deep Links",
                    title=f"HTTP deep link: {dl}",
                    description="Deep link uses HTTP scheme, vulnerable to hijacking",
                    location="AndroidManifest.xml",
                    recommendation="Use HTTPS or app-specific schemes with verification",
                    cvss=6.5,
                ))
            else:
                result.findings.append(Finding(
                    severity="INFO", category="Deep Links",
                    title=f"Deep link: {dl}",
                    description="Custom scheme deep link found",
                    location="AndroidManifest.xml",
                ))

    def _scan_dex_files(self, zf: zipfile.ZipFile, result: AnalysisResult):
        compiled_secrets = {}
        for name, pat in SECRET_PATTERNS.items():
            try:
                compiled_secrets[name] = re.compile(pat)
            except re.error:
                pass
        compiled_insecure = {}
        for name, pat in INSECURE_CODE_PATTERNS.items():
            try:
                compiled_insecure[name] = re.compile(pat)
            except re.error:
                pass

        dex_files = [n for n in zf.namelist() if n.endswith(".dex")]
        for dex_name in dex_files:
            try:
                data = zf.read(dex_name)
            except Exception:
                continue
            strings = self._extract_dex_strings(data)
            result.dex_strings.extend(strings[:500])

            for pattern_name, compiled in compiled_secrets.items():
                found_for_pattern = 0
                for s in strings:
                    try:
                        if compiled.search(s):
                            result.secrets.append({
                                "type": pattern_name,
                                "value": s[:200],
                                "location": dex_name,
                            })
                            result.findings.append(Finding(
                                severity="CRITICAL" if "key" in pattern_name.lower() or "private" in pattern_name.lower() else "HIGH",
                                category="Hardcoded Secrets",
                                title=f"{pattern_name} found in {dex_name}",
                                description=f"Potential secret: {s[:100]}",
                                location=dex_name,
                                recommendation="Remove hardcoded secrets; use Android Keystore or env variables",
                                cvss=8.0,
                            ))
                            found_for_pattern += 1
                            if found_for_pattern >= 5:
                                break
                    except Exception:
                        continue

            for pattern_name, compiled in compiled_insecure.items():
                for s in strings:
                    try:
                        if compiled.search(s):
                            result.findings.append(Finding(
                                severity="MEDIUM",
                                category="Insecure Code",
                                title=f"{pattern_name} in {dex_name}",
                                description=f"Pattern match: {s[:100]}",
                                location=dex_name,
                                recommendation="Review and fix insecure code pattern",
                            ))
                            break
                    except Exception:
                        continue

    def _extract_dex_strings(self, data: bytes) -> list[str]:
        strings = []
        try:
            current = []
            for byte in data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= 6:
                        strings.append("".join(current))
                    current = []
            if len(current) >= 6:
                strings.append("".join(current))
        except Exception:
            pass
        return strings

    def _scan_resources(self, zf: zipfile.ZipFile, result: AnalysisResult):
        for name in zf.namelist():
            if name.startswith("res/xml/") and "file_provider" in name.lower():
                try:
                    content = zf.read(name).decode("utf-8", errors="replace")
                    if "root-path" in content and 'path=""' in content:
                        result.findings.append(Finding(
                            severity="CRITICAL", category="FileProvider",
                            title="FileProvider root-path with empty path",
                            description="Full filesystem access via FileProvider",
                            location=name,
                            recommendation="Restrict FileProvider paths to specific directories",
                            cvss=9.0,
                        ))
                    elif "external-path" in content and 'path=""' in content:
                        result.findings.append(Finding(
                            severity="HIGH", category="FileProvider",
                            title="FileProvider external-path with empty path",
                            description="Full external storage access via FileProvider",
                            location=name,
                            cvss=7.0,
                        ))
                except Exception:
                    pass

            if name.endswith(".xml") and "res/values" in name:
                try:
                    content = zf.read(name).decode("utf-8", errors="replace")
                    for pattern_name, pattern in SECRET_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        for match in matches[:3]:
                            val = match if isinstance(match, str) else match[0]
                            result.secrets.append({
                                "type": pattern_name,
                                "value": val[:200],
                                "location": name,
                            })
                except Exception:
                    pass

    def _check_certificates(self, zf: zipfile.ZipFile, result: AnalysisResult):
        cert_files = [n for n in zf.namelist() if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))]
        for cf in cert_files:
            result.certificates.append({"file": cf, "size": zf.getinfo(cf).file_size})

        if not cert_files:
            result.findings.append(Finding(
                severity="INFO", category="Signing",
                title="No signature files found",
                description="APK may use v2/v3 signing only",
            ))

    def _check_file_structure(self, zf: zipfile.ZipFile, result: AnalysisResult):
        names = zf.namelist()

        native_libs = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
        if native_libs:
            result.findings.append(Finding(
                severity="INFO", category="Native Code",
                title=f"{len(native_libs)} native libraries found",
                description="Native code may contain vulnerabilities not detectable by static analysis",
                evidence=", ".join(native_libs[:10]),
            ))

        asset_files = [n for n in names if n.startswith("assets/")]
        for af in asset_files:
            lower = af.lower()
            if any(ext in lower for ext in [".db", ".sqlite", ".json", ".xml", ".pem", ".key", ".p12", ".jks"]):
                result.findings.append(Finding(
                    severity="MEDIUM", category="Sensitive Assets",
                    title=f"Sensitive asset: {af}",
                    description="Asset file may contain sensitive data",
                    location=af,
                ))


class SemgrepRunner:
    """Runs semgrep rules from the semgrep-android directory against decompiled source."""

    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir

    async def scan(self, target_dir: str) -> list[Finding]:
        import shutil as sh
        if not sh.which("semgrep"):
            return [Finding(
                severity="INFO", category="Tool",
                title="Semgrep not installed",
                description="Install semgrep: pip install semgrep",
            )]

        findings = []
        import asyncio

        proc = await asyncio.create_subprocess_exec(
            "semgrep", "--config", self.rules_dir, target_dir,
            "--json", "--no-git-ignore",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        try:
            import json
            data = json.loads(stdout.decode("utf-8", errors="replace"))
            for r in data.get("results", []):
                sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                findings.append(Finding(
                    severity=sev_map.get(r.get("extra", {}).get("severity", "INFO"), "MEDIUM"),
                    category="MASVS/" + r.get("check_id", "unknown").split(".")[-1],
                    title=r.get("extra", {}).get("message", r.get("check_id", "")),
                    description=r.get("extra", {}).get("metadata", {}).get("message", ""),
                    location=f"{r.get('path', '')}:{r.get('start', {}).get('line', '')}",
                    evidence=r.get("extra", {}).get("lines", ""),
                ))
        except Exception:
            pass

        return findings
