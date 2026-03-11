"""Vulnerability Scanner – automated comprehensive security assessment pipeline."""

import asyncio
import json
import os
import re
import tempfile
import time
import traceback
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable

from portal.core.adb import ADBManager, PackageInfo
from portal.core.analyzer import APKAnalyzer, Finding, SemgrepRunner
from portal.core.agents import AndroHunterAgent
from portal.config import SEMGREP_DIR, REPORTS_DIR, ADB_PATH


@dataclass
class ScanProgress:
    phase: str = ""
    percent: int = 0
    message: str = ""
    findings_count: int = 0


@dataclass
class ScanResult:
    scan_id: str
    package: str
    timestamp: float = 0
    duration: float = 0
    status: str = "pending"
    device_info: dict = field(default_factory=dict)
    package_info: dict = field(default_factory=dict)
    static_findings: list = field(default_factory=list)
    dynamic_findings: list = field(default_factory=list)
    network_findings: list = field(default_factory=list)
    component_findings: list = field(default_factory=list)
    hunter_findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: str = ""

    def all_findings(self) -> list:
        return self.static_findings + self.dynamic_findings + self.network_findings + self.component_findings + self.hunter_findings

    def to_dict(self) -> dict:
        d = asdict(self)
        d["total_findings"] = len(self.all_findings())
        return d


class VulnerabilityScanner:
    def __init__(self, adb: ADBManager):
        self.adb = adb
        self.apk_analyzer = APKAnalyzer()
        self.semgrep = SemgrepRunner(str(SEMGREP_DIR))
        self.hunter = AndroHunterAgent(ADB_PATH)
        self._active_scans: dict[str, ScanResult] = {}

    async def _safe_shell(self, cmd: str, timeout: int = 10) -> str:
        """Shell command that never hangs."""
        try:
            return await asyncio.wait_for(
                self.adb.shell(cmd, timeout=timeout), timeout=timeout + 2
            )
        except (asyncio.TimeoutError, Exception):
            return ""

    async def full_scan(
        self,
        package: str,
        scan_id: str,
        progress_cb: Optional[Callable] = None,
        include_dynamic: bool = True,
    ) -> ScanResult:
        result = ScanResult(
            scan_id=scan_id,
            package=package,
            timestamp=time.time(),
            status="running",
        )
        self._active_scans[scan_id] = result

        async def report(phase, pct, msg):
            if progress_cb:
                try:
                    await progress_cb(ScanProgress(
                        phase=phase, percent=pct, message=msg,
                        findings_count=len(result.all_findings()),
                    ))
                except Exception:
                    pass

        try:
            # Phase 1: Device info (5%)
            await report("init", 5, "Gathering device info...")
            try:
                dev = await asyncio.wait_for(self.adb.get_device_info(), timeout=10)
                result.device_info = {
                    "serial": dev.serial, "model": dev.model,
                    "android_version": dev.android_version,
                    "api_level": dev.api_level, "arch": dev.arch,
                    "is_rooted": dev.is_rooted, "selinux": dev.selinux,
                }
            except Exception:
                result.device_info = {"error": "Could not get device info"}

            # Phase 2: Package info (10%)
            await report("package_info", 10, f"Getting package info for {package}...")
            pkg_info = None
            try:
                pkg_info = await asyncio.wait_for(self.adb.get_package_info(package), timeout=15)
                result.package_info = asdict(pkg_info)
            except Exception:
                result.package_info = {"package_name": package}

            # Phase 3: Pull APK + Static Analysis (15-40%)
            await report("pull_apk", 15, "Pulling APK from device...")
            apk_dest = os.path.join(tempfile.gettempdir(), f"{package}.apk")
            try:
                pulled = await asyncio.wait_for(self.adb.pull_apk(package, apk_dest), timeout=60)
            except Exception:
                pulled = False

            if pulled and os.path.exists(apk_dest):
                await report("static_analysis", 20, "Running static analysis...")
                try:
                    analysis = self.apk_analyzer.analyze(apk_dest)
                    for f in analysis.findings:
                        result.static_findings.append(asdict(f))
                    for s in analysis.secrets:
                        result.static_findings.append({
                            "severity": "CRITICAL",
                            "category": "Hardcoded Secrets",
                            "title": s["type"],
                            "description": f"Found in {s['location']}",
                            "evidence": s["value"][:100],
                            "location": s["location"],
                            "recommendation": "Remove hardcoded secrets; use Android Keystore",
                        })
                except Exception:
                    pass
                await report("static_analysis", 35, f"Found {len(result.static_findings)} static findings")

            # Phase 4: Component scan (40-55%)
            await report("component_scan", 40, "Scanning exported components...")
            await self._scan_components(package, result)

            # Phase 5: Dynamic checks (55-80%)
            if include_dynamic:
                await report("dynamic_checks", 55, "Running dynamic checks...")
                await self._dynamic_checks(package, result, report)

            # Phase 6: Permission audit (80%)
            await report("permission_audit", 80, "Auditing permissions...")
            if pkg_info:
                await self._permission_audit(package, pkg_info, result)

            # Phase 7: Network (85%)
            await report("network_checks", 85, "Checking network...")
            await self._network_checks(package, result)

            # Phase 8: Logcat (90%)
            await report("logcat_scan", 85, "Scanning logcat...")
            await self._logcat_scan(package, result)

            # Phase 9: Hunter (90-98%)
            await report("hunter_scan", 90, "Running Hunter security tests...")
            await self._hunter_scan(package, result, report, apk_dest if pulled else None)

            # Done
            result.summary = self._generate_summary(result)
            result.status = "completed"
            result.duration = time.time() - result.timestamp
            await report("complete", 100, f"Done! {len(result.all_findings())} findings")
            self._save_result(result)

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.summary = self._generate_summary(result)
            result.summary["error"] = str(e)
            result.duration = time.time() - result.timestamp
            self._save_result(result)

        return result

    async def _scan_components(self, package: str, result: ScanResult):
        out = await self._safe_shell(f"dumpsys package {package}", timeout=10)
        if not out:
            return

        exported_activities = []
        exported_services = []
        exported_receivers = []
        exported_providers = []

        for line in out.splitlines():
            stripped = line.strip()
            if "exported=true" in stripped:
                if "Activity" in stripped or "activity" in stripped:
                    exported_activities.append(stripped)
                elif "Service" in stripped or "service" in stripped:
                    exported_services.append(stripped)
                elif "Receiver" in stripped or "receiver" in stripped:
                    exported_receivers.append(stripped)
                elif "Provider" in stripped or "provider" in stripped:
                    exported_providers.append(stripped)

        total_exported = len(exported_activities) + len(exported_services) + len(exported_receivers) + len(exported_providers)

        if total_exported > 5:
            result.component_findings.append({
                "severity": "HIGH",
                "category": "Attack Surface",
                "title": f"{total_exported} exported components ({len(exported_activities)} activities, {len(exported_services)} services, {len(exported_receivers)} receivers, {len(exported_providers)} providers)",
                "description": "Large number of exported components increases attack surface",
                "location": "AndroidManifest.xml",
                "recommendation": "Minimize exported components; add permission checks",
            })
        elif total_exported > 0:
            result.component_findings.append({
                "severity": "MEDIUM",
                "category": "Attack Surface",
                "title": f"{total_exported} exported component(s)",
                "description": f"Activities: {len(exported_activities)}, Services: {len(exported_services)}, Receivers: {len(exported_receivers)}, Providers: {len(exported_providers)}",
                "location": "AndroidManifest.xml",
            })

        if "DEBUGGABLE" in out.upper():
            result.component_findings.append({
                "severity": "CRITICAL",
                "category": "Configuration",
                "title": "Application is debuggable",
                "description": "Debugger can be attached to the running process",
                "location": "AndroidManifest.xml",
                "recommendation": "Set android:debuggable=false in release builds",
            })

        if "allowBackup=true" in out.lower():
            result.component_findings.append({
                "severity": "HIGH",
                "category": "Configuration",
                "title": "Backup allowed (allowBackup=true)",
                "description": "App data can be extracted via adb backup",
                "location": "AndroidManifest.xml",
                "recommendation": "Set android:allowBackup=false",
            })

    async def _dynamic_checks(self, package: str, result: ScanResult, report):
        sensitive_keys = ["token", "password", "secret", "api_key", "session",
                          "jwt", "cookie", "auth", "credential", "pin", "otp"]

        # SharedPreferences
        await report("dynamic_checks", 60, "Checking SharedPreferences...")
        prefs = await self._safe_shell(f"run-as {package} ls shared_prefs/ 2>/dev/null", timeout=5)
        if not prefs or "No such" in prefs or "not debuggable" in prefs:
            prefs = await self._safe_shell(f"su 0 ls /data/data/{package}/shared_prefs/ 2>/dev/null", timeout=5)

        if prefs and "No such" not in prefs and "not debuggable" not in prefs:
            for pref_file in prefs.splitlines()[:10]:
                pref_file = pref_file.strip()
                if not pref_file or not pref_file.endswith(".xml"):
                    continue
                content = await self._safe_shell(
                    f"run-as {package} cat shared_prefs/{pref_file} 2>/dev/null", timeout=5
                )
                if not content:
                    content = await self._safe_shell(
                        f"su 0 cat /data/data/{package}/shared_prefs/{pref_file} 2>/dev/null", timeout=5
                    )
                if content:
                    for key in sensitive_keys:
                        if key.lower() in content.lower():
                            result.dynamic_findings.append({
                                "severity": "HIGH",
                                "category": "Insecure Data Storage",
                                "title": f"Sensitive data '{key}' in SharedPreferences: {pref_file}",
                                "description": f"Cleartext '{key}' found in SharedPreferences",
                                "evidence": content[:150],
                                "location": f"shared_prefs/{pref_file}",
                                "recommendation": "Use EncryptedSharedPreferences or Android Keystore",
                            })
                            break

        # Databases
        await report("dynamic_checks", 70, "Checking databases...")
        dbs = await self._safe_shell(f"run-as {package} ls databases/ 2>/dev/null", timeout=5)
        if not dbs or "No such" in dbs:
            dbs = await self._safe_shell(f"su 0 ls /data/data/{package}/databases/ 2>/dev/null", timeout=5)
        if dbs and "No such" not in dbs:
            for db in dbs.splitlines():
                db = db.strip()
                if db and (db.endswith(".db") or db.endswith(".sqlite")):
                    result.dynamic_findings.append({
                        "severity": "MEDIUM",
                        "category": "Insecure Data Storage",
                        "title": f"Unencrypted database: {db}",
                        "description": "SQLite database may contain sensitive data in cleartext",
                        "location": f"databases/{db}",
                        "recommendation": "Use SQLCipher for encrypted database storage",
                    })

        # External storage
        await report("dynamic_checks", 75, "Checking external storage...")
        ext = await self._safe_shell(f"ls /sdcard/Android/data/{package}/ 2>/dev/null", timeout=5)
        if ext and "No such" not in ext and ext.strip():
            result.dynamic_findings.append({
                "severity": "MEDIUM",
                "category": "Insecure Data Storage",
                "title": "Data stored on external storage",
                "description": f"Files on /sdcard/Android/data/{package}/",
                "evidence": ext[:200],
                "location": f"/sdcard/Android/data/{package}/",
                "recommendation": "Avoid storing sensitive data on external storage",
            })

    async def _permission_audit(self, package: str, pkg_info: PackageInfo, result: ScanResult):
        from portal.core.analyzer import DANGEROUS_PERMISSIONS
        for perm in pkg_info.permissions:
            if perm in DANGEROUS_PERMISSIONS:
                result.static_findings.append({
                    "severity": "MEDIUM",
                    "category": "Dangerous Permission",
                    "title": f"{perm.split('.')[-1]}",
                    "description": f"App requests dangerous permission {perm}",
                    "location": "AndroidManifest.xml",
                })

    async def _network_checks(self, package: str, result: ScanResult):
        dump = await self._safe_shell(f"dumpsys package {package} | grep -i cleartext", timeout=5)
        if dump and "true" in dump.lower():
            result.network_findings.append({
                "severity": "HIGH",
                "category": "Insecure Communication",
                "title": "Cleartext traffic allowed",
                "description": "usesCleartextTraffic=true allows unencrypted HTTP",
                "location": "AndroidManifest.xml",
                "recommendation": "Set usesCleartextTraffic=false and use HTTPS",
            })

        dump2 = await self._safe_shell(f"dumpsys package {package} | grep networkSecurityConfig", timeout=5)
        if not dump2 or "networkSecurityConfig" not in (dump2 or ""):
            result.network_findings.append({
                "severity": "MEDIUM",
                "category": "Insecure Communication",
                "title": "No Network Security Config",
                "description": "Missing network_security_config.xml",
                "location": "AndroidManifest.xml",
                "recommendation": "Add network security config to restrict CAs and pin certificates",
            })

    async def _logcat_scan(self, package: str, result: ScanResult):
        logs = await self._safe_shell(f"logcat -d -t 200", timeout=8)
        if not logs:
            return
        patterns = [
            (r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+", "Password leak in logcat"),
            (r"(?i)(token|jwt|session_id)\s*[:=]\s*\S+", "Token leak in logcat"),
            (r"(?i)(api_key|apikey|secret)\s*[:=]\s*\S+", "API key leak in logcat"),
            (r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer token in logcat"),
        ]
        for pat, title in patterns:
            try:
                matches = re.findall(pat, logs)
                if matches:
                    result.dynamic_findings.append({
                        "severity": "HIGH",
                        "category": "Information Disclosure",
                        "title": title,
                        "description": f"{len(matches)} sensitive data matches in logcat",
                        "location": "logcat",
                        "recommendation": "Remove sensitive logging in production builds",
                    })
            except Exception:
                pass

    async def _hunter_scan(self, package: str, result: ScanResult, report, apk_path: str = None):
        """Run all AndroHunter modules: intents, providers, broadcasts, task hijack, FileProvider, DEX secrets."""
        try:
            await report("hunter_scan", 90, "Fuzzing intents...")
            try:
                intent_r = await asyncio.wait_for(
                    self.hunter.fuzz_intents(package), timeout=90
                )
                result.hunter_findings.extend(intent_r.get("findings", []))
            except Exception:
                pass

            await report("hunter_scan", 92, "Fuzzing content providers...")
            try:
                provider_r = await asyncio.wait_for(
                    self.hunter.fuzz_providers(package), timeout=60
                )
                result.hunter_findings.extend(provider_r.get("findings", []))
            except Exception:
                pass

            await report("hunter_scan", 94, "Fuzzing broadcasts...")
            try:
                broadcast_r = await asyncio.wait_for(
                    self.hunter.fuzz_broadcasts(package), timeout=60
                )
                result.hunter_findings.extend(broadcast_r.get("findings", []))
            except Exception:
                pass

            await report("hunter_scan", 95, "Checking StrandHogg...")
            try:
                hijack_r = await asyncio.wait_for(
                    self.hunter.check_task_hijack(package), timeout=30
                )
                result.hunter_findings.extend(hijack_r.get("findings", []))
            except Exception:
                pass

            if apk_path and os.path.exists(apk_path):
                await report("hunter_scan", 96, "Analyzing FileProvider...")
                try:
                    fp_r = await asyncio.wait_for(
                        self.hunter.analyze_fileproviders(package, apk_path), timeout=30
                    )
                    result.hunter_findings.extend(fp_r.get("findings", []))
                except Exception:
                    pass

                await report("hunter_scan", 97, "Scanning DEX secrets...")
                try:
                    dex_r = await asyncio.wait_for(
                        self.hunter.scan_dex_secrets(apk_path), timeout=60
                    )
                    result.hunter_findings.extend(dex_r.get("findings", []))
                except Exception:
                    pass

            await report("hunter_scan", 98, f"Hunter found {len(result.hunter_findings)} issues")
        except Exception:
            pass

    def _generate_summary(self, result: ScanResult) -> dict:
        all_findings = result.all_findings()
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        category_counts = {}

        for f in all_findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = f.get("category", "Other")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        risk_score = (
            severity_counts["CRITICAL"] * 10 +
            severity_counts["HIGH"] * 7 +
            severity_counts["MEDIUM"] * 4 +
            severity_counts["LOW"] * 1
        )
        risk_level = (
            "CRITICAL" if risk_score >= 50 else
            "HIGH" if risk_score >= 30 else
            "MEDIUM" if risk_score >= 15 else
            "LOW" if risk_score >= 5 else
            "PASS"
        )

        return {
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "scan_duration": result.duration,
        }

    def _save_result(self, result: ScanResult):
        REPORTS_DIR.mkdir(exist_ok=True)
        path = REPORTS_DIR / f"scan_{result.scan_id}.json"
        with open(path, "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        return self._active_scans.get(scan_id)

    def list_scans(self) -> list[dict]:
        scans = []
        seen = set()
        for sid, sr in self._active_scans.items():
            seen.add(sid)
            scans.append({
                "scan_id": sid,
                "package": sr.package,
                "status": sr.status,
                "timestamp": sr.timestamp,
                "finding_count": len(sr.all_findings()),
                "risk_level": sr.summary.get("risk_level", ""),
            })
        if REPORTS_DIR.exists():
            for f in REPORTS_DIR.glob("scan_*.json"):
                sid = f.stem.replace("scan_", "")
                if sid in seen:
                    continue
                try:
                    data = json.loads(f.read_text())
                    scans.append({
                        "scan_id": sid,
                        "package": data.get("package", ""),
                        "status": data.get("status", "completed"),
                        "timestamp": data.get("timestamp", 0),
                        "finding_count": data.get("total_findings", 0),
                        "risk_level": data.get("summary", {}).get("risk_level", ""),
                    })
                except Exception:
                    pass
        return sorted(scans, key=lambda x: x["timestamp"], reverse=True)
