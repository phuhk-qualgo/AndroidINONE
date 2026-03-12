"""AndroidINONE Portal – FastAPI backend with WebSocket real-time updates."""

import asyncio
import json
import os
import shutil
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from portal.config import (
    PORTAL_DIR, BASE_DIR, REPORTS_DIR, UPLOADS_DIR,
    FRIPTS_DIR, SEMGREP_DIR, FRIDA_SCRIPTS, ADB_PATH,
)
from portal.core.adb import ADBManager
from portal.core.frida_manager import FridaManager
from portal.core.analyzer import APKAnalyzer
from portal.core.scanner import VulnerabilityScanner
from portal.core.agents import AgentManager, DrozerAgent, MedusaAgent, OWASPChecker, AndroHunterAgent, _exec
from portal.core.report_engine import ReportEngine


adb = ADBManager()
frida_mgr = FridaManager()
apk_analyzer = APKAnalyzer()
scanner = VulnerabilityScanner(adb)
agent_mgr = AgentManager()
report_engine = ReportEngine()


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        for ws in self.active[:]:
            try:
                await ws.send_json(data)
            except Exception:
                self.active.remove(ws)


ws_manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(device_monitor_loop())
    yield

app = FastAPI(
    title="AndroidINONE Portal",
    description="Android Security Assessment Command Center",
    version="2.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(PORTAL_DIR / "static")), name="static")


async def device_monitor_loop():
    """Background task that broadcasts device status every 5 seconds."""
    while True:
        try:
            connected = await adb.is_connected()
            data = {"type": "device_status", "connected": connected}
            if connected:
                info = await adb.get_device_info()
                data["device"] = {
                    "serial": info.serial, "model": info.model,
                    "android_version": info.android_version,
                    "api_level": info.api_level, "arch": info.arch,
                    "is_rooted": info.is_rooted, "selinux": info.selinux,
                    "manufacturer": info.manufacturer,
                }
                frida_running = await frida_mgr.is_server_running()
                data["frida_running"] = frida_running
            await ws_manager.broadcast(data)
        except Exception:
            pass
        await asyncio.sleep(5)


# ──────────────────── MAIN PAGE ────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = PORTAL_DIR / "static" / "index.html"
    return FileResponse(str(index_path))


# ──────────────────── WEBSOCKET ────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            await handle_ws_message(ws, msg)
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)


async def handle_ws_message(ws: WebSocket, msg: dict):
    action = msg.get("action")

    if action == "ping":
        await ws.send_json({"type": "pong", "ts": time.time()})

    elif action == "shell":
        cmd = msg.get("command", "")
        if cmd:
            output = await adb.shell(cmd)
            await ws.send_json({"type": "shell_output", "command": cmd, "output": output})

    elif action == "logcat":
        lines = msg.get("lines", 100)
        filters = msg.get("filters", "")
        output = await adb.logcat(filters, lines)
        await ws.send_json({"type": "logcat", "output": output})


# ──────────────────── DEVICE API ────────────────────

@app.get("/api/device")
async def get_device():
    connected = await adb.is_connected()
    if not connected:
        return {"connected": False, "error": "No device connected"}
    info = await adb.get_device_info()
    return {"connected": True, "device": asdict(info)}


@app.get("/api/device/processes")
async def get_processes():
    return {"processes": await adb.get_running_processes()}


@app.post("/api/device/root")
async def root_device():
    success, msg = await adb.root_adb()
    return {"success": success, "message": msg}


@app.post("/api/device/shell")
async def run_shell(cmd: str = Query(...)):
    output = await adb.shell(cmd)
    return {"command": cmd, "output": output}


@app.get("/api/device/screenshot")
async def get_screenshot():
    path = await adb.screencap()
    if path:
        return FileResponse(path, media_type="image/png")
    raise HTTPException(500, "Failed to capture screenshot")


# ──────────────────── PACKAGES API ────────────────────

@app.get("/api/packages")
async def list_packages(system: bool = False):
    packages = await adb.list_packages(include_system=system)
    return {"packages": packages, "count": len(packages)}


@app.get("/api/packages/{package}")
async def get_package(package: str):
    info = await adb.get_package_info(package)
    return asdict(info)


@app.get("/api/packages/{package}/activities")
async def get_activities(package: str):
    return {"activities": await adb.get_activities(package)}


@app.post("/api/packages/{package}/pull")
async def pull_package_apk(package: str):
    dest = str(UPLOADS_DIR / f"{package}.apk")
    success = await adb.pull_apk(package, dest)
    if success:
        return {"success": True, "path": dest}
    raise HTTPException(500, "Failed to pull APK")


# ──────────────────── STATIC ANALYSIS API ────────────────────

@app.post("/api/analyze/apk")
async def analyze_apk_upload(file: UploadFile = File(...)):
    dest = str(UPLOADS_DIR / file.filename)
    with open(dest, "wb") as f:
        content = await file.read()
        f.write(content)
    result = apk_analyzer.analyze(dest)
    return {
        "package": result.package,
        "sha256": result.sha256,
        "file_size": result.file_size,
        "manifest": asdict(result.manifest) if result.manifest else None,
        "findings": [asdict(f) for f in result.findings],
        "secrets": result.secrets,
        "certificates": result.certificates,
    }


@app.post("/api/analyze/package/{package}")
async def analyze_package(package: str):
    dest = str(UPLOADS_DIR / f"{package}.apk")
    pulled = await adb.pull_apk(package, dest)
    if not pulled:
        raise HTTPException(500, f"Failed to pull APK for {package}")
    result = apk_analyzer.analyze(dest)
    return {
        "package": result.package,
        "sha256": result.sha256,
        "file_size": result.file_size,
        "manifest": asdict(result.manifest) if result.manifest else None,
        "findings": [asdict(f) for f in result.findings],
        "secrets": result.secrets,
        "certificates": result.certificates,
    }


# ──────────────────── SCANNER API ────────────────────

@app.post("/api/scan/{package}")
async def start_scan(package: str, dynamic: bool = True):
    scan_id = str(uuid.uuid4())[:8]

    async def progress_cb(progress):
        try:
            await ws_manager.broadcast({
                "type": "scan_progress",
                "scan_id": scan_id,
                "phase": progress.phase,
                "percent": progress.percent,
                "message": progress.message,
                "findings_count": progress.findings_count,
            })
        except Exception:
            pass

    async def run_scan():
        try:
            result = await scanner.full_scan(package, scan_id, progress_cb, dynamic)
            try:
                await ws_manager.broadcast({
                    "type": "scan_complete", "scan_id": scan_id,
                    "status": result.status, "findings": len(result.all_findings()),
                })
            except Exception:
                pass
        except Exception as e:
            scan = scanner.get_scan(scan_id)
            if scan:
                scan.status = "error"
                scan.error = str(e)

    asyncio.create_task(run_scan())

    return {"scan_id": scan_id, "package": package, "status": "started"}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    result = scanner.get_scan(scan_id)
    if result:
        return result.to_dict()

    report_path = REPORTS_DIR / f"scan_{scan_id}.json"
    if report_path.exists():
        return json.loads(report_path.read_text())

    raise HTTPException(404, "Scan not found")


@app.get("/api/scans")
async def list_scans():
    return {"scans": scanner.list_scans()}


# ──────────────────── FRIDA API ────────────────────

@app.get("/api/frida/status")
async def frida_status():
    version = await frida_mgr.get_frida_version()
    running = await frida_mgr.is_server_running()
    port_ok = await frida_mgr.check_server_port()
    return {
        "installed": version is not None,
        "version": version,
        "running": running,
        "server_running": running,
        "port_listening": port_ok,
    }


@app.post("/api/frida/install")
async def frida_install():
    async def progress_cb(phase, pct, msg):
        await ws_manager.broadcast({
            "type": "frida_progress",
            "phase": phase, "percent": pct, "message": msg,
        })
    success, msg = await frida_mgr.install_server(progress_cb)
    return {"success": success, "message": msg}


@app.post("/api/frida/start")
async def frida_start():
    success, msg = await frida_mgr.start_server()
    return {"success": success, "message": msg}


@app.post("/api/frida/stop")
async def frida_stop():
    success, msg = await frida_mgr.stop_server()
    return {"success": success, "message": msg}


@app.get("/api/frida/processes")
async def frida_processes():
    return {"processes": await frida_mgr.list_processes()}


@app.get("/api/frida/scripts")
async def frida_scripts():
    return {"scripts": frida_mgr.get_available_scripts()}


@app.post("/api/frida/run")
async def frida_run(package: str, script: str, spawn: bool = True, timeout: int = 30):
    success, msg, logs = await frida_mgr.run_script(package, script, spawn=spawn, timeout=timeout)
    return {"success": success, "message": msg, "logs": logs}


@app.post("/api/frida/run-custom")
async def frida_run_custom(package: str, code: str, spawn: bool = True):
    success, msg, logs = await frida_mgr.run_script(
        package, "custom", custom_script=code, spawn=spawn
    )
    return {"success": success, "message": msg, "logs": logs}


@app.post("/api/frida/generate-hook")
async def frida_generate_hook(package: str, classes: list[str]):
    script = await frida_mgr.generate_hook_script(package, classes)
    return {"script": script}


@app.post("/api/frida/memory-dump/{package}")
async def frida_memory_dump(package: str):
    success, msg = await frida_mgr.memory_dump(package)
    return {"success": success, "message": msg}


# ──────────────────── AGENTS API ────────────────────

@app.get("/api/agents")
async def agents_status():
    return {"agents": await agent_mgr.get_all_status()}


# ── FRIDUMP ──

@app.post("/api/agents/fridump/search")
async def fridump_search(output_dir: str, query: str, max_results: int = 100):
    results = await agent_mgr.fridump.search_strings(output_dir, query, max_results)
    return {"query": query, "results": results, "count": len(results)}


@app.post("/api/agents/fridump/{package}")
async def fridump_dump(package: str, read_only: bool = False, strings: bool = True):
    if not agent_mgr.fridump.is_available():
        raise HTTPException(400, "fridump not found in workspace")

    frida_running = await frida_mgr.is_server_running()
    if not frida_running:
        raise HTTPException(400, "frida-server not running. Start it from the Frida page first.")

    async def progress_cb(agent, pct, msg):
        try:
            await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
        except Exception:
            pass
    result = await agent_mgr.fridump.dump_memory(
        package, usb=True, read_only=read_only, run_strings=strings, progress_cb=progress_cb
    )
    return result


# ── SEMGREP ──

@app.get("/api/agents/semgrep/rules")
async def semgrep_rules():
    return {"rules": agent_mgr.semgrep.list_rules(), "total": len(agent_mgr.semgrep.list_rules())}


@app.post("/api/agents/semgrep/scan")
async def semgrep_scan(target_dir: str, categories: list[str] = None):
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    result = await agent_mgr.semgrep.scan_directory(target_dir, categories, progress_cb)
    return result


@app.post("/api/agents/semgrep/scan-apk/{package}")
async def semgrep_scan_package(package: str):
    dest = str(UPLOADS_DIR / f"{package}.apk")
    pulled = await adb.pull_apk(package, dest)
    if not pulled:
        raise HTTPException(500, f"Failed to pull APK for {package}")
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    result = await agent_mgr.semgrep.scan_apk_xml(dest, progress_cb)
    return result


# ── OWASP ──

@app.post("/api/agents/owasp/{package}")
async def owasp_check(package: str):
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    findings = await agent_mgr.owasp.full_check(package, progress_cb)
    return {"package": package, "findings": findings, "count": len(findings)}


# ── DROZER ──

@app.post("/api/agents/drozer/connect")
async def drozer_connect():
    success, msg = await agent_mgr.drozer.setup_connection()
    return {"success": success, "message": msg}


@app.post("/api/agents/drozer/run")
async def drozer_run(module: str, package: str = "", extra_args: str = ""):
    result = await agent_mgr.drozer.run_module(module, package, extra_args)
    return result


@app.post("/api/agents/drozer/assess/{package}")
async def drozer_assess(package: str):
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    results = await agent_mgr.drozer.full_assessment(package, progress_cb)
    return {"results": results}


@app.post("/api/agents/drozer/setup")
async def drozer_setup():
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.drozer.full_setup(progress_cb)


# ── ANDROHUNTER ──

@app.post("/api/agents/hunter/intents/{package}")
async def hunter_fuzz_intents(package: str):
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.hunter.fuzz_intents(package, progress_cb)


@app.post("/api/agents/hunter/providers/{package}")
async def hunter_fuzz_providers(package: str):
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.hunter.fuzz_providers(package, progress_cb)


@app.post("/api/agents/hunter/broadcasts/{package}")
async def hunter_fuzz_broadcasts(package: str):
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.hunter.fuzz_broadcasts(package, progress_cb)


@app.post("/api/agents/hunter/fileprovider/{package}")
async def hunter_fileprovider(package: str):
    apk_path = str(UPLOADS_DIR / f"{package}.apk")
    if not os.path.exists(apk_path):
        pulled = await adb.pull_apk(package, apk_path)
        if not pulled:
            apk_path = None
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.hunter.analyze_fileproviders(package, apk_path, progress_cb)


@app.post("/api/agents/hunter/taskhijack/{package}")
async def hunter_task_hijack(package: str):
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.hunter.check_task_hijack(package, progress_cb)


@app.post("/api/agents/hunter/dex/{package}")
async def hunter_dex_secrets(package: str):
    apk_path = str(UPLOADS_DIR / f"{package}.apk")
    if not os.path.exists(apk_path):
        pulled = await adb.pull_apk(package, apk_path)
        if not pulled:
            raise HTTPException(500, f"Failed to pull APK for {package}")
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.hunter.scan_dex_secrets(apk_path, progress_cb)


@app.post("/api/agents/hunter/full/{package}")
async def hunter_full(package: str):
    apk_path = str(UPLOADS_DIR / f"{package}.apk")
    if not os.path.exists(apk_path):
        pulled = await adb.pull_apk(package, apk_path)
        if not pulled:
            apk_path = None
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.hunter.full_hunt(package, apk_path, progress_cb)


@app.post("/api/agents/hunter/sharedprefs/{package}")
async def hunter_shared_prefs(package: str):
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.hunter.read_shared_prefs(package, progress_cb)


@app.post("/api/agents/hunter/manifest/{package}")
async def hunter_manifest(package: str):
    async def progress_cb(agent, pct, msg):
        await ws_manager.broadcast({"type": "agent_progress", "agent": agent, "percent": pct, "message": msg})
    return await agent_mgr.hunter.analyze_manifest(package, progress_cb)


@app.get("/api/agents/hunter/activities/{package}")
async def hunter_list_activities(package: str):
    return await agent_mgr.hunter.list_activities(package)


@app.post("/api/agents/hunter/launch/{package}")
async def hunter_launch_activity(package: str, activity: str, data_uri: str = "", extras: dict = None):
    return await agent_mgr.hunter.launch_activity(package, activity, data_uri, extras or {})


@app.get("/api/agents/hunter/frida-templates")
async def hunter_frida_templates(package: str = ""):
    return {"templates": agent_mgr.hunter.get_frida_templates(package)}


@app.get("/api/agents/hunter/ssl-methods")
async def hunter_ssl_methods(package: str = ""):
    return {"methods": agent_mgr.hunter.get_ssl_bypass_methods(package)}


@app.get("/api/agents/hunter/auto-adb")
async def hunter_auto_adb_commands(package: str = ""):
    return {"categories": agent_mgr.hunter.get_auto_adb_commands(package)}


@app.post("/api/agents/hunter/auto-adb/run")
async def hunter_run_auto_adb(package: str, command: str):
    return await agent_mgr.hunter.run_auto_adb(package, command)


# ── MEDUSA (full workflow: stash → compile → run) ──

@app.get("/api/agents/medusa/modules")
async def medusa_modules():
    mods = agent_mgr.medusa.list_modules()
    return {"modules": mods, "total": len(mods)}


@app.get("/api/agents/medusa/snippets")
async def medusa_snippets():
    return {"snippets": agent_mgr.medusa.list_snippets()}


@app.post("/api/agents/medusa/stash")
async def medusa_stash(module_path: str):
    ok, msg = agent_mgr.medusa.stash(module_path)
    return {"success": ok, "message": msg, "staged": agent_mgr.medusa.get_staged()}


@app.post("/api/agents/medusa/unstash")
async def medusa_unstash(module_path: str):
    ok, msg = agent_mgr.medusa.unstash(module_path)
    return {"success": ok, "message": msg, "staged": agent_mgr.medusa.get_staged()}


@app.get("/api/agents/medusa/staged")
async def medusa_staged():
    return {"staged": agent_mgr.medusa.get_staged()}


@app.post("/api/agents/medusa/reset")
async def medusa_reset():
    agent_mgr.medusa.reset_staged()
    return {"success": True}


@app.post("/api/agents/medusa/compile")
async def medusa_compile(module_path: str = None, scratchpad: str = ""):
    if module_path:
        ok, script = await agent_mgr.medusa.compile_module(module_path)
        return {"success": ok, "script": script}
    ok, script = agent_mgr.medusa.compile(scratchpad)
    return {"success": ok, "script": script}


@app.post("/api/agents/medusa/run")
async def medusa_run(package: str, module_path: str = None, spawn: bool = True, timeout: int = 60):
    if module_path:
        return await agent_mgr.medusa.run_module_on_package(module_path, package, timeout)
    return await agent_mgr.medusa.run_session(package, spawn, timeout)


# ── OBJECTION (persistent session) ──

_objection_sessions: dict[str, dict] = {}


async def _run_objection(package: str, command: str, timeout: int = 30) -> dict:
    """Run a single objection command with proper stdin piping."""
    if not shutil.which("objection"):
        return {"output": "", "error": "objection is not installed. Run: pip install objection", "success": False}

    args = ["objection", "-g", package, "run", command]
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(input=b""), timeout=timeout)
        out = stdout.decode(errors="replace").strip()
        err = stderr.decode(errors="replace").strip()
        err_lower = err.lower()
        if any(s in err_lower for s in ["servernotrunningerror", "unable to find process", "need gadget", "notsupportederror"]):
            hint = ""
            if "need gadget" in err_lower or "notsupported" in err_lower:
                hint = (
                    "frida-server is required on the device.\n"
                    "1. Start frida-server (push to /data/local/tmp/ and chmod +x)\n"
                    "2. Or use a rooted device/emulator\n"
                    "3. Make sure the target app is installed"
                )
            else:
                hint = (
                    "Cannot connect to app. Ensure:\n"
                    "1. frida-server is running on the device\n"
                    "2. The app is running\n"
                    "3. Package name is correct"
                )
            return {"output": "", "error": hint, "success": False}
        is_ok = proc.returncode == 0 and ("traceback" not in err_lower)
        return {"output": out, "error": err if not is_ok else "", "success": is_ok}
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.wait()
        except Exception:
            pass
        return {"output": "", "error": f"Command timed out after {timeout}s. Try increasing timeout for heavy operations.", "success": False}


@app.post("/api/agents/objection/run")
async def objection_run(package: str, command: str, timeout: int = 30):
    """Run an objection command against a package."""
    return await _run_objection(package, command, timeout=timeout)


@app.post("/api/agents/objection/explore/{package}")
async def objection_explore(package: str):
    """Start a persistent objection session and run initial exploration."""
    if not shutil.which("objection"):
        raise HTTPException(400, "objection is not installed. Run: pip install objection")

    env_r = await _run_objection(package, "env", timeout=25)
    if not env_r["success"]:
        return {"connected": False, "error": env_r["error"], "results": {}}

    _objection_sessions[package] = {"connected": True, "started": True}

    results = {"env": {"output": env_r["output"], "success": True}}
    for key, cmd in {"activities": "android hooking list activities",
                     "services": "android hooking list services",
                     "receivers": "android hooking list receivers"}.items():
        r = await _run_objection(package, cmd, timeout=15)
        results[key] = {"output": r["output"] or r["error"], "success": r["success"]}

    return {"connected": True, "results": results}


@app.post("/api/agents/objection/stop/{package}")
async def objection_stop(package: str):
    """Mark objection session as stopped."""
    _objection_sessions.pop(package, None)
    return {"success": True, "message": "Objection session stopped"}


@app.get("/api/agents/objection/status/{package}")
async def objection_status(package: str):
    """Check if we have an active session for this package."""
    session = _objection_sessions.get(package)
    return {"connected": session is not None and session.get("connected", False)}


# ──────────────────── REPORTS API ────────────────────

@app.get("/api/reports")
async def list_reports():
    return {"reports": report_engine.list_reports()}


@app.post("/api/reports/generate")
async def generate_report(scan_id: str, fmt: str = "markdown"):
    result = scanner.get_scan(scan_id)
    if not result:
        report_path = REPORTS_DIR / f"scan_{scan_id}.json"
        if report_path.exists():
            scan_data = json.loads(report_path.read_text())
        else:
            raise HTTPException(404, "Scan not found")
    else:
        scan_data = result.to_dict()

    path = report_engine.save_report(scan_data, fmt)
    return {"path": path, "format": fmt}


@app.get("/api/reports/{filename}")
async def download_report(filename: str):
    path = REPORTS_DIR / filename
    if not path.exists():
        raise HTTPException(404, "Report not found")

    media_types = {
        ".json": "application/json",
        ".md": "text/markdown",
        ".html": "text/html",
    }
    mt = media_types.get(path.suffix, "application/octet-stream")
    return FileResponse(str(path), media_type=mt, filename=filename)


@app.get("/api/reports/preview/{filename}")
async def preview_report(filename: str):
    path = REPORTS_DIR / filename
    if not path.exists():
        raise HTTPException(404, "Report not found")
    content = path.read_text(errors="replace")
    if path.suffix == ".json":
        try:
            data = json.loads(content)
            html = report_engine.generate_html(data)
            return HTMLResponse(html)
        except Exception:
            return HTMLResponse(f"<pre>{content[:50000]}</pre>")
    elif path.suffix == ".md":
        scan_data = {}
        for sf in REPORTS_DIR.glob(f"scan_*.json"):
            try:
                d = json.loads(sf.read_text())
                if d.get("package", "") in filename:
                    scan_data = d
                    break
            except Exception:
                pass
        if scan_data:
            return HTMLResponse(report_engine.generate_html(scan_data))
        return HTMLResponse(f"<pre style='background:#0a0e17;color:#c9d1d9;padding:20px;font-family:monospace'>{content[:50000]}</pre>")
    elif path.suffix == ".html":
        return HTMLResponse(content)
    return HTMLResponse(f"<pre>{content[:50000]}</pre>")


# ──────────────────── COMPONENT TESTING API ────────────────────

@app.post("/api/test/broadcast")
async def test_broadcast(action: str, package: str = "", extras: dict = None):
    output = await adb.send_broadcast(action, extras, package)
    return {"action": action, "output": output}


@app.post("/api/test/activity")
async def test_activity(component: str, data: str = None, extras: dict = None):
    output = await adb.start_activity(component, data, extras)
    return {"component": component, "output": output}


@app.post("/api/test/provider")
async def test_provider(uri: str):
    output = await adb.shell(f"content query --uri '{uri}'")
    return {"uri": uri, "output": output}


# ──────────────────── TRAFFIC INSPECTOR API ────────────────────

@app.get("/api/traffic/proxy")
async def traffic_proxy_get():
    """Get current proxy configuration on device."""
    proxy = await adb.shell("settings get global http_proxy")
    proxy = proxy.strip()
    if proxy in ("null", ":0", ""):
        return {"proxy": None, "configured": False}
    return {"proxy": proxy, "configured": True}


@app.post("/api/traffic/proxy/set")
async def traffic_proxy_set(host: str, port: int = 8080):
    """Set HTTP proxy on device (for Burp Suite)."""
    proxy_val = f"{host}:{port}"
    out = await adb.shell(f"settings put global http_proxy {proxy_val}")
    verify = await adb.shell("settings get global http_proxy")
    return {"success": proxy_val in verify, "proxy": proxy_val, "output": out}


@app.post("/api/traffic/proxy/reset")
async def traffic_proxy_reset():
    """Remove HTTP proxy from device."""
    await adb.shell("settings put global http_proxy :0")
    await adb.shell("settings delete global http_proxy 2>/dev/null")
    return {"success": True, "message": "Proxy cleared"}


@app.post("/api/traffic/cert/install")
async def traffic_cert_install(cert_name: str = "burp_ca"):
    """Download Burp CA cert from proxy, convert, and install as system CA."""
    import tempfile
    import hashlib

    work = tempfile.mkdtemp(prefix="burp_cert_")
    der_path = os.path.join(work, "cacert.der")
    pem_path = os.path.join(work, "cacert.pem")

    proxy_info = await adb.shell("settings get global http_proxy")
    proxy_host = proxy_info.strip().split(":")[0] if ":" in proxy_info.strip() else "127.0.0.1"
    proxy_port = proxy_info.strip().split(":")[-1] if ":" in proxy_info.strip() else "8080"

    steps = []

    try:
        out, err, rc = await _exec(
            ["curl", "-s", "-o", der_path, "--connect-timeout", "5",
             f"http://{proxy_host}:{proxy_port}/cert"],
            timeout=15,
        )
        if rc == 0 and os.path.exists(der_path) and os.path.getsize(der_path) > 100:
            steps.append({"step": "download_cert", "success": True, "detail": "Downloaded from Burp proxy"})
        else:
            steps.append({"step": "download_cert", "success": False,
                          "detail": f"Could not download cert from http://{proxy_host}:{proxy_port}/cert. "
                                    "Make sure Burp Suite is running and proxy is accessible."})
            return {"success": False, "steps": steps, "error": "Failed to download cert from Burp"}
    except Exception as e:
        steps.append({"step": "download_cert", "success": False, "detail": str(e)})
        return {"success": False, "steps": steps, "error": str(e)}

    out_conv, err_conv, rc_conv = await _exec(
        ["openssl", "x509", "-inform", "DER", "-in", der_path, "-out", pem_path],
        timeout=10,
    )
    if rc_conv != 0:
        out_conv, err_conv, rc_conv = await _exec(
            ["openssl", "x509", "-inform", "PEM", "-in", der_path, "-out", pem_path],
            timeout=10,
        )
    if rc_conv == 0 and os.path.exists(pem_path):
        steps.append({"step": "convert_pem", "success": True, "detail": "Converted to PEM"})
    else:
        steps.append({"step": "convert_pem", "success": False, "detail": err_conv})
        return {"success": False, "steps": steps, "error": "OpenSSL conversion failed"}

    hash_out, _, _ = await _exec(
        ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", pem_path, "-noout"],
        timeout=10,
    )
    cert_hash = hash_out.strip()
    if not cert_hash:
        hash_out2, _, _ = await _exec(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash", "-in", pem_path, "-noout"],
            timeout=10,
        )
        cert_hash = hash_out2.strip()

    if not cert_hash:
        steps.append({"step": "hash", "success": False, "detail": "Could not compute cert hash"})
        return {"success": False, "steps": steps, "error": "Hash computation failed"}

    system_cert_name = f"{cert_hash}.0"
    system_cert_local = os.path.join(work, system_cert_name)
    os.rename(pem_path, system_cert_local)
    steps.append({"step": "hash", "success": True, "detail": f"Cert hash: {cert_hash}"})

    push_out = await adb.shell(f"echo test_write > /data/local/tmp/_certtest && rm /data/local/tmp/_certtest && echo ok")
    device_tmp = f"/data/local/tmp/{system_cert_name}"

    push_cmd_out, push_err, push_rc = await _exec(
        [ADB_PATH, "push", system_cert_local, device_tmp], timeout=15,
    )
    if push_rc != 0:
        steps.append({"step": "push", "success": False, "detail": push_err})
        return {"success": False, "steps": steps, "error": "Failed to push cert to device"}
    steps.append({"step": "push", "success": True, "detail": f"Pushed to {device_tmp}"})

    installed = False
    cert_dest = f"/system/etc/security/cacerts/{system_cert_name}"
    install_detail = ""

    # Ensure adb runs as root
    await _exec([ADB_PATH, "root"], timeout=10)
    await asyncio.sleep(2)

    # Strategy 1: adb remount (older emulators / writable-system images)
    remount_out, remount_err, remount_rc = await _exec([ADB_PATH, "remount"], timeout=15)
    if remount_rc == 0 and "failed" not in (remount_out + remount_err).lower():
        await _exec([ADB_PATH, "shell", f"cp {device_tmp} {cert_dest} && chmod 644 {cert_dest}"], timeout=10)
        check = await adb.shell(f"ls {cert_dest} 2>/dev/null")
        if system_cert_name in check:
            installed = True
            install_detail = f"Installed via adb remount: {cert_dest}"

    # Strategy 2: tmpfs overlay (modern emulators with dm-verity / read-only /system)
    if not installed:
        tmp_ca = "/data/local/tmp/cacerts-copy"
        overlay_cmds = (
            f"mkdir -p {tmp_ca} && "
            f"cp /system/etc/security/cacerts/* {tmp_ca}/ 2>/dev/null; "
            f"cp {device_tmp} {tmp_ca}/{system_cert_name} && "
            f"chmod 644 {tmp_ca}/{system_cert_name} && "
            f"mount -t tmpfs tmpfs /system/etc/security/cacerts && "
            f"cp {tmp_ca}/* /system/etc/security/cacerts/ && "
            f"chcon u:object_r:system_file:s0 /system/etc/security/cacerts/* 2>/dev/null; "
            f"echo DONE"
        )
        r = await adb.shell(overlay_cmds)
        if "DONE" in r:
            check = await adb.shell(f"ls {cert_dest} 2>/dev/null")
            if system_cert_name in check:
                installed = True
                install_detail = f"Installed via tmpfs overlay: {cert_dest} (persists until reboot)"

    # Strategy 3: su-based mount (rooted physical devices)
    if not installed:
        for su_prefix in ["su 0 sh -c", "su -c"]:
            cmd = (
                f"{su_prefix} 'mount -o remount,rw /system 2>/dev/null; "
                f"cp {device_tmp} {cert_dest} && chmod 644 {cert_dest}'"
            )
            await adb.shell(cmd)
            check = await adb.shell(f"ls {cert_dest} 2>/dev/null")
            if system_cert_name in check:
                installed = True
                install_detail = f"Installed via su: {cert_dest}"
                break

    if installed:
        steps.append({"step": "install_system", "success": True, "detail": install_detail})
    else:
        steps.append({"step": "install_system", "success": False,
                       "detail": f"Could not install as system CA. Cert pushed to {device_tmp}. "
                                 "Try manually: adb root && adb shell, then run: "
                                 f"mount -t tmpfs tmpfs /system/etc/security/cacerts && "
                                 f"cp {device_tmp} {cert_dest}"})

    return {
        "success": installed,
        "steps": steps,
        "cert_hash": cert_hash,
        "cert_path": f"/system/etc/security/cacerts/{system_cert_name}" if installed else device_tmp,
    }


@app.get("/api/traffic/cert/status")
async def traffic_cert_status():
    """Check if Burp CA is already installed as system cert."""
    certs = await adb.shell("ls /system/etc/security/cacerts/ 2>/dev/null")
    user_certs = await adb.shell("ls /data/misc/user/0/cacerts-added/ 2>/dev/null")
    return {
        "system_certs_count": len(certs.splitlines()) if certs else 0,
        "user_certs": user_certs.strip() if user_certs else "",
        "raw": certs[:500] if certs else "",
    }


@app.post("/api/traffic/cert/upload")
async def traffic_cert_upload(file: UploadFile = File(...)):
    """Upload a cert file manually and install it."""
    import tempfile
    work = tempfile.mkdtemp(prefix="cert_upload_")
    dest = os.path.join(work, file.filename)
    content = await file.read()
    with open(dest, "wb") as f:
        f.write(content)

    if dest.endswith(".der") or dest.endswith(".cer"):
        pem_path = dest + ".pem"
        await _exec(["openssl", "x509", "-inform", "DER", "-in", dest, "-out", pem_path], timeout=10)
        if os.path.exists(pem_path):
            dest = pem_path

    hash_out, _, _ = await _exec(
        ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", dest, "-noout"], timeout=10,
    )
    cert_hash = hash_out.strip()
    if not cert_hash:
        hash_out2, _, _ = await _exec(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash", "-in", dest, "-noout"], timeout=10,
        )
        cert_hash = hash_out2.strip()

    if not cert_hash:
        return {"success": False, "error": "Invalid certificate file"}

    system_name = f"{cert_hash}.0"
    final_path = os.path.join(work, system_name)
    os.rename(dest, final_path)

    device_tmp = f"/data/local/tmp/{system_name}"
    await _exec([ADB_PATH, "push", final_path, device_tmp], timeout=15)

    await adb.shell(
        f"su 0 sh -c 'mount -o remount,rw /system; "
        f"cp {device_tmp} /system/etc/security/cacerts/{system_name}; "
        f"chmod 644 /system/etc/security/cacerts/{system_name}' 2>/dev/null"
    )
    check = await adb.shell(f"ls /system/etc/security/cacerts/{system_name} 2>/dev/null")
    installed = system_name in check

    return {
        "success": installed,
        "cert_hash": cert_hash,
        "cert_path": f"/system/etc/security/cacerts/{system_name}" if installed else device_tmp,
        "message": "Installed as system CA" if installed else f"Pushed to {device_tmp}. Install manually with root.",
    }


# ──────────────────── TOOLS API ────────────────────

@app.get("/api/tools")
async def tools_status():
    tools = {}
    for tool in ["frida", "objection", "drozer", "apktool", "jadx", "semgrep", "adb"]:
        tools[tool] = shutil.which(tool) is not None
    frida_ver = await frida_mgr.get_frida_version()
    if frida_ver:
        tools["frida_version"] = frida_ver
    return {"tools": tools}


@app.post("/api/tools/install/{tool}")
async def install_tool(tool: str):
    import sys
    tool_map = {
        "frida-tools": "frida-tools",
        "objection": "objection",
        "semgrep": "semgrep",
        "drozer": "drozer",
    }
    pip_name = tool_map.get(tool)
    if not pip_name:
        raise HTTPException(400, f"Unknown tool: {tool}")

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "pip", "install", pip_name,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    success = proc.returncode == 0
    return {
        "success": success,
        "output": stdout.decode("utf-8", errors="replace") if success
                  else stderr.decode("utf-8", errors="replace"),
    }
