"""Frida Manager – controls Frida server lifecycle, script injection, and hooking."""

import asyncio
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Optional, Callable

from portal.config import ADB_PATH, FRIPTS_DIR, FRIDA_SCRIPTS
from portal.core.agents import _get_android_serial


@dataclass
class FridaSession:
    pid: int
    package: str
    script_name: str
    status: str = "running"
    logs: list = field(default_factory=list)


class FridaManager:

    def __init__(self, adb_path: str = ADB_PATH):
        self.adb_path = adb_path
        self.sessions: dict[str, FridaSession] = {}
        self._server_running = False

    async def _exec(self, args: list[str], timeout: int = 30) -> tuple[str, str, int]:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return "", "Timeout", -1
        return (
            stdout.decode("utf-8", errors="replace").strip(),
            stderr.decode("utf-8", errors="replace").strip(),
            proc.returncode or 0,
        )

    async def _adb(self, args: list[str], timeout: int = 30) -> str:
        out, err, _ = await self._exec([self.adb_path] + args, timeout)
        return out or err

    async def get_frida_version(self) -> Optional[str]:
        if not shutil.which("frida"):
            return None
        out, _, rc = await self._exec(["frida", "--version"])
        return out if rc == 0 else None

    async def is_server_running(self) -> bool:
        out = await self._adb(["shell", "ps -A | grep frida-server"])
        self._server_running = "frida-server" in (out or "")
        return self._server_running

    async def check_server_port(self) -> bool:
        out = await self._adb(["shell", "netstat -tulpn 2>/dev/null | grep 27042"])
        return "27042" in (out or "")

    async def install_server(self, progress_cb: Optional[Callable] = None) -> tuple[bool, str]:
        version = await self.get_frida_version()
        if not version:
            return False, "frida-tools not installed. Run: pip install frida-tools"

        arch_raw = await self._adb(["shell", "getprop ro.product.cpu.abi"])
        arch_map = {
            "arm64-v8a": "arm64", "armeabi-v7a": "arm",
            "x86": "x86", "x86_64": "x86_64",
        }
        arch = arch_map.get(arch_raw.strip(), "arm64")

        url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch}.xz"

        try:
            import requests
            import lzma

            if progress_cb:
                await progress_cb("downloading", 10, f"Downloading frida-server {version} ({arch})...")

            resp = requests.get(url, stream=True, timeout=60)
            resp.raise_for_status()

            xz_path = os.path.join(tempfile.gettempdir(), f"frida-server-{version}-{arch}.xz")
            bin_path = xz_path.replace(".xz", "")

            total = int(resp.headers.get("content-length", 0))
            downloaded = 0
            with open(xz_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_cb and total > 0:
                        pct = min(int((downloaded / total) * 50), 50)
                        await progress_cb("downloading", 10 + pct, f"Downloading: {pct * 2}%")

            if progress_cb:
                await progress_cb("extracting", 65, "Extracting...")

            with lzma.open(xz_path, "rb") as compressed:
                with open(bin_path, "wb") as decompressed:
                    decompressed.write(compressed.read())

            if progress_cb:
                await progress_cb("pushing", 75, "Pushing to device...")

            await self._adb(["push", bin_path, "/data/local/tmp/frida-server"])
            await self._adb(["shell", "chmod 755 /data/local/tmp/frida-server"])

            os.unlink(xz_path)
            os.unlink(bin_path)

            if progress_cb:
                await progress_cb("done", 100, "Frida server installed!")

            return True, f"frida-server {version} ({arch}) installed"

        except Exception as e:
            return False, str(e)

    async def start_server(self) -> tuple[bool, str]:
        if await self.is_server_running():
            return True, "Frida server already running"

        await self._adb(["shell", "su 0 killall frida-server 2>/dev/null"])
        await asyncio.sleep(1)

        proc = await asyncio.create_subprocess_exec(
            self.adb_path, "shell", "su", "0",
            "nohup", "/data/local/tmp/frida-server", "&",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.sleep(3)

        if await self.check_server_port():
            self._server_running = True
            return True, "Frida server started on port 27042"
        return False, "Failed to start Frida server"

    async def stop_server(self) -> tuple[bool, str]:
        await self._adb(["shell", "su 0 killall frida-server 2>/dev/null"])
        await asyncio.sleep(1)
        self._server_running = False
        return True, "Frida server stopped"

    async def list_processes(self) -> list[dict]:
        if not shutil.which("frida-ps"):
            return []
        serial = await _get_android_serial()
        ps_cmd = ["frida-ps", "-D", serial, "-ai"] if serial else ["frida-ps", "-Uai"]
        out, _, rc = await self._exec(ps_cmd, timeout=15)
        if rc != 0 or not out:
            return []

        processes = []
        for line in out.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) >= 2:
                entry = {"pid": parts[0], "name": parts[1]}
                if len(parts) == 3:
                    entry["identifier"] = parts[2]
                processes.append(entry)
        return processes

    async def run_script(
        self,
        package: str,
        script_key: str,
        custom_script: str = None,
        spawn: bool = True,
        timeout: int = 30,
    ) -> tuple[bool, str, list[str]]:
        if not shutil.which("frida"):
            return False, "frida not installed", []

        if custom_script:
            script_path = os.path.join(tempfile.gettempdir(), f"custom_{package}.js")
            with open(script_path, "w") as f:
                f.write(custom_script)
        elif script_key in FRIDA_SCRIPTS:
            script_path = str(FRIDA_SCRIPTS[script_key])
            if not os.path.exists(script_path):
                return False, f"Script not found: {script_path}", []
        else:
            return False, f"Unknown script key: {script_key}", []

        serial = await _get_android_serial()
        cmd = ["frida"]
        cmd += ["-D", serial] if serial else ["-U"]
        if spawn:
            cmd += ["-f", package]
        else:
            cmd += ["-n", package]
        cmd += ["-l", script_path]

        logs = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=b""), timeout=timeout
                )
                output = stdout.decode("utf-8", errors="replace")
                errors = stderr.decode("utf-8", errors="replace")
                logs = output.splitlines()
                if errors:
                    logs += [f"[STDERR] {l}" for l in errors.splitlines()]
            except asyncio.TimeoutError:
                proc.kill()
                logs.append("[INFO] Script execution timed out (hooks were injected)")

            return True, f"Script {script_key} executed on {package}", logs

        except Exception as e:
            return False, str(e), logs

    async def generate_hook_script(self, package: str, classes: list[str]) -> str:
        hooks = []
        for cls in classes:
            hooks.append(f"""
    try {{
        var {cls.split('.')[-1]} = Java.use('{cls}');
        var methods = {cls.split('.')[-1]}.class.getDeclaredMethods();
        methods.forEach(function(method) {{
            var methodName = method.getName();
            try {{
                {cls.split('.')[-1]}[methodName].overloads.forEach(function(overload) {{
                    overload.implementation = function() {{
                        console.log('[HOOK] ' + '{cls}.' + methodName + '(' + JSON.stringify(arguments) + ')');
                        return overload.apply(this, arguments);
                    }};
                }});
            }} catch(e) {{}}
        }});
        console.log('[+] Hooked: {cls}');
    }} catch(e) {{
        console.log('[-] Failed: {cls} - ' + e);
    }}""")

        return f"""'use strict';

Java.perform(function() {{
    console.log('[*] AndroidINONE Hook Script for {package}');
    console.log('[*] Hooking {len(classes)} classes...');
{"".join(hooks)}
    console.log('[*] All hooks installed!');
}});
"""

    async def generate_ssl_bypass_script(self) -> str:
        script_path = FRIDA_SCRIPTS.get("ssl_bypass")
        if script_path and os.path.exists(script_path):
            with open(script_path, "r") as f:
                return f.read()
        return self._default_ssl_bypass()

    async def generate_root_bypass_script(self) -> str:
        script_path = FRIDA_SCRIPTS.get("root_bypass")
        if script_path and os.path.exists(script_path):
            with open(script_path, "r") as f:
                return f.read()
        return ""

    def _default_ssl_bypass(self) -> str:
        return """'use strict';
Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: 'com.inone.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.getInstance.overload('java.lang.String').implementation = function(type) {
        var c = this.getInstance(type);
        c.init(null, [TrustManager.$new()], null);
        return c;
    };
    console.log('[+] SSL Pinning Bypassed!');
});
"""

    def get_available_scripts(self) -> list[dict]:
        scripts = []
        for key, path in FRIDA_SCRIPTS.items():
            scripts.append({
                "key": key,
                "name": key.replace("_", " ").title(),
                "path": str(path),
                "exists": os.path.exists(path),
            })
        if FRIPTS_DIR.exists():
            for f in FRIPTS_DIR.glob("*.js"):
                key = f.stem
                if key not in [s["key"] for s in scripts]:
                    scripts.append({
                        "key": key,
                        "name": key.replace("_", " ").title(),
                        "path": str(f),
                        "exists": True,
                    })
        return scripts

    async def memory_dump(self, package: str, output_dir: str = None) -> tuple[bool, str]:
        fridump_script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "fridump", "fridump.py"
        )
        if not os.path.exists(fridump_script):
            return False, "fridump.py not found"

        if not output_dir:
            output_dir = os.path.join(tempfile.gettempdir(), f"fridump_{package}")

        import sys
        cmd = [sys.executable, fridump_script, "-U", "-s", "-o", output_dir, package]
        out, err, rc = await self._exec(cmd, timeout=120)
        return rc == 0, out or err
