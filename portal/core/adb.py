"""ADB Manager – async wrapper around Android Debug Bridge."""

import asyncio
import re
import shutil
from dataclasses import dataclass, field
from typing import Optional

from portal.config import ADB_PATH


@dataclass
class DeviceInfo:
    serial: str = ""
    model: str = ""
    android_version: str = ""
    api_level: int = 0
    arch: str = ""
    build_type: str = ""
    build_tags: str = ""
    is_rooted: bool = False
    is_emulator: bool = False
    manufacturer: str = ""
    brand: str = ""
    security_patch: str = ""
    kernel: str = ""
    selinux: str = ""


@dataclass
class PackageInfo:
    package_name: str
    version_name: str = ""
    version_code: str = ""
    target_sdk: int = 0
    min_sdk: int = 0
    is_debuggable: bool = False
    is_system: bool = False
    apk_path: str = ""
    uid: str = ""
    permissions: list = field(default_factory=list)
    activities: list = field(default_factory=list)
    services: list = field(default_factory=list)
    receivers: list = field(default_factory=list)
    providers: list = field(default_factory=list)


class ADBManager:
    def __init__(self, adb_path: str = ADB_PATH):
        self.adb_path = adb_path
        if not shutil.which(adb_path) and not __import__("os").path.exists(adb_path):
            raise FileNotFoundError(f"ADB not found at {adb_path}")

    async def execute(self, args: list[str], timeout: int = 30) -> tuple[str, str, int]:
        proc = await asyncio.create_subprocess_exec(
            self.adb_path, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return "", "Command timed out", -1
        return (
            stdout.decode("utf-8", errors="replace").strip(),
            stderr.decode("utf-8", errors="replace").strip(),
            proc.returncode or 0,
        )

    async def shell(self, cmd: str, timeout: int = 30) -> str:
        out, err, rc = await self.execute(["shell", cmd], timeout=timeout)
        return out if out else err

    async def is_connected(self) -> bool:
        out, _, rc = await self.execute(["get-state"])
        return out == "device"

    async def get_device_info(self) -> DeviceInfo:
        info = DeviceInfo()
        props = {
            "serial": ["get-serialno"],
        }
        out, _, _ = await self.execute(["get-serialno"])
        info.serial = out

        shell_props = {
            "ro.product.model": "model",
            "ro.build.version.release": "android_version",
            "ro.build.version.sdk": "api_level",
            "ro.product.cpu.abi": "arch",
            "ro.build.type": "build_type",
            "ro.build.tags": "build_tags",
            "ro.product.manufacturer": "manufacturer",
            "ro.product.brand": "brand",
            "ro.build.version.security_patch": "security_patch",
            "ro.hardware": "is_emulator",
        }

        for prop, attr in shell_props.items():
            val = await self.shell(f"getprop {prop}")
            if attr == "api_level":
                try:
                    info.api_level = int(val)
                except ValueError:
                    pass
            elif attr == "arch":
                abi_map = {
                    "arm64-v8a": "arm64",
                    "armeabi-v7a": "arm",
                    "x86": "x86",
                    "x86_64": "x86_64",
                }
                info.arch = abi_map.get(val, val)
            elif attr == "is_emulator":
                info.is_emulator = "goldfish" in val or "ranchu" in val
                setattr(info, "hardware", val)
            else:
                setattr(info, attr, val)

        id_result = await self.shell("id")
        info.is_rooted = "uid=0" in id_result if id_result else False

        if not info.is_rooted:
            for su in ["/sbin/su", "/system/xbin/su", "/system/bin/su",
                       "/data/adb/magisk/su", "/data/local/tmp/su"]:
                result = await self.shell(f"{su} -c id")
                if result and "uid=0" in result:
                    info.is_rooted = True
                    break

        selinux = await self.shell("getenforce")
        info.selinux = selinux if selinux else "Unknown"

        kernel = await self.shell("uname -r")
        info.kernel = kernel if kernel else "Unknown"

        return info

    async def list_packages(self, include_system: bool = False) -> list[str]:
        flag = "" if include_system else "-3"
        out = await self.shell(f"pm list packages {flag}")
        if not out:
            return []
        return sorted([
            line.replace("package:", "").strip()
            for line in out.splitlines()
            if line.startswith("package:")
        ])

    async def get_package_info(self, package: str) -> PackageInfo:
        info = PackageInfo(package_name=package)

        dump = await self.shell(f"dumpsys package {package}")
        if not dump:
            return info

        for line in dump.splitlines():
            line = line.strip()
            if line.startswith("versionName="):
                info.version_name = line.split("=", 1)[1]
            elif line.startswith("versionCode="):
                info.version_code = line.split("=", 1)[1].split()[0]
            elif line.startswith("targetSdk="):
                try:
                    info.target_sdk = int(line.split("=", 1)[1])
                except ValueError:
                    pass
            elif line.startswith("minSdk="):
                try:
                    info.min_sdk = int(line.split("=", 1)[1])
                except ValueError:
                    pass
            elif "pkgFlags=" in line and "DEBUGGABLE" in line:
                info.is_debuggable = True
            elif "pkgFlags=" in line and "SYSTEM" in line:
                info.is_system = True
            elif line.startswith("codePath="):
                info.apk_path = line.split("=", 1)[1]
            elif line.startswith("userId="):
                info.uid = line.split("=", 1)[1]

        perms = await self.shell(f"dumpsys package {package} | grep 'android.permission'")
        if perms:
            info.permissions = list(set(
                re.findall(r"(android\.permission\.\w+)", perms)
            ))

        return info

    async def get_apk_path(self, package: str) -> Optional[str]:
        out = await self.shell(f"pm path {package}")
        if not out:
            return None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                path = line.replace("package:", "").strip()
                if path.endswith(".apk"):
                    return path
                return path
        return None

    async def pull_apk(self, package: str, dest: str) -> bool:
        apk_path = await self.get_apk_path(package)
        if not apk_path:
            return False
        _, err, rc = await self.execute(["pull", apk_path, dest])
        return rc == 0

    async def install_apk(self, path: str) -> tuple[bool, str]:
        out, err, rc = await self.execute(["install", "-r", path], timeout=120)
        return rc == 0, out or err

    async def forward_port(self, local: int, remote: int) -> bool:
        _, _, rc = await self.execute(["forward", f"tcp:{local}", f"tcp:{remote}"])
        return rc == 0

    async def logcat(self, filters: str = "", lines: int = 500) -> str:
        cmd = f"logcat -d -t {lines}"
        if filters:
            cmd += f" {filters}"
        return await self.shell(cmd)

    async def push_file(self, local: str, remote: str) -> bool:
        _, _, rc = await self.execute(["push", local, remote])
        return rc == 0

    async def root_adb(self) -> tuple[bool, str]:
        out, err, rc = await self.execute(["root"])
        await asyncio.sleep(2)
        await self.execute(["wait-for-device"])
        id_out = await self.shell("id")
        success = "uid=0" in (id_out or "")
        return success, out or err

    async def get_running_processes(self) -> list[dict]:
        out = await self.shell("ps -A -o PID,NAME")
        procs = []
        for line in (out or "").splitlines()[1:]:
            parts = line.split(None, 1)
            if len(parts) == 2:
                procs.append({"pid": parts[0], "name": parts[1]})
        return procs

    async def screencap(self, dest: str = "/tmp/screen.png") -> Optional[str]:
        await self.shell("screencap -p /sdcard/screen.png")
        _, _, rc = await self.execute(["pull", "/sdcard/screen.png", dest])
        if rc == 0:
            return dest
        return None

    async def get_activities(self, package: str) -> list[dict]:
        out = await self.shell(f"dumpsys package {package}")
        activities = []
        in_activity_section = False
        for line in (out or "").splitlines():
            stripped = line.strip()
            if "Activity Resolver Table:" in stripped:
                in_activity_section = True
                continue
            if in_activity_section and stripped.startswith("Schemes:"):
                in_activity_section = False
            if in_activity_section and f"{package}/" in stripped:
                match = re.search(rf"({package}/[\w.]+)", stripped)
                if match:
                    act = match.group(1)
                    exported = "exported=true" in stripped.lower()
                    activities.append({
                        "name": act,
                        "exported": exported,
                    })
        return activities

    async def get_content_providers(self, package: str) -> list[dict]:
        out = await self.shell(f"dumpsys package {package}")
        providers = []
        in_provider = False
        for line in (out or "").splitlines():
            stripped = line.strip()
            if "ContentProvider Coverage" in stripped or "Provider{" in stripped:
                in_provider = True
            if in_provider and f"{package}" in stripped:
                match = re.search(rf"({package}/[\w.]+)", stripped)
                if match:
                    providers.append({
                        "name": match.group(1),
                        "authority": "",
                    })
        return providers

    async def send_broadcast(self, action: str, extras: dict = None, package: str = None) -> str:
        cmd = f"am broadcast -a {action}"
        if package:
            cmd += f" -n {package}"
        if extras:
            for k, v in extras.items():
                cmd += f" --es {k} '{v}'"
        return await self.shell(cmd)

    async def start_activity(self, component: str, data: str = None, extras: dict = None) -> str:
        cmd = f"am start -n {component}"
        if data:
            cmd += f" -d '{data}'"
        if extras:
            for k, v in extras.items():
                cmd += f" --es {k} '{v}'"
        return await self.shell(cmd)
