# AndroidINONE

**Comprehensive Android Security Assessment Platform** – CLI toolkit + standalone web portal for mobile penetration testing.

Covers the full Android attack surface: static analysis (APK, manifest, DEX, secrets), dynamic testing (Frida hooks, SSL/root bypass, memory dump), component fuzzing (activities, broadcasts, providers), network interception, and automated vulnerability scanning with report generation.

---

## Architecture

```
AndroidINONE/
├── portal/                      # Web portal (FastAPI backend + frontend)
│   ├── app.py                   # API endpoints & WebSocket
│   ├── config.py                # Configuration & paths
│   ├── run.py                   # Entry point with banner
│   ├── core/
│   │   ├── adb.py               # Async ADB manager
│   │   ├── frida_manager.py     # Frida server lifecycle & script injection
│   │   ├── analyzer.py          # APK static analysis engine
│   │   ├── scanner.py           # Automated vulnerability scanner
│   │   ├── agents.py            # Hunter, Medusa, drozer, OWASP, fridump, semgrep
│   │   └── report_engine.py     # Multi-format report generation
│   └── static/                  # Web frontend (dark terminal UI)
│       ├── css/style.css
│       ├── js/app.js
│       └── index.html
│
├── Fripts/                      # Frida scripts
│   ├── SSL-BYE.js               # SSL pinning bypass
│   ├── ROOTER.js                # Root detection bypass
│   ├── PintooR.js               # Combined SSL + root bypass
│   ├── dex_dump.js              # DEX file dumper
│   ├── hook_list.js             # Method hooking helpers
│   └── hunter_hooks.js          # Runtime crypto/SQL/HTTP monitoring
│
├── fridump/                     # Memory dumper (frida-based)
├── medusa/                      # Dynamic analysis framework (122 modules)
│   ├── modules/                 # .med hook modules (32 categories)
│   └── snippets/                # Reusable JS snippets (14)
├── semgrep-android/             # MASVS static analysis rules (53 YAML)
├── top10_owasp/                 # OWASP Mobile Top 10 shell checks
│
├── AndroidINONE.py              # Original CLI tool
├── launch_portal.py             # Quick portal launcher
├── requirements.txt             # Python dependencies
├── reports/                     # Generated scan reports (gitignored)
├── uploads/                     # Pulled APKs (gitignored)
└── dump_output/                 # Memory dumps (gitignored)
```

---

## Quick Start

### Prerequisites
- Python 3.10+, macOS/Linux
- Android SDK platform-tools (ADB)
- Device/emulator with USB debugging enabled

### Install & Run

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Optional tools for full capabilities
pip install frida-tools objection drozer semgrep

# Launch the web portal
python3 launch_portal.py
# → Open http://localhost:1337
```

---

## Portal Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Device status, package count, scan history, tool status |
| **Target** | Package explorer → static analysis → full scan → OWASP/Semgrep/Hunter |
| **Semgrep** | MASVS static analysis with 53 categorized rules |
| **Drozer** | Component security: auto-setup, connect, run modules, full assessment |
| **Hunter** | AndroHunter: Intent/Provider/Broadcast fuzzing, FileProvider, StrandHogg, DEX secrets |
| **Frida** | Server management, ADB root, script runner, custom scripts |
| **Objection** | Persistent session: explore → run commands → stop |
| **Medusa** | Stash modules → compile → run session (122 modules, 32 categories) |
| **Memory** | fridump memory dump with sensitive string extraction & search |
| **Traffic** | Burp Suite proxy config, CA cert auto-install, setup guide |
| **Shell** | ADB shell with command history and quick commands |
| **Reports** | HTML/Markdown/JSON report generation and preview |

---

## AndroHunter Integration

Full feature parity with [AndroHunter](https://github.com/ynsmroztas/AndroHunter):

| Module | Description |
|--------|-------------|
| **Intent Fuzzer** | 12 payloads: LFI, SQLi, XSS, Redirect, Template Injection, Command Injection. VULN/SUSP/SAFE classification. |
| **Provider Fuzzer** | 9 SQLi payloads per provider: Error-based, Boolean, UNION. Readable provider detection. |
| **Broadcast Fuzzer** | 10 broadcast payloads across 6 categories: Auth bypass, SQLi, LFI, Redirect, PrivEsc, Exfil. |
| **FileProvider Analyzer** | Parse FileProvider XML paths (root/cache/external), 9 path traversal payloads incl. URL-encoded. |
| **StrandHogg Detector** | Detect StrandHogg 1.0: custom taskAffinity, empty affinity, standard launchMode. |
| **DEX Secret Scanner** | 19 patterns: API keys, AWS, Firebase, JWT, passwords, IPs, debug flags, SQL queries. VULN/SUSP/INFO. |
| **Payload Engine** | 7 categories: SQLi (8), XSS (6), LFI (6), Redirect (6), Template (6), CmdI (8), IDOR (9). |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/device` | Device info |
| POST | `/api/device/root` | ADB root |
| POST | `/api/device/shell?cmd=` | Shell command |
| GET | `/api/packages` | List packages |
| POST | `/api/scan/{pkg}` | Start vulnerability scan |
| GET | `/api/scan/{id}` | Scan results |
| POST | `/api/analyze/package/{pkg}` | Static analysis |
| GET/POST | `/api/frida/*` | Frida server control & scripts |
| POST | `/api/agents/hunter/full/{pkg}` | Full AndroHunter hunt |
| POST | `/api/agents/hunter/intents/{pkg}` | Intent fuzzer |
| POST | `/api/agents/hunter/providers/{pkg}` | Provider fuzzer |
| POST | `/api/agents/hunter/broadcasts/{pkg}` | Broadcast fuzzer |
| POST | `/api/agents/hunter/fileprovider/{pkg}` | FileProvider analysis |
| POST | `/api/agents/hunter/taskhijack/{pkg}` | StrandHogg check |
| POST | `/api/agents/hunter/dex/{pkg}` | DEX secret scan |
| POST | `/api/agents/medusa/stash` | Stash a Medusa module |
| POST | `/api/agents/medusa/compile` | Compile stashed modules |
| POST | `/api/agents/medusa/run` | Run compiled/single module |
| POST | `/api/agents/drozer/setup` | Auto-setup drozer (download, install, connect) |
| POST | `/api/agents/drozer/connect` | Connect to drozer Agent |
| POST | `/api/agents/drozer/run` | Run drozer module |
| POST | `/api/agents/objection/explore/{pkg}` | Start objection session |
| POST | `/api/agents/objection/run` | Run objection command |
| POST | `/api/agents/owasp/{pkg}` | OWASP Mobile Top 10 |
| POST | `/api/agents/fridump/{pkg}` | Memory dump |
| GET/POST | `/api/traffic/*` | Proxy config & cert install |
| POST | `/api/reports/generate` | Generate report |
| WS | `/ws` | Real-time WebSocket |

Full Swagger docs at `http://localhost:1337/docs`.

---

## Integrated Tools

| Tool | Integration Level |
|------|------------------|
| **AndroHunter** | Full: 6 modules, Payload Engine, VULN/SUSP/SAFE classification |
| **Frida** | Full: server lifecycle, script injection, process listing |
| **Objection** | Full: persistent session, all commands |
| **Medusa** | Full: 122 modules, stash/compile/run workflow |
| **Drozer** | Full: auto-setup, module runner, assessment pipeline |
| **fridump** | Full: memory dump with PID resolution, string extraction |
| **Semgrep** | Full: 53 MASVS rules, APK decompilation (apktool/jadx) |
| **OWASP Checker** | Full: M1–M10 automated checks via ADB |

---

## Notes

- Root the device/emulator before dynamic analysis
- Start frida-server from the Frida page before using Medusa/Objection/fridump
- Portal runs standalone – no Node.js or build tools required
- For authorized security research and bug bounty programs only
