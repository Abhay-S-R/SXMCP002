# Hazmat Live Demo: Catching Malicious npm Packages

## The Story

**Static Analysis Fails** → "Looks like a normal crypto utils library, probably fine."  
**Runtime Execution** → "Wait, it's writing files to /tmp/hazmat and calling home to localhost:9999?!"

This demo visually shows the difference between code review and **runtime behavior detection**. A package can look innocent in static review but execute malicious payloads during `npm install` or `pip install`.

---

## What's in the Demo

### 1. **Test Packages**

#### `test_packages/benign_pkg/`
- Simple string utilities (capitalize, reverse, repeat)
- No postinstall hooks
- No network activity
- **Expected**: Clean, low-risk verdict

#### `test_packages/malicious_pkg/`
- Looks like "crypto-utils" library
- **Postinstall hook** (`postinstall.js`) that:
  - Writes marker files to `/tmp/hazmat/postinstall_*.txt`
  - Attempts outbound connection to mock server (`localhost:9999`)
  - Scans environment for credential-like variables
  - Steals into `/tmp/hazmat/env_scan_*.json`
- **Expected**: CRITICAL verdict with multiple red alerts

### 2. **Mock Server** (`mock_server.py`)
- Listens on `localhost:9999` for outbound connections
- Logs all connection attempts to `/tmp/hazmat/beacon_log.json`
- Shows the "C&C communication" that happens at install time
- Runs silently; postinstall script handles failures gracefully

### 3. **Hazmat CLI** (`hazmat_cli.py`)
Main orchestrator that:
1. Spins up isolated Docker/container sandbox
2. Installs the package in sandbox
3. Collects telemetry (network, filesystem, process)
4. Scans for runtime artifacts (marker files, beacons)
5. Scores risk-level
6. **Outputs human-readable verdict banner**

#### Verdict Banner Example (MALICIOUS):

```
============================================================
🔴 VERDICT: MALICIOUS
============================================================

Risk Level: CRITICAL
Risk Score: 85/100
Alerts: 3
Package: test_packages/malicious_pkg
Manager: npm

------------------------------------------------------------
TOP ALERTS:
------------------------------------------------------------

1. POSTINSTALL_MARKER
    MALICIOUS POSTINSTALL EXECUTED
    Timestamp: 2026-04-08T12:34:56.789Z
    User: root

2. OUTBOUND_BEACON
    Outbound connections: 1 total
    Sample: {'action': 'postinstall_hook', 'package': 'crypto-utils-malicious', 
             'user': 'root', 'timestamp': '2026-04-08T12:34:56.789Z'}

3. CREDENTIAL_RECONNAISSANCE
    Scanning for credentials in environment
    Suspicious variables found: 2
      - AWS_SECRET_ACCESS_KEY
      - GITHUB_TOKEN

============================================================
```

---

## How to Run the Live Demo

### Prerequisites

```bash
# From the solaris/ directory
source .venv/bin/activate
pip install -r requirements.txt
```

The setup already includes:
- Docker (for sandbox)
- httpx + mcp (for server infrastructure)
- Standard library modules

### Run Full Demo

```bash
chmod +x demo.sh
./demo.sh
```

This script:
1. ✅ Starts the mock server
2. ✅ Scans benign package → GREEN/CLEAN
3. ✅ Scans malicious package → RED/CRITICAL with alerts
4. ✅ Cleans up automatically

### Manual Testing

If you want to test individual packages:

```bash
# Test benign package
python3 hazmat_cli.py --manager npm --package ./test_packages/benign_pkg

# Test malicious package
python3 hazmat_cli.py --manager npm --package ./test_packages/malicious_pkg --verbose

# In another terminal, start mock server
python3 mock_server.py
```

---

## Evidence Collection

After running the demo, inspect `/tmp/hazmat/` for raw evidence:

```bash
ls -la /tmp/hazmat/

# Marker files from postinstall
cat /tmp/hazmat/postinstall_*.txt

# Environment scan results
cat /tmp/hazmat/env_scan_*.json

# Network beacons (if mock server was running)
cat /tmp/hazmat/beacon_log.json
```

---

## Key Differences: Benign vs. Malicious

| Aspect | Benign | Malicious |
|--------|--------|-----------|
| **size** | ~2 files | code + postinstall hook |
| **postinstall hook** | None | ✓ Yes |
| **file writes** | None | ✓ Yes (/tmp/hazmat/) |
| **network calls** | None | ✓ Yes (localhost:9999) |
| **env scanning** | None | ✓ Yes (credential hunt) |
| **Hazmat Verdict** | 🟢 CLEAN (0-25) | 🔴 CRITICAL (75+) |
| **Exit Code** | 0 | 1 |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│         hazmat_cli.py                       │
│         (Main Orchestrator)                 │
└──────────┬──────────────────────────────────┘
           │
           ├─→ hazmat_server.py
           │   ├─ spin_up_sandbox()
           │   ├─ execute_install()
           │   ├─ get_telemetry()
           │   └─ nuke_sandbox()
           │
           ├─→ Docker Container
           │   ├─ npm install <package>
           │   ├─ postinstall hook executes
           │   └─ Telemetry collected
           │
           ├─→ Filesystem Scanning
           │   └─ /tmp/hazmat/postinstall_*.txt
           │   └─ /tmp/hazmat/env_scan_*.json
           │   └─ /tmp/hazmat/beacon_log.json
           │
           └─→ Risk Scoring & Verdict
               ├─ Marker file found: +25
               ├─ Network connection: +30
               ├─ Env credentials scanned: +15
               └─ Output: CRITICAL 🔴
```

---

## Why This Demo Matters

✅ **Visual Impact**: Judges see "looks innocent" → "GOES BOOM" in real time  
✅ **Concrete Evidence**: Not abstract; shows actual artifacts (files, connections)  
✅ **Static Analysis Gap**: Proves static review miss runtime behavior  
✅ **Scalable Story**: Same approach detects real supply-chain attacks  
✅ **Easy to Reproduce**: One script; reproducible every time  

---

## Extending the Demo

### Add More Attack Vectors

Modify `test_packages/malicious_pkg/postinstall.js` to:
- Write SSH keys
- Exfiltrate source code
- Install backdoors
- Modify shell profiles
- Steal git credentials

### Support Multiple Managers

Extend `hazmat_cli.py` to test:
- PyPI packages (`pip`)
- RubyGems packages (`gem`)
- Maven packages (Java)

### Production Integration

Use this as foundation for:
- Continuous monitoring of dependencies
- Automated scanning in CI/CD
- Real-time supply chain risk dashboard

---

## Questions for Judges

**"How would static analysis find this?"**  
→ It wouldn't. The code looks fine; the attack happens at runtime.

**"Is this realistic?"**  
→ Yes. Real attacks (left-pad, old version of npm packages) use similar techniques.

**"Can packages hide postinstall hooks?"**  
→ Yes, which is why **runtime detection is essential**.

---

## File Structure

```
solaris/
├── hazmat_cli.py           # Main CLI orchestrator
├── mock_server.py           # Connection logger
├── demo.sh                  # Full demo script
├── hazmat_server.py         # MCP server (existing)
├── smoke_test.py            # Basic smoke test (existing)
├── requirements.txt         # Dependencies
├── README.md                # Project overview
└── test_packages/
    ├── benign_pkg/          # ✓ Clean package
    │   ├── package.json
    │   └── index.js
    └── malicious_pkg/       # ✗ Malicious package
        ├── package.json
        ├── postinstall.js   # THE ATTACK
        └── index.js
```

---

## Troubleshooting

### Docker not running
```bash
# Start Docker
docker ps  # should work
```

### Port 9999 already in use
```bash
# Kill existing process
lsof -i :9999 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

### /tmp/hazmat/ permission error
```bash
# Ensure /tmp/hazmat is writable
mkdir -p /tmp/hazmat
chmod 777 /tmp/hazmat
```

### npm not found in Docker
Check that Docker image has Node.js installed. Sandbox base image should be Alpine Linux with nodejs pre-installed.

---

## Success Criteria

- [ ] Run `./demo.sh` → no errors
- [ ] Benign package → 🟢 CLEAN, exit 0
- [ ] Malicious package → 🔴 CRITICAL, exit 1
- [ ] Evidence files exist in `/tmp/hazmat/`
- [ ] Judges can understand the story without deep tech knowledge
