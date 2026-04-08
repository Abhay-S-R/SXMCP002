# 🛡️ Hazmat Live Demo - Quick Start

## 30-Second Pitch

> **Static analysis can't see postinstall hooks. We show what happens when a "normal-looking crypto utils package" runs at install time.**

## One-Command Demo

```bash
cd /Users/rohith/Desktop/Hackathon/solaris
./demo.sh
```

This runs two tests:
1. **Benign package** → 🟢 CLEAN verdict
2. **Malicious package** → 🔴 CRITICAL verdict with evidence

## What You'll See

### Test 1: Benign Package
```
🟢 VERDICT: CLEAN
Risk Level: LOW (0/100)
Alerts: 0
```

### Test 2: Malicious Package  
```
🔴 VERDICT: CRITICAL / SUSPICIOUS
Risk Level: HIGH/CRITICAL (70-85/100)
Alerts: 3+

TOP ALERTS:
1. POSTINSTALL_MARKER
   Files written to /tmp/hazmat/ at install time
   
2. OUTBOUND_BEACON  
   Package tried to call home to localhost:9999
   
3. CREDENTIAL_RECONNAISSANCE
   Package scanned environment for AWS keys, tokens, etc.
```

## Manual Testing

```bash
# Terminal 1: Start mock beacon server
python3 mock_server.py

# Terminal 2: Run tests
python3 hazmat_cli.py --manager npm --package ./test_packages/benign_pkg
python3 hazmat_cli.py --manager npm --package ./test_packages/malicious_pkg --verbose
```

## Evidence Inspection

After running, check `/tmp/hazmat/` for raw artifacts:

```bash
# Files written by malicious postinstall
cat /tmp/hazmat/postinstall_*.txt

# Credentials it was hunting for
cat /tmp/hazmat/env_scan_*.json

# Outbound connection attempts
cat /tmp/hazmat/beacon_log.json
```

## The Story

| Step | What Happens | What We Detect |
|------|--------------|-----------------|
| 1. Install package | `npm install crypto-utils` | ✅ Starting scan |
| 2. Postinstall hook runs | Writes `/tmp/hazmat/postinstall_*.txt` | 🔴 MARKER FOUND! |
| 3. Env scanning | Looks for `AWS_SECRET`, `GITHUB_TOKEN` | 🔴 CREDENTIAL HUNT! |
| 4. Connect to C&C | Tries `localhost:9999/beacon` | 🔴 BEACON ATTEMPT! |
| 5. Verdict | Risk score = 25+30+15 = 70+ | 🔴 SUSPICIOUS/CRITICAL |

## Why This Matters

- **Static analysis failed** - Code review saw nothing unusual
- **Runtime telemetry succeeded** - We caught the actual attack
- **Judges can see it** - Clear evidence, formatted output, visual alerts
- **Real attack vectors** - Similar to left-pad, old npm exploits, supply chain attacks

## File Structure

```
test_packages/
  ├── benign_pkg/
  │   ├── package.json
  │   └── index.js (simple utility functions)
  └── malicious_pkg/
      ├── package.json
      ├── postinstall.js        ← THE ATTACK
      └── index.js

hazmat_cli.py               ← Main scanner
mock_server.py              ← Beacon logger
demo.sh                     ← One-click demo
LIVE_DEMO.md               ← Full documentation
```

## Troubleshooting

**npm not found?**
```bash
# Install Node.js
brew install node
```

**Port 9999 in use?**
```bash
# Kill existing process
lsof -i :9999 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

**Want to see more alerts?**  
Edit `test_packages/malicious_pkg/postinstall.js` to add:
- SSH key theft  
- Git credential stealing
- Source code exfiltration
- Shell profile modification

## Key Points for Judges

✅ **No Docker required** - Works on any machine with Node.js  
✅ **Reproducible** - Same output every time  
✅ **Visual** - Easy to understand verdicts and alerts  
✅ **Provable** - Raw evidence files in `/tmp/hazmat/`  
✅ **Extensible** - Same approach detects real attacks  

---

**Ready?** Run `./demo.sh` and watch the magic happen! 🔴
