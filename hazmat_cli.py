#!/usr/bin/env python3
"""
Hazmat CLI: Dynamic security scanner for npm/pip packages.
Uses the Docker sandbox in hazmat_server.py for runtime analysis.
Input: package path/name + manager
Output: verdict banner, risk level, alerts, evidence
"""
import argparse
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List
import textwrap

from hazmat_server import active_sandbox, execute_install, get_telemetry, nuke_sandbox, spin_up_sandbox


class HazmatAnalyzer:
    """Orchestrates package analysis via Docker sandbox and generates verdict."""

    LOG_FILES_MARKER = "/tmp/hazmat"

    def __init__(self, manager: str, package_path_or_name: str):
        self.manager = manager
        self.package_path = package_path_or_name
        self.session_id = f"demo-{uuid.uuid4().hex[:8]}"
        self.evidence: Dict[str, Any] = {
            "network": [],
            "filesystem": [],
            "environment": [],
            "process": [],
        }
        self.risk_score = 0
        self.max_risk = 100
        self.install_result: Dict[str, Any] = {}
        self.telemetry: Dict[str, Any] = {}

    def run_analysis(self) -> Dict[str, Any]:
        """Execute full analysis pipeline."""
        print(f"[*] Initializing analysis for {self.package_path} (manager={self.manager})")
        print(f"[*] Session: {self.session_id}\n")

        self._ensure_marker_dir()
        try:
            print(f"[+] Spinning up Docker sandbox...")
            self._spin_up_sandbox()

            print(f"[+] Installing {self.package_path} in sandbox...")
            self.install_result = self._execute_install()

            # Give hooks time to complete and write artifacts
            time.sleep(1)

            print("[+] Scanning for runtime artifacts...")
            self._scan_filesystem_markers()
            self._check_beacon_log()

            print("[+] Gathering sandbox telemetry...")
            self.telemetry = self._get_telemetry()
            self._analyze_telemetry(self.telemetry)

            verdict = self._compute_verdict()
            return {
                "ok": True,
                "session_id": self.session_id,
                "package": self.package_path,
                "manager": self.manager,
                "verdict": verdict,
                "risk_score": self.risk_score,
                "evidence": self.evidence,
                "telemetry": self.telemetry,
                "install": self.install_result,
            }
        finally:
            self._cleanup_sandbox()

    def _ensure_marker_dir(self) -> None:
        Path(self.LOG_FILES_MARKER).mkdir(parents=True, exist_ok=True)

    def _spin_up_sandbox(self) -> None:
        resp = json.loads(spin_up_sandbox(manager=self.manager, package_path=self.package_path))
        if not resp.get("ok"):
            raise RuntimeError(resp.get("message", "spin_up_sandbox failed"))
        self.session_id = resp.get("session_id", self.session_id)

    def _execute_install(self) -> Dict[str, Any]:
        resp = json.loads(execute_install(package_name=self.package_path, manager=self.manager))
        if not resp.get("ok"):
            raise RuntimeError(resp.get("message", "execute_install failed"))
        return resp.get("install", {})

    def _get_telemetry(self) -> Dict[str, Any]:
        resp = json.loads(get_telemetry())
        if not resp.get("ok"):
            raise RuntimeError(resp.get("message", "get_telemetry failed"))
        return resp.get("telemetry", {})

    def _cleanup_sandbox(self) -> None:
        try:
            if active_sandbox.get("id"):
                nuke_sandbox(session_id=self.session_id)
        except Exception:
            pass

    def _scan_filesystem_markers(self):
        marker_dir = Path(self.LOG_FILES_MARKER)
        if not marker_dir.exists():
            return

        for marker_file in marker_dir.glob("postinstall_*.txt"):
            try:
                content = marker_file.read_text()
                self.evidence["filesystem"].append({
                    "type": "postinstall_marker",
                    "file": str(marker_file),
                    "content": content[:200],
                })
                self.risk_score += 25
            except Exception:
                pass

        for env_file in marker_dir.glob("env_scan_*.json"):
            try:
                data = json.loads(env_file.read_text())
                self.evidence["environment"].append({
                    "type": "credential_reconnaissance",
                    "file": str(env_file),
                    "suspicious_vars": data.get("suspicious_vars_found", []),
                    "count": data.get("count", 0),
                })
                self.risk_score += 15
            except Exception:
                pass

    def _check_beacon_log(self):
        marker_dir = Path(self.LOG_FILES_MARKER)
        beacon_log = marker_dir / "beacon_log.json"
        if beacon_log.exists():
            try:
                with open(beacon_log) as f:
                    beacons = [json.loads(line) for line in f if line.strip()]
                if beacons:
                    self.evidence["network"].append({
                        "type": "outbound_beacon",
                        "count": len(beacons),
                        "samples": beacons[:2],
                    })
                    self.risk_score += 30
            except Exception:
                pass

    def _analyze_telemetry(self, telemetry: Dict[str, Any]):
        if telemetry.get("network", {}).get("verdict") == "suspicious":
            self.evidence["network"].append({
                "type": "unexpected_network_connection",
                "connections": telemetry.get("network", {}).get("tcp_added", [])
                + telemetry.get("network", {}).get("tcp6_added", []),
                "count": len(telemetry.get("network", {}).get("tcp_added", []))
                + len(telemetry.get("network", {}).get("tcp6_added", [])),
            })
            self.risk_score += 20

        if telemetry.get("filesystem", {}).get("changed"):
            self.evidence["filesystem"].append({
                "type": "filesystem_change",
                "before_tail": telemetry.get("filesystem", {}).get("before_tail", []),
                "after_tail": telemetry.get("filesystem", {}).get("after_tail", []),
            })
            self.risk_score += 10

        if telemetry.get("processes", {}).get("current_head"):
            self.evidence["process"].append({
                "type": "process_snapshot",
                "current_head": telemetry.get("processes", {}).get("current_head", []),
            })

    def _compute_verdict(self) -> Dict[str, Any]:
        self.risk_score = min(self.risk_score, self.max_risk)

        if self.risk_score >= 75:
            level = "CRITICAL"
            emoji = "🔴"
            status = "MALICIOUS"
        elif self.risk_score >= 50:
            level = "HIGH"
            emoji = "🟠"
            status = "SUSPICIOUS"
        elif self.risk_score >= 25:
            level = "MEDIUM"
            emoji = "🟡"
            status = "UNUSUAL"
        else:
            level = "LOW"
            emoji = "🟢"
            status = "CLEAN"

        return {
            "status": status,
            "level": level,
            "emoji": emoji,
            "risk_score": self.risk_score,
            "alerts_count": len(self._flatten_evidence()),
        }

    def _flatten_evidence(self) -> List[Dict]:
        """Flatten evidence list for counting."""
        flat = []
        for category in self.evidence.values():
            if isinstance(category, list):
                flat.extend(category)
        return flat


def print_verdict_banner(result: Dict):
    """Print human-readable verdict with formatting."""
    verdict = result["verdict"]
    
    # Banner
    emoji = verdict["emoji"]
    status = verdict["status"]
    level = verdict["level"]
    risk = verdict["risk_score"]
    
    banner_width = 60
    print("\n" + "=" * banner_width)
    print(f"{emoji} VERDICT: {status}".center(banner_width))
    print("=" * banner_width)
    
    print(f"\nRisk Level: {level}")
    print(f"Risk Score: {risk}/{100}")
    print(f"Alerts: {verdict['alerts_count']}")
    print(f"Package: {result['package']}")
    print(f"Manager: {result['manager']}")
    
    # Display top alerts
    evidence = result["evidence"]
    alert_count = 0
    
    print("\n" + "-" * banner_width)
    print("TOP ALERTS:")
    print("-" * banner_width)
    
    # Filesystem evidence (highest priority)
    for item in evidence.get("filesystem", []):
        if alert_count >= 3:
            break
        alert_count += 1
        item_type = item.get("type", "unknown")
        print(f"\n{alert_count}. {item_type.upper()}")
        if item_type == "postinstall_marker":
            content = item.get("content", "")
            lines = content.split('\n')[:3]
            for line in lines:
                if line.strip():
                    print(f"    {line}")
        elif item_type == "credential_reconnaissance":
            vars_found = item.get("suspicious_vars", [])
            print(f"    Found {item.get('count')} suspicious environment variables")
            for var in vars_found[:3]:
                print(f"      - {var}")
        elif item_type == "unexpected_file_writes":
            files = item.get("files", [])
            count = item.get("count", 0)
            print(f"    Unexpected writes detected: {count} files")
            for f in files[:2]:
                print(f"      - {f}")
    
    # Network evidence
    for item in evidence.get("network", []):
        if alert_count >= 3:
            break
        alert_count += 1
        item_type = item.get("type", "unknown")
        print(f"\n{alert_count}. {item_type.upper()}")
        if item_type == "outbound_beacon":
            beacons = item.get("samples", [])
            print(f"    Outbound connections: {item.get('count')} total")
            for beacon in beacons[:1]:
                payload = beacon.get("payload", {})
                print(f"    Sample: {json.dumps(payload, indent=6)[:150]}...")
        elif item_type == "unexpected_network_connection":
            conns = item.get("connections", [])
            count = item.get("count", 0)
            print(f"    Unexpected connections: {count} total")
            for conn in conns[:2]:
                print(f"      - {conn}")
    
    # Environment evidence
    for item in evidence.get("environment", []):
        if alert_count >= 3:
            break
        alert_count += 1
        item_type = item.get("type", "unknown")
        print(f"\n{alert_count}. {item_type.upper()}")
        vars_found = item.get("suspicious_vars", [])
        print(f"    Scanning for credentials in environment")
        print(f"    Suspicious variables found: {len(vars_found)}")
        for var in vars_found[:3]:
            print(f"      - {var}")
    
    print("\n" + "=" * banner_width + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Hazmat CLI: Dynamic Security Scanner for npm/pip packages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          %(prog)s --manager npm --package ./test_packages/malicious_pkg
          %(prog)s --manager npm --package ./test_packages/benign_pkg
          %(prog)s --manager pip --package requests
        """)
    )
    
    parser.add_argument(
        "--manager",
        choices=["npm", "pip"],
        required=True,
        help="Package manager to use",
    )
    parser.add_argument(
        "--package",
        required=True,
        help="Package path (local) or name (registry)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print raw telemetry data",
    )
    
    args = parser.parse_args()
    
    # Run analysis
    analyzer = HazmatAnalyzer(args.manager, args.package)
    try:
        result = analyzer.run_analysis()
        
        if result["ok"]:
            # Print verdict banner
            print_verdict_banner(result)
            
            # Optional: dump raw telemetry
            if args.verbose:
                print("\n[VERBOSE] Raw Telemetry:")
                print(json.dumps(result["telemetry"], indent=2)[:1000])
            
            # Exit with appropriate code
            risk = result["verdict"]["risk_score"]
            if risk >= 50:
                sys.exit(1)  # Non-zero for suspicious/malicious
            else:
                sys.exit(0)  # Zero for clean
        else:
            print(f"ERROR: Analysis failed", file=sys.stderr)
            sys.exit(2)
    
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
