from __future__ import annotations
import subprocess
import platform
import shutil
import re
import socket
import time
import datetime
import sys
import json
from typing import Tuple, List, Optional

# -----------------------
# Utility helpers
# -----------------------

def is_windows() -> bool:
    return platform.system().lower() == "windows"

def now_ts() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def run_cmd(cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    """
    Run external command and return (returncode, stdout, stderr).
    Using shell=False for safety.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", f"Error running command {' '.join(cmd)}: {e}"

def safe_section(title: str):
    sep = "=" * 76
    print(f"\n{sep}\n{title}\n{sep}\n")

def save_report(text: str, prefix: str = "win_net_diag"):
    fname = f"{prefix}_{now_ts()}.txt"
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(text)
        return fname
    except Exception as e:
        return f"ERROR:{e}"

# -----------------------
# Diagnostic functions
# -----------------------

def quick_system_info() -> str:
    """Small OS/host summary."""
    info = []
    info.append(f"Report generated: {datetime.datetime.now().isoformat()}")
    info.append(f"Platform: {platform.platform()}")
    info.append(f"Hostname: {socket.gethostname()}")
    return "\n".join(info)

def get_ipconfig_all() -> str:
    rc, out, err = run_cmd(["ipconfig", "/all"], timeout=30)
    if rc >= 0:
        return out or err
    return f"ipconfig error: {err}"

def parse_gateways_and_dns(ipconfig_text: str) -> Tuple[List[str], List[str]]:
    """Return (gateways, dns_servers) parsed from ipconfig text."""
    gateways = []
    dns = []
    # Split blocks by blank lines - simple heuristic
    blocks = re.split(r"\r?\n\r?\n", ipconfig_text)
    for block in blocks:
        for line in block.splitlines():
            m_gw = re.search(r"Default Gateway[.\s]*:\s*(.+)", line)
            m_dns = re.search(r"DNS Servers[.\s]*:\s*(.+)", line)
            if m_gw:
                gw = m_gw.group(1).strip()
                if gw:
                    gateways.append(gw)
            if m_dns:
                d = m_dns.group(1).strip()
                if d:
                    dns.append(d)
    # dedupe while preserving order
    def uniq(seq):
        seen = set(); out = []
        for s in seq:
            if s and s not in seen:
                seen.add(s); out.append(s)
        return out
    return uniq(gateways), uniq(dns)

def netsh_interface_show() -> str:
    rc, out, err = run_cmd(["netsh", "interface", "show", "interface"], timeout=20)
    return out or err

def tracert_host(target: str = "google.com", max_hops: int = 30) -> str:
    rc, out, err = run_cmd(["tracert", "-d", "-h", str(max_hops), target], timeout=120)
    return out or err

def ping_host(target: str, count: int = 4) -> str:
    rc, out, err = run_cmd(["ping", "-n", str(count), target], timeout=30)
    return out or err

def nslookup_host(target: str = "google.com") -> str:
    rc, out, err = run_cmd(["nslookup", target], timeout=20)
    return out or err

def firewall_status() -> str:
    rc, out, err = run_cmd(["netsh", "advfirewall", "show", "allprofiles"], timeout=20)
    return out or err

def netstat_listening() -> str:
    rc, out, err = run_cmd(["netstat", "-ano"], timeout=20)
    return out or err

# -----------------------
# Speedtest helpers
# -----------------------

def run_speedtest_python_module(timeout: int = 120) -> Optional[dict]:
    """
    Try to run the Python 'speedtest' module (community speedtest-cli).
    Returns structured dict or None if not available.
    """
    try:
        # Import locally to avoid hard dependency during import-time.
        import speedtest as st  # package name: speedtest (speedtest-cli)
    except Exception:
        return None

    try:
        s = st.Speedtest()
        # get best server (may take a few seconds)
        s.get_best_server()
        # download & upload (may take time)
        dl_bps = s.download()  # bytes per second
        ul_bps = s.upload(pre_allocate=False)
        ping_ms = s.results.ping
        results = {
            "provider": "python_speedtest_module",
            "download_bps": dl_bps,
            "upload_bps": ul_bps,
            "ping_ms": ping_ms,
            "server": getattr(s, "best", None) or getattr(s, "server", None) or s.results.server
        }
        return results
    except Exception as e:
        return {"error": f"python speedtest run error: {e}"}

def run_speedtest_cli(timeout: int = 180) -> Optional[dict]:
    """
    Try Ookla 'speedtest' CLI on PATH. Returns basic parsed output or None.
    """
    if shutil.which("speedtest") is None:
        return None
    # Prefer JSON output if supported
    rc, out, err = run_cmd(["speedtest", "--format=json"], timeout=timeout)
    if rc == 0 and out:
        try:
            j = json.loads(out)
            # Normalize keys if possible
            return {"provider": "ookla_cli_json", "raw": j}
        except Exception:
            # fallback: capture raw CLI text
            return {"provider": "ookla_cli_text", "raw_text": out}
    # If JSON not available, fallback to simple output
    rc2, out2, err2 = run_cmd(["speedtest", "--simple"], timeout=timeout)
    if rc2 == 0 and out2:
        return {"provider": "ookla_cli_simple", "raw_text": out2}
    return {"error": "speedtest CLI failed", "stderr": err or err2}

def run_iperf3_subprocess(server: str, port: int = 5201, duration: int = 10) -> Optional[dict]:
    """
    If 'iperf3' binary is available, run a basic client test to given server.
    Requires an iperf3 server to be reachable.
    """
    if shutil.which("iperf3") is None:
        return None
    # run basic TCP test (-J for json output if supported)
    rc, out, err = run_cmd(["iperf3", "-c", server, "-p", str(port), "-t", str(duration), "-J"], timeout=duration + 30)
    if rc == 0 and out:
        try:
            return {"provider": "iperf3", "json": json.loads(out)}
        except Exception:
            return {"provider": "iperf3", "raw": out}
    return {"error": f"iperf3 failed: {err}"}

def run_automated_speedtest(iperf3_server: Optional[str] = None) -> Tuple[str, Optional[dict]]:
    """
    Try multiple speedtest methods in order; returns provider_name and result dict or None.
    Priority:
      1) python speedtest module
      2) Ookla speedtest CLI
      3) iperf3 if server provided and binary present
    """
    # 1) python module
    res = run_speedtest_python_module()
    if res:
        return "python_module", res

    # 2) Ookla CLI
    res = run_speedtest_cli()
    if res:
        return "ookla_cli", res

    # 3) iperf3
    if iperf3_server:
        res = run_iperf3_subprocess(iperf3_server)
        if res:
            return "iperf3", res

    # None found
    return "none", None

# -----------------------
# Recommendation logic
# -----------------------

def compact_recommendations(measures: dict) -> List[Tuple[str, str]]:
    """
    Build a checklist of simple Yes/No suggestions based on collected measures.
    Returns list of tuples: (question/issue, "Yes" or "No" and a short rationale).
    Example checks:
      - High latency to public DNS / target
      - Packet loss visible in traceroute (rudimentary)
      - Firewall disabled
      - Risky listening ports
      - Slow speed (download < 50 Mbps) — threshold configurable
    """
    checks = []

    # helper: safe fetch
    def getf(k, default=None):
        return measures.get(k, default)

    # Ping average check (8.8.8.8)
    ping_8 = getf("ping_8.8.8.8_avg_ms")
    if ping_8 is None:
        checks.append(("Public ping (8.8.8.8) measured", "No", "Ping not measured"))
    else:
        if ping_8 > 150:
            checks.append(("High public latency (avg >150ms)", "Yes", f"{ping_8:.0f} ms"))
        else:
            checks.append(("High public latency (avg >150ms)", "No", f"{ping_8:.0f} ms"))

    # DNS timing
    dns_avg = getf("dns_avg_ms")
    if dns_avg is None:
        checks.append(("DNS resolution slow (>50ms)", "No data", "DNS not measured"))
    else:
        checks.append(("DNS resolution slow (>50ms)", "Yes" if dns_avg > 50 else "No", f"{dns_avg:.1f} ms"))

    # Speed check threshold (example: 50 Mbps)
    dl_mbps = getf("download_mbps")
    if dl_mbps is None:
        checks.append(("Download speed measured", "No", "No speedtest result"))
    else:
        thr = measures.get("speed_threshold_mbps", 50)
        checks.append((f"Download < {thr} Mbps", "Yes" if dl_mbps < thr else "No", f"{dl_mbps:.2f} Mbps"))

    # Firewall disabled?
    fw_state = getf("firewall_on")
    if fw_state is None:
        checks.append(("Firewall enabled (all profiles)", "No data", "Firewall state not determined"))
    else:
        checks.append(("Firewall enabled (all profiles)", "Yes" if fw_state else "No", "OK" if fw_state else "Consider enabling"))

    # Listening risky ports (common ones)
    risky_found = measures.get("risky_listening_ports", [])
    if risky_found:
        checks.append(("Common risky listening ports open (e.g., 445, 3389, 23)", "Yes", ", ".join(str(p) for p in risky_found)))
    else:
        checks.append(("Common risky listening ports open (e.g., 445, 3389, 23)", "No", "Not found"))

    # NAT / private IP
    nat = measures.get("private_ip_detected")
    if nat is None:
        checks.append(("Private IP (NAT) detected", "No data", "ipconfig not parsed"))
    else:
        checks.append(("Private IP (NAT) detected", "Yes" if nat else "No", "NAT likely" if nat else "Public IP on interface"))

    return checks

# -----------------------
# High-level full diagnostic run
# -----------------------

def run_full_diagnostic(auto_speed: bool = True, iperf3_server: Optional[str] = None) -> str:
    """
    Orchestrates running many checks and returns a big text report.
    Collects structured measures used by recommendation generator.
    """
    measures = {}
    parts: List[str] = []
    parts.append("WIN_NET_DIAG FULL REPORT")
    parts.append(now_ts())
    parts.append("\n-- System --")
    parts.append(quick_system_info())

    parts.append("\n-- netsh interface show interface --")
    parts.append(netsh_interface_show())

    parts.append("\n-- ipconfig /all --")
    ipconf = get_ipconfig_all()
    parts.append(ipconf)

    # parse gateways and dns
    gateways, dns_servers = parse_gateways_and_dns(ipconf)
    parts.append(f"\nParsed gateways: {gateways}")
    parts.append(f"Parsed DNS servers: {dns_servers}")

    # mark private IP
    ipv4s = re.findall(r"IPv4 Address[.\s]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ipconf)
    private_ip_detected = any(ip.startswith(("10.", "172.", "192.168.")) for ip in ipv4s)
    measures["private_ip_detected"] = private_ip_detected

    # Wi-Fi details (netsh wlan show interfaces)
    rc, wifi_out, wifi_err = run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=10)
    parts.append("\n-- Wi-Fi info --")
    parts.append(wifi_out or wifi_err or "No Wi-Fi info")

    # DNS timing (python)
    parts.append("\n-- DNS resolution timing (python getaddrinfo x5) --")
    dns_host = "google.com"
    dns_times = []
    for i in range(5):
        t0 = time.perf_counter()
        try:
            socket.getaddrinfo(dns_host, None)
            t1 = time.perf_counter()
            dns_times.append((t1 - t0) * 1000.0)
        except Exception as e:
            parts.append(f"DNS attempt {i+1} failed: {e}")
            dns_times.append(float("inf"))
        time.sleep(0.08)
    valid_dns = [t for t in dns_times if t != float("inf")]
    measures["dns_avg_ms"] = (sum(valid_dns) / len(valid_dns)) if valid_dns else None
    parts.append("Attempts ms: " + ", ".join(f"{t:.1f}" if t != float("inf") else "fail" for t in dns_times))
    if measures["dns_avg_ms"] is not None:
        parts.append(f"DNS avg: {measures['dns_avg_ms']:.2f} ms")

    # nslookup
    parts.append("\n-- nslookup google.com --")
    parts.append(nslookup_host("google.com"))

    # ping tests to well-known IPs
    parts.append("\n-- Ping tests --")
    def measure_ping(tgt):
        out = ping_host(tgt, count=4)
        parts.append(f"\nPing -> {tgt}\n{out}")
        # attempt to parse avg
        m = re.search(r"Average = (\d+)ms", out)
        if not m:
            m2 = re.search(r"Average = (\d+)ms", out.replace("\r",""))
            m = m2
        if m:
            return float(m.group(1))
        # try other pattern
        m3 = re.search(r"Average = (\d+)ms", out)
        if m3:
            return float(m3.group(1))
        return None

    ping_8 = measure_ping("8.8.8.8")
    measures["ping_8.8.8.8_avg_ms"] = ping_8
    ping_1 = measure_ping("1.1.1.1")
    measures["ping_1.1.1.1_avg_ms"] = ping_1
    ping_google = measure_ping("google.com")
    measures["ping_google_avg_ms"] = ping_google

    # traceroute (may be long)
    parts.append("\n-- Traceroute to google.com (tracert -d) --")
    parts.append(tracert_host("google.com", max_hops=30))

    # firewall
    parts.append("\n-- Firewall status --")
    fw_out = firewall_status()
    parts.append(fw_out)
    # simple firewall on/off detection: search for 'State ON' or 'State OFF' per profile
    measures["firewall_on"] = True if re.search(r"State\s*ON", fw_out, re.IGNORECASE) else False

    # netstat listening ports
    parts.append("\n-- netstat -ano (listening) --")
    netstat_out = netstat_listening()
    parts.append(netstat_out[:4000] + ("\n... (truncated netstat output)" if len(netstat_out) > 4000 else ""))

    # find common risky ports in netstat - simple grep
    risky_ports = [3389, 445, 139, 23, 21]
    risky_found = []
    for p in risky_ports:
        if re.search(rf"[:\.]\b{p}\b", netstat_out):
            risky_found.append(p)
    measures["risky_listening_ports"] = risky_found

    # Routing summary
    rc, route_out, route_err = run_cmd(["route", "print"], timeout=10)
    parts.append("\n-- route print (summary truncated) --")
    parts.append("\n".join(route_out.splitlines()[:60]))

    # Automated speedtest (auto)
    measures["download_mbps"] = None
    measures["upload_mbps"] = None
    if auto_speed:
        parts.append("\n-- Automated speedtest (attempting python module, then CLI, then iperf3 if provided) --")
        provider, st_res = run_automated_speedtest(iperf3_server=iperf3_server)
        parts.append(f"Speedtest provider used: {provider}")
        if st_res is None:
            parts.append("No speedtest method available. To enable automated speedtests: install 'speedtest-cli' (pip) or put 'speedtest' CLI on PATH, or provide an iperf3 server.")
            parts.append("Install examples:\n  pip install speedtest-cli\n  OR download official Ookla Speedtest CLI and add to PATH\n  OR install iperf3 and point iperf3_server to a reachable server.")
        else:
            parts.append("Raw speedtest result (provider-specific):")
            parts.append(json.dumps(st_res, indent=2, default=str))
            # Try to extract mbps values from common providers
            if provider == "python_module" and isinstance(st_res, dict):
                try:
                    dl_mbps = float(st_res["download_bps"]) / 1e6
                    ul_mbps = float(st_res["upload_bps"]) / 1e6
                    measures["download_mbps"] = dl_mbps
                    measures["upload_mbps"] = ul_mbps
                except Exception:
                    pass
            elif provider == "ookla_cli" and isinstance(st_res, dict) and "raw" in st_res:
                # If JSON structure present, try common fields
                raw = st_res["raw"]
                if isinstance(raw, dict):
                    # Official Ookla JSON uses 'download'/'upload' in bits per second in some outputs
                    if "download" in raw and isinstance(raw["download"], dict) and "bandwidth" in raw["download"]:
                        try:
                            measures["download_mbps"] = float(raw["download"]["bandwidth"]) / 1e6
                        except Exception:
                            pass
                    # fallback: check typical keys
                    for k in ("download_bps","download","bytes_received"):
                        if k in raw and isinstance(raw[k], (int, float)):
                            measures["download_mbps"] = float(raw[k]) / 1e6
                    # similar for upload
                    if "upload" in raw and isinstance(raw["upload"], dict) and "bandwidth" in raw["upload"]:
                        try:
                            measures["upload_mbps"] = float(raw["upload"]["bandwidth"]) / 1e6
                        except Exception:
                            pass
            elif provider == "iperf3" and isinstance(st_res, dict) and "json" in st_res:
                try:
                    # iperf3 JSON -> end->sum->bits_per_second
                    js = st_res["json"]
                    if "end" in js and "sum_received" in js["end"] and "bits_per_second" in js["end"]["sum_received"]:
                        measures["download_mbps"] = float(js["end"]["sum_received"]["bits_per_second"]) / 1e6
                    if "end" in js and "sum_sent" in js["end"] and "bits_per_second" in js["end"]["sum_sent"]:
                        measures["upload_mbps"] = float(js["end"]["sum_sent"]["bits_per_second"]) / 1e6
                except Exception:
                    pass

    # add a speed threshold param for recommendations
    measures["speed_threshold_mbps"] = 50.0

    # Build recommendation checklist
    parts.append("\n-- Compact Recommendation Checklist (Yes/No) --")
    checklist = compact_recommendations(measures)
    for item, verdict, note in checklist:
        parts.append(f"{item:60} | {verdict:3} | {note}")

    # Return full report
    full_report = "\n\n".join(parts)
    return full_report

# -----------------------
# Command-line / interactive menu (numbered)
# -----------------------

def print_menu():
    print("""
Windows Network Diagnostic Tool (with automated speedtest)
1) Run full diagnostic + speedtest (recommended)
2) Run only automated speedtest now
3) Quick summary (ipconfig/netsh)
4) Traceroute to host
5) Ping tests (8.8.8.8, 1.1.1.1, google.com)
6) Netstat listening scan (risky ports)
7) Firewall status
8) Save last full report to file
0) Exit
""")

def interactive_cli():
    if not is_windows():
        print("This script is intended to run on Windows. Exiting.")
        return
    last_full = ""
    while True:
        print_menu()
        try:
            choice = input("Choose an option (number): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            return
        if not choice.isdigit():
            print("Enter a number from the menu.")
            continue
        c = int(choice)
        if c == 0:
            return
        elif c == 1:
            safe_section("Running full diagnostic (may take several minutes)")
            last_full = run_full_diagnostic(auto_speed=True, iperf3_server=None)
            print(last_full[:2000])  # print head to avoid extremely long terminal dumps
            print("\n...Full report stored in memory. Use option 8 to save to a file.")
        elif c == 2:
            safe_section("Automated speedtest now")
            provider, res = run_automated_speedtest()
            print("Provider used:", provider)
            print(json.dumps(res or {"error":"no method available"}, indent=2, default=str))
        elif c == 3:
            safe_section("Quick summary")
            print(quick_system_info())
            print("\n-- netsh interfaces --")
            print(netsh_interface_show())
            print("\n-- ipconfig /all head --")
            ic = get_ipconfig_all()
            print("\n".join(ic.splitlines()[:60]))
        elif c == 4:
            host = input("Enter host (default google.com): ").strip() or "google.com"
            safe_section(f"Traceroute to {host}")
            print(tracert_host(host))
        elif c == 5:
            safe_section("Ping tests")
            print(ping_host("8.8.8.8", count=4))
            print(ping_host("1.1.1.1", count=4))
            print(ping_host("google.com", count=4))
        elif c == 6:
            safe_section("Listening ports (netstat -ano)")
            ns = netstat_listening()
            print(ns[:4000] + ("\n... (truncated)" if len(ns) > 4000 else ""))
        elif c == 7:
            safe_section("Firewall status")
            print(firewall_status())
        elif c == 8:
            if not last_full:
                print("No full report in memory — generating one now.")
                last_full = run_full_diagnostic(auto_speed=True)
            fname = save_report(last_full)
            print("Saved to:", fname)
        else:
            print("Unknown option.")

# -----------------------
# CLI entry
# -----------------------

if __name__ == "__main__":
    # quick flags: -q run full and save; --iperf server: use iperf
    if len(sys.argv) > 1:
        if sys.argv[1] in ("-q","--quicksave"):
            rep = run_full_diagnostic(auto_speed=True, iperf3_server=None)
            fn = save_report(rep)
            print(fn)
            sys.exit(0)
        if sys.argv[1] == "--iperf" and len(sys.argv) > 2:
            srv = sys.argv[2]
            rep = run_full_diagnostic(auto_speed=True, iperf3_server=srv)
            fn = save_report(rep)
            print(fn)
            sys.exit(0)
    interactive_cli()
