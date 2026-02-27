"""External security scanning tools: nmap, nikto, sslyze, subfinder.

These tools invoke external binaries installed in the Docker image and return
structured JSON results to the MCP client.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any


def _run(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -2


def _check_tool(name: str) -> str | None:
    """Return the path to a binary or None if not installed."""
    return shutil.which(name)


# ---------------------------------------------------------------------------
# nmap output parsing
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_str: str) -> dict[str, Any]:
    """Parse nmap XML output into a structured dict."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {"error": "Failed to parse nmap XML output"}

    result: dict[str, Any] = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "hosts": [],
    }

    for host_el in root.findall("host"):
        host: dict[str, Any] = {"status": "", "addresses": [], "ports": [], "os": [], "hostnames": []}

        status = host_el.find("status")
        if status is not None:
            host["status"] = status.get("state", "unknown")

        for addr in host_el.findall("address"):
            host["addresses"].append({
                "addr": addr.get("addr", ""),
                "type": addr.get("addrtype", ""),
            })

        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                host["hostnames"].append(hn.get("name", ""))

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_info: dict[str, Any] = {
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                }
                state = port_el.find("state")
                if state is not None:
                    port_info["state"] = state.get("state", "")
                    port_info["reason"] = state.get("reason", "")
                service = port_el.find("service")
                if service is not None:
                    port_info["service"] = service.get("name", "")
                    port_info["product"] = service.get("product", "")
                    port_info["version"] = service.get("version", "")
                    port_info["extrainfo"] = service.get("extrainfo", "")

                # Script output (e.g. vuln detection)
                scripts = []
                for script_el in port_el.findall("script"):
                    scripts.append({
                        "id": script_el.get("id", ""),
                        "output": script_el.get("output", "")[:2000],
                    })
                if scripts:
                    port_info["scripts"] = scripts

                port_info = {k: v for k, v in port_info.items() if v}
                host["ports"].append(port_info)

        os_el = host_el.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                host["os"].append({
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                })

        # Clean empty lists
        host = {k: v for k, v in host.items() if v}
        result["hosts"].append(host)

    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            result["elapsed"] = finished.get("elapsed", "")
        hosts_stat = runstats.find("hosts")
        if hosts_stat is not None:
            result["hosts_up"] = hosts_stat.get("up", "0")
            result["hosts_down"] = hosts_stat.get("down", "0")

    return result


# ---------------------------------------------------------------------------
# nikto output parsing
# ---------------------------------------------------------------------------

def _parse_nikto_json(output: str) -> dict[str, Any]:
    """Parse nikto JSON output."""
    # nikto -Format json outputs one JSON object
    try:
        data = json.loads(output)
        return data
    except json.JSONDecodeError:
        pass
    # Fallback: parse text output into structured form
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("+"):
            findings.append(line[2:].strip())
    return {"raw_findings": findings, "count": len(findings)}


# ---------------------------------------------------------------------------
# sslyze output parsing
# ---------------------------------------------------------------------------

def _parse_sslyze_json(output: str) -> dict[str, Any]:
    """Parse sslyze JSON output."""
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"raw_output": output[:5000]}


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register(mcp, helpers):
    _json = helpers["_json"]

    @mcp.tool()
    def nmap_scan(
        target: str,
        scan_type: str = "service",
        ports: str | None = None,
        scripts: str | None = None,
        timeout: int = 120,
    ) -> str:
        """Run an nmap scan against a target host or IP.

        target: hostname or IP address to scan (e.g. "example.com", "192.168.1.1")
        scan_type: one of:
          - "quick"    : fast top-100 port scan (-F)
          - "service"  : service/version detection on common ports (-sV, default)
          - "full"     : all 65535 ports with service detection (-p- -sV)
          - "vuln"     : run vulnerability detection scripts (--script vuln)
          - "stealth"  : SYN scan (-sS, requires root)
          - "udp"      : UDP scan (-sU, slower)
          - "os"       : OS detection (-O, requires root)
        ports: custom port specification (e.g. "80,443,8080" or "1-1000")
        scripts: comma-separated nmap scripts to run (e.g. "http-headers,ssl-enum-ciphers")
        timeout: max seconds to wait (default 120)

        Returns structured results: open ports, services, versions, script output.
        """
        if not _check_tool("nmap"):
            return _json({"error": "nmap is not installed in the container"})

        # Sanitize target - only allow hostnames, IPs, and CIDR
        if not re.match(r'^[a-zA-Z0-9._\-:/]+$', target):
            return _json({"error": "Invalid target format"})

        cmd = ["nmap", "-oX", "-"]  # XML output to stdout

        type_flags = {
            "quick": ["-F"],
            "service": ["-sV"],
            "full": ["-p-", "-sV"],
            "vuln": ["-sV", "--script", "vuln"],
            "stealth": ["-sS"],
            "udp": ["-sU"],
            "os": ["-O"],
        }
        cmd.extend(type_flags.get(scan_type, ["-sV"]))

        if ports:
            if re.match(r'^[\d,\-]+$', ports):
                cmd.extend(["-p", ports])
            else:
                return _json({"error": "Invalid port specification"})

        if scripts:
            if re.match(r'^[a-zA-Z0-9_,\-]+$', scripts):
                cmd.extend(["--script", scripts])
            else:
                return _json({"error": "Invalid script names"})

        cmd.append(target)

        stdout, stderr, rc = _run(cmd, timeout=timeout)
        if rc < 0:
            return _json({"error": stderr})

        result = _parse_nmap_xml(stdout)
        if stderr and "WARNING" in stderr:
            result["warnings"] = [l.strip() for l in stderr.splitlines() if "WARNING" in l][:5]
        return _json(result)

    @mcp.tool()
    def nikto_scan(
        target: str,
        port: int | None = None,
        ssl: bool = False,
        tuning: str | None = None,
        timeout: int = 180,
    ) -> str:
        """Run a nikto web vulnerability scan against a target.

        target: hostname or IP to scan (e.g. "example.com")
        port: port to scan (default: 80 or 443 if ssl=True)
        ssl: force SSL/HTTPS
        tuning: nikto tuning options to control scan scope:
          1 - Interesting File / Seen in logs
          2 - Misconfiguration / Default File
          3 - Information Disclosure
          4 - Injection (XSS/Script/HTML)
          5 - Remote File Retrieval - Inside Web Root
          6 - Denial of Service
          7 - Remote File Retrieval - Server Wide
          8 - Command Execution / Remote Shell
          9 - SQL Injection
          0 - File Upload
          a - Authentication Bypass
          b - Software Identification
          c - Remote source inclusion
          x - Reverse Tuning (exclude these tests)
        timeout: max seconds (default 180)

        Returns categorized vulnerability findings.
        """
        if not _check_tool("nikto"):
            return _json({"error": "nikto is not installed in the container"})

        if not re.match(r'^[a-zA-Z0-9._\-:]+$', target):
            return _json({"error": "Invalid target format"})

        cmd = ["nikto", "-h", target, "-Format", "json", "-o", "-"]

        if port:
            cmd.extend(["-p", str(port)])
        if ssl:
            cmd.append("-ssl")
        if tuning:
            if re.match(r'^[0-9a-cx]+$', tuning):
                cmd.extend(["-Tuning", tuning])
            else:
                return _json({"error": "Invalid tuning value"})

        # Limit scan duration
        cmd.extend(["-maxtime", str(min(timeout, 300))])

        stdout, stderr, rc = _run(cmd, timeout=timeout + 10)
        if rc < 0:
            return _json({"error": stderr})

        result = _parse_nikto_json(stdout)
        result["target"] = target
        return _json(result)

    @mcp.tool()
    def sslyze_scan(
        target: str,
        port: int = 443,
        timeout: int = 60,
    ) -> str:
        """Analyze SSL/TLS configuration and certificates of a target.

        target: hostname to scan (e.g. "example.com")
        port: port to connect to (default: 443)
        timeout: max seconds (default 60)

        Reports: certificate info, supported protocols (SSLv2/3, TLS 1.0-1.3),
        cipher suites, vulnerabilities (Heartbleed, ROBOT, etc.), HSTS status.
        """
        if not _check_tool("sslyze"):
            return _json({"error": "sslyze is not installed in the container"})

        if not re.match(r'^[a-zA-Z0-9._\-]+$', target):
            return _json({"error": "Invalid target format"})

        server = f"{target}:{port}" if port != 443 else target
        cmd = ["sslyze", "--json_out=-", server]

        stdout, stderr, rc = _run(cmd, timeout=timeout)
        if rc < 0:
            return _json({"error": stderr})

        full = _parse_sslyze_json(stdout)

        # Extract the most useful info into a summary
        summary: dict[str, Any] = {"target": server}

        if isinstance(full, dict) and "server_scan_results" in full:
            results = full["server_scan_results"]
            if results and len(results) > 0:
                scan = results[0]
                cmds = scan.get("scan_result", {}) or scan.get("scan_commands_results", {})

                # Certificate info
                cert_info = cmds.get("certificate_info", {})
                if cert_info:
                    deployments = cert_info.get("result", {}).get("certificate_deployments", [])
                    if deployments:
                        leaf = deployments[0].get("received_certificate_chain", [{}])
                        if leaf:
                            subj = leaf[0].get("subject", {})
                            summary["certificate"] = {
                                "subject": subj,
                                "issuer": leaf[0].get("issuer", {}),
                                "not_before": leaf[0].get("not_valid_before", ""),
                                "not_after": leaf[0].get("not_valid_after", ""),
                                "serial": leaf[0].get("serial_number", ""),
                            }

                # Protocol support
                protocols = {}
                for proto in ["ssl_2_0", "ssl_3_0", "tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"]:
                    proto_result = cmds.get(proto, {})
                    if proto_result:
                        accepted = proto_result.get("result", {}).get("accepted_cipher_suites", [])
                        protocols[proto] = {
                            "supported": len(accepted) > 0,
                            "cipher_count": len(accepted),
                        }
                if protocols:
                    summary["protocols"] = protocols

                # Vulnerabilities
                vulns = {}
                for vuln_name in ["heartbleed", "openssl_ccs_injection", "robot"]:
                    vuln_result = cmds.get(vuln_name, {})
                    if vuln_result:
                        r = vuln_result.get("result", {})
                        vulns[vuln_name] = r.get("is_vulnerable_to_" + vuln_name,
                                                  r.get("result", "unknown"))
                if vulns:
                    summary["vulnerabilities"] = vulns

                return _json(summary)

        # Fallback: return truncated raw output
        summary["raw"] = full if isinstance(full, dict) else {"output": str(full)[:5000]}
        return _json(summary)

    @mcp.tool()
    def subfinder_scan(
        domain: str,
        timeout: int = 60,
    ) -> str:
        """Enumerate subdomains of a domain using passive sources.

        domain: target domain (e.g. "example.com")
        timeout: max seconds (default 60)

        Returns a list of discovered subdomains from certificate transparency
        logs, search engines, DNS databases, and other OSINT sources.
        No active scanning is performed — all data comes from public sources.
        """
        if not _check_tool("subfinder"):
            return _json({"error": "subfinder is not installed in the container"})

        if not re.match(r'^[a-zA-Z0-9._\-]+$', domain):
            return _json({"error": "Invalid domain format"})

        cmd = ["subfinder", "-d", domain, "-silent", "-json"]

        stdout, stderr, rc = _run(cmd, timeout=timeout)
        if rc < 0:
            return _json({"error": stderr})

        subdomains = []
        sources: dict[str, list[str]] = {}
        for line in stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                host = entry.get("host", "")
                src = entry.get("source", "unknown")
                if host:
                    subdomains.append(host)
                    sources.setdefault(src, []).append(host)
            except json.JSONDecodeError:
                if line.strip():
                    subdomains.append(line.strip())

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for s in subdomains:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return _json({
            "domain": domain,
            "subdomain_count": len(unique),
            "subdomains": unique,
            "by_source": {k: list(set(v)) for k, v in sources.items()},
        })

    @mcp.tool()
    def scan_available_tools() -> str:
        """Check which external scanning tools are installed and available.

        Returns the availability status of nmap, nikto, sslyze, and subfinder.
        """
        tools = ["nmap", "nikto", "sslyze", "subfinder"]
        status = {}
        for t in tools:
            path = _check_tool(t)
            if path:
                # Get version
                version_flags = {
                    "nmap": ["nmap", "--version"],
                    "nikto": ["nikto", "-Version"],
                    "sslyze": ["sslyze", "--version"],
                    "subfinder": ["subfinder", "-version"],
                }
                stdout, stderr, _ = _run(version_flags.get(t, [t, "--version"]), timeout=10)
                ver = (stdout or stderr).strip().splitlines()
                status[t] = {
                    "available": True,
                    "path": path,
                    "version": ver[0] if ver else "unknown",
                }
            else:
                status[t] = {"available": False}
        return _json(status)
