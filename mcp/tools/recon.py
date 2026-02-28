"""Asset discovery and reconnaissance tools.

Combines nmap (network layer), httpx (HTTP probing), dnsx (DNS enumeration),
and subfinder (subdomain discovery) into high-level recon workflows.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def _run(cmd: list[str], timeout: int = 120, stdin_data: str | None = None) -> tuple[str, str, int]:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -2


def _has(name: str) -> bool:
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# nmap XML parsing (host-discovery focused)
# ---------------------------------------------------------------------------

def _parse_nmap_hosts(xml_str: str) -> list[dict[str, Any]]:
    """Parse nmap XML into a list of discovered hosts."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return []

    hosts = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        entry: dict[str, Any] = {"addresses": [], "hostnames": [], "ports": [], "os": []}

        for addr in host_el.findall("address"):
            entry["addresses"].append({
                "addr": addr.get("addr", ""),
                "type": addr.get("addrtype", ""),
            })

        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                entry["hostnames"].append(hn.get("name", ""))

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state = port_el.find("state")
                if state is not None and state.get("state") != "open":
                    continue
                p: dict[str, Any] = {
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                }
                svc = port_el.find("service")
                if svc is not None:
                    p["service"] = svc.get("name", "")
                    p["product"] = svc.get("product", "")
                    p["version"] = svc.get("version", "")
                    p["extrainfo"] = svc.get("extrainfo", "")
                    p = {k: v for k, v in p.items() if v}
                entry["ports"].append(p)

        os_el = host_el.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                entry["os"].append({
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                })

        entry = {k: v for k, v in entry.items() if v}
        hosts.append(entry)

    return hosts


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register(mcp, helpers):
    _json = helpers["_json"]

    @mcp.tool()
    def discover_hosts(
        target: str,
        scan_type: str = "ping",
        ports: str | None = None,
        timeout: int = 120,
    ) -> str:
        """Discover live hosts on a network or subnet using nmap.

        target: IP range or CIDR (e.g. "192.168.1.0/24", "10.0.0.1-50")
        scan_type: one of:
          - "ping"    : ICMP ping sweep (-sn) — fast, finds live hosts
          - "arp"     : ARP discovery (-PR) — best for local networks
          - "syn"     : TCP SYN discovery on common ports (-PS)
          - "connect" : TCP connect on top ports — finds hosts with firewalls
          - "service" : live hosts + top-port service detection (-sV)
        ports: custom ports for syn/connect (default: common ports)
        timeout: max seconds (default 120)

        Returns a list of live hosts with IPs, hostnames, and open ports.
        """
        if not _has("nmap"):
            return _json({"error": "nmap is not installed"})

        if not re.match(r'^[a-zA-Z0-9._\-:/\s]+$', target):
            return _json({"error": "Invalid target format"})

        cmd = ["nmap", "-oX", "-"]

        if scan_type == "ping":
            cmd.append("-sn")
        elif scan_type == "arp":
            cmd.extend(["-sn", "-PR"])
        elif scan_type == "syn":
            cmd.append("-PS")
            if ports and re.match(r'^[\d,\-]+$', ports):
                cmd[-1] = f"-PS{ports}"
        elif scan_type == "connect":
            cmd.extend(["-sT", "-F"])  # Fast top-100 ports
            if ports and re.match(r'^[\d,\-]+$', ports):
                cmd.extend(["-p", ports])
        elif scan_type == "service":
            cmd.extend(["-sV", "-F"])
            if ports and re.match(r'^[\d,\-]+$', ports):
                cmd.extend(["-p", ports])
        else:
            cmd.append("-sn")

        cmd.append(target)

        stdout, stderr, rc = _run(cmd, timeout=timeout)
        if rc < 0:
            return _json({"error": stderr})

        hosts = _parse_nmap_hosts(stdout)
        return _json({
            "target": target,
            "scan_type": scan_type,
            "hosts_found": len(hosts),
            "hosts": hosts,
        })

    @mcp.tool()
    def fingerprint_services(
        target: str,
        ports: str = "1-1000",
        detect_os: bool = False,
        timeout: int = 180,
    ) -> str:
        """Deep service fingerprinting on a single host.

        Detects service names, versions, and optionally OS. More thorough
        than a basic port scan — uses nmap's version probes.

        target: single IP or hostname
        ports: port range (default "1-1000")
        detect_os: attempt OS fingerprinting (slower, may need root)
        timeout: max seconds (default 180)

        Returns: open ports with service name, product, version, and OS guess.
        """
        if not _has("nmap"):
            return _json({"error": "nmap is not installed"})

        if not re.match(r'^[a-zA-Z0-9._\-:]+$', target):
            return _json({"error": "Invalid target format"})

        cmd = ["nmap", "-oX", "-", "-sV", "--version-intensity", "5"]

        if detect_os:
            cmd.append("-O")

        if ports and re.match(r'^[\d,\-]+$', ports):
            cmd.extend(["-p", ports])

        cmd.append(target)

        stdout, stderr, rc = _run(cmd, timeout=timeout)
        if rc < 0:
            return _json({"error": stderr})

        hosts = _parse_nmap_hosts(stdout)
        host = hosts[0] if hosts else {}
        return _json({
            "target": target,
            "ports_scanned": ports,
            **host,
        })

    @mcp.tool()
    def http_probe(
        targets: str,
        ports: str | None = None,
        follow_redirects: bool = True,
        tech_detect: bool = True,
        timeout: int = 90,
    ) -> str:
        """Probe hosts/URLs for HTTP services using httpx.

        Takes a list of hosts, IPs, or URLs and discovers which ones have
        web servers. Reports status codes, titles, tech stack, CDN, and more.

        targets: newline or comma-separated list of hosts/IPs/URLs
            (e.g. "example.com, 192.168.1.1, https://api.example.com")
        ports: comma-separated ports to probe (default: 80,443,8080,8443)
        follow_redirects: follow HTTP redirects (default true)
        tech_detect: detect technologies like Nginx, React, WordPress (default true)
        timeout: max seconds (default 90)

        Returns: list of live web servers with status, title, tech, and headers.
        """
        if not _has("httpx"):
            return _json({"error": "httpx is not installed"})

        # Normalize targets
        target_list = [t.strip() for t in re.split(r'[,\n]+', targets) if t.strip()]
        if not target_list:
            return _json({"error": "No targets provided"})

        stdin_data = "\n".join(target_list)

        cmd = ["httpx", "-silent", "-json"]

        if ports:
            cmd.extend(["-ports", ports])
        else:
            cmd.extend(["-ports", "80,443,8080,8443"])

        if follow_redirects:
            cmd.append("-follow-redirects")

        if tech_detect:
            cmd.append("-tech-detect")

        cmd.extend([
            "-status-code",
            "-title",
            "-web-server",
            "-content-length",
            "-cdn",
            "-method", "GET",
        ])

        stdout, stderr, rc = _run(cmd, timeout=timeout, stdin_data=stdin_data)
        if rc < 0:
            return _json({"error": stderr})

        results = []
        for line in stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                results.append({
                    "url": entry.get("url", ""),
                    "input": entry.get("input", ""),
                    "status_code": entry.get("status_code"),
                    "title": entry.get("title", ""),
                    "web_server": entry.get("webserver", ""),
                    "content_length": entry.get("content_length"),
                    "content_type": entry.get("content_type", ""),
                    "technologies": entry.get("tech", []),
                    "cdn": entry.get("cdn", False),
                    "cdn_name": entry.get("cdn_name", ""),
                    "host": entry.get("host", ""),
                    "port": entry.get("port", ""),
                    "scheme": entry.get("scheme", ""),
                    "tls": entry.get("tls", {}),
                    "final_url": entry.get("final_url", ""),
                })
            except json.JSONDecodeError:
                continue

        return _json({
            "targets_provided": len(target_list),
            "web_servers_found": len(results),
            "results": results,
        })

    @mcp.tool()
    def dns_enum(
        domain: str,
        record_types: str = "A,AAAA,MX,NS,CNAME,TXT,SOA",
        wordlist: str | None = None,
        timeout: int = 60,
    ) -> str:
        """Enumerate DNS records for a domain using dnsx.

        domain: target domain (e.g. "example.com")
        record_types: comma-separated DNS record types to query
            (A, AAAA, MX, NS, CNAME, TXT, SOA, PTR, SRV, CAA)
        wordlist: optional JSON array of subdomains to brute-force
            (e.g. '["www", "api", "mail", "dev", "staging"]')
        timeout: max seconds (default 60)

        Returns: DNS records organized by type, with resolved IPs.
        """
        if not _has("dnsx"):
            return _json({"error": "dnsx is not installed"})

        if not re.match(r'^[a-zA-Z0-9._\-]+$', domain):
            return _json({"error": "Invalid domain format"})

        # Build the list of domains to query
        domains = [domain]
        if wordlist:
            try:
                subs = json.loads(wordlist)
                domains.extend(f"{s}.{domain}" for s in subs if re.match(r'^[a-zA-Z0-9_\-]+$', s))
            except json.JSONDecodeError:
                return _json({"error": "wordlist must be a JSON array of strings"})

        stdin_data = "\n".join(domains)
        types = [t.strip().lower() for t in record_types.split(",")]

        cmd = ["dnsx", "-silent", "-json", "-resp"]
        for t in types:
            flag = f"-{t.lower()}"
            cmd.append(flag)

        stdout, stderr, rc = _run(cmd, timeout=timeout, stdin_data=stdin_data)
        if rc < 0:
            return _json({"error": stderr})

        records: dict[str, list[dict]] = {}
        all_ips: set[str] = set()

        for line in stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                host = entry.get("host", "")

                for rtype in ["a", "aaaa", "mx", "ns", "cname", "txt", "soa", "ptr", "srv", "caa"]:
                    values = entry.get(rtype, [])
                    if values:
                        key = rtype.upper()
                        records.setdefault(key, [])
                        for v in (values if isinstance(values, list) else [values]):
                            records[key].append({"host": host, "value": v})
                            if rtype == "a":
                                all_ips.add(v)
            except json.JSONDecodeError:
                continue

        return _json({
            "domain": domain,
            "domains_queried": len(domains),
            "records": records,
            "unique_ips": sorted(all_ips),
            "total_records": sum(len(v) for v in records.values()),
        })

    @mcp.tool()
    def full_recon(
        domain: str,
        probe_ports: str = "80,443,8080,8443,8000,3000,9090",
        timeout: int = 180,
    ) -> str:
        """Run a full reconnaissance pipeline on a domain.

        Chains: subfinder (subdomains) → dnsx (DNS resolution) → httpx (HTTP probing)

        This gives you a complete picture of a domain's attack surface:
        subdomains, their IPs, and which ones have web servers with what tech.

        domain: target domain (e.g. "example.com")
        probe_ports: ports to check for web servers (default: common web ports)
        timeout: max total seconds (default 180)

        Returns: subdomains, resolved IPs, live web servers with tech stack.
        """
        if not re.match(r'^[a-zA-Z0-9._\-]+$', domain):
            return _json({"error": "Invalid domain format"})

        result: dict[str, Any] = {
            "domain": domain,
            "stages": {},
        }

        # Stage 1: Subdomain discovery (subfinder)
        subdomains: list[str] = [domain]
        if _has("subfinder"):
            stdout, stderr, rc = _run(
                ["subfinder", "-d", domain, "-silent"],
                timeout=min(timeout // 3, 60),
            )
            if rc >= 0 and stdout.strip():
                found = [s.strip() for s in stdout.strip().splitlines() if s.strip()]
                # Deduplicate
                seen = set(subdomains)
                for s in found:
                    if s not in seen:
                        subdomains.append(s)
                        seen.add(s)
            result["stages"]["subfinder"] = {
                "subdomains_found": len(subdomains) - 1,
                "status": "ok" if rc >= 0 else stderr,
            }
        else:
            result["stages"]["subfinder"] = {"status": "not_installed"}

        # Stage 2: DNS resolution (dnsx)
        dns_map: dict[str, list[str]] = {}
        all_ips: set[str] = set()
        if _has("dnsx"):
            stdin_data = "\n".join(subdomains)
            stdout, stderr, rc = _run(
                ["dnsx", "-silent", "-json", "-resp", "-a"],
                timeout=min(timeout // 3, 60),
                stdin_data=stdin_data,
            )
            if rc >= 0:
                for line in stdout.strip().splitlines():
                    try:
                        entry = json.loads(line)
                        host = entry.get("host", "")
                        ips = entry.get("a", [])
                        if host and ips:
                            dns_map[host] = ips
                            all_ips.update(ips)
                    except json.JSONDecodeError:
                        continue
            result["stages"]["dnsx"] = {
                "resolved_hosts": len(dns_map),
                "unique_ips": len(all_ips),
                "status": "ok" if rc >= 0 else stderr,
            }
        else:
            result["stages"]["dnsx"] = {"status": "not_installed"}

        # Stage 3: HTTP probing (httpx)
        web_servers: list[dict] = []
        if _has("httpx"):
            stdin_data = "\n".join(subdomains)
            cmd = [
                "httpx", "-silent", "-json",
                "-ports", probe_ports,
                "-status-code", "-title", "-web-server",
                "-tech-detect", "-cdn",
                "-follow-redirects",
            ]
            stdout, stderr, rc = _run(
                cmd,
                timeout=min(timeout // 3, 90),
                stdin_data=stdin_data,
            )
            if rc >= 0:
                for line in stdout.strip().splitlines():
                    try:
                        entry = json.loads(line)
                        web_servers.append({
                            "url": entry.get("url", ""),
                            "host": entry.get("input", ""),
                            "status_code": entry.get("status_code"),
                            "title": entry.get("title", ""),
                            "web_server": entry.get("webserver", ""),
                            "technologies": entry.get("tech", []),
                            "cdn": entry.get("cdn", False),
                            "cdn_name": entry.get("cdn_name", ""),
                        })
                    except json.JSONDecodeError:
                        continue
            result["stages"]["httpx"] = {
                "web_servers_found": len(web_servers),
                "status": "ok" if rc >= 0 else stderr,
            }
        else:
            result["stages"]["httpx"] = {"status": "not_installed"}

        # Combined asset inventory
        assets: list[dict] = []
        for sub in subdomains:
            asset: dict[str, Any] = {
                "subdomain": sub,
                "ips": dns_map.get(sub, []),
            }
            # Find matching web servers
            web = [w for w in web_servers if w.get("host") == sub]
            if web:
                asset["web_services"] = web
            assets.append(asset)

        result["total_subdomains"] = len(subdomains)
        result["total_unique_ips"] = len(all_ips)
        result["total_web_servers"] = len(web_servers)
        result["assets"] = assets

        return _json(result)
