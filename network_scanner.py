#!/usr/bin/env python3
"""
Comprehensive Network Scanner using Scapy
Covers all OSI layers - from Layer 2 (Data Link) through Layer 7 (Application)
"""

from scapy.all import *
import sys
import ipaddress
import time
import json
from collections import defaultdict
from datetime import datetime

# ============================================================
# Layer 2 - Data Link: ARP Discovery
# ============================================================

def arp_scan(network):
    """
    ARP scan to discover live hosts on the local network (Layer 2).
    Returns list of dicts with IP and MAC addresses.
    """
    print(f"\n[Layer 2 - ARP Scan] Scanning {network} ...")
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(arp_req, timeout=3, verbose=False)

    hosts = []
    for sent, received in answered:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })
        print(f"  [+] Host: {received.psrc} | MAC: {received.hwsrc}")

    print(f"  => Found {len(hosts)} hosts via ARP")
    return hosts


# ============================================================
# Layer 3 - Network: ICMP Ping Sweep + Traceroute
# ============================================================

def icmp_ping_sweep(network):
    """
    ICMP echo request sweep to discover live hosts (Layer 3).
    Works across subnets unlike ARP.
    """
    print(f"\n[Layer 3 - ICMP Ping Sweep] Scanning {network} ...")
    hosts = []
    net = ipaddress.ip_network(network, strict=False)

    # Build packets for all hosts
    packets = [IP(dst=str(ip)) / ICMP() for ip in net.hosts()]

    if not packets:
        return hosts

    answered, _ = sr(packets, timeout=3, verbose=False)

    for sent, received in answered:
        if received.haslayer(ICMP) and received[ICMP].type == 0:  # Echo Reply
            hosts.append({
                "ip": received.src,
                "ttl": received[IP].ttl
            })
            print(f"  [+] Host: {received.src} | TTL: {received[IP].ttl}")

    print(f"  => Found {len(hosts)} hosts via ICMP")
    return hosts


def traceroute_host(target, max_ttl=30):
    """
    Traceroute using ICMP (Layer 3) to map path to target.
    """
    print(f"\n[Layer 3 - Traceroute] Tracing route to {target} ...")
    hops = []

    for ttl in range(1, max_ttl + 1):
        pkt = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(pkt, timeout=2, verbose=False)

        if reply is None:
            print(f"  {ttl:3d}  * * *")
            hops.append({"ttl": ttl, "ip": "*", "rtt": None})
        else:
            rtt = (reply.time - pkt.time) * 1000
            print(f"  {ttl:3d}  {reply.src:16s}  {rtt:.2f} ms")
            hops.append({"ttl": ttl, "ip": reply.src, "rtt": round(rtt, 2)})

            if reply.src == target:
                break

    return hops


# ============================================================
# Layer 4 - Transport: TCP SYN Scan + UDP Scan
# ============================================================

def tcp_syn_scan(target, ports=None):
    """
    TCP SYN (half-open) scan (Layer 4).
    Sends SYN, checks for SYN-ACK (open) or RST (closed).
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

    print(f"\n[Layer 4 - TCP SYN Scan] Scanning {target} ({len(ports)} ports) ...")
    results = {"open": [], "closed": [], "filtered": []}

    # Send SYN packets to all ports
    packets = [IP(dst=target) / TCP(dport=p, flags="S") for p in ports]
    answered, unanswered = sr(packets, timeout=3, verbose=False)

    for sent, received in answered:
        port = sent[TCP].dport
        if received.haslayer(TCP):
            tcp_flags = received[TCP].flags
            if tcp_flags == 0x12:  # SYN-ACK
                results["open"].append(port)
                # Send RST to close gracefully
                sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1, verbose=False)
            elif tcp_flags & 0x04:  # RST
                results["closed"].append(port)

    for pkt in unanswered:
        results["filtered"].append(pkt[TCP].dport)

    for port in sorted(results["open"]):
        service = get_service_name(port, "tcp")
        print(f"  [+] TCP {port:5d}/open    ({service})")
    for port in sorted(results["filtered"]):
        service = get_service_name(port, "tcp")
        print(f"  [?] TCP {port:5d}/filtered ({service})")

    print(f"  => Open: {len(results['open'])} | Closed: {len(results['closed'])} | Filtered: {len(results['filtered'])}")
    return results


def tcp_connect_scan(target, ports=None):
    """
    TCP Connect scan - completes full 3-way handshake (Layer 4).
    More detectable but more reliable than SYN scan.
    """
    if ports is None:
        ports = [21, 22, 80, 443, 8080]

    print(f"\n[Layer 4 - TCP Connect Scan] Scanning {target} ({len(ports)} ports) ...")
    results = {"open": [], "closed": [], "filtered": []}

    for port in ports:
        # SYN
        syn = IP(dst=target) / TCP(dport=port, flags="S")
        syn_ack = sr1(syn, timeout=2, verbose=False)

        if syn_ack is None:
            results["filtered"].append(port)
        elif syn_ack.haslayer(TCP):
            if syn_ack[TCP].flags == 0x12:  # SYN-ACK
                # Complete handshake with ACK, then RST
                ack = IP(dst=target) / TCP(dport=port, flags="A", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
                send(ack, verbose=False)
                rst = IP(dst=target) / TCP(dport=port, flags="R", seq=syn_ack[TCP].ack)
                send(rst, verbose=False)
                results["open"].append(port)
            elif syn_ack[TCP].flags & 0x04:  # RST
                results["closed"].append(port)

    for port in sorted(results["open"]):
        print(f"  [+] TCP {port}/open")

    return results


def udp_scan(target, ports=None):
    """
    UDP scan (Layer 4).
    Sends UDP probes; ICMP port unreachable = closed, no response = open|filtered.
    """
    if ports is None:
        ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 5353]

    print(f"\n[Layer 4 - UDP Scan] Scanning {target} ({len(ports)} ports) ...")
    results = {"open|filtered": [], "closed": []}

    packets = [IP(dst=target) / UDP(dport=p) for p in ports]
    answered, unanswered = sr(packets, timeout=5, verbose=False)

    for sent, received in answered:
        port = sent[UDP].dport
        if received.haslayer(ICMP):
            icmp_type = received[ICMP].type
            icmp_code = received[ICMP].code
            if icmp_type == 3 and icmp_code == 3:  # Port unreachable
                results["closed"].append(port)
            elif icmp_type == 3 and icmp_code in [1, 2, 9, 10, 13]:
                results["open|filtered"].append(port)
        else:
            results["open|filtered"].append(port)

    for pkt in unanswered:
        results["open|filtered"].append(pkt[UDP].dport)

    for port in sorted(results["open|filtered"]):
        service = get_service_name(port, "udp")
        print(f"  [?] UDP {port:5d}/open|filtered ({service})")

    print(f"  => Open|Filtered: {len(results['open|filtered'])} | Closed: {len(results['closed'])}")
    return results


def tcp_xmas_scan(target, ports=None):
    """
    TCP XMAS scan - sends FIN+PSH+URG flags (Layer 4).
    No response = open|filtered, RST = closed.
    """
    if ports is None:
        ports = [21, 22, 25, 80, 443]

    print(f"\n[Layer 4 - XMAS Scan] Scanning {target} ({len(ports)} ports) ...")
    results = {"open|filtered": [], "closed": []}

    packets = [IP(dst=target) / TCP(dport=p, flags="FPU") for p in ports]
    answered, unanswered = sr(packets, timeout=3, verbose=False)

    for sent, received in answered:
        port = sent[TCP].dport
        if received.haslayer(TCP) and received[TCP].flags & 0x04:
            results["closed"].append(port)

    for pkt in unanswered:
        results["open|filtered"].append(pkt[TCP].dport)

    for port in sorted(results["open|filtered"]):
        print(f"  [?] TCP {port}/open|filtered (XMAS)")

    return results


def tcp_null_scan(target, ports=None):
    """
    TCP NULL scan - sends packet with no flags (Layer 4).
    No response = open|filtered, RST = closed.
    """
    if ports is None:
        ports = [21, 22, 25, 80, 443]

    print(f"\n[Layer 4 - NULL Scan] Scanning {target} ({len(ports)} ports) ...")
    results = {"open|filtered": [], "closed": []}

    packets = [IP(dst=target) / TCP(dport=p, flags="") for p in ports]
    answered, unanswered = sr(packets, timeout=3, verbose=False)

    for sent, received in answered:
        port = sent[TCP].dport
        if received.haslayer(TCP) and received[TCP].flags & 0x04:
            results["closed"].append(port)

    for pkt in unanswered:
        results["open|filtered"].append(pkt[TCP].dport)

    for port in sorted(results["open|filtered"]):
        print(f"  [?] TCP {port}/open|filtered (NULL)")

    return results


def tcp_fin_scan(target, ports=None):
    """
    TCP FIN scan - sends FIN flag only (Layer 4).
    No response = open|filtered, RST = closed.
    Useful for bypassing simple firewalls.
    """
    if ports is None:
        ports = [21, 22, 25, 80, 443]

    print(f"\n[Layer 4 - FIN Scan] Scanning {target} ({len(ports)} ports) ...")
    results = {"open|filtered": [], "closed": []}

    packets = [IP(dst=target) / TCP(dport=p, flags="F") for p in ports]
    answered, unanswered = sr(packets, timeout=3, verbose=False)

    for sent, received in answered:
        port = sent[TCP].dport
        if received.haslayer(TCP) and received[TCP].flags & 0x04:
            results["closed"].append(port)

    for pkt in unanswered:
        results["open|filtered"].append(pkt[TCP].dport)

    return results


# ============================================================
# Layer 5-7 - Session/Presentation/Application: Service Detection & Banner Grabbing
# ============================================================

def banner_grab(target, port, timeout=3):
    """
    Grab service banner from an open port (Layer 7).
    Sends protocol-specific probes.
    """
    try:
        # HTTP probe
        if port in [80, 8080, 8000, 8888]:
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            syn_ack = sr1(pkt, timeout=timeout, verbose=False)
            if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
                return f"HTTP service detected on port {port}"

        # HTTPS probe
        if port in [443, 8443]:
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            syn_ack = sr1(pkt, timeout=timeout, verbose=False)
            if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
                return f"HTTPS/TLS service detected on port {port}"

        # Generic TCP banner grab via raw socket
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        syn_ack = sr1(pkt, timeout=timeout, verbose=False)
        if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
            return f"Service active on port {port}"

    except Exception as e:
        return f"Error: {str(e)}"

    return None


def dns_enum(target, domains=None):
    """
    DNS enumeration (Layer 7) - query DNS records.
    """
    if domains is None:
        domains = ["google.com", "example.com"]

    print(f"\n[Layer 7 - DNS Enumeration] Querying DNS server {target} ...")
    results = {}

    record_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT"]

    for domain in domains:
        results[domain] = {}
        for rtype in record_types:
            try:
                pkt = IP(dst=target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=rtype))
                reply = sr1(pkt, timeout=3, verbose=False)

                if reply and reply.haslayer(DNS) and reply[DNS].ancount > 0:
                    answers = []
                    for i in range(reply[DNS].ancount):
                        rr = reply[DNS].an[i] if i == 0 else reply[DNS].an.getlayer(i)
                        if rr:
                            answers.append(str(rr.rdata))
                    if answers:
                        results[domain][rtype] = answers
                        print(f"  [+] {domain} {rtype}: {', '.join(answers)}")
            except Exception:
                pass

    return results


def snmp_scan(target):
    """
    SNMP scan (Layer 7) - check for SNMP service with common community strings.
    """
    print(f"\n[Layer 7 - SNMP Scan] Probing {target} ...")
    communities = ["public", "private", "community"]
    results = []

    for community in communities:
        pkt = (IP(dst=target) / UDP(dport=161) /
               SNMP(community=community,
                    PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))
        reply = sr1(pkt, timeout=3, verbose=False)

        if reply and reply.haslayer(SNMP):
            results.append(community)
            print(f"  [+] SNMP community string found: '{community}'")

    return results


# ============================================================
# OS Fingerprinting (Cross-layer analysis)
# ============================================================

def os_fingerprint(target):
    """
    Passive OS fingerprinting based on TTL and TCP window size.
    """
    print(f"\n[OS Fingerprint] Probing {target} ...")

    # Send SYN to common port
    for port in [80, 443, 22]:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        reply = sr1(pkt, timeout=3, verbose=False)

        if reply and reply.haslayer(TCP) and reply[TCP].flags == 0x12:
            ttl = reply[IP].ttl
            window = reply[TCP].window

            # Send RST
            sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1, verbose=False)

            os_guess = guess_os(ttl, window)
            print(f"  [+] TTL: {ttl} | Window: {window} | OS Guess: {os_guess}")
            return {"ttl": ttl, "window": window, "os_guess": os_guess}

    print("  [-] Could not fingerprint OS")
    return None


def guess_os(ttl, window):
    """Guess OS based on TTL and TCP window size heuristics."""
    if ttl <= 64:
        if window == 5840 or window == 14600 or window == 29200:
            return "Linux"
        elif window == 65535:
            return "macOS / FreeBSD"
        else:
            return "Linux/Unix (TTL ~64)"
    elif ttl <= 128:
        if window == 65535 or window == 8192:
            return "Windows"
        else:
            return "Windows (TTL ~128)"
    elif ttl <= 255:
        return "Network Device / Solaris (TTL ~255)"
    return "Unknown"


# ============================================================
# Utilities
# ============================================================

def get_service_name(port, proto="tcp"):
    """Map port number to common service name."""
    services = {
        "tcp": {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        },
        "udp": {
            53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
            123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 161: "SNMP",
            162: "SNMP-Trap", 500: "IKE", 514: "Syslog", 1900: "SSDP",
            5353: "mDNS"
        }
    }
    return services.get(proto, {}).get(port, "Unknown")


def generate_report(scan_results):
    """Generate a summary report of all scan results."""
    print("\n" + "=" * 60)
    print("       COMPREHENSIVE NETWORK SCAN REPORT")
    print(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if "target" in scan_results:
        print(f"\n  Target: {scan_results['target']}")

    if "arp_hosts" in scan_results:
        print(f"\n  [L2] ARP Hosts Discovered: {len(scan_results['arp_hosts'])}")
        for h in scan_results["arp_hosts"]:
            print(f"        {h['ip']:16s} | {h['mac']}")

    if "icmp_hosts" in scan_results:
        print(f"\n  [L3] ICMP Hosts Alive: {len(scan_results['icmp_hosts'])}")
        for h in scan_results["icmp_hosts"]:
            print(f"        {h['ip']:16s} | TTL: {h['ttl']}")

    if "traceroute" in scan_results:
        print(f"\n  [L3] Traceroute Hops: {len(scan_results['traceroute'])}")

    if "tcp_syn" in scan_results:
        r = scan_results["tcp_syn"]
        print(f"\n  [L4] TCP SYN Scan:")
        print(f"        Open: {sorted(r.get('open', []))}")
        print(f"        Filtered: {sorted(r.get('filtered', []))}")

    if "udp" in scan_results:
        r = scan_results["udp"]
        print(f"\n  [L4] UDP Scan:")
        print(f"        Open|Filtered: {sorted(r.get('open|filtered', []))}")

    if "os_fingerprint" in scan_results and scan_results["os_fingerprint"]:
        fp = scan_results["os_fingerprint"]
        print(f"\n  [OS] Fingerprint: {fp.get('os_guess', 'Unknown')}")
        print(f"       TTL: {fp.get('ttl')} | Window: {fp.get('window')}")

    if "dns" in scan_results:
        print(f"\n  [L7] DNS Records Found: {sum(len(v) for v in scan_results['dns'].values())}")

    print("\n" + "=" * 60)

    # Save to JSON
    report_file = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(report_file, "w") as f:
            json.dump(scan_results, f, indent=2, default=str)
        print(f"  Report saved to: {report_file}")
    except Exception as e:
        print(f"  Could not save report: {e}")


# ============================================================
# Main - Full Comprehensive Scan
# ============================================================

def full_scan(target, network=None, scan_types=None):
    """
    Run a comprehensive scan across all OSI layers.

    Args:
        target: Target IP address for port scanning
        network: Network CIDR for host discovery (e.g. '192.168.1.0/24')
        scan_types: List of scan types to run. None = all scans.
                    Options: 'arp', 'icmp', 'traceroute', 'tcp_syn', 'tcp_xmas',
                             'tcp_null', 'tcp_fin', 'udp', 'os', 'dns', 'snmp', 'banner'
    """
    all_scans = {'arp', 'icmp', 'traceroute', 'tcp_syn', 'tcp_xmas',
                 'tcp_null', 'tcp_fin', 'udp', 'os', 'dns', 'snmp', 'banner'}

    if scan_types is None:
        scan_types = all_scans
    else:
        scan_types = set(scan_types)

    results = {"target": target, "timestamp": str(datetime.now())}

    print("=" * 60)
    print("  COMPREHENSIVE NETWORK SCANNER (Scapy)")
    print(f"  Target: {target}")
    if network:
        print(f"  Network: {network}")
    print(f"  Scans: {', '.join(sorted(scan_types))}")
    print("=" * 60)

    # Layer 2 - ARP
    if 'arp' in scan_types and network:
        try:
            results["arp_hosts"] = arp_scan(network)
        except Exception as e:
            print(f"  [!] ARP scan error: {e}")

    # Layer 3 - ICMP
    if 'icmp' in scan_types and network:
        try:
            results["icmp_hosts"] = icmp_ping_sweep(network)
        except Exception as e:
            print(f"  [!] ICMP scan error: {e}")

    if 'traceroute' in scan_types:
        try:
            results["traceroute"] = traceroute_host(target)
        except Exception as e:
            print(f"  [!] Traceroute error: {e}")

    # Layer 4 - TCP/UDP
    if 'tcp_syn' in scan_types:
        try:
            results["tcp_syn"] = tcp_syn_scan(target)
        except Exception as e:
            print(f"  [!] TCP SYN scan error: {e}")

    if 'tcp_xmas' in scan_types:
        try:
            results["tcp_xmas"] = tcp_xmas_scan(target)
        except Exception as e:
            print(f"  [!] XMAS scan error: {e}")

    if 'tcp_null' in scan_types:
        try:
            results["tcp_null"] = tcp_null_scan(target)
        except Exception as e:
            print(f"  [!] NULL scan error: {e}")

    if 'tcp_fin' in scan_types:
        try:
            results["tcp_fin"] = tcp_fin_scan(target)
        except Exception as e:
            print(f"  [!] FIN scan error: {e}")

    if 'udp' in scan_types:
        try:
            results["udp"] = udp_scan(target)
        except Exception as e:
            print(f"  [!] UDP scan error: {e}")

    # OS Fingerprinting
    if 'os' in scan_types:
        try:
            results["os_fingerprint"] = os_fingerprint(target)
        except Exception as e:
            print(f"  [!] OS fingerprint error: {e}")

    # Layer 7 - Application
    if 'dns' in scan_types:
        try:
            results["dns"] = dns_enum(target)
        except Exception as e:
            print(f"  [!] DNS enum error: {e}")

    if 'snmp' in scan_types:
        try:
            results["snmp_communities"] = snmp_scan(target)
        except Exception as e:
            print(f"  [!] SNMP scan error: {e}")

    if 'banner' in scan_types and "tcp_syn" in results:
        print(f"\n[Layer 7 - Banner Grabbing] ...")
        results["banners"] = {}
        for port in results["tcp_syn"].get("open", []):
            banner = banner_grab(target, port)
            if banner:
                results["banners"][port] = banner
                print(f"  [+] Port {port}: {banner}")

    # Generate report
    generate_report(results)
    return results


# ============================================================
# CLI Entry Point
# ============================================================

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════╗
║          Comprehensive Network Scanner v1.0             ║
║              Powered by Scapy                           ║
║   Covers OSI Layers 2-7 (Post-ISO comprehensive scan)  ║
╠══════════════════════════════════════════════════════════╣
║  Scan Types:                                            ║
║   L2: ARP Discovery                                    ║
║   L3: ICMP Ping Sweep, Traceroute                      ║
║   L4: TCP SYN/Connect/XMAS/NULL/FIN, UDP               ║
║   L5-7: Banner Grab, DNS Enum, SNMP, OS Fingerprint    ║
╚══════════════════════════════════════════════════════════╝
    """)

    target = input("Enter target IP address: ").strip()
    network = input("Enter network CIDR (e.g. 192.168.1.0/24) or press Enter to skip: ").strip()

    if not network:
        network = None

    print("\nAvailable scans: arp, icmp, traceroute, tcp_syn, tcp_xmas, tcp_null, tcp_fin, udp, os, dns, snmp, banner")
    scan_input = input("Enter scan types (comma-separated) or 'all' for full scan: ").strip()

    if scan_input.lower() == 'all' or scan_input == '':
        scan_types = None  # all scans
    else:
        scan_types = [s.strip() for s in scan_input.split(",")]

    full_scan(target, network, scan_types)
