#!/usr/bin/env python3
"""Shared parsing utilities for PRADS asset log analysis.

Provides:
- Log file parsing into structured HostAsset objects
- OS inference from TCP fingerprints, service banners, and client headers
- CPE and User-Agent parsing
- OS transition detection
- Deduplication helpers
- Snort policy mapping (frag3/stream5)
- Suricata policy mapping (host-os-policy, defrag, libhtp personalities)
- ECS (Elastic Common Schema) JSON serialization
"""

import ipaddress
import os
import re
import socket
import struct
from collections import defaultdict
from datetime import datetime, timezone

# ── Windows NT version mapping ──────────────────────────────────────────────

WINDOWS_NT_MAP = {
    '10.0': 'Windows 10/11',
    '6.3':  'Windows 8.1/Server 2012 R2',
    '6.2':  'Windows 8/Server 2012',
    '6.1':  'Windows 7/Server 2008 R2',
    '6.0':  'Windows Vista/Server 2008',
    '5.2':  'Windows Server 2003/XP x64',
    '5.1':  'Windows XP',
    '5.0':  'Windows 2000',
}

WIN11_MIN_BUILD = 22000


def ip_sort_key(ip):
    """Sort key that handles both IPv4 and IPv6 addresses."""
    try:
        return (4, struct.unpack('!I', socket.inet_aton(ip))[0])
    except (OSError, socket.error):
        pass
    try:
        return (6, int.from_bytes(socket.inet_pton(socket.AF_INET6, ip), 'big'))
    except (OSError, socket.error):
        return (9, ip)

# ── MAC OUI database ────────────────────────────────────────────────────────

_oui_db = None  # lazy-loaded


def _load_oui_db(mac_sig_path=None):
    """Load the Wireshark-format mac.sig OUI database. Returns {prefix: (short_vendor, full_vendor)}."""
    global _oui_db
    if _oui_db is not None:
        return _oui_db

    _oui_db = {}
    if mac_sig_path is None:
        # Try standard locations relative to this script
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'etc', 'mac.sig'),
            '/usr/local/etc/prads/mac.sig',
            '/etc/prads/mac.sig',
        ]
        for c in candidates:
            if os.path.isfile(c):
                mac_sig_path = c
                break

    if not mac_sig_path or not os.path.isfile(mac_sig_path):
        return _oui_db

    with open(mac_sig_path, 'r', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] == '#':
                continue
            # Format: "XX:XX:XX\tShortName\t# Full Name" or with /mask
            parts = re.split(r'\t+', line, maxsplit=2)
            if len(parts) < 2:
                # Try space-separated (first line in some files)
                parts = line.split(None, 2)
                if len(parts) < 2:
                    continue

            prefix_raw = parts[0].strip()
            short_name = parts[1].strip()
            full_name = ''
            if len(parts) > 2:
                full_name = parts[2].lstrip('#').strip()

            # Normalize prefix: strip /mask, convert - to :, uppercase
            prefix = prefix_raw.split('/')[0].replace('-', ':').upper()
            _oui_db[prefix] = (short_name, full_name)

    return _oui_db


def lookup_oui_vendor(mac, mac_sig_path=None):
    """Look up the vendor for a MAC address using the OUI database.
    Returns (short_name, full_name) or (None, None) if not found.
    Tries 3-byte (standard OUI) and 6-byte (exact) prefixes.
    """
    db = _load_oui_db(mac_sig_path)
    if not db:
        return None, None

    mac_upper = mac.upper().replace('-', ':')

    # Try exact match first (6-byte entries)
    if mac_upper in db:
        return db[mac_upper]

    # Try 3-byte OUI prefix
    oui = mac_upper[:8]  # "XX:XX:XX"
    if oui in db:
        return db[oui]

    return None, None


# Vendor name patterns that strongly indicate device type
_VENDOR_DEVICE_HINTS = {
    # VoIP phones
    'Yealink':   ('Embedded', 'Yealink VoIP phone', 7),
    'Polycom':   ('Embedded', 'Polycom VoIP phone', 7),
    'Grandstrea': ('Embedded', 'Grandstream VoIP phone', 7),
    'Snom':      ('Embedded', 'Snom VoIP phone', 7),
    'Cisco-Lin': ('Embedded', 'Cisco VoIP phone', 5),
    # Printers
    'HewlettPac': ('Embedded', 'HP printer/device', 3),
    'Hewlett-Pa': ('Embedded', 'HP printer/device', 3),
    'Xerox':     ('Embedded', 'Xerox printer', 5),
    'Canon':     ('Embedded', 'Canon printer', 5),
    'Brother':   ('Embedded', 'Brother printer', 5),
    'Lexmark':   ('Embedded', 'Lexmark printer', 5),
    'Ricoh':     ('Embedded', 'Ricoh printer', 5),
    'KonicaMin': ('Embedded', 'Konica Minolta printer', 5),
    # Network infrastructure
    'Cisco':     ('Cisco', 'Cisco device', 3),
    'Juniper':   ('Linux', 'Juniper device', 3),
    'Aruba':     ('Linux', 'Aruba device', 3),
    'Fortinet':  ('Linux', 'Fortinet device', 3),
    'Ruckus':    ('Linux', 'Ruckus device', 3),
    'Ubiquiti':  ('Linux', 'Ubiquiti device', 3),
    # Server/BMC
    'SuperMicr': ('Embedded', 'SuperMicro BMC/server', 4),
    'Dell':      (None, 'Dell device', 0),  # could be anything
    'LannerElec': ('Embedded', 'Lanner appliance', 5),
    'Lanner':    ('Embedded', 'Lanner appliance', 5),
    # Apple
    'Apple':     ('MacOS', 'Apple device', 3),
    # VMware
    'Vmware':    ('Linux', 'VMware VM', 4),
    'VMware':    ('Linux', 'VMware VM', 4),
    # Microsoft (Hyper-V)
    'Microsoft': ('Windows', 'Hyper-V VM', 4),
    # I/O and embedded
    'I/OInterco': ('Embedded', 'I/O Interconnect device', 3),
    'GeneralDyn': ('Embedded', 'General Dynamics device', 3),
    'IETF-VRRP':  (None, 'VRRP virtual MAC', 0),
}


def infer_os_from_vendor(vendor_short, vendor_full=''):
    """Infer OS/device type from MAC OUI vendor name. Returns (os_family, detail, weight) or None."""
    if not vendor_short:
        return None
    # Check short name against known patterns
    for pattern, hint in _VENDOR_DEVICE_HINTS.items():
        if pattern in vendor_short or pattern in vendor_full:
            if hint[0] is not None:
                return hint
            return None
    return None


# ── OS inference from services ──────────────────────────────────────────────

def infer_os_from_service(service_name, info):
    """Infer OS from a SERVER fingerprint. Returns [(os_family, os_detail, weight)]."""
    hints = []

    # CPE-embedded OS tag: (os:Windows cpe:...)
    cpe_os = re.search(r'\(os:([^)]+?)(?:\s+cpe:[^)]+)?\)', info)
    if cpe_os:
        os_str = cpe_os.group(1).strip()
        if 'Windows' in os_str:
            hints.append(('Windows', os_str, 8))
        elif 'Mac OS' in os_str or 'macOS' in os_str:
            hints.append(('MacOS', os_str, 8))
        elif 'Linux' in os_str:
            hints.append(('Linux', os_str, 8))
        elif 'Solaris' in os_str:
            hints.append(('Solaris', os_str, 8))

    if 'Microsoft-IIS' in info or 'Microsoft IIS' in info:
        ver_m = re.search(r'IIS[/ ]?(?:httpd )?(\d+(?:\.\d+)?)', info)
        v = ver_m.group(1) if ver_m else ''
        hints.append(('Windows', f'Windows Server (IIS {v})' if v else 'Windows Server (IIS)', 5))
    if 'Microsoft Exchange' in info:
        hints.append(('Windows', 'Windows Server (Exchange)', 5))
    if 'Microsoft HTTPAPI' in info:
        hints.append(('Windows', 'Windows Server (HTTPAPI)', 4))
    if 'SuperMicro IPMI' in info:
        hints.append(('Embedded', 'SuperMicro BMC', 7))

    # Weak server-side indicators
    if re.search(r'\bnginx\b', info, re.I):
        hints.append(('Linux', 'Linux (nginx likely)', 2))
    if 'Apache' in info and 'Microsoft' not in info:
        hints.append(('Linux', 'Linux (Apache likely)', 2))
    if 'OpenSSH' in info:
        ver_m = re.search(r'OpenSSH[_ ](\S+)', info)
        v = ver_m.group(1) if ver_m else ''
        hints.append(('Linux', f'Linux/Unix (OpenSSH {v})', 2))
    if 'Mac OS X' in info:
        hints.append(('MacOS', 'Mac OS X', 7))

    return hints


def infer_os_from_client(service_name, details):
    """Infer OS from a CLIENT fingerprint. Returns [(os_family, os_detail, weight)]."""
    hints = []

    # Windows NT from User-Agent
    nt_match = re.search(r'Windows NT (\d+\.\d+)', details)
    if nt_match:
        nt_ver = nt_match.group(1)
        os_name = WINDOWS_NT_MAP.get(nt_ver, f'Windows (NT {nt_ver})')
        hints.append(('Windows', os_name, 7))

    # aws-sdk with explicit Windows build
    aws_match = re.search(r'Windows/(\d+)\.(\d+)\.(\d+)', details)
    if aws_match:
        build = int(aws_match.group(3))
        if build >= WIN11_MIN_BUILD:
            hints.append(('Windows', f'Windows 11 (build {build})', 9))
        else:
            hints.append(('Windows', f'Windows 10 (build {build})', 9))

    # WebDAV MiniRedir with build
    webdav_match = re.search(r'MiniRedir/(\d+)\.(\d+)\.(\d+)', details)
    if webdav_match:
        build = int(webdav_match.group(3))
        if build >= WIN11_MIN_BUILD:
            hints.append(('Windows', f'Windows 11 (build {build})', 8))
        else:
            hints.append(('Windows', f'Windows 10 (build {build})', 8))

    # Microsoft ecosystem clients
    if 'Microsoft CryptoAPI' in details:
        hints.append(('Windows', 'Windows (CryptoAPI)', 4))
    if 'Windows-Update-Agent' in details:
        hints.append(('Windows', 'Windows (WUA)', 4))
    if 'Microsoft-Delivery-Optimization' in details or 'Microsoft-Delivery Optimization' in details:
        hints.append(('Windows', 'Windows 10+', 5))
    if 'Microsoft NCSI' in details or 'msftconnecttest' in details:
        hints.append(('Windows', 'Windows (NCSI)', 3))
    if 'Microsoft BITS' in details:
        hints.append(('Windows', 'Windows (BITS)', 4))
    if 'Microsoft WNS' in details or 'Microsoft-WNS' in details:
        hints.append(('Windows', 'Windows 10+ (WNS)', 4))
    if 'WSDAPI' in details:
        hints.append(('Windows', 'Windows (WSDAPI)', 3))
    if 'WinHttp' in details:
        hints.append(('Windows', 'Windows (WinHTTP)', 4))

    # Microsoft Office
    office_match = re.search(
        r'Microsoft Office/[\d.]+ \(Windows NT (\d+\.\d+);.*?(Microsoft \w+ [\d.]+)', details)
    if office_match:
        nt_ver = office_match.group(1)
        os_name = WINDOWS_NT_MAP.get(nt_ver, f'Windows (NT {nt_ver})')
        hints.append(('Windows', os_name, 6))
    elif 'MSOffice' in details or 'Microsoft Office' in details:
        hints.append(('Windows', 'Windows (Office)', 3))

    # SharePoint
    if 'SharePoint' in details:
        sp_nt = re.search(r'Windows NT (\d+\.\d+)', details)
        if sp_nt:
            hints.append(('Windows', WINDOWS_NT_MAP.get(sp_nt.group(1), 'Windows Server'), 6))
        else:
            hints.append(('Windows', 'Windows Server (SharePoint)', 5))

    # IE / Trident
    ie_match = re.search(r'MSIE \d+\.\d+; Windows NT (\d+\.\d+)', details)
    if ie_match:
        nt_ver = ie_match.group(1)
        hints.append(('Windows', WINDOWS_NT_MAP.get(nt_ver, f'Windows (NT {nt_ver})'), 7))

    # Apple / iOS
    ios_match = re.search(r'iPhone OS[, ]*([0-9.]+)', details)
    if ios_match:
        hints.append(('iOS', f'iOS {ios_match.group(1)}', 9))
    elif 'iPad' in details:
        ipad_match = re.search(r'iPad(\w+,\w+)', details)
        model = f' ({ipad_match.group(1)})' if ipad_match else ''
        hints.append(('iOS', f'iPadOS{model}', 8))
    if 'com.apple' in details:
        hints.append(('Apple', 'macOS/iOS', 4))

    # Linux indicators
    if 'Debian APT' in details:
        ver_m = re.search(r'APT[- ]HTTP/[\d.]+ \((\S+)\)', details)
        v = ver_m.group(1) if ver_m else ''
        hints.append(('Linux', f'Debian/Ubuntu (APT {v})' if v else 'Debian/Ubuntu', 8))
    if 'fwupd' in details:
        hints.append(('Linux', 'Linux (fwupd)', 6))
    if re.match(r'PVE/', details):
        ver_m = re.search(r'PVE/(\S+)', details)
        v = ver_m.group(1) if ver_m else ''
        hints.append(('Linux', f'Proxmox VE {v}', 9))
    if re.match(r'pkg/', details):
        hints.append(('FreeBSD', 'FreeBSD (pkg)', 6))

    # Embedded / IoT / VoIP
    yealink = re.search(r'Yealink (\S+ \S+) (\S+)', details)
    if yealink:
        hints.append(('Embedded', f'Yealink {yealink.group(1)} fw:{yealink.group(2)}', 9))
    grandstream = re.search(r'Grandstream Model HW (\S+) SW (\S+)', details)
    if grandstream:
        hints.append(('Embedded', f'Grandstream {grandstream.group(1)} fw:{grandstream.group(2)}', 9))
    if 'Canon HTTP Client' in details:
        hints.append(('Embedded', 'Canon printer/MFP', 8))
    if 'Xerox' in details:
        hints.append(('Embedded', 'Xerox printer/MFP', 7))
    if 'DynGate' in details:
        hints.append(('Embedded', 'DynGate appliance', 5))

    # ZOOM.Win
    zoom_match = re.search(r'ZOOM\.Win (\S+)', details)
    if zoom_match:
        hints.append(('Windows', f'Windows ({zoom_match.group(1)})', 5))

    # Java runtime (weak signal)
    java_match = re.search(r'Java/(\S+)', details)
    if java_match and not hints:
        hints.append(('unknown', f'Java {java_match.group(1)}', 1))

    # SSH client
    if 'PuTTY' in details:
        hints.append(('Windows', 'Windows (PuTTY)', 3))
    if 'OpenSSH' in details and 'keyscan' not in details:
        hints.append(('Linux', 'Linux/Unix (OpenSSH client)', 2))

    return hints


# ── CPE parsing ─────────────────────────────────────────────────────────────

def parse_cpe(info_str):
    """Extract CPE values from a service info string."""
    cpes = []
    for match in re.finditer(r'cpe:([a-z]):([^)\s,]+)', info_str):
        part = match.group(1)
        value = match.group(2)
        parts = value.split(':')
        cpes.append({
            'part': {'a': 'application', 'o': 'os', 'h': 'hardware'}.get(part, part),
            'vendor': parts[0] if len(parts) > 0 else '',
            'product': parts[1] if len(parts) > 1 else '',
            'version': parts[2] if len(parts) > 2 else '',
            'raw': f'cpe:/{part}:{value}',
        })
    return cpes


# ── User-Agent parsing ──────────────────────────────────────────────────────

def parse_user_agent(details):
    """Extract structured browser/application info from a User-Agent string."""
    ua = {}

    # Browser detection
    edge = re.search(r'Edg(?:e)?/(\S+)', details)
    chrome = re.search(r'Chrome/(\S+)', details)
    if edge:
        ua['browser'] = 'Microsoft Edge'
        ua['browser_version'] = edge.group(1)
    elif chrome:
        ua['browser'] = 'Chrome'
        ua['browser_version'] = chrome.group(1)

    ie = re.search(r'MSIE (\d+\.\d+)', details)
    rv = re.search(r'rv:(\d+\.\d+)', details)
    if ie:
        ua['browser'] = 'Internet Explorer'
        ua['browser_version'] = ie.group(1)
    elif rv and 'Trident' in details:
        ua['browser'] = 'Internet Explorer'
        ua['browser_version'] = rv.group(1)

    # OS from UA
    nt = re.search(r'Windows NT (\d+\.\d+)', details)
    if nt:
        nt_ver = nt.group(1)
        ua['os'] = WINDOWS_NT_MAP.get(nt_ver, f'Windows (NT {nt_ver})')
        ua['os_nt_version'] = nt_ver

    # Architecture
    if 'Win64; x64' in details or 'x64' in details:
        ua['arch'] = 'x64'
    elif 'WOW64' in details:
        ua['arch'] = 'x64 (WoW64)'

    # Named applications
    office = re.search(r'Microsoft (\w+) ([\d.]+)', details)
    if office:
        ua['application'] = f'Microsoft {office.group(1)}'
        ua['app_version'] = office.group(2)

    wua = re.search(r'Windows-Update-Agent/([\d.]+).*?Client.Protocol/([\d.]+)', details)
    if wua:
        ua['application'] = 'Windows Update Agent'
        ua['app_version'] = wua.group(1)
        ua['protocol_version'] = wua.group(2)

    java = re.search(r'Java/(\S+)', details)
    if java:
        ua['runtime'] = 'Java'
        ua['runtime_version'] = java.group(1)

    return ua if ua else None


# ── SYN fingerprint parsing ─────────────────────────────────────────────────

def parse_os_from_syn(info):
    """Parse OS name and details from a SYN/SYNACK/ACK/FIN/RST fingerprint."""
    m = re.search(r':[\d]{2,4}:\d:.*?:.*?:.*?:(\w+):(.*?):link', info)
    if m:
        return m.group(1), m.group(2)

    m = re.search(r':[\d]{2,4}:\d:.*?:.*?:.*?:(\w+):(.*?):uptime', info)
    if m:
        return m.group(1), m.group(2)

    for os_name in ('Linux', 'Windows', 'FreeBSD', 'OpenBSD', 'NetBSD',
                    'MacOS', 'Solaris', 'HPUX', 'Cisco', 'IRIX'):
        if f':{os_name}:' in info:
            m = re.search(f':{os_name}:(.*?)(?::|$)', info)
            return os_name, m.group(1) if m else 'unknown'

    return 'unknown', 'unknown'


def parse_service_info(info):
    """Split 'service_name:details' from bracket-enclosed service info."""
    m = re.match(r'^(\w[\w-]*):(.*)$', info)
    if m:
        return m.group(1), m.group(2)
    return 'unknown', info


# ── Data model ──────────────────────────────────────────────────────────────

class HostAsset:
    """Aggregated asset data for a single IP address."""

    def __init__(self, ip):
        self.ip = ip
        self.vlans = set()
        self.os_fingerprints = []
        self.tcp_services = defaultdict(list)
        self.tcp_clients  = defaultdict(list)
        self.udp_services = defaultdict(list)
        self.udp_clients  = defaultdict(list)
        self.arp_entries   = []          # [(mac, vendor_short, vendor_full, ts)]
        self.has_icmp      = False
        self.cpes          = []
        self.os_hints_svc  = []
        self.os_hints_cli  = []
        self.os_hints_mac  = []          # [(os_family, detail, weight, ts)]
        self.client_apps   = []
        self.first_seen    = None
        self.last_seen     = None

    def _update_times(self, ts):
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

    def add_os_fingerprint(self, svc_type, os_name, details, ts):
        self.os_fingerprints.append((svc_type, os_name, details, ts))
        self._update_times(ts)

    def add_service(self, proto, port, svc_name, details, ts):
        target = self.tcp_services if proto == 6 else self.udp_services
        target[port].append((svc_name, details, ts))
        self._update_times(ts)

    def add_client(self, proto, port, svc_name, details, ts):
        target = self.tcp_clients if proto == 6 else self.udp_clients
        target[port].append((svc_name, details, ts))
        self._update_times(ts)

    def add_arp(self, mac, vendor_short, vendor_full, ts):
        self.arp_entries.append((mac, vendor_short, vendor_full, ts))
        self._update_times(ts)


# ── Log parser ──────────────────────────────────────────────────────────────

_LINE_RE = re.compile(
    r'^([\w.:]+),(\d{1,4}),(\d{1,5}),(\d{1,3}),(\S+?),\[(.*)\],(\d{1,3}),(\d{10})'
)


def parse_log_file(filepath, filter_ip=None):
    """Parse a PRADS asset log file and return {ip: HostAsset}.

    filter_ip can be a single IP address or a CIDR network (e.g. '10.15.1.0/24').
    """
    hosts = {}

    # Build the IP filter: exact match for single IP, network containment for CIDR
    ip_filter = None
    if filter_ip:
        if '/' in filter_ip:
            ip_filter = ipaddress.ip_network(filter_ip, strict=False)
        else:
            ip_filter = filter_ip

    with open(filepath, 'r', errors='replace') as fh:
        for line in fh:
            line = line.rstrip('\n\r')
            if not line or line[0] == '#' or line.startswith('asset,vlan,port,proto'):
                continue

            m = _LINE_RE.match(line)
            if not m:
                continue

            ip    = m.group(1)
            vlan  = int(m.group(2))
            port  = int(m.group(3))
            proto = int(m.group(4))
            svc   = m.group(5)
            info  = m.group(6)
            dist  = int(m.group(7))
            ts    = int(m.group(8))

            if ip_filter:
                if isinstance(ip_filter, str):
                    if ip != ip_filter:
                        continue
                else:
                    if ipaddress.ip_address(ip) not in ip_filter:
                        continue

            if ip not in hosts:
                hosts[ip] = HostAsset(ip)
            host = hosts[ip]
            if vlan:
                host.vlans.add(vlan)

            if svc in ('SYN', 'SYNACK', 'ACK', 'RST', 'FIN'):
                os_name, details = parse_os_from_syn(info)
                host.add_os_fingerprint(svc, os_name, details, ts)

            elif svc == 'ARP':
                # Parse MAC and optional inline vendor: "AA:BB:CC:DD:EE:FF" or
                # "AA:BB:CC:DD:EE:FF,(VendorName)"
                arp_m = re.match(r'^([0-9A-Fa-f:]{17})(?:,\((\w+)\))?', info)
                if arp_m:
                    mac = arp_m.group(1)
                    inline_vendor = arp_m.group(2) or ''
                    if inline_vendor:
                        vendor_short = inline_vendor
                        vendor_full = inline_vendor
                    else:
                        vendor_short, vendor_full = lookup_oui_vendor(mac)
                        vendor_short = vendor_short or ''
                        vendor_full = vendor_full or ''
                    host.add_arp(mac, vendor_short, vendor_full, ts)
                    # Infer OS/device type from vendor
                    hint = infer_os_from_vendor(vendor_short, vendor_full)
                    if hint:
                        host.os_hints_mac.append((hint[0], hint[1], hint[2], ts))
                else:
                    host.add_arp(info, '', '', ts)

            elif proto == 1:
                host.has_icmp = True
                host._update_times(ts)

            elif svc == 'SERVER':
                svc_name, svc_details = parse_service_info(info)
                host.add_service(proto, port, svc_name, svc_details, ts)
                host.cpes.extend(parse_cpe(info))
                for os_fam, os_det, w in infer_os_from_service(svc_name, info):
                    host.os_hints_svc.append((os_fam, os_det, w, ts))

            elif svc == 'CLIENT':
                svc_name, svc_details = parse_service_info(info)
                host.add_client(proto, port, svc_name, svc_details, ts)
                for os_fam, os_det, w in infer_os_from_client(svc_name, svc_details):
                    host.os_hints_cli.append((os_fam, os_det, w, ts))
                if svc_name == 'http':
                    ua = parse_user_agent(svc_details)
                    if ua:
                        ua['timestamp'] = ts
                        ua['raw'] = svc_details[:200]
                        host.client_apps.append(ua)

            elif svc == 'UDP':
                host._update_times(ts)

    return hosts


# ── OS guessing ─────────────────────────────────────────────────────────────

def detect_os_transitions(host, cutoff_ts):
    """Find points where a host's OS fingerprint changed."""
    observations = []
    for svc_type, os_name, details, ts in host.os_fingerprints:
        if os_name == 'unknown' or ts < cutoff_ts:
            continue
        if svc_type in ('SYN', 'SYNACK'):
            observations.append((ts, os_name, details, svc_type))

    observations.sort()
    transitions = []
    if len(observations) < 2:
        return transitions

    prev_os, prev_ts = observations[0][1], observations[0][0]
    for ts, os_name, details, svc_type in observations[1:]:
        if os_name != prev_os:
            transitions.append({
                'from_os': prev_os, 'to_os': os_name,
                'from_ts': prev_ts, 'to_ts': ts,
                'to_details': details,
            })
        prev_os, prev_ts = os_name, ts

    return transitions


def guess_os(host, lookback_hours=12):
    """
    Guess the OS using TCP fingerprints + service/client inference.
    Returns dict: os, details, confidence, timestamp, flux, transitions,
                  inference_sources
    """
    latest_ts = 0
    syn_count = 0

    for svc_type, os_name, details, ts in host.os_fingerprints:
        if svc_type == 'SYN':
            syn_count += 1
            latest_ts = max(latest_ts, ts)
    if syn_count == 0:
        for svc_type, os_name, details, ts in host.os_fingerprints:
            if svc_type == 'SYNACK':
                syn_count += 1
                latest_ts = max(latest_ts, ts)

    if latest_ts == 0 and host.last_seen:
        latest_ts = host.last_seen

    cutoff_ts = latest_ts - (lookback_hours * 3600)

    os_votes = defaultdict(lambda: {'count': 0, 'timestamps': []})
    sources  = defaultdict(list)

    FP_WEIGHTS = {'SYN': 6, 'SYNACK': 4, 'ACK': 1, 'FIN': 1, 'RST': 1}

    for svc_type, os_name, details, ts in host.os_fingerprints:
        if ts < cutoff_ts or os_name == 'unknown':
            continue
        w = FP_WEIGHTS.get(svc_type, 1)
        os_votes[os_name]['count'] += w
        os_votes[os_name]['timestamps'].append(ts)
        sources[os_name].append(f'TCP {svc_type} fingerprint (+{w})')

    for os_fam, os_det, w, ts in host.os_hints_svc:
        if ts < cutoff_ts:
            continue
        os_votes[os_fam]['count'] += w
        os_votes[os_fam]['timestamps'].append(ts)
        sources[os_fam].append(f'Server: {os_det} (+{w})')

    for os_fam, os_det, w, ts in host.os_hints_cli:
        if ts < cutoff_ts:
            continue
        os_votes[os_fam]['count'] += w
        os_votes[os_fam]['timestamps'].append(ts)
        sources[os_fam].append(f'Client: {os_det} (+{w})')

    for os_fam, os_det, w, ts in host.os_hints_mac:
        if ts < cutoff_ts:
            continue
        os_votes[os_fam]['count'] += w
        os_votes[os_fam]['timestamps'].append(ts)
        sources[os_fam].append(f'MAC OUI: {os_det} (+{w})')

    if not os_votes:
        return {
            'os': 'unknown', 'details': 'unknown', 'confidence': 0,
            'timestamp': latest_ts, 'flux': 0, 'transitions': [],
            'inference_sources': [],
        }

    sorted_os = sorted(os_votes.items(), key=lambda x: x[1]['count'], reverse=True)
    best_os = sorted_os[0][0]
    best_count = sorted_os[0][1]['count']

    # Best details — prefer SYN fingerprint details
    best_details = 'unknown'
    for svc_type, os_name, details, ts in host.os_fingerprints:
        if ts < cutoff_ts or os_name != best_os:
            continue
        if svc_type == 'SYN':
            best_details = details
            break
        elif svc_type == 'SYNACK' and best_details == 'unknown':
            best_details = details

    if best_details == 'unknown':
        for os_fam, os_det, w, ts in host.os_hints_svc + host.os_hints_cli + host.os_hints_mac:
            if os_fam == best_os and os_det != best_os:
                best_details = os_det
                break

    # Refine generic "XP/2000" with build-level details from client hints
    if best_os == 'Windows' and ('XP/2000' in best_details or best_details == 'unknown'):
        for os_fam, os_det, w, ts in host.os_hints_cli:
            if os_fam == 'Windows' and ts >= cutoff_ts:
                if 'build' in os_det or 'Windows 1' in os_det:
                    best_details = os_det
                    break

    confidence = min(100, 20 + (10 * best_count))

    transitions = detect_os_transitions(host, cutoff_ts)

    deduped_sources = []
    seen_srcs = set()
    for s in sources.get(best_os, []):
        if s not in seen_srcs:
            deduped_sources.append(s)
            seen_srcs.add(s)

    return {
        'os': best_os, 'details': best_details,
        'confidence': confidence, 'timestamp': latest_ts,
        'flux': len(transitions), 'transitions': transitions,
        'inference_sources': deduped_sources,
    }


# ── Deduplication helpers ───────────────────────────────────────────────────

def get_latest_services(host, cutoff_ts=0):
    """Deduplicated latest service per (proto, port)."""
    result = {'tcp': {}, 'udp': {}}
    for proto_name, store in [('tcp', host.tcp_services), ('udp', host.udp_services)]:
        for port, entries in store.items():
            valid = [(s, d, t) for s, d, t in entries if t >= cutoff_ts]
            if not valid:
                continue
            identified = [(s, d, t) for s, d, t in valid
                          if s != 'unknown' and not d.startswith('@')]
            pick = identified if identified else valid
            result[proto_name][port] = max(pick, key=lambda x: x[2])
    return result


def get_deduplicated_clients(host, cutoff_ts=0):
    """Deduplicated client entries (normalized to remove session-specific data)."""
    dedup = {}
    for proto_name, store in [('tcp', host.tcp_clients), ('udp', host.udp_clients)]:
        for port, entries in store.items():
            for svc, det, ts in entries:
                if ts < cutoff_ts:
                    continue
                if svc == 'unknown' and det.startswith('@'):
                    norm_key = (proto_name, svc, det)
                else:
                    norm = re.sub(r'Cookie: \S+', 'Cookie:...', det)
                    norm = re.sub(r'Content.?Length: \d+', '', norm)
                    norm = re.sub(r'Host: \S+', '', norm)
                    norm = re.sub(r'ASP\.NET_SessionId=\S+', '', norm)
                    norm = re.sub(r'MS-CV: \S+', '', norm)
                    norm = re.sub(r'Referer: \S+', '', norm)
                    norm = norm.strip()
                    norm_key = (proto_name, svc, norm)
                if norm_key not in dedup or ts > dedup[norm_key][4]:
                    dedup[norm_key] = (proto_name, port, svc, det, ts)
    return list(dedup.values())


# ── Formatting helpers ──────────────────────────────────────────────────────

def format_timestamp(ts):
    """Unix timestamp -> 'YYYY/MM/DD HH:MM:SS'."""
    if not ts:
        return 'unknown'
    return datetime.fromtimestamp(ts).strftime('%Y/%m/%d %H:%M:%S')


def format_iso8601(ts):
    """Unix timestamp -> ISO 8601 UTC string."""
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _dedup_cpes(cpes):
    seen = set()
    result = []
    for c in cpes:
        if c['raw'] not in seen:
            seen.add(c['raw'])
            result.append(c)
    return result


# ── Snort policy mapping ───────────────────────────────────────────────────

SNORT_POLICY_MAP = {
    'Cisco':    ('Last',    'last'),
    'IOS':      ('Last',    'last'),
    'IRIX':     ('BSD',     'irix'),
    'NetBSD':   ('BSD',     'bsd'),
    'FreeBSD':  ('BSD',     'bsd'),
    'OpenBSD':  ('linux',   'bsd'),
    'MacOS':    ('First',   'macos'),
    'SunOS':    ('First',   'first'),
    'Solaris':  ('Solaris',  'solaris'),
    'Embedded': ('BSD',      'bsd'),
    'iOS':      ('First',   'macos'),
    'Apple':    ('First',   'macos'),
}


def get_snort_policy(os_name, os_details, default_os='linux'):
    """Return (frag3_policy, stream5_policy) for Snort host_attribute.xml."""
    if os_name in SNORT_POLICY_MAP:
        frag3, stream5 = SNORT_POLICY_MAP[os_name]
        if os_name == 'HPUX':
            if '10' in os_details:
                return 'BSD', 'hpux10'
            return 'First', 'hpux'
        return frag3, stream5

    if os_name == 'Linux':
        frag3 = 'linux'
        if '2.2' in os_details or '2.0' in os_details:
            return frag3, 'old-linux'
        return frag3, 'linux'

    if os_name == 'Windows':
        frag3 = 'Windows'
        if '2003' in os_details or '2008' in os_details:
            return frag3, 'win2003'
        if 'Vista' in os_details:
            return frag3, 'vista'
        return frag3, 'windows'

    defaults = {
        'linux':   ('linux',   'linux'),
        'bsd':     ('BSD',     'bsd'),
        'windows': ('Windows', 'windows'),
        'macos':   ('First',   'macos'),
    }
    return defaults.get(default_os, ('BSD', 'bsd'))


# ── Suricata policy mapping ────────────────────────────────────────────────
# Suricata host-os-policy values:
#   windows, linux, bsd, bsd-right, old-linux, solaris,
#   hpux10, hpux11, irix, macos, vista, windows2k3
# Suricata defrag policies:
#   bsd, bsd-right, linux, windows, solaris, first, last
# Suricata libhtp personalities:
#   Apache_2, IDS, IIS_4_0, IIS_5_0, IIS_5_1, IIS_6_0, IIS_7_0, IIS_7_5,
#   Minimal

def get_suricata_os_policy(os_name, os_details):
    """Return Suricata host-os-policy value."""
    if os_name == 'Windows':
        if 'Vista' in os_details:
            return 'vista'
        if '2003' in os_details or '2008' in os_details:
            return 'windows2k3'
        return 'windows'
    if os_name == 'Linux':
        if '2.2' in os_details or '2.0' in os_details:
            return 'old-linux'
        return 'linux'
    if os_name in ('FreeBSD', 'NetBSD'):
        return 'bsd'
    if os_name == 'OpenBSD':
        return 'bsd'
    if os_name in ('MacOS', 'Apple', 'iOS'):
        return 'macos'
    if os_name == 'Solaris' or os_name == 'SunOS':
        return 'solaris'
    if os_name == 'HPUX':
        return 'hpux11' if '11' in os_details else 'hpux10'
    if os_name == 'IRIX':
        return 'irix'
    if os_name == 'Cisco' or os_name == 'IOS':
        return 'bsd'
    return 'linux'  # safe default


def get_suricata_defrag_policy(os_name, os_details):
    """Return Suricata defrag policy value."""
    if os_name == 'Windows':
        return 'windows'
    if os_name == 'Linux':
        return 'linux'
    if os_name in ('FreeBSD', 'NetBSD', 'OpenBSD'):
        return 'bsd'
    if os_name in ('MacOS', 'Apple', 'iOS'):
        return 'first'
    if os_name == 'Solaris' or os_name == 'SunOS':
        return 'solaris'
    if os_name == 'Cisco' or os_name == 'IOS':
        return 'last'
    return 'bsd'


def get_libhtp_personality(svc_name, svc_details):
    """Return Suricata libhtp personality for an HTTP server."""
    if 'Microsoft-IIS' in svc_details or 'Microsoft IIS' in svc_details:
        ver_m = re.search(r'IIS[/ ]?(?:httpd )?(\d+)', svc_details)
        if ver_m:
            v = int(ver_m.group(1))
            if v <= 4:
                return 'IIS_4_0'
            if v == 5:
                # Check sub-version
                sub_m = re.search(r'IIS[/ ]?(?:httpd )?5\.(\d)', svc_details)
                if sub_m and sub_m.group(1) == '1':
                    return 'IIS_5_1'
                return 'IIS_5_0'
            if v == 6:
                return 'IIS_6_0'
            if v == 7:
                sub_m = re.search(r'IIS[/ ]?(?:httpd )?7\.(\d)', svc_details)
                if sub_m and sub_m.group(1) == '5':
                    return 'IIS_7_5'
                return 'IIS_7_0'
            # IIS 8+ — use IIS_7_5 as closest match
            return 'IIS_7_5'
        return 'IIS_7_0'
    if 'Apache' in svc_details:
        return 'Apache_2'
    if 'nginx' in svc_details.lower():
        return 'Minimal'
    if 'lighttpd' in svc_details:
        return 'Minimal'
    return 'IDS'


def build_suricata_config(hosts, os_results):
    """
    Build Suricata configuration fragments from analyzed hosts.
    Returns dict with keys: host_os_policy, defrag, libhtp_server_config
    """
    # Group hosts by os-policy
    os_policy_groups = defaultdict(list)
    defrag_groups    = defaultdict(list)

    for ip, host in sorted(hosts.items()):
        oi = os_results.get(ip)
        if not oi or oi['confidence'] < 20:
            continue
        os_pol = get_suricata_os_policy(oi['os'], oi['details'])
        defrag_pol = get_suricata_defrag_policy(oi['os'], oi['details'])
        os_policy_groups[os_pol].append(ip)
        defrag_groups[defrag_pol].append(ip)

    # Group HTTP servers by libhtp personality
    libhtp_groups = defaultdict(list)
    for ip, host in sorted(hosts.items()):
        for port, entries in host.tcp_services.items():
            for svc_name, svc_details, ts in entries:
                if svc_name == 'http' and svc_details and not svc_details.startswith('@'):
                    personality = get_libhtp_personality(svc_name, svc_details)
                    libhtp_groups[personality].append({'ip': ip, 'port': port,
                                                      'details': svc_details})
                    break  # one per port per host

    # Deduplicate IPs in libhtp groups
    for personality in libhtp_groups:
        seen = set()
        deduped = []
        for entry in libhtp_groups[personality]:
            if entry['ip'] not in seen:
                seen.add(entry['ip'])
                deduped.append(entry)
        libhtp_groups[personality] = deduped

    return {
        'host_os_policy': dict(os_policy_groups),
        'defrag': dict(defrag_groups),
        'libhtp_server_config': dict(libhtp_groups),
    }


def format_suricata_yaml(suricata_config):
    """Render Suricata config fragments as includable YAML strings."""
    lines = []

    # host-os-policy
    lines.append('# Suricata host-os-policy settings')
    lines.append('# Include in suricata.yaml under: host-os-policy:')
    lines.append('host-os-policy:')
    for policy in sorted(suricata_config['host_os_policy']):
        ips = suricata_config['host_os_policy'][policy]
        lines.append(f'  {policy}:')
        for ip in sorted(ips):
            lines.append(f'    - "{ip}"')
    lines.append('')

    # defrag host-config
    lines.append('# Suricata defrag host configuration')
    lines.append('# Include in suricata.yaml under: defrag: host-config:')
    lines.append('defrag:')
    lines.append('  host-config:')
    for policy in sorted(suricata_config['defrag']):
        ips = suricata_config['defrag'][policy]
        lines.append(f'    - policy: {policy}')
        lines.append(f'      bind:')
        for ip in sorted(ips):
            lines.append(f'        - "{ip}"')
    lines.append('')

    # libhtp server-config
    lines.append('# Suricata libhtp server personality configuration')
    lines.append('# Include in suricata.yaml under: app-layer: protocols: http: libhtp: server-config:')
    lines.append('libhtp:')
    lines.append('  default-config:')
    lines.append('    personality: IDS')
    lines.append('  server-config:')
    for personality in sorted(suricata_config['libhtp_server_config']):
        entries = suricata_config['libhtp_server_config'][personality]
        label = personality.lower().replace('_', '-')
        lines.append(f'    - {label}:')
        lines.append(f'        personality: {personality}')
        lines.append(f'        address:')
        for entry in entries:
            lines.append(f'          - "{entry["ip"]}"')
    lines.append('')

    return '\n'.join(lines)


# ── Server / version extraction ────────────────────────────────────────────

def get_server_and_version(details):
    """Extract (server_product, version) from a service detail string."""
    cpe_match = re.search(r'cpe:\w:[\w_]+:([\w_]+)(?::([\d.]+))?', details)
    if cpe_match:
        product = cpe_match.group(1).replace('_', ' ').title()
        version = cpe_match.group(2) or ''
        text_before = details.split('cpe:')[0].strip()
        if text_before:
            product = text_before
        return product, version

    patterns = [
        (r'Apache(?:\s+httpd)?\s*([\d.]+)?',           'Apache'),
        (r'Microsoft[- ]IIS(?:\s+httpd)?\s*([\d.]+)?',  'Microsoft-IIS'),
        (r'nginx(?:/(\S+))?',                           'nginx'),
        (r'OpenSSH\s+(\S+)',                            'OpenSSH'),
        (r'TLSv([\d.]+)',                               'TLS'),
        (r'Remote Desktop Protocol.*?\((.+?)\)',        'RDP'),
    ]
    for pat, name in patterns:
        m = re.search(pat, details)
        if m:
            ver = m.group(1) if m.lastindex and m.group(1) else ''
            return name, ver

    word_m = re.match(r'(\w+)', details)
    ver_m = re.search(r'([\d]+(?:\.[\d]+)+)', details)
    return (word_m.group(1) if word_m else 'unknown',
            ver_m.group(1) if ver_m else '')


# ── ECS (Elastic Common Schema) output ─────────────────────────────────────

def _ecs_os_type(os_family):
    """Map OS family to ECS host.os.type enum."""
    mapping = {
        'Windows': 'windows', 'Linux': 'linux', 'MacOS': 'macos',
        'FreeBSD': 'unix', 'OpenBSD': 'unix', 'NetBSD': 'unix',
        'Solaris': 'unix', 'SunOS': 'unix', 'HPUX': 'unix',
        'IRIX': 'unix', 'iOS': 'ios', 'Apple': 'macos',
    }
    return mapping.get(os_family, 'unknown')


def _ecs_os_family(os_family):
    """Map OS family to ECS host.os.family."""
    mapping = {
        'Windows': 'windows', 'Linux': 'linux', 'MacOS': 'darwin',
        'FreeBSD': 'bsd', 'OpenBSD': 'bsd', 'NetBSD': 'bsd',
        'Solaris': 'sysv', 'SunOS': 'sysv', 'HPUX': 'sysv',
        'IRIX': 'sysv', 'iOS': 'darwin', 'Apple': 'darwin',
        'Embedded': 'other',
    }
    return mapping.get(os_family, 'unknown')


def host_to_ecs(host, os_info=None, services=None, clients=None):
    """
    Serialize a HostAsset to Elastic Common Schema (ECS) format.
    Returns a dict suitable for JSON output / Elasticsearch indexing.
    """
    if os_info is None:
        os_info = guess_os(host)
    cutoff = (os_info.get('timestamp', 0) or 0) - 43200
    if services is None:
        services = get_latest_services(host, cutoff)
    if clients is None:
        clients = get_deduplicated_clients(host, cutoff)

    doc = {
        '@timestamp': format_iso8601(host.last_seen),
        'event': {
            'kind': 'enrichment',
            'category': ['host'],
            'type': ['info'],
            'module': 'prads',
        },
        'host': {
            'ip': [host.ip],
            'os': {
                'name': os_info['os'],
                'full': f"{os_info['os']} {os_info['details']}" if os_info['details'] != 'unknown'
                        else os_info['os'],
                'family': _ecs_os_family(os_info['os']),
                'type': _ecs_os_type(os_info['os']),
            },
        },
        'prads': {
            'os_confidence': os_info['confidence'],
            'os_inference_sources': os_info['inference_sources'][:10],
            'first_seen': format_iso8601(host.first_seen),
            'last_seen': format_iso8601(host.last_seen),
        },
    }

    # VLANs
    if host.vlans:
        doc['network'] = {'vlan': {'id': sorted(host.vlans)}}

    # MACs + vendors
    mac_set = {}
    for mac, vs, vf, ts in host.arp_entries:
        if mac not in mac_set or vs:
            mac_set[mac] = (vs, vf)
    if mac_set:
        doc['host']['mac'] = sorted(mac_set.keys())
        vendors = {vs for vs, vf in mac_set.values() if vs}
        if vendors:
            doc['prads']['mac_vendors'] = sorted(vendors)

    # OS transitions
    if os_info.get('transitions'):
        doc['prads']['os_transitions'] = [
            {'from': t['from_os'], 'to': t['to_os'],
             'timestamp': format_iso8601(t['to_ts']),
             'details': t['to_details']}
            for t in os_info['transitions']
        ]

    # Services
    svc_list = []
    for port in sorted(services['tcp']):
        svc_name, det, ts = services['tcp'][port]
        entry = {
            'type': svc_name,
            'port': port,
            'transport': 'tcp',
            'description': det,
            'observed_at': format_iso8601(ts),
        }
        cpes = parse_cpe(det)
        if cpes:
            entry['cpe'] = [c['raw'] for c in cpes]
        svc_list.append(entry)

    for port in sorted(services['udp']):
        svc_name, det, ts = services['udp'][port]
        svc_list.append({
            'type': svc_name,
            'port': port,
            'transport': 'udp',
            'description': det,
            'observed_at': format_iso8601(ts),
        })
    if svc_list:
        doc['service'] = svc_list

    # CPEs
    deduped_cpes = _dedup_cpes(host.cpes)
    if deduped_cpes:
        doc['prads']['cpe'] = [c['raw'] for c in deduped_cpes]

    # Client applications (deduplicated)
    if host.client_apps:
        seen = set()
        apps = []
        for ua in host.client_apps:
            key = (ua.get('browser', ''), ua.get('browser_version', ''),
                   ua.get('application', ''), ua.get('app_version', ''),
                   ua.get('runtime', ''), ua.get('runtime_version', ''))
            if key not in seen and key != ('', '', '', '', '', ''):
                seen.add(key)
                apps.append({k: v for k, v in ua.items()
                             if k not in ('timestamp', 'raw')})
        if apps:
            doc['prads']['client_applications'] = apps

        # Also populate ECS user_agent from the most recent browser entry
        for ua in reversed(host.client_apps):
            if 'browser' in ua:
                doc['user_agent'] = {
                    'name': ua['browser'],
                    'version': ua.get('browser_version', ''),
                }
                if 'os' in ua:
                    doc['user_agent']['os'] = {'name': ua['os']}
                break

    # Clients (protocol connections)
    cli_protos = set()
    for proto, port, svc, det, ts in clients:
        if svc == 'unknown' and det.startswith('@'):
            cli_protos.add(det.lstrip('@'))
        else:
            cli_protos.add(svc)
    if cli_protos:
        doc['prads']['client_protocols'] = sorted(cli_protos)

    return doc


def host_to_report_dict(host, os_info=None, services=None, clients=None):
    """Serialize a HostAsset to a general-purpose report dict (non-ECS)."""
    if os_info is None:
        os_info = guess_os(host)
    cutoff = (os_info.get('timestamp', 0) or 0) - 43200
    if services is None:
        services = get_latest_services(host, cutoff)
    if clients is None:
        clients = get_deduplicated_clients(host, cutoff)

    d = {
        'ip': host.ip,
        'vlans': sorted(host.vlans),
        'first_seen': format_timestamp(host.first_seen),
        'last_seen': format_timestamp(host.last_seen),
        'os': {
            'name': os_info['os'],
            'details': os_info['details'],
            'confidence': os_info['confidence'],
            'inference_sources': os_info['inference_sources'][:10],
        },
        'mac_addresses': [
            {'mac': mac, 'vendor': vs, 'vendor_full': vf}
            for mac, vs, vf in {(m, vs, vf) for m, vs, vf, t in host.arp_entries}
        ],
        'icmp': host.has_icmp,
        'cpes': [c['raw'] for c in _dedup_cpes(host.cpes)],
        'tcp_services': [],
        'udp_services': [],
        'clients': [],
    }

    if os_info.get('transitions'):
        d['os']['transitions'] = [
            {'from': t['from_os'], 'to': t['to_os'],
             'at': format_timestamp(t['to_ts']),
             'details': t['to_details']}
            for t in os_info['transitions']
        ]

    for port in sorted(services['tcp']):
        svc, det, ts = services['tcp'][port]
        entry = {'port': port, 'service': svc, 'details': det,
                 'discovered': format_timestamp(ts)}
        cpes = parse_cpe(det)
        if cpes:
            entry['cpe'] = [c['raw'] for c in cpes]
        d['tcp_services'].append(entry)

    for port in sorted(services['udp']):
        svc, det, ts = services['udp'][port]
        d['udp_services'].append({
            'port': port, 'service': svc, 'details': det,
            'discovered': format_timestamp(ts),
        })

    for proto, port, svc, det, ts in clients:
        if svc == 'unknown' and det.startswith('@'):
            d['clients'].append({
                'protocol': proto, 'service': det.lstrip('@'),
                'details': '', 'discovered': format_timestamp(ts),
            })
        else:
            d['clients'].append({
                'protocol': proto, 'service': svc,
                'details': det[:200],
                'discovered': format_timestamp(ts),
            })

    if host.client_apps:
        seen = set()
        apps = []
        for ua in host.client_apps:
            key = (ua.get('browser', ''), ua.get('browser_version', ''),
                   ua.get('application', ''), ua.get('app_version', ''),
                   ua.get('runtime', ''), ua.get('runtime_version', ''))
            if key not in seen and key != ('', '', '', '', '', ''):
                seen.add(key)
                apps.append({k: v for k, v in ua.items()
                             if k not in ('timestamp', 'raw')})
        if apps:
            d['client_applications'] = apps

    return d
