# PRADS Asset Analysis Tools

Python-based tooling for analyzing PRADS (Passive Real-time Asset Detection System) asset logs. These tools replace and extend the original Perl `prads-asset-report` and `prads2snort` scripts with improved OS detection, deduplication, MAC OUI vendor enrichment, and multi-format output including Suricata YAML and Elastic Common Schema (ECS) JSON.

## Architecture

```
prads-asset.log
       │
       ▼
 prads_utils.py          ← shared parsing, inference, policy mapping
   ┌───┴───┐
   ▼       ▼
prads-asset-report2    prads2snort2
   │                     │
   ├─ text report        ├─ Snort host_attribute.xml
   ├─ ECS JSON           ├─ Suricata YAML fragments
   └─ dict JSON          ├─ ECS JSON
                         └─ all (combined)
```

## Dependencies

- Python 3.6+
- Standard library only (no pip packages required)
- Optional: `etc/mac.sig` OUI database (auto-discovered from `../etc/mac.sig`)

```bash
chmod +x tools/prads-asset-report2 tools/prads2snort2
```

---

## prads-asset-report2

Human-readable asset inventory reports with OS inference, deduplication, and structured output.

### Usage

```
prads-asset-report2 [-r FILE] [-w FILE] [-i IP] [-n] [-p] [-f FORMAT]

Options:
  -r, --report-file FILE   PRADS asset log (default: /var/log/prads-asset.log)
  -w, --output-file FILE   Write output to file instead of stdout
  -i, --ip IP              Report only this IP address
  -n, --no-dns             Skip reverse DNS lookups
  -p, --private-only       Only resolve RFC 1918 addresses
  -f, --format FORMAT      text (default), json (ECS), or dict
```

### Example Workflows

**Full network text report (no DNS):**
```bash
python3 tools/prads-asset-report2 -r logs/prads-asset.log -n -f text
```

**Investigate a single host:**
```bash
python3 tools/prads-asset-report2 -r logs/prads-asset.log -n -i 10.15.1.27
```

**Export ECS JSON for Elasticsearch:**
```bash
python3 tools/prads-asset-report2 -r logs/prads-asset.log -n -f json -w assets.json
```

### Example Output: Text Report

**Windows Server with IIS (CPE, service inference):**
```
1 ──────────────────────────────────────────────────────
IP:   10.15.1.27
OS:   Windows — XP/2000 (RFC1323+, w+, tstamp-) (100%)
      Evidence: TCP SYN fingerprint (+6); Server: Windows Server (IIS 10.0) (+5);
                Server: Windows (+8); Client: Windows (CryptoAPI) (+4)
Seen: 2026/03/10 01:59:11 — 2026/03/13 20:42:44
VLAN: 10
MAC:  CE:A9:BB:B5:CA:5C  (2026/03/13 01:59:38)
CPE:  cpe:/a:microsoft:internet_information_services:10.0

Port    Service      TCP Application
80      SERVER       http:Microsoft IIS httpd 10.0 (os:Windows cpe:a:microsoft:...)
90      SERVER       http:Unknown HTTP (HTTP/1.1)
445     SERVER       unknown:@microsoft-ds

Proto  Service    Client Details
tcp    http       RestSharp/112.1.0.0
tcp    http       Microsoft CryptoAPI/10.0

Client protocols: domain, https, ldap, microsoft-ds, smtp
```

**Windows Workstation (User-Agent parsing, client app inventory):**
```
1 ──────────────────────────────────────────────────────
IP:   10.15.3.235
OS:   Windows — Windows 10/11 (100%)
      Evidence: TCP SYN fingerprint (+6); Client: Windows 8/Server 2012 (+7);
                Client: Windows 10/11 (+7); Client: Windows (CryptoAPI) (+4);
                Client: Windows (WUA) (+4)
Seen: 2026/03/10 01:59:05 — 2026/03/13 20:42:39
VLAN: 10
ICMP: Enabled

Proto  Service    Client Details
tcp    http       Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/145.0 ... Edg/145.0...
tcp    http       Microsoft CryptoAPI/10.0
tcp    http       Windows-Update-Agent/1023.1020.2192.0 Client Protocol/2.71

Client protocols: domain, https, ldap, microsoft-ds, ntp

Client Applications:
  Windows Update Agent 1023.1020.2192.0
  Microsoft Edge 145.0.0.0 | [Windows 10/11] | (x64)
  Internet Explorer 7.0 | [Windows 8/Server 2012] | (x64 (WoW64))
```

**Linux Server (OpenSSH, curl):**
```
1 ──────────────────────────────────────────────────────
IP:   10.15.1.5
OS:   Linux — Linux/Unix (OpenSSH 10.0p2) (100%)
      Evidence: Server: Linux/Unix (OpenSSH 10.0p2) (+2);
                Client: Linux/Unix (OpenSSH client) (+2)
MAC:  90:5A:08:11:B6:B8  (2026/03/13 01:59:09)

Port    Service      TCP Application
35878   SERVER       ssh:OpenSSH 10.0p2 (Protocol 2.0)
56602   SERVER       ssh:OpenSSH 10.0p2 (Protocol 2.0)

Proto  Service    Client Details
tcp    ssh        OpenSSH 10.0p2 (Protocol 2.0)
tcp    http       curl/8.14.1
```

**Embedded Device (MAC OUI vendor inference):**
```
1 ──────────────────────────────────────────────────────
IP:   10.15.1.150
OS:   Embedded — Lanner appliance (100%)
      Evidence: MAC OUI: Lanner appliance (+5)
MAC:  00:90:0B:C2:C0:89  [LannerElec]  (2026/03/13 01:59:08)
      00:90:0B:C2:C0:8A  [LannerElec]  (2026/03/13 02:01:23)

Port    Service      TCP Application
4080    SERVER       http:Unknown HTTP (HTTP/1.1)
4081    SERVER       ssl:TLSv1.2
```

### Example Output: ECS JSON

```json
{
  "@timestamp": "2026-03-14T01:42:44+00:00",
  "event": {
    "kind": "enrichment",
    "category": ["host"],
    "type": ["info"],
    "module": "prads"
  },
  "host": {
    "ip": ["10.15.1.27"],
    "os": {
      "name": "Windows",
      "full": "Windows XP/2000 (RFC1323+, w+, tstamp-)",
      "family": "windows",
      "type": "windows"
    },
    "mac": ["CE:A9:BB:B5:CA:5C"]
  },
  "prads": {
    "os_confidence": 100,
    "os_inference_sources": [
      "TCP SYN fingerprint (+6)",
      "Server: Windows Server (IIS 10.0) (+5)",
      "Server: Windows (+8)",
      "Client: Windows (CryptoAPI) (+4)"
    ],
    "first_seen": "2026-03-10T06:59:11+00:00",
    "last_seen": "2026-03-14T01:42:44+00:00",
    "cpe": ["cpe:/a:microsoft:internet_information_services:10.0"],
    "client_protocols": ["domain", "http", "https", "ldap", "microsoft-ds", "smtp"]
  },
  "network": { "vlan": { "id": [10] } },
  "service": [
    {
      "type": "http", "port": 80, "transport": "tcp",
      "description": "Microsoft IIS httpd 10.0 (os:Windows cpe:a:microsoft:...)",
      "cpe": ["cpe:/a:microsoft:internet_information_services:10.0"]
    }
  ]
}
```

---

## prads2snort2

Generates IDS host attribute configurations from PRADS asset logs.

### Usage

```
prads2snort2 [-i FILE] [-o FILE] [-d OS] [-s PCT] [-f FORMAT] [-v] [--force]

Options:
  -i, --infile FILE        PRADS asset log (default: /var/log/prads-asset.log)
  -o, --outfile FILE       Output file (or base name for -f all)
  -d, --default-os OS      Default OS for unknowns: linux|bsd|windows|macos
  -s, --skip PCT           Skip hosts with confidence below this %
  -f, --format FORMAT      snort (default), suricata, json, or all
  -v, --verbose            Print per-host details to stderr
  --force                  Overwrite existing output files
  --filter-ip IP           Process only this IP
```

### Example Workflows

**Snort host_attribute.xml:**
```bash
python3 tools/prads2snort2 -i logs/prads-asset.log -f snort -o host_attribute.xml --force
```

**Suricata YAML fragments:**
```bash
python3 tools/prads2snort2 -i logs/prads-asset.log -f suricata -o suricata-prads.yaml --force
```

**All formats at once:**
```bash
python3 tools/prads2snort2 -i logs/prads-asset.log -f all -o prads-output --force
# Creates: prads-output.xml, prads-output-suricata.yaml, prads-output.json
```

**Skip low-confidence hosts with verbose output:**
```bash
python3 tools/prads2snort2 -i logs/prads-asset.log -f snort -o ha.xml -s 50 -v --force
```

### Example Output: Snort XML

```xml
<HOST>
  <IP>10.15.1.27</IP>
  <OPERATING_SYSTEM>
    <NAME>
      <ATTRIBUTE_VALUE>Windows</ATTRIBUTE_VALUE>
      <CONFIDENCE>100</CONFIDENCE>
    </NAME>
    <VENDOR>
      <ATTRIBUTE_VALUE>Windows</ATTRIBUTE_VALUE>
      <CONFIDENCE>100</CONFIDENCE>
    </VENDOR>
    <VERSION>
      <ATTRIBUTE_VALUE>XP/2000 (RFC1323+, w+, tstamp-)</ATTRIBUTE_VALUE>
      <CONFIDENCE>100</CONFIDENCE>
    </VERSION>
    <FRAG_POLICY>Windows</FRAG_POLICY>
    <STREAM_POLICY>windows</STREAM_POLICY>
  </OPERATING_SYSTEM>
  <SERVICES>
    <SERVICE>
      <PORT><ATTRIBUTE_VALUE>80</ATTRIBUTE_VALUE>...</PORT>
      <IPPROTO><ATTRIBUTE_VALUE>tcp</ATTRIBUTE_VALUE>...</IPPROTO>
      <PROTOCOL><ATTRIBUTE_VALUE>http</ATTRIBUTE_VALUE>...</PROTOCOL>
      <APPLICATION>
        <ATTRIBUTE_VALUE>Microsoft IIS httpd 10.0</ATTRIBUTE_VALUE>
        <VERSION><ATTRIBUTE_VALUE>10.0</ATTRIBUTE_VALUE>...</VERSION>
      </APPLICATION>
    </SERVICE>
  </SERVICES>
  <CLIENTS>
    <CLIENT>
      <PROTOCOL><ATTRIBUTE_VALUE>http</ATTRIBUTE_VALUE></PROTOCOL>
      <APPLICATION><ATTRIBUTE_VALUE>Microsoft CryptoAPI/10.0</ATTRIBUTE_VALUE>...</APPLICATION>
    </CLIENT>
  </CLIENTS>
</HOST>
```

### Example Output: Suricata YAML

The tool generates three includable YAML fragments:

**host-os-policy** (TCP stream reassembly):
```yaml
host-os-policy:
  linux:
    - "10.15.1.5"
    - "10.15.1.35"
    - "10.15.1.84"
    - "172.16.1.101"
  windows:
    - "10.15.1.27"
    - "10.15.1.31"
    - "10.15.3.235"
  macos:
    - "10.15.1.40"
    - "10.15.1.47"
```

**defrag** (IP defragmentation):
```yaml
defrag:
  host-config:
    - policy: bsd
      bind:
        - "10.15.10.146"
    - policy: linux
      bind:
        - "10.15.1.5"
    - policy: windows
      bind:
        - "10.15.1.27"
```

**libhtp** (HTTP server personalities):
```yaml
libhtp:
  default-config:
    personality: IDS
  server-config:
    - apache-2:
        personality: Apache_2
        address:
          - "10.15.2.52"
          - "10.15.8.50"
    - iis-7-5:
        personality: IIS_7_5
        address:
          - "10.15.1.27"
          - "10.15.1.31"
    - minimal:
        personality: Minimal
        address:
          - "10.15.1.35"
```

---

## OS Inference Engine

The engine combines multiple evidence sources with weighted voting.

### Weight System

| Source | Weight | Example |
|--------|--------|---------|
| TCP SYN fingerprint | +6 | `Windows:XP/2000 (RFC1323+...)` |
| TCP SYNACK fingerprint | +4 | `unknown:unknown` |
| TCP ACK/FIN/RST fingerprint | +1 | `Windows:XP` |
| CPE OS tag in server banner | +8 | `(os:Windows cpe:a:microsoft:...)` |
| Server banner (strong) | +5 | IIS → Windows, Exchange → Windows |
| Client User-Agent (NT version) | +7 | `Windows NT 10.0` → Windows 10/11 |
| aws-sdk / WebDAV build number | +8-9 | `Windows/10.0.22631` → Win11 |
| Microsoft ecosystem client | +3-5 | CryptoAPI, WUA, BITS, WNS, NCSI |
| Apple device string | +8-9 | `iPhone OS,17.4.1,21E236,iPad7,5` |
| Embedded device (Yealink, etc.) | +9 | `Yealink SIP T33G fw:124.86.0.40` |
| MAC OUI vendor | +3-7 | Lanner → Embedded, Cisco → Cisco |
| Server banner (weak) | +2 | nginx → Linux likely, Apache → Linux likely |

### Confidence Formula

```
confidence = min(100, 20 + (10 × total_vote_count_for_winning_OS))
```

### OS Transition Detection

When SYN/SYNACK fingerprints for a host change OS family during the observation window (e.g., `Linux` → `Windows`), the engine flags this as a transition, indicating potential re-imaging, VM migration, or IP reuse. Transitions appear in both text and JSON output.

### Windows Version Refinement

The TCP SYN fingerprint typically reports `Windows:XP/2000` for all modern Windows versions (the TCP stack parameters are unchanged). The engine refines this using:

- User-Agent `Windows NT 10.0` → Windows 10/11
- `aws-sdk ... Windows/10.0.26100` → Windows 11 (build ≥22000)
- `Microsoft-WebDAV-MiniRedir/10.0.22631` → Windows 11 (build 22631)
- `Windows NT 6.2` → Windows 8/Server 2012
- `Windows NT 6.3` → Windows 8.1/Server 2012 R2

### MAC OUI Vendor Inference

The `etc/mac.sig` Wireshark OUI database (17,495 entries) is loaded at parse time. For each ARP entry:

1. Check if prads already embedded vendor inline: `[00:90:0B:C2:C0:89,(LannerElec)]`
2. If not, look up the 3-byte OUI prefix in the database
3. Map vendor to device type hints (e.g., Lanner → Embedded appliance, Cisco → network device, Dell → ambiguous)

---

## Suricata Configuration

### host-os-policy Mapping

| OS Family | Suricata Policy |
|-----------|----------------|
| Windows | `windows` |
| Windows Vista | `vista` |
| Windows 2003/2008 | `windows2k3` |
| Linux | `linux` |
| Linux 2.0/2.2 | `old-linux` |
| FreeBSD, NetBSD, OpenBSD | `bsd` |
| MacOS, iOS, Apple | `macos` |
| Solaris, SunOS | `solaris` |
| HPUX 10 | `hpux10` |
| HPUX 11 | `hpux11` |
| IRIX | `irix` |

### defrag Policy Mapping

| OS Family | Defrag Policy |
|-----------|--------------|
| Windows | `windows` |
| Linux | `linux` |
| *BSD | `bsd` |
| MacOS, iOS | `first` |
| Solaris | `solaris` |
| Cisco | `last` |

### libhtp Personality Mapping

| Server Banner | Personality |
|--------------|-------------|
| Microsoft IIS ≤4 | `IIS_4_0` |
| Microsoft IIS 5.0 | `IIS_5_0` |
| Microsoft IIS 5.1 | `IIS_5_1` |
| Microsoft IIS 6 | `IIS_6_0` |
| Microsoft IIS 7.0 | `IIS_7_0` |
| Microsoft IIS 7.5 | `IIS_7_5` |
| Microsoft IIS 8+ | `IIS_7_5` |
| Apache | `Apache_2` |
| nginx, lighttpd | `Minimal` |
| Other/unknown | `IDS` |

### Including in suricata.yaml

The generated YAML fragments can be included directly using YAML merge or by pasting the relevant sections:

```yaml
# In suricata.yaml, replace or merge:
host-os-policy:
  # paste from generated host-os-policy section

defrag:
  host-config:
    # paste from generated defrag section

app-layer:
  protocols:
    http:
      libhtp:
        # paste from generated libhtp section
```

---

## ECS Field Mapping

### Standard ECS Fields

| ECS Field | Source |
|-----------|--------|
| `@timestamp` | `host.last_seen` (ISO 8601 UTC) |
| `event.kind` | `"enrichment"` |
| `event.category` | `["host"]` |
| `event.module` | `"prads"` |
| `host.ip` | Asset IP address |
| `host.mac` | Deduplicated MAC addresses |
| `host.os.name` | Winning OS family |
| `host.os.full` | OS family + details |
| `host.os.family` | `windows`, `linux`, `darwin`, `bsd`, `sysv`, `other` |
| `host.os.type` | `windows`, `linux`, `macos`, `unix`, `ios` |
| `network.vlan.id` | Observed VLAN IDs |
| `service[].type` | Service protocol name |
| `service[].port` | Service port number |
| `service[].transport` | `tcp` or `udp` |
| `user_agent.name` | Browser name (from most recent UA) |
| `user_agent.version` | Browser version |
| `user_agent.os.name` | OS from User-Agent |

### PRADS Extension Fields (`prads.*`)

| Field | Description |
|-------|-------------|
| `prads.os_confidence` | 0-100 confidence score |
| `prads.os_inference_sources` | Evidence list with weights |
| `prads.first_seen` | First observation timestamp |
| `prads.last_seen` | Last observation timestamp |
| `prads.cpe` | CPE identifiers from service banners |
| `prads.mac_vendors` | OUI vendor names for observed MACs |
| `prads.client_protocols` | Deduplicated client protocol list |
| `prads.client_applications` | Parsed browser/app inventory |
| `prads.os_transitions` | OS change events (from/to/timestamp) |

### Ingesting into Elasticsearch

```bash
# Single bulk import
python3 tools/prads-asset-report2 -r prads-asset.log -n -f json -w /tmp/assets.json
# Then use Elasticsearch bulk API or Filebeat to index
```

---

## Shared Library: prads_utils.py

### Key Classes

**`HostAsset`** — aggregated data for one IP:

| Attribute | Type | Description |
|-----------|------|-------------|
| `ip` | str | IP address |
| `vlans` | set[int] | Observed VLAN IDs |
| `os_fingerprints` | list[tuple] | `(svc_type, os, details, ts)` |
| `tcp_services` | dict[int, list] | port → `[(svc_name, details, ts)]` |
| `tcp_clients` | dict[int, list] | port → `[(svc_name, details, ts)]` |
| `udp_services` | dict[int, list] | port → `[(svc_name, details, ts)]` |
| `udp_clients` | dict[int, list] | port → `[(svc_name, details, ts)]` |
| `arp_entries` | list[tuple] | `(mac, vendor_short, vendor_full, ts)` |
| `cpes` | list[dict] | Extracted CPE values |
| `os_hints_svc` | list[tuple] | `(os_fam, detail, weight, ts)` |
| `os_hints_cli` | list[tuple] | `(os_fam, detail, weight, ts)` |
| `os_hints_mac` | list[tuple] | `(os_fam, detail, weight, ts)` |
| `client_apps` | list[dict] | Parsed User-Agent data |

### Key Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `parse_log_file(path, filter_ip)` | `{ip: HostAsset}` | Parse entire log file |
| `guess_os(host, lookback_hours)` | dict | OS guess with confidence and transitions |
| `get_latest_services(host, cutoff)` | dict | Deduplicated services per port |
| `get_deduplicated_clients(host, cutoff)` | list | Normalized unique client entries |
| `lookup_oui_vendor(mac)` | `(short, full)` | MAC OUI vendor lookup |
| `infer_os_from_service(name, info)` | list | OS hints from server banner |
| `infer_os_from_client(name, details)` | list | OS hints from client fingerprint |
| `infer_os_from_vendor(short, full)` | tuple or None | OS hint from MAC vendor |
| `get_snort_policy(os, details, default)` | `(frag3, stream5)` | Snort policy mapping |
| `get_suricata_os_policy(os, details)` | str | Suricata host-os-policy value |
| `get_suricata_defrag_policy(os, details)` | str | Suricata defrag policy value |
| `get_libhtp_personality(name, details)` | str | Suricata libhtp personality |
| `build_suricata_config(hosts, os_results)` | dict | Grouped Suricata config |
| `format_suricata_yaml(config)` | str | Render config as YAML |
| `host_to_ecs(host, os_info, ...)` | dict | ECS-formatted document |
| `host_to_report_dict(host, os_info, ...)` | dict | General-purpose report dict |

### Programmatic Usage

```python
import sys
sys.path.insert(0, 'tools')
from prads_utils import parse_log_file, guess_os, get_latest_services

hosts = parse_log_file('logs/prads-asset.log', filter_ip='10.15.1.27')
for ip, host in hosts.items():
    os_info = guess_os(host)
    services = get_latest_services(host)
    print(f"{ip}: {os_info['os']} ({os_info['confidence']}%)")
    for port, (svc, det, ts) in sorted(services['tcp'].items()):
        print(f"  tcp/{port}: {svc} — {det}")
```
