# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is PRADS

PRADS (Passive Real-time Asset Detection System) is a C network monitoring tool that passively sniffs traffic via libpcap to fingerprint hosts and services. It identifies OS fingerprints (TCP SYN/SYNACK/ACK/FIN/RST, ICMP, DHCP) and application-layer services (TCP/UDP server and client signatures) without sending any packets.

## Build Commands

```bash
# Dependencies (Debian/Ubuntu)
sudo apt-get install libpcap-dev libpcre2-dev libvectorscan-dev  # or libhyperscan-dev

# Standard build (from project root)
make                    # builds src/prads and src/shm-client
make clean              # remove object files and binaries

# Build variants
make pfring             # build with PF_RING support (needs libpfring, librt, libnuma)
cd src && make debug    # debug build (-g -DDEBUG -Wall)
cd src && make static   # fully static binary
cd src && make TCMALLOC=y   # use tcmalloc

# CMake alternative
cmake -B build && cmake --build build

# Install (installs to /usr/local by default)
sudo make install
```

Always `make clean` before switching build variants (debug, static, etc.).

## Architecture

### Packet Processing Pipeline

`prads.c` is the main entry point — sets up libpcap, enters the capture loop, and dispatches packets by protocol. The global `config` struct (`globalconfig` in `config.h`) holds all runtime state: pcap handle, signature databases, asset hash tables, and connection tracking buckets.

### Fingerprinting Subsystems

- **OS fingerprinting** (`sig_tcp.c`, `ipfp/`): TCP flag-based fingerprints (SYN, SYNACK, ACK, FIN, RST) loaded from `etc/*.fp` files. UDP and ICMP fingerprinting in `ipfp/`. Uses p0f-style signature format.
- **Service fingerprinting** (`servicefp/`): Regex-based payload matching for TCP server (`tcps.c`), TCP client (`tcpc.c`), and UDP (`udps.c`) signatures loaded from `etc/*.sig` files. `servicefp.c` parses signature files and provides `get_app_name()`.
- **Vectorscan/Hyperscan engine** (`hs_engine.c/.h`): Compiles all service signatures into a single Vectorscan multi-pattern DFA for fast matching. Falls back to PCRE2 for patterns needing capture groups (`$1`/`$2` in title templates) or patterns that can't compile in Vectorscan (marked `HS_SIG_PREFILTER` or `HS_SIG_PCRE2_ONLY`).
- **Other**: ARP (`servicefp.c:arp_check`), DHCP (`dhcp.c`), DNS (`dump_dns.c`), MAC OUI (`mac.c`)

### Data Structures

- **Assets** (`assets.c/.h`): Hash table (`passet[BUCKET_SIZE]`) tracking discovered hosts and their services/OS info.
- **Connections** (`cxt.c/.h`): Hash table (`bucket[BUCKET_SIZE]`) for connection tracking with idle timeout (TCP_TIMEOUT=300s).
- **Signatures** (`prads.h:_signature`): Linked lists of compiled regex patterns. Each category (tcp-server, tcp-client, udp-server, udp-client) has both a linked list (`sig_serv_tcp`, etc.) and a compiled Vectorscan database (`hs_serv_tcp`, etc.).

### Output Plugins

`output-plugins/log_dispatch.c` routes asset events to enabled backends: stdout, file, FIFO (sguil-compatible), ringbuffer (shared memory for `shm-client`), and sguil.

### Configuration

`etc/prads.conf` — runtime config (interface, BPF filters, home_nets, enable/disable fingerprint types). Signature/fingerprint files are in `etc/`. Config path defaults to `CONFDIR` set at compile time (typically `../etc` for dev builds, `/usr/local/etc/prads` for installs). SIGHUP reloads runtime flags.

## Key Patterns

- The Makefile links against `-lhs` (Vectorscan/Hyperscan) and `-lpcre2-8`. The library is called `hs` in linker flags regardless of whether it's Vectorscan or Hyperscan.
- Signature files use the format: `<proto>,<port>,<regex>,<title_template>` where title templates can contain `$1`/`$2` for PCRE2 capture group substitution.
- `bstrlib.c/.h` is a vendored "Better String Library" used throughout for safe string handling. Use `bstring` type and `bstr*` functions, not raw C strings, for new code.
- The `patches/` directory contains the Vectorscan+PCRE2 migration patches (replacing the original PCRE dependency).

## Analysis Tools (Python)

Three Python tools in `tools/` analyze prads-asset.log output. No pip dependencies — stdlib only.

```bash
# Asset report (text, ECS JSON, or dict JSON)
python3 tools/prads-asset-report2 -r logs/prads-asset.log -n -f text
python3 tools/prads-asset-report2 -r logs/prads-asset.log -n -f json -w assets.json
python3 tools/prads-asset-report2 -r logs/prads-asset.log -n -i 10.15.1.27   # single host

# IDS config generation (Snort XML, Suricata YAML, ECS JSON)
python3 tools/prads2snort2 -i logs/prads-asset.log -f snort -o host_attribute.xml --force
python3 tools/prads2snort2 -i logs/prads-asset.log -f suricata -o suricata-prads.yaml --force
python3 tools/prads2snort2 -i logs/prads-asset.log -f all -o prads-output --force
```

- `prads_utils.py` is the shared library — log parsing, OS inference engine, policy mapping, ECS serialization
- OS inference combines TCP fingerprint voting (SYN=6, SYNACK=4, ACK/FIN/RST=1) with service banner CPE tags, client User-Agent parsing (Windows NT version, aws-sdk builds, Microsoft ecosystem clients), and MAC OUI vendor lookup (`etc/mac.sig`)
- Output formats: text report, Snort `host_attribute.xml`, Suricata YAML (host-os-policy, defrag, libhtp personalities), ECS-compliant JSON
- See `tools/README.md` for full documentation, example outputs, and API reference

## Log Format

`prads-asset.log` is CSV: `asset,vlan,port,proto,service,[service-info],distance,discovered`

- Service types: `SYN`, `SYNACK`, `ACK`, `RST`, `FIN` (OS fingerprints), `SERVER`, `CLIENT` (application layer), `ARP`, `UDP`, `ICMP`
- Service-info varies by type: TCP fingerprints use p0f format (`WSS:TTL:DF:...`), services use `svc_name:details`, ARP uses `MAC,(Vendor)`
- Discovered field is unix epoch (10 digits)

## Signature Pipeline

`tools/nmap2prads/nmap2prads.py` converts nmap-service-probes to PRADS passive signatures with Hyperscan/PCRE2 optimization. Output goes to `etc/tcp-service.sig.hsdb` and `etc/udp-service.sig.hsdb`. Config files in `tools/nmap2prads/`: `passive-probes.conf`, `priority.conf`, `include_services.conf`.
