# PRADS #

```text
 ______
|  __  |                  __
| _____|.----..------..--|  |.-----. (tm)
|  |    |  |-'|  __  ||  _  |__  --'
|__|    |__|  |____|_||_____|______|

Passive Real-time Asset Detection system!
```

> **Fork notice:** This is a fork of [gamelinux/prads](https://github.com/gamelinux/prads) with significant engine and tooling improvements. See [What's New in This Fork](#whats-new-in-this-fork) below.

## About ##

PRADS stands for `Passive Real-time Asset Detection System`. PRADS passively
listens to network traffic and gathers information about hosts and services
sending traffic. One potential use of this data is to map out your network
without performing an active scan (no packets are ever sent), allowing you to
enumerate active hosts and services. It can also be used together with your
favorite IDS/IPS setup for "event to application" correlation.

## What's New in This Fork ##

### Vectorscan/Hyperscan + PCRE2 Engine (v0.4.0)

The original PCRE-based service fingerprinting engine has been replaced with a
Vectorscan (Hyperscan) + PCRE2 hybrid:

- All service signatures are compiled into a single Vectorscan multi-pattern DFA
  per category (TCP server, TCP client, UDP server, UDP client) for fast matching
- Signatures requiring capture groups or incompatible with Vectorscan fall back
  to PCRE2 automatically
- Compiled Vectorscan databases are cached to disk and reloaded on startup,
  avoiding recompilation when signatures haven't changed

### Build Improvements

- PF_RING support is now guarded behind a `HAVE_PFRING` preprocessor flag,
  allowing clean builds without PF_RING installed
- CMake build support added alongside the existing Makefile

### Python Analysis Tools

Three new tools in `tools/` for working with prads-asset.log output (stdlib only, no pip dependencies):

- **prads-asset-report2** -- Asset report generator with text, ECS JSON, and dict JSON output. Includes an OS inference engine combining TCP fingerprint voting with service banner and User-Agent analysis.
- **prads2snort2** -- IDS host attribute generator for Snort XML, Suricata YAML (host-os-policy, defrag, libhtp personalities), and ECS JSON.
- **prads_utils.py** -- Shared library for log parsing, OS inference, policy mapping, and ECS serialization.
- **nmap2prads** -- Signature converter for generating PRADS passive service signatures from nmap-service-probes with Vectorscan/PCRE2 optimization.

See [tools/README.md](tools/README.md) for full documentation and examples.

### Patches

The `patches/` directory contains the Vectorscan + PCRE2 migration patches for
reference only. The code in this fork already has these changes applied -- you
do **not** need to apply the patches.

## Disclaimer ##

This was developed as part of an autodidactic journey taken with Anthropic's excellent Claude (code) prompted to instruct me.

## As is! ##

This program is provided 'as is'. We take no responsibility for anything :)

## License ##

GPL v2 or later. See [LICENSE](LICENSE).

## Install ##

See [doc/INSTALL](doc/INSTALL)

## Usage ##

There are several ways to use PRADS.
PRADS has many commandline options, see the `prads(1)` man page.

## Example ##

`prads -i eth0 -l prads.log`

If you run the prads service, the assets it sees will be dumped into
`/var/log/prads.log` and look like this:

```text
10.43.2.181,0,54354,6,SYN,[65535:64:1:64:M1460,N,W2,N,N,T,S,E,E:P:MacOS:iPhone OS 3.1.3 (UC):link:ethernet/modem:uptime:1574hrs],0,1300882012
10.43.2.181,0,0,0,ARP (Apple),C8:BC:C8:48:65:CA,0,1300882017
```

This information can be further processed, inserted into an SQL database etc.

The general format of this data is:

```text
asset,vlan,port,proto,service,[service-info],distance,discovered

... where ...

asset        = The ip address of the asset.
vlan         = The virtual lan tag of the asset.
port         = The port number of the detected service.
proto        = The protocol number of the matching fingerprint.
service      = The "Service" detected, like: TCP-SERVICE, UDP-SERVICE, SYN, SYNACK,MAC,.....
service-info = The fingerprint that the match was done on, with info.
distance     = Distance based on guessed initial TTL (service = SYN/SYNACK)
discovered   = The timestamp when the data was collected
```

Let it sniff your network for a while and you will be able to do anomaly
detection.

## SNORT (snort.org) ##

The prads2snort script may be used to convert the prads log into a
hosts_attribute.xml file that can be used by snort to decide fragmentation
policies, for better event detection.
http://snort.org/docs/snort_manual/node189.html

## Sguil (sguil.net) ##

You can feed events from PRADS straight into sguil replacing pads by using
the sguil pads agent. PRADS supports the -f fifo argument and the 'fifo:
/path/to/fifo' configuration option to feed events into a FIFO.

## SQL database, WebGUI etc. ##

This is on the agenda. There will be a webgui to the database, for easy
browsing of your network.
