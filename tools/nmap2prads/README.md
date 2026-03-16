# nmap2prads

Convert nmap active probe response patterns to PRADS passive fingerprint signatures, with Hyperscan/PCRE2 optimization.

## Overview

`nmap2prads.py` reads an `nmap-service-probes` file and converts its `match` directives into the comma-delimited signature format consumed by PRADS (Passive Real-time Asset Detection System). The tool is designed for a modified PRADS build that uses **Hyperscan** as its primary regex engine with **PCRE2** as a fallback. All output is tuned for safe, high-performance passive fingerprinting on critical infrastructure networks (healthcare, government).

The converter runs as a multi-stage pipeline. Each stage is optional and controlled by command-line flags, so you can do a plain conversion or apply the full optimization chain in a single invocation.

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## Quick Start

Basic conversion, splitting output by protocol:

```bash
./nmap2prads.py nmap-service-probes -o ./output/
```

This produces `tcp-service.sig` and `udp-service.sig` in `./output/`.

Production-optimized conversion with full DFA cost reduction:

```bash
./nmap2prads.py nmap-service-probes -o ./output/ \
    --passive-probes passive-probes.conf \
    --dedup \
    --merge-versions \
    --max-per-product 3 \
    --bound-dotstar 2048 \
    --replace-header-skip 2048 \
    --max-dfa-cost 10000 \
    --tag-backrefs \
    --priority-sort priority.conf \
    --emit-prefixes output/prefixes.txt
```

## Pipeline Architecture

The converter processes signatures through an ordered pipeline. Each stage feeds the next, operating on structured `NmapMatch` objects rather than text, so filtering, transformation, and sorting all compose cleanly.

```
nmap-service-probes
        │
        ▼
┌──────────────────┐
│  1. Parse         │  Read match lines, track Probe protocol/name context.
│                   │  Skip softmatch lines. Reject malformed lines to stderr.
└───────┬──────────┘
        ▼
┌──────────────────┐
│  2. Filter        │  --include-services / --exclude-services / --max-length
│                   │  --passive-probes
│                   │  Drop signatures by service name, probe relevance,
│                   │  or regex length.
└───────┬──────────┘
        ▼
┌──────────────────┐
│  3. Deduplicate   │  --dedup
│  & Merge          │  --merge-versions / --max-per-product N
│                   │  Remove exact duplicates, collapse version-pinned
│                   │  variants, cap patterns per (service, product).
└───────┬──────────┘
        ▼
┌──────────────────┐
│  4. Transform     │  --bound-dotstar N / --replace-header-skip N
│  & Cost Filter    │  --max-dfa-cost N
│                   │  Bound quantifiers, replace NFA-forcing constructs,
│                   │  drop patterns exceeding DFA cost threshold.
└───────┬──────────┘
        ▼
┌──────────────────┐
│  5. Sort          │  --priority-sort FILE
│                   │  Order by service priority, then by per-pattern
│                   │  specificity (version-extracting before generic).
└───────┬──────────┘
        ▼
┌──────────────────┐
│  6. Convert       │  Build PRADS output lines. Embed inline regex flags.
│                   │  Pack OS/host/device/CPE into info field. Sanitize
│                   │  $SUBST macros and field commas.
└───────┬──────────┘
        ▼
┌──────────────────┐
│  7. Write         │  Split by TCP/UDP (or --combined). Annotate with
│                   │  probe context and PCRE2_ONLY tags. Emit literal
│                   │  prefix file for Hyperscan prefilter compilation.
└──────────────────┘
```

## Format Mapping

### Input: nmap match directive

```
match <service> m<delim><regex><delim><flags> p/<product>/ v/<version>/ i/<info>/ o/<os>/ h/<host>/ d/<device>/ cpe:/<cpe>/
```

The regex delimiter can be `|`, `=`, or `%`. Flags are `s` (DOTALL) and/or `i` (case-insensitive). All metadata fields after the regex are optional and can use either `/` or `|` as their own delimiter.

### Output: PRADS signature

```
<service>,v/<product>/<version>/<info>/,<regex>
```

The three fields are delimited by the first two commas. The regex occupies the entire remainder of the line (commas within the regex are safe).

Regex flags are embedded as inline prefixes (`(?s)`, `(?i)`, `(?si)`) at the start of the regex for engine-agnostic compatibility — both Hyperscan and PCRE2 handle these natively.

Extra nmap metadata is packed into the info field:

```
v/OpenSSH/$1/protocol $2 os:Linux host:$3 cpe:a:openbsd:openssh:$1//
```

## Command Reference

### Input/Output

| Flag | Description |
|------|-------------|
| `input` | Path to `nmap-service-probes` file (positional, required) |
| `-o`, `--output-dir` | Output directory (default: current directory) |
| `--combined` | Write a single `service.sig` instead of splitting TCP/UDP |
| `--tcp-filename` | Override TCP output filename (default: `tcp-service.sig`) |
| `--udp-filename` | Override UDP output filename (default: `udp-service.sig`) |

### Filtering

| Flag | Description |
|------|-------------|
| `--include-services FILE` | Only convert services listed in FILE. Takes precedence over `--exclude-services`. |
| `--exclude-services FILE` | Skip services listed in FILE. |
| `--max-length N` | Skip patterns whose regex exceeds N characters. Skipped patterns are logged to stderr. |
| `--passive-probes FILE` | Keep only signatures from probes listed in FILE. Drops patterns from active-only probes whose responses would not appear in passive network captures. See `passive-probes.conf` for the default list. |

Service and probe list files are newline-delimited, one name per line. Lines starting with `#` are comments. Names are case-sensitive (matching nmap conventions).

### Optimization

| Flag | Description |
|------|-------------|
| `--dedup` | Remove exact regex+flags duplicates, keeping the first occurrence. |
| `--merge-versions` | Merge patterns within the same (service, product) group that differ only in version-pinned literals (e.g., source line numbers, version strings). Keeps one representative with generalized regex. Most effective on services like PostgreSQL where nmap uses source code line numbers for version fingerprinting. |
| `--max-per-product N` | Keep at most N patterns per (service, product) group, ranked by specificity score. Patterns that extract versions and have more literal anchoring are kept; generic fallbacks are dropped first. Recommended value: `3`. |
| `--bound-dotstar N` | In patterns that use `(?s)` (DOTALL), replace `.*` with `.{0,N}` and `.+` with `.{1,N}`. Only modifies patterns outside character classes and skips already-bounded quantifiers. Recommended value: `2048`. |
| `--replace-header-skip N` | Replace the HTTP header-skip construct `(?:[^\r\n]*\r\n(?!\r\n))*?` with `.{0,N}`. This construct uses a negative lookahead repetition that forces NFA evaluation in Hyperscan, causing disproportionate compile cost. The replacement is semantically broader but DFA-friendly. Recommended value: `2048`. |
| `--max-dfa-cost N` | Drop patterns whose estimated DFA compilation cost exceeds N. The cost heuristic scores `.{0,K}` as K, unbounded `.*` as 5000, negative lookahead repetitions as 3000, plus pattern length and alternation branch counts. Patterns above the threshold typically contain multiple wide bounded repeats or many `.*` and dominate Hyperscan compile time while representing only a small percentage of patterns. Recommended value: `10000`. |
| `--priority-sort FILE` | Reorder output by service priority. FILE lists service names highest-priority-first. Within each service group, patterns are sorted by a specificity heuristic (version-extracting patterns before generic fallbacks, penalizing `.*`). Services not listed in FILE appear after all listed services in their original nmap order. |

### Annotation

| Flag | Description |
|------|-------------|
| `--tag-backrefs` | Add `# PCRE2_ONLY` comment above patterns containing backreferences (`\1`–`\9`), which Hyperscan cannot compile. Allows the PRADS loader to route these directly to PCRE2. |
| `--emit-probe-context` | Add `# probe:<PROTO>:<NAME>` comment above each signature identifying the nmap Probe type that elicits the matched response (e.g., `probe:TCP:GetRequest`). |
| `--emit-prefixes FILE` | Extract the longest literal byte prefix from each pattern and write to FILE in tab-delimited format for Hyperscan prefilter compilation. |

### Validation

| Flag | Description |
|------|-------------|
| `--validate` | Test each output regex against Python's `re.compile()`. Failures are reported as warnings only — Hyperscan and PCRE2 support constructs that Python's `re` does not. |
| `--dry-run` | Run the full pipeline but do not write any output files. Useful with `--validate` to preview conversion results. |

## Use Cases

### 1. Basic Conversion

Convert all match lines, splitting TCP and UDP into separate files:

```bash
./nmap2prads.py nmap-service-probes -o ./sigs/
```

**Output:** `sigs/tcp-service.sig` (11,273 signatures), `sigs/udp-service.sig` (323 signatures).

### 2. Production-Optimized for Hyperscan

Apply the full optimization pipeline — passive probe filtering, deduplication, version merging, per-product capping, DFA cost reduction, and priority sorting:

```bash
./nmap2prads.py nmap-service-probes -o ./sigs/ \
    --passive-probes passive-probes.conf \
    --dedup \
    --merge-versions \
    --max-per-product 3 \
    --bound-dotstar 2048 \
    --replace-header-skip 2048 \
    --max-dfa-cost 10000 \
    --tag-backrefs \
    --priority-sort priority.conf \
    --emit-prefixes sigs/prefixes.txt
```

**Effect (from 11,723 nmap match lines):**
- 596 patterns from active-only probes removed
- 48 exact duplicates removed
- 229 version-pinned variants merged (e.g., PostgreSQL 221 → 4)
- 1,443 excess per-product patterns capped
- 1,085 DOTALL `.*` patterns bounded to `.{0,2048}`
- 516 NFA-forcing header-skip constructs replaced
- 333 extreme-cost patterns dropped (DFA cost > 10,000)
- 14 backref patterns annotated with `# PCRE2_ONLY`
- **Final output: ~8,950 signatures** (23% reduction with dramatically lower per-pattern DFA cost)

### 3. Lean Deployment (Critical Services Only)

For sensors monitoring a known, limited set of services:

```bash
cat > critical.conf << 'EOF'
http
ssh
smtp
ftp
telnet
mysql
postgresql
microsoft-ds
vnc
ldap
backdoor
EOF

./nmap2prads.py nmap-service-probes -o ./sigs/ \
    --include-services critical.conf \
    --dedup
```

**Effect:** Produces ~7,700 signatures covering only the listed services. Significantly reduces DFA compilation time and memory.

### 4. Exclude Irrelevant Services

Remove game servers and other services unlikely to appear on hospital/gov networks:

```bash
./nmap2prads.py nmap-service-probes -o ./sigs/ \
    --exclude-services exclude_gameservers.conf \
    --dedup
```

### 5. Cap Regex Complexity

Control DFA compilation cost through multiple levers:

```bash
./nmap2prads.py nmap-service-probes -o ./sigs/ \
    --max-length 512 \
    --bound-dotstar 2048 \
    --replace-header-skip 2048 \
    --max-dfa-cost 10000
```

Patterns exceeding 512 characters are skipped outright. Remaining patterns get bounded quantifiers, header-skip construct replacement, and a final cost filter that drops the ~2.4% of patterns whose DFA cost still exceeds the threshold after transforms. Dropped patterns are logged to stderr with their cost scores.

### 6. Validation Dry-Run

Preview the full pipeline without writing files:

```bash
./nmap2prads.py nmap-service-probes \
    --dedup --bound-dotstar 2048 \
    --validate --dry-run 2>&1 | less
```

The summary report on stderr shows match counts, skip reasons, and any regex validation warnings.

### 7. Annotated Output for Debugging

Generate fully-annotated output showing probe context and engine routing:

```bash
./nmap2prads.py nmap-service-probes -o ./debug/ \
    --emit-probe-context \
    --tag-backrefs
```

**Sample output:**

```
# probe:TCP:NULL
ssh,v/OpenSSH/$2/protocol $1 os:Linux cpe:a:openbsd:openssh:$2//,^SSH-([\d.]+)-OpenSSH[_-](\d[\w._-]+)
# probe:TCP:GetRequest
http,v/Apache httpd/$1//,(?s)^HTTP/1\.[01] \d\d\d .{0,2048}Server: Apache/([\d.]+)
# probe:TCP:NULL PCRE2_ONLY
bindshell,v/Bash shell//**BACKDOOR** host:$2 cpe:a:gnu:bash//,^(root@([^:]+):[^#$]+)# ...
```

### 8. Combined Single-File Output

Write all protocols to one file (useful for simplified loader configurations):

```bash
./nmap2prads.py nmap-service-probes -o ./sigs/ --combined
```

**Output:** `sigs/service.sig` containing both TCP and UDP signatures.

## Output Format Details

### Signature Lines

```
<service>,v/<product>/<version>/<info>/,(?<flags>)<regex>
```

Example:

```
ssh,v/OpenSSH/$2/protocol $1 os:Linux host:$3 cpe:a:openbsd:openssh:$2//,^SSH-([\d.]+)-OpenSSH[_-](\d[\w._-]+) .* ([\w._-]+)\r?\n
```

The version template uses nmap-style `$N` capture group references. Your PRADS matcher substitutes these with the corresponding regex match groups at runtime.

### Info Field Packing

When nmap metadata includes OS, hostname, device type, or CPE data, these are packed into the info field with prefixed keys:

| Prefix | Source nmap field | Example |
|--------|------------------|---------|
| `os:` | `o/Linux/` | `os:Linux` |
| `host:` | `h/$1/` | `host:$1` |
| `device:` | `d/webcam/` | `device:webcam` |
| `cpe:` | `cpe:/a:apache:httpd:$1/` | `cpe:a:apache:httpd:$1/` |

### Annotation Comments

Comments appear on the line immediately above the signature they annotate:

```
# probe:TCP:GetRequest PCRE2_ONLY
```

| Annotation | Meaning |
|------------|---------|
| `probe:<PROTO>:<NAME>` | The nmap Probe type whose stimulus elicits this server response |
| `PCRE2_ONLY` | Pattern contains backreferences; must be compiled with PCRE2, not Hyperscan |

### Literal Prefix File

The `--emit-prefixes` output is tab-delimited:

```
# Literal prefixes for Hyperscan prefilter compilation
# Format: pattern_id<TAB>prefix_len<TAB>prefix<TAB>service
0	10	HTTP/1\.1 	http
1	21	HTTP/1\.0  200 OK\r\n	http
2	33	g\0\0\0\x1b\0\0\0\0\0\0\0acarsd\t	acarsd
```

`pattern_id` is the 0-based index matching the line order in the corresponding `.sig` file. This allows your PRADS loader to build a Hyperscan literal database where each prefix maps back to the full pattern for confirmation matching.

## Sanitization

The converter automatically handles two format-safety issues discovered during testing against the full nmap-service-probes corpus:

### $SUBST Macros

Nmap's `$SUBST(N,"from","to")` macros perform post-match string substitution (e.g., replacing underscores with dots in version strings). These macros contain commas and quotes that break the PRADS comma-delimited format. Since PRADS has no `$SUBST` engine, the converter replaces them with bare capture group references:

```
$SUBST(1,"_",".")  →  $1
$SUBST(6,"_",".")  →  $6
```

### Commas in Metadata Fields

Some nmap product names contain literal commas (e.g., `QNAP TS-239, or TS-509 NAS`). Since PRADS splits on the first two commas to find the three fields, a comma in the product or info field would corrupt the regex. The converter replaces commas with semicolons in metadata fields:

```
QNAP TS-239, or TS-509  →  QNAP TS-239; or TS-509
```

## Configuration Files

### Priority File (`priority.conf`)

One service name per line, highest priority first. Comments with `#` and blank lines are allowed.

```
# Tier 1: High-traffic services
http
ssh
smtp
ftp
telnet
# Tier 2: Security-relevant
microsoft-ds
vnc
ldap
backdoor
```

Services not listed appear after all listed services in their original nmap file order.

### Passive Probe List (`passive-probes.conf`)

One nmap probe name per line. Only signatures from these probes are kept when `--passive-probes` is used. The default `passive-probes.conf` includes probes whose responses appear in natural (passive) traffic:

```
# TCP probes — responses commonly seen in passive monitoring
NULL
GetRequest
GenericLines
SSLSessionReq
TLSSessionReq
SSLv23SessionReq
SMBProgNeg
RTSPRequest
# TCP probes — responses sometimes seen depending on environment
HTTPOptions
FourOhFourRequest
Help
SIPOptions
TerminalServer
...
# UDP probes
DNSStatusRequest
SNMPv1public
NTPRequest
...
```

Probes not listed (e.g., `X11Probe`, `RPCCheck`, `Socks4`) require specific active payloads that would not naturally appear in passive captures. Their response patterns would never match and only add to DFA compile cost.

### Service List Files (`include.conf` / `exclude.conf`)

Same format as the priority file — one service name per line.

```
# Game servers to exclude from hospital deployments
quake
minecraft
teamspeak
ventrilo
```

## Summary Report

Every run prints a summary to stderr:

```
============================================================
nmap2prads conversion summary
============================================================
  Match lines processed:     11723
  Softmatch lines skipped:   194
  Successfully converted:    8947
    TCP signatures:          8778
    UDP signatures:          169
  Skipped (no product):      127
  Skipped (parse errors):    0
  Skipped (probe filter):    596
  Deduplicated:              48
  Merged (versions):         229
  Capped (per-product):      1443
  Dropped (DFA cost):        333
  Inline flags embedded:     2125
  Metadata packed into info: 6634
  Dot-star patterns bounded: 1085
  Header-skip replaced:      516
  Backref patterns tagged:   14
------------------------------------------------------------
  Output: ./output/tcp-service.sig
  Output: ./output/udp-service.sig
============================================================
```

Parse errors and skipped patterns are always reported. The first 10 errors are shown inline; a count indicates when more exist.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | One or more match lines could not be parsed (details on stderr) |

## Safety Considerations

This tool produces signatures deployed on IDS/IPS sensors protecting hospitals and government networks. The following safety properties are maintained:

- **No silent data loss.** Every skipped line is accounted for in the summary report with a specific reason (no product, parse error, service filter, probe filter, max length, DFA cost, dedup, merge, cap). The sum of converted + skipped always equals total match lines processed.
- **Malformed input is rejected, not guessed.** Parse errors halt processing of that line and log the error with line number and cause. The remaining lines continue processing.
- **Regex transformations are conservative.** Dot-star bounding only applies to DOTALL patterns (where the risk is highest) and only replaces bare `.*`/`.+` outside character classes. Already-bounded quantifiers are left untouched. Header-skip replacement targets a specific NFA-forcing construct that has no DFA-compatible equivalent.
- **DFA cost filtering logs every drop.** Patterns dropped by `--max-dfa-cost` are logged to stderr with their cost score and service name, so operators can verify that no critical detection capability was lost.
- **Version merging preserves detection.** Merged patterns use generalized regexes (`[\d.]+` instead of `2\.4`) that match a broader range of versions. Service and product identification remains accurate; only version precision is relaxed.
- **Per-product capping keeps the best patterns.** When `--max-per-product` drops excess patterns, it retains those with the highest specificity score (anchored patterns with version extraction over generic fallbacks).
- **Backref patterns are flagged, not dropped.** Patterns that Hyperscan cannot compile are annotated for PCRE2 routing rather than silently excluded.
- **Validation is advisory.** The `--validate` flag reports Python `re` module warnings without blocking output, since Hyperscan and PCRE2 support constructs that Python cannot.

## License

GPL

## Authors

Panoptic Engineering
