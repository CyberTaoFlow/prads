# PRADS Signature Optimization for Hyperscan/PCRE2

## Executive Summary

Converting the full nmap-service-probes file produces **11,596 signatures**. The remaining patterns can be reduced through **deduplication and service relevance filtering**, and significantly optimized for Hyperscan DFA compilation through **priority sorting**, **pattern consolidation**, and **Hyperscan-aware regex restructuring**.

---

## 1. Priority Sorting

PRADS uses first-match-wins semantics. The order signatures appear in the file directly affects both correctness and performance.

### Why Order Matters for Hyperscan

Hyperscan compiles all patterns into a single automaton and reports *all* matches simultaneously. However, PRADS processes matches sequentially and stops after the first hit. This means:

- Patterns that match frequently should be **early** in the file so the post-match processing loop exits quickly.
- More *specific* patterns for a given service should appear **before** more generic fallbacks for the same service, otherwise the generic pattern swallows everything and you lose version/detail extraction.

### Recommended Sort Strategy

A three-tier ordering:

**Tier 1 — High-traffic services (first in file)**

These services dominate real network traffic. Matching them quickly reduces average per-packet processing time.

| Service | Signature Count | Why Tier 1 |
|---------|----------------|------------|
| http | 4,346 | Dominates traffic volume by far |
| ssh | 235 | Present on nearly every host |
| smtp | 473 | High volume on mail-heavy networks |
| ftp | 772 | Still common in healthcare/gov |
| telnet | 1,095 | Common on embedded/network devices |
| pop3/imap | 430 | Mail infrastructure |
| mysql/postgresql | 234 | Database traffic on internal nets |
| microsoft-ds | 32 | SMB — pervasive on Windows networks |

**Tier 2 — Medium-traffic and security-relevant services**

| Service | Why Tier 2 |
|---------|------------|
| vnc, vnc-http | Remote access — security relevant |
| rdp (ms-wbt-server) | Remote access — security relevant |
| ldap | Active Directory infrastructure |
| backdoor | Threat detection (31 signatures) |
| sip/sip-proxy | VoIP infrastructure |
| upnp | Network device discovery |

**Tier 3 — Long tail (everything else)**

The remaining ~1,100+ unique services, ordered by signature specificity: exact-match patterns before wildcard patterns within each service group.

### Within-Service Ordering

Within each service group, order by specificity:

1. **Exact literal matches** — patterns that are entirely or mostly fixed bytes
2. **Version-extracting patterns** — patterns with capture groups that pull specific version info
3. **Generic/fallback patterns** — broad patterns with `.*` or minimal differentiation

Example for SSH:
```
# Specific vendor patterns first
ssh,v/Cisco SSH/$1//,^SSH-([.\d]+)-Cisco-(\d[\w._-]+)
ssh,v/OpenSSH/$2/protocol $1/,^SSH-([\d.]+)-OpenSSH[_-](\d[\w._-]+)
# Generic fallback last
ssh,v/SSH/$1//,^SSH-([\S]+)\n
```

### Implementation Approach

Add a `--priority-sort` flag to `nmap2prads.py` that accepts a service priority file:

```
# priority.conf — one service per line, highest priority first
# Lines starting with # are comments
http
ssh
smtp
ftp
telnet
pop3
imap
mysql
postgresql
microsoft-ds
vnc
backdoor
```

The converter would:
1. Group output signatures by service name
2. Sort groups according to the priority file (unlisted services go to the end)
3. Within each group, sort by specificity: literal-heavy patterns before wildcard patterns

---

## 2. Reducing Pattern Count

The current 11,596 patterns can be substantially reduced without meaningful detection loss.

### 2a. Probe Context as Metadata (Not a Filter)

Nmap match lines describe **server responses** to specific probe stimuli. In passive mode PRADS doesn't send the probes, but real clients on the monitored network do. A browser's `GET / HTTP/1.0\r\n\r\n` is the same stimulus as nmap's `GetRequest` probe; a Windows client's SMB negotiation is the same stimulus as `SMBProgNeg`; an SMTP client's `EHLO` is the same stimulus as the `Hello` probe. The server's response — which is what the match pattern describes — is visible on the wire in both cases.

Therefore nearly all probe types are passive-viable in practice:

| Probe | Match Count | Real-World Client Stimulus |
|-------|-------------|---------------------------|
| TCP:NULL | 3,959 | Banners sent immediately on connection |
| TCP:GetRequest | 4,808 | HTTP clients (browsers, APIs, health checks) |
| TCP:GenericLines | 687 | Any client sending CRLF to a text protocol |
| TCP:SMBProgNeg | 323 | Windows SMB clients (pervasive on enterprise/hospital nets) |
| TCP:Help / TCP:Hello | 326 | Mail clients (EHLO), protocol probers, monitoring tools |
| TCP:SIPOptions | 156 | VoIP phones, SIP registrars, keepalive |
| TCP:SSLSessionReq | 95 | Any TLS client handshake |
| TCP:LDAPBindReq | 21 | AD-joined machines binding to domain controllers |
| TCP:RPCCheck | 52 | RPC portmapper queries from Unix/NFS clients |
| TCP:DNSVersionBindReqTCP | 86 | DNS monitoring tools, recursive resolvers |
| TCP:X11Probe | 67 | X11 forwarding (SSH -X) |
| All others | ~900 | Various protocol-specific client interactions |

**The probe context should not be used to exclude patterns.** Doing so would cut real detection capability — the opposite of what a critical-infrastructure IDS deployment needs.

However, the probe context remains useful as **metadata** for priority sorting. Probes whose stimuli occur more frequently in real traffic (GetRequest, NULL, SMBProgNeg) should have their match patterns sorted earlier in the output file, since those patterns will fire more often and benefit most from early placement in the first-match-wins evaluation order. Rare-stimulus probes (X11Probe, beast2, insteonPLM) can be sorted toward the end.

The converter tracks probe context via `--emit-probe-context` and writes it as a comment, which can feed the priority sort.

### 2b. Duplicate Elimination

Analysis found **76 regexes that appear more than once** (153 total lines). These are exact regex duplicates with different service names or metadata. Some are legitimate (same banner, different service classification), but many are redundant.

Recommendation: Deduplicate by regex, keeping the first occurrence (which should be the higher-priority service after sorting).

**Estimated reduction: ~75 signatures.**

### 2c. Service Relevance Filtering

Some nmap services are not useful for passive asset detection in your deployment context:

- **Game servers** (quake, minecraft, teamspeak, etc.) — unlikely in hospital/gov networks
- **Backdoor signatures** (31 entries) — *keep these*, they're security-relevant
- **Obscure/discontinued services** — entries for products with single-digit deployment counts globally

Provide a `--exclude-services` option with a deny list:

```
# exclude.conf
quake
minecraft
teamspeak
ventrilo
murmur
freelancer
```

**Estimated reduction: 200–400 signatures** depending on how aggressively you prune.

### 2d. Subsumption Analysis

Some patterns are strict subsets of others. For example:

```
bitcoin,v/.../0.2.0/,(?s)^<long_fixed_prefix>...\0$
bitcoin,v/.../0.2.0/,(?s)^<long_fixed_prefix>...\0
```

The second pattern (without `$`) matches everything the first does plus more. If they map to the same service/version, the more specific pattern is redundant.

This requires careful analysis since version extraction may differ, but automated subsumption detection could eliminate another **100–200 patterns**.

### Combined Reduction Estimate

| Technique | Estimated Reduction |
|-----------|-------------------|
| Duplicate elimination | ~75 |
| Service relevance filtering | 200–400 |
| Subsumption analysis | 100–200 |
| **Total** | **~375–675** |

**Resulting pattern count: ~10,900–11,200 (from 11,596)**

The pattern count reduction is modest because all probe contexts are passive-viable. The real performance gains come from the DFA compilation optimizations in §3 below — priority sorting, dot-star bounding, literal prefix prefiltering, and compilation grouping — which dramatically reduce match latency without discarding detection capability.

---

## 3. Optimizing for DFA Compilation

Hyperscan compiles regex patterns into a DFA (or hybrid DFA/NFA) automaton. Certain regex constructs cause state explosion that increases compilation time, memory usage, and sometimes match latency.

### Current Risk Profile

| Risk Factor | Count | Severity |
|-------------|-------|----------|
| `.*` with DOTALL flag | 1,782 | **High** — each `.*` under `(?s)` matches any byte including `\n`, creating massive state fan-out |
| Nested quantifiers | 942 | **Medium** — can cause exponential state growth |
| Backreferences (`\1`, `\2`) | 16 | **Critical for HS** — Hyperscan cannot compile these at all; must fall back to PCRE2 |
| Unanchored patterns | 285 | **Medium** — HS must search at every byte offset |
| Wide alternation (>5 branches) | 12 | **Low** — but each branch multiplies states |

### 3a. Anchoring

**97.5% of patterns are already anchored** with `^`. The remaining 285 unanchored patterns force Hyperscan to attempt matching at every byte position in the stream.

Recommendation: Audit the 285 unanchored patterns. Many can likely be anchored to `^` without changing correctness (if the pattern describes a banner that always starts at byte 0 of a connection). Those that genuinely need mid-stream matching should be flagged with `HS_FLAG_SOM_LEFTMOST` at compile time.

### 3b. DOTALL + Dot-Star Optimization

This is the **biggest DFA optimization opportunity**. 1,782 patterns use `.*` under `(?s)`, which means "match any byte, zero or more times." This creates massive NFA state sets.

**Strategy 1: Replace `.*` with `[^\n]*` where DOTALL isn't semantically needed.**

Many nmap patterns use `(?s)` because the nmap format requires `s` for multi-line matching, but the actual data they match is single-line (binary protocol headers). For these, the `(?s)` flag is inherited but unnecessary. Automated analysis:

- If the pattern contains `\r\n` literals (text protocol), `(?s)` is probably unnecessary
- If the pattern is anchored and contains only fixed hex bytes with `.*` bridging fixed segments, the `.*` can be replaced with `.{0,N}` with a reasonable bound

**Strategy 2: Bound the dot-star with `.{0,N}` maximum.**

Replace `.*` with `.{0,256}` or similar. Hyperscan compiles bounded repeats much more efficiently than unbounded ones. The bound should be set to the maximum realistic gap between the fixed segments — for most protocol banners, 256 or 512 bytes is generous.

Before:
```
(?s)^HTTP/1\.0 200.*Server: Apache/([\d.]+)
```

After:
```
^HTTP/1\.0 200[^\r\n]*\r\n(?:[^\r\n]*\r\n){0,30}Server: Apache/([\d.]+)
```

Or the simpler bounded form:
```
(?s)^HTTP/1\.0 200.{0,2048}Server: Apache/([\d.]+)
```

**Strategy 3: Multi-pattern decomposition.**

For patterns like `^PREFIX.*MIDDLE.*SUFFIX`, decompose into:

1. A Hyperscan literal match on `PREFIX` (extremely fast)
2. A PCRE2 confirmation match on the full pattern (only runs on the small fraction of streams that hit the prefix)

This is the **prefilter** approach and it's what Hyperscan is architecturally designed for. Your modified PRADS would:

1. Compile all literal prefixes into a Hyperscan multi-pattern database
2. On a prefix match, run the full PCRE2 pattern against the stream

This trades a tiny amount of latency on true matches for massive savings on non-matches.

### 3c. Backreference Isolation

16 patterns contain backreferences (`\1`, `\2`, etc.) which Hyperscan fundamentally cannot support. These **must** fall back to PCRE2.

Recommendation: Flag these at conversion time with a comment or a separate output section so your PRADS loader knows to route them directly to PCRE2 and skip HS compilation entirely. Trying and failing to compile them with HS wastes startup time.

### 3d. Compilation Grouping

Hyperscan performs better when patterns are compiled in groups with similar characteristics. Recommendation for your PRADS loader:

| Group | Compilation Strategy | Expected Count |
|-------|---------------------|----------------|
| Pure literals | `HS_FLAG_LITERAL` mode — bypasses regex engine entirely | ~2,962 |
| Anchored, no `.*` | Standard DFA compilation with `HS_FLAG_SINGLEMATCH` | ~5,500 |
| Anchored with bounded `.*` | DFA with `HS_FLAG_SINGLEMATCH` after dot-star bounding | ~1,700 |
| Unanchored | `HS_FLAG_SOM_LEFTMOST` for stream scanning | ~285 |
| Backreference patterns | Skip HS, compile with PCRE2 only | 16 |

Using `HS_FLAG_SINGLEMATCH` is critical — it tells Hyperscan to stop after the first match per pattern, which avoids redundant match reporting.

### 3e. Literal Prefix Extraction for Prefiltering

Analysis shows **8,947 patterns (77%) have 8+ byte literal prefixes** and another **2,141 (18%) have 3–7 byte prefixes**. This is excellent for Hyperscan's prefilter mode.

Architecture:

```
Packet arrives
    │
    ▼
┌─────────────────────────┐
│ Hyperscan Literal Match  │  ← Scans for all 11K+ literal prefixes simultaneously
│ (streaming or block mode)│     at wire speed. Vast majority of packets: zero matches.
└─────────┬───────────────┘
          │ match on prefix P
          ▼
┌─────────────────────────┐
│ PCRE2 Confirmation       │  ← Only runs on the ~1-5% of packets that hit a prefix.
│ (full pattern for P)     │     Handles captures, backrefs, complex patterns.
└─────────────────────────┘
```

This two-stage approach is how Suricata's own MPM (Multi-Pattern Matcher) works with Hyperscan, and it's the reason Hyperscan exists. Applying it to PRADS would give you near-wire-speed passive fingerprinting.

### 3f. Pattern Complexity Budget

For production deployments on hospital/gov networks, establish a maximum per-pattern complexity budget:

- **Max regex length**: 512 characters (flag longer patterns for review)
- **Max unbounded quantifiers**: 2 per pattern
- **Max alternation branches**: 8 per group
- **Max total DFA states**: Set `HS_FLAG_PREFILTER` on any pattern that exceeds Hyperscan's internal limit (the compile call will return `HS_COMPILER_ERROR` which you can catch and route to PCRE2)

---

## Implementation Roadmap

### Phase 1: Converter Enhancements (nmap2prads.py)

Add these flags to the existing converter:

| Flag | Purpose |
|------|---------|
| `--exclude-services FILE` | Service deny list |
| `--include-services FILE` | Service allow list (for lean deployments) |
| `--priority-sort FILE` | Service priority ordering |
| `--dedup` | Eliminate exact regex duplicates |
| `--bound-dotstar N` | Replace `.*` with `.{0,N}` |
| `--strip-dotall` | Remove `(?s)` from patterns where it's provably unnecessary |
| `--tag-backrefs` | Add `# PCRE2_ONLY` comment to backref patterns |
| `--max-length N` | Skip or flag patterns exceeding N characters |
| `--emit-prefixes FILE` | Extract literal prefixes to a separate file for prefilter compilation |
| `--emit-probe-context` | Write probe type as comment above each signature (useful for priority sort tuning) |

### Phase 2: PRADS Loader Changes

Modify the signature loader to:

1. Recognize `# PCRE2_ONLY` tagged patterns and skip HS compilation
2. Compile patterns in the 5 groups listed in §3d
3. Implement two-stage prefilter → confirm matching
4. Report compilation statistics at startup (pattern count per group, total DFA size, compilation time)

### Phase 3: Operational Tooling

- Signature coverage report: given a pcap, which signatures matched? Which never matched?
- DFA size monitoring: track compilation memory across signature updates
- Performance regression tests: measure packets/sec before and after signature updates
