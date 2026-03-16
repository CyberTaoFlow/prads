#!/usr/bin/env python3
"""
nmap2prads.py — Convert nmap-service-probes match lines to PRADS passive signature format.

Converts nmap active probe response patterns (match directives) into the PRADS
passive fingerprint format used by tcp-service.sig and udp-service.sig.

Designed for use with a modified PRADS build that leverages Hyperscan (primary)
and PCRE2 (fallback) for regex matching. Regex flags are embedded as inline
flags (e.g., (?si)) for engine-agnostic compatibility.

Output format:
    <service>,v/<product>/<version>/<info>/,<regex>

Where <info> is packed with OS, hostname, device type, and CPE data from the
original nmap metadata when present.

Optimization features:
    --exclude-services FILE    Skip services listed in FILE
    --include-services FILE    Only convert services listed in FILE
    --priority-sort FILE       Sort output by service priority
    --dedup                    Eliminate exact regex duplicates
    --bound-dotstar N          Replace .* with .{0,N} for DFA-friendly compilation
    --tag-backrefs             Annotate backref patterns with # PCRE2_ONLY
    --max-length N             Skip patterns exceeding N characters
    --passive-probes FILE      Keep only sigs from passive-relevant probes
    --merge-versions           Collapse version-pinned pattern variants
    --max-per-product N        Cap patterns per (service, product) group
    --replace-header-skip N    Replace NFA-forcing header-skip with .{0,N}
    --max-dfa-cost N           Drop patterns exceeding DFA cost threshold
    --emit-prefixes FILE       Extract literal prefixes for Hyperscan prefilter
    --emit-probe-context       Annotate each signature with its nmap Probe type

Safety notes:
    - Only 'match' lines are converted; 'softmatch' lines are skipped.
    - Malformed lines are logged to stderr and skipped (never silently dropped).
    - A summary report is written to stderr on completion.
    - Use --validate to test regex compilation with the 're' module before output.
    - Use --dry-run to preview without writing files.

Author: Panoptic Engineering
License: GPL
"""

import argparse
import os
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class NmapMatch:
    """Parsed representation of a single nmap match directive."""
    line_number: int
    service: str
    regex: str
    flags: str           # raw flag chars from nmap (e.g., "si", "s", "i", "")
    product: str
    version: str
    info: str
    os: str
    hostname: str
    device_type: str
    cpe: list            # list of CPE strings
    protocol: str        # TCP or UDP (from enclosing Probe directive)
    probe_name: str      # e.g., "NULL", "GetRequest", "SMBProgNeg"
    raw_line: str        # original line for diagnostics


@dataclass
class ConversionStats:
    """Tracks conversion metrics for the summary report."""
    total_match_lines: int = 0
    total_softmatch_skipped: int = 0
    total_converted: int = 0
    total_skipped_errors: int = 0
    total_skipped_no_product: int = 0
    total_skipped_service_filter: int = 0
    total_skipped_max_length: int = 0
    total_skipped_probe_filter: int = 0
    total_deduped: int = 0
    total_merged_versions: int = 0
    total_capped_product: int = 0
    total_skipped_dfa_cost: int = 0
    header_skip_replaced: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    flags_embedded: int = 0
    info_packed: int = 0
    backrefs_tagged: int = 0
    dotstar_bounded: int = 0
    regex_validation_failures: int = 0
    errors: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Nmap match line parser
# ---------------------------------------------------------------------------

def parse_metadata_field(text: str, pos: int, key: str) -> tuple[str, int]:
    """Parse a single nmap metadata field like p/.../ or p|...|.

    Args:
        text: The full metadata string after the regex portion.
        pos: Current position in text.
        key: The expected key character (e.g., 'p', 'v', 'i').

    Returns:
        Tuple of (field_value, new_position). Returns ("", pos) if the key
        is not found at the current position.
    """
    search_patterns = [f" {key}/", f" {key}|"]
    best_idx = -1
    best_delim = None

    for pat in search_patterns:
        idx = text.find(pat, pos)
        if idx != -1 and (best_idx == -1 or idx < best_idx):
            best_idx = idx
            best_delim = pat[-1]

    if best_idx == -1:
        return "", pos

    content_start = best_idx + len(f" {key}") + 1
    close_idx = text.find(best_delim, content_start)
    if close_idx == -1:
        return text[content_start:].strip(), len(text)

    return text[content_start:close_idx], close_idx + 1


def extract_metadata(metadata_str: str) -> dict:
    """Extract all nmap metadata fields from the post-regex portion of a match line.

    Handles fields: p (product), v (version), i (info), o (os),
    h (hostname), d (device type), and cpe entries.
    """
    result = {
        "product": "",
        "version": "",
        "info": "",
        "os": "",
        "hostname": "",
        "device_type": "",
        "cpe": [],
    }

    for nmap_key, result_key in [
        ("p", "product"),
        ("v", "version"),
        ("i", "info"),
        ("o", "os"),
        ("h", "hostname"),
        ("d", "device_type"),
    ]:
        val, _ = parse_metadata_field(metadata_str, 0, nmap_key)
        if val:
            result[result_key] = val

    cpe_pattern = re.compile(r'cpe:/([^\s/]+(?:/[^\s]*)?)')
    result["cpe"] = cpe_pattern.findall(metadata_str)

    return result


def parse_match_regex(line: str, regex_start: int) -> tuple[str, str, int]:
    """Parse the m<delim><regex><delim><flags> portion of a match line.

    Returns:
        Tuple of (regex, flags, end_position).

    Raises:
        ValueError: If the regex cannot be parsed.
    """
    if regex_start >= len(line) or line[regex_start] != 'm':
        raise ValueError("Expected 'm' at regex_start")

    delim = line[regex_start + 1]
    content_start = regex_start + 2
    pos = content_start

    while pos < len(line):
        idx = line.find(delim, pos)
        if idx == -1:
            raise ValueError(
                f"No closing delimiter '{delim}' found for regex "
                f"starting at col {regex_start}"
            )

        after = idx + 1
        flags = ""
        while after < len(line) and line[after] in "si":
            flags += line[after]
            after += 1

        if after >= len(line) or line[after] == ' ':
            regex_body = line[content_start:idx]
            return regex_body, flags, after

        pos = idx + 1

    raise ValueError(
        f"No valid closing delimiter '{delim}' found for regex "
        f"starting at col {regex_start}"
    )


def parse_match_line(
    line: str, line_number: int, current_protocol: str, current_probe: str
) -> Optional[NmapMatch]:
    """Parse a single nmap 'match' directive line.

    Returns:
        NmapMatch if successfully parsed, None if the line is not a match line.

    Raises:
        ValueError: On parse failures.
    """
    stripped = line.strip()
    if not stripped.startswith("match "):
        return None

    after_match = stripped[6:]
    m_idx = after_match.find(" m")
    if m_idx == -1:
        raise ValueError("No regex field found (expected ' m<delim>')")

    service = after_match[:m_idx].strip()
    if not service:
        raise ValueError("Empty service name")

    regex_abs_start = 6 + m_idx + 1
    regex_body, flags, end_pos = parse_match_regex(stripped, regex_abs_start)

    metadata_str = stripped[end_pos:]
    meta = extract_metadata(metadata_str)

    return NmapMatch(
        line_number=line_number,
        service=service,
        regex=regex_body,
        flags=flags,
        product=meta["product"],
        version=meta["version"],
        info=meta["info"],
        os=meta["os"],
        hostname=meta["hostname"],
        device_type=meta["device_type"],
        cpe=meta["cpe"],
        protocol=current_protocol,
        probe_name=current_probe,
        raw_line=line,
    )


# ---------------------------------------------------------------------------
# Stage 1: Parse nmap file → list of NmapMatch
# ---------------------------------------------------------------------------

def parse_nmap_file(input_path: str) -> tuple[list[NmapMatch], ConversionStats]:
    """Parse an nmap-service-probes file into structured NmapMatch objects.

    This is the first pipeline stage — pure parsing, no filtering or
    transformation.

    Returns:
        Tuple of (matches, stats).
    """
    stats = ConversionStats()
    matches = []
    current_protocol = "TCP"
    current_probe = "NULL"

    with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
        for line_number, line in enumerate(fh, start=1):
            stripped = line.strip()

            if stripped.startswith("Probe "):
                parts = stripped.split()
                if len(parts) >= 3:
                    current_protocol = parts[1].upper()
                    current_probe = parts[2]
                continue

            if stripped.startswith("softmatch "):
                stats.total_softmatch_skipped += 1
                continue

            if not stripped.startswith("match "):
                continue

            stats.total_match_lines += 1

            try:
                match = parse_match_line(
                    line, line_number, current_protocol, current_probe
                )
                if match is None:
                    continue

                if not match.product:
                    stats.total_skipped_no_product += 1
                    continue

                matches.append(match)

            except ValueError as e:
                stats.total_skipped_errors += 1
                error_msg = f"line {line_number}: {e}"
                stats.errors.append(error_msg)
                print(f"WARNING: {error_msg}", file=sys.stderr)

    return matches, stats


# ---------------------------------------------------------------------------
# Stage 2: Filter
# ---------------------------------------------------------------------------

def load_service_list(filepath: str) -> set[str]:
    """Load a newline-delimited service list file.

    Lines starting with # are comments. Blank lines are skipped.
    Service names are case-sensitive to match nmap conventions.
    """
    services = set()
    with open(filepath, "r") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                services.add(line)
    return services


def filter_services(
    matches: list[NmapMatch],
    stats: ConversionStats,
    include: Optional[set[str]] = None,
    exclude: Optional[set[str]] = None,
) -> list[NmapMatch]:
    """Filter matches by service name.

    If include is set, only services in the set are kept.
    If exclude is set, services in the set are dropped.
    Include takes precedence if both are set.
    """
    result = []
    for m in matches:
        if include is not None:
            if m.service not in include:
                stats.total_skipped_service_filter += 1
                continue
        elif exclude is not None:
            if m.service in exclude:
                stats.total_skipped_service_filter += 1
                continue
        result.append(m)
    return result


def filter_max_length(
    matches: list[NmapMatch],
    stats: ConversionStats,
    max_length: int,
) -> list[NmapMatch]:
    """Drop patterns whose regex exceeds max_length characters."""
    result = []
    for m in matches:
        if len(m.regex) > max_length:
            stats.total_skipped_max_length += 1
            stats.errors.append(
                f"line {m.line_number}: regex length {len(m.regex)} exceeds "
                f"--max-length {max_length}, skipping ({m.service})"
            )
            continue
        result.append(m)
    return result


def load_probe_list(filepath: str) -> set[str]:
    """Load a probe list file. Format: one probe name per line.

    Lines starting with # are comments. Blank lines are skipped.
    """
    probes = set()
    with open(filepath, "r") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                probes.add(line)
    return probes


def filter_passive_probes(
    matches: list[NmapMatch],
    stats: ConversionStats,
    allowed_probes: set[str],
) -> list[NmapMatch]:
    """Keep only signatures from passive-relevant probes.

    Each NmapMatch carries a probe_name from the enclosing nmap Probe
    directive. Signatures from probes not in allowed_probes are dropped.
    """
    result = []
    for m in matches:
        if m.probe_name in allowed_probes:
            result.append(m)
        else:
            stats.total_skipped_probe_filter += 1
    return result


# ---------------------------------------------------------------------------
# Stage 3: Deduplicate
# ---------------------------------------------------------------------------

def deduplicate(
    matches: list[NmapMatch],
    stats: ConversionStats,
) -> list[NmapMatch]:
    """Remove exact regex duplicates, keeping the first occurrence.

    Two matches are considered duplicates if they have the same regex
    AND the same flags. Different service names or metadata are ignored
    for dedup purposes — the first-seen entry wins.
    """
    seen = set()
    result = []
    for m in matches:
        key = (m.regex, m.flags)
        if key in seen:
            stats.total_deduped += 1
            continue
        seen.add(key)
        result.append(m)
    return result


# ---------------------------------------------------------------------------
# Stage 3b: Merge version-pinned patterns
# ---------------------------------------------------------------------------

# Version-like literal: sequences of digits joined by escaped dots.
# Matches: 2\.0, 10\.0\.2, 3\.14\.1\.6
# Does NOT match bare numbers (200, 8080) or single-component versions.
_VERSION_LITERAL_RE = re.compile(r'\d+(?:\\\.\d+)+')

# Multi-digit number sequences (source line numbers, error codes, etc.)
_MULTIDIGIT_RE = re.compile(r'\d{3,}')


def _version_skeleton(regex: str) -> str:
    """Compute a normalized skeleton for grouping merge candidates.

    Replaces version-like literal sequences and multi-digit numbers
    with placeholders so that patterns differing only in these values
    map to the same skeleton.
    """
    s = _VERSION_LITERAL_RE.sub('__V__', regex)
    s = _MULTIDIGIT_RE.sub('__N__', s)
    return s


def _generalize_versions(regex: str) -> str:
    """Replace version-pinned literals with broad match patterns.

    Transforms:
        2\\.4\\.49  →  [\\d.]+
        1695       →  \\d+   (for 3+ digit sequences)
    """
    s = _VERSION_LITERAL_RE.sub(r'[\\d.]+', regex)
    s = _MULTIDIGIT_RE.sub(r'\\d+', s)
    return s


def _extract_product(meta: str) -> str:
    """Extract product name from the v/product/version/info/ metadata."""
    m = re.match(r'v/([^/]*)', meta)
    return m.group(1) if m else ''


def merge_versions(
    matches: list[NmapMatch],
    stats: ConversionStats,
) -> list[NmapMatch]:
    """Merge patterns that differ only in version-pinned literals.

    Groups patterns by (service, product, regex_skeleton) where the
    skeleton normalizes version literals and multi-digit numbers. When
    multiple patterns share a skeleton, one representative is kept with
    its regex generalized to match any version at those positions.

    Preserves input ordering (first occurrence of each group determines
    output position).
    """
    # Build groups keyed by (service, product, skeleton), tracking indices
    groups: dict[tuple[str, str, str], list[int]] = OrderedDict()
    for idx, m in enumerate(matches):
        product = _extract_product(
            f"v/{m.product}/{m.version}/{build_info_field(m)}/"
        )
        skel = _version_skeleton(m.regex)
        key = (m.service, product, skel)
        groups.setdefault(key, []).append(idx)

    # Build result preserving order of first occurrence
    emitted = set()
    result = []
    for key, indices in groups.items():
        if len(indices) == 1:
            result.append(matches[indices[0]])
        else:
            # Multiple patterns share the same skeleton — merge
            representative = matches[indices[0]]
            generalized = _generalize_versions(representative.regex)
            if generalized != representative.regex:
                representative.regex = generalized
            stats.total_merged_versions += len(indices) - 1
            result.append(representative)

    return result


# ---------------------------------------------------------------------------
# Stage 3c: Cap patterns per (service, product)
# ---------------------------------------------------------------------------

def cap_per_product(
    matches: list[NmapMatch],
    stats: ConversionStats,
    max_count: int,
) -> list[NmapMatch]:
    """Limit the number of patterns per (service, product) group.

    Within each group, patterns are ranked by specificity (highest first)
    and only the top max_count are kept. This preserves the most useful
    patterns while eliminating redundant low-specificity variants.

    Preserves overall output ordering — patterns appear in their original
    sequence, with excess patterns removed.
    """
    # Count per group and determine which indices to keep
    group_counts: dict[tuple[str, str], list[int]] = OrderedDict()
    for idx, m in enumerate(matches):
        product = _extract_product(
            f"v/{m.product}/{m.version}/{build_info_field(m)}/"
        )
        key = (m.service, product)
        group_counts.setdefault(key, []).append(idx)

    keep = set()
    for key, indices in group_counts.items():
        if len(indices) <= max_count:
            keep.update(indices)
        else:
            # Sort by specificity descending, keep top N
            ranked = sorted(
                indices,
                key=lambda i: compute_specificity(matches[i]),
                reverse=True,
            )
            keep.update(ranked[:max_count])
            stats.total_capped_product += len(indices) - max_count

    return [m for i, m in enumerate(matches) if i in keep]


# ---------------------------------------------------------------------------
# Stage 4: Transform (dot-star bounding)
# ---------------------------------------------------------------------------

def bound_dotstar(
    matches: list[NmapMatch],
    stats: ConversionStats,
    bound: int,
) -> list[NmapMatch]:
    """Replace unbounded .* and .+ with bounded equivalents for DFA efficiency.

    Transforms:
        .*  → .{0,N}
        .+  → .{1,N}

    Only transforms patterns where the flag set includes 's' (DOTALL),
    since .* without DOTALL already cannot match newlines and is less
    dangerous for DFA state explosion.
    """
    for m in matches:
        if 's' not in m.flags:
            continue

        original = m.regex
        new_regex = _bound_dotstar_in_regex(original, bound)
        if new_regex != original:
            m.regex = new_regex
            stats.dotstar_bounded += 1

    return matches


def _bound_dotstar_in_regex(regex: str, bound: int) -> str:
    """Replace .* and .+ with bounded forms, respecting character classes.

    Avoids modifying:
    - Patterns inside [...] character classes
    - Already-bounded patterns like .{0,100}
    - Escaped dots \\. (literal dots)
    """
    result = []
    i = 0
    in_class = False

    while i < len(regex):
        c = regex[i]

        # Handle escape sequences — skip over them entirely
        if c == '\\' and i + 1 < len(regex):
            result.append(regex[i:i+2])
            i += 2
            continue

        # Track character class state
        if c == '[' and not in_class:
            in_class = True
            result.append(c)
            i += 1
            continue
        if c == ']' and in_class:
            in_class = False
            result.append(c)
            i += 1
            continue

        # Only transform outside character classes
        if not in_class and c == '.':
            if i + 1 < len(regex) and regex[i + 1] == '*':
                if i + 2 < len(regex) and regex[i + 2] == '?':
                    result.append(f'.{{0,{bound}}}?')
                    i += 3
                else:
                    result.append(f'.{{0,{bound}}}')
                    i += 2
                continue
            elif i + 1 < len(regex) and regex[i + 1] == '+':
                if i + 2 < len(regex) and regex[i + 2] == '?':
                    result.append(f'.{{1,{bound}}}?')
                    i += 3
                else:
                    result.append(f'.{{1,{bound}}}')
                    i += 2
                continue

        result.append(c)
        i += 1

    return ''.join(result)


# ---------------------------------------------------------------------------
# Stage 4b: Transform (header-skip replacement)
# ---------------------------------------------------------------------------

# Matches the nmap HTTP header-skip idiom:
#   (?:[^\r\n]*\r\n(?!\r\n))*?
# This construct skips HTTP headers one line at a time using a negative
# lookahead to stop before the blank line (\r\n\r\n). It forces NFA-mode
# evaluation in Hyperscan because the negative lookahead prevents DFA
# compilation. Replacing it with .{0,N} is semantically broader (it can
# match across the blank line) but DFA-friendly and sufficient for service
# fingerprinting where the discriminating content follows the headers.
_HEADER_SKIP_RE = re.compile(
    r'\(\?:\[\^\\r\\n\]\*\\r\\n\(\?!\\r\\n\)\)\*\??'
)


def replace_header_skip(
    matches: list[NmapMatch],
    stats: ConversionStats,
    bound: int,
) -> list[NmapMatch]:
    """Replace HTTP header-skip constructs with bounded dot-any.

    Transforms:
        (?:[^\\r\\n]*\\r\\n(?!\\r\\n))*?  →  .{0,N}

    This eliminates negative-lookahead repetitions that force
    NFA evaluation in Hyperscan, replacing them with a DFA-friendly
    bounded wildcard.
    """
    replacement = f'.{{0,{bound}}}'
    for m in matches:
        new_regex = _HEADER_SKIP_RE.sub(replacement, m.regex)
        if new_regex != m.regex:
            m.regex = new_regex
            stats.header_skip_replaced += 1
    return matches


# ---------------------------------------------------------------------------
# Stage 4c: Filter by DFA compilation cost
# ---------------------------------------------------------------------------

def dfa_cost_score(regex: str) -> int:
    """Heuristic score estimating DFA compilation cost.

    Higher scores indicate patterns more likely to cause state explosion
    in Hyperscan/Vectorscan compilation. The score considers:

    - .{0,N} bounded repeats: each contributes N to the state space
    - Unbounded .* and .+: each treated as ~5000 and ~4000 states
    - Negative lookahead in repetition: NFA-forcing, +3000
    - Pattern length: linear contribution (more literal states)
    - Deep alternations: branch count * 200

    Typical scores:
        Simple banner match:      50-200
        HTTP with one .{0,2048}: 2100-2500
        HTTP with 3+ .{0,2048}: 6000-8000
        Pathological (12x .*):    60000+
    """
    score = 0

    # Each .{0,N} contributes N to state space
    for m in re.finditer(r'\.\{0,(\d+)\}', regex):
        score += int(m.group(1))

    # Each .{1,N} similarly
    for m in re.finditer(r'\.\{1,(\d+)\}', regex):
        score += int(m.group(1))

    # Unbounded .* and .+ are very expensive
    score += len(re.findall(r'(?<!\\)\.\*', regex)) * 5000
    score += len(re.findall(r'(?<!\\)\.\+', regex)) * 4000

    # Negative lookahead in repetition forces NFA
    if '(?!' in regex and (')*' in regex or ')+' in regex):
        score += 3000

    # Pattern length contributes linearly
    score += len(regex)

    # Deep alternations multiply states
    for m in re.finditer(r'\((?:[^()]*\|)+[^()]*\)', regex):
        branches = m.group(0).count('|') + 1
        score += branches * 200

    return score


def filter_dfa_cost(
    matches: list[NmapMatch],
    stats: ConversionStats,
    max_cost: int,
) -> list[NmapMatch]:
    """Drop patterns whose estimated DFA compilation cost exceeds max_cost.

    Patterns scoring above the threshold are disproportionately expensive
    to compile and often contain multiple unbounded repetitions that cause
    combinatorial state explosion in the DFA engine.
    """
    result = []
    for m in matches:
        full_regex = build_inline_flags(m.flags) + m.regex
        cost = dfa_cost_score(full_regex)
        if cost > max_cost:
            stats.total_skipped_dfa_cost += 1
            stats.errors.append(
                f"line {m.line_number}: DFA cost {cost} exceeds "
                f"--max-dfa-cost {max_cost}, skipping ({m.service})"
            )
        else:
            result.append(m)
    return result


# ---------------------------------------------------------------------------
# Stage 5: Sort
# ---------------------------------------------------------------------------

def load_priority_list(filepath: str) -> list[str]:
    """Load a priority ordering file. First line = highest priority."""
    priorities = []
    with open(filepath, "r") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                priorities.append(line)
    return priorities


def compute_specificity(match: NmapMatch) -> int:
    """Score a pattern's specificity (higher = more specific, should sort first).

    Heuristic based on:
    - Presence of capture groups (version extraction = more specific)
    - Ratio of literal to metacharacters
    - Absence of .* (more specific)
    - Pattern length (longer fixed patterns = more specific)
    """
    score = 0
    regex = match.regex

    # Capture groups indicate version extraction — more useful
    score += regex.count('(') * 10

    # Penalize .* and .+ heavily
    score -= regex.count('.*') * 20
    score -= regex.count('.+') * 15

    # Reward anchoring
    clean = re.sub(r'^\(\?[si]+\)', '', regex)
    if clean.startswith('^'):
        score += 5
    if clean.endswith('$'):
        score += 5

    # Reward length (longer literal patterns are more specific)
    score += min(len(regex) // 10, 20)

    # Reward having version info
    if match.version:
        score += 15

    return score


def priority_sort(
    matches: list[NmapMatch],
    priority_list: list[str],
) -> list[NmapMatch]:
    """Sort matches by service priority, then by specificity within each service.

    Services in priority_list are sorted first (in list order).
    Services not in the list come after, in their original order.
    Within each service group, more-specific patterns sort before generic ones.
    """
    priority_rank = {svc: i for i, svc in enumerate(priority_list)}
    unlisted_rank = len(priority_list)

    # Group matches by service, preserving insertion order for unlisted
    groups: dict[str, list[NmapMatch]] = OrderedDict()
    for m in matches:
        groups.setdefault(m.service, []).append(m)

    # Sort each group internally by specificity (descending)
    for svc in groups:
        groups[svc].sort(key=lambda m: compute_specificity(m), reverse=True)

    # Sort groups by priority rank, preserving original order for ties
    sorted_groups = sorted(
        groups.items(),
        key=lambda item: priority_rank.get(item[0], unlisted_rank),
    )

    result = []
    for _svc, group in sorted_groups:
        result.extend(group)
    return result


# ---------------------------------------------------------------------------
# Stage 6: Convert to PRADS format
# ---------------------------------------------------------------------------

def build_info_field(match: NmapMatch) -> str:
    """Build the PRADS info field by packing extra nmap metadata."""
    parts = []

    if match.info:
        parts.append(match.info)
    if match.os:
        parts.append(f"os:{match.os}")
    if match.hostname:
        parts.append(f"host:{match.hostname}")
    if match.device_type:
        parts.append(f"device:{match.device_type}")
    for cpe_entry in match.cpe:
        parts.append(f"cpe:{cpe_entry}")

    return " ".join(parts)


# Regex to match nmap's $SUBST(N,"from","to") macro syntax.
# These macros contain commas and quotes that would break the PRADS
# 3-field comma-delimited parser. Since PRADS has no $SUBST engine,
# we replace them with the bare capture group reference ($N).
#
# Handles both standard and edge-case forms:
#   $SUBST(1,"_",".")       → $1
#   $SUBST(2," ","")        → $2
#   $SUBST(1, "\r\n", ",")  → $1
_SUBST_RE = re.compile(r'\$SUBST\(\s*(\d+)\s*(?:,\s*"[^"]*"\s*)*\)')


def sanitize_subst_macros(text: str) -> str:
    """Replace nmap $SUBST(N,"from","to") macros with bare $N references.

    Nmap uses $SUBST() for post-match string substitution (e.g., replacing
    underscores with dots in version strings). PRADS has no equivalent
    engine, and the commas/quotes inside $SUBST() break the comma-delimited
    signature format.

    Examples:
        $SUBST(1,"_",".") → $1
        $SUBST(6,"_",".") → $6
    """
    return _SUBST_RE.sub(r'$\1', text)


def sanitize_field_commas(text: str) -> str:
    """Replace commas in metadata fields with semicolons.

    The PRADS format uses commas to delimit the 3 top-level fields:
        service,v/product/version/info/,regex

    If the product, version, or info fields contain literal commas
    (e.g., 'QNAP TS-239, or TS-509'), the parser will mis-split and
    corrupt the regex field. Replacing with semicolons preserves
    readability while making the format unambiguous.
    """
    return text.replace(",", ";")


def build_inline_flags(flags: str) -> str:
    """Convert nmap regex flags to an inline flag prefix for Hyperscan/PCRE2."""
    if not flags:
        return ""
    unique_flags = "".join(sorted(set(flags)))
    return f"(?{unique_flags})"


def has_backreferences(regex: str) -> bool:
    """Check if a regex contains backreferences (\\1 through \\9).

    These are unsupported by Hyperscan and must fall back to PCRE2.
    Distinguishes actual backrefs from hex escapes (\\xNN).
    """
    i = 0
    while i < len(regex):
        if regex[i] == '\\' and i + 1 < len(regex):
            next_char = regex[i + 1]
            if next_char == 'x':
                # Hex escape \xNN — skip past it
                i += 4
                continue
            if next_char in '123456789':
                return True
            i += 2
            continue
        i += 1
    return False


def extract_literal_prefix(regex: str, flags: str) -> str:
    """Extract the longest literal byte prefix from a regex.

    Walks the pattern from the start (after ^ anchor if present),
    collecting literal characters and recognized escape sequences
    (\\xNN, \\t, \\r, \\n, \\0, escaped metacharacters).

    Stops at the first regex metacharacter or unrecognized escape.
    """
    r = re.sub(r'^\(\?[si]+\)', '', regex)
    if r.startswith('^'):
        r = r[1:]

    prefix = []
    i = 0

    while i < len(r):
        c = r[i]

        if c == '\\' and i + 1 < len(r):
            nc = r[i + 1]
            if nc == 'x' and i + 3 < len(r):
                prefix.append(r[i:i+4])
                i += 4
                continue
            elif nc in 'tnr0':
                prefix.append(r[i:i+2])
                i += 2
                continue
            elif nc in r'.+*?{}()|[]^$\\':
                prefix.append(r[i:i+2])
                i += 2
                continue
            else:
                break
        elif c in r'.+*?{}()|[]^$':
            break
        else:
            prefix.append(c)
            i += 1

    return ''.join(prefix)


def convert_match_to_prads(
    match: NmapMatch,
    tag_backrefs: bool = False,
    emit_probe_context: bool = False,
) -> tuple[str, Optional[str]]:
    """Convert a parsed NmapMatch to a PRADS signature line.

    Returns:
        Tuple of (prads_line, annotation_comment_or_none).
    """
    info_field = build_info_field(match)
    inline_flags = build_inline_flags(match.flags)

    # Sanitize nmap $SUBST() macros that contain commas/quotes
    # which would break the PRADS comma-delimited format
    product = sanitize_subst_macros(match.product)
    version = sanitize_subst_macros(match.version)
    info_field = sanitize_subst_macros(info_field)

    # Replace any remaining literal commas in metadata fields
    # to prevent mis-splitting the 3-field PRADS format
    product = sanitize_field_commas(product)
    version = sanitize_field_commas(version)
    info_field = sanitize_field_commas(info_field)

    prads_line = (
        f"{match.service},"
        f"v/{product}/{version}/{info_field}/,"
        f"{inline_flags}{match.regex}"
    )

    annotations = []
    if emit_probe_context:
        annotations.append(f"probe:{match.protocol}:{match.probe_name}")
    if tag_backrefs and has_backreferences(match.regex):
        annotations.append("PCRE2_ONLY")

    comment = None
    if annotations:
        comment = f"# {' '.join(annotations)}"

    return prads_line, comment


# ---------------------------------------------------------------------------
# Regex validation
# ---------------------------------------------------------------------------

def validate_regex(pattern: str, line_number: int) -> Optional[str]:
    """Validate a regex pattern compiles with Python's re module."""
    try:
        re.compile(pattern)
        return None
    except re.error as e:
        return f"line {line_number}: regex validation warning (Python re): {e}"


# ---------------------------------------------------------------------------
# Stage 7: Output writing
# ---------------------------------------------------------------------------

PRADS_HEADER_TEMPLATE = """\
############################################################################
#
# PRADS - Passive Real-time Asset Detection System
#  - {proto_label} service signature list
#
# AUTO-GENERATED by nmap2prads.py from nmap-service-probes
# Source: {source_file}
# Generated: {timestamp}
# Match lines converted: {count}
#
# NOTE: This file is intended for use with a modified PRADS build using
# Hyperscan (primary) and PCRE2 (fallback) regex engines. Inline flags
# (e.g., (?si)) are embedded in regexes for engine-agnostic compatibility.
#
# Format:
# <service>,<version info>,<signature>
#
# Service: Service name from the nmap match directive.
#
# Version Info: NMAP-like template: v/product/version/info/
#   The info field may contain packed metadata:
#     os:<operating_system> host:<hostname> device:<type> cpe:<cpe_string>
#
# Signature: PCRE-compatible regex. Inline flags appear at the start.
#   Matching is first-match-wins (order matters).
#
# Annotations:
#   # probe:<PROTO>:<PROBE>  — nmap Probe type that elicits this response
#   # PCRE2_ONLY             — pattern requires PCRE2 (backreferences)
#
############################################################################
"""


def write_output(
    matches: list[NmapMatch],
    stats: ConversionStats,
    source_file: str,
    output_dir: str,
    combined: bool = False,
    tcp_filename: str = "tcp-service.sig",
    udp_filename: str = "udp-service.sig",
    tag_backrefs: bool = False,
    emit_probe_context: bool = False,
    validate: bool = False,
) -> list[str]:
    """Convert matches to PRADS format and write to output files."""
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    os.makedirs(output_dir, exist_ok=True)

    # Convert all matches to output lines with annotations
    converted = []  # list of (protocol, prads_line, comment_or_none)
    for m in matches:
        prads_line, comment = convert_match_to_prads(
            m,
            tag_backrefs=tag_backrefs,
            emit_probe_context=emit_probe_context,
        )

        # Track stats
        if m.flags:
            stats.flags_embedded += 1
        if m.os or m.hostname or m.device_type or m.cpe:
            stats.info_packed += 1
        if tag_backrefs and has_backreferences(m.regex):
            stats.backrefs_tagged += 1
        if m.protocol == "TCP":
            stats.tcp_count += 1
        else:
            stats.udp_count += 1

        # Optional validation
        if validate:
            full_regex = build_inline_flags(m.flags) + m.regex
            err = validate_regex(full_regex, m.line_number)
            if err:
                stats.regex_validation_failures += 1
                stats.errors.append(err)

        stats.total_converted += 1
        converted.append((m.protocol, prads_line, comment))

    # Write files
    written_files = []

    def write_sig_file(path, proto_label, entries):
        header = PRADS_HEADER_TEMPLATE.format(
            proto_label=proto_label,
            source_file=os.path.basename(source_file),
            timestamp=timestamp,
            count=len(entries),
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(header)
            for _proto, line, comment in entries:
                if comment:
                    fh.write(comment + "\n")
                fh.write(line + "\n")
        written_files.append(path)

    if combined:
        write_sig_file(
            os.path.join(output_dir, "service.sig"),
            "TCP/UDP combined", converted,
        )
    else:
        tcp_entries = [e for e in converted if e[0] == "TCP"]
        udp_entries = [e for e in converted if e[0] == "UDP"]
        if tcp_entries:
            write_sig_file(
                os.path.join(output_dir, tcp_filename),
                "TCP server", tcp_entries,
            )
        if udp_entries:
            write_sig_file(
                os.path.join(output_dir, udp_filename),
                "UDP service", udp_entries,
            )

    return written_files


def write_prefixes(matches: list[NmapMatch], prefix_path: str) -> int:
    """Extract and write literal prefixes for Hyperscan prefilter compilation.

    Output format (tab-delimited):
        <pattern_id>\\t<prefix_length>\\t<prefix>\\t<service>

    Where pattern_id is the 0-based index matching the order in the .sig file.

    Returns:
        Number of prefixes written.
    """
    count = 0
    with open(prefix_path, "w", encoding="utf-8") as fh:
        fh.write("# Literal prefixes for Hyperscan prefilter compilation\n")
        fh.write("# Format: pattern_id<TAB>prefix_len<TAB>prefix<TAB>service\n")
        fh.write(f"# Extracted from {len(matches)} patterns\n")
        for idx, m in enumerate(matches):
            prefix = extract_literal_prefix(m.regex, m.flags)
            if prefix:
                fh.write(f"{idx}\t{len(prefix)}\t{prefix}\t{m.service}\n")
                count += 1
    return count


# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

def print_summary(stats: ConversionStats, written_files: list[str]) -> None:
    """Print conversion summary to stderr."""
    print("\n" + "=" * 60, file=sys.stderr)
    print("nmap2prads conversion summary", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Match lines processed:     {stats.total_match_lines}", file=sys.stderr)
    print(f"  Softmatch lines skipped:   {stats.total_softmatch_skipped}", file=sys.stderr)
    print(f"  Successfully converted:    {stats.total_converted}", file=sys.stderr)
    print(f"    TCP signatures:          {stats.tcp_count}", file=sys.stderr)
    print(f"    UDP signatures:          {stats.udp_count}", file=sys.stderr)
    print(f"  Skipped (no product):      {stats.total_skipped_no_product}", file=sys.stderr)
    print(f"  Skipped (parse errors):    {stats.total_skipped_errors}", file=sys.stderr)
    if stats.total_skipped_service_filter:
        print(f"  Skipped (service filter):  {stats.total_skipped_service_filter}", file=sys.stderr)
    if stats.total_skipped_probe_filter:
        print(f"  Skipped (probe filter):    {stats.total_skipped_probe_filter}", file=sys.stderr)
    if stats.total_skipped_max_length:
        print(f"  Skipped (max length):      {stats.total_skipped_max_length}", file=sys.stderr)
    if stats.total_deduped:
        print(f"  Deduplicated:              {stats.total_deduped}", file=sys.stderr)
    if stats.total_merged_versions:
        print(f"  Merged (versions):         {stats.total_merged_versions}", file=sys.stderr)
    if stats.total_capped_product:
        print(f"  Capped (per-product):      {stats.total_capped_product}", file=sys.stderr)
    print(f"  Inline flags embedded:     {stats.flags_embedded}", file=sys.stderr)
    print(f"  Metadata packed into info: {stats.info_packed}", file=sys.stderr)
    if stats.total_skipped_dfa_cost:
        print(f"  Dropped (DFA cost):        {stats.total_skipped_dfa_cost}", file=sys.stderr)
    if stats.dotstar_bounded:
        print(f"  Dot-star patterns bounded: {stats.dotstar_bounded}", file=sys.stderr)
    if stats.header_skip_replaced:
        print(f"  Header-skip replaced:      {stats.header_skip_replaced}", file=sys.stderr)
    if stats.backrefs_tagged:
        print(f"  Backref patterns tagged:   {stats.backrefs_tagged}", file=sys.stderr)
    if stats.regex_validation_failures:
        print(
            f"  Regex validation warnings: {stats.regex_validation_failures}",
            file=sys.stderr,
        )
    print("-" * 60, file=sys.stderr)
    for path in written_files:
        print(f"  Output: {path}", file=sys.stderr)

    if stats.errors:
        print(f"\n  First 10 errors/warnings:", file=sys.stderr)
        for err in stats.errors[:10]:
            print(f"    {err}", file=sys.stderr)
        if len(stats.errors) > 10:
            print(
                f"    ... and {len(stats.errors) - 10} more",
                file=sys.stderr,
            )
    print("=" * 60, file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert nmap-service-probes match lines to PRADS "
                    "signature format.",
        epilog=(
            "Examples:\n"
            "  # Basic conversion with protocol splitting\n"
            "  %(prog)s nmap-service-probes -o ./output/\n\n"
            "  # Optimized for Hyperscan DFA compilation\n"
            "  %(prog)s nmap-service-probes -o ./output/ \\\n"
            "      --dedup --bound-dotstar 2048 --tag-backrefs \\\n"
            "      --priority-sort priority.conf \\\n"
            "      --emit-prefixes prefixes.txt\n\n"
            "  # Lean deployment (specific services only)\n"
            "  %(prog)s nmap-service-probes -o ./output/ \\\n"
            "      --include-services critical.conf --dedup\n\n"
            "  # Validation dry-run\n"
            "  %(prog)s nmap-service-probes --validate --dry-run\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Input/output ---
    parser.add_argument(
        "input",
        help="Path to nmap-service-probes file",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=".",
        help="Output directory for generated .sig files (default: .)",
    )
    parser.add_argument(
        "--combined",
        action="store_true",
        help="Write all signatures to a single service.sig file",
    )
    parser.add_argument(
        "--tcp-filename",
        default="tcp-service.sig",
        help="Filename for TCP signatures (default: tcp-service.sig)",
    )
    parser.add_argument(
        "--udp-filename",
        default="udp-service.sig",
        help="Filename for UDP signatures (default: udp-service.sig)",
    )

    # --- Filtering ---
    filt = parser.add_argument_group("filtering")
    filt.add_argument(
        "--exclude-services",
        metavar="FILE",
        help="File listing service names to exclude (one per line)",
    )
    filt.add_argument(
        "--include-services",
        metavar="FILE",
        help="File listing service names to include (one per line). "
             "Takes precedence over --exclude-services.",
    )
    filt.add_argument(
        "--max-length",
        type=int,
        metavar="N",
        help="Skip patterns whose regex exceeds N characters",
    )
    filt.add_argument(
        "--passive-probes",
        metavar="FILE",
        help="File listing probe names to keep (passive-relevant). "
             "Signatures from unlisted probes are dropped.",
    )

    # --- Optimization ---
    opt = parser.add_argument_group("optimization")
    opt.add_argument(
        "--dedup",
        action="store_true",
        help="Eliminate exact regex+flags duplicates (keep first occurrence)",
    )
    opt.add_argument(
        "--max-per-product",
        type=int,
        metavar="N",
        default=None,
        help="Keep at most N patterns per (service, product) group, "
             "ranked by specificity (default when flag used: 3)",
    )
    opt.add_argument(
        "--merge-versions",
        action="store_true",
        help="Merge patterns within the same (service, product) group "
             "that differ only in version-pinned literals. Keeps one "
             "representative per group with a generalized regex.",
    )
    opt.add_argument(
        "--bound-dotstar",
        type=int,
        metavar="N",
        help="Replace .* with .{0,N} and .+ with .{1,N} in DOTALL "
             "patterns for DFA-friendly compilation (recommended: 2048)",
    )
    opt.add_argument(
        "--replace-header-skip",
        type=int,
        metavar="N",
        default=None,
        help="Replace HTTP header-skip constructs "
             "(?:[^\\r\\n]*\\r\\n(?!\\r\\n))*? with .{0,N}. "
             "Eliminates NFA-forcing negative lookahead repetitions "
             "(recommended: 2048)",
    )
    opt.add_argument(
        "--max-dfa-cost",
        type=int,
        metavar="N",
        default=None,
        help="Drop patterns whose estimated DFA compilation cost exceeds N. "
             "Eliminates the small percentage of patterns that "
             "disproportionately drive Hyperscan compile time "
             "(recommended: 10000)",
    )
    opt.add_argument(
        "--priority-sort",
        metavar="FILE",
        help="File listing services in priority order (highest first). "
             "Within each service, patterns sorted by specificity.",
    )

    # --- Annotation ---
    ann = parser.add_argument_group("annotation")
    ann.add_argument(
        "--tag-backrefs",
        action="store_true",
        help="Add '# PCRE2_ONLY' annotation above backref patterns",
    )
    ann.add_argument(
        "--emit-probe-context",
        action="store_true",
        help="Add '# probe:<PROTO>:<name>' annotation above each signature",
    )
    ann.add_argument(
        "--emit-prefixes",
        metavar="FILE",
        help="Write literal prefixes to FILE for Hyperscan prefilter",
    )

    # --- Validation ---
    val = parser.add_argument_group("validation")
    val.add_argument(
        "--validate",
        action="store_true",
        help="Validate regexes with Python re module (warnings only)",
    )
    val.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and process but do not write output files",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # ---------------------------------------------------------------
    # Pipeline: parse → filter → dedup → transform → sort → write
    # ---------------------------------------------------------------

    # Stage 1: Parse
    matches, stats = parse_nmap_file(args.input)
    print(f"Parsed {len(matches)} match lines", file=sys.stderr)

    # Stage 2: Filter by service
    if args.include_services:
        include_set = load_service_list(args.include_services)
        matches = filter_services(matches, stats, include=include_set)
        print(f"After include filter: {len(matches)}", file=sys.stderr)
    elif args.exclude_services:
        exclude_set = load_service_list(args.exclude_services)
        matches = filter_services(matches, stats, exclude=exclude_set)
        print(f"After exclude filter: {len(matches)}", file=sys.stderr)

    # Stage 2b: Filter by passive probe relevance
    if args.passive_probes:
        probe_set = load_probe_list(args.passive_probes)
        matches = filter_passive_probes(matches, stats, probe_set)
        print(f"After passive probe filter: {len(matches)}", file=sys.stderr)

    # Stage 2c: Filter by max length
    if args.max_length:
        matches = filter_max_length(matches, stats, args.max_length)
        print(f"After max-length filter: {len(matches)}", file=sys.stderr)

    # Stage 3: Deduplicate
    if args.dedup:
        matches = deduplicate(matches, stats)
        print(f"After dedup: {len(matches)}", file=sys.stderr)

    # Stage 3b: Merge version-pinned patterns
    if args.merge_versions:
        matches = merge_versions(matches, stats)
        print(f"After merge-versions: {len(matches)} "
              f"({stats.total_merged_versions} merged)", file=sys.stderr)

    # Stage 3c: Cap per (service, product)
    if args.max_per_product is not None:
        cap = args.max_per_product if args.max_per_product > 0 else 3
        matches = cap_per_product(matches, stats, cap)
        print(f"After max-per-product (N={cap}): {len(matches)} "
              f"({stats.total_capped_product} capped)", file=sys.stderr)

    # Stage 4: Transform — bound dot-star
    if args.bound_dotstar:
        matches = bound_dotstar(matches, stats, args.bound_dotstar)
        print(f"Dot-star bounded (N={args.bound_dotstar}): "
              f"{stats.dotstar_bounded} patterns modified", file=sys.stderr)

    # Stage 4b: Transform — replace header-skip constructs
    if args.replace_header_skip is not None:
        bound = args.replace_header_skip if args.replace_header_skip > 0 else 2048
        matches = replace_header_skip(matches, stats, bound)
        print(f"Header-skip replaced (N={bound}): "
              f"{stats.header_skip_replaced} patterns modified",
              file=sys.stderr)

    # Stage 4c: Filter by DFA compilation cost
    if args.max_dfa_cost is not None:
        matches = filter_dfa_cost(matches, stats, args.max_dfa_cost)
        print(f"After max-dfa-cost (N={args.max_dfa_cost}): {len(matches)} "
              f"({stats.total_skipped_dfa_cost} dropped)", file=sys.stderr)

    # Stage 5: Sort by priority
    if args.priority_sort:
        priority_list = load_priority_list(args.priority_sort)
        matches = priority_sort(matches, priority_list)
        print(f"Priority sorted ({len(priority_list)} priority services)",
              file=sys.stderr)

    # Stage 6-7: Convert and write
    written_files = []
    if not args.dry_run:
        written_files = write_output(
            matches=matches,
            stats=stats,
            source_file=args.input,
            output_dir=args.output_dir,
            combined=args.combined,
            tcp_filename=args.tcp_filename,
            udp_filename=args.udp_filename,
            tag_backrefs=args.tag_backrefs,
            emit_probe_context=args.emit_probe_context,
            validate=args.validate,
        )

        if args.emit_prefixes:
            prefix_count = write_prefixes(matches, args.emit_prefixes)
            written_files.append(args.emit_prefixes)
            print(f"Emitted {prefix_count} literal prefixes to "
                  f"{args.emit_prefixes}", file=sys.stderr)
    else:
        # Dry-run: still compute stats for the summary
        for m in matches:
            if m.flags:
                stats.flags_embedded += 1
            if m.os or m.hostname or m.device_type or m.cpe:
                stats.info_packed += 1
            if args.tag_backrefs and has_backreferences(m.regex):
                stats.backrefs_tagged += 1
            if m.protocol == "TCP":
                stats.tcp_count += 1
            else:
                stats.udp_count += 1
            if args.validate:
                full_regex = build_inline_flags(m.flags) + m.regex
                err = validate_regex(full_regex, m.line_number)
                if err:
                    stats.regex_validation_failures += 1
                    stats.errors.append(err)
            stats.total_converted += 1
        print("(dry-run: no files written)", file=sys.stderr)

    print_summary(stats, written_files)

    if stats.total_skipped_errors > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
