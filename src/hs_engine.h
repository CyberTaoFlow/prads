/*
** hs_engine.h - Vectorscan multi-pattern matching engine for PRADS
**
** This module replaces the per-signature PCRE linear scan with a
** Vectorscan (Hyperscan-compatible) multi-pattern database.  All
** service/client signatures are compiled into a single DFA that is
** evaluated in one pass per payload.  Signatures requiring capture-
** group extraction or those compiled in prefilter mode fall back to
** a single targeted PCRE2 match after Vectorscan identifies which
** signature matched.
**
** Copyright (C) 2025 — released under the same GPLv2 terms as PRADS.
*/

#ifndef HS_ENGINE_H
#define HS_ENGINE_H

#include <hs/hs.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "bstrlib.h"

/* Forward declaration — full definition lives in prads.h */
typedef struct _signature signature;

/* -------------------------------------------------------------------
 * Per-signature flags that describe how to handle a Vectorscan match.
 * ------------------------------------------------------------------- */
enum hs_sig_flags {
    HS_SIG_NORMAL     = 0,        /* Pure Vectorscan match — no PCRE2 needed  */
    HS_SIG_PREFILTER  = (1 << 0), /* Compiled with HS_FLAG_PREFILTER — PCRE2
                                     must confirm the match (may over-report)  */
    HS_SIG_CAPTURE    = (1 << 1), /* Title template contains $1/$2 — PCRE2
                                     required for capture-group extraction     */
    HS_SIG_PCRE2_ONLY = (1 << 2), /* Pattern could not be compiled in
                                     Vectorscan at all — linear PCRE2 fallback */
};

/* -------------------------------------------------------------------
 * Compiled multi-pattern database for one signature category
 * (e.g. TCP server, TCP client, UDP server, etc.).
 * ------------------------------------------------------------------- */
typedef struct _hs_sigdb {
    hs_database_t   *db;          /* Compiled Vectorscan block-mode database   */
    hs_scratch_t    *scratch;     /* Per-thread scratch space                  */
    signature       **sig_array;  /* Map: hs pattern id  →  signature*         */
    uint8_t         *sig_flags;   /* Map: hs pattern id  →  hs_sig_flags       */
    uint32_t         hs_count;    /* Number of patterns in the hs database     */

    /* Signatures that could not be compiled in Vectorscan at all.
     * These are scanned linearly with PCRE2 as a last resort.       */
    signature       **pcre2_only; /* Array of PCRE2-only signature pointers    */
    uint32_t         pcre2_only_count;
} hs_sigdb_t;

/* -------------------------------------------------------------------
 * Match context passed to the Vectorscan callback.  Collects all
 * matching pattern IDs so we can honour first-match-wins ordering.
 * ------------------------------------------------------------------- */
#define HS_MAX_MATCHES  128       /* Upper bound on simultaneous matches       */

typedef struct _hs_match_ctx {
    unsigned int     ids[HS_MAX_MATCHES];
    int              count;
} hs_match_ctx_t;

/* -------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------- */

/*
 * Build a Vectorscan multi-pattern database from a linked list of
 * signatures that have already been parsed (service, title, regex
 * string populated).  Returns NULL on total failure.
 *
 * For each signature:
 *   1. Try hs_compile() in block mode.
 *   2. On failure, retry with HS_FLAG_PREFILTER.
 *   3. On failure, mark as PCRE2_ONLY (linear fallback).
 *   4. If the title template contains $N, compile a PCRE2 pattern.
 *
 * The original signature linked-list ordering is preserved as the
 * pattern ID, ensuring first-match-wins semantics.
 */
hs_sigdb_t *hs_sigdb_compile(signature *siglist, const char *db_label);

/*
 * Scan a payload against a compiled multi-pattern database.
 * Populates match_ctx with all matching pattern IDs.
 * Returns 0 on success, non-zero on error.
 */
int hs_sigdb_scan(const hs_sigdb_t *hsdb, const char *data,
                  unsigned int length, hs_match_ctx_t *ctx);

/*
 * Free a compiled multi-pattern database and all associated
 * resources (scratch, sig_array, pcre2_only array).
 * Does NOT free the underlying signature linked-list nodes.
 */
void hs_sigdb_free(hs_sigdb_t *hsdb);

/*
 * Extract application name from a signature that matched via PCRE2.
 * This is the PCRE2 equivalent of the original get_app_name().
 * Caller must bdestroy() the returned bstring.
 */
bstring hs_get_app_name_pcre2(signature *sig, const uint8_t *payload,
                              pcre2_match_data *match_data, int rc);

/*
 * Build application name from a signature that matched without
 * requiring captures (no $N in the title template).
 * Caller must bdestroy() the returned bstring.
 */
bstring hs_get_app_name_static(signature *sig);

/*
 * Vectorscan match callback — collects pattern IDs into match_ctx.
 */
int hs_on_match(unsigned int id, unsigned long long from,
                unsigned long long to, unsigned int flags, void *ctx);

/*
 * Return a human-readable Vectorscan version string.
 */
const char *hs_engine_version(void);

#endif /* HS_ENGINE_H */
