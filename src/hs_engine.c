/*
** hs_engine.c - Vectorscan multi-pattern matching engine for PRADS
**
** See hs_engine.h for design overview.
**
** Copyright (C) 2025 — released under the same GPLv2 terms as PRADS.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "prads.h"
#include "config.h"
#include "hs_engine.h"
#include "sys_func.h"

extern globalconfig config;

/* -------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------- */

/*
 * Check whether a signature title template uses $N capture references.
 * Returns 1 if any $0-$9 placeholder is found in app, ver, or misc.
 */
static int sig_needs_captures(const signature *sig)
{
    const char *fields[3];
    int nfields = 0;

    if (sig->title.app  && sig->title.app->slen  > 0)
        fields[nfields++] = (const char *)sig->title.app->data;
    if (sig->title.ver  && sig->title.ver->slen  > 0)
        fields[nfields++] = (const char *)sig->title.ver->data;
    if (sig->title.misc && sig->title.misc->slen > 0)
        fields[nfields++] = (const char *)sig->title.misc->data;

    for (int i = 0; i < nfields; i++) {
        for (const char *p = fields[i]; *p; p++) {
            if (*p == '$' && p[1] >= '0' && p[1] <= '9')
                return 1;
        }
    }
    return 0;
}

/*
 * Sort an array of unsigned ints in ascending order (for first-match-wins).
 * Simple insertion sort — HS_MAX_MATCHES is small.
 */
static void sort_match_ids(unsigned int *ids, int count)
{
    for (int i = 1; i < count; i++) {
        unsigned int key = ids[i];
        int j = i - 1;
        while (j >= 0 && ids[j] > key) {
            ids[j + 1] = ids[j];
            j--;
        }
        ids[j + 1] = key;
    }
}

/* -------------------------------------------------------------------
 * Vectorscan match callback
 * ------------------------------------------------------------------- */
int hs_on_match(unsigned int id, unsigned long long from,
                unsigned long long to, unsigned int flags, void *ctx)
{
    (void)from;
    (void)to;
    (void)flags;

    hs_match_ctx_t *mctx = (hs_match_ctx_t *)ctx;
    if (mctx->count < HS_MAX_MATCHES) {
        mctx->ids[mctx->count++] = id;
    }
    return 0; /* continue scanning — collect all matches */
}

/* -------------------------------------------------------------------
 * hs_sigdb_compile — build multi-pattern database from signature list
 *
 * Strategy: collect all patterns, attempt hs_compile_multi().  On
 * failure, promote the offending pattern to PREFILTER and retry.
 * If PREFILTER also fails, move the pattern to the PCRE2-only list.
 * This avoids thousands of individual hs_compile / hs_free_database
 * cycles that can fragment the heap with large signature libraries.
 * ------------------------------------------------------------------- */
hs_sigdb_t *hs_sigdb_compile(signature *siglist, const char *db_label)
{
    signature *sig;
    uint32_t total = 0;

    /* First pass: count signatures with valid regex strings */
    for (sig = siglist; sig != NULL; sig = sig->next) {
        if (sig->regex_str != NULL && bdata(sig->regex_str) != NULL
            && sig->regex_str->slen > 0)
            total++;
    }

    if (total == 0) {
        olog("[!] hs_sigdb_compile(%s): empty signature list\n", db_label);
        return NULL;
    }

    olog("[*] hs_sigdb_compile(%s): processing %u signatures\n", db_label, total);

    /* Allocate working arrays sized to total (some may move to pcre2_only) */
    const char  **expressions  = calloc(total, sizeof(char *));
    unsigned int *hs_flags_arr = calloc(total, sizeof(unsigned int));
    unsigned int *hs_ids       = calloc(total, sizeof(unsigned int));
    uint8_t      *per_sig_fl   = calloc(total, sizeof(uint8_t));
    signature   **sig_map      = calloc(total, sizeof(signature *));

    /* Temporary array for PCRE2-only fallback signatures */
    signature   **pcre2_only_tmp = calloc(total, sizeof(signature *));
    uint32_t      pcre2_only_cnt = 0;

    /* Track which batch slots are still active (not evicted to pcre2_only) */
    int          *active       = calloc(total, sizeof(int));

    if (!expressions || !hs_flags_arr || !hs_ids || !per_sig_fl ||
        !sig_map || !pcre2_only_tmp || !active) {
        olog("[!] hs_sigdb_compile(%s): allocation failure\n", db_label);
        goto fail_alloc;
    }

    /* -----------------------------------------------------------
     * Second pass: populate batch arrays
     * ----------------------------------------------------------- */
    uint32_t batch_count = 0;
    for (sig = siglist; sig != NULL; sig = sig->next) {
        if (sig->regex_str == NULL || bdata(sig->regex_str) == NULL
            || sig->regex_str->slen == 0)
            continue;

        const char *pattern = (const char *)bdata(sig->regex_str);
        int needs_cap = sig_needs_captures(sig);

        expressions[batch_count]  = pattern; /* points into bstring — valid for lifetime */
        hs_flags_arr[batch_count] = HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH;
        hs_ids[batch_count]       = batch_count;
        sig_map[batch_count]      = sig;
        per_sig_fl[batch_count]   = needs_cap ? HS_SIG_CAPTURE : HS_SIG_NORMAL;
        active[batch_count]       = 1;
        sig->hs_id                = batch_count;
        sig->hs_flags             = per_sig_fl[batch_count];

        batch_count++;
    }

    olog("[*] hs_sigdb_compile(%s): %u patterns in initial batch\n",
         db_label, batch_count);

    /* -----------------------------------------------------------
     * Iterative multi-compile: on failure, promote or evict the
     * offending pattern and retry until success or empty batch.
     *
     * Vectorscan's compile_err->expression gives us the index of
     * the first pattern that caused the compilation to fail.
     * ----------------------------------------------------------- */
    int max_retries = (int)batch_count + 10; /* safety bound */
    int retries = 0;

    while (retries < max_retries) {
        /* Build compact arrays from active slots */
        uint32_t hs_count = 0;
        for (uint32_t j = 0; j < batch_count; j++) {
            if (!active[j]) continue;
            expressions[hs_count]  = (const char *)bdata(sig_map[j]->regex_str);
            hs_flags_arr[hs_count] = HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH;
            if (per_sig_fl[j] & HS_SIG_PREFILTER)
                hs_flags_arr[hs_count] |= HS_FLAG_PREFILTER;
            hs_ids[hs_count]       = j;  /* maps back to original slot */
            hs_count++;
        }

        if (hs_count == 0)
            break;

        hs_compile_error_t *compile_err = NULL;
        hs_database_t *db = NULL;
        hs_error_t ret = hs_compile_multi(expressions, hs_flags_arr, hs_ids,
                                          hs_count, HS_MODE_BLOCK, NULL,
                                          &db, &compile_err);
        if (ret == HS_SUCCESS) {
            /* Success — build the final database structure */
            hs_sigdb_t *hsdb = calloc(1, sizeof(hs_sigdb_t));
            if (!hsdb) {
                hs_free_database(db);
                goto fail_alloc;
            }
            hsdb->db = db;

            ret = hs_alloc_scratch(hsdb->db, &hsdb->scratch);
            if (ret != HS_SUCCESS) {
                olog("[!] hs_sigdb_compile(%s): hs_alloc_scratch failed (%d)\n",
                     db_label, ret);
                hs_free_database(db);
                free(hsdb);
                goto fail_alloc;
            }

            /* Build mapping arrays (indexed by original slot ID) */
            hsdb->sig_array = calloc(batch_count, sizeof(signature *));
            hsdb->sig_flags = calloc(batch_count, sizeof(uint8_t));
            hsdb->hs_count  = batch_count; /* max possible ID + 1 */

            if (!hsdb->sig_array || !hsdb->sig_flags) {
                hs_sigdb_free(hsdb);
                goto fail_alloc;
            }
            for (uint32_t j = 0; j < batch_count; j++) {
                hsdb->sig_flags[j] = per_sig_fl[j];
                if (!active[j]) continue;
                hsdb->sig_array[j] = sig_map[j];
            }

            /* Compile PCRE2 patterns for sigs that need captures or prefilter confirm */
            for (uint32_t j = 0; j < batch_count; j++) {
                if (!active[j]) continue;
                signature *s = sig_map[j];
                uint8_t sf = per_sig_fl[j];
                if (sf & (HS_SIG_CAPTURE | HS_SIG_PREFILTER)) {
                    int errcode;
                    PCRE2_SIZE errofs;
                    const char *pat = (const char *)bdata(s->regex_str);
                    if (pat == NULL) continue;
                    s->re = pcre2_compile((PCRE2_SPTR)pat,
                                          PCRE2_ZERO_TERMINATED,
                                          PCRE2_DOTALL,
                                          &errcode, &errofs, NULL);
                    if (s->re != NULL) {
                        s->match_data = pcre2_match_data_create_from_pattern(
                                            s->re, NULL);
                    }
                    s->hs_flags = sf;
                }
            }

            /* Transfer PCRE2-only list */
            if (pcre2_only_cnt > 0) {
                hsdb->pcre2_only = calloc(pcre2_only_cnt, sizeof(signature *));
                if (hsdb->pcre2_only) {
                    memcpy(hsdb->pcre2_only, pcre2_only_tmp,
                           pcre2_only_cnt * sizeof(signature *));
                }
            }
            hsdb->pcre2_only_count = pcre2_only_cnt;

            olog("[*] hs_sigdb_compile(%s): %u in Vectorscan, %u PCRE2-only\n",
                 db_label, hs_count, pcre2_only_cnt);

            /* Clean up working arrays */
            free(expressions);
            free(hs_flags_arr);
            free(hs_ids);
            free(per_sig_fl);
            free(sig_map);
            free(pcre2_only_tmp);
            free(active);
            return hsdb;
        }

        /* Compilation failed — identify and handle the offending pattern */
        int fail_orig = -1;
        if (compile_err) {
            /* compile_err->expression is the index within the COMPACT array,
             * but hs_ids[that_index] gives us the original slot number.    */
            if (compile_err->expression >= 0 &&
                (unsigned int)compile_err->expression < hs_count) {
                fail_orig = (int)hs_ids[compile_err->expression];
            }
            dlog("[*] hs(%s): pattern #%d failed: %s\n",
                 db_label, fail_orig, compile_err->message);
            hs_free_compile_error(compile_err);
        }

        if (fail_orig < 0 || fail_orig >= (int)batch_count) {
            /* Can't identify the failing pattern — bail out */
            olog("[!] hs_sigdb_compile(%s): unidentifiable compile failure\n",
                 db_label);
            break;
        }

        /* Strategy: if not yet PREFILTER, promote to PREFILTER and retry.
         * If already PREFILTER, evict to PCRE2-only.                     */
        if (!(per_sig_fl[fail_orig] & HS_SIG_PREFILTER)) {
            per_sig_fl[fail_orig] |= HS_SIG_PREFILTER;
            dlog("[*] hs(%s): promoting pattern #%d to prefilter mode\n",
                 db_label, fail_orig);
        } else {
            /* Already prefilter — evict to PCRE2-only */
            active[fail_orig] = 0;
            per_sig_fl[fail_orig] |= HS_SIG_PCRE2_ONLY;
            sig_map[fail_orig]->hs_flags = per_sig_fl[fail_orig];

            /* Compile PCRE2 pattern for the evicted sig */
            signature *s = sig_map[fail_orig];
            const char *pat = (const char *)bdata(s->regex_str);
            if (pat != NULL) {
                int errcode;
                PCRE2_SIZE errofs;
                s->re = pcre2_compile((PCRE2_SPTR)pat,
                                      PCRE2_ZERO_TERMINATED,
                                      PCRE2_DOTALL,
                                      &errcode, &errofs, NULL);
                if (s->re != NULL) {
                    s->match_data = pcre2_match_data_create_from_pattern(
                                        s->re, NULL);
                }
            }
            pcre2_only_tmp[pcre2_only_cnt++] = s;

            dlog("[*] hs(%s): evicted pattern #%d to PCRE2-only fallback\n",
                 db_label, fail_orig);
        }

        retries++;
    }

    /* If we get here, compilation failed completely */
    olog("[!] hs_sigdb_compile(%s): all compile attempts failed after %d retries\n",
         db_label, retries);

    /* Return a PCRE2-only database so matching still works (linear fallback) */
    if (pcre2_only_cnt > 0) {
        hs_sigdb_t *hsdb = calloc(1, sizeof(hs_sigdb_t));
        if (hsdb) {
            hsdb->pcre2_only = calloc(pcre2_only_cnt, sizeof(signature *));
            if (hsdb->pcre2_only) {
                memcpy(hsdb->pcre2_only, pcre2_only_tmp,
                       pcre2_only_cnt * sizeof(signature *));
            }
            hsdb->pcre2_only_count = pcre2_only_cnt;
            olog("[!] hs_sigdb_compile(%s): falling back to %u PCRE2-only patterns\n",
                 db_label, pcre2_only_cnt);

            free(expressions);
            free(hs_flags_arr);
            free(hs_ids);
            free(per_sig_fl);
            free(sig_map);
            free(pcre2_only_tmp);
            free(active);
            return hsdb;
        }
    }

fail_alloc:
    free(expressions);
    free(hs_flags_arr);
    free(hs_ids);
    free(per_sig_fl);
    free(sig_map);
    free(pcre2_only_tmp);
    free(active);
    return NULL;
}

/* -------------------------------------------------------------------
 * hs_sigdb_scan — run a payload against the multi-pattern database
 * ------------------------------------------------------------------- */
int hs_sigdb_scan(const hs_sigdb_t *hsdb, const char *data,
                  unsigned int length, hs_match_ctx_t *ctx)
{
    ctx->count = 0;

    if (!hsdb || !hsdb->db || !hsdb->scratch)
        return 0;  /* no Vectorscan DB — return success with 0 matches
                    * so callers fall through to pcre2_only check */

    hs_error_t ret = hs_scan(hsdb->db, data, length, 0,
                             hsdb->scratch, hs_on_match, ctx);
    if (ret != HS_SUCCESS && ret != HS_SCAN_TERMINATED) {
        return (int)ret;
    }

    /* Sort matches by pattern ID (ordinal) for first-match-wins */
    if (ctx->count > 1)
        sort_match_ids(ctx->ids, ctx->count);

    return 0;
}

/* -------------------------------------------------------------------
 * hs_sigdb_free
 * ------------------------------------------------------------------- */
void hs_sigdb_free(hs_sigdb_t *hsdb)
{
    if (!hsdb) return;

    if (hsdb->scratch)
        hs_free_scratch(hsdb->scratch);
    if (hsdb->db)
        hs_free_database(hsdb->db);

    free(hsdb->sig_array);
    free(hsdb->sig_flags);
    free(hsdb->pcre2_only);
    free(hsdb);
}

/* -------------------------------------------------------------------
 * hs_get_app_name_pcre2 — capture-group version of get_app_name
 *
 * Mirrors the original get_app_name() logic but uses the PCRE2 API
 * to retrieve captured substrings.
 * ------------------------------------------------------------------- */
bstring hs_get_app_name_pcre2(signature *sig, const uint8_t *payload,
                              pcre2_match_data *match_data, int rc)
{
    char sub[512];
    char app[5000];
    int i = 0, z = 0;

    /* Build the base application string from title fields.
     * bdata() is captured into a local to satisfy GCC nonnull analysis. */
    const char *p;
    app[0] = '\0';
    if (sig->title.app != NULL && (p = bdata(sig->title.app)) != NULL)
        strncpy(app, p, MAX_APP);
    if (sig->title.ver != NULL && sig->title.ver->slen > 0
        && (p = (const char *)bdata(sig->title.ver)) != NULL) {
        strcat(app, " ");
        strncat(app, p, MAX_VER);
    }
    if (sig->title.misc != NULL && sig->title.misc->slen > 0
        && (p = (const char *)bdata(sig->title.misc)) != NULL) {
        strcat(app, " (");
        strncat(app, p, MAX_MISC);
        strcat(app, ")");
    }

    /* Replace $N placeholders with captured substrings */
    while (app[i] != '\0' && z < (int)(sizeof(sub) - 1)) {
        if (app[i] == '$') {
            i++;
            int n = atoi(&app[i]);

            if (n >= 0 && n < rc) {
                PCRE2_UCHAR *substr = NULL;
                PCRE2_SIZE sublen = 0;
                int ret = pcre2_substring_get_bynumber(
                              match_data, (uint32_t)n, &substr, &sublen);
                if (ret == 0 && substr != NULL) {
                    for (PCRE2_SIZE x = 0; x < sublen && z < (int)(sizeof(sub) - 1); x++) {
                        unsigned char c = (unsigned char)substr[x];
                        if (c >= 0x20 && c != 0x7f)
                            sub[z++] = (char)c;
                    }
                    pcre2_substring_free(substr);
                }
            }
            i++;  /* skip the digit after $ */
        } else {
            sub[z++] = app[i++];
        }
    }
    sub[z] = '\0';
    return bfromcstr(sub);
}

/* -------------------------------------------------------------------
 * hs_get_app_name_static — no captures, build from title fields only
 * ------------------------------------------------------------------- */
bstring hs_get_app_name_static(signature *sig)
{
    char app[5000];
    const char *p;

    app[0] = '\0';
    if (sig->title.app != NULL && (p = bdata(sig->title.app)) != NULL)
        strncpy(app, p, MAX_APP);
    if (sig->title.ver != NULL && sig->title.ver->slen > 0
        && (p = (const char *)bdata(sig->title.ver)) != NULL) {
        strcat(app, " ");
        strncat(app, p, MAX_VER);
    }
    if (sig->title.misc != NULL && sig->title.misc->slen > 0
        && (p = (const char *)bdata(sig->title.misc)) != NULL) {
        strcat(app, " (");
        strncat(app, p, MAX_MISC);
        strcat(app, ")");
    }
    return bfromcstr(app);
}

/* -------------------------------------------------------------------
 * hs_engine_version
 * ------------------------------------------------------------------- */
const char *hs_engine_version(void)
{
    return hs_version();
}

/* ===================================================================
 * Serialized database cache
 * =================================================================== */

#define HS_CACHE_MAGIC      "PRADS_HSDB_V1"
#define HS_CACHE_MAGIC_SIZE 16
#define HS_CACHE_VER_SIZE   32

typedef struct {
    char     magic[HS_CACHE_MAGIC_SIZE];
    char     hs_ver[HS_CACHE_VER_SIZE];  /* Vectorscan version string     */
    uint64_t sig_hash;                   /* FNV-1a of sig file contents   */
    uint32_t batch_count;                /* Number of pattern slots       */
    uint32_t hsdb_size;                  /* Serialized HS database bytes  */
} hs_cache_header_t;

/* FNV-1a 64-bit constants */
#define FNV1A_64_INIT  0xcbf29ce484222325ULL
#define FNV1A_64_PRIME 0x100000001b3ULL

static uint64_t fnv1a_hash_file(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;

    uint64_t h = FNV1A_64_INIT;
    uint8_t buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        for (size_t i = 0; i < n; i++) {
            h ^= buf[i];
            h *= FNV1A_64_PRIME;
        }
    }
    fclose(fp);
    return h;
}

/* Count signatures with valid regex in the linked list */
static uint32_t count_valid_sigs(signature *siglist)
{
    uint32_t n = 0;
    for (signature *s = siglist; s != NULL; s = s->next) {
        if (s->regex_str != NULL && bdata(s->regex_str) != NULL
            && s->regex_str->slen > 0)
            n++;
    }
    return n;
}

/* Compile a PCRE2 pattern for a signature (helper for cache load) */
static void compile_pcre2_for_sig(signature *s)
{
    const char *pat = (const char *)bdata(s->regex_str);
    if (pat == NULL) return;
    int errcode;
    PCRE2_SIZE errofs;
    s->re = pcre2_compile((PCRE2_SPTR)pat, PCRE2_ZERO_TERMINATED,
                          PCRE2_DOTALL, &errcode, &errofs, NULL);
    if (s->re != NULL)
        s->match_data = pcre2_match_data_create_from_pattern(s->re, NULL);
}

/* -------------------------------------------------------------------
 * hs_cache_save
 * ------------------------------------------------------------------- */
int hs_cache_save(const hs_sigdb_t *hsdb, const char *cache_path,
                  const char *sig_file_path, const char *db_label)
{
    if (!hsdb || !hsdb->db || !cache_path || !sig_file_path)
        return -1;

    /* Serialize the HS database to a byte blob */
    char *serialized = NULL;
    size_t serialized_len = 0;
    hs_error_t ret = hs_serialize_database(hsdb->db, &serialized,
                                           &serialized_len);
    if (ret != HS_SUCCESS) {
        olog("[!] hs_cache_save(%s): hs_serialize_database failed (%d)\n",
             db_label, ret);
        return -1;
    }

    /* Build header */
    hs_cache_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    strncpy(hdr.magic, HS_CACHE_MAGIC, HS_CACHE_MAGIC_SIZE);
    strncpy(hdr.hs_ver, hs_version(), HS_CACHE_VER_SIZE);
    hdr.sig_hash    = fnv1a_hash_file(sig_file_path);
    hdr.batch_count = hsdb->hs_count;
    hdr.hsdb_size   = (uint32_t)serialized_len;

    /* Write cache file */
    FILE *fp = fopen(cache_path, "wb");
    if (!fp) {
        dlog("[*] hs_cache_save(%s): cannot write %s (non-fatal)\n",
             db_label, cache_path);
        free(serialized);
        return -1;
    }

    size_t written = 0;
    written += fwrite(&hdr, 1, sizeof(hdr), fp);
    written += fwrite(hsdb->sig_flags, 1, hsdb->hs_count, fp);
    written += fwrite(serialized, 1, serialized_len, fp);
    fclose(fp);
    free(serialized);

    size_t expected = sizeof(hdr) + hsdb->hs_count + serialized_len;
    if (written != expected) {
        olog("[!] hs_cache_save(%s): short write (%zu/%zu), removing %s\n",
             db_label, written, expected, cache_path);
        unlink(cache_path);
        return -1;
    }

    olog("[*] hs_cache_save(%s): cached %u patterns (%zu bytes) to %s\n",
         db_label, hsdb->hs_count, expected, cache_path);
    return 0;
}

/* -------------------------------------------------------------------
 * hs_cache_load
 * ------------------------------------------------------------------- */
hs_sigdb_t *hs_cache_load(signature *siglist, const char *cache_path,
                           const char *sig_file_path, const char *db_label)
{
    if (!siglist || !cache_path || !sig_file_path)
        return NULL;

    FILE *fp = fopen(cache_path, "rb");
    if (!fp) return NULL;

    /* Read header */
    hs_cache_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr)) {
        fclose(fp);
        return NULL;
    }

    /* Validate magic */
    if (memcmp(hdr.magic, HS_CACHE_MAGIC, strlen(HS_CACHE_MAGIC)) != 0) {
        olog("[*] hs_cache_load(%s): invalid magic in %s\n",
             db_label, cache_path);
        fclose(fp);
        return NULL;
    }

    /* Check Vectorscan version — serialized DBs are not portable across versions */
    if (strncmp(hdr.hs_ver, hs_version(), HS_CACHE_VER_SIZE) != 0) {
        olog("[*] hs_cache_load(%s): hs version mismatch "
             "(cached: %.*s, current: %s)\n",
             db_label, HS_CACHE_VER_SIZE, hdr.hs_ver, hs_version());
        fclose(fp);
        return NULL;
    }

    /* Check sig file content hash */
    uint64_t current_hash = fnv1a_hash_file(sig_file_path);
    if (current_hash != hdr.sig_hash) {
        olog("[*] hs_cache_load(%s): sig file changed, cache invalidated\n",
             db_label);
        fclose(fp);
        return NULL;
    }

    /* Verify sig count still matches */
    uint32_t sig_count = count_valid_sigs(siglist);
    if (sig_count != hdr.batch_count) {
        olog("[*] hs_cache_load(%s): sig count mismatch (%u vs cached %u)\n",
             db_label, sig_count, hdr.batch_count);
        fclose(fp);
        return NULL;
    }

    /* Read per-sig flags */
    uint8_t *cached_flags = calloc(hdr.batch_count, sizeof(uint8_t));
    if (!cached_flags) { fclose(fp); return NULL; }
    if (fread(cached_flags, 1, hdr.batch_count, fp) != hdr.batch_count) {
        free(cached_flags);
        fclose(fp);
        return NULL;
    }

    /* Read serialized HS database */
    char *serialized = malloc(hdr.hsdb_size);
    if (!serialized) { free(cached_flags); fclose(fp); return NULL; }
    if (fread(serialized, 1, hdr.hsdb_size, fp) != hdr.hsdb_size) {
        free(cached_flags);
        free(serialized);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    /* Deserialize */
    hs_database_t *db = NULL;
    hs_error_t ret = hs_deserialize_database(serialized, hdr.hsdb_size, &db);
    free(serialized);
    if (ret != HS_SUCCESS) {
        olog("[!] hs_cache_load(%s): hs_deserialize_database failed (%d)\n",
             db_label, ret);
        free(cached_flags);
        return NULL;
    }

    /* Build the hs_sigdb_t */
    hs_sigdb_t *hsdb = calloc(1, sizeof(hs_sigdb_t));
    if (!hsdb) { hs_free_database(db); free(cached_flags); return NULL; }

    hsdb->db = db;
    ret = hs_alloc_scratch(hsdb->db, &hsdb->scratch);
    if (ret != HS_SUCCESS) {
        olog("[!] hs_cache_load(%s): hs_alloc_scratch failed (%d)\n",
             db_label, ret);
        hs_free_database(db);
        free(hsdb);
        free(cached_flags);
        return NULL;
    }

    hsdb->hs_count  = hdr.batch_count;
    hsdb->sig_array = calloc(hdr.batch_count, sizeof(signature *));
    hsdb->sig_flags = calloc(hdr.batch_count, sizeof(uint8_t));
    if (!hsdb->sig_array || !hsdb->sig_flags) {
        hs_sigdb_free(hsdb);
        free(cached_flags);
        return NULL;
    }

    /* Count PCRE2-only patterns for pre-allocation */
    uint32_t pcre2_only_cnt = 0;
    for (uint32_t j = 0; j < hdr.batch_count; j++) {
        if (cached_flags[j] & HS_SIG_PCRE2_ONLY)
            pcre2_only_cnt++;
    }
    signature **pcre2_only_arr = NULL;
    if (pcre2_only_cnt > 0)
        pcre2_only_arr = calloc(pcre2_only_cnt, sizeof(signature *));

    /* Walk the signature linked list and rebuild mappings */
    uint32_t idx = 0;
    uint32_t p2idx = 0;
    for (signature *sig = siglist; sig != NULL; sig = sig->next) {
        if (sig->regex_str == NULL || bdata(sig->regex_str) == NULL
            || sig->regex_str->slen == 0)
            continue;
        if (idx >= hdr.batch_count) break;

        uint8_t sf = cached_flags[idx];
        sig->hs_id    = idx;
        sig->hs_flags = sf;

        if (sf & HS_SIG_PCRE2_ONLY) {
            if (pcre2_only_arr && p2idx < pcre2_only_cnt)
                pcre2_only_arr[p2idx++] = sig;
            compile_pcre2_for_sig(sig);
        } else {
            hsdb->sig_array[idx] = sig;
            hsdb->sig_flags[idx] = sf;
            if (sf & (HS_SIG_CAPTURE | HS_SIG_PREFILTER))
                compile_pcre2_for_sig(sig);
        }
        idx++;
    }

    hsdb->pcre2_only       = pcre2_only_arr;
    hsdb->pcre2_only_count = p2idx;

    free(cached_flags);
    olog("[*] hs_cache_load(%s): loaded %u patterns from cache "
         "(%u PCRE2-only)\n",
         db_label, hsdb->hs_count, hsdb->pcre2_only_count);
    return hsdb;
}
