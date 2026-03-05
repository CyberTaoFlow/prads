/*
** Copyright (C) 2009 Redpill Linpro, AS.
** Copyright (C) 2009 Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
** Copyright (C) 2025 Vectorscan integration
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "../prads.h"
#include "../config.h"
#include "../sys_func.h"
#include "../assets.h"
#include "../hs_engine.h"
#include "servicefp.h"

extern globalconfig config;
extern bstring UNKNOWN;

/* -------------------------------------------------------------------
 * Internal helper: attempt match + app-name extraction for one sig.
 * Returns 1 on confirmed match, 0 on miss (prefilter false positive).
 * ------------------------------------------------------------------- */
static int try_sig_match(signature *sig, uint8_t sflags,
                         const uint8_t *payload, int plen,
                         bstring *out_app)
{
    if (sflags & (HS_SIG_PREFILTER | HS_SIG_CAPTURE)) {
        /* Need PCRE2 for confirmation and/or capture extraction */
        if (sig->re == NULL)
            return 0;
        int rc = pcre2_match(sig->re, (PCRE2_SPTR)payload, plen,
                             0, 0, sig->match_data, NULL);
        if (rc < 0)
            return 0;  /* prefilter false positive or match failure */
        if (sflags & HS_SIG_CAPTURE)
            *out_app = get_app_name(sig, payload, sig->match_data, rc);
        else
            *out_app = hs_get_app_name_static(sig);
        return 1;
    }
    /* Pure Vectorscan match — no PCRE2 needed */
    *out_app = hs_get_app_name_static(sig);
    return 1;
}

/* -------------------------------------------------------------------
 * service_tcp4 / service_tcp6 — TCP server service fingerprinting
 *
 * Hot path: Vectorscan scans all ~N patterns in a single DFA pass.
 * On match, at most one targeted PCRE2 exec for capture extraction.
 * ------------------------------------------------------------------- */
void service_tcp4(packetinfo *pi, signature* sig_serv_tcp)
{
    int tmplen;
    bstring app, service_name;

    (void)sig_serv_tcp; /* signature list no longer walked directly */

    if (pi->plen < PAYLOAD_MIN) return;
    if (pi->plen > 600) tmplen = 600;
        else tmplen = pi->plen;

    if (config.hs_serv_tcp == NULL) return;

    /* Single Vectorscan pass across all patterns */
    hs_match_ctx_t ctx;
    hs_sigdb_scan(config.hs_serv_tcp, (const char *)pi->payload,
                    tmplen, &ctx);

    /* Process matches in ordinal order (first-match-wins) */
    for (int i = 0; i < ctx.count; i++) {
        unsigned int id = ctx.ids[i];
        if (id >= config.hs_serv_tcp->hs_count) continue;
        signature *tmpsig = config.hs_serv_tcp->sig_array[id];
        if (tmpsig == NULL) continue;
        uint8_t sflags    = config.hs_serv_tcp->sig_flags[id];

        if (try_sig_match(tmpsig, sflags, pi->payload, tmplen, &app)) {
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        }
    }

    /* PCRE2-only fallback: linear scan of patterns Vectorscan couldn't compile */
    for (uint32_t j = 0; j < config.hs_serv_tcp->pcre2_only_count; j++) {
        signature *tmpsig = config.hs_serv_tcp->pcre2_only[j];
        if (tmpsig->re == NULL) continue;
        int rc = pcre2_match(tmpsig->re, (PCRE2_SPTR)pi->payload, tmplen,
                             0, 0, tmpsig->match_data, NULL);
        if (rc >= 0) {
            if (tmpsig->hs_flags & HS_SIG_CAPTURE)
                app = get_app_name(tmpsig, pi->payload, tmpsig->match_data, rc);
            else
                app = hs_get_app_name_static(tmpsig);
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        }
    }

    /* No match — try known port fallback */
    if ( !ISSET_SERVICE_UNKNOWN(pi)
        && (service_name = check_known_port(IP_PROTO_TCP,ntohs(pi->s_port))) !=NULL ) {
        update_asset_service(pi, UNKNOWN, service_name);
        pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
        bdestroy(service_name);
    }
}

void service_tcp6(packetinfo *pi, signature* sig_serv_tcp)
{
    int tmplen;
    bstring app, service_name;

    (void)sig_serv_tcp;

    if (pi->plen < 10) return;
    if (pi->plen > 600) tmplen = 600;
        else tmplen = pi->plen;

    if (config.hs_serv_tcp == NULL) return;

    hs_match_ctx_t ctx;
    hs_sigdb_scan(config.hs_serv_tcp, (const char *)pi->payload,
                    tmplen, &ctx);

    for (int i = 0; i < ctx.count; i++) {
        unsigned int id = ctx.ids[i];
        if (id >= config.hs_serv_tcp->hs_count) continue;
        signature *tmpsig = config.hs_serv_tcp->sig_array[id];
        if (tmpsig == NULL) continue;
        uint8_t sflags    = config.hs_serv_tcp->sig_flags[id];

        if (try_sig_match(tmpsig, sflags, pi->payload, tmplen, &app)) {
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        }
    }

    for (uint32_t j = 0; j < config.hs_serv_tcp->pcre2_only_count; j++) {
        signature *tmpsig = config.hs_serv_tcp->pcre2_only[j];
        if (tmpsig->re == NULL) continue;
        int rc = pcre2_match(tmpsig->re, (PCRE2_SPTR)pi->payload, tmplen,
                             0, 0, tmpsig->match_data, NULL);
        if (rc >= 0) {
            if (tmpsig->hs_flags & HS_SIG_CAPTURE)
                app = get_app_name(tmpsig, pi->payload, tmpsig->match_data, rc);
            else
                app = hs_get_app_name_static(tmpsig);
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        }
    }

    if ( !ISSET_SERVICE_UNKNOWN(pi)
        && (service_name = check_known_port(IP_PROTO_TCP,ntohs(pi->s_port))) !=NULL ) {
        update_asset_service(pi, UNKNOWN, service_name);
        pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
        bdestroy(service_name);
    }
}
