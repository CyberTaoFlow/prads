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
#include "../assets.h"
#include "../cxt.h"
#include "../hs_engine.h"
#include "servicefp.h"

extern globalconfig config;
extern bstring UNKNOWN;

static int try_sig_match(signature *sig, uint8_t sflags,
                         const uint8_t *payload, int plen,
                         bstring *out_app)
{
    if (sflags & (HS_SIG_PREFILTER | HS_SIG_CAPTURE)) {
        if (sig->re == NULL)
            return 0;
        int rc = pcre2_match(sig->re, (PCRE2_SPTR)payload, plen,
                             0, 0, sig->match_data, NULL);
        if (rc < 0)
            return 0;
        if (sflags & HS_SIG_CAPTURE)
            *out_app = get_app_name(sig, payload, sig->match_data, rc);
        else
            *out_app = hs_get_app_name_static(sig);
        return 1;
    }
    *out_app = hs_get_app_name_static(sig);
    return 1;
}

void service_udp4(packetinfo *pi, signature* sig_serv_udp)
{
    bstring app, service_name;
    app = service_name = NULL;

    (void)sig_serv_udp;

    if (pi->plen < 5 ) return;

    if (config.hs_serv_udp == NULL) return;

    hs_match_ctx_t ctx;
    hs_sigdb_scan(config.hs_serv_udp, (const char *)pi->payload,
                  pi->plen, &ctx);

    for (int i = 0; i < ctx.count; i++) {
        unsigned int id = ctx.ids[i];
        if (id >= config.hs_serv_udp->hs_count) continue;
        signature *tmpsig = config.hs_serv_udp->sig_array[id];
        if (tmpsig == NULL) continue;
        uint8_t sflags    = config.hs_serv_udp->sig_flags[id];

        if (try_sig_match(tmpsig, sflags, pi->payload, pi->plen, &app)) {
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        }
    }

    for (uint32_t j = 0; j < config.hs_serv_udp->pcre2_only_count; j++) {
        signature *tmpsig = config.hs_serv_udp->pcre2_only[j];
        if (tmpsig->re == NULL) continue;
        int rc = pcre2_match(tmpsig->re, (PCRE2_SPTR)pi->payload, pi->plen,
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

udp4_fallback:
    /* 
     * If no sig is found/matched, use default port to determine.
     */
    if (pi->sc == SC_CLIENT && !ISSET_CLIENT_UNKNOWN(pi)) {
        if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->d_port))) !=NULL ) {
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_CLIENT_UNKNOWN_SET;
            bdestroy(service_name);
        } else if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->s_port))) !=NULL ) {
            reverse_pi_cxt(pi);
            pi->d_port = pi->udph->src_port;
            update_asset_service(pi, UNKNOWN, service_name);
            pi->d_port = pi->udph->dst_port;
            pi->cxt->check |= CXT_CLIENT_UNKNOWN_SET;
            bdestroy(service_name);
        }
    } else if (pi->sc == SC_SERVER && !ISSET_SERVICE_UNKNOWN(pi)) {
        if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->s_port))) !=NULL ) {
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
            bdestroy(service_name);
        } else if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->d_port))) !=NULL ) {
            reverse_pi_cxt(pi);
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
            bdestroy(service_name);
        }
    }
}

void service_udp6(packetinfo *pi, signature* sig_serv_udp)
{
    int tmplen;
    bstring app, service_name;

    (void)sig_serv_udp;
    
    if (pi->plen < 5) return; 
    if (pi->plen > 600) tmplen = 600;
        else tmplen = pi->plen;

    if (config.hs_serv_udp == NULL) return;

    hs_match_ctx_t ctx;
    hs_sigdb_scan(config.hs_serv_udp, (const char *)pi->payload,
                  tmplen, &ctx);

    for (int i = 0; i < ctx.count; i++) {
        unsigned int id = ctx.ids[i];
        if (id >= config.hs_serv_udp->hs_count) continue;
        signature *tmpsig = config.hs_serv_udp->sig_array[id];
        if (tmpsig == NULL) continue;
        uint8_t sflags    = config.hs_serv_udp->sig_flags[id];

        if (try_sig_match(tmpsig, sflags, pi->payload, tmplen, &app)) {
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        }
    }

    for (uint32_t j = 0; j < config.hs_serv_udp->pcre2_only_count; j++) {
        signature *tmpsig = config.hs_serv_udp->pcre2_only[j];
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

udp6_fallback:
    if (pi->sc == SC_CLIENT && !ISSET_CLIENT_UNKNOWN(pi)) {
        if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->d_port))) !=NULL ) {
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_CLIENT_UNKNOWN_SET;
            bdestroy(service_name);
        } else if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->s_port))) !=NULL ) {
            reverse_pi_cxt(pi);
            pi->d_port = pi->udph->src_port;
            update_asset_service(pi, UNKNOWN, service_name);
            pi->d_port = pi->udph->dst_port;
            pi->cxt->check |= CXT_CLIENT_UNKNOWN_SET;
            bdestroy(service_name);
        }
    } else if (pi->sc == SC_SERVER && !ISSET_SERVICE_UNKNOWN(pi)) {
        if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->s_port))) !=NULL ) {
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
            bdestroy(service_name);
        } else if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->d_port))) !=NULL ) {
            reverse_pi_cxt(pi);
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
            bdestroy(service_name);
        }
    }
}
