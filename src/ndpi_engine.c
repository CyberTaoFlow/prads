#ifdef HAVE_NDPI

#include <string.h>
#include <ndpi_api.h>

#include "common.h"
#include "prads.h"
#include "config.h"
#include "assets.h"
#include "ndpi_engine.h"
#include "sys_func.h"

extern globalconfig config;

#define NDPI_MAX_PKT_CHECK 20

/* ---- internal helper --------------------------------------------------- */

static void ndpi_engine_surface_result(struct _globalconfig *conf,
                                       packetinfo *pi,
                                       struct ndpi_flow_struct *flow,
                                       ndpi_protocol result)
{
    struct ndpi_detection_module_struct *mod =
        (struct ndpi_detection_module_struct *)conf->ndpi_module;
    connection *cxt = pi->cxt;

    u_int16_t master = result.proto.master_protocol;
    u_int16_t app    = result.proto.app_protocol;

    if (master == NDPI_PROTOCOL_UNKNOWN && app == NDPI_PROTOCOL_UNKNOWN)
        return;

    /* Protocol name — once, only if Vectorscan didn't already match */
    if (!(cxt->ndpi_flags & NDPI_FL_HAS_PROTO)
        && !(cxt->check & CXT_SERVICE_DONT_CHECK)) {
        u_int16_t proto_id = (app != NDPI_PROTOCOL_UNKNOWN) ? app : master;
        char *name = ndpi_get_proto_name(mod, proto_id);
        if (name && name[0]) {
            bstring svc = bfromcstr(name);
            bstring appl = bfromcstr(name);
            update_asset_service(pi, svc, appl);
            cxt->ndpi_flags |= NDPI_FL_HAS_PROTO;
        }
    }

    /* Hostname — surface once when available */
    if (!(cxt->ndpi_flags & NDPI_FL_HAS_HOST)
        && flow->host_server_name[0]) {
        bstring svc = bfromcstr("hostname");
        bstring val = bfromcstr((char *)flow->host_server_name);
        update_asset_service(pi, svc, val);
        cxt->ndpi_flags |= NDPI_FL_HAS_HOST;
    }

    /* JA4 — once, only when protocol is TLS/DTLS/QUIC */
    if (!(cxt->ndpi_flags & NDPI_FL_HAS_JA4)
        && (master == NDPI_PROTOCOL_TLS || app == NDPI_PROTOCOL_TLS)
        && flow->protos.tls_quic.ja4_client[0]) {
        bstring svc = bfromcstr("tls-ja4");
        bstring val = bfromcstr(flow->protos.tls_quic.ja4_client);
        update_asset_service(pi, svc, val);
        cxt->ndpi_flags |= NDPI_FL_HAS_JA4;
    }

    /* HTTP User-Agent — once, only for client direction on HTTP flows */
    if (!(cxt->ndpi_flags & NDPI_FL_HAS_UA)
        && (master == NDPI_PROTOCOL_HTTP || app == NDPI_PROTOCOL_HTTP)
        && flow->http.user_agent != NULL
        && pi->sc == SC_CLIENT) {
        bstring svc = bfromcstr("http-useragent");
        bstring val = bfromcstr(flow->http.user_agent);
        update_asset_service(pi, svc, val);
        cxt->ndpi_flags |= NDPI_FL_HAS_UA;
    }
}

/* ---- public API -------------------------------------------------------- */

int ndpi_engine_init(struct _globalconfig *conf)
{
    struct ndpi_global_context *gctx = ndpi_global_init();
    /* gctx may be NULL on older nDPI — that's acceptable */

    struct ndpi_detection_module_struct *mod =
        ndpi_init_detection_module(gctx);
    if (mod == NULL) {
        if (gctx) ndpi_global_deinit(gctx);
        return -1;
    }

    /* Validate ABI compatibility -- a mismatch means the nDPI library was
     * built with a different struct layout than our headers.  Continuing
     * would cause heap buffer overflow on every flow allocation. */
    {
        u_int32_t lib_sz = ndpi_detection_get_sizeof_ndpi_flow_struct();
        u_int32_t hdr_sz = (u_int32_t)sizeof(struct ndpi_flow_struct);
        if (lib_sz != hdr_sz) {
            elog("[!] nDPI ABI mismatch: library ndpi_flow_struct = %u bytes, "
                 "header = %u bytes -- aborting DPI init\n", lib_sz, hdr_sz);
            ndpi_exit_detection_module(mod);
            if (gctx) ndpi_global_deinit(gctx);
            return -1;
        }
    }

    if (ndpi_finalize_initialization(mod) != 0) {
        ndpi_exit_detection_module(mod);
        if (gctx) ndpi_global_deinit(gctx);
        return -1;
    }

    conf->ndpi_module = mod;
    conf->ndpi_gctx   = gctx;

    olog("[*] nDPI %s initialized (%u bytes/flow)\n",
         ndpi_revision(),
         ndpi_detection_get_sizeof_ndpi_flow_struct());
    return 0;
}

void ndpi_engine_destroy(struct _globalconfig *conf)
{
    if (conf->ndpi_module) {
        ndpi_exit_detection_module(
            (struct ndpi_detection_module_struct *)conf->ndpi_module);
        conf->ndpi_module = NULL;
    }
    if (conf->ndpi_gctx) {
        ndpi_global_deinit(
            (struct ndpi_global_context *)conf->ndpi_gctx);
        conf->ndpi_gctx = NULL;
    }
}

void ndpi_engine_process_packet(struct _globalconfig *conf, packetinfo *pi)
{
    struct ndpi_detection_module_struct *mod =
        (struct ndpi_detection_module_struct *)conf->ndpi_module;
    connection *cxt = pi->cxt;

    if (mod == NULL || cxt == NULL)
        return;

    /* Lazy-allocate the per-flow nDPI state.
     *
     * nDPI's own SIZEOF_FLOW_STRUCT macro uses compile-time sizeof,
     * but we use the runtime size from ndpi_detection_get_sizeof_ndpi_flow_struct()
     * for consistency with our ABI check in ndpi_engine_init().  When the
     * ABI matches (which we enforce at init), the two values are identical.
     *
     * Note: zero-init via memset is fragile for a third-party struct whose
     * internals may change across versions.  nDPI does not provide an
     * ndpi_flow_calloc or explicit flow-init function, so memset is
     * currently the only option -- this matches upstream's own pattern
     * in ndpiReader and ndpiSimpleIntegration. */
    if (cxt->ndpi_flow == NULL) {
        u_int32_t flow_sz = ndpi_detection_get_sizeof_ndpi_flow_struct();
        cxt->ndpi_flow = ndpi_flow_malloc(flow_sz);
        if (cxt->ndpi_flow == NULL)
            return;
        memset(cxt->ndpi_flow, 0, flow_sz);
    }

    struct ndpi_flow_struct *flow =
        (struct ndpi_flow_struct *)cxt->ndpi_flow;

    /* Packet budget check */
    uint64_t pkt_count = cxt->s_total_pkts + cxt->d_total_pkts;
    if (pkt_count > NDPI_MAX_PKT_CHECK) {
        ndpi_protocol result = ndpi_detection_giveup(mod, flow);
        cxt->ndpi_flags |= NDPI_FL_GIVEUP;
        ndpi_engine_surface_result(conf, pi, flow, result);
        return;
    }

    /* L3 pointer — use pi->ip4/ip6 directly (inherits VLAN correction) */
    const uint8_t *l3_ptr;
    uint16_t l3_len;
    if (pi->af == AF_INET) {
        l3_ptr = (const uint8_t *)pi->ip4;
    } else {
        l3_ptr = (const uint8_t *)pi->ip6;
    }
    l3_len = (uint16_t)(pi->pheader->caplen - pi->eth_hlen);

    /* Timestamp in milliseconds */
    uint64_t ts_ms = (uint64_t)pi->pheader->ts.tv_sec * 1000ULL
                   + (uint64_t)pi->pheader->ts.tv_usec / 1000ULL;

    /* Direction hint */
    struct ndpi_flow_input_info finfo;
    memset(&finfo, 0, sizeof(finfo));
    finfo.in_pkt_dir = (pi->sc == SC_CLIENT) ? 0 : 1;
    finfo.seen_flow_beginning = (pkt_count <= 1) ? 1 : 0;

    ndpi_protocol result = ndpi_detection_process_packet(
        mod, flow, l3_ptr, l3_len, ts_ms, &finfo);

    /*
     * Surface results progressively:
     * - MONITORING: classification final, but nDPI wants more packets for
     *   metadata (hostname, JA4, etc).  Surface what's available, keep going.
     * - CLASSIFIED: fully done.  Surface final metadata, stop processing.
     */
    if (result.state >= NDPI_STATE_MONITORING) {
        ndpi_engine_surface_result(conf, pi, flow, result);
        if (result.state >= NDPI_STATE_CLASSIFIED)
            cxt->ndpi_flags |= NDPI_FL_DONE;
    }
}

void ndpi_engine_free_flow(connection *cxt)
{
    if (cxt->ndpi_flow != NULL) {
        ndpi_flow_free(cxt->ndpi_flow);
        cxt->ndpi_flow = NULL;
    }
}

#endif /* HAVE_NDPI */
