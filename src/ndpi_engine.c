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

/* ---- internal helpers -------------------------------------------------- */

/* Append nDPI risk flags as a comma-separated list.
 * Only security-relevant risks are surfaced (informational ones skipped). */
static void append_risk_flags(bstring appl, ndpi_risk risk)
{
    if (risk == 0)
        return;

    static const ndpi_risk_enum security_risks[] = {
        NDPI_TLS_SELFSIGNED_CERTIFICATE,
        NDPI_TLS_OBSOLETE_VERSION,
        NDPI_TLS_WEAK_CIPHER,
        NDPI_TLS_CERTIFICATE_EXPIRED,
        NDPI_TLS_CERTIFICATE_MISMATCH,
        NDPI_TLS_MISSING_SNI,
        NDPI_TLS_FATAL_ALERT,
        NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE,
        NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER,
        NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER,
        NDPI_CLEAR_TEXT_CREDENTIALS,
        NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,
        NDPI_SUSPICIOUS_DGA_DOMAIN,
        NDPI_MALICIOUS_FINGERPRINT,
        NDPI_MALICIOUS_SHA1_CERTIFICATE,
        NDPI_MALWARE_HOST_CONTACTED,
        NDPI_POSSIBLE_EXPLOIT,
        NDPI_OBFUSCATED_TRAFFIC,
    };

    int first = 1;
    for (size_t i = 0; i < sizeof(security_risks)/sizeof(security_risks[0]); i++) {
        if (risk & (1ULL << security_risks[i])) {
            if (first) {
                bformata(appl, " {RISK:%s", ndpi_risk2str(security_risks[i]));
                first = 0;
            } else {
                bformata(appl, ",%s", ndpi_risk2str(security_risks[i]));
            }
        }
    }
    if (!first)
        bformata(appl, "}");
}

static void ndpi_engine_surface_result(struct _globalconfig *conf,
                                       packetinfo *pi,
                                       struct ndpi_flow_struct *flow,
                                       ndpi_protocol result)
{
    struct ndpi_detection_module_struct *mod =
        (struct ndpi_detection_module_struct *)conf->ndpi_module;

    u_int16_t master = result.proto.master_protocol;
    u_int16_t app    = result.proto.app_protocol;

    if (master == NDPI_PROTOCOL_UNKNOWN && app == NDPI_PROTOCOL_UNKNOWN)
        return;

    u_int16_t proto_id = (app != NDPI_PROTOCOL_UNKNOWN) ? app : master;
    char *name = ndpi_get_proto_name(mod, proto_id);
    if (!name || !name[0])
        return;

    /* Build ONE combined service entry with all available metadata.
     *
     * We make a single update_asset_service() call per invocation.  The
     * port-based dedup in assets.c uses a superset-replacement check so
     * strings that grow with new metadata ("TLS" → "TLS (foo) [JA4:x]")
     * replace their shorter predecessor immediately.
     *
     * Format examples:
     *   "TLS (host.example.com) [TLSv1.3] [JA4:t12d18...] [cert:*.example.com/Let's Encrypt]"
     *   "SSH [client:OpenSSH_9.7] [HASSH-c:abc123] [server:OpenSSH_9.0] [HASSH-s:def456]"
     *   "HTTP (host.example.com) [Server:nginx/1.24] [UA:Mozilla/5.0...]"
     *   "Kerberos [domain:CORP.LOCAL] [user:jsmith]"
     */
    bstring svc  = bfromcstr(name);
    bstring appl = bfromcstr(name);
    if (svc == NULL || appl == NULL) {
        bdestroy(svc);
        bdestroy(appl);
        return;
    }

    int is_tls = (master == NDPI_PROTOCOL_TLS  || app == NDPI_PROTOCOL_TLS
               || master == NDPI_PROTOCOL_QUIC || app == NDPI_PROTOCOL_QUIC
               || master == NDPI_PROTOCOL_DTLS || app == NDPI_PROTOCOL_DTLS);
    int is_http = (master == NDPI_PROTOCOL_HTTP || app == NDPI_PROTOCOL_HTTP);
    int is_ssh  = (master == NDPI_PROTOCOL_SSH  || app == NDPI_PROTOCOL_SSH);

    /* ── Hostname (TLS SNI, HTTP Host, etc.) ── */
    if (flow->host_server_name[0]) {
        bformata(appl, " (%s)", (char *)flow->host_server_name);
    }

    /* ── TLS / QUIC / DTLS metadata ── */
    if (is_tls) {
        /* TLS version */
        if (flow->protos.tls_quic.ssl_version) {
            char ver_buf[24];
            u_int8_t unknown = 0;
            ndpi_ssl_version2str(ver_buf, sizeof(ver_buf),
                                 flow->protos.tls_quic.ssl_version, &unknown);
            if (!unknown)
                bformata(appl, " [%s]", ver_buf);
        }

        /* JA4 client fingerprint */
        if (flow->protos.tls_quic.ja4_client[0])
            bformata(appl, " [JA4:%s]", flow->protos.tls_quic.ja4_client);

        /* JA3 server fingerprint */
        if (flow->protos.tls_quic.ja3_server[0])
            bformata(appl, " [JA3s:%s]", flow->protos.tls_quic.ja3_server);

        /* Negotiated ALPN (h2, http/1.1, etc.) */
        if (flow->protos.tls_quic.negotiated_alpn != NULL
            && flow->protos.tls_quic.negotiated_alpn[0])
            bformata(appl, " [ALPN:%s]", flow->protos.tls_quic.negotiated_alpn);

        /* Certificate CN/SAN and issuer — compact "cert:CN/Issuer" */
        if (flow->protos.tls_quic.server_names != NULL
            && flow->protos.tls_quic.server_names[0]) {
            if (flow->protos.tls_quic.issuerDN != NULL
                && flow->protos.tls_quic.issuerDN[0])
                bformata(appl, " [cert:%s/%s]",
                         flow->protos.tls_quic.server_names,
                         flow->protos.tls_quic.issuerDN);
            else
                bformata(appl, " [cert:%s]",
                         flow->protos.tls_quic.server_names);
        }

        /* Cipher strength warning */
        if (flow->protos.tls_quic.server_unsafe_cipher == ndpi_cipher_weak)
            bformata(appl, " [WEAK-CIPHER]");
        else if (flow->protos.tls_quic.server_unsafe_cipher == ndpi_cipher_insecure)
            bformata(appl, " [INSECURE-CIPHER]");
    }

    /* ── SSH metadata ── */
    if (is_ssh) {
        if (pi->sc == SC_CLIENT) {
            if (flow->protos.ssh.client_signature[0])
                bformata(appl, " [client:%s]", flow->protos.ssh.client_signature);
            if (flow->protos.ssh.hassh_client[0])
                bformata(appl, " [HASSH-c:%s]", flow->protos.ssh.hassh_client);
        } else {
            if (flow->protos.ssh.server_signature[0])
                bformata(appl, " [server:%s]", flow->protos.ssh.server_signature);
            if (flow->protos.ssh.hassh_server[0])
                bformata(appl, " [HASSH-s:%s]", flow->protos.ssh.hassh_server);
        }
    }

    /* ── HTTP metadata ── */
    if (is_http) {
        if (flow->http.server != NULL && flow->http.server[0])
            bformata(appl, " [Server:%s]", flow->http.server);
        if (flow->http.user_agent != NULL && pi->sc == SC_CLIENT) {
            /* Truncate excessively long User-Agents */
            char ua_buf[257];
            snprintf(ua_buf, sizeof(ua_buf), "%s", flow->http.user_agent);
            bformata(appl, " [UA:%s]", ua_buf);
        }
    }

    /* ── Kerberos metadata ── */
    if (master == NDPI_PROTOCOL_KERBEROS || app == NDPI_PROTOCOL_KERBEROS) {
        if (flow->protos.kerberos.domain[0])
            bformata(appl, " [domain:%s]", flow->protos.kerberos.domain);
        if (flow->protos.kerberos.hostname[0])
            bformata(appl, " [host:%s]", flow->protos.kerberos.hostname);
        if (flow->protos.kerberos.username[0])
            bformata(appl, " [user:%s]", flow->protos.kerberos.username);
    }

    /* ── Security risk flags ── */
    append_risk_flags(appl, flow->risk);

    update_asset_service(pi, svc, appl);
    bdestroy(svc);
    bdestroy(appl);
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
    /* prads always tracks flows from the SYN — tell nDPI we saw the
     * beginning so it can properly parse TLS ClientHello metadata
     * (SNI, JA4).  The old (pkt_count <= 1) test was always 0 for TCP
     * data packets because SYN/SYNACK/ACK are counted first. */
    finfo.seen_flow_beginning = 1;

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
