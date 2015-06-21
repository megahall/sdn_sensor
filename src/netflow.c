/*
 * Copyright (c) 2004, 2005 Damien Miller <djm@mindrot.org>
 * Copyright (c) 2014 Matthew Hall <mhall@mhcomputing.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <bsd/string.h>
#include <bsd/sys/queue.h>
#include <bsd/sys/tree.h>

#include <rte_log.h>
#include <rte_memcpy.h>

#include <jemalloc/jemalloc.h>

#include "sdn_sensor.h"

#include "common.h"
#include "ioc.h"
#include "metadata.h"
#include "netflow.h"
#include "netflow_addr.h"
#include "netflow_common.h"
#include "netflow_format.h"
#include "netflow_log.h"
#include "netflow_packet.h"
#include "netflow_peer.h"
#include "nn_queue.h"
#include "sensor_conf.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wsign-compare"

/* Dump unknown packet types */
#define DEBUG 1

/* Reams of netflow v.9 verbosity */
#define DEBUG_NF9 1

/* Reams of netflow v.10 verbosity */
#define DEBUG_NF10 1

/* Prototype this (can't make it static because it only #ifdef DEBUG) */
void dump_packet(const char *tag, const u_int8_t *p, u_int len);

/* XXX: mhall: global so netflow_peer.c can use the peers_lock */
struct peers netflow_peers;

/* Input queue management */

struct flow_packet {
    TAILQ_ENTRY(flow_packet) entry;
    struct timeval recv_time;
    struct xaddr flow_source;
    u_int len;
    u_int8_t* packet;
};

/* Allocate a new packet (XXX: make this use a pool of preallocated entries) */
struct flow_packet* flow_packet_alloc(void)
{
    return (je_calloc(1, sizeof(struct flow_packet)));
}

/* Deallocate a flow packet (XXX: change to return entry to freelist) */
void flow_packet_dealloc(struct flow_packet* f)
{
    if (f->packet != NULL)
        je_free(f->packet);
    je_free(f);
}

/* Format data to a hex string */
const char* data_ntoa(const u_int8_t* p, u_int len)
{
    static char buf[2048];
    char tmp[3];
    int i;

    for (*buf = '\0', i = 0; i < len; i++) {
        snprintf(tmp, sizeof(tmp), "%02x%s", p[i], i % 2 ? " " : "");
        if (strlcat(buf, tmp, sizeof(buf) - 4) >= sizeof(buf) - 4) {
            strlcat(buf, "...", sizeof(buf));
            break;
        }
    }
    return (buf);
}

/* Dump a packet */
void
dump_packet(const char* tag, const u_int8_t* p, u_int len)
{
    if (tag == NULL)
        logit(LOG_INFO, "packet len %d: %s", len, data_ntoa(p, len));
    else {
        logit(LOG_INFO, "%s: packet len %d: %s",
            tag, len, data_ntoa(p, len));
    }
}

/*
 * Netflow frame extractor function
 * Match netflow metadata against ioc_entries
 * Relay matches to appropriate nm_queue
 */
int process_flow(struct store_flow_complete* flow) {
    ss_ioc_entry_t* iptr;
    uint8_t* metadata = NULL;
    size_t mlength = 0;
    int rv = 0;
    
    /* Another sanity check */
    if (flow->src_addr.af != flow->dst_addr.af) {
        logit(LOG_WARNING, "%s: flow src(%d)/dst(%d) AF mismatch",
            __func__, flow->src_addr.af, flow->dst_addr.af);
        return -1;
    }

    /* Prepare for writing */
    flow->hdr.fields = htonl(flow->hdr.fields);
    flow->recv_time.recv_sec = htonl(flow->recv_time.recv_sec);
    flow->recv_time.recv_usec = htonl(flow->recv_time.recv_usec);
    
    /* mhall hardcoded verbose */
    char fmtbuf[1024];
    netflow_format_flow(flow, fmtbuf, sizeof(fmtbuf), 0,
        STORE_DISPLAY_ALL, 0);
    logit(LOG_DEBUG, "%s: ACCEPT flow %s", __func__, fmtbuf);
    
    iptr = ss_ioc_netflow_match(flow);
    if (iptr) {
        // match
        RTE_LOG(NOTICE, EXTRACTOR, "successful netflow ioc match from frame\n");
        ss_ioc_entry_dump_dpdk(iptr);
        nn_queue_t* nn_queue = &ss_conf->ioc_files[iptr->file_id].nn_queue;
        // XXX: fill in something useful in rule field
        metadata = ss_metadata_prepare_netflow("netflow_ioc", NULL, nn_queue, flow, iptr);
        // XXX: for now assume the output is C char*
        mlength = strlen((char*) metadata);
        //printf("metadata: %s\n", metadata);
        rv = ss_nn_queue_send(nn_queue, metadata, (uint16_t) mlength);
    }
    
    return rv;
}

void process_netflow_v1(struct flow_packet* fp, struct peer_state* peer)
{
    struct NF1_HEADER* nf1_hdr = (struct NF1_HEADER*)fp->packet;
    struct NF1_FLOW* nf1_flow;
    struct store_flow_complete flow;
    size_t offset;
    u_int i, nflows;

    if (fp->len < sizeof(*nf1_hdr)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short netflow v.1 packet %d bytes from %s",
            fp->len, addr_ntop_buf(&fp->flow_source));
        return;
    }
    nflows = ntohs(nf1_hdr->c.flows);
    if (nflows == 0 || nflows > NF1_MAXFLOWS) {
        peer->ninvalid++;
        logit(LOG_WARNING, "Invalid number of flows (%u) in netflow "
            "v.1 packet from %s", nflows,
            addr_ntop_buf(&fp->flow_source));
        return;
    }
    if (fp->len != NF1_PACKET_SIZE(nflows)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "Inconsistent Netflow v.1 packet from %s: "
            "len %u expected %zu", addr_ntop_buf(&fp->flow_source),
            fp->len, NF1_PACKET_SIZE(nflows));
        return;
    }

    logit(LOG_DEBUG, "Valid netflow v.1 packet %d flows", nflows);
    update_peer(peer, nflows, 1);

    for (i = 0; i < nflows; i++) {
        offset = NF1_PACKET_SIZE(i);
        nf1_flow = (struct NF1_FLOW*)(fp->packet + offset);

        bzero(&flow, sizeof(flow));

        /* NB. These are converted to network byte order later */
        flow.hdr.fields = STORE_FIELD_ALL;
        /* flow.hdr.tag is set later */
        flow.hdr.fields &= ~STORE_FIELD_TAG;
        flow.hdr.fields &= ~STORE_FIELD_SRC_ADDR6;
        flow.hdr.fields &= ~STORE_FIELD_DST_ADDR6;
        flow.hdr.fields &= ~STORE_FIELD_GATEWAY_ADDR6;
        flow.hdr.fields &= ~STORE_FIELD_AS_INFO;
        flow.hdr.fields &= ~STORE_FIELD_FLOW_ENGINE_INFO;

        flow.recv_time.recv_sec = fp->recv_time.tv_sec;
        flow.recv_time.recv_usec = fp->recv_time.tv_usec;

        flow.pft.tcp_flags = nf1_flow->tcp_flags;
        flow.pft.protocol = nf1_flow->protocol;
        flow.pft.tos = nf1_flow->tos;

        rte_memcpy(&flow.agent_addr, &fp->flow_source,
            sizeof(flow.agent_addr));

        flow.src_addr.v4.s_addr = nf1_flow->src_ip;
        flow.src_addr.af = AF_INET;
        flow.dst_addr.v4.s_addr = nf1_flow->dest_ip;
        flow.dst_addr.af = AF_INET;
        flow.gateway_addr.v4.s_addr = nf1_flow->nexthop_ip;
        flow.gateway_addr.af = AF_INET;

        flow.ports.src_port = nf1_flow->src_port;
        flow.ports.dst_port = nf1_flow->dest_port;

#define NTO64(a) (netflow_htonll(ntohl(a)))
        flow.octets.flow_octets = NTO64(nf1_flow->flow_octets);
        flow.packets.flow_packets = NTO64(nf1_flow->flow_packets);
#undef NTO64

        flow.ifndx.if_index_in = htonl(ntohs(nf1_flow->if_index_in));
        flow.ifndx.if_index_out = htonl(ntohs(nf1_flow->if_index_out));

        flow.ainfo.sys_uptime_ms = nf1_hdr->uptime_ms;
        flow.ainfo.time_sec = nf1_hdr->time_sec;
        flow.ainfo.time_nanosec = nf1_hdr->time_nanosec;
        flow.ainfo.netflow_version = nf1_hdr->c.version;

        flow.ftimes.flow_start = nf1_flow->flow_start;
        flow.ftimes.flow_finish = nf1_flow->flow_finish;

        process_flow(&flow);
    }
}

void process_netflow_v5(struct flow_packet* fp, struct peer_state* peer)
{
    struct NF5_HEADER* nf5_hdr = (struct NF5_HEADER*)fp->packet;
    struct NF5_FLOW* nf5_flow;
    struct store_flow_complete flow;
    size_t offset;
    u_int i, nflows;

    if (fp->len < sizeof(*nf5_hdr)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short netflow v.5 packet %d bytes from %s",
            fp->len, addr_ntop_buf(&fp->flow_source));
        return;
    }
    nflows = ntohs(nf5_hdr->c.flows);
    if (nflows == 0 || nflows > NF5_MAXFLOWS) {
        peer->ninvalid++;
        logit(LOG_WARNING, "Invalid number of flows (%u) in netflow "
            "v.5 packet from %s", nflows,
            addr_ntop_buf(&fp->flow_source));
        return;
    }
    if (fp->len != NF5_PACKET_SIZE(nflows)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "Inconsistent Netflow v.5 packet from %s: "
            "len %u expected %zu", addr_ntop_buf(&fp->flow_source),
            fp->len, NF5_PACKET_SIZE(nflows));
        return;
    }

    logit(LOG_DEBUG, "Valid netflow v.5 packet %d flows", nflows);
    update_peer(peer, nflows, 5);

    for (i = 0; i < nflows; i++) {
        offset = NF5_PACKET_SIZE(i);
        nf5_flow = (struct NF5_FLOW*)(fp->packet + offset);

        bzero(&flow, sizeof(flow));

        /* NB. These are converted to network byte order later */
        flow.hdr.fields = STORE_FIELD_ALL;
        /* flow.hdr.tag is set later */
        flow.hdr.fields &= ~STORE_FIELD_TAG;
        flow.hdr.fields &= ~STORE_FIELD_SRC_ADDR6;
        flow.hdr.fields &= ~STORE_FIELD_DST_ADDR6;
        flow.hdr.fields &= ~STORE_FIELD_GATEWAY_ADDR6;

        flow.recv_time.recv_sec = fp->recv_time.tv_sec;
        flow.recv_time.recv_usec = fp->recv_time.tv_usec;

        flow.pft.tcp_flags = nf5_flow->tcp_flags;
        flow.pft.protocol = nf5_flow->protocol;
        flow.pft.tos = nf5_flow->tos;

        rte_memcpy(&flow.agent_addr, &fp->flow_source,
            sizeof(flow.agent_addr));

        flow.src_addr.v4.s_addr = nf5_flow->src_ip;
        flow.src_addr.af = AF_INET;
        flow.dst_addr.v4.s_addr = nf5_flow->dest_ip;
        flow.dst_addr.af = AF_INET;
        flow.gateway_addr.v4.s_addr = nf5_flow->nexthop_ip;
        flow.gateway_addr.af = AF_INET;

        flow.ports.src_port = nf5_flow->src_port;
        flow.ports.dst_port = nf5_flow->dest_port;

#define NTO64(a) (netflow_htonll(ntohl(a)))
        flow.octets.flow_octets = NTO64(nf5_flow->flow_octets);
        flow.packets.flow_packets = NTO64(nf5_flow->flow_packets);
#undef NTO64

        flow.ifndx.if_index_in = htonl(ntohs(nf5_flow->if_index_in));
        flow.ifndx.if_index_out = htonl(ntohs(nf5_flow->if_index_out));

        flow.ainfo.sys_uptime_ms = nf5_hdr->uptime_ms;
        flow.ainfo.time_sec = nf5_hdr->time_sec;
        flow.ainfo.time_nanosec = nf5_hdr->time_nanosec;
        flow.ainfo.netflow_version = nf5_hdr->c.version;

        flow.ftimes.flow_start = nf5_flow->flow_start;
        flow.ftimes.flow_finish = nf5_flow->flow_finish;

        flow.asinf.src_as = htonl(ntohs(nf5_flow->src_as));
        flow.asinf.dst_as = htonl(ntohs(nf5_flow->dest_as));
        flow.asinf.src_mask = nf5_flow->src_mask;
        flow.asinf.dst_mask = nf5_flow->dst_mask;

        flow.finf.engine_type = nf5_hdr->engine_type;
        flow.finf.engine_id = nf5_hdr->engine_id;
        flow.finf.flow_sequence = nf5_hdr->flow_sequence;

        process_flow(&flow);
    }
}

void process_netflow_v7(struct flow_packet* fp, struct peer_state* peer)
{
    struct NF7_HEADER* nf7_hdr = (struct NF7_HEADER*)fp->packet;
    struct NF7_FLOW* nf7_flow;
    struct store_flow_complete flow;
    size_t offset;
    u_int i, nflows;

    if (fp->len < sizeof(*nf7_hdr)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short netflow v.7 packet %d bytes from %s",
            fp->len, addr_ntop_buf(&fp->flow_source));
        return;
    }
    nflows = ntohs(nf7_hdr->c.flows);
    if (nflows == 0 || nflows > NF7_MAXFLOWS) {
        peer->ninvalid++;
        logit(LOG_WARNING, "Invalid number of flows (%u) in netflow "
            "v.7 packet from %s", nflows,
            addr_ntop_buf(&fp->flow_source));
        return;
    }
    if (fp->len != NF7_PACKET_SIZE(nflows)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "Inconsistent Netflow v.7 packet from %s: "
            "len %u expected %zu", addr_ntop_buf(&fp->flow_source),
            fp->len, NF7_PACKET_SIZE(nflows));
        return;
    }

    logit(LOG_DEBUG, "Valid netflow v.7 packet %d flows", nflows);
    update_peer(peer, nflows, 7);

    for (i = 0; i < nflows; i++) {
        offset = NF7_PACKET_SIZE(i);
        nf7_flow = (struct NF7_FLOW*)(fp->packet + offset);

        bzero(&flow, sizeof(flow));

        /* NB. These are converted to network byte order later */
        flow.hdr.fields = STORE_FIELD_ALL;
        /* flow.hdr.tag is set later */
        flow.hdr.fields &= ~STORE_FIELD_TAG;
        flow.hdr.fields &= ~STORE_FIELD_SRC_ADDR6;
        flow.hdr.fields &= ~STORE_FIELD_DST_ADDR6;
        flow.hdr.fields &= ~STORE_FIELD_GATEWAY_ADDR6;

        /*
         * XXX: we can parse the (undocumented) flags1 and flags2
         * fields of the packet to disable flow fields not set by
         * the Cat5k (e.g. destination-only mls nde mode)
         */

        flow.recv_time.recv_sec = fp->recv_time.tv_sec;
        flow.recv_time.recv_usec = fp->recv_time.tv_usec;

        flow.pft.tcp_flags = nf7_flow->tcp_flags;
        flow.pft.protocol = nf7_flow->protocol;
        flow.pft.tos = nf7_flow->tos;

        rte_memcpy(&flow.agent_addr, &fp->flow_source,
            sizeof(flow.agent_addr));

        flow.src_addr.v4.s_addr = nf7_flow->src_ip;
        flow.src_addr.af = AF_INET;
        flow.dst_addr.v4.s_addr = nf7_flow->dest_ip;
        flow.dst_addr.af = AF_INET;
        flow.gateway_addr.v4.s_addr = nf7_flow->nexthop_ip;
        flow.gateway_addr.af = AF_INET;

        flow.ports.src_port = nf7_flow->src_port;
        flow.ports.dst_port = nf7_flow->dest_port;

#define NTO64(a) (netflow_htonll(ntohl(a)))
        flow.octets.flow_octets = NTO64(nf7_flow->flow_octets);
        flow.packets.flow_packets = NTO64(nf7_flow->flow_packets);
#undef NTO64

        flow.ifndx.if_index_in = htonl(ntohs(nf7_flow->if_index_in));
        flow.ifndx.if_index_out = htonl(ntohs(nf7_flow->if_index_out));

        flow.ainfo.sys_uptime_ms = nf7_hdr->uptime_ms;
        flow.ainfo.time_sec = nf7_hdr->time_sec;
        flow.ainfo.time_nanosec = nf7_hdr->time_nanosec;
        flow.ainfo.netflow_version = nf7_hdr->c.version;

        flow.ftimes.flow_start = nf7_flow->flow_start;
        flow.ftimes.flow_finish = nf7_flow->flow_finish;

        flow.asinf.src_as = htonl(ntohs(nf7_flow->src_as));
        flow.asinf.dst_as = htonl(ntohs(nf7_flow->dest_as));
        flow.asinf.src_mask = nf7_flow->src_mask;
        flow.asinf.dst_mask = nf7_flow->dst_mask;

        flow.finf.flow_sequence = nf7_hdr->flow_sequence;

        process_flow(&flow);
    }
}

int nf9_rec_to_flow(struct peer_nf9_record* rec, struct store_flow_complete* flow, u_int8_t* data)
{
    /* XXX: use a table-based interpreter */
    switch (rec->type) {

/* Copy an int (possibly shorter than the target) keeping their LSBs aligned */
#define BE_COPY(a) rte_memcpy((u_char*)&a + (sizeof(a) - rec->len), data, rec->len);
#define V9_FIELD(v9_field, store_field, flow_field) \
    case v9_field: \
        flow->hdr.fields |= STORE_FIELD_##store_field; \
        BE_COPY(flow->flow_field); \
        break
#define V9_FIELD_ADDR(v9_field, store_field, flow_field, sub, family) \
    case v9_field: \
        flow->hdr.fields |= STORE_FIELD_##store_field; \
        rte_memcpy(&flow->flow_field.v##sub, data, rec->len); \
        flow->flow_field.af = AF_##family; \
        break

    V9_FIELD(NF9_IN_BYTES, OCTETS, octets.flow_octets);
    V9_FIELD(NF9_IN_PACKETS, PACKETS, packets.flow_packets);
    V9_FIELD(NF9_IN_PROTOCOL, PROTO_FLAGS_TOS, pft.protocol);
    V9_FIELD(NF9_SRC_TOS, PROTO_FLAGS_TOS, pft.tos);
    V9_FIELD(NF9_TCP_FLAGS, PROTO_FLAGS_TOS, pft.tcp_flags);
    V9_FIELD(NF9_L4_SRC_PORT, SRCDST_PORT, ports.src_port);
    V9_FIELD(NF9_SRC_MASK, AS_INFO, asinf.src_mask);
    V9_FIELD(NF9_INPUT_SNMP, IF_INDICES, ifndx.if_index_in);
    V9_FIELD(NF9_L4_DST_PORT, SRCDST_PORT, ports.dst_port);
    V9_FIELD(NF9_DST_MASK, AS_INFO, asinf.dst_mask);
    V9_FIELD(NF9_OUTPUT_SNMP, IF_INDICES, ifndx.if_index_out);
    V9_FIELD(NF9_SRC_AS, AS_INFO, asinf.src_as);
    V9_FIELD(NF9_DST_AS, AS_INFO, asinf.dst_as);
    V9_FIELD(NF9_LAST_SWITCHED, FLOW_TIMES, ftimes.flow_finish);
    V9_FIELD(NF9_FIRST_SWITCHED, FLOW_TIMES, ftimes.flow_start);
    V9_FIELD(NF9_IPV6_SRC_MASK, AS_INFO, asinf.src_mask);
    V9_FIELD(NF9_IPV6_DST_MASK, AS_INFO, asinf.dst_mask);
    V9_FIELD(NF9_ENGINE_TYPE, FLOW_ENGINE_INFO, finf.engine_type);
    V9_FIELD(NF9_ENGINE_ID, FLOW_ENGINE_INFO, finf.engine_id);

    V9_FIELD_ADDR(NF9_IPV4_SRC_ADDR, SRC_ADDR4, src_addr, 4, INET);
    V9_FIELD_ADDR(NF9_IPV4_DST_ADDR, DST_ADDR4, dst_addr, 4, INET);
    V9_FIELD_ADDR(NF9_IPV4_NEXT_HOP, GATEWAY_ADDR4, gateway_addr, 4, INET);

    V9_FIELD_ADDR(NF9_IPV6_SRC_ADDR, SRC_ADDR6, src_addr, 6, INET6);
    V9_FIELD_ADDR(NF9_IPV6_DST_ADDR, DST_ADDR6, dst_addr, 6, INET6);
    V9_FIELD_ADDR(NF9_IPV6_NEXT_HOP, GATEWAY_ADDR6, gateway_addr, 6, INET6);

#undef V9_FIELD
#undef V9_FIELD_ADDR
#undef BE_COPY
    }
    return (0);
}

int nf9_check_rec_len(u_int type, u_int len)
{
    struct store_flow_complete t;

    /* Sanity check */
    if (len == 0 || len > 0x4000)
        return (0);

    /* XXX: use a table-based interpreter */
    switch (type) {
#define V9_FIELD_LEN(v9_field, flow_field) \
    case v9_field: \
        return (len <= sizeof(t.flow_field));

    V9_FIELD_LEN(NF9_IN_BYTES, octets.flow_octets);
    V9_FIELD_LEN(NF9_IN_PACKETS, packets.flow_packets);
    V9_FIELD_LEN(NF9_IN_PROTOCOL, pft.protocol);
    V9_FIELD_LEN(NF9_SRC_TOS, pft.tos);
    V9_FIELD_LEN(NF9_TCP_FLAGS, pft.tcp_flags);
    V9_FIELD_LEN(NF9_L4_SRC_PORT, ports.src_port);
    V9_FIELD_LEN(NF9_IPV4_SRC_ADDR, src_addr.v4);
    V9_FIELD_LEN(NF9_SRC_MASK, asinf.src_mask);
    V9_FIELD_LEN(NF9_INPUT_SNMP, ifndx.if_index_in);
    V9_FIELD_LEN(NF9_L4_DST_PORT, ports.dst_port);
    V9_FIELD_LEN(NF9_IPV4_DST_ADDR, dst_addr.v4);
    V9_FIELD_LEN(NF9_DST_MASK, asinf.src_mask);
    V9_FIELD_LEN(NF9_OUTPUT_SNMP, ifndx.if_index_out);
    V9_FIELD_LEN(NF9_IPV4_NEXT_HOP, gateway_addr.v4);
    V9_FIELD_LEN(NF9_SRC_AS, asinf.src_as);
    V9_FIELD_LEN(NF9_DST_AS, asinf.dst_as);
    V9_FIELD_LEN(NF9_LAST_SWITCHED, ftimes.flow_finish);
    V9_FIELD_LEN(NF9_FIRST_SWITCHED, ftimes.flow_start);
    V9_FIELD_LEN(NF9_IPV6_SRC_ADDR, src_addr.v6);
    V9_FIELD_LEN(NF9_IPV6_DST_ADDR, dst_addr.v6);
    V9_FIELD_LEN(NF9_IPV6_SRC_MASK, asinf.src_mask);
    V9_FIELD_LEN(NF9_IPV6_DST_MASK, asinf.dst_mask);
    V9_FIELD_LEN(NF9_ENGINE_TYPE, finf.engine_type);
    V9_FIELD_LEN(NF9_ENGINE_ID, finf.engine_id);
    V9_FIELD_LEN(NF9_IPV6_NEXT_HOP, gateway_addr.v6);

#undef V9_FIELD_LEN
    default:
        return (1);
    }
}

int nf9_flowset_to_store(u_int8_t* pkt, size_t len, struct timeval* tv, 
    struct xaddr* flow_source, struct NF9_HEADER* nf9_hdr,
    struct peer_nf9_template* template, u_int32_t source_id,
    struct store_flow_complete* flow)
{
    u_int offset, i;

    if (template->total_len > len)
        return (-1);

    bzero(flow, sizeof(*flow));

    flow->hdr.fields = STORE_FIELD_RECV_TIME | STORE_FIELD_AGENT_INFO |
        STORE_FIELD_AGENT_ADDR | STORE_FIELD_FLOW_ENGINE_INFO;
    flow->ainfo.sys_uptime_ms = nf9_hdr->uptime_ms;
    flow->ainfo.time_sec = nf9_hdr->time_sec;
    flow->ainfo.netflow_version = nf9_hdr->c.version;
    flow->finf.flow_sequence = nf9_hdr->package_sequence;
    flow->finf.source_id = htonl(source_id);
    flow->recv_time.recv_sec = tv->tv_sec;
    flow->recv_time.recv_usec = tv->tv_usec;
    rte_memcpy(&flow->agent_addr, flow_source, sizeof(flow->agent_addr));

    offset = 0;
    for (i = 0; i < template->num_records; i++) {
#ifdef DEBUG_NF9
        logit(LOG_DEBUG, "    record %d: type %d len %d: %s",
            i, template->records[i].type, template->records[i].len,
            data_ntoa(pkt + offset, template->records[i].len));
#endif
        nf9_rec_to_flow(&template->records[i], flow, pkt + offset);
        offset += template->records[i].len;
    }
    return (0);
}

int process_netflow_v9_template(u_int8_t* pkt, size_t len, struct peer_state* peer, u_int32_t source_id)
{
    struct NF9_FLOWSET_HEADER_COMMON* template_header;
    struct NF9_TEMPLATE_FLOWSET_HEADER* tmplh;
    struct NF9_TEMPLATE_FLOWSET_RECORD* tmplr;
    u_int i, count, offset, template_id, total_size;
    struct peer_nf9_record* recs;
    struct peer_nf9_template* template;

    logit(LOG_DEBUG, "netflow v.9 template flowset from source 0x%x "
        "(len %zd)", source_id, len);
#ifdef DEBUG_NF9
    dump_packet(__func__, pkt, len);
#endif

    template_header = (struct NF9_FLOWSET_HEADER_COMMON*)pkt;
    if (len < sizeof(*template_header)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short netflow v.9 flowset template header "
            "%zd bytes from %s/0x%x", len, addr_ntop_buf(&peer->from),
            source_id);
        /* XXX ratelimit */
        return (-1);
    }
    if (ntohs(template_header->flowset_id) != NF9_TEMPLATE_FLOWSET_ID)
        logerrx("Confused template");

    logit(LOG_DEBUG, "NetFlow v.9 template set from %s/0x%x with len %zd:",
        addr_ntop_buf(&peer->from), source_id, len);

    for (offset = sizeof(*template_header); offset < len;) {
        tmplh = (struct NF9_TEMPLATE_FLOWSET_HEADER*)(pkt + offset);

        template_id = ntohs(tmplh->template_id);
        count = ntohs(tmplh->count);
        offset += sizeof(*tmplh);

        logit(LOG_DEBUG, " Contains template 0x%08x/0x%04x with "
            "%d records (offset %d):", source_id, template_id,
            count, offset);

        if ((recs = je_calloc(count, sizeof(*recs))) == NULL)
            logerrx("%s: calloc failed (num %d)", __func__, count);

        total_size = 0;
        for (i = 0; i < count; i++) {
            if (offset >= len) {
                je_free(recs);
                peer->ninvalid++;
                logit(LOG_WARNING, "short netflow v.9 flowset "
                    "template 0x%08x/0x%04x %zd bytes from %s",
                    source_id, template_id, len, 
                    addr_ntop_buf(&peer->from));
                /* XXX ratelimit */
                return (-1);
            }
            tmplr = (struct NF9_TEMPLATE_FLOWSET_RECORD*)
                (pkt + offset);
            recs[i].type = ntohs(tmplr->type);
            recs[i].len = ntohs(tmplr->length);
            offset += sizeof(*tmplr);
#ifdef DEBUG_NF9
            logit(LOG_DEBUG, "  record %d: type %d len %d",
                i, recs[i].type, recs[i].len);
#endif
            total_size += recs[i].len;
            if (total_size > netflow_peers.max_template_len) {
                je_free(recs);
                peer->ninvalid++;
                logit(LOG_WARNING, "netflow v.9 flowset "
                    "template 0x%08x/0x%04x from %s too large "
                    "len %d > max %d", source_id, template_id,
                    addr_ntop_buf(&peer->from), total_size,
                    netflow_peers.max_template_len);
                /* XXX ratelimit */
                return (-1);
            }
            if (!nf9_check_rec_len(recs[i].type, recs[i].len)) {
                peer->ninvalid++;
                logit(LOG_WARNING, "Invalid field length in "
                    "netflow v.9 flowset template %d from "
                    "%s/0x%08x type %d len %d", template_id, 
                    addr_ntop_buf(&peer->from), source_id,
                    recs[i].type, recs[i].len);
                je_free(recs);
                /* XXX ratelimit */
                return (-1);
            }
            /* XXX kill existing template on error! */
        }
    
        template = peer_nf9_find_template(peer, source_id, template_id);
        if (template == NULL) {
            template = peer_nf9_new_template(peer, source_id, template_id);
        }
    
        if (template->records != NULL)
            je_free(template->records);
    
        template->records = recs;
        template->num_records = i;
        template->total_len = total_size;
    }

    return (0);
}

int process_netflow_v9_data(u_int8_t* pkt, size_t len, struct timeval* tv, 
    struct peer_state* peer, u_int32_t source_id, struct NF9_HEADER* nf9_hdr,
    u_int* num_flows)
{
    struct store_flow_complete* flows;
    struct peer_nf9_template* template;
    struct NF9_DATA_FLOWSET_HEADER* dath;
    u_int flowset_id, i, offset, num_flowsets;

    *num_flows = 0;

    logit(LOG_DEBUG, "netflow v.9 data flowset (len %zd) source 0x%08x",
        len, source_id);

    dath = (struct NF9_DATA_FLOWSET_HEADER*)pkt;
    if (len < sizeof(*dath)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short netflow v.9 data flowset header "
            "%zd bytes from %s", len, addr_ntop_buf(&peer->from));
        /* XXX ratelimit */
        return (-1);
    }

    flowset_id = ntohs(dath->c.flowset_id);

    if ((template = peer_nf9_find_template(peer, source_id,
        flowset_id)) == NULL) {
            peer->no_template++;
        logit(LOG_DEBUG, "netflow v.9 data flowset without template "
            "%s/0x%08x/0x%04x", addr_ntop_buf(&peer->from), source_id,
            flowset_id);
        return (0);
    }

    if (template->records == NULL)
        logerrx("%s: template->records == NULL", __func__);

    offset = sizeof(*dath);
    num_flowsets = (len - offset) / template->total_len;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        logit(LOG_WARNING, "invalid netflow v.9 data flowset "
            "from %s: strange number of flows %d",
            addr_ntop_buf(&peer->from), num_flowsets);
        return (-1);
    }

    if ((flows = je_calloc(num_flowsets, sizeof(*flows))) == NULL)
        logerrx("%s: calloc failed (num %d)", __func__, num_flowsets);

    for (i = 0; i < num_flowsets; i++) {
        if (nf9_flowset_to_store(pkt + offset, template->total_len, tv,
            &peer->from, nf9_hdr, template, source_id, 
            &flows[i]) == -1) {
            peer->ninvalid++;
            je_free(flows);
            logit(LOG_WARNING, "invalid netflow v.9 data flowset "
                "from %s", addr_ntop_buf(&peer->from));
            /* XXX ratelimit */
            return (-1);
        }

        offset += template->total_len;
    }
    *num_flows = i;

    for (i = 0; i < *num_flows; i++)
        process_flow(&flows[i]);

    je_free(flows);

    return (0);
}

void process_netflow_v9(struct flow_packet* fp, struct peer_state* peer)
{
    struct NF9_HEADER* nf9_hdr = (struct NF9_HEADER*)fp->packet;
    struct NF9_FLOWSET_HEADER_COMMON* flowset;
    u_int32_t i, count, flowset_id, flowset_len, flowset_flows;
    u_int32_t offset, source_id, total_flows;

    if (fp->len < sizeof(*nf9_hdr)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short netflow v.9 header %d bytes from %s",
            fp->len, addr_ntop_buf(&fp->flow_source));
#ifdef DEBUG_NF9
        dump_packet(__func__, fp->packet, fp->len);
#endif
        return;
    }

    count = ntohs(nf9_hdr->c.flows);
    source_id = ntohl(nf9_hdr->source_id);

    logit(LOG_DEBUG, "netflow v.9 packet (len %d) %d recs, source 0x%08x",
        fp->len, count, source_id);

#ifdef DEBUG_NF9
    dump_packet(__func__, fp->packet, fp->len);
#endif

    offset = sizeof(*nf9_hdr);
    total_flows = 0;

    for (i = 0;; i++) {
        /* Make sure we don't run off the end of the flow */
        if (offset >= fp->len) {
            peer->ninvalid++;
            logit(LOG_WARNING,
                "short netflow v.9 flowset header %d bytes from %s",
                fp->len, addr_ntop_buf(&fp->flow_source));
            return;
        }

        flowset = (struct NF9_FLOWSET_HEADER_COMMON*)
            (fp->packet + offset);
        flowset_id = ntohs(flowset->flowset_id);
        flowset_len = ntohs(flowset->length);

#ifdef DEBUG_NF9
        logit(LOG_DEBUG, "offset=%d i=%d len=%d count=%d",
            offset, i, fp->len, count);
        logit(LOG_DEBUG, "netflow v.9 flowset %d: type %d(0x%04x) "
            "len %d(0x%04x)",
            i, flowset_id, flowset_id, flowset_len, flowset_len);
#endif

        /*
         * Yes, this is a near duplicate of the short packet check
         * above, but this one validates the flowset length from in
         * the packet before we pass it to the flowset-specific
         * handlers below.
         */
        if (offset + flowset_len > fp->len) {
            peer->ninvalid++;
            logit(LOG_WARNING,
                "short netflow v.9 flowset length %d bytes from %s",
                fp->len, addr_ntop_buf(&fp->flow_source));
            return;
        }

        switch (flowset_id) {
        case NF9_TEMPLATE_FLOWSET_ID:
            if (process_netflow_v9_template(fp->packet + offset,
                flowset_len, peer, source_id) != 0)
                return;
            break;
        case NF9_OPTIONS_FLOWSET_ID:
            /* XXX: implement this (maybe) */
            logit(LOG_DEBUG, "netflow v.9 options flowset");
            break;
        default:
            if (flowset_id < NF9_MIN_RECORD_FLOWSET_ID) {
                logit(LOG_WARNING, "Received unknown netflow "
                    "v.9 reserved flowset type %d "
                    "from %s/0x%08x", flowset_id,
                    addr_ntop_buf(&fp->flow_source), source_id);
                /* XXX ratelimit */
                break;
            }
            if (process_netflow_v9_data(fp->packet + offset,
                flowset_len, &fp->recv_time, peer, source_id,
                nf9_hdr, &flowset_flows) != 0)
                return;
            total_flows += flowset_flows;
            break;
        }
        offset += flowset_len;
        if (offset == fp->len)
            break;
        /* XXX check header->count against what we got */
    }

    /* Don't update peer unless we actually receive data from it */
    if (total_flows > 0)
        update_peer(peer, total_flows, 9);
}

int nf10_rec_to_flow(struct peer_nf10_record* rec, struct store_flow_complete* flow,
    u_int8_t* data)
{
    /* XXX: use a table-based interpreter */
    switch (rec->type) {

/* Copy an int (possibly shorter than the target) keeping their LSBs aligned */
#define BE_COPY(a) rte_memcpy((u_char*)&a + (sizeof(a) - rec->len), data, rec->len);
#define V10_FIELD(v10_field, store_field, flow_field) \
    case v10_field: \
        flow->hdr.fields |= STORE_FIELD_##store_field; \
        BE_COPY(flow->flow_field); \
        break
#define V10_FIELD_ADDR(v10_field, store_field, flow_field, sub, family) \
    case v10_field: \
        flow->hdr.fields |= STORE_FIELD_##store_field; \
        rte_memcpy(&flow->flow_field.v##sub, data, rec->len); \
        flow->flow_field.af = AF_##family; \
        break

    V10_FIELD(NF10_IN_BYTES, OCTETS, octets.flow_octets);
    V10_FIELD(NF10_IN_PACKETS, PACKETS, packets.flow_packets);
    V10_FIELD(NF10_IN_PROTOCOL, PROTO_FLAGS_TOS, pft.protocol);
    V10_FIELD(NF10_SRC_TOS, PROTO_FLAGS_TOS, pft.tos);
    V10_FIELD(NF10_TCP_FLAGS, PROTO_FLAGS_TOS, pft.tcp_flags);
    V10_FIELD(NF10_L4_SRC_PORT, SRCDST_PORT, ports.src_port);
    V10_FIELD(NF10_SRC_MASK, AS_INFO, asinf.src_mask);
    V10_FIELD(NF10_INPUT_SNMP, IF_INDICES, ifndx.if_index_in);
    V10_FIELD(NF10_L4_DST_PORT, SRCDST_PORT, ports.dst_port);
    V10_FIELD(NF10_DST_MASK, AS_INFO, asinf.dst_mask);
    V10_FIELD(NF10_OUTPUT_SNMP, IF_INDICES, ifndx.if_index_out);
    V10_FIELD(NF10_SRC_AS, AS_INFO, asinf.src_as);
    V10_FIELD(NF10_DST_AS, AS_INFO, asinf.dst_as);
    V10_FIELD(NF10_LAST_SWITCHED, FLOW_TIMES, ftimes.flow_finish);
    V10_FIELD(NF10_FIRST_SWITCHED, FLOW_TIMES, ftimes.flow_start);
    V10_FIELD(NF10_IPV6_SRC_MASK, AS_INFO, asinf.src_mask);
    V10_FIELD(NF10_IPV6_DST_MASK, AS_INFO, asinf.dst_mask);
    V10_FIELD(NF10_ENGINE_TYPE, FLOW_ENGINE_INFO, finf.engine_type);
    V10_FIELD(NF10_ENGINE_ID, FLOW_ENGINE_INFO, finf.engine_id);

    V10_FIELD_ADDR(NF10_IPV4_SRC_ADDR, SRC_ADDR4, src_addr, 4, INET);
    V10_FIELD_ADDR(NF10_IPV4_DST_ADDR, DST_ADDR4, dst_addr, 4, INET);
    V10_FIELD_ADDR(NF10_IPV4_NEXT_HOP, GATEWAY_ADDR4, gateway_addr, 4, INET);

    V10_FIELD_ADDR(NF10_IPV6_SRC_ADDR, SRC_ADDR6, src_addr, 6, INET6);
    V10_FIELD_ADDR(NF10_IPV6_DST_ADDR, DST_ADDR6, dst_addr, 6, INET6);
    V10_FIELD_ADDR(NF10_IPV6_NEXT_HOP, GATEWAY_ADDR6, gateway_addr, 6, INET6);

#undef V10_FIELD
#undef V10_FIELD_ADDR
#undef BE_COPY
    }
    return (0);
}

int nf10_check_rec_len(u_int type, u_int len)
{
    struct store_flow_complete t;

    /* Sanity check */
    if (len == 0 || len > 0x4000)
        return (0);

    /* XXX: use a table-based interpreter */
    switch (type) {
#define V10_FIELD_LEN(v10_field, flow_field) \
    case v10_field: \
        return (len <= sizeof(t.flow_field));

    V10_FIELD_LEN(NF10_IN_BYTES, octets.flow_octets);
    V10_FIELD_LEN(NF10_IN_PACKETS, packets.flow_packets);
    V10_FIELD_LEN(NF10_IN_PROTOCOL, pft.protocol);
    V10_FIELD_LEN(NF10_SRC_TOS, pft.tos);
    V10_FIELD_LEN(NF10_TCP_FLAGS, pft.tcp_flags);
    V10_FIELD_LEN(NF10_L4_SRC_PORT, ports.src_port);
    V10_FIELD_LEN(NF10_IPV4_SRC_ADDR, src_addr.v4);
    V10_FIELD_LEN(NF10_SRC_MASK, asinf.src_mask);
    V10_FIELD_LEN(NF10_INPUT_SNMP, ifndx.if_index_in);
    V10_FIELD_LEN(NF10_L4_DST_PORT, ports.dst_port);
    V10_FIELD_LEN(NF10_IPV4_DST_ADDR, dst_addr.v4);
    V10_FIELD_LEN(NF10_DST_MASK, asinf.src_mask);
    V10_FIELD_LEN(NF10_OUTPUT_SNMP, ifndx.if_index_out);
    V10_FIELD_LEN(NF10_IPV4_NEXT_HOP, gateway_addr.v4);
    V10_FIELD_LEN(NF10_SRC_AS, asinf.src_as);
    V10_FIELD_LEN(NF10_DST_AS, asinf.dst_as);
    V10_FIELD_LEN(NF10_LAST_SWITCHED, ftimes.flow_finish);
    V10_FIELD_LEN(NF10_FIRST_SWITCHED, ftimes.flow_start);
    V10_FIELD_LEN(NF10_IPV6_SRC_ADDR, src_addr.v6);
    V10_FIELD_LEN(NF10_IPV6_DST_ADDR, dst_addr.v6);
    V10_FIELD_LEN(NF10_IPV6_SRC_MASK, asinf.src_mask);
    V10_FIELD_LEN(NF10_IPV6_DST_MASK, asinf.dst_mask);
    V10_FIELD_LEN(NF10_ENGINE_TYPE, finf.engine_type);
    V10_FIELD_LEN(NF10_ENGINE_ID, finf.engine_id);
    V10_FIELD_LEN(NF10_IPV6_NEXT_HOP, gateway_addr.v6);

#undef V10_FIELD_LEN
    default:
        return (1);
    }
}

int nf10_flowset_to_store(u_int8_t* pkt, size_t len, struct timeval* tv,
    struct xaddr* flow_source, struct NF10_HEADER* nf10_hdr,
    struct peer_nf10_template* template, u_int32_t source_id,
    struct store_flow_complete* flow)
{
    u_int offset, i;

    if (template->total_len > len)
        return (-1);

    bzero(flow, sizeof(*flow));

    flow->hdr.fields = STORE_FIELD_RECV_TIME | STORE_FIELD_AGENT_INFO |
        STORE_FIELD_AGENT_ADDR;
    flow->ainfo.sys_uptime_ms = 0;
    flow->ainfo.time_sec = nf10_hdr->time_sec;
    flow->ainfo.netflow_version = nf10_hdr->c.version;
    flow->finf.flow_sequence = nf10_hdr->package_sequence;
    flow->finf.source_id = htonl(source_id);
    flow->recv_time.recv_sec = tv->tv_sec;
    flow->recv_time.recv_usec = tv->tv_usec;
    rte_memcpy(&flow->agent_addr, flow_source, sizeof(flow->agent_addr));

    offset = 0;
    for (i = 0; i < template->num_records; i++) {
        if (DEBUG_NF10) {
            logit(LOG_DEBUG, "    record %d: type %d len %d: %s",
                i, template->records[i].type, template->records[i].len,
                data_ntoa(pkt + offset, template->records[i].len));
        }
        nf10_rec_to_flow(&template->records[i], flow, pkt + offset);
        offset += template->records[i].len;
    }
    return (0);
}

int process_netflow_v10_template(u_int8_t* pkt, size_t len, struct peer_state* peer, u_int32_t source_id)
{
    struct NF10_FLOWSET_HEADER_COMMON* template_header;
    struct NF10_TEMPLATE_FLOWSET_HEADER* tmplh;
    struct NF10_TEMPLATE_FLOWSET_RECORD* tmplr;
    u_int i, count, offset, template_id, total_size;
    struct peer_nf10_record* recs;
    struct peer_nf10_template* template;

    logit(LOG_DEBUG, "netflow v.10 template flowset from source 0x%x "
        "(len %zd)", source_id, len);
    if (DEBUG_NF10) {
        dump_packet(__func__, pkt, len);
    }

    template_header = (struct NF10_FLOWSET_HEADER_COMMON*)pkt;
    if (len < sizeof(*template_header)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short netflow v.10 flowset template header "
            "%zd bytes from %s/0x%x", len, addr_ntop_buf(&peer->from),
            source_id);
        /* XXX ratelimit */
        return (-1);
    }
    if (ntohs(template_header->flowset_id) != NF10_TEMPLATE_FLOWSET_ID)
        logerrx("Confused template");

    logit(LOG_DEBUG, "NetFlow v.10 template set from %s/0x%x with len %zd:",
        addr_ntop_buf(&peer->from), source_id, len);

    for (offset = sizeof(*template_header); offset < len;) {
        tmplh = (struct NF10_TEMPLATE_FLOWSET_HEADER*)(pkt + offset);

        template_id = ntohs(tmplh->template_id);
        count = ntohs(tmplh->count);
        offset += sizeof(*tmplh);

        logit(LOG_DEBUG, " Contains template 0x%08x/0x%04x with "
            "%d records (offset %d):", source_id, template_id,
            count, offset);

        if ((recs = je_calloc(count, sizeof(*recs))) == NULL)
            logerrx("%s: calloc failed (num %d)", __func__, count);

        total_size = 0;
        for (i = 0; i < count; i++) {
            if (offset >= len) {
                peer->ninvalid++;
                logit(LOG_WARNING, "short netflow v.10 flowset "
                    "template 0x%08x/0x%04x %zd bytes from %s",
                    source_id, template_id, len,
                    addr_ntop_buf(&peer->from));
                je_free(recs);
                /* XXX ratelimit */
                return (-1);
            }
            tmplr = (struct NF10_TEMPLATE_FLOWSET_RECORD*)
                (pkt + offset);
            recs[i].type = ntohs(tmplr->type);
            recs[i].len = ntohs(tmplr->length);
            offset += sizeof(*tmplr);
            if (recs[i].type & NF10_ENTERPRISE)
                offset += sizeof(u_int32_t);    /* XXX -- ? */
            if (DEBUG_NF10) {
                logit(LOG_DEBUG, "  record %d: type %d len %d",
                    i, recs[i].type, recs[i].len);
            }
            total_size += recs[i].len;
            if (total_size > netflow_peers.max_template_len) {
                je_free(recs);
                peer->ninvalid++;
                logit(LOG_WARNING, "netflow v.10 flowset "
                    "template 0x%08x/0x%04x from %s too large "
                    "len %d > max %d", source_id, template_id,
                    addr_ntop_buf(&peer->from), total_size,
                    netflow_peers.max_template_len);
                /* XXX ratelimit */
                return (-1);
            }
            if (!nf10_check_rec_len(recs[i].type, recs[i].len)) {
                peer->ninvalid++;
                logit(LOG_WARNING, "Invalid field length in "
                    "netflow v.10 flowset template %d from "
                    "%s/0x%08x type %d len %d", template_id,
                    addr_ntop_buf(&peer->from), source_id,
                    recs[i].type, recs[i].len);
                je_free(recs);
                /* XXX ratelimit */
                return (-1);
            }
            /* XXX kill existing template on error! */
        }

        template = peer_nf10_find_template(peer, source_id, template_id);
        if (template == NULL) {
            template = peer_nf10_new_template(peer, source_id, template_id);
        }

        if (template->records != NULL)
            je_free(template->records);

        template->records = recs;
        template->num_records = i;
        template->total_len = total_size;
    }

    return (0);
}

int process_netflow_v10_data(u_int8_t* pkt, size_t len, struct timeval* tv,
    struct peer_state* peer, u_int32_t source_id, struct NF10_HEADER* nf10_hdr,
    u_int* num_flows)
{
    struct store_flow_complete* flows;
    struct peer_nf10_template* template;
    struct NF10_DATA_FLOWSET_HEADER* dath;
    u_int flowset_id, i, offset, num_flowsets;

    *num_flows = 0;

    logit(LOG_DEBUG, "netflow v.10 data flowset (len %zd) source 0x%08x",
        len, source_id);

    dath = (struct NF10_DATA_FLOWSET_HEADER*)pkt;
    if (len < sizeof(*dath)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short netflow v.10 data flowset header "
            "%zd bytes from %s", len, addr_ntop_buf(&peer->from));
        /* XXX ratelimit */
        return (-1);
    }

    flowset_id = ntohs(dath->c.flowset_id);

    if ((template = peer_nf10_find_template(peer, source_id,
        flowset_id)) == NULL) {
        peer->no_template++;
        logit(LOG_DEBUG, "netflow v.10 data flowset without template "
            "%s/0x%08x/0x%04x", addr_ntop_buf(&peer->from), source_id,
            flowset_id);
        return (0);
    }

    if (template->records == NULL)
        logerrx("%s: template->records == NULL", __func__);

    offset = sizeof(*dath);
    num_flowsets = (len - offset) / template->total_len;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        logit(LOG_WARNING, "invalid netflow v.10 data flowset "
            "from %s: strange number of flows %d",
            addr_ntop_buf(&peer->from), num_flowsets);
        return (-1);
    }

    if ((flows = je_calloc(num_flowsets, sizeof(*flows))) == NULL)
        logerrx("%s: calloc failed (num %d)", __func__, num_flowsets);

    for (i = 0; i < num_flowsets; i++) {
        if (nf10_flowset_to_store(pkt + offset, template->total_len, tv,
            &peer->from, nf10_hdr, template, source_id,
            &flows[i]) == -1) {
            peer->ninvalid++;
            je_free(flows);
            logit(LOG_WARNING, "invalid netflow v.10 data flowset "
                "from %s", addr_ntop_buf(&peer->from));
            /* XXX ratelimit */
            return (-1);
        }

        offset += template->total_len;
    }
    *num_flows = i;

    for (i = 0; i < *num_flows; i++)
        process_flow(&flows[i]);

    je_free(flows);

    return (0);
}

void process_netflow_v10(struct flow_packet* fp, struct peer_state* peer)
{
    struct NF10_HEADER* nf10_hdr = (struct NF10_HEADER*)fp->packet;
    struct NF10_FLOWSET_HEADER_COMMON* flowset;
    u_int32_t i, pktlen, flowset_id, flowset_len, flowset_flows;
    u_int32_t offset, source_id, total_flows;

    if (fp->len < sizeof(*nf10_hdr)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short netflow v.10 header %d bytes from %s",
            fp->len, addr_ntop_buf(&fp->flow_source));
        if (DEBUG_NF10) {
            dump_packet(__func__, fp->packet, fp->len);
        }
        return;
    }

    /* v10 uses pkt length, not # of flows */
    pktlen = ntohs(nf10_hdr->c.flows);
    source_id = ntohl(nf10_hdr->source_id);

    logit(LOG_DEBUG, "netflow v.10 packet (len %d) %d recs, source 0x%08x",
        fp->len, pktlen, source_id);
    if (DEBUG_NF10) {
        dump_packet(__func__, fp->packet, fp->len);
    }

    offset = sizeof(*nf10_hdr);
    total_flows = 0;

    for (i = 0;; i++) {
        /* Make sure we don't run off the end of the flow */
        if (offset >= fp->len) {
            peer->ninvalid++;
            logit(LOG_WARNING,
                "short netflow v.10 flowset header %d bytes from %s",
                fp->len, addr_ntop_buf(&fp->flow_source));
            return;
        }

        flowset = (struct NF10_FLOWSET_HEADER_COMMON*)
            (fp->packet + offset);
        flowset_id = ntohs(flowset->flowset_id);
        flowset_len = ntohs(flowset->length);

        if (DEBUG_NF10) {
            logit(LOG_DEBUG, "offset=%d i=%d len=%d pktlen=%d",
                offset, i, fp->len, pktlen);
            logit(LOG_DEBUG, "netflow v.10 flowset %d: type %d(0x%04x) "
                "len %d(0x%04x)",
                i, flowset_id, flowset_id, flowset_len, flowset_len);
        }

        /*
         * Yes, this is a near duplicate of the short packet check
         * above, but this one validates the flowset length from in
         * the packet before we pass it to the flowset-specific
         * handlers below.
         */
        if (offset + flowset_len > fp->len) {
            peer->ninvalid++;
            logit(LOG_WARNING,
                "short netflow v.10 flowset length %d bytes from %s",
                fp->len, addr_ntop_buf(&fp->flow_source));
            return;
        }

        switch (flowset_id) {
        case NF10_TEMPLATE_FLOWSET_ID:
            if (process_netflow_v10_template(fp->packet + offset,
                flowset_len, peer, source_id) != 0)
                return;
            break;
        case NF10_OPTIONS_FLOWSET_ID:
            /* XXX: implement this (maybe) */
            logit(LOG_DEBUG, "netflow v.10 options flowset");
            break;
        default:
            if (flowset_id < NF10_MIN_RECORD_FLOWSET_ID) {
                logit(LOG_WARNING, "Received unknown netflow "
                    "v.10 reserved flowset type %d "
                    "from %s/0x%08x", flowset_id,
                    addr_ntop_buf(&fp->flow_source), source_id);
                /* XXX ratelimit */
                break;
            }
            if (process_netflow_v10_data(fp->packet + offset,
                flowset_len, &fp->recv_time, peer, source_id,
                nf10_hdr, &flowset_flows) != 0)
                return;
            total_flows += flowset_flows;
            break;
        }
        offset += flowset_len;
        if (offset == fp->len)
            break;
    }

    /* Don't update peer unless we actually receive data from it */
    if (total_flows > 0)
        update_peer(peer, total_flows, 10);
}

int process_packet(struct flow_packet* fp) {
    struct peer_state* peer;
    struct NF_HEADER_COMMON* hdr = (struct NF_HEADER_COMMON*)fp->packet;

    if ((peer = find_peer(&fp->flow_source)) == NULL) {
        logit(LOG_WARNING, "flow source %s was expired between "
            "between flow packet reception and processing", 
            addr_ntop_buf(&fp->flow_source));
        return -1;
    }

    switch (ntohs(hdr->version)) {
    case 1:
        process_netflow_v1(fp, peer);
        break;
    case 5:
        process_netflow_v5(fp, peer);
        break;
    case 7:
        process_netflow_v7(fp, peer);
        break;
    case 9:
        process_netflow_v9(fp, peer);
        break;
    case 10:
        process_netflow_v10(fp, peer);
        break;
    default:
        logit(LOG_INFO, "Unsupported netflow version %u from %s",
            ntohs(hdr->version), addr_ntop_buf(&fp->flow_source));
        if (DEBUG) dump_packet("Unknown packet type", fp->packet, fp->len);
        return -1;
    }
    
    return 0;
}

int netflow_frame_handle(ss_frame_t* fbuf) {
    if (DEBUG) {
        dump_peers();
    }
    
    struct peer_state* peer;
    struct xaddr flow_source;
    struct flow_packet* fp;

    if ((fp = flow_packet_alloc()) == NULL) {
        logit(LOG_WARNING, "flow packet metadata alloc failed");
        return -1;
    }

    fp->len = fbuf->data.l4_length;
    gettimeofday(&fp->recv_time, NULL);

    if (addr_frame_to_xaddr(fbuf, &fp->flow_source) == -1) {
        logit(LOG_WARNING, "Invalid agent address");
        flow_packet_dealloc(fp);
        return (1);
    }

    if ((peer = find_peer(&fp->flow_source)) == NULL)
        peer = new_peer(&fp->flow_source);
    if (peer == NULL) {
        logit(LOG_DEBUG, "packet from unauthorised agent %s",
            addr_ntop_buf(&fp->flow_source));
        flow_packet_dealloc(fp);
        return (1);
    }

    if (fp->len < sizeof(struct NF_HEADER_COMMON)) {
        peer->ninvalid++;
        logit(LOG_WARNING, "short packet %d bytes from %s", fp->len,
            addr_ntop_buf(&flow_source));
        flow_packet_dealloc(fp);
        return (1);
    }

    if ((fp->packet = je_malloc(fp->len)) == NULL) {
        logit(LOG_WARNING, "flow packet alloc failed (len %d)",
            fp->len);
        flow_packet_dealloc(fp);
        return (0);
    }
    rte_memcpy(fp->packet, fbuf->l4_offset, fp->len);
    process_packet(fp);

    return (1);
}

int netflow_init(int argc, char **argv) {
    tzset();
    bzero(&netflow_peers, sizeof(netflow_peers));
    rte_spinlock_recursive_init(&netflow_peers.peers_lock);
    netflow_peers.max_peers = DEFAULT_MAX_PEERS;
    netflow_peers.max_templates = DEFAULT_MAX_TEMPLATES;
    netflow_peers.max_sources = DEFAULT_MAX_SOURCES;
    netflow_peers.max_template_len = DEFAULT_MAX_TEMPLATE_LEN;
    SPLAY_INIT(&netflow_peers.peer_tree);
    TAILQ_INIT(&netflow_peers.peer_list);

    return (0);
}

#pragma clang diagnostic pop
