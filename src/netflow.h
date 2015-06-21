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

#pragma once

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <syslog.h>

#include <bsd/sys/queue.h>

#include "common.h"
#include "netflow_addr.h"
#include "netflow_common.h"
#include "netflow_format.h"
#include "netflow_packet.h"
#include "netflow_peer.h"

/* Initial stateholding limits */
/* XXX these are not actually tunable yet */
#define DEFAULT_MAX_PEERS        128
#define DEFAULT_MAX_TEMPLATES        8
#define DEFAULT_MAX_TEMPLATE_LEN    1024
#define DEFAULT_MAX_SOURCES        64

extern struct peers netflow_peers;

/* BEGIN PROTOTYPES */

struct flow_packet* flow_packet_alloc(void);
void flow_packet_dealloc(struct flow_packet* f);
const char* data_ntoa(const u_int8_t* p, u_int len);
void dump_packet(const char* tag, const u_int8_t* p, u_int len);
int process_flow(struct store_flow_complete* flow);
void process_netflow_v1(struct flow_packet* fp, struct peer_state* peer);
void process_netflow_v5(struct flow_packet* fp, struct peer_state* peer);
void process_netflow_v7(struct flow_packet* fp, struct peer_state* peer);
int nf9_rec_to_flow(struct peer_nf9_record* rec, struct store_flow_complete* flow, u_int8_t* data);
int nf9_check_rec_len(u_int type, u_int len);
int nf9_flowset_to_store(u_int8_t* pkt, size_t len, struct timeval* tv, struct xaddr* flow_source, struct NF9_HEADER* nf9_hdr, struct peer_nf9_template* template, u_int32_t source_id, struct store_flow_complete* flow);
int process_netflow_v9_template(u_int8_t* pkt, size_t len, struct peer_state* peer, u_int32_t source_id);
int process_netflow_v9_data(u_int8_t* pkt, size_t len, struct timeval* tv, struct peer_state* peer, u_int32_t source_id, struct NF9_HEADER* nf9_hdr, u_int* num_flows);
void process_netflow_v9(struct flow_packet* fp, struct peer_state* peer);
int nf10_rec_to_flow(struct peer_nf10_record* rec, struct store_flow_complete* flow, u_int8_t* data);
int nf10_check_rec_len(u_int type, u_int len);
int nf10_flowset_to_store(u_int8_t* pkt, size_t len, struct timeval* tv, struct xaddr* flow_source, struct NF10_HEADER* nf10_hdr, struct peer_nf10_template* template, u_int32_t source_id, struct store_flow_complete* flow);
int process_netflow_v10_template(u_int8_t* pkt, size_t len, struct peer_state* peer, u_int32_t source_id);
int process_netflow_v10_data(u_int8_t* pkt, size_t len, struct timeval* tv, struct peer_state* peer, u_int32_t source_id, struct NF10_HEADER* nf10_hdr, u_int* num_flows);
void process_netflow_v10(struct flow_packet* fp, struct peer_state* peer);
int process_packet(struct flow_packet* fp);
int netflow_frame_handle(ss_frame_t* fbuf);
int netflow_init(int argc, char** argv);

/* END PROTOTYPES */
