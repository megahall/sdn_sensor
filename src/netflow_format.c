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

#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>
#include <endian.h>

#include <bsd/string.h>

#include "netflow_common.h"
#include "netflow_format.h"
#include "netflow_crc32.h"

/* This is a useful abbreviation, used in several places below */
#define SHASFIELD(flag) (fields & STORE_FIELD_##flag)

const char* iso_time(time_t t, int utc_flag) {
    struct tm* tm;
    static char buf[128];

    if (utc_flag)
        tm = gmtime(&t);
    else
        tm = localtime(&t);

    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);

    return (buf);
}

#define MINUTE        (60)
#define HOUR        (MINUTE * 60)
#define DAY        (HOUR * 24)
#define WEEK        (DAY * 7)
#define YEAR        (WEEK * 52)
const char* interval_time(time_t t) {
    static char buf[128];
    char tmp[128];
    u_long r;
    int unit_div[] = { YEAR, WEEK, DAY, HOUR, MINUTE, 1, -1 };
    char unit_sym[] = { 'y', 'w', 'd', 'h', 'm', 's' };
    int i;

    *buf = '\0';

    for (i = 0; unit_div[i] != -1; i++) {
        if ((r = t / unit_div[i]) != 0 || unit_div[i] == 1) {
            snprintf(tmp, sizeof(tmp), "%lu%c", r, unit_sym[i]);
            strlcat(buf, tmp, sizeof(buf));
            t %= unit_div[i];
        }
    }
    return (buf);
}

/*
 * Some helper functions for netflow_format_flow() and netflow_swab_flow(), 
 * so we can switch between host and network byte order easily.
 */
u_int64_t netflow_swp_ntoh64(u_int64_t v) {
    return netflow_ntohll(v);
}

u_int32_t netflow_swp_ntoh32(u_int32_t v) {
    return ntohl(v);
}

u_int16_t netflow_swp_ntoh16(u_int16_t v) {
    return ntohs(v);
}

u_int64_t netflow_swp_hton64(u_int64_t v) {
    return netflow_htonll(v);
}

u_int32_t netflow_swp_hton32(u_int32_t v) {
    return htonl(v);
}

u_int16_t netflow_swp_hton16(u_int16_t v) {
    return htons(v);
}

u_int64_t netflow_swp_fake64(u_int64_t v) {
    return v;
}

u_int32_t netflow_swp_fake32(u_int32_t v) {
    return v;
}

u_int16_t netflow_swp_fake16(u_int16_t v) {
    return v;
}

void netflow_format_flow(struct store_flow_complete* flow, char* buf, size_t len,
    int utc_flag, u_int32_t display_mask, int hostorder) {
    char tmp[256];
    u_int32_t fields;
    u_int64_t (*fmt_ntoh64)(u_int64_t) = netflow_swp_ntoh64;
    u_int32_t (*fmt_ntoh32)(u_int32_t) = netflow_swp_ntoh32;
    u_int16_t (*fmt_ntoh16)(u_int16_t) = netflow_swp_ntoh16;

    if (hostorder) {
        fmt_ntoh64 = netflow_swp_fake64;
        fmt_ntoh32 = netflow_swp_fake32;
        fmt_ntoh16 = netflow_swp_fake16;
    }

    *buf = '\0';

    fields = fmt_ntoh32(flow->hdr.fields) & display_mask;

    strlcat(buf, "FLOW ", len);

    if (SHASFIELD(TAG)) {
        snprintf(tmp, sizeof(tmp), "tag %u ", fmt_ntoh32(flow->tag.tag));
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(RECV_TIME)) {
        snprintf(tmp, sizeof(tmp), "recv_time %s.%05d ",
            iso_time(fmt_ntoh32(flow->recv_time.recv_sec), utc_flag),
            fmt_ntoh32(flow->recv_time.recv_usec));
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(PROTO_FLAGS_TOS)) {
        snprintf(tmp, sizeof(tmp), "proto %d ", flow->pft.protocol);
        strlcat(buf, tmp, len);
        snprintf(tmp, sizeof(tmp), "tcpflags %02x ",
            flow->pft.tcp_flags);
        strlcat(buf, tmp, len);
        snprintf(tmp, sizeof(tmp), "tos %02x " , flow->pft.tos);
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(AGENT_ADDR4) || SHASFIELD(AGENT_ADDR6)) {
        snprintf(tmp, sizeof(tmp), "agent [%s] ",
            addr_ntop_buf(&flow->agent_addr));
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(SRC_ADDR4) || SHASFIELD(SRC_ADDR6)) {
        snprintf(tmp, sizeof(tmp), "src [%s]",
            addr_ntop_buf(&flow->src_addr));
        strlcat(buf, tmp, len);
        if (SHASFIELD(SRCDST_PORT)) {
            snprintf(tmp, sizeof(tmp), ":%d",
                fmt_ntoh16(flow->ports.src_port));
            strlcat(buf, tmp, len);
        }
        strlcat(buf, " ", len);
    }
    if (SHASFIELD(DST_ADDR4) || SHASFIELD(DST_ADDR6)) {
        snprintf(tmp, sizeof(tmp), "dst [%s]",
            addr_ntop_buf(&flow->dst_addr));
        strlcat(buf, tmp, len);
        if (SHASFIELD(SRCDST_PORT)) {
            snprintf(tmp, sizeof(tmp), ":%d",
                fmt_ntoh16(flow->ports.dst_port));
            strlcat(buf, tmp, len);
        }
        strlcat(buf, " ", len);
    }
    if (SHASFIELD(GATEWAY_ADDR4) || SHASFIELD(GATEWAY_ADDR6)) {
        snprintf(tmp, sizeof(tmp), "gateway [%s] ",
            addr_ntop_buf(&flow->gateway_addr));
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(PACKETS)) {
        snprintf(tmp, sizeof(tmp), "packets %lu ",
            fmt_ntoh64(flow->packets.flow_packets));
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(OCTETS)) {
        snprintf(tmp, sizeof(tmp), "octets %lu ",
            fmt_ntoh64(flow->octets.flow_octets));
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(IF_INDICES)) {
        snprintf(tmp, sizeof(tmp), "in_if %d out_if %d ",
            fmt_ntoh32(flow->ifndx.if_index_in),
            fmt_ntoh32(flow->ifndx.if_index_out));
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(AGENT_INFO)) {
        snprintf(tmp, sizeof(tmp), "sys_uptime_ms %s.%03u ",
            interval_time(fmt_ntoh32(flow->ainfo.sys_uptime_ms) / 1000),
            fmt_ntoh32(flow->ainfo.sys_uptime_ms) % 1000);
        strlcat(buf, tmp, len);
        snprintf(tmp, sizeof(tmp), "time_sec %s ",
            iso_time(fmt_ntoh32(flow->ainfo.time_sec), utc_flag));
        strlcat(buf, tmp, len);
        snprintf(tmp, sizeof(tmp), "time_nanosec %lu netflow ver %u ",
            (u_long)fmt_ntoh32(flow->ainfo.time_nanosec),
            fmt_ntoh16(flow->ainfo.netflow_version));
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(FLOW_TIMES)) {
        snprintf(tmp, sizeof(tmp), "flow_start %s.%03u ",
            interval_time(fmt_ntoh32(flow->ftimes.flow_start) / 1000),
            fmt_ntoh32(flow->ftimes.flow_start) % 1000);
        strlcat(buf, tmp, len);
        snprintf(tmp, sizeof(tmp), "flow_finish %s.%03u ",
            interval_time(fmt_ntoh32(flow->ftimes.flow_finish) / 1000),
            fmt_ntoh32(flow->ftimes.flow_finish) % 1000);
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(AS_INFO)) {
        snprintf(tmp, sizeof(tmp), "src_AS %u src_masklen %u ",
            fmt_ntoh32(flow->asinf.src_as), flow->asinf.src_mask);
        strlcat(buf, tmp, len);
        snprintf(tmp, sizeof(tmp), "dst_AS %u dst_masklen %u ",
            fmt_ntoh32(flow->asinf.dst_as), flow->asinf.dst_mask);
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(FLOW_ENGINE_INFO)) {
        snprintf(tmp, sizeof(tmp),
            "engine_type %u engine_id %u seq %lu source %lu ",
            fmt_ntoh16(flow->finf.engine_type), 
            fmt_ntoh16(flow->finf.engine_id),
            (u_long)fmt_ntoh32(flow->finf.flow_sequence), 
            (u_long)fmt_ntoh32(flow->finf.source_id));
        strlcat(buf, tmp, len);
    }
    if (SHASFIELD(CRC32)) {
        snprintf(tmp, sizeof(tmp), "crc32 %08x ",
            fmt_ntoh32(flow->crc32.crc32));
        strlcat(buf, tmp, len);
    }
}

u_int64_t netflow_ntohll(u_int64_t v) {
    v = be64toh(v);
    return (v);
}

u_int64_t netflow_htonll(u_int64_t v) {
    v = htobe64(v);
    return (v);
}
