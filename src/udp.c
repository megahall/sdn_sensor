#include <stdint.h>
#include <stdio.h>

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <rte_byteorder.h>
#include <rte_hexdump.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include <dns.h>

#include "udp.h"

#include "common.h"
#include "extractor.h"
#include "l4_utils.h"
#include "netflow.h"

int ss_frame_handle_udp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    ss_frame_layer_off_len_get(rx_buf, rx_buf->udp, sizeof(udp_hdr_t), &rx_buf->l4_offset, &rx_buf->data.l4_length);
    rx_buf->data.sport = rte_bswap16(rx_buf->udp->uh_sport);
    rx_buf->data.dport = rte_bswap16(rx_buf->udp->uh_dport);
    
    RTE_LOG(INFO, STACK, "rx udp packet: sport: %hu dport: %hu length: %hu\n",
        rx_buf->data.sport, rx_buf->data.dport, rx_buf->data.l4_length);
    
    switch (rx_buf->data.dport) {
        case L4_PORT_DNS: {
            RTE_LOG(DEBUG, STACK, "rx udp dns packet\n");
            ss_extract_dns(rx_buf);
            break;
        }
        case L4_PORT_SYSLOG: {
            RTE_LOG(DEBUG, STACK, "rx udp syslog packet\n");
            SS_CHECK_SELF(rx_buf, 0);
            ss_extract_syslog(rx_buf);
            break;
        }
        case L4_PORT_SYSLOG_TLS: {
            RTE_LOG(DEBUG, STACK, "rx udp syslog-tls packet\n");
            SS_CHECK_SELF(rx_buf, 0);
            break;
        }
        case L4_PORT_SFLOW: {
            RTE_LOG(DEBUG, STACK, "rx udp sFlow packet\n");
            SS_CHECK_SELF(rx_buf, 0);
            break;
        }
        case L4_PORT_NETFLOW_1:
        case L4_PORT_NETFLOW_2:
        case L4_PORT_NETFLOW_3: {
            RTE_LOG(DEBUG, STACK, "rx udp NetFlow packet\n");
            SS_CHECK_SELF(rx_buf, 0);
            break;
        }
    }

    return rv;
}
