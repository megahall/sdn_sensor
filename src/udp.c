#include <stdint.h>
#include <stdio.h>

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <rte_byteorder.h>
#include <rte_hexdump.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "udp.h"

#include "common.h"

int ss_frame_handle_udp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    rx_buf->data.sport     = rte_bswap16(rx_buf->udp->uh_sport);
    rx_buf->data.dport     = rte_bswap16(rx_buf->udp->uh_dport);
    rx_buf->data.l4_length = rte_bswap16(rx_buf->udp->uh_ulen);
    RTE_LOG(INFO, SS, "rx udp packet: sport: %hu dport: %hu length: %hu\n",
        rx_buf->data.sport, rx_buf->data.dport, rx_buf->data.l4_length);
    
    if (!rx_buf->data.self) {
        return rv;
    }
    
    // XXX: check for sFlow, NetFlow, or Syslog
    switch (rx_buf->data.dport) {
        case L4_PORT_SYSLOG: {
            RTE_LOG(INFO, SS, "rx udp syslog packet\n");
            break;
        }
        case L4_PORT_SYSLOG_TLS: {
            RTE_LOG(INFO, SS, "rx udp syslog-tls packet\n");
            break;
        }
        case L4_PORT_SFLOW: {
            RTE_LOG(INFO, SS, "rx udp sFlow packet\n");
            break;
        }
        case L4_PORT_NETFLOW: {
            RTE_LOG(INFO, SS, "rx udp NetFlow packet\n");
            break;
        }
    }

    return rv;
}
