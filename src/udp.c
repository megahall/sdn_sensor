#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

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
#include "re_utils.h"

int ss_frame_handle_udp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    ss_frame_layer_off_len_get(rx_buf, rx_buf->udp, sizeof(udp_hdr_t), &rx_buf->l4_offset, &rx_buf->data.l4_length);
    rx_buf->data.sport = rte_bswap16(rx_buf->udp->uh_sport);
    rx_buf->data.dport = rte_bswap16(rx_buf->udp->uh_dport);
    
    RTE_LOG(DEBUG, L3L4, "rx udp packet: sport: %hu dport: %hu length: %hu\n",
        rx_buf->data.sport, rx_buf->data.dport, rx_buf->data.l4_length);
    
    switch (rx_buf->data.dport) {
        case L4_PORT_DNS: {
            RTE_LOG(DEBUG, L3L4, "rx udp dns packet\n");
            ss_extract_dns(rx_buf);
            break;
        }
        case L4_PORT_SYSLOG: {
            RTE_LOG(DEBUG, L3L4, "rx udp syslog packet\n");
            SS_CHECK_SELF(rx_buf, 0);
            ss_udp_extract_syslog(rx_buf);
            break;
        }
        case L4_PORT_SFLOW: {
            RTE_LOG(DEBUG, L3L4, "rx udp sFlow packet\n");
            SS_CHECK_SELF(rx_buf, 0);
            break;
        }
        case L4_PORT_NETFLOW_1:
        case L4_PORT_NETFLOW_2:
        case L4_PORT_NETFLOW_3: {
            RTE_LOG(DEBUG, L3L4, "rx udp NetFlow packet\n");
            SS_CHECK_SELF(rx_buf, 0);
            netflow_frame_handle(rx_buf);
            break;
        }
    }

    return rv;
}

int ss_udp_extract_syslog(ss_frame_t* fbuf) {
    uint8_t* match_string;
    int rv = 0;
    ss_re_match_t re_match;

    memset(&re_match, 0, sizeof(re_match));

    // exit if the syslog packet was not sent to us
    SS_CHECK_SELF(fbuf, rv);

    // place a zero byte at the end of the log message to form a C string
    match_string = (uint8_t*) rte_pktmbuf_append(fbuf->mbuf, 1);
    if (match_string == NULL) {
        RTE_LOG(ERR, EXTRACTOR, "could not append zero byte to syslog message\n");
        return -1;
    }
    *match_string = 0;

    return ss_extract_syslog("udp_syslog", fbuf, fbuf->l4_offset, fbuf->data.l4_length);
}
