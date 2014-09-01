#include <stdint.h>
#include <stdio.h>

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <rte_byteorder.h>
#include <rte_hexdump.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "tcp.h"

#include "common.h"

int ss_frame_handle_tcp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    // l4_length = packet_length - (tcp_data_start - packet_start)
    uint16_t l4_length     = rte_pktmbuf_pkt_len(rx_buf->mbuf) - (((uint8_t*) rx_buf->tcp + sizeof(tcp_hdr_t)) - rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*));    
    
    uint16_t sport         = rte_bswap16(rx_buf->tcp->source);
    uint16_t dport         = rte_bswap16(rx_buf->tcp->dest);
    uint32_t seq           = rte_bswap32(rx_buf->tcp->seq);
    uint32_t ack_seq       = rte_bswap32(rx_buf->tcp->ack_seq);
    uint16_t hdr_length    = 4 * rx_buf->tcp->doff;
    uint8_t  tcp_flags     = rx_buf->tcp->th_flags;
    uint16_t wsize         = rx_buf->tcp->window;
    
    rx_buf->data.l4_length = l4_length;
    rx_buf->data.tcp_flags = tcp_flags;
    rx_buf->data.sport     = sport;
    rx_buf->data.dport     = dport;
    
    RTE_LOG(INFO, SS, "rx tcp packet: sport: %hu dport: %hu seq: %u ack: %u hlen: %hu flags: %hhx wsize: %hu\n",
        sport, dport, seq, ack_seq, hdr_length, tcp_flags, wsize);
    
    if (!rx_buf->data.self) {
        return rv;
    }
        
    // XXX: check for sFlow, NetFlow, or Syslog
    switch (rx_buf->data.dport) {
        case L4_PORT_SYSLOG: {
            RTE_LOG(INFO, SS, "rx tcp syslog packet\n");
            break;
        }
        case L4_PORT_SYSLOG_TLS: {
            RTE_LOG(INFO, SS, "rx tcp syslog-tls packet\n");
            break;
        }
        case L4_PORT_SFLOW: {
            RTE_LOG(INFO, SS, "rx tcp sFlow packet\n");
            break;
        }
        case L4_PORT_NETFLOW: {
            RTE_LOG(INFO, SS, "rx tcp NetFlow packet\n");
            break;
        }
    }
    
    return rv;
}
