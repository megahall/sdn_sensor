#include <stdint.h>
#include <stdio.h>

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <rte_byteorder.h>
#include <rte_hexdump.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "ip.h"

#include "common.h"
#include "sdn_sensor.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"

int ss_frame_handle_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    rx_buf->ip4 = (ip4_hdr_t*) ((uint8_t*) rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*) + sizeof(eth_hdr_t));
    RTE_LOG(DEBUG, STACK, "ip4 src %08x\n", rx_buf->ip4->saddr);
    RTE_LOG(DEBUG, STACK, "ip4 dst %08x\n", rx_buf->ip4->daddr);
    rte_memcpy(&rx_buf->data.sip, &rx_buf->ip4->saddr, sizeof(rx_buf->data.sip));
    rte_memcpy(&rx_buf->data.dip, &rx_buf->ip4->daddr, sizeof(rx_buf->data.dip));
    
    rx_buf->data.self = (memcmp(&rx_buf->ip4->daddr, &ss_conf->ip4_address.ip4_addr, IPV4_ALEN)) == 0;

    // XXX: walk through extension headers eventually
    RTE_LOG(DEBUG, STACK, "ip4 protocol %hhu\n", rx_buf->ip4->protocol);
    rx_buf->data.ip_protocol = rx_buf->ip4->protocol;
    rv = ss_frame_find_l4_header(rx_buf, rx_buf->ip4->protocol);
    if (rv) {
        RTE_LOG(ERR, STACK, "port %u received damaged ip4 %hhu frame:\n", rx_buf->data.port_id, rx_buf->ip4->protocol);
        rte_pktmbuf_dump(stderr, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
    }
    
    switch (rx_buf->ip4->protocol) {
        case IPPROTO_ICMP: {
            rv = ss_frame_handle_icmp4(rx_buf, tx_buf);
            break;
        }
        case IPPROTO_UDP: {
            rv = ss_frame_handle_udp(rx_buf, tx_buf);
            break;
        }
        case IPPROTO_TCP: {
            rv = ss_frame_handle_tcp(rx_buf, tx_buf);
            break;
        }
        default: {
            RTE_LOG(INFO, STACK, "port %u received unsupported ip4 %hhu frame:\n", rx_buf->data.port_id, rx_buf->ip4->protocol);
            rte_pktmbuf_dump(stderr, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
            rv = -1;
            break;
        }
    }

    return rv;
}

int ss_frame_handle_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    rx_buf->ip6 = (ip6_hdr_t*) ((uint8_t*) rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*) + sizeof(eth_hdr_t));
    //rte_memdump(stderr, "ip6 hdr", rx_buf->ip6, sizeof(ip6_hdr_t));
    if (rte_get_log_level() >= RTE_LOG_INFO)
        rte_memdump(stderr, "ip6 src", &rx_buf->ip6->ip6_src, sizeof(rx_buf->ip6->ip6_src));
    if (rte_get_log_level() >= RTE_LOG_INFO)
        rte_memdump(stderr, "ip6 dst", &rx_buf->ip6->ip6_dst, sizeof(rx_buf->ip6->ip6_dst));
    rte_memcpy(&rx_buf->data.sip, &rx_buf->ip6->ip6_src, sizeof(rx_buf->data.sip));
    rte_memcpy(&rx_buf->data.dip, &rx_buf->ip6->ip6_dst, sizeof(rx_buf->data.dip));

    rx_buf->data.self = (memcmp(&rx_buf->ip6->ip6_dst, &ss_conf->ip6_address.ip6_addr, IPV6_ALEN)) == 0;
    
    // XXX: walk through extension headers eventually
    RTE_LOG(DEBUG, STACK, "ip6 protocol %hhu\n", rx_buf->ip6->ip6_nxt);
    rx_buf->data.ip_protocol = rx_buf->ip6->ip6_nxt;
    rv = ss_frame_find_l4_header(rx_buf, rx_buf->ip6->ip6_nxt);
    if (rv) {
        RTE_LOG(ERR, STACK, "port %u received damaged ip6 %hhu frame:\n", rx_buf->data.port_id, rx_buf->ip6->ip6_nxt);
        rte_pktmbuf_dump(stderr, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
    }
    
    switch (rx_buf->ip6->ip6_nxt) {
        case IPPROTO_ICMPV6: {
            rv = ss_frame_handle_icmp6(rx_buf, tx_buf);
            break;
        }
        case IPPROTO_UDP: {
            rv = ss_frame_handle_udp(rx_buf, tx_buf);
            break;
        }
        case IPPROTO_TCP: {
            rv = ss_frame_handle_tcp(rx_buf, tx_buf);
            break;
        }
        default: {
            RTE_LOG(INFO, STACK, "port %u received unsupported ip6 %hhu frame:\n", rx_buf->data.port_id, rx_buf->ip6->ip6_nxt);
            rte_pktmbuf_dump(stderr, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
            rv = -1;
            break;
        }
    }

    return rv;
}

int ss_frame_find_l4_header(ss_frame_t* rx_buf, uint8_t ip_protocol) {
    uint16_t ether_type = rte_bswap16(rx_buf->eth->ether_type);
    
    uint8_t* l3_pointer;
    size_t   l3_size;
    
    switch (ether_type) {
        case ETHER_TYPE_IPV4: {
            l3_pointer = (uint8_t*) rx_buf->ip4;
            l3_size = sizeof(ip4_hdr_t);
            break;
        }
        case ETHER_TYPE_IPV6: {
            l3_pointer = (uint8_t*) rx_buf->ip6;
            l3_size = sizeof(ip6_hdr_t);
            break;
        }
        default: {
            RTE_LOG(ERR, STACK, "could not locate l4 header for ether type 0x%04hx\n", ether_type);
            return -1;
        }
    }
    
    switch (ip_protocol) {
        case IPPROTO_ICMP: {
            rx_buf->icmp4 = (icmp4_hdr_t*) (l3_pointer + l3_size);
            return 0;
        }
        case IPPROTO_ICMPV6: {
            rx_buf->icmp6 = (icmp6_hdr_t*) (l3_pointer + l3_size);
            return 0;
        }
        case IPPROTO_UDP: {
            rx_buf->udp   = (udp_hdr_t*) (l3_pointer + l3_size);
            return 0;
        }
        case IPPROTO_TCP: {
            rx_buf->tcp   = (tcp_hdr_t*) (l3_pointer + l3_size);
            return 0;
        }
        default: {
            RTE_LOG(ERR, STACK, "could not locate l4 header for ip protocol %hhd\n", ip_protocol);
            return -1;
        }
    }
}
