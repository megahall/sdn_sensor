#include <rte_hexdump.h>

#include "common.h"
#include "ethernet.h"
#include "sdn_sensor.h"

int ss_frame_handle_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    rx_buf->ip4 = (ip4_hdr_t*) ((uint8_t*) rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*) + sizeof(eth_hdr_t));
    rte_memdump(stdout, "ipv4 src", &rx_buf->ip4->saddr, sizeof(rx_buf->ip4->saddr));
    rte_memdump(stdout, "ipv4 dst", &rx_buf->ip4->daddr, sizeof(rx_buf->ip4->daddr));
    // XXX: check if this packet is for us

    // XXX: walk through extension headers eventually
    printf("ip4 protocol %hhu\n", rx_buf->ip4->protocol);
    switch (rx_buf->ip4->protocol) {
        case IPPROTO_ICMP: {
            rv = ss_frame_handle_icmp4(rx_buf, tx_buf);
            break;
        }
        default: {
            RTE_LOG(INFO, SS, "port %u received unsupported ipv4 0x%04hhx frame:\n", rx_buf->port_id, rx_buf->ip4->protocol);
            rte_pktmbuf_dump(stdout, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
            rv = -1;
            break;
        }
    }

    return rv;
}

int ss_frame_handle_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    rx_buf->ip6 = (ip6_hdr_t*) ((uint8_t*) rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*) + sizeof(eth_hdr_t));
    rte_memdump(stdout, "ipv6 hdr", rx_buf->ip6, sizeof(ip6_hdr_t));
    rte_memdump(stdout, "ipv6 src", &rx_buf->ip6->ip6_src, sizeof(rx_buf->ip6->ip6_src));
    rte_memdump(stdout, "ipv6 dst", &rx_buf->ip6->ip6_dst, sizeof(rx_buf->ip6->ip6_dst));
    // XXX: check if this packet is for us

    // XXX: walk through extension headers eventually
    switch (rx_buf->ip6->ip6_nxt) {
        case IPPROTO_ICMPV6: {
            rv = ss_frame_handle_icmp6(rx_buf, tx_buf);
            break;
        }
        default: {
            RTE_LOG(INFO, SS, "port %u received unsupported ipv6 0x%04hhx frame:\n", rx_buf->port_id, rx_buf->ip6->ip6_nxt);
            rte_pktmbuf_dump(stdout, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
            rv = -1;
            break;
        }
    }

    return rv;
}

int ss_frame_handle_ip(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    uint8_t protocol;

    if (rx_buf->ip4) {
        protocol = rx_buf->ip4->protocol;
    }
    else if (rx_buf->ip6) {
        protocol = rx_buf->ip6->ip6_nxt;
    }
    else {
        RTE_LOG(ERR, SS, "unknown IP packet with EtherType %02hx\n", rx_buf->eth->ether_type);
        return -1;
    }

    switch (protocol) {
        // ICMP
        // IGMP
        // TCP
        // UDP
        // DCCP
        // IPv4 tunneled, IPv6 tunneled
        // GRE
        // ICMPv6
        // ESP
        // AH
        // SCTP
    }

    return 0;
}

