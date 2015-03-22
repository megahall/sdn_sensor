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
#include "l4_utils.h"
#include "tcp.h"
#include "udp.h"

int ss_frame_handle_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    rx_buf->ip4 = (ip4_hdr_t*) ((uint8_t*) rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*) + sizeof(eth_hdr_t));
    rte_memcpy(&rx_buf->data.sip, &rx_buf->ip4->saddr, sizeof(rx_buf->data.sip));
    rte_memcpy(&rx_buf->data.dip, &rx_buf->ip4->daddr, sizeof(rx_buf->data.dip));
    
    rx_buf->data.self = (memcmp(&rx_buf->ip4->daddr, &ss_conf->ip4_address.ip4_addr, IPV4_ALEN)) == 0;

    RTE_LOG(DEBUG, L3L4, "rx ip4 src %08x, ip4 dst %08x, protocol %hhu, self %hhu\n",
        rte_bswap32(rx_buf->ip4->saddr), rte_bswap32(rx_buf->ip4->daddr), rx_buf->ip4->protocol, rx_buf->data.self);

    // XXX: walk through extension headers eventually
    rx_buf->data.ip_protocol = rx_buf->ip4->protocol;
    rv = ss_frame_find_l4_header(rx_buf, rx_buf->ip4->protocol);
    if (rv && rx_buf->ip4->protocol != IPPROTO_IGMP) {
        RTE_LOG(ERR, L3L4, "port %u received damaged ip4 %hhu frame:\n", rx_buf->data.port_id, rx_buf->ip4->protocol);
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
            if (rx_buf->ip4->protocol != IPPROTO_IGMP) {
                RTE_LOG(INFO, L3L4, "port %u received unsupported ip4 %hhu frame:\n", rx_buf->data.port_id, rx_buf->ip4->protocol);
                rte_pktmbuf_dump(stderr, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
            }
            rv = -1;
            break;
        }
    }

    return rv;
}

int ss_frame_handle_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    rx_buf->ip6 = (ip6_hdr_t*) ((uint8_t*) rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*) + sizeof(eth_hdr_t));
    if (rte_get_log_level() >= RTE_LOG_DEBUG) {
        rte_memdump(stderr, "ip6 src", &rx_buf->ip6->ip6_src, sizeof(rx_buf->ip6->ip6_src));
        rte_memdump(stderr, "ip6 dst", &rx_buf->ip6->ip6_dst, sizeof(rx_buf->ip6->ip6_dst));
        RTE_LOG(DEBUG, L3L4, "ip6 protocol %hhu\n", rx_buf->ip6->ip6_nxt);
    }
    rte_memcpy(&rx_buf->data.sip, &rx_buf->ip6->ip6_src, sizeof(rx_buf->data.sip));
    rte_memcpy(&rx_buf->data.dip, &rx_buf->ip6->ip6_dst, sizeof(rx_buf->data.dip));

    rx_buf->data.self = (memcmp(&rx_buf->ip6->ip6_dst, &ss_conf->ip6_address.ip6_addr, IPV6_ALEN)) == 0;
    
    // XXX: walk through extension headers eventually
    rx_buf->data.ip_protocol = rx_buf->ip6->ip6_nxt;
    rv = ss_frame_find_l4_header(rx_buf, rx_buf->ip6->ip6_nxt);
    if (rv) {
        RTE_LOG(ERR, L3L4, "port %u received damaged ip6 %hhu frame:\n",
            rx_buf->data.port_id, rx_buf->ip6->ip6_nxt);
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
            RTE_LOG(INFO, L3L4, "port %u received unsupported ip6 %hhu frame:\n",
                rx_buf->data.port_id, rx_buf->ip6->ip6_nxt);
            rte_pktmbuf_dump(stderr, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
            rv = -1;
            break;
        }
    }

    return rv;
}

/* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
int ss_frame_check_ipv4(ip4_hdr_t* ip4, uint32_t l2_length) {
    /*
     * 1. The packet length reported by the Link Layer must be large
     * enough to hold the minimum length legal IP datagram (20 bytes).
     */
    if (l2_length < sizeof(ip4_hdr_t))
        return -1;
    
    /* 2. The IP checksum must be correct. */
    /* XXX: add code / HW check for this */
    
    /*
     * 3. The IP version number must be 4. If the version number is not 4
     * then the packet may be another version of IP, such as IPng or
     * ST-II.
     */
    if (ip4->version != 4)
        return -3;
    
    /*
     * 4. The IP header length field must be large enough to hold the
     * minimum length legal IP datagram (20 bytes = 5 words).
     */
    if (ip4->ihl < 5)
        return -4;
    
    /*
     * 5. The IP total length field must be large enough to hold the IP
     * datagram header, whose length is specified in the IP header length
     * field.
     */
    if (rte_bswap16(ip4->tot_len) < sizeof(ip4_hdr_t))
        return -5;
    
    return 0;
}
