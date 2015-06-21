#include <ctype.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdio.h>

#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>

#include "common.h"
#include "ip_utils.h"
#include "l4_utils.h"
#include "sdn_sensor.h"
#include "sensor_conf.h"

int ss_buffer_dump(const char* source, uint8_t* buffer, uint16_t length) {
    printf("dump %s buffer: size [%hu]: [ ", source, length);

    for (size_t i = 0; i < length; ++i) {
        char c = (char) buffer[i];
        if (isalnum(c) || ispunct(c)) {
            printf("%c", c);
        }
        else {
            printf("[0x%hhx]", c);
        }
    }
    printf(" ]\n");

    return 0;
}

int ss_frame_layer_off_len_get(ss_frame_t* rx_buf,
    void* layer_start, size_t layer_hdr_size,
    uint8_t** layer_offset, uint16_t* layer_length) {

    uint8_t* mbuf_start   = rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*);
    uint16_t mbuf_length  = (uint16_t) rte_pktmbuf_pkt_len(rx_buf->mbuf);

    *layer_offset = ((uint8_t*) layer_start) + layer_hdr_size;
    *layer_length = (uint16_t) (mbuf_length - (*layer_offset - mbuf_start));

    uint16_t total_length = (uint16_t) ((*layer_offset + *layer_length) - mbuf_start);
    if (total_length > mbuf_length) {
        RTE_LOG(ERR, UTILS, "received unsafe packet, total_length %u > mbuf_length %u\n",
        total_length, mbuf_length);
        *layer_offset = NULL;
        *layer_length = 0;
        return -1;
    }

    return 0;
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
            RTE_LOG(ERR, UTILS, "could not locate l4 header for ether type 0x%04hx\n", ether_type);
            return -1;
        }
    }

    switch (ip_protocol) {
        case IPPROTO_ICMPV4: {
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
            RTE_LOG(ERR, UTILS, "could not locate l4 header for ip protocol %hhd\n", ip_protocol);
            return -1;
        }
    }
}

uint8_t* ss_phdr_append(rte_mbuf_t* pmbuf, void* data, uint16_t length) {
    uint8_t* pptr = (uint8_t*) rte_pktmbuf_append(pmbuf, length);
    rte_memcpy(pptr, data, length);
    return pptr;
}

int ss_frame_prepare_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    tx_buf->ip4 = (ip4_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(ip4_hdr_t));
    if (tx_buf->ip4 == NULL) {
        RTE_LOG(ERR, L3L4, "could not allocate mbuf ipv4 header\n");
        return -1;
    }
    tx_buf->ip4->version   = 0x4;
    tx_buf->ip4->ihl       = 20 / 4;
    tx_buf->ip4->tos       = 0x0;
    // L4 must set this
    //tx_buf->ip4->tot_len = ????;
    tx_buf->ip4->id        = rte_bswap16(0x0000);
    tx_buf->ip4->frag_off  = 0;
    tx_buf->ip4->ttl       = 0xff; // XXX: use constant
    tx_buf->ip4->protocol  = rx_buf->ip4->protocol;
    tx_buf->ip4->check     = rte_bswap16(0x0000);
    tx_buf->ip4->saddr     = ss_conf->ip4_address.ip4_addr.addr; // bswap ?????
    tx_buf->ip4->daddr     = rx_buf->ip4->saddr;

    return 0;
}

int ss_frame_prepare_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    tx_buf->ip6 = (ip6_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(ip6_hdr_t));
    if (tx_buf->ip6 == NULL) {
        RTE_LOG(ERR, L3L4, "could not allocate mbuf ipv6 header\n");
        return -1;
    }
    tx_buf->ip6->ip6_flow   = rte_bswap32(0x60000000);
    tx_buf->ip6->ip6_hlim   = 0x0ff; // XXX: use constant
    tx_buf->ip6->ip6_nxt    = rx_buf->ip6->ip6_nxt;
    // L4 must set this
    //tx_buf->ip6->ip6_plen = ????;
    rte_memcpy(&tx_buf->ip6->ip6_dst, &rx_buf->ip6->ip6_src, sizeof(tx_buf->ip6->ip6_dst));
    rte_memcpy(&tx_buf->ip6->ip6_src, &ss_conf->ip6_address.ip6_addr, sizeof(tx_buf->ip6->ip6_src));

    return 0;
}

void ss_frame_destroy(ss_frame_t* fbuf) {
    if (!fbuf) return;
    fbuf->active = 0;
    if (fbuf->mbuf) {
        rte_pktmbuf_free(fbuf->mbuf);
        fbuf->mbuf = NULL;
    }
}
