#include <rte_byteorder.h>
#include <rte_hexdump.h>

#include "common.h"
#include "sdn_sensor.h"

int ss_frame_prep_eth(ss_frame_t* tx_buf, int port_id, eth_addr_t* d_addr, uint16_t type) {
    tx_buf->port_id = port_id;

    tx_buf->mbuf = rte_pktmbuf_alloc(ss_pool);
    if (tx_buf->mbuf == NULL) {
        RTE_LOG(ERR, SS, "could not allocate ethernet mbuf\n");
        goto error_out;
    }

    rte_pktmbuf_reset(tx_buf->mbuf);
    tx_buf->eth = (eth_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(eth_hdr_t));
    if (tx_buf->eth == NULL) {
        RTE_LOG(ERR, SS, "could not allocate ethernet mbuf\n");
        goto error_out;
    }
    ether_addr_copy(d_addr, &tx_buf->eth->d_addr);
    ether_addr_copy(&port_eth_addrs[port_id], &tx_buf->eth->s_addr);
    tx_buf->eth->ether_type = rte_bswap16(type);
    rte_memdump(stdout, "prep eth src", &tx_buf->eth->s_addr, sizeof(tx_buf->eth->s_addr));
    rte_memdump(stdout, "prep eth dst", &tx_buf->eth->d_addr, sizeof(tx_buf->eth->d_addr));
    tx_buf->active = 1;

    return 0;

    error_out:
    if (tx_buf->mbuf) {
        tx_buf->active = 0;
        rte_pktmbuf_free(tx_buf->mbuf);
        tx_buf->mbuf = NULL;
    }
    return -1;
}

void ss_frame_handle(struct rte_mbuf* mbuf, unsigned int port_id) {
    int rv;
    ss_frame_t rx_buf;
    ss_frame_t tx_buf;
    memset(&rx_buf, 0, sizeof(rx_buf));
    memset(&tx_buf, 0, sizeof(tx_buf));

    rx_buf.port_id  = port_id;
    rx_buf.length   = rte_pktmbuf_pkt_len(mbuf);
    rx_buf.mbuf     = mbuf;

    if (rx_buf.length < sizeof(eth_hdr_t)) {
        RTE_LOG(ERR, SS, "received runt Ethernet frame of length %u:\n", rx_buf.length);
        rte_pktmbuf_dump(stdout, mbuf, rte_pktmbuf_pkt_len(mbuf));
        goto out;
    }
    rx_buf.eth = rte_pktmbuf_mtod(mbuf, eth_hdr_t*);
    rte_memdump(stdout, "eth src", &rx_buf.eth->s_addr, sizeof(rx_buf.eth->s_addr));
    rte_memdump(stdout, "eth dst", &rx_buf.eth->d_addr, sizeof(rx_buf.eth->d_addr));

    uint16_t ether_type = rte_bswap16(rx_buf.eth->ether_type);
    switch (ether_type) {
        case ETHER_TYPE_VLAN: {
            RTE_LOG(INFO, SS, "port %u received unsupported VLAN frame:\n", port_id);
            rte_pktmbuf_dump(stdout, mbuf, rte_pktmbuf_pkt_len(mbuf));
            break;
        }
        case ETHER_TYPE_ARP:  {
            ss_frame_handle_arp(&rx_buf, &tx_buf);
            break;
        }
        case ETHER_TYPE_IPV4: {
            if (rx_buf.length < sizeof(eth_hdr_t) + sizeof(ip4_hdr_t)) {
                RTE_LOG(ERR, SS, "received runt IPv4 frame of length %u:\n", rx_buf.length);
                rte_pktmbuf_dump(stdout, mbuf, rte_pktmbuf_pkt_len(mbuf));
                goto out;
            }
            ss_frame_handle_ip4(&rx_buf, &tx_buf);
            break;
        }
        case ETHER_TYPE_IPV6: {
            if (rx_buf.length < sizeof(eth_hdr_t) + sizeof(ip6_hdr_t)) {
                RTE_LOG(ERR, SS, "received runt IPv6 frame of length %u:\n", rx_buf.length);
                rte_pktmbuf_dump(stdout, mbuf, rte_pktmbuf_pkt_len(mbuf));
                goto out;
            }
            ss_frame_handle_ip6(&rx_buf, &tx_buf);
            break;
        }
        default: {
            RTE_LOG(INFO, SS, "port %u received unsupported 0x%04hx frame:\n", port_id, ether_type);
            rte_pktmbuf_dump(stdout, mbuf, rte_pktmbuf_pkt_len(mbuf));
            break;
        }
    }

    out:

    if (rx_buf.mbuf) {
        rte_pktmbuf_free(rx_buf.mbuf);
        rx_buf.mbuf = NULL;
    }

    if (tx_buf.active && tx_buf.mbuf) {
        RTE_LOG(INFO, SS, "sending tx_buf size %d\n", rte_pktmbuf_pkt_len(tx_buf.mbuf));
        rv = ss_send_packet(tx_buf.mbuf, tx_buf.port_id);
        if (rv) {
            RTE_LOG(ERR, SS, "could not transmit tx_buf, rv: %d\n", rv);
            // XXX: what would we do here?
            rte_pktmbuf_free(tx_buf.mbuf);
            tx_buf.mbuf = NULL;
        }
    }
    else {
        RTE_LOG(ERR, SS, "not sending tx_buf marked inactive\n");
        if (tx_buf.mbuf) {
            rte_pktmbuf_dump(stdout, tx_buf.mbuf, rte_pktmbuf_pkt_len(tx_buf.mbuf));
            rte_pktmbuf_free(tx_buf.mbuf);
            tx_buf.mbuf = NULL;
        }
    }
}

// XXX: eventually allow VLAN to be recursive
int ss_frame_handle_eth(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    return 0;
}

int ss_frame_handle_arp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    rx_buf->arp = (arp_hdr_t*) ((uint8_t*) rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*) + sizeof(eth_hdr_t));
    printf("eth size %ld\n", (uint8_t*) rx_buf->arp - (uint8_t*) rx_buf->eth);

    rte_memdump(stdout, "arp src", &rx_buf->arp->arp_sha, sizeof(rx_buf->arp->arp_sha));
    rte_memdump(stdout, "arp dst", &rx_buf->arp->arp_tha, sizeof(rx_buf->arp->arp_tha));
    rte_memdump(stdout, "ip src",  &rx_buf->arp->arp_spa, sizeof(rx_buf->arp->arp_spa));
    rte_memdump(stdout, "ip dst",  &rx_buf->arp->arp_tpa, sizeof(rx_buf->arp->arp_tpa));
    rte_memdump(stdout, "in dst",  &ss_conf->ip4_address.ip4, IPV4_ADDR_LEN);
    rte_pktmbuf_dump(stdout, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));

    int is_ip_daddr_ok = memcmp(&rx_buf->arp->arp_tpa, &ss_conf->ip4_address.ip4, IPV4_ADDR_LEN) == 0;
    if (!is_ip_daddr_ok) {
        RTE_LOG(INFO, SS, "arp request is not for this system, ignoring\n");
        goto error_out;
    }

    rv = ss_frame_prep_eth(tx_buf, rx_buf->port_id, (eth_addr_t*) &rx_buf->eth->s_addr, ETHER_TYPE_ARP);
    if (rv) {
        RTE_LOG(ERR, SS, "could not prepare ethernet mbuf\n");
        goto error_out;
    }

    tx_buf->arp = (arp_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(arp_hdr_t));
    if (tx_buf->arp == NULL) {
        RTE_LOG(ERR, SS, "could not allocate ethernet mbuf\n");
        goto error_out;
    }
    tx_buf->arp->arp_hrd = rte_bswap16(ARPHRD_ETHER);
    tx_buf->arp->arp_pro = rte_bswap16(ETHER_TYPE_IPV4);
    tx_buf->arp->arp_hln = ETHER_ADDR_LEN;
    tx_buf->arp->arp_pln = IPV4_ADDR_LEN;
    tx_buf->arp->arp_op  = rte_bswap16(ARPOP_REPLY);
    // copy port eth_addr     into tx arp_src_eth_addr
    // copy rx   eth_src_addr into tx arp_dst_eth_addr
    ether_addr_copy(&port_eth_addrs[rx_buf->port_id], (eth_addr_t*) &tx_buf->arp->arp_sha);
    rte_memcpy(&tx_buf->arp->arp_spa, &ss_conf->ip4_address.ip4, IPV4_ADDR_LEN);
    ether_addr_copy((eth_addr_t*) &rx_buf->eth->s_addr, (eth_addr_t*) tx_buf->arp->arp_tha);
    rte_memcpy(&tx_buf->arp->arp_tpa, &rx_buf->arp->arp_spa, IPV4_ADDR_LEN);

    return 0;

    error_out:
    if (tx_buf->mbuf) {
        RTE_LOG(ERR, SS, "could not process arp frame\n");
        tx_buf->active = 0;
        rte_pktmbuf_free(tx_buf->mbuf);
        tx_buf->mbuf = NULL;
    }
    return -1;
}

int ss_frame_handle_ndp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    rx_buf->ndp_rx = (ndp_request_t*) ((uint8_t*) rx_buf->ip6 + sizeof(ip6_hdr_t));

    rte_memdump(stdout, "ndp  dst", &rx_buf->ndp_rx->hdr.nd_ns_target, sizeof(rx_buf->ndp_rx->hdr.nd_ns_target));
    rte_memdump(stdout, "self    ", &ss_conf->ip6_address.ip6, sizeof(ss_conf->ip6_address.ip6));
    rte_pktmbuf_dump(stdout, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));

    int is_ndp_saddr_ok = memcmp(&rx_buf->ndp_rx->hdr.nd_ns_target, &ss_conf->ip6_address.ip6, sizeof(rx_buf->ndp_rx->hdr.nd_ns_target)) == 0;
    if (!is_ndp_saddr_ok) {
        RTE_LOG(INFO, SS, "ndp request is not for this system, ignoring\n");
        goto error_out;
    }

    rv = ss_frame_prep_eth(tx_buf, rx_buf->port_id, (eth_addr_t*) &rx_buf->eth->s_addr, ETHER_TYPE_IPV6);
    if (rv) {
        RTE_LOG(ERR, SS, "could not prepare ethernet mbuf\n");
        goto error_out;
    }

    tx_buf->ip6 = (ip6_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(ip6_hdr_t));
    if (tx_buf->ip6 == NULL) {
        RTE_LOG(ERR, SS, "could not allocate mbuf ipv6 header\n");
        goto error_out;
    }
    tx_buf->ip6->ip6_flow = rte_bswap32(0x60000000);
    tx_buf->ip6->ip6_plen = rte_bswap16(sizeof(ndp_reply_t));
    tx_buf->ip6->ip6_hlim = 0x0ff; // XXX: use constant
    tx_buf->ip6->ip6_nxt  = IPPROTO_ICMPV6;
    rte_memcpy(&tx_buf->ip6->ip6_dst, &rx_buf->ip6->ip6_src, sizeof(tx_buf->ip6->ip6_dst));
    rte_memcpy(&tx_buf->ip6->ip6_src, &ss_conf->ip6_address.ip6, sizeof(tx_buf->ip6->ip6_src));

    tx_buf->ndp_tx = (ndp_reply_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(ndp_reply_t));
    tx_buf->icmp6  = (icmp6_hdr_t*) tx_buf->ndp_tx;
    if (tx_buf->ndp_tx == NULL) {
        RTE_LOG(ERR, SS, "could not allocate mbuf ndp header\n");
        goto error_out;
    }
    tx_buf->ndp_tx->hdr.nd_na_type     = ND_NEIGHBOR_ADVERT;
    tx_buf->ndp_tx->hdr.nd_na_code     = 0;
    tx_buf->ndp_tx->hdr.nd_na_cksum    = 0;
    // Flags:
    // Router:    0 (not router)
    // Solicited: 1 (requested by remote node)
    // Override:  1 (override old mapping)
    tx_buf->ndp_tx->hdr.nd_na_flags_reserved = rte_bswap32(0x60000000);
    tx_buf->ndp_tx->lhdr.nd_opt_type         = ND_OPT_TARGET_LINKADDR;
    // XXX: length needs to be 1 8-byte width
    // XXX: find a nicer way to code this
    tx_buf->ndp_tx->lhdr.nd_opt_len          = 1;

    memset(&tx_buf->ndp_tx->nd_addr, 0, NDP_ADDR_LEN);
    // copy port eth_addr     into tx ndp_src_eth_addr
    ether_addr_copy(&port_eth_addrs[rx_buf->port_id], (eth_addr_t*) &tx_buf->ndp_tx->nd_addr);
    rte_memcpy(&tx_buf->ndp_tx->hdr.nd_na_target, &ss_conf->ip6_address.ip6, IPV6_ALEN);

    rv = ss_frame_prepare_icmp6(tx_buf, (uint8_t*) tx_buf->ndp_tx, sizeof(ndp_reply_t));
    if (rv) {
        RTE_LOG(ERR, SS, "could not prepare ndp frame\n");
        goto error_out;
    }

    return 0;

    error_out:
    if (tx_buf->mbuf) {
        RTE_LOG(ERR, SS, "could not process ndp frame\n");
        tx_buf->active = 0;
        rte_pktmbuf_free(tx_buf->mbuf);
        tx_buf->mbuf = NULL;
    }
    return -1;
}

