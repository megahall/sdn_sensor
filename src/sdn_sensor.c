#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wordexp.h>

#include <bsd/sys/queue.h>

#include <net/if_arp.h>
#include <netinet/in.h>

#include <sys/types.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_hexdump.h>

#include "checksum.h"
#include "common.h"
#include "sdn_sensor.h"
#include "dpdk.h"
#include "sensor_configuration.h"

ss_conf_t* ss_conf = NULL;

//const char* icmp_payload = "mhallmhallmhallmhallmhallmhallmhallmhall!!!!!!!!";

static uint16_t rxd_count = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t txd_count = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr port_eth_addrs[RTE_MAX_ETHPORTS];

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 0, /**< IP checksum offload disabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 0, /**< CRC stripped by hardware */
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = RX_PTHRESH,
        .hthresh = RX_HTHRESH,
        .wthresh = RX_WTHRESH,
    },
};

static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = TX_PTHRESH,
        .hthresh = TX_HTHRESH,
        .wthresh = TX_WTHRESH,
    },
    .tx_free_thresh = 0, /* Use PMD default values */
    .tx_rs_thresh = 0, /* Use PMD default values */
    .txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};

struct rte_mempool* ss_pool = NULL;

struct ss_port_statistics port_statistics[RTE_MAX_ETHPORTS];

/* A tsc-based timer responsible for triggering statistics printout */
/* default period is 10 seconds */
static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000;

/* Send the burst of packets on an output interface */
int ss_send_burst(struct lcore_queue_conf *queue_conf, unsigned int n, uint8_t port) {
    struct rte_mbuf** mbufs;
    unsigned int rv;
    unsigned int queueid =0;

    mbufs = (struct rte_mbuf**) queue_conf->tx_table[port].mbufs;

    rv = rte_eth_tx_burst(port, (uint16_t) queueid, mbufs, (uint16_t) n);
    port_statistics[port].tx += rv;
    if (unlikely(rv < n)) {
        port_statistics[port].dropped += (n - rv);
        do {
            rte_pktmbuf_free(mbufs[rv]);
        } while (++rv < n);
    }

    return 0;
}

/* Enqueue packets for TX and prepare them to be sent */
int ss_send_packet(struct rte_mbuf *m, uint8_t port_id) {
    unsigned int lcore_id;
    unsigned int length;
    struct lcore_queue_conf *queue_conf;

    lcore_id = rte_lcore_id();

    queue_conf = &lcore_queue_conf[lcore_id];
    length = queue_conf->tx_table[port_id].length;
    queue_conf->tx_table[port_id].mbufs[length] = m;
    length++;

    /* enough pkts to be sent */
    if (unlikely(length == MAX_PKT_BURST)) {
        ss_send_burst(queue_conf, MAX_PKT_BURST, port_id);
        length = 0;
    }

    queue_conf->tx_table[port_id].length = length;
    return 0;
}

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

// ICMPv6 Pseudo Header
// 
// Source Address
// Destination Address
// 
// ICMPv6 Length (32 bits)
// Zeros         (24 bits)
// Next Header   ( 8 bits)
int ss_frame_prepare_icmp6(ss_frame_t* tx_buf, uint8_t* pl_ptr, uint32_t pl_len) {
    rte_mbuf_t* pmbuf = NULL;
    uint8_t* pptr;
    uint32_t icmp_len;
    uint32_t zeros_nxt;
    uint16_t checksum;
    
    pmbuf = rte_pktmbuf_alloc(ss_pool);
    if (pmbuf == NULL) {
        RTE_LOG(ERR, SS, "could not allocate mbuf icmp6 pseudo header\n");
        goto error_out;
    }
    icmp_len  = rte_bswap32(pl_len);
    zeros_nxt = rte_bswap32((uint32_t) tx_buf->ip6->ip6_nxt);
    
    pptr = (uint8_t*) rte_pktmbuf_append(pmbuf, sizeof(tx_buf->ip6->ip6_src));
    rte_memcpy(pptr, &tx_buf->ip6->ip6_src, sizeof(tx_buf->ip6->ip6_src));
    pptr = (uint8_t*) rte_pktmbuf_append(pmbuf, sizeof(tx_buf->ip6->ip6_dst));
    rte_memcpy(pptr, &tx_buf->ip6->ip6_dst, sizeof(tx_buf->ip6->ip6_dst));
    pptr = (uint8_t*) rte_pktmbuf_append(pmbuf, 4);
    rte_memcpy(pptr, &icmp_len, sizeof(icmp_len));
    pptr = (uint8_t*) rte_pktmbuf_append(pmbuf, 4);
    rte_memcpy(pptr, &zeros_nxt, sizeof(zeros_nxt));
    pptr = (uint8_t*) rte_pktmbuf_append(pmbuf, pl_len);
    printf("icmp6 tx size %u\n", pl_len);
    rte_memcpy(pptr, pl_ptr, pl_len);
    printf("pseudo-header:\n");
    rte_pktmbuf_dump(stdout, pmbuf, rte_pktmbuf_pkt_len(pmbuf));
    checksum = ss_in_cksum(rte_pktmbuf_mtod(pmbuf, uint16_t*), rte_pktmbuf_pkt_len(pmbuf));
    rte_pktmbuf_free(pmbuf);
    tx_buf->icmp6->icmp6_cksum = checksum;
    //tx_buf->ndp_tx->hdr.nd_na_cksum = checksum;

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

int ss_frame_handle_echo4(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    uint16_t checksum;
    uint8_t* dptr;
    
    rv = ss_frame_prep_eth(tx_buf, rx_buf->port_id, (eth_addr_t*) &rx_buf->eth->s_addr, ETHER_TYPE_IPV4);
    if (rv) {
        RTE_LOG(ERR, SS, "could not prepare ethernet mbuf\n");
        goto error_out;
    }
    
    tx_buf->ip4 = (ip4_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(ip4_hdr_t));
    if (tx_buf->ip4 == NULL) {
        RTE_LOG(ERR, SS, "could not allocate mbuf ipv4 header\n");
        goto error_out;
    }
    tx_buf->ip4->version             = 0x4;
    tx_buf->ip4->ihl                 = 20 / 4;
    tx_buf->ip4->tos                 = 0x0;
    //tx_buf->ip4->tot_len             = ????;
    tx_buf->ip4->id                  = rte_bswap16(0x0000);
    tx_buf->ip4->frag_off            = 0;
    tx_buf->ip4->ttl                 = 0xff; // XXX: use constant
    tx_buf->ip4->protocol            = IPPROTO_ICMP;
    tx_buf->ip4->check               = rte_bswap16(0x0000);
    tx_buf->ip4->saddr               = ss_conf->ip4_address.ip4.addr; // bswap ?????
    tx_buf->ip4->daddr               = rx_buf->ip4->saddr;
    
    tx_buf->icmp4 = (icmp4_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(icmp4_hdr_t));
    if (tx_buf->icmp4 == NULL) {
        RTE_LOG(ERR, SS, "could not allocate mbuf icmp4 header\n");
        goto error_out;
    }
    tx_buf->icmp4->type              = ICMP_ECHOREPLY;
    tx_buf->icmp4->code              = 0;
    tx_buf->icmp4->checksum          = rte_bswap16(0x0000);
    tx_buf->icmp4->un.echo.id        = rx_buf->icmp4->un.echo.id;
    tx_buf->icmp4->un.echo.sequence  = rx_buf->icmp4->un.echo.sequence;
    dptr = (uint8_t*) rte_pktmbuf_append(tx_buf->mbuf, rte_bswap16(rx_buf->ip4->tot_len) - sizeof(ip4_hdr_t) - sizeof(icmp4_hdr_t));
    if (dptr == NULL) {
        RTE_LOG(ERR, SS, "could not allocate mbuf icmp4 dptr\n");
        goto error_out;
    }
    memcpy(dptr, (uint8_t*) rx_buf->icmp4 + sizeof(icmp4_hdr_t), rx_buf->ip4->tot_len - sizeof(ip4_hdr_t) - sizeof(icmp4_hdr_t));
    
    checksum = ss_in_cksum((uint16_t*) tx_buf->icmp4, rte_pktmbuf_pkt_len(tx_buf->mbuf) - ((uint8_t*) tx_buf->icmp4 - rte_pktmbuf_mtod(tx_buf->mbuf, uint8_t*)));
    tx_buf->icmp4->checksum          = checksum;
    
    tx_buf->ip4->tot_len             = rte_bswap16(rte_pktmbuf_pkt_len(tx_buf->mbuf) - sizeof(eth_hdr_t)); // XXX: better way?
    checksum = ss_in_cksum((uint16_t*) tx_buf->ip4, sizeof(ip4_hdr_t));
    tx_buf->ip4->check               = checksum;
    
    return 0;
    
    error_out:
    if (tx_buf->mbuf) {
        RTE_LOG(ERR, SS, "could not process icmp4 frame\n");
        tx_buf->active = 0;
        rte_pktmbuf_free(tx_buf->mbuf);
        tx_buf->mbuf = NULL;
    }
    return -1;
}

int ss_frame_handle_echo6(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    uint8_t* dptr;
    uint16_t rx_dlen;
    uint16_t tx_plen;
    
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
    tx_buf->ip6->ip6_hlim = 0x0ff; // XXX: use constant
    tx_buf->ip6->ip6_nxt  = IPPROTO_ICMPV6;
    rte_memcpy(&tx_buf->ip6->ip6_dst, &rx_buf->ip6->ip6_src, sizeof(tx_buf->ip6->ip6_dst));
    rte_memcpy(&tx_buf->ip6->ip6_src, &ss_conf->ip6_address.ip6, sizeof(tx_buf->ip6->ip6_src));
    
    tx_buf->icmp6 = (icmp6_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(icmp6_hdr_t));
    if (tx_buf->icmp6 == NULL) {
        RTE_LOG(ERR, SS, "could not allocate mbuf icmp6 header\n");
        goto error_out;
    }
    tx_buf->icmp6->icmp6_type        = ICMP6_ECHO_REPLY;
    tx_buf->icmp6->icmp6_code        = 0;
    tx_buf->icmp6->icmp6_cksum       = rte_bswap16(0x0000);
    tx_buf->icmp6->icmp6_data16[0]   = rx_buf->icmp6->icmp6_data16[0]; // ICMP ID
    tx_buf->icmp6->icmp6_data16[1]   = rx_buf->icmp6->icmp6_data16[1]; // Sequence Number
    rx_dlen                          = rte_bswap16(rx_buf->ip6->ip6_plen) - sizeof(icmp6_hdr_t);
    dptr = (uint8_t*) rte_pktmbuf_append(tx_buf->mbuf, rx_dlen);
    if (dptr == NULL) {
        RTE_LOG(ERR, SS, "could not allocate mbuf icmp6 dptr\n");
        goto error_out;
    }
    memcpy(dptr, (uint8_t*) rx_buf->icmp6 + sizeof(icmp6_hdr_t), rx_dlen);
    tx_plen                          = rte_pktmbuf_pkt_len(tx_buf->mbuf) - sizeof(eth_hdr_t) - sizeof(ip6_hdr_t); // XXX: better way?
    tx_buf->ip6->ip6_plen            = rte_bswap16(tx_plen);
    
    rv = ss_frame_prepare_icmp6(tx_buf, (uint8_t*) tx_buf->icmp6, tx_plen);
    if (rv) {
        RTE_LOG(ERR, SS, "could not prepare echo6 frame\n");
        goto error_out;
    }
    // mhall
    printf("debug echo6\n");
    rte_pktmbuf_dump(stdout, tx_buf->mbuf, rte_pktmbuf_pkt_len(tx_buf->mbuf));

    return 0;
    
    error_out:
    if (tx_buf->mbuf) {
        RTE_LOG(ERR, SS, "could not process icmp6 frame\n");
        tx_buf->active = 0;
        rte_pktmbuf_free(tx_buf->mbuf);
        tx_buf->mbuf = NULL;
    }
    return -1;
}

int ss_frame_handle_icmp4(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    rx_buf->icmp4 = (icmp4_hdr_t*) ((uint8_t*) rx_buf->ip4 + sizeof(ip4_hdr_t));
    
    uint8_t icmp_type = rx_buf->icmp4->type;
    switch (icmp_type) {
        case ICMP_ECHO: {
            rv = ss_frame_handle_echo4(rx_buf, tx_buf);
            break;
        }
        default: {
            RTE_LOG(INFO, SS, "port %u received unsupported icmpv4 0x%04hhx frame:\n", rx_buf->port_id, icmp_type);
            rte_pktmbuf_dump(stdout, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
            rv = -1;
            break;
        }
    }
    
    return rv;
}

int ss_frame_handle_icmp6(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    rx_buf->icmp6 = (icmp6_hdr_t*) ((uint8_t*) rx_buf->ip6 + sizeof(ip6_hdr_t));
    
    // XXX: add the PMTUD request
    uint8_t icmp_type = rx_buf->icmp6->icmp6_type;
    switch (icmp_type) {
        case ICMP6_ECHO_REQUEST: {
            rv = ss_frame_handle_echo6(rx_buf, tx_buf);
            break;
        }
        case ND_NEIGHBOR_SOLICIT: {
            rv = ss_frame_handle_ndp(rx_buf, tx_buf);
            break;
        }
        default: {
            RTE_LOG(INFO, SS, "port %u received unsupported icmpv6 0x%04hhx frame:\n", rx_buf->port_id, icmp_type);
            rte_pktmbuf_dump(stdout, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
            rv = -1;
            break;
        }
    }
    
    return rv;
}

/* main processing loop */
void ss_main_loop(void) {
    struct rte_mbuf* pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf* m;
    unsigned int lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    unsigned i, j, port_id, rx_count;
    struct lcore_queue_conf* queue_conf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;
    timer_tsc = 0;

    lcore_id = rte_lcore_id();
    queue_conf = &lcore_queue_conf[lcore_id];

    if (queue_conf->rx_port_count == 0) {
        RTE_LOG(INFO, SS, "lcore %u has nothing to do\n", lcore_id);
        return;
    }

    RTE_LOG(INFO, SS, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < queue_conf->rx_port_count; i++) {
        port_id = queue_conf->rx_port_list[i];
        RTE_LOG(INFO, SS, " -- lcoreid=%u port_id=%u\n", lcore_id, port_id);
    }

    while (1) {
        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {

            for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
                //RTE_LOG(INFO, SS, "attempt send for port %d\n", port_id);
                if (queue_conf->tx_table[port_id].length == 0) {
                    //RTE_LOG(INFO, SS, "send no frames for port %d\n", port_id);
                    continue;
                }
                //RTE_LOG(INFO, SS, "send %u frames for port %d\n", queue_conf->tx_table[port_id].length, port_id);
                ss_send_burst(&lcore_queue_conf[lcore_id], queue_conf->tx_table[port_id].length, (uint8_t) port_id);
                queue_conf->tx_table[port_id].length = 0;
            }

            /* if timer is enabled */
            if (timer_period > 0) {
                /* advance the timer */
                timer_tsc += diff_tsc;

                /* if timer has reached its timeout */
                if (unlikely(timer_tsc >= (uint64_t) timer_period)) {

                    /* do this only on master core */
                    if (lcore_id == rte_get_master_lcore()) {
                        ss_port_stats_print(port_statistics, ss_conf->port_count);
                        /* reset the timer */
                        timer_tsc = 0;
                    }
                }
            }

            prev_tsc = cur_tsc;
        }

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < queue_conf->rx_port_count; i++) {
            port_id = queue_conf->rx_port_list[i];
            rx_count = rte_eth_rx_burst((uint8_t) port_id, 0, pkts_burst, MAX_PKT_BURST);
            
            port_statistics[port_id].rx += rx_count;
            
            for (j = 0; j < rx_count; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                ss_frame_handle(m, port_id);
            }
        }
    }
}

int ss_launch_one_lcore(__attribute__((unused)) void *dummy) {
    ss_main_loop();
    return 0;
}

int main(int argc, char* argv[]) {
    ss_conf = ss_conf_file_parse();
    if (ss_conf == NULL) {
        fprintf(stderr, "could not parse sdn_sensor configuration\n");
        exit(1);
    }
    
    struct lcore_queue_conf* queue_conf;
    struct rte_eth_dev_info dev_info;
    int rv;
    uint8_t port_id, last_port;
    unsigned int lcore_id;
    unsigned int rx_lcore_id;

    /* init EAL */
    rv = rte_eal_init(ss_conf->eal_vector.we_wordc, ss_conf->eal_vector.we_wordv);
    if (rv < 0) {
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    }

    /* create the mbuf pool */
    ss_pool =
        rte_mempool_create("mbuf_pool", NB_MBUF,
                   MBUF_SIZE, 32,
                   sizeof(struct rte_pktmbuf_pool_private),
                   rte_pktmbuf_pool_init, NULL,
                   rte_pktmbuf_init, NULL,
                   rte_socket_id(), 0);
    if (ss_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
    }
    
    if (rte_eal_pci_probe() < 0) {
        rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");
    }
    
    ss_conf->port_count = rte_eth_dev_count();
    printf("port_count %d\n", ss_conf->port_count);
    if (ss_conf->port_count == 0) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
    }

    if (ss_conf->port_count > RTE_MAX_ETHPORTS) {
        ss_conf->port_count = RTE_MAX_ETHPORTS;
    }

    last_port = 0;

    /*
     * Each logical core is assigned a dedicated TX queue on each port.
     */
    rx_lcore_id = 0;
    queue_conf = NULL;
    for (port_id = 0; port_id < ss_conf->port_count; port_id++) {
        rte_eth_dev_info_get(port_id, &dev_info);
        
        /* get the lcore_id for this port */
        while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
               lcore_queue_conf[rx_lcore_id].rx_port_count ==
               ss_conf->queue_count) {
            rx_lcore_id++;
            if (rx_lcore_id >= RTE_MAX_LCORE) {
                rte_exit(EXIT_FAILURE, "Not enough cores\n");
            }
        }

        if (queue_conf != &lcore_queue_conf[rx_lcore_id]) {
            /* Assigned a new logical core in the loop above. */
            queue_conf = &lcore_queue_conf[rx_lcore_id];
        }

        queue_conf->rx_port_list[queue_conf->rx_port_count] = port_id;
        queue_conf->rx_port_count++;
        printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) port_id);
        
        /* init port */
        printf("Initializing port %u... ", (unsigned) port_id);
        fflush(stdout);
        rv = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", rv, (unsigned) port_id);
        }

        rte_eth_macaddr_get(port_id, &port_eth_addrs[port_id]);

        /* init one RX queue */
        fflush(stdout);
        rv = rte_eth_rx_queue_setup(port_id, 0, rxd_count,
                         rte_eth_dev_socket_id(port_id), &rx_conf,
                         ss_pool);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", rv, (unsigned) port_id);
        }

        /* init one TX queue on each port */
        fflush(stdout);
        rv = rte_eth_tx_queue_setup(port_id, 0, txd_count, rte_eth_dev_socket_id(port_id), &tx_conf);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", rv, (unsigned) port_id);
        }

        /* Start device */
        rv = rte_eth_dev_start(port_id);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", rv, (unsigned) port_id);
        }

        printf("done: \n");

        rte_eth_promiscuous_enable(port_id);

        printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                (unsigned) port_id,
                port_eth_addrs[port_id].addr_bytes[0],
                port_eth_addrs[port_id].addr_bytes[1],
                port_eth_addrs[port_id].addr_bytes[2],
                port_eth_addrs[port_id].addr_bytes[3],
                port_eth_addrs[port_id].addr_bytes[4],
                port_eth_addrs[port_id].addr_bytes[5]);

        /* initialize port stats */
        memset(&port_statistics, 0, sizeof(port_statistics));
    }

    //ss_port_link_status_check_all(ss_conf->port_count);

    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(ss_launch_one_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }

    return 0;
}
