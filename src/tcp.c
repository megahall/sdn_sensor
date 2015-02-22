#include <stdint.h>
#include <stdio.h>

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_hexdump.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_rwlock.h>

#include "tcp.h"

#include "checksum.h"
#include "common.h"
#include "ethernet.h"
#include "je_utils.h"
#include "sdn_sensor.h"

#define SS_TCP_FLAGS_STR_MAX 32

// XXX: how can I place a TCP hash on each socket?
static struct rte_hash_parameters tcp_hash_params = {
    .name               = "tcp_hash_socket_0",
    .entries            = L4_TCP_HASH_SIZE,
    .bucket_entries     = L4_TCP_BUCKET_SIZE,
    .key_len            = sizeof(ss_flow_key_t),
    .hash_func          = rte_hash_crc,
    .hash_func_init_val = 0,
    .socket_id          = 0,
};

static rte_rwlock_t tcp_hash_lock;
static rte_hash_t* tcp_hash;
static ss_tcp_socket_t* tcp_sockets[L4_TCP_HASH_SIZE];
static char tcp_flags_strings[RTE_MAX_LCORE][SS_TCP_FLAGS_STR_MAX];

int ss_tcp_init() {
    rte_rwlock_init(&tcp_hash_lock);

    tcp_hash = rte_hash_create(&tcp_hash_params);
    if (tcp_hash == NULL) {
        RTE_LOG(ERR, STACK, "could not initialize tcp socket hash\n");
        return -1;
    }
    
    return 0;
}

int ss_flow_key_dump(const char* message, ss_flow_key_t* key) {
/*
    struct ss_flow_key_s {
    uint8_t  sip[IPV6_ALEN];
    uint8_t  dip[IPV6_ALEN];
    uint16_t sport;
    uint16_t dport;
    uint8_t  protocol;
*/
    uint8_t family;
    const char* protocol;
    char sip[SS_ADDR_STR_MAX];
    char dip[SS_ADDR_STR_MAX];
    uint16_t sport = rte_bswap16(key->sport);
    uint16_t dport = rte_bswap16(key->dport);
    
    memset(sip, 0, sizeof(sip));
    memset(dip, 0, sizeof(dip));
    
    if (key->protocol == L4_TCP4) {
        family = SS_AF_INET4;
        protocol = "L4_TCP4";
    }
    else if (key->protocol == L4_TCP6) {
        family = SS_AF_INET6;
        protocol = "L4_TCP6";
    }
    else {
        // XXX: now panic and freak out?
        return -1;
    }
    ss_inet_ntop_raw(family, key->sip, sip, sizeof(sip));
    ss_inet_ntop_raw(family, key->dip, dip, sizeof(dip));
    
    RTE_LOG(INFO, STACK, "%s: flow key: %s: %s:%hu --> %s:%hu\n",
        message, protocol, sip, sport, dip, dport);
    
    return 0;
}

const char* ss_tcp_flags_dump(uint8_t tcp_flags) {
    char* flags = tcp_flags_strings[rte_lcore_id()];
    int offset = 0;
    if      (tcp_flags & TH_URG) {
        offset += snprintf(flags + offset, sizeof(flags) - offset, "%s ", "URG");
    }    
    else if (tcp_flags & TH_ACK) {
        offset += snprintf(flags + offset, sizeof(flags) - offset, "%s ", "ACK");
    }    
    else if (tcp_flags & TH_PSH) {
        offset += snprintf(flags + offset, sizeof(flags) - offset, "%s ", "PSH");
    }    
    else if (tcp_flags & TH_RST) {
        offset += snprintf(flags + offset, sizeof(flags) - offset, "%s ", "RST");
    }    
    else if (tcp_flags & TH_SYN) {
        offset += snprintf(flags + offset, sizeof(flags) - offset, "%s ", "SYN");
    }    
    else if (tcp_flags & TH_FIN) {
        offset += snprintf(flags + offset, sizeof(flags) - offset, "%s ", "FIN");
    }
    return flags;
}

int ss_tcp_socket_init(ss_flow_key_t* key, ss_tcp_socket_t* socket) {
    rte_memcpy(&socket->key, key, sizeof(ss_flow_key_t));
    rte_spinlock_init(&socket->lock);
    socket->state = SS_TCP_CLOSED;
    socket->rx_ticks = rte_rdtsc();
    socket->tx_ticks = rte_rdtsc();
    socket->rx_buf_offset = 0;
    socket->mss = 0;
    socket->rx_failures = 0;
    return 0;
}

ss_tcp_socket_t* ss_tcp_socket_create(ss_flow_key_t* key, ss_frame_t* rx_buf) {
    // XXX: should these be allocated from jemalloc or RTE alloc?
    ss_tcp_socket_t* socket = je_calloc(1, sizeof(ss_flow_key_t));
    if (socket == NULL) goto error_out;
    
    ss_tcp_socket_init(key, socket);
    rte_spinlock_lock(&socket->lock);
    if (rx_buf->tcp->th_flags == TH_SYN) {
        socket->state = SS_TCP_SYN_RX;
    }
    else {
        socket->state = SS_TCP_UNKNOWN;
    }
    rte_spinlock_unlock(&socket->lock);
    
    rte_rwlock_write_lock(&tcp_hash_lock);
    rte_spinlock_lock(&socket->lock);
    socket->id = rte_hash_add_key(tcp_hash, &key);
    rte_spinlock_unlock(&socket->lock);
    rte_rwlock_write_unlock(&tcp_hash_lock);
    if (((int32_t) socket->id) < 0) goto error_out;
    
    tcp_sockets[socket->id] = socket;

    rte_spinlock_lock(&socket->lock);
    RTE_LOG(INFO, STACK, "new tcp socket: sport: %hu dport: %hu id: %u\n",
        rte_bswap16(key->sport), rte_bswap16(key->dport), socket->id);
    rte_spinlock_unlock(&socket->lock);

    return socket;

    error_out:
    if (socket) { je_free(socket); socket = NULL; }
    RTE_LOG(ERR, STACK, "failed to allocate tcp socket\n");
    return NULL;
}

int ss_tcp_socket_delete(ss_flow_key_t* key) {
    rte_rwlock_read_lock(&tcp_hash_lock);
    uint32_t socket_id = rte_hash_del_key(tcp_hash, key);
    rte_rwlock_read_unlock(&tcp_hash_lock);

    ss_tcp_socket_t* socket = ((int32_t) socket_id) < 0 ? NULL : tcp_sockets[socket_id];
    if (!socket) return -1;
    
    socket->state = SS_TCP_CLOSED;
    je_free(socket);
    tcp_sockets[socket_id] = NULL;

    return 0;
}

ss_tcp_socket_t* ss_tcp_socket_lookup(ss_flow_key_t* key) {
    rte_rwlock_read_lock(&tcp_hash_lock);
    uint32_t socket_id = rte_hash_lookup(tcp_hash, &key);
    rte_rwlock_read_unlock(&tcp_hash_lock);
    ss_tcp_socket_t* socket = ((int32_t) socket_id) < 0 ? NULL : tcp_sockets[socket_id];
    return socket;
}

int ss_frame_handle_tcp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    SS_CHECK_SELF(rx_buf, 0);    
    
    ss_flow_key_t key;
    memset(&key, 0, sizeof(key));

    // l4_length = packet_length - (tcp_data_start - packet_start)
    uint8_t* l4_offset          = (uint8_t*) rx_buf->tcp + sizeof(tcp_hdr_t);
    uint16_t l4_length          = rte_pktmbuf_pkt_len(rx_buf->mbuf) - (l4_offset - rte_pktmbuf_mtod(rx_buf->mbuf, uint8_t*));
    
    uint16_t sport              = rte_bswap16(rx_buf->tcp->source);
    uint16_t dport              = rte_bswap16(rx_buf->tcp->dest);
    uint32_t seq                = rte_bswap32(rx_buf->tcp->seq);
    uint32_t ack_seq            = rte_bswap32(rx_buf->tcp->ack_seq);
    uint16_t hdr_length         = 4 * rx_buf->tcp->doff;
    uint8_t  tcp_flags          = rx_buf->tcp->th_flags;
    uint16_t wsize              = rx_buf->tcp->window;
    
    rx_buf->l4_offset           = l4_offset;
    rx_buf->data.l4_length      = l4_length;
    rx_buf->data.tcp_flags      = tcp_flags;
    rx_buf->data.sport          = sport;
    rx_buf->data.dport          = dport;

    // XXX: eliminate flow_key copy / duplication later
    // XXX: instead store the flow_key in the ss_metadata_t
    key.sport                   = rx_buf->tcp->source;
    key.dport                   = rx_buf->tcp->dest;
    key.protocol                = rx_buf->data.eth_type == ETHER_TYPE_IPV4 ? L4_TCP4 : L4_TCP6;
    uint32_t alen               = key.protocol == L4_TCP4? IPV4_ALEN: IPV6_ALEN;
    if (key.protocol == L4_TCP4) {
        rte_memcpy(key.sip, &rx_buf->ip4->saddr, alen);
        rte_memcpy(key.dip, &rx_buf->ip4->daddr, alen);
    }
    else if (key.protocol == L4_TCP6) {
        rte_memcpy(key.sip, &rx_buf->ip6->ip6_src, alen);
        rte_memcpy(key.dip, &rx_buf->ip6->ip6_dst, alen);
    }
    else {
        // XXX: now panic and freak out?
    }
    
    RTE_LOG(INFO, STACK, "rx tcp packet: sport: %hu dport: %hu seq: %u ack: %u hlen: %hu flags: %s wsize: %hu\n",
        sport, dport, seq, ack_seq, hdr_length, ss_tcp_flags_dump(tcp_flags), wsize);

    ss_tcp_socket_t* socket     = ss_tcp_socket_lookup(&key);
    
    if (socket == NULL) {
        socket = ss_tcp_socket_create(&key, rx_buf);
    }
    
    if (unlikely(socket == NULL)) {
        RTE_LOG(ERR, STACK, "could not find or create tcp socket\n");
        return -1;
    }
    
    switch (rx_buf->data.dport) {
        case L4_PORT_DNS: {
            RTE_LOG(DEBUG, STACK, "rx tcp dns packet\n");
            break;
        }
        case L4_PORT_SYSLOG: {
            RTE_LOG(DEBUG, STACK, "rx tcp syslog packet\n");
            break;
        }
        case L4_PORT_SYSLOG_TLS: {
            RTE_LOG(DEBUG, STACK, "rx tcp syslog-tls packet\n");
            break;
        }
        case L4_PORT_NETFLOW_1:
        case L4_PORT_NETFLOW_2:
        case L4_PORT_NETFLOW_3: {
            RTE_LOG(DEBUG, STACK, "rx tcp NetFlow packet\n");
            break;
        }
    }
    
    /*    
     * C: SYN
     * S: SYN, ACK
     * C: ACK
     */

    handle_flags:    
    if      (tcp_flags == TH_RST) {
        RTE_LOG(INFO, STACK, "rx tcp rst packet\n");
        // just delete connection
        return ss_tcp_handle_close(socket, rx_buf, tx_buf);
    }
    else if (tcp_flags == TH_FIN) {
        // send FIN ACK and delete connection
        RTE_LOG(INFO, STACK, "rx tcp fin packet\n");
        return ss_tcp_handle_close(socket, rx_buf, tx_buf);
    }
    else if (tcp_flags == TH_SYN) {
        RTE_LOG(INFO, STACK, "rx tcp syn packet\n");
        return ss_tcp_handle_open(socket, rx_buf, tx_buf);
    }
    else if (tcp_flags == TH_ACK || tcp_flags == 0) {
        RTE_LOG(INFO, STACK, "rx tcp ack packet\n");
        // if they send us an ack, we can just ignore it?
        return ss_tcp_handle_update(socket, rx_buf, tx_buf);
    }
    else {
        RTE_LOG(ERR, STACK, "unknown tcp flags: %s\n",
            ss_tcp_flags_dump(tcp_flags));
    }

    return rv;
}

int ss_tcp_handle_close(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    uint16_t checksum;

    if (rx_buf->tcp->th_flags & TH_RST) goto delete_only;
    
    rv = ss_frame_prepare_tcp(rx_buf, tx_buf);
    if (rv) {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf, error: %d\n", rv);
        return -1;
    }
    
    // FIN ACK should be set. Client closed socket now.
    // Send back current seq_num + 1.
    tx_buf->tcp->seq      = rte_bswap32(rte_bswap32(rx_buf->tcp->seq) + 1);
    // Send back current ack_num + 1.
    tx_buf->tcp->ack_seq  = rte_bswap32(rte_bswap32(rx_buf->tcp->ack) + 1);
    tx_buf->tcp->doff     = 5;
    tx_buf->tcp->th_flags = TH_FIN | TH_ACK;
    tx_buf->tcp->window   = rte_bswap16(L4_TCP_WINDOW_SIZE);
    tx_buf->tcp->check    = rte_bswap16(0x0000);
    tx_buf->tcp->urg_ptr  = rte_bswap16(0x0000);
    
    rv = ss_tcp_prepare_checksum(tx_buf);
    if (rv) {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf checksum, error: %d\n", rv);
        return -1;
    }

    tx_buf->ip4->tot_len  = rte_bswap16(rte_pktmbuf_pkt_len(tx_buf->mbuf) - sizeof(eth_hdr_t)); // XXX: better way?
    checksum = ss_in_cksum((uint16_t*) tx_buf->ip4, sizeof(ip4_hdr_t));
    tx_buf->ip4->check    = checksum;
    
    delete_only:

    return ss_tcp_socket_delete(&socket->key);
}

int ss_tcp_handle_open(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    uint16_t checksum;

    rv = ss_frame_prepare_tcp(rx_buf, tx_buf);
    if (rv) {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf, error: %d\n", rv);
        return -1;
    }
    
    // SYN flag is set. Client is opening connection.
    // Send back initial seq_num + 1.
    tx_buf->tcp->seq      = rte_bswap32(rte_bswap32(rx_buf->tcp->seq) + 1);
    // ACK flag is being set. Client sent initial seq_num.
    // Send back initial seq_num + 1.
    tx_buf->tcp->ack_seq  = rte_bswap32(rte_bswap32(rx_buf->tcp->seq) + 1);
    tx_buf->tcp->doff     = 5;
    tx_buf->tcp->th_flags = TH_SYN | TH_ACK;
    tx_buf->tcp->window   = rte_bswap16(L4_TCP_WINDOW_SIZE);
    tx_buf->tcp->check    = rte_bswap16(0x0000);
    tx_buf->tcp->urg_ptr  = rte_bswap16(0x0000);
    
    rv = ss_tcp_prepare_checksum(tx_buf);
    if (rv) {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf checksum, error: %d\n", rv);
        return -1;
    }

    tx_buf->ip4->tot_len  = rte_bswap16(rte_pktmbuf_pkt_len(tx_buf->mbuf) - sizeof(eth_hdr_t)); // XXX: better way?
    checksum = ss_in_cksum((uint16_t*) tx_buf->ip4, sizeof(ip4_hdr_t));
    tx_buf->ip4->check    = checksum;
    
    rte_spinlock_lock(&socket->lock);
    socket->state = SS_TCP_SYN_TX;
    rte_spinlock_unlock(&socket->lock);
    
    return 0;
}

int ss_tcp_handle_update(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    uint16_t checksum;

    rv = ss_frame_prepare_tcp(rx_buf, tx_buf);
    if (rv) {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf, error: %d\n", rv);
        return -1;
    }
    
    // Send back current seq_num + 1.
    tx_buf->tcp->seq        = rte_bswap32(rte_bswap32(rx_buf->tcp->seq) + 1);
    // ACK flag should be set. Client opened socket now.    
    // XXX: Make the client happy, just ACK everything sent to us.
    tx_buf->tcp->ack_seq    = rx_buf->tcp->seq;
    tx_buf->tcp->doff       = 5;
    tx_buf->tcp->th_flags   = TH_SYN | TH_ACK;
    tx_buf->tcp->window     = rte_bswap16(L4_TCP_WINDOW_SIZE);
    tx_buf->tcp->check      = rte_bswap16(0x0000);
    tx_buf->tcp->urg_ptr    = rte_bswap16(0x0000);

    rv = ss_tcp_prepare_checksum(tx_buf);
    if (rv) {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf checksum, error: %d\n", rv);
        return -1;
    }

    tx_buf->ip4->tot_len    = rte_bswap16(rte_pktmbuf_pkt_len(tx_buf->mbuf) - sizeof(eth_hdr_t)); // XXX: better way?
    checksum = ss_in_cksum((uint16_t*) tx_buf->ip4, sizeof(ip4_hdr_t));
    tx_buf->ip4->check      = checksum;
    
    rte_spinlock_lock(&socket->lock);
    if (socket->state == SS_TCP_SYN_TX) {
        socket->state = SS_TCP_SYN_OPEN;
    }
    rte_spinlock_unlock(&socket->lock);
    
    return 0;
}

int ss_frame_prepare_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    tx_buf->ip4 = (ip4_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(ip4_hdr_t));
    if (tx_buf->ip4 == NULL) {
        RTE_LOG(ERR, STACK, "could not allocate mbuf ipv4 header\n");
        return -1;
    }
    tx_buf->ip4->version             = 0x4;
    tx_buf->ip4->ihl                 = 20 / 4;
    tx_buf->ip4->tos                 = 0x0;
    //tx_buf->ip4->tot_len             = ????;
    tx_buf->ip4->id                  = rte_bswap16(0x0000);
    tx_buf->ip4->frag_off            = 0;
    tx_buf->ip4->ttl                 = 0xff; // XXX: use constant
    tx_buf->ip4->protocol            = IPPROTO_TCP;
    tx_buf->ip4->check               = rte_bswap16(0x0000);
    tx_buf->ip4->saddr               = ss_conf->ip4_address.ip4_addr.addr; // bswap ?????
    tx_buf->ip4->daddr               = rx_buf->ip4->saddr;

    return 0;
}

int ss_frame_prepare_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    tx_buf->ip6 = (ip6_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(ip6_hdr_t));
    if (tx_buf->ip6 == NULL) {
        RTE_LOG(ERR, STACK, "could not allocate mbuf ipv6 header\n");
        return -1;
    }
    tx_buf->ip6->ip6_flow = rte_bswap32(0x60000000);
    tx_buf->ip6->ip6_hlim = 0x0ff; // XXX: use constant
    tx_buf->ip6->ip6_nxt  = IPPROTO_TCP;
    // XXX: plen???
    rte_memcpy(&tx_buf->ip6->ip6_dst, &rx_buf->ip6->ip6_src, sizeof(tx_buf->ip6->ip6_dst));
    rte_memcpy(&tx_buf->ip6->ip6_src, &ss_conf->ip6_address.ip6_addr, sizeof(tx_buf->ip6->ip6_src));

    return 0;
}

int ss_frame_prepare_tcp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    rv = ss_frame_prepare_eth(tx_buf, rx_buf->data.port_id, (eth_addr_t*) &rx_buf->eth->s_addr, rx_buf->data.eth_type);
    if (rv) {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf, ethernet error: %d\n", rv);
        goto error_out;
    }
    
    if (rx_buf->data.eth_type == ETHER_TYPE_IPV4) {
        rv = ss_frame_prepare_ip4(rx_buf, tx_buf);
    }
    else if (rx_buf->data.eth_type == ETHER_TYPE_IPV6) {
        rv = ss_frame_prepare_ip6(rx_buf, tx_buf);
    }
    else {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf, unknown L3 protocol: %hhu\n", rx_buf->data.ip_protocol);
        goto error_out;
    }
    
    if (rv) {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf, L3 error: %d\n", rv);
        goto error_out;
    }

    tx_buf->tcp = (tcp_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(tcp_hdr_t));
    if (tx_buf->tcp == NULL) {
        RTE_LOG(ERR, STACK, "could not allocate tcp tx_mbuf tcp header\n");
        goto error_out;
    }
    tx_buf->tcp->source = rte_bswap16(rx_buf->data.dport);
    tx_buf->tcp->dest   = rte_bswap16(rx_buf->data.sport);
    
    return 0;

    error_out:
    if (tx_buf->mbuf) {
        RTE_LOG(ERR, STACK, "could not prepare tcp tx_mbuf\n");
        tx_buf->active = 0;
        rte_pktmbuf_free(tx_buf->mbuf);
        tx_buf->mbuf = NULL;
    }
    return -1;
}

uint8_t* ss_phdr_append(rte_mbuf_t* pmbuf, void* data, uint32_t length) {
    uint8_t* pptr = (uint8_t*) rte_pktmbuf_append(pmbuf, length);
    rte_memcpy(pptr, data, length);
    return pptr;
}

int ss_tcp_prepare_checksum(ss_frame_t* tx_buf) {
    rte_mbuf_t* pmbuf = NULL;
    uint8_t* pptr;
    uint16_t checksum;
    
    uint8_t  zeros         = 0x00;
    uint8_t  protocol      = IPPROTO_TCP;
    uint16_t tcp_length_le = rte_pktmbuf_pkt_len(tx_buf->mbuf) - ((uint8_t*) tx_buf->tcp - rte_pktmbuf_mtod(tx_buf->mbuf, uint8_t*));
    uint16_t tcp_length_pl = tcp_length_le - sizeof(tcp_hdr_t);
    uint16_t tcp_length    = rte_bswap16(tcp_length_le);
    uint8_t  doff_rsvd     = tx_buf->tcp->doff << 4 | 0x0;
    uint16_t check_zeros   = rte_bswap16(0x0000);
    
    uint8_t* pl_ptr        = ((uint8_t*) tx_buf->tcp) + sizeof(tcp_hdr_t); // XXX: better way?
    
    pmbuf = rte_pktmbuf_alloc(ss_pool[rte_socket_id()]);
    if (pmbuf == NULL) {
        RTE_LOG(ERR, STACK, "could not allocate mbuf icmp6 pseudo header\n");
        goto error_out;
    }
    
    pptr = ss_phdr_append(pmbuf, &tx_buf->ip4->saddr,    sizeof(tx_buf->ip4->saddr));
    pptr = ss_phdr_append(pmbuf, &tx_buf->ip4->daddr,    sizeof(tx_buf->ip4->daddr));
    pptr = ss_phdr_append(pmbuf, &zeros,                 sizeof(zeros));
    pptr = ss_phdr_append(pmbuf, &protocol,              sizeof(protocol));
    pptr = ss_phdr_append(pmbuf, &tcp_length,            sizeof(tcp_length));
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->source,   sizeof(tx_buf->tcp->source));
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->dest,     sizeof(tx_buf->tcp->dest));
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->seq,      sizeof(tx_buf->tcp->seq));
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->ack_seq,  sizeof(tx_buf->tcp->ack_seq));
    pptr = ss_phdr_append(pmbuf, &doff_rsvd,             sizeof(doff_rsvd));
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->th_flags, sizeof(tx_buf->tcp->th_flags));
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->window,   sizeof(tx_buf->tcp->window));
    pptr = ss_phdr_append(pmbuf, &check_zeros,           sizeof(check_zeros));
    pptr = ss_phdr_append(pmbuf, &check_zeros,           sizeof(check_zeros)); // XXX: URG Pointer
    pptr = ss_phdr_append(pmbuf, pl_ptr,                 tcp_length_pl);

    RTE_LOG(DEBUG, STACK, "tcp payload size %u\n", tcp_length_pl);
    if (rte_get_log_level() >= RTE_LOG_DEBUG) {
        printf("tcp pseudo-header:\n");
        rte_pktmbuf_dump(stderr, pmbuf, rte_pktmbuf_pkt_len(pmbuf));
    }
    checksum = ss_in_cksum(rte_pktmbuf_mtod(pmbuf, uint16_t*), rte_pktmbuf_pkt_len(pmbuf));
    rte_pktmbuf_free(pmbuf);
    tx_buf->tcp->check = checksum;
    RTE_LOG(DEBUG, STACK, "tcp checksum: 0x%04hX\n", checksum);

    return 0;

    error_out:
    if (tx_buf->mbuf) {
        RTE_LOG(ERR, STACK, "could not process icmp6 frame\n");
        tx_buf->active = 0;
        rte_pktmbuf_free(tx_buf->mbuf);
        tx_buf->mbuf = NULL;
    }
    return -1;
}
