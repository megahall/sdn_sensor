#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_hexdump.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_random.h>
#include <rte_rwlock.h>
#include <rte_spinlock.h>

#include <jemalloc/jemalloc.h>

#include "checksum.h"
#include "common.h"
#include "ethernet.h"
#include "extractor.h"
#include "ip_utils.h"
#include "je_utils.h"
#include "l4_utils.h"
#include "sdn_sensor.h"
#include "sensor_conf.h"
#include "tcp.h"

// XXX: how can I place a TCP hash on each socket?
static struct rte_hash_parameters tcp_hash_params = {
    .name               = "tcp_hash_socket_0",
    .entries            = L4_TCP_HASH_SIZE,
    .bucket_entries     = L4_TCP_BUCKET_SIZE,
    .key_len            = sizeof(ss_tcp_key_t),
    .hash_func          = rte_hash_crc,
    .hash_func_init_val = 0,
    .socket_id          = 0,
};

static rte_rwlock_t tcp_hash_lock;
static rte_hash_t* tcp_hash;
static ss_tcp_socket_t* tcp_sockets[L4_TCP_HASH_SIZE];

int ss_tcp_init() {
    rte_rwlock_init(&tcp_hash_lock);

    tcp_hash = rte_hash_create(&tcp_hash_params);
    if (tcp_hash == NULL) {
        RTE_LOG(ERR, L3L4, "could not initialize tcp socket hash\n");
        return -1;
    }
    
    memset(tcp_sockets, 0, sizeof(tcp_sockets));
    
    return 0;
}

int ss_tcp_timer_callback() {
    uint64_t expired_ticks = rte_rdtsc() - (rte_get_tsc_hz() * L4_TCP_EXPIRED_SECONDS);
    int expired_sockets = 0;
    ss_tcp_socket_t* socket;

    rte_rwlock_write_lock(&tcp_hash_lock);
    for (int i = 0; i < L4_TCP_HASH_SIZE; ++i) {
        socket = tcp_sockets[i];
        if (!socket) continue;
        if (socket->rx_ticks < expired_ticks &&
            socket->tx_ticks < expired_ticks) {
            rte_spinlock_recursive_lock(&socket->lock);
            ss_tcp_socket_delete(&socket->key, 1);
            rte_spinlock_recursive_unlock(&socket->lock);
            ++expired_sockets;
        }
    }
    rte_rwlock_write_unlock(&tcp_hash_lock);
    
    RTE_LOG(NOTICE, L3L4, "deleted %d expired tcp sockets\n", expired_sockets);
    return 0;
}

int ss_frame_handle_tcp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    SS_CHECK_SELF(rx_buf, 0);    
    
    ss_tcp_key_t key;
    memset(&key, 0, sizeof(key));

    ss_frame_layer_off_len_get(rx_buf, rx_buf->tcp, sizeof(tcp_hdr_t), &rx_buf->l4_offset, &rx_buf->data.l4_length);
    
    uint16_t sport         = rte_bswap16(rx_buf->tcp->source);
    uint16_t dport         = rte_bswap16(rx_buf->tcp->dest);
    uint32_t seq           = rte_bswap32(rx_buf->tcp->seq);
    uint32_t ack_seq       = rte_bswap32(rx_buf->tcp->ack_seq);
    uint16_t hdr_length    = 4 * rx_buf->tcp->doff;
    uint8_t  tcp_flags     = rx_buf->tcp->th_flags;
    uint16_t wsize         = rx_buf->tcp->window;
    
    rx_buf->data.tcp_flags = tcp_flags;
    rx_buf->data.sport     = sport;
    rx_buf->data.dport     = dport;
    
    // tcp_data_len must be based on ip_total_len or padding will be included
    // adjust L4 data to account for TCP options
    uint16_t tcp_data_len  = rte_bswap16(rx_buf->ip4->tot_len) - sizeof(ip4_hdr_t) - hdr_length;
    rx_buf->l4_offset      = (uint8_t*) rx_buf->tcp + hdr_length;
    rx_buf->data.l4_length = tcp_data_len;

    // XXX: eliminate tcp_key copy / duplication later
    // XXX: instead store the tcp_key in the ss_metadata_t
    key.sport              = rx_buf->tcp->source;
    key.dport              = rx_buf->tcp->dest;
    key.protocol           = rx_buf->data.eth_type == ETHER_TYPE_IPV4 ? L4_TCP4 : L4_TCP6;
    uint32_t alen          = key.protocol == L4_TCP4? IPV4_ALEN : IPV6_ALEN;
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
    
    RTE_LOG(DEBUG, L3L4, "rx tcp packet: sport: %hu dport: %hu seq: %u ack: %u hlen: %hu dlen: %hu flags: %s wsize: %hu\n",
        sport, dport, seq, ack_seq, hdr_length, rx_buf->data.l4_length, ss_tcp_flags_dump(tcp_flags), wsize);

    ss_tcp_socket_t* socket     = ss_tcp_socket_lookup(&key);
    if (socket == NULL) {
        socket = ss_tcp_socket_create(&key, rx_buf);
    }
    if (unlikely(socket == NULL)) {
        RTE_LOG(ERR, L3L4, "could not find or create tcp socket\n");
        return -1;
    }
    
    rte_spinlock_recursive_lock(&socket->lock);
    ss_tcp_prepare_rx(rx_buf, socket);
    uint32_t curr_seq = 0;

    /*    
     * C: SYN
     * S: SYN, ACK
     * C: ACK
     */

    if      (tcp_flags & TH_RST) {
        RTE_LOG(FINE, L3L4, "rx tcp rst packet\n");
        // just delete the connection
        rv = ss_tcp_handle_close(socket, rx_buf, tx_buf);
    }
    else if (tcp_flags & TH_FIN) {
        // send RST (as if SO_LINGER is 0) and delete the connection
        RTE_LOG(FINE, L3L4, "rx tcp fin packet\n");
        rv = ss_tcp_handle_close(socket, rx_buf, tx_buf);
    }
    else if (tcp_flags == TH_SYN) {
        RTE_LOG(FINE, L3L4, "rx tcp syn packet\n");
        rv = ss_tcp_handle_open(socket, rx_buf, tx_buf);
    }
    else if (tcp_flags & TH_ACK || tcp_flags == 0) {
        RTE_LOG(FINE, L3L4, "rx tcp ack packet\n");
        rv = ss_tcp_handle_update(socket, rx_buf, tx_buf, &curr_seq);
    }
    else {
        RTE_LOG(ERR, L3L4, "unknown tcp flags: %s\n",
            ss_tcp_flags_dump(tcp_flags));
        rv = -1;
    }
    
    // check for stale packets
    if (socket->state != SS_TCP_SYN_RX && curr_seq < socket->last_ack_seq) {
        RTE_LOG(DEBUG, L3L4, "rx tcp stale skipped packet\n");
        goto out;
    }
    else if (rx_buf->data.l4_length == 0) {
        RTE_LOG(FINE, L3L4, "rx tcp control packet\n");
        goto out;
    }
    else {
        RTE_LOG(FINE, L3L4, "rx tcp data packet\n");
    }

    switch (rx_buf->data.dport) {
        case L4_PORT_DNS: {
            RTE_LOG(DEBUG, L3L4, "rx tcp dns packet\n");
            break;
        }
        case L4_PORT_SYSLOG: {
            RTE_LOG(DEBUG, L3L4, "rx tcp syslog packet\n");
            ss_tcp_extract_syslog(socket, rx_buf);
            break;
        }
        case L4_PORT_SYSLOG_TCP: {
            RTE_LOG(DEBUG, L3L4, "rx tcp syslog-conn packet\n");
            ss_tcp_extract_syslog(socket, rx_buf);
            break;
        }
        case L4_PORT_NETFLOW_1:
        case L4_PORT_NETFLOW_2:
        case L4_PORT_NETFLOW_3: {
            RTE_LOG(DEBUG, L3L4, "rx tcp NetFlow packet\n");
            break;
        }
    }
    
    out:
    rte_spinlock_recursive_unlock(&socket->lock);

    return rv;
}

int ss_tcp_extract_syslog(ss_tcp_socket_t* socket, ss_frame_t* rx_buf) {
    int    rv    = 0;
    size_t len   = 0;
    char*  c     = (char*) rx_buf->l4_offset;
    char*  limit = (char*) (rx_buf->l4_offset + rx_buf->data.l4_length);
    char*  next  = (char*) rx_buf->l4_offset;
    
    if (rte_get_log_level() >= RTE_LOG_FINEST) {
        RTE_LOG(FINEST, L3L4, "dump tcp syslog segment:\n");
        rte_pktmbuf_dump(stderr, rx_buf->mbuf, rte_pktmbuf_pkt_len(rx_buf->mbuf));
    }
    
    while (c < limit) {
        if (*c == '\n') {
            // append to existing rx_data
            len = (size_t) SS_MIN((uint8_t*) c - rx_buf->l4_offset, (long) sizeof(socket->rx_data) - socket->rx_length);
            RTE_LOG(FINER, L3L4, "syslog_tcp: copy %zu bytes to rx_data from %hu to %hu due to delimiter\n",
                len, socket->rx_length, (uint16_t) (socket->rx_length + len));
            rte_memcpy((uint8_t*) (socket->rx_data + socket->rx_length), (uint8_t*) rx_buf->l4_offset, len);
            socket->rx_length += len;
            socket->rx_data[socket->rx_length + 1]  = '\0';

            //ss_buffer_dump("delimited message", socket->rx_data, socket->rx_length);
            // process full message, XXX: check return value
            rv = ss_extract_syslog("tcp_syslog", rx_buf, socket->rx_data, socket->rx_length);

            // mark new message start
            socket->rx_length = 0;
            next = c + 1;
        }
        ++c;
    }

    if (next < limit) {
        len = (size_t) SS_MIN(limit - next, (long) sizeof(socket->rx_data) - socket->rx_length);
        RTE_LOG(FINER, L3L4, "syslog_tcp: copy %zu bytes to rx_data from %hu to %hu due to segment end\n",
            len, socket->rx_length, (uint16_t) (socket->rx_length + len));
        rte_memcpy((uint8_t*) (socket->rx_data + socket->rx_length), (uint8_t*) next, len);
        socket->rx_length += len;
        socket->rx_data[socket->rx_length + 1]  = '\0';
    }
    
    if (socket->rx_length >= L4_TCP_BUFFER_SIZE) {
        char message[256];
        snprintf(message, sizeof(message), "syslog_tcp: truncate message at %hu bytes due to buffer limit",
            socket->rx_length);
        ss_tcp_key_dump(message, &socket->key);

        //ss_buffer_dump("truncated message", socket->rx_data, socket->rx_length);
        // process full message, XXX: check return value
        rv = ss_extract_syslog("tcp_syslog", rx_buf, socket->rx_data, socket->rx_length);

        // mark new message start
        socket->rx_length = 0;
    }
    
    return 0;
}

int ss_tcp_socket_init(ss_tcp_key_t* key, ss_tcp_socket_t* socket) {
    memset(socket, 0, sizeof(ss_tcp_socket_t));
    rte_memcpy(&socket->key, key, sizeof(ss_tcp_key_t));
    rte_spinlock_recursive_init(&socket->lock);
    socket->state = SS_TCP_CLOSED;
    return 0;
}

ss_tcp_socket_t* ss_tcp_socket_create(ss_tcp_key_t* key, ss_frame_t* rx_buf) {
    int is_error = 0;
    
    ss_tcp_key_dump("create socket for key", key);
    // XXX: should these be allocated from jemalloc or RTE alloc?
    ss_tcp_socket_t* socket = je_calloc(1, sizeof(ss_tcp_socket_t));
    if (socket == NULL) { is_error = 1; goto error_out; }
    
    ss_tcp_socket_init(key, socket);

    if (rx_buf->tcp->th_flags == TH_SYN) {
        socket->state = SS_TCP_SYN_RX;
    }
    else {
        socket->state = SS_TCP_UNKNOWN;
    }
    
    rte_rwlock_write_lock(&tcp_hash_lock);
    int32_t socket_id = rte_hash_add_key(tcp_hash, key);
    socket->id = (uint64_t) socket_id;
    if (socket_id >= 0) {
        tcp_sockets[socket->id] = socket;
    }
    else {
        is_error = 1;
    }
    rte_rwlock_write_unlock(&tcp_hash_lock);

    RTE_LOG(INFO, L3L4, "new tcp socket: sport: %hu dport: %hu id: %lu is_error: %d\n",
        rte_bswap16(key->sport), rte_bswap16(key->dport), socket->id, is_error);

    error_out:
    if (unlikely(is_error)) {
        if (socket) { je_free(socket); socket = NULL; }
        RTE_LOG(ERR, L3L4, "failed to allocate tcp socket\n");
        return NULL;
    }

    return socket;
}

int ss_tcp_socket_delete(ss_tcp_key_t* key, bool is_locked) {
    ss_tcp_key_dump("delete socket for key", key);

    if (likely(!is_locked)) rte_rwlock_write_lock(&tcp_hash_lock);
    int32_t socket_id = rte_hash_del_key(tcp_hash, key);
    ss_tcp_socket_t* socket = ((int32_t) socket_id) < 0 ? NULL : tcp_sockets[socket_id];
    if (likely(!is_locked)) rte_rwlock_write_unlock(&tcp_hash_lock);

    if (!socket) return -1;
    
    socket->state = SS_TCP_CLOSED;
    je_free(socket);
    tcp_sockets[socket_id] = NULL;

    return 0;
}

ss_tcp_socket_t* ss_tcp_socket_lookup(ss_tcp_key_t* key) {
    ss_tcp_key_dump("find socket for key", key);
    rte_rwlock_read_lock(&tcp_hash_lock);
    int32_t socket_id = rte_hash_lookup(tcp_hash, key);
    rte_rwlock_read_unlock(&tcp_hash_lock);
    ss_tcp_socket_t* socket = ((int32_t) socket_id) < 0 ? NULL : tcp_sockets[socket_id];
    if (socket) {
        RTE_LOG(DEBUG, L3L4, "found socket at id: %u\n", socket_id);
    }
    return socket;
}

int ss_tcp_prepare_rx(ss_frame_t* rx_buf, ss_tcp_socket_t* socket) {
    socket->rx_ticks = rte_rdtsc();
    if (socket->state == SS_TCP_SYN_RX) {
        socket->last_seq = rte_bswap32(rx_buf->tcp->seq);
        socket->last_ack_seq = rte_bswap32(rx_buf->tcp->ack_seq);
    }
    return 0;
}

int ss_tcp_prepare_tx(ss_frame_t* tx_buf, ss_tcp_socket_t* socket, ss_tcp_state_t state) {
    socket->tx_ticks = rte_rdtsc();

    tcp_hdr_t* tcp = tx_buf ? tx_buf->tcp : NULL;
    if (!tcp) return -1;

    socket->last_seq = rte_bswap32(tx_buf->tcp->seq);
    if (tcp->th_flags & TH_ACK) {
        socket->last_ack_seq = rte_bswap32(tx_buf->tcp->ack_seq);
    }

    if (rte_get_log_level() >= RTE_LOG_DEBUG) {
        RTE_LOG(DEBUG, L3L4, "tx tcp packet: sport: %hu dport: %hu seq: %u ack: %u hlen: %hu flags: %s wsize: %hu\n",
            rte_bswap16(tcp->source), rte_bswap16(tcp->dest),
            rte_bswap32(tcp->seq),    rte_bswap32(tcp->ack_seq),
            (uint16_t) (4 * tcp->doff), ss_tcp_flags_dump(tcp->th_flags),
            rte_bswap16(tcp->window));
    }

    return 0;
}

uint16_t ss_tcp_rx_mss_get(ss_tcp_socket_t* socket) {
    uint16_t ip_hdr_max = SS_MAX(sizeof(ip4_hdr_t), sizeof(ip6_hdr_t));
    return ss_conf->mtu - ip_hdr_max - sizeof(tcp_hdr_t);
}

int ss_tcp_handle_close(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    if (rx_buf->tcp->th_flags & TH_RST) goto shutdown_only;
    
    rv = ss_frame_prepare_tcp(rx_buf, tx_buf);
    if (rv) {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf, error: %d\n", rv);
        return -1;
    }
    
    // Client closed socket now.
    // RST should be set for hard close (equivalent to SO_LINGER == 0) from server.
    tx_buf->tcp->seq      = rx_buf->tcp->ack_seq;
    tx_buf->tcp->ack_seq  = 0;
    tx_buf->tcp->doff     = L4_TCP_HEADER_OFFSET;
    tx_buf->tcp->th_flags = TH_RST;
    tx_buf->tcp->window   = rte_bswap16(L4_TCP_WINDOW_SIZE);
    tx_buf->tcp->check    = rte_bswap16(0x0000);
    tx_buf->tcp->urg_ptr  = rte_bswap16(0x0000);
    
    rv = ss_tcp_prepare_checksum(tx_buf);
    if (rv) {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf checksum, error: %d\n", rv);
        return -1;
    }
    
    shutdown_only:
    ss_tcp_prepare_tx(tx_buf, socket, SS_TCP_CLOSED);
    return ss_tcp_socket_delete(&socket->key, 0);
}

int ss_tcp_handle_open(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;

    rv = ss_frame_prepare_tcp(rx_buf, tx_buf);
    if (rv) {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf, error: %d\n", rv);
        return -1;
    }
    
    // SYN flag is set. Client is opening connection.
    // Send back server's initial seq_num.
    uint32_t rand_seq     = (uint32_t) rte_rand();
    tx_buf->tcp->seq      = rte_bswap32(rand_seq);
    // ACK flag is set. Client sent initial seq_num.
    // Send back initial seq_num + 1.
    tx_buf->tcp->ack_seq  = rte_bswap32(rte_bswap32(rx_buf->tcp->seq) + 1);
    tx_buf->tcp->doff     = L4_TCP_HEADER_OFFSET + 2; // 1-byte MSS, 1-byte window scale
    tx_buf->tcp->th_flags = TH_SYN | TH_ACK;
    tx_buf->tcp->window   = rte_bswap16(L4_TCP_WINDOW_SIZE);
    tx_buf->tcp->check    = rte_bswap16(0x0000);
    tx_buf->tcp->urg_ptr  = rte_bswap16(0x0000);
    // add the two most fundamental hard-coded options
    uint32_t* tcp_mss     = (uint32_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(uint32_t));
    if (!tcp_mss) {
        RTE_LOG(ERR, L3L4, "could not add tcp_mss to tx_mbuf\n");
        return -1;
    }
    // mss: kind 2, length 4, uint16_t mss
    *tcp_mss              = rte_bswap32(0x0204 << 16 | ss_tcp_rx_mss_get(socket));

    uint32_t* win_scale   = (uint32_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(uint32_t));
    if (!win_scale) {
        RTE_LOG(ERR, L3L4, "could not add win_scale to tx_mbuf\n");
        return -1;
    }
    // win_scale: kind 3, length 3, uint8_t shift, followed by uint8_t nop (0x01)
    *win_scale            = rte_bswap32(0x0303 << 16 | ((L4_TCP_WINDOW_SHIFT & 0xff) << 8) | 0x1);
    
    rv = ss_tcp_prepare_checksum(tx_buf);
    if (rv) {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf checksum, error: %d\n", rv);
        return -1;
    }
    
    ss_tcp_prepare_tx(tx_buf, socket, SS_TCP_SYN_TX);
    
    return 0;
}

int ss_tcp_handle_update(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf, uint32_t* curr_ack_seq_ptr) {
    int rv = 0;
    
    if (socket->state == SS_TCP_CLOSED) return 0;

    uint16_t tcp_data_len  = rte_bswap16(rx_buf->ip4->tot_len) - (4 * rx_buf->tcp->doff) - sizeof(tcp_hdr_t);
    uint32_t curr_seq      = rx_buf->tcp->ack_seq;
    uint32_t curr_ack_seq  = rte_bswap32(rx_buf->tcp->seq) + (tcp_data_len ? tcp_data_len : 1);

    if (curr_ack_seq <= socket->last_ack_seq) {
        socket->last_ack_seq = curr_ack_seq;
        *curr_ack_seq_ptr = curr_ack_seq;
        return 0;
    }
        
    rv = ss_frame_prepare_tcp(rx_buf, tx_buf);
    if (rv) {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf, error: %d\n", rv);
        return -1;
    }

    // XXX: Make the client "happy", and just ACK everything.
    // This is lossy, but back-pressure on syslog messages is pointless.
    tx_buf->tcp->seq       = curr_seq;
    tx_buf->tcp->ack_seq   = rte_bswap32(curr_ack_seq);
    tx_buf->tcp->doff      = L4_TCP_HEADER_OFFSET;
    tx_buf->tcp->th_flags  = TH_ACK;
    tx_buf->tcp->window    = rte_bswap16(L4_TCP_WINDOW_SIZE);
    tx_buf->tcp->check     = rte_bswap16(0x0000);
    tx_buf->tcp->urg_ptr   = rte_bswap16(0x0000);

    rv = ss_tcp_prepare_checksum(tx_buf);
    if (rv) {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf checksum, error: %d\n", rv);
        return -1;
    }
    
    ss_tcp_prepare_tx(tx_buf, socket, SS_TCP_OPEN);
    
    *curr_ack_seq_ptr = curr_ack_seq;
    return 0;
}

int ss_frame_prepare_tcp(ss_frame_t* rx_buf, ss_frame_t* tx_buf) {
    int rv = 0;
    
    rv = ss_frame_prepare_eth(tx_buf, rx_buf->data.port_id, (eth_addr_t*) &rx_buf->eth->s_addr, rx_buf->data.eth_type);
    if (rv) {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf, ethernet error: %d\n", rv);
        goto error_out;
    }
    
    if (rx_buf->data.eth_type == ETHER_TYPE_IPV4) {
        rv = ss_frame_prepare_ip4(rx_buf, tx_buf);
    }
    else if (rx_buf->data.eth_type == ETHER_TYPE_IPV6) {
        rv = ss_frame_prepare_ip6(rx_buf, tx_buf);
    }
    else {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf, unknown L3 protocol: %hhu\n", rx_buf->data.ip_protocol);
        goto error_out;
    }
    
    if (rv) {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf, L3 error: %d\n", rv);
        goto error_out;
    }

    tx_buf->tcp = (tcp_hdr_t*) rte_pktmbuf_append(tx_buf->mbuf, sizeof(tcp_hdr_t));
    if (tx_buf->tcp == NULL) {
        RTE_LOG(ERR, L3L4, "could not allocate tcp tx_mbuf tcp header\n");
        goto error_out;
    }
    tx_buf->tcp->source = rte_bswap16(rx_buf->data.dport);
    tx_buf->tcp->dest   = rte_bswap16(rx_buf->data.sport);
    
    return 0;

    error_out:
    if (tx_buf->mbuf) {
        RTE_LOG(ERR, L3L4, "could not prepare tcp tx_mbuf\n");
        tx_buf->active = 0;
        rte_pktmbuf_free(tx_buf->mbuf);
        tx_buf->mbuf = NULL;
    }
    return -1;
}

int ss_tcp_prepare_checksum(ss_frame_t* tx_buf) {
    rte_mbuf_t* pmbuf = NULL;

    if (!tx_buf || !tx_buf->mbuf) goto error_out;

    uint8_t* pptr;
    uint16_t ip_checksum;
    uint16_t tcp_checksum;
    
    uint8_t  zeros         = 0x00;
    uint8_t  protocol      = IPPROTO_TCP;
    uint16_t tcp_len_le    = (uint16_t) (rte_pktmbuf_pkt_len(tx_buf->mbuf) - ((uint8_t*) tx_buf->tcp - rte_pktmbuf_mtod(tx_buf->mbuf, uint8_t*)));
    uint16_t tcp_data_len  = tcp_len_le - sizeof(tcp_hdr_t);
    uint16_t tcp_len       = rte_bswap16(tcp_len_le);
    uint8_t  doff_rsvd     = (uint8_t) (tx_buf->tcp->doff << 4 | 0x0);
    uint16_t check_zeros   = rte_bswap16(0x0000);
    
    uint8_t* data_ptr      = ((uint8_t*) tx_buf->tcp) + sizeof(tcp_hdr_t); // XXX: better way?
    
    pmbuf = rte_pktmbuf_alloc(ss_pool[rte_socket_id()]);
    if (pmbuf == NULL) {
        RTE_LOG(ERR, L3L4, "could not allocate mbuf tcp pseudo header\n");
        goto error_out;
    }
    
    pptr = ss_phdr_append(pmbuf, &tx_buf->ip4->saddr,    sizeof(tx_buf->ip4->saddr));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &tx_buf->ip4->daddr,    sizeof(tx_buf->ip4->daddr));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &zeros,                 sizeof(zeros));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &protocol,              sizeof(protocol));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &tcp_len,               sizeof(tcp_len));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->source,   sizeof(tx_buf->tcp->source));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->dest,     sizeof(tx_buf->tcp->dest));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->seq,      sizeof(tx_buf->tcp->seq));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->ack_seq,  sizeof(tx_buf->tcp->ack_seq));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &doff_rsvd,             sizeof(doff_rsvd));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->th_flags, sizeof(tx_buf->tcp->th_flags));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->window,   sizeof(tx_buf->tcp->window));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &check_zeros,           sizeof(check_zeros));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, &tx_buf->tcp->urg_ptr,  sizeof(check_zeros));
    if (pptr == NULL) goto error_out;
    pptr = ss_phdr_append(pmbuf, data_ptr,               tcp_data_len);
    if (pptr == NULL) goto error_out;

    if (rte_get_log_level() >= RTE_LOG_FINER) {
        printf("tcp pseudo-header:\n");
        rte_pktmbuf_dump(stderr, pmbuf, rte_pktmbuf_pkt_len(pmbuf));
    }
    tcp_checksum = ss_in_cksum(rte_pktmbuf_mtod(pmbuf, uint16_t*), rte_pktmbuf_pkt_len(pmbuf));
    rte_pktmbuf_free(pmbuf);
    tx_buf->tcp->check = tcp_checksum;
    
    uint16_t ip_len = rte_bswap16(rte_pktmbuf_pkt_len(tx_buf->mbuf) - sizeof(eth_hdr_t));
    tx_buf->ip4->tot_len = ip_len; // XXX: better way?
    ip_checksum = ss_in_cksum((uint16_t*) tx_buf->ip4, sizeof(ip4_hdr_t));
    tx_buf->ip4->check   = ip_checksum;
    RTE_LOG(DEBUG, L3L4, "prepare tcp: tcp data len: %u, tcp checksum: 0x%04hX, ip4 checksum: 0x%04hX\n",
        tcp_data_len, tcp_checksum, ip_checksum);
    
    return 0;

    error_out:
    if (tx_buf->mbuf) {
        RTE_LOG(ERR, L3L4, "could not process tcp frame\n");
        if (pmbuf) rte_pktmbuf_free(pmbuf);
        tx_buf->active = 0;
        rte_pktmbuf_free(tx_buf->mbuf);
        tx_buf->mbuf = NULL;
    }
    return -1;
}
