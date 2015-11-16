#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_hash_crc.h>
#include <rte_log.h>
#include <rte_rwlock.h>

#include <jemalloc/jemalloc.h>

#include <json-c/json.h>
#include <json-c/json_object_private.h>

#include "common.h"
#include "ioc.h"
#include "ip_utils.h"
#include "je_utils.h"
#include "json.h"
#include "metadata.h"
#include "nn_queue.h"
#include "sdn_sensor.h"
#include "sflow.h"
#include "sflow_cb.h"
#include "sflow_utils.h"

#define be32 rte_bswap32
#define be64 rte_bswap64

// XXX: how can I place an sFlow hash on each socket?
static struct rte_hash_parameters sflow_hash_params = {
    .name               = "sflow_hash_socket_0",
    .entries            = L4_SFLOW_HASH_SIZE,
    .bucket_entries     = L4_SFLOW_BUCKET_SIZE,
    .key_len            = sizeof(sflow_key_t),
    .hash_func          = rte_hash_crc,
    .hash_func_init_val = 0,
    .socket_id          = 0,
};

static rte_rwlock_t sflow_hash_lock;
static rte_hash_t* sflow_hash;
static sflow_socket_t* sflow_sockets[L4_TCP_HASH_SIZE];

int sflow_init() {
    sflow_sample_cb = &sflow_sample_callback;

    rte_rwlock_init(&sflow_hash_lock);

    sflow_hash = rte_hash_create(&sflow_hash_params);
    if (sflow_hash == NULL) {
        RTE_LOG(ERR, L3L4, "could not initialize sflow socket hash\n");
        return -1;
    }

    memset(sflow_sockets, 0, sizeof(sflow_sockets));

    return 0;
}

int sflow_timer_callback() {
    uint64_t expired_ticks = rte_rdtsc() - (rte_get_tsc_hz() * L4_SFLOW_EXPIRED_SECONDS);
    int expired_sockets = 0;
    sflow_socket_t* socket;

    rte_rwlock_write_lock(&sflow_hash_lock);
    for (int i = 0; i < L4_SFLOW_HASH_SIZE; ++i) {
        socket = sflow_sockets[i];
        if (!socket) continue;
        if (socket->rx_ticks < expired_ticks) {
            rte_spinlock_recursive_lock(&socket->lock);
            sflow_socket_delete(&socket->key, 1);
            rte_spinlock_recursive_unlock(&socket->lock);
            ++expired_sockets;
        }
    }
    rte_rwlock_write_unlock(&sflow_hash_lock);

    RTE_LOG(NOTICE, L3L4, "deleted %d expired sflow sockets\n", expired_sockets);
    return 0;
}

int sflow_frame_handle(ss_frame_t* rx_buf) {
    uint16_t eth_type = rx_buf->data.eth_type;

    sflow_sample_t sample;
    memset(&sample, 0, sizeof(sample));

    sample.raw_sample = rx_buf->l4_offset;
    sample.raw_sample_len = rx_buf->data.l4_length;

    size_t source_ip_size = eth_type == ETHER_TYPE_IPV4 ? IPV4_ALEN : IPV6_ALEN;
    memcpy(&sample.source_ip.ipv6, rx_buf->data.sip, source_ip_size);

    if (eth_type == ETHER_TYPE_IPV4) {
        sample.source_ip.type = SFLOW_ADDRESS_TYPE_IP_V4;
    }
    else if (eth_type == ETHER_TYPE_IPV6) {
        sample.source_ip.type = SFLOW_ADDRESS_TYPE_IP_V6;
    }
    sflow_datagram_receive(&sample);

    return 0;
}

int sflow_socket_init(sflow_key_t* key, sflow_socket_t* socket) {
    memset(socket, 0, sizeof(sflow_socket_t));
    rte_memcpy(&socket->key, key, sizeof(sflow_key_t));
    rte_spinlock_recursive_init(&socket->lock);
    return 0;
}

sflow_socket_t* sflow_socket_create(sflow_key_t* key, ss_frame_t* rx_buf) {
    int is_error = 0;

    sflow_key_dump("create socket for key", key);
    // XXX: should these be allocated from jemalloc or RTE alloc?
    sflow_socket_t* socket = je_calloc(1, sizeof(sflow_socket_t));
    if (socket == NULL) { is_error = 1; goto error_out; }

    sflow_socket_init(key, socket);

    rte_rwlock_write_lock(&sflow_hash_lock);
    int32_t socket_id = rte_hash_add_key(sflow_hash, key);
    socket->id = (uint64_t) socket_id;
    if (socket_id >= 0) {
        sflow_sockets[socket->id] = socket;
    }
    else {
        is_error = 1;
    }
    rte_rwlock_write_unlock(&sflow_hash_lock);

    // XXX: figure out what should be in this
    //RTE_LOG(INFO, L3L4, "new sflow socket: sport: %hu dport: %hu id: %lu is_error: %d\n",
    //    rte_bswap16(key->sport), rte_bswap16(key->dport), socket->id, is_error);

    error_out:
    if (unlikely(is_error)) {
        if (socket) { je_free(socket); socket = NULL; }
        RTE_LOG(ERR, L3L4, "failed to allocate sflow socket\n");
        return NULL;
    }

    return socket;
}

int sflow_socket_delete(sflow_key_t* key, bool is_locked) {
    sflow_key_dump("delete socket for key", key);

    if (likely(!is_locked)) rte_rwlock_write_lock(&sflow_hash_lock);
    int32_t socket_id = rte_hash_del_key(sflow_hash, key);
    sflow_socket_t* socket = ((int32_t) socket_id) < 0 ? NULL : sflow_sockets[socket_id];
    if (likely(!is_locked)) rte_rwlock_write_unlock(&sflow_hash_lock);

    if (!socket) return -1;

    je_free(socket);
    sflow_sockets[socket_id] = NULL;

    return 0;
}

sflow_socket_t* sflow_socket_lookup(sflow_key_t* key) {
    sflow_key_dump("find socket for key", key);
    rte_rwlock_read_lock(&sflow_hash_lock);
    int32_t socket_id = rte_hash_lookup(sflow_hash, key);
    rte_rwlock_read_unlock(&sflow_hash_lock);
    sflow_socket_t* socket = ((int32_t) socket_id) < 0 ? NULL : sflow_sockets[socket_id];
    if (socket) {
        RTE_LOG(DEBUG, L3L4, "found socket at id: %u\n", socket_id);
    }
    return socket;
}

int sflow_prepare_rx(ss_frame_t* rx_buf, sflow_socket_t* socket) {
    socket->rx_ticks = rte_rdtsc();
    // XXX: populate the packet sequence number
    socket->last_seq = (uint32_t) -1;
    return 0;
}

void sflow_sample_callback(sflow_sample_t* sample, uint32_t s_index, uint32_t e_index) {
    char agent_ip[SS_IPV6_STR_MAX];
    sflow_ip_string(&sample->agent_ip, agent_ip, sizeof(agent_ip));
    char* sample_type = sflow_sample_type_dump(sample->sample_type);
    char* data_format = sflow_sample_format_dump(sample->sample_type, sample->data_format);
    char* ds_type     = sflow_ds_type_dump(sample->ds_type);

    RTE_LOG(INFO, EXTRACTOR, "sample_meta %u/%u:\n"
           "    agent_ip %s sub_id %u\n"
           "    packet_seq_num %u\n"
           "    sys_up_time %u\n"
           "    sample_type %s\n"
           "    data_format %s\n"
           "    sample_seq_num %u\n"
           "    ds_type %s\n"
           "    ds_index %u\n",
        s_index, e_index,
        agent_ip, sample->agent_sub_id,
        sample->packet_seq_num,
        sample->sys_up_time / 1000,
        sample_type,
        data_format,
        sample->sample_seq_num,
        ds_type,
        sample->ds_index);

    if (sample->sample_type == SFLOW_FLOW_SAMPLE ||
        sample->sample_type == SFLOW_FLOW_SAMPLE_EXPANDED) {
        sflow_sampled_header_t* header = &sample->header;
        sflow_flow_sample_callback(sample, header, s_index, e_index);
    }
    else if (sample->sample_type == SFLOW_COUNTERS_SAMPLE ||
        sample->sample_type == SFLOW_COUNTERS_SAMPLE_EXPANDED) {
        
        if (sample->counters_type != SFLOW_COUNTERS_GENERIC) {
            RTE_LOG(NOTICE, EXTRACTOR, "skip counters_type: %s\n",
                sflow_counters_format_dump(sample->counters_type));
            return;
        }

        sflow_if_counters_t* if_counters = &sample->counters->if_counters;
        sflow_counter_sample_callback(sample, if_counters, s_index, e_index);
    }

    // XXX: counter blocks
    //uint32_t stats_sampling_interval;
    //uint32_t counter_block_version;
}

void sflow_flow_sample_callback(sflow_sample_t* sample, sflow_sampled_header_t* header, uint32_t s_index, uint32_t e_index) {
    ss_ioc_entry_t* iptr;
    uint8_t* metadata = NULL;
    size_t mlength = 0;
    int rv = 0;

    char src_ip[SS_IPV6_STR_MAX];
    char dst_ip[SS_IPV6_STR_MAX];
    char nat_src_ip[SS_IPV6_STR_MAX];
    char nat_dst_ip[SS_IPV6_STR_MAX];

    RTE_LOG(INFO, EXTRACTOR, "flow_sample_meta %u/%u:\n"
           "    sample_rate %u\n"
           "    sample_pool %u\n"
           "    drop_count %u\n"
           "    input_port %s\n"
           "    output_port %s\n",
        s_index, e_index,
        sample->sample_rate,
        sample->sample_pool,
        sample->drop_count,
        sflow_port_id_dump(sample->input_port_format, sample->input_port),
        sflow_port_id_dump(sample->output_port_format, sample->output_port));

    RTE_LOG(INFO, EXTRACTOR, "header_meta %u/%u:\n"
           "    protocol %s\n"
           "    packet_size %u\n"
           "    stripped_size %u\n"
           "    header_size %u\n",
        s_index, e_index,
        sflow_header_protocol_dump(header->protocol),
        header->packet_size,
        header->stripped_size,
        header->header_size);
    // XXX: print bytes?
    
    sflow_ip_string(&sample->src_ip, src_ip, sizeof(src_ip));
    sflow_ip_string(&sample->dst_ip, dst_ip, sizeof(dst_ip));
    sflow_ip_string(&sample->nat_src_ip, nat_src_ip, sizeof(nat_src_ip));
    sflow_ip_string(&sample->nat_dst_ip, nat_dst_ip, sizeof(nat_dst_ip));

    RTE_LOG(INFO, EXTRACTOR, "header_data: %u/%u\n"
           "    smac %s\n"
           "    dmac %s\n"
           "    rx_vlan %u\n"
           "    tx_vlan %u\n"
           "    eth_type 0x%04x\n"
           "    ether_len %u\n"
           "    sip %s\n"
           "    dip %s\n"
           "    natsip %s\n"
           "    natdip %s\n"
           "    ip_protocol %u\n"
           "    ip_tot_len %u\n"
           "    ip_fragoff %u\n"
           "    sport %u\n"
           "    dport %u\n"
           "    natsport %u\n"
           "    natdport %u\n"
           "    tcp_flags %u\n"
           "    udp_len %u\n"
           "    user_ids %s, %s\n",
         s_index, e_index,
         sflow_mac_string(sample->src_eth),
         sflow_mac_string(sample->dst_eth),
         sample->rx_vlan,
         sample->tx_vlan,
         sample->eth_type,
         sample->eth_len,
         src_ip,
         dst_ip,
         nat_src_ip,
         nat_dst_ip,
         sample->ip_protocol,
         sample->ip_tot_len,
         sample->ip_fragoff,
         sample->src_port,
         sample->dst_port,
         sample->nat_src_port,
         sample->nat_dst_port,
         sample->tcp_flags,
         sample->udp_len,
         sample->src_user, sample->dst_user);

    iptr = ss_ioc_sflow_match(sample);
    if (iptr) {
        // match
        RTE_LOG(NOTICE, EXTRACTOR, "successful sflow ioc match from sample\n");
        ss_ioc_entry_dump_dpdk(iptr);
        nn_queue_t* nn_queue = &ss_conf->ioc_files[iptr->file_id].nn_queue;
        // XXX: fill in something useful in rule field
        metadata = ss_metadata_prepare_sflow("sflow_ioc", NULL, nn_queue, sample, iptr);
        // XXX: for now assume the output is C char*
        mlength = strlen((char*) metadata);
        //printf("metadata: %s\n", metadata);
        rv = ss_nn_queue_send(nn_queue, metadata, (uint16_t) mlength);
    }
}

int ss_metadata_prepare_sflow_mac(
    json_object* jobject, const char* field_name, uint8_t* m) {
    char*        mac  = sflow_mac_string(m);
    json_object* item = NULL;
    item = json_object_new_string(mac);
    if (item == NULL) return -1;
    json_object_object_add(jobject, field_name, item);
    return 0;
}

int ss_metadata_prepare_sflow_ip(
    json_object* jobject, const char* field_name, sflow_ip_t* i) {
    char*        ip      = sflow_ip_string(i, NULL, 0);
    json_object* item    = NULL;
    item = json_object_new_string(ip);
    if (item == NULL) return -1;
    json_object_object_add(jobject, field_name, item);
    return 0;
}

uint8_t* ss_metadata_prepare_sflow(
    const char* source, const char* rule, nn_queue_t* nn_queue,
    sflow_sample_t* sample, ss_ioc_entry_t* iptr) {
    int          irv;
    json_object* jobject = NULL;
    json_object* item    = NULL;
    uint8_t*     rv      = NULL;
    uint8_t*     jstring = NULL;

    jobject = json_object_new_object();
    if (jobject == NULL) {
        RTE_LOG(ERR, EXTRACTOR, "could not allocate sflow json object\n");
        goto error_out;
    }

    item = json_object_new_string(source);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "source", item);

    item = json_object_new_int64((int64_t) __sync_add_and_fetch(&nn_queue->tx_messages, 1));
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "seq_num", item);

    irv = ss_metadata_prepare_sflow_ip(jobject, "source_ip", &sample->source_ip);
    if (irv) goto error_out;
    irv = ss_metadata_prepare_sflow_ip(jobject, "agent_ip", &sample->agent_ip);
    if (irv) goto error_out;

    item = json_object_new_int((int32_t) sample->agent_sub_id);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "agent_sub_id", item);

    item = json_object_new_int((int32_t) sample->packet_seq_num);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "packet_seq_num", item);

    item = json_object_new_double(sample->sys_up_time / 1000.0);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "sys_up_time", item);

    item = json_object_new_string(sflow_sample_type_dump(sample->sample_type));
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "sample_type", item);
    
    item = json_object_new_string(sflow_sample_format_dump(sample->sample_type, sample->data_format));
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "sample_format", item);

    item = json_object_new_int((int32_t) sample->sample_seq_num);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "sample_seq_num", item);

    item = json_object_new_string(sflow_ds_type_dump(sample->ds_type));
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "ds_type", item);

    item = json_object_new_int((int32_t) sample->ds_index);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "ds_index", item);

    item = json_object_new_int((int32_t) sample->sample_rate);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "sample_rate", item);

    item = json_object_new_int((int32_t) sample->sample_pool);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "sample_pool", item);

    item = json_object_new_int((int32_t) sample->drop_count);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "drop_count", item);

    item = json_object_new_string(sflow_port_id_dump(sample->input_port_format, sample->input_port));
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "input_port", item);

    item = json_object_new_string(sflow_port_id_dump(sample->output_port_format, sample->output_port));
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "output_port", item);

    item = json_object_new_string(sflow_header_protocol_dump(sample->header.protocol));
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "sample_protocol", item);
    
    item = json_object_new_int((int32_t) sample->header.packet_size);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "packet_length", item);
    
    item = json_object_new_int((int32_t) sample->header.stripped_size);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "stripped_length", item);
    
    item = json_object_new_int((int32_t) sample->header.header_size);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "header_length", item);

    item = json_object_new_int((int32_t) sample->eth_type);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "eth_type", item);

    irv = ss_metadata_prepare_sflow_mac(jobject, "smac", (uint8_t*) &sample->src_eth);
    if (irv) goto error_out;

    irv = ss_metadata_prepare_sflow_mac(jobject, "dmac", (uint8_t*) &sample->src_eth);
    if (irv) goto error_out;

    item = json_object_new_int((int32_t) sample->rx_vlan);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "rx_vlan", item);
    item = json_object_new_int((int32_t) sample->tx_vlan);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "tx_vlan", item);
    
    irv = ss_metadata_prepare_sflow_ip(jobject, "sip", &sample->src_ip);
    if (irv == -1) goto error_out;
    irv = ss_metadata_prepare_sflow_ip(jobject, "dip", &sample->dst_ip);
    if (irv == -1) goto error_out;
    irv = ss_metadata_prepare_sflow_ip(jobject, "natsip", &sample->nat_src_ip);
    if (irv == -1) goto error_out;
    irv = ss_metadata_prepare_sflow_ip(jobject, "natdip", &sample->nat_dst_ip);
    if (irv == -1) goto error_out;

    item = json_object_new_int((int32_t) sample->ip_protocol);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "ip_protocol", item);

    item = json_object_new_int((int32_t) sample->ip_tot_len);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "ip_length", item);

    item = json_object_new_int((int32_t) sample->ip_ttl);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "ttl", item);

    // XXX: fix this field
    item = json_object_new_int((int32_t) sample->udp_len);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "l4_length", item);

    if (sample->ip_protocol == IPPROTO_ICMP || sample->ip_protocol == IPPROTO_ICMPV6) {
        item = json_object_new_int((int32_t) sample->src_port);
        if (item == NULL) goto error_out;
        json_object_object_add(jobject, "icmp_type", item);

        item = json_object_new_int((int32_t) sample->dst_port);
        if (item == NULL) goto error_out;
        json_object_object_add(jobject, "icmp_code", item);
    }
    else {
        item = json_object_new_int((int32_t) sample->src_port);
        if (item == NULL) goto error_out;
        json_object_object_add(jobject, "sport", item);

        item = json_object_new_int((int32_t) sample->dst_port);
        if (item == NULL) goto error_out;
        json_object_object_add(jobject, "dport", item);
    }

    item = json_object_new_int((int32_t) sample->nat_src_port);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "natsport", item);

    item = json_object_new_int((int32_t) sample->nat_dst_port);
    if (item == NULL) goto error_out;
    json_object_object_add(jobject, "natdport", item);

    if (sample->ip_protocol == IPPROTO_TCP) {
        item = json_object_new_int((int32_t) sample->tcp_flags);
        if (item == NULL) goto error_out;
        json_object_object_add(jobject, "tcp_flags", item);
    }

    if (sample->src_user[0]) {
        item = json_object_new_string(sample->src_user);
        if (item == NULL) goto error_out;
        json_object_object_add(jobject, "src_user", item);
    }
    
    if (sample->dst_user[0]) {
        item = json_object_new_string(sample->dst_user);
        if (item == NULL) goto error_out;
        json_object_object_add(jobject, "dst_user", item);
    }

    if (iptr) {
        irv = ss_metadata_prepare_ioc(source, rule, nn_queue, iptr, jobject);
        if (irv) goto error_out;
    }

    item = NULL;

    // XXX: NOTE: String pointer is internal to JSON object.
    jstring = (uint8_t*) json_object_to_json_string_ext(jobject, JSON_C_TO_STRING_SPACED);
    rv = (uint8_t*) je_strdup((char*)jstring);
    if (!rv) goto error_out;

    json_object_put(jobject); jobject = NULL;
    
    return rv;
    
    error_out:
    fprintf(stderr, "could not serialize sflow metadata\n");
    if (rv)      { je_free(rv); rv = NULL; }
    if (jobject) { json_object_put(jobject); jobject = NULL; }
    if (item)    { json_object_put(item);    item = NULL;    }

    return NULL;
}

void sflow_counter_sample_callback(sflow_sample_t* sample, sflow_if_counters_t* if_counters, uint32_t s_index, uint32_t e_index) {
    sflow_if_counters_t c;

    if (rte_get_log_level() >= RTE_LOG_FINE) {    
        RTE_LOG(INFO, EXTRACTOR, "if_counters %u/%u:\n"
               "    skipped\n",
            s_index, e_index);
        return;
    }

    rte_memcpy(&c, if_counters, sizeof(if_counters));

    c.ifIndex            = be32(if_counters->ifIndex);
    c.ifType             = be32(if_counters->ifType);
    c.ifSpeed            = be64(if_counters->ifSpeed);
    c.ifDirection        = be32(if_counters->ifDirection);
    c.ifStatus           = be32(if_counters->ifStatus);
    c.ifInOctets         = be64(if_counters->ifInOctets);
    c.ifInUcastPkts      = be32(if_counters->ifInUcastPkts);
    c.ifInMulticastPkts  = be32(if_counters->ifInMulticastPkts);
    c.ifInBroadcastPkts  = be32(if_counters->ifInBroadcastPkts);
    c.ifInDiscards       = be32(if_counters->ifInDiscards);
    c.ifInErrors         = be32(if_counters->ifInErrors);
    c.ifInUnknownProtos  = be32(if_counters->ifInUnknownProtos);
    c.ifOutOctets        = be64(if_counters->ifOutOctets);
    c.ifOutUcastPkts     = be32(if_counters->ifOutUcastPkts);
    c.ifOutMulticastPkts = be32(if_counters->ifOutMulticastPkts);
    c.ifOutBroadcastPkts = be32(if_counters->ifOutBroadcastPkts);
    c.ifOutDiscards      = be32(if_counters->ifOutDiscards);
    c.ifOutErrors        = be32(if_counters->ifOutErrors);
    c.ifPromiscuousMode  = be32(if_counters->ifPromiscuousMode);

    RTE_LOG(FINE, EXTRACTOR, "if_counters %u/%u:\n"
           "    ifIndex %u\n"
           "    ifType %u\n"
           "    ifSpeed %lu\n"
           "    ifDirection %s\n"
           "    ifStatus %s\n"
           "    ifInOctets %lu\n"
           "    ifInUcastPkts %u\n"
           "    ifInMulticastPkts %u\n"
           "    ifInBroadcastPkts %u\n"
           "    ifInDiscards %u\n"
           "    ifInErrors %u\n"
           "    ifInUnknownProtos %u\n"
           "    ifOutOctets %lu\n"
           "    ifOutUcastPkts %u\n"
           "    ifOutMulticastPkts %u\n"
           "    ifOutBroadcastPkts %u\n"
           "    ifOutDiscards %u\n"
           "    ifOutErrors %u\n"
           "    ifPromiscuousMode %u\n",
           s_index, e_index,
           c.ifIndex,
           c.ifType,
           c.ifSpeed,
           sflow_counters_direction_dump(c.ifDirection),
           sflow_counters_status_dump(c.ifStatus),
           c.ifInOctets,
           c.ifInUcastPkts,
           c.ifInMulticastPkts,
           c.ifInBroadcastPkts,
           c.ifInDiscards,
           c.ifInErrors,
           c.ifInUnknownProtos,
           c.ifOutOctets,
           c.ifOutUcastPkts,
           c.ifOutMulticastPkts,
           c.ifOutBroadcastPkts,
           c.ifOutDiscards,
           c.ifOutErrors,
           c.ifPromiscuousMode);
}

void sflow_log(sflow_sample_t* sample, char* fmt, ...) __attribute__ ((__format__ (__printf__, 2, 3))) {
    /* scripts like to have all the context on every line */
    printf("%s %u %u %u:%u %s %s ",
            "mhall",// sflow_ip_string(&sample->agent_ip),
            sample->agent_sub_id,
            sample->packet_seq_num,
            sample->ds_type,
            sample->ds_index,
            sflow_tag_dump(sample->sample_type),
            sflow_tag_dump(sample->data_format));
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
}

static const char* sflow_http_method_names[] = { "-", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT" };

void sflow_log_clf(sflow_sample_t* sample, char* auth_user, char* uri, uint32_t protocol, char* referrer, char* user_agent, uint32_t method, uint32_t status, uint64_t resp_bytes) {
    time_t now = time(NULL);
    char now_str[200];
    strftime(now_str, sizeof(now_str), "%d/%b/%Y:%H:%M:%S %z", localtime(&now));
    printf("%s - %s [%s] \"%s %s HTTP/%u.%u\" %u %lu \"%s\" \"%s\"",
        sample->client,
        auth_user[0] ? auth_user : "-",
        now_str,
        sflow_http_method_names[method],
        uri[0] ? uri : "-",
        protocol / 1000,
        protocol % 1000,
        status,
        resp_bytes,
        referrer[0] ? referrer : "-",
        user_agent[0] ? user_agent : "-");
}
