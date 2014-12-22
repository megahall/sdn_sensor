#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>

#include <bsd/string.h>

#include <nanomsg/nn.h>
#include <nanomsg/inproc.h>
#include <nanomsg/ipc.h>
#include <nanomsg/tcp.h>
#include <nanomsg/pair.h>
#include <nanomsg/pubsub.h>
#include <nanomsg/reqrep.h>
#include <nanomsg/pipeline.h>
#include <nanomsg/survey.h>
#include <nanomsg/bus.h>

#include <rte_log.h>

#include <pcap/pcap.h>

/* XXX: mhall: causes include loop w/ common.h */
/* #include "nn_queue.h" */

#include "common.h"
#include "json.h"
#include "sdn_sensor.h"

int ss_nn_queue_create(json_object* items, nn_queue_t* nn_queue) {
    // int rv;
    int so_value;
    char* value = NULL;
    
    memset(nn_queue, 0, sizeof(nn_queue_t));
    
    value = ss_json_string_get(items, "nm_url");
    if (value == NULL) {
        fprintf(stderr, "nm_url is null\n");
        goto error_out;
    }
    strlcpy(nn_queue->url, value, sizeof(nn_queue->url));
    je_free(value);
    
    value = ss_json_string_get(items, "nm_type");
    if (value == NULL) {
        fprintf(stderr, "nm_type is null\n");
        goto error_out;
    }
    if      (!strcasecmp(value, "BUS"))        nn_queue->type = NN_BUS;
    else if (!strcasecmp(value, "PAIR"))       nn_queue->type = NN_PAIR;
    else if (!strcasecmp(value, "PUSH"))       nn_queue->type = NN_PUSH;
    else if (!strcasecmp(value, "PULL"))       nn_queue->type = NN_PULL;
    else if (!strcasecmp(value, "PUB"))        nn_queue->type = NN_PUB;
    else if (!strcasecmp(value, "SUB"))        nn_queue->type = NN_SUB;
    else if (!strcasecmp(value, "REQ"))        nn_queue->type = NN_REQ;
    else if (!strcasecmp(value, "REP"))        nn_queue->type = NN_REP;
    else if (!strcasecmp(value, "SURVEYOR"))   nn_queue->type = NN_SURVEYOR;
    else if (!strcasecmp(value, "RESPONDENT")) nn_queue->type = NN_RESPONDENT;
    else {
        fprintf(stderr, "unknown nm_type %s\n", value);
        goto error_out;
    }
    je_free(value);
    
    value = ss_json_string_get(items, "nm_format");
    if      (!strcasecmp(value, "metadata")) nn_queue->format = NN_FORMAT_METADATA;
    else if (!strcasecmp(value, "packet"))   nn_queue->format = NN_FORMAT_PACKET;
    else {
        fprintf(stderr, "unknown nm_format %s\n", value);
        goto error_out;
    }
    je_free(value);
    
    nn_queue->conn = nn_socket(AF_SP, nn_queue->type);
    if (nn_queue->conn < 0) {
        fprintf(stderr, "could not allocate nm queue socket: %s\n", nn_strerror(nn_errno()));
        goto error_out;
    }
    so_value = 0;
    /*
    rv = nn_setsockopt(nn_queue->conn, NN_SOL_SOCKET, NN_IPV4ONLY, &so_value, sizeof(so_value));
    if (rv != 0) {
        fprintf(stderr, "could not enable nm ipv6 support: %s\n", nn_strerror(nn_errno()));
        goto error_out;
    }
    */
    nn_queue->remote_id = nn_connect(nn_queue->conn, nn_queue->url);
    if (nn_queue->remote_id < 0) {
        fprintf(stderr, "could not connect nm queue socket: %s\n", nn_strerror(nn_errno()));
        goto error_out;
    }
    
    fprintf(stderr, "created nm_queue type %s url %s\n", ss_nn_queue_type_dump(nn_queue->type), nn_queue->url);
    return 0;
    
    error_out:
    if (nn_queue) ss_nn_queue_destroy(nn_queue);
    if (value) je_free(value);
    return -1;
}

int ss_nn_queue_destroy(nn_queue_t* nn_queue) {
    if (!nn_queue) return 0;
    if (nn_queue->conn >= 0) { nn_close(nn_queue->conn); nn_queue->conn = -1; }
    nn_queue->remote_id = -1;
    nn_queue->format    = -1;
    nn_queue->content   = -1;
    nn_queue->type      = -1;
    memset(nn_queue->url, 0, sizeof(nn_queue->url));
    return 0;
}

const char* ss_nn_queue_type_dump(int nn_queue_type) {
    switch (nn_queue_type) {
        case NN_BUS:        return "NN_BUS";
        case NN_PAIR:       return "NN_PAIR";
        case NN_PUSH:       return "NN_PUSH";
        case NN_PULL:       return "NN_PULL";
        case NN_PUB:        return "NN_PUB";
        case NN_SUB:        return "NN_SUB";
        case NN_REQ:        return "NN_REQ";
        case NN_REP:        return "NN_REP";
        case NN_SURVEYOR:   return "NN_SURVEYOR";
        case NN_RESPONDENT: return "NN_RESPONDENT";
        default:            return "UNKNOWN";
    }
}

const char* ss_nn_queue_format_dump(nn_queue_format_t nn_format) {
    switch (nn_format) {
        case NN_FORMAT_METADATA: return "NN_FORMAT_METADATA";
        case NN_FORMAT_PACKET:   return "NN_FORMAT_PACKET";
        default:                 return "UNKNOWN";
    }
}

const char* ss_nn_queue_content_dump(nn_content_type_t nn_type) {
    switch (nn_type) {
        case NN_OBJECT_PCAP:    return "NN_OBJECT_PCAP";
        case NN_OBJECT_SYSLOG:  return "NN_OBJECT_SYSLOG";
        case NN_OBJECT_SFLOW:   return "NN_OBJECT_SFLOW";
        case NN_OBJECT_NETFLOW: return "NN_OBJECT_NETFLOW";
        default:                return "UNKNOWN";
    }
}

int ss_nn_queue_dump(nn_queue_t* nn_queue) {
    fprintf(stderr, "nn_queue: id [%d] remote [%d] format [%s] content [%s] type [%s]\n"
        "TX: Messages [%'20lu] Bytes [%'20lu] Discards [%'20lu]\n",
        nn_queue->conn, nn_queue->remote_id,
        ss_nn_queue_format_dump(nn_queue->format), ss_nn_queue_content_dump(nn_queue->content), ss_nn_queue_type_dump(nn_queue->type),
        nn_queue->tx_messages, nn_queue->tx_bytes, nn_queue->tx_discards);
    return 0;
}

int ss_nn_queue_send(nn_queue_t* nn_queue, uint8_t* message, uint16_t length) {
    int rv = 0;
    
    // XXX: assume message is a C string for now
    RTE_LOG(NOTICE, NM, "nn_queue %s: message id %014lu: %s\n",
        nn_queue->url, nn_queue->tx_messages, message);
    
    rv = nn_send(nn_queue->conn, message, length, NN_DONTWAIT);
    
    if (rv >= 0) {
        // XXX: note: tx_messages is used as seq_num
        // incremented in different code from this
        __sync_add_and_fetch(&nn_queue->tx_bytes, rv);
    }
    else {
        __sync_add_and_fetch(&nn_queue->tx_discards, 1);
    }
    
    return rv;
}
