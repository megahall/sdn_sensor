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

#include <pcap/pcap.h>

#include "common.h"
#include "sdn_sensor.h"

int ss_nn_queue_create(json_object* items, nn_queue_t* nn_queue) {
    char* value;
    
    value = ss_json_string_get(items, "nm_queue_url");
    if (value == NULL) {
        fprintf(stderr, "nm_queue_url is null\n");
        goto error_out;
    }
    strlcpy(nn_queue->url, value, sizeof(nn_queue->url));
    
    value = ss_json_string_get(items, "nm_queue_type");
    if (value == NULL) {
        fprintf(stderr, "nm_queue_type is null\n");
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
        fprintf(stderr, "unknown nm_queue_type %s\n", value);
    }
    
    nn_queue->conn = nn_socket(AF_SP, nn_queue->type);
    if (nn_queue->conn < 0) {
        fprintf(stderr, "could not allocate nm queue socket: %s\n", nn_strerror(nn_errno()));
        goto error_out;
    }
    
    fprintf(stderr, "created nm_queue type %s url %s\n", value, nn_queue->url);
    
    return 0;
    
    error_out:
    ss_nn_queue_destroy(nn_queue);
    return -1;
}

int ss_nn_queue_destroy(nn_queue_t* nn_queue) {
    if (nn_queue->conn >= 0) { nn_close(nn_queue->conn); nn_queue->conn = -1; }
    nn_queue->type = -1;
    memset(nn_queue->url, 0, sizeof(nn_queue->url));
    return 0;
}

uint8_t* ss_nn_queue_prepare_pcap(nn_queue_t* nn_queue, ss_frame_t* fbuf) {
    char tmp[1024];
    uint8_t* rv;
    
    if (nn_queue->format != NN_FORMAT_METADATA) {
        fprintf(stderr, "format %d not supported yet\n", nn_queue->format);
        goto error_out;
    }
    
    fbuf->data.json = json_object_new_object();
    if (fbuf->data.json == NULL) {
        fprintf(stderr, "could not create json object\n");
        goto error_out;
    }
    
    json_object* port_id     = json_object_new_int(fbuf->data.port_id);
    if (port_id == NULL) goto error_out;
    json_object* direction   = json_object_new_int(fbuf->data.direction);
    if (direction == NULL) goto error_out;
    json_object* self        = json_object_new_int(fbuf->data.self);
    if (self == NULL) goto error_out;
    json_object* length      = json_object_new_int(fbuf->data.length);
    if (length == NULL) goto error_out;
    
    snprintf(tmp, sizeof(tmp), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        fbuf->data.smac[0], fbuf->data.smac[1], fbuf->data.smac[2],
        fbuf->data.smac[3], fbuf->data.smac[4], fbuf->data.smac[5]);
    json_object* smac        = json_object_new_string(tmp);
    if (smac == NULL) goto error_out;
    
    snprintf(tmp, sizeof(tmp), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        fbuf->data.dmac[0], fbuf->data.dmac[1], fbuf->data.dmac[2],
        fbuf->data.dmac[3], fbuf->data.dmac[4], fbuf->data.dmac[5]);
    json_object* dmac        = json_object_new_string(tmp);
    if (dmac == NULL) goto error_out;
    
    json_object* eth_type    = json_object_new_int(fbuf->data.eth_type);
    if (eth_type == NULL) goto error_out;
    
    json_object* sip = NULL;
    json_object* dip = NULL;
    if      (fbuf->data.eth_type == ETHER_TYPE_IPV4) {
        snprintf(tmp, sizeof(tmp), "%hhu.%hhu.%hhu.%hhu",
            fbuf->data.sip[0], fbuf->data.sip[1], fbuf->data.sip[2], fbuf->data.sip[3]);
        sip = json_object_new_string(tmp);
        snprintf(tmp, sizeof(tmp), "%hhu.%hhu.%hhu.%hhu",
            fbuf->data.dip[0], fbuf->data.dip[1], fbuf->data.dip[2], fbuf->data.dip[3]);
        dip = json_object_new_string(tmp);
    }
    else if (fbuf->data.eth_type == ETHER_TYPE_IPV6) {
        snprintf(tmp, sizeof(tmp), "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
            *(uint16_t*) &fbuf->data.sip[0],  *(uint16_t*) &fbuf->data.sip[2],
            *(uint16_t*) &fbuf->data.sip[4],  *(uint16_t*) &fbuf->data.sip[6],
            *(uint16_t*) &fbuf->data.sip[8],  *(uint16_t*) &fbuf->data.sip[10],
            *(uint16_t*) &fbuf->data.sip[12], *(uint16_t*) &fbuf->data.sip[14]);
        sip = json_object_new_string(tmp);
        snprintf(tmp, sizeof(tmp), "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
            *(uint16_t*) &fbuf->data.sip[0],  *(uint16_t*) &fbuf->data.sip[2],
            *(uint16_t*) &fbuf->data.sip[4],  *(uint16_t*) &fbuf->data.sip[6],
            *(uint16_t*) &fbuf->data.sip[8],  *(uint16_t*) &fbuf->data.sip[10],
            *(uint16_t*) &fbuf->data.sip[12], *(uint16_t*) &fbuf->data.sip[14]);
        dip = json_object_new_string(tmp);
    }
    else {
        fprintf(stderr, "could not extract IP addresses\n");
    }
    
    json_object* ip_protocol = json_object_new_int(fbuf->data.ip_protocol);
    if (ip_protocol == NULL) goto error_out;
    json_object* ttl         = json_object_new_int(fbuf->data.ttl);
    if (ttl == NULL) goto error_out;
    json_object* l4_length   = json_object_new_int(fbuf->data.l4_length);
    if (l4_length == NULL) goto error_out;
    json_object* icmp_type   = json_object_new_int(fbuf->data.icmp_type);
    if (icmp_type == NULL) goto error_out;
    json_object* icmp_code   = json_object_new_int(fbuf->data.icmp_code);
    if (icmp_code == NULL) goto error_out;
    json_object* sport       = json_object_new_int(fbuf->data.sport);
    if (sport == NULL) goto error_out;
    json_object* dport       = json_object_new_int(fbuf->data.dport);
    if (dport == NULL) goto error_out;
    
    json_object_object_add(fbuf->data.json, "port_id",     port_id);
    json_object_object_add(fbuf->data.json, "direction",   direction);
    json_object_object_add(fbuf->data.json, "self",        self);
    json_object_object_add(fbuf->data.json, "length",      length);
    json_object_object_add(fbuf->data.json, "smac",        smac);
    json_object_object_add(fbuf->data.json, "dmac",        dmac);
    json_object_object_add(fbuf->data.json, "eth_type",    eth_type);
    json_object_object_add(fbuf->data.json, "sip",         sip);
    json_object_object_add(fbuf->data.json, "dip",         dip);
    json_object_object_add(fbuf->data.json, "ip_protocol", ip_protocol);
    json_object_object_add(fbuf->data.json, "ttl",         ttl);
    json_object_object_add(fbuf->data.json, "l4_length",   l4_length);
    json_object_object_add(fbuf->data.json, "icmp_type",   icmp_type);
    json_object_object_add(fbuf->data.json, "icmp_code",   icmp_code);
    json_object_object_add(fbuf->data.json, "sport",       sport);
    json_object_object_add(fbuf->data.json, "dport",       dport);
    
    rv = (uint8_t*) json_object_to_json_string_ext(fbuf->data.json, JSON_C_TO_STRING_SPACED);
    return rv;
    
    error_out:
    fprintf(stderr, "could not serialize packet metadata\n");
    return NULL;
}

int ss_nn_queue_send(nn_queue_t* nn_queue, uint8_t* message, uint16_t length) {
    int rv = 0;
    
    rv = nn_send(nn_queue->conn, message, length, 0);
    
    return rv;
}
