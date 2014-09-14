#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>

#include "metadata.h"
#include "common.h"
#include "ioc.h"
#include "json.h"
#include "nn_queue.h"

uint8_t* ss_nn_queue_prepare_metadata(const char* source, nn_queue_t* nn_queue, ss_frame_t* fbuf, ss_ioc_entry_t* iptr) {
    char tmp[1024];
    uint8_t* rv;
    
    if (nn_queue->format != NN_FORMAT_METADATA) {
        fprintf(stderr, "format %d not supported yet\n", nn_queue->format);
        goto error_out;
    }
    
    fbuf->data.json = json_object_new_object();
    if (fbuf->data.json == NULL) {
        fprintf(stderr, "could not allocate json object\n");
        goto error_out;
    }
    
    json_object* jsource     = json_object_new_string(source);
    
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
    
    json_object* dns_name    = json_object_new_string((char*)fbuf->data.dns_name);
    if (dns_name == NULL) goto error_out;
    
    // XXX: add support for dns_answers field, dns query type
    
    json_object_object_add(fbuf->data.json, "source",      jsource);
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
    json_object_object_add(fbuf->data.json, "dns_name",    dns_name);
    
    if (iptr) {
        ss_ioc_prepare_metadata(source, nn_queue, iptr, fbuf->data.json);
    }
    
    rv = (uint8_t*) json_object_to_json_string_ext(fbuf->data.json, JSON_C_TO_STRING_SPACED);
    return rv;
    
    error_out:
    fprintf(stderr, "could not serialize packet metadata\n");
    return NULL;
}

json_object* ss_ioc_prepare_metadata(const char* source, nn_queue_t* nn_queue, ss_ioc_entry_t* iptr, json_object* json) {
    char ip_str[SS_ADDR_STR_MAX];
    const char* result;

    if (nn_queue->format != NN_FORMAT_METADATA) {
        fprintf(stderr, "format %d not supported yet\n", nn_queue->format);
        goto error_out;
    }

    if (json == NULL) {
        json = json_object_new_object();
    }
    if (json == NULL) {
        fprintf(stderr, "could not allocate json object\n");
        goto error_out;
    }

    json_object* file_id     = json_object_new_int(iptr->file_id);
    if (file_id == NULL) goto error_out;
    json_object* ioc_id      = json_object_new_int(iptr->id);
    if (ioc_id == NULL) goto error_out;
    json_object* type        = json_object_new_string(ss_ioc_type_dump(iptr->type));
    if (type == NULL) goto error_out;
    json_object* threat_type = json_object_new_string(iptr->threat_type);
    if (threat_type == NULL) goto error_out;
    result = ss_inet_ntop(&iptr->ip, ip_str, sizeof(ip_str));
    json_object* ip          = NULL;
    if (result != NULL) {
        ip = json_object_new_string(ip_str);
    }
    if (ip == NULL) goto error_out;
    json_object* value       = json_object_new_string(iptr->value);
    if (value == NULL) goto error_out;
    json_object* dns         = json_object_new_string(iptr->dns);
    if (dns == NULL) goto error_out;

    json_object_object_add(json, "file_id",     file_id);
    json_object_object_add(json, "ioc_id",      ioc_id);
    json_object_object_add(json, "type",        type);
    json_object_object_add(json, "threat_type", threat_type);
    json_object_object_add(json, "ip",          ip);
    json_object_object_add(json, "value",       value);
    json_object_object_add(json, "dns",         dns);

    return json;

    error_out:
    fprintf(stderr, "could not serialize ioc id: %lu\n", iptr->id);
    return NULL;
}
