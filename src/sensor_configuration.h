#ifndef __SENSOR_CONFIGURATION_H__
#define __SENSOR_CONFIGURATION_H__

#include <stdint.h>
#include <wordexp.h>

#include <json-c/json.h>

#include "common.h"

typedef enum json_type json_type_t;
typedef enum json_tokener_error json_error_t;
typedef struct array_list array_list_t;

struct ss_conf_s {
    // options
    int promiscuous_mode;
    uint16_t mtu;
    
    struct ip_addr ipv4_address;
    struct ip_addr ipv4_gateway;
    struct ip_addr ipv6_address;
    struct ip_addr ipv6_gateway;
    
    char* eal_options;
    uint32_t port_mask;
    uint32_t queue_count;
    uint64_t timer_msec;
    int port_count;
    
    wordexp_t eal_vector;
    
    ss_re_chain_t re_chain;
    ss_pcap_chain_t pcap_chain;
    ss_cidr_table_t cidr_table;
    ss_string_trie_t string_trie;
};

typedef struct ss_conf_s ss_conf_t;

/* BEGIN PROTOTYPES */

int ss_conf_destroy(ss_conf_t* ss_conf);
char* ss_conf_path_get(void);
char* ss_conf_file_read(void);
int ss_conf_network_parse(ss_conf_t* ss_conf, json_object* items);
ss_conf_t* ss_conf_file_parse(void);

/* END PROTOTYPES */

#endif /* __SENSOR_CONFIGURATION_H__ */
