#ifndef __SENSOR_CONF_H__
#define __SENSOR_CONF_H__

#include <stdint.h>
#include <wordexp.h>

#include <rte_memory.h>

#include <json-c/json.h>
#include <json-c/json_object_private.h>

#include "common.h"
#include "ioc.h"
#include "re_utils.h"

typedef enum json_type json_type_t;
typedef enum json_tokener_error json_error_t;

struct ss_conf_s {
    // options
    int promiscuous_mode;
    uint16_t mtu;
    
    ip_addr_t ip4_address;
    ip_addr_t ip4_gateway;
    ip_addr_t ip6_address;
    ip_addr_t ip6_gateway;
    
    char* eal_options;
    uint32_t log_level;
    uint32_t port_mask;
    uint64_t timer_msec;
    
    wordexp_t eal_vector;
    
    ss_pcap_chain_t pcap_chain;
    ss_cidr_table_t cidr_table;
    ss_dns_chain_t dns_chain;
    ss_re_chain_t re_chain;
    ss_string_trie_t string_trie;
    
    uint64_t ioc_file_id;
    ss_ioc_file_t ioc_files[SS_IOC_FILE_MAX];
    ss_ioc_chain_t ioc_chain;
    
    ss_ioc_entry_t* ip4_table;
    ss_ioc_entry_t* ip6_table;
    ss_ioc_entry_t* domain_table;
    ss_ioc_entry_t* url_table;
    ss_ioc_entry_t* email_table;
} __rte_cache_aligned;

typedef struct ss_conf_s ss_conf_t;

/* BEGIN PROTOTYPES */

int ss_conf_destroy(void);
char* ss_conf_path_get(void);
char* ss_conf_file_read(void);
int ss_conf_network_parse(json_object* items);
int ss_conf_dpdk_parse(json_object* items);
ss_conf_t* ss_conf_file_parse(void);

/* END PROTOTYPES */

#endif /* __SENSOR_CONF_H__ */
