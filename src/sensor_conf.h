#ifndef __SENSOR_CONF_H__
#define __SENSOR_CONF_H__

#include <stdint.h>
#include <wordexp.h>

#include <rte_memory.h>

#include <json-c/json.h>
#include <json-c/json_object_private.h>

#define MDB_MAXKEYSIZE 1023
#include <lmdb.h>

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
    uint16_t rxd_count;
    uint16_t txd_count;
    int      rss_enabled;
    uint64_t timer_cycles;
    
    wordexp_t eal_vector;
    
    ss_pcap_chain_t pcap_chain;
    ss_cidr_table_t cidr_table;
    ss_dns_chain_t dns_chain;
    ss_re_chain_t re_chain;
    
    uint64_t ioc_file_id;
    ss_ioc_file_t ioc_files[SS_IOC_FILE_MAX];
    ss_ioc_chain_t ioc_chain;
    
    ss_ioc_entry_t* ip4_table;
    ss_ioc_entry_t* ip6_table;
    ss_ioc_entry_t* domain_table;
    ss_ioc_entry_t* url_table;
    ss_ioc_entry_t* email_table;
    
    MDB_env* mdb_env;
    MDB_dbi  ip4_dbi;
    MDB_dbi  ip6_dbi;
    MDB_dbi  domain_dbi;
    MDB_dbi  url_dbi;
    MDB_dbi  email_dbi;
} __rte_cache_aligned;

typedef struct ss_conf_s ss_conf_t;

/* BEGIN PROTOTYPES */

int ss_conf_destroy(void);
char* ss_conf_path_get(void);
uint64_t ss_conf_tsc_read(void);
uint64_t ss_conf_tsc_hz_get(void);
char* ss_conf_file_read(char* conf_path);
int ss_conf_network_parse(json_object* items);
int ss_conf_dpdk_parse(json_object* items);
int ss_conf_mdb_init(void);
ss_conf_t* ss_conf_file_parse(char* conf_path);

/* END PROTOTYPES */

#endif /* __SENSOR_CONF_H__ */
