#ifndef __IOC_H__
#define __IOC_H__

#include <bsd/sys/queue.h>

#include <rte_memory.h>

#include <uthash.h>

#include "common.h"
#include "ip_utils.h"

/* CONSTANTS */

#define SS_IOC_FILE_MAX           8
#define SS_IOC_THREAT_TYPE_SIZE  24
#define SS_IOC_VALUE_SIZE        96
#define SS_IOC_DNS_SIZE          96

enum ss_ioc_type_e {
    SS_IOC_TYPE_IP     = 1,
    SS_IOC_TYPE_DOMAIN = 2,
    SS_IOC_TYPE_URL    = 3,
    SS_IOC_TYPE_EMAIL  = 4,
    SS_IOC_TYPE_MD5    = 5,
    SS_IOC_TYPE_SHA256 = 6,
    SS_IOC_TYPE_MAX,
};

typedef enum ss_ioc_type_e ss_ioc_type_t;

struct ss_ioc_entry_s {
    uint64_t      file_id;
    uint64_t      matches;
    uint64_t      id;
    ss_ioc_type_t type;
    char          threat_type[SS_IOC_THREAT_TYPE_SIZE];
    ip_addr_t     ip;
    char          value[SS_IOC_VALUE_SIZE];
    char          dns[SS_IOC_DNS_SIZE];
    UT_hash_handle hh;
    UT_hash_handle hh_full;
    TAILQ_ENTRY(ss_ioc_entry_s) entry;
} __rte_cache_aligned;

typedef struct ss_ioc_entry_s ss_ioc_entry_t;

TAILQ_HEAD(ss_ioc_list_s, ss_ioc_entry_s);
typedef struct ss_ioc_list_s ss_ioc_list_t;

struct ss_ioc_chain_s {
    ss_ioc_list_t ioc_list;
} __rte_cache_aligned;

typedef struct ss_ioc_chain_s ss_ioc_chain_t;

/* BEGIN PROTOTYPES */

int ss_ioc_file_load(json_object* ioc_json);
int ss_ioc_chain_dump(uint64_t limit);
int ss_ioc_tables_dump(uint64_t limit);
ss_ioc_entry_t* ss_ioc_entry_create(ss_ioc_file_t* ioc_file, char* ioc_str);
int ss_ioc_entry_destroy(ss_ioc_entry_t* ioc_entry);
int ss_ioc_entry_dump(ss_ioc_entry_t* ioc);
int ss_ioc_entry_dump_dpdk(ss_ioc_entry_t* ioc);
ss_ioc_type_t ss_ioc_type_load(const char* ioc_type);
const char* ss_ioc_type_dump(ss_ioc_type_t ioc_type);
int ss_ioc_chain_destroy(void);
int ss_ioc_chain_add(ss_ioc_entry_t* ioc_entry);
int ss_ioc_chain_remove_index(int index);
int ss_ioc_chain_remove_id(uint64_t id);
int ss_ioc_chain_optimize(void);
ss_ioc_entry_t* ss_ioc_metadata_match(ss_metadata_t* md);
ss_ioc_entry_t* ss_ioc_dns_match(ss_metadata_t* md);
ss_ioc_entry_t* ss_ioc_syslog_match(const char* ioc, ss_ioc_type_t ioc_type);

/* END PROTOTYPES */

#endif /* __IOC_H__ */
