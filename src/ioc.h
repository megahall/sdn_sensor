#ifndef __IOC_H__
#define __IOC_H__

#include <bsd/sys/queue.h>

#include <rte_memory.h>

#include "ip_utils.h"

/*
id,type,threat_type,ip,rdns,value
48,ip,scan_ip,58.245.126.184,,58.245.126.184
49,ip,scan_ip,60.169.80.103,,60.169.80.103
50,ip,scan_ip,115.238.54.231,,115.238.54.231
163,ip,apt_ip,103.30.7.77,,103.30.7.77
164,domain,apt_domain,216.83.32.29,,uygurinfo.com
261,ip,spam_ip,203.196.130.111,,203.196.130.111
52970,url,mal_url,193.124.93.76,,http://auspost-tracking24.biz
52996,domain,dyn_dns,104.28.7.65,,ipcheker.com
53029,ip,scan_ip,115.88.194.40,,115.88.194.40
*/

/* CONSTANTS */

#define SS_IOC_THREAT_TYPE_SIZE  32
#define SS_IOC_RDNS_SIZE        256
#define SS_IOC_VALUE_SIZE       384

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
    uint64_t      matches;
    uint64_t      id;
    ss_ioc_type_t type;
    char          threat_type[SS_IOC_THREAT_TYPE_SIZE];
    ip_addr_t     ip;
    char          rdns[SS_IOC_RDNS_SIZE];
    char          value[SS_IOC_VALUE_SIZE];
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

int ss_ioc_chain_load(const char* ioc_path);
int ss_ioc_chain_dump(uint64_t limit);
ss_ioc_entry_t* ss_ioc_entry_create(char* ioc_str);
int ss_ioc_entry_destroy(ss_ioc_entry_t* ioc_entry);
int ss_ioc_entry_dump(ss_ioc_entry_t* ioc);
ss_ioc_type_t ss_ioc_type_load(const char* ioc_type);
const char* ss_ioc_type_dump(ss_ioc_type_t ioc_type);
int ss_ioc_chain_destroy(void);
int ss_ioc_chain_add(ss_ioc_entry_t* ioc_entry);
int ss_ioc_chain_remove_index(int index);
int ss_ioc_chain_remove_id(uint64_t id);

/* END PROTOTYPES */

#endif /* __IOC_H__ */
