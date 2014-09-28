#ifndef __PCRE_UTILS_H__
#define __PCRE_UTILS_H__

#include <stdbool.h>
#include <stdint.h>

#include <bsd/sys/queue.h>
#include <pcap/pcap.h>
#include <pcre.h>

#include <jemalloc/jemalloc.h>

#include <uthash.h>

#include "ioc.h"
#include "ip_utils.h"
#include "nn_queue.h"

/* CONSTANTS */

#define SS_PCRE_MATCH_MAX  (16 * 3)

/* RE CHAIN */

enum ss_re_type_e {
    SS_RE_TYPE_EMPTY     = 0,
    SS_RE_TYPE_COMPLETE  = 1,
    SS_RE_TYPE_SUBSTRING = 2,
    SS_RE_TYPE_MAX,
};

typedef enum ss_re_type_e ss_re_type_t;

struct ss_re_entry_s {
    uint64_t matches;
    int inverted;
    ss_re_type_t type;
    pcre* re;
    pcre_extra* re_extra;
    ss_ioc_type_t ioc_type;
    nn_queue_t nn_queue;
    char* name;
    TAILQ_ENTRY(ss_re_entry_s) entry;
} __rte_cache_aligned;

typedef struct ss_re_entry_s ss_re_entry_t;

TAILQ_HEAD(ss_re_list_s, ss_re_entry_s);
typedef struct ss_re_list_s ss_re_list_t;

struct ss_re_chain_s {
    ss_re_list_t re_list;
} __rte_cache_aligned;

typedef struct ss_re_chain_s ss_re_chain_t;

struct ss_re_match_s {
    uint64_t matches;
    char** match_list;
    json_object* match_result;
} __rte_cache_aligned;

typedef struct ss_re_match_s ss_re_match_t;

/* BEGIN PROTOTYPES */

int ss_pcre_init(void);
const char* ss_pcre_strerror(int pcre_errno);
ss_re_type_t ss_re_type_load(const char* re_type);
int ss_re_chain_destroy(void);
ss_re_entry_t* ss_re_entry_create(json_object* re_json);
int ss_re_entry_destroy(ss_re_entry_t* re_entry);
int ss_re_chain_match(char* input);
int ss_re_chain_add(ss_re_entry_t* re_entry);
int ss_re_chain_remove_index(int index);
int ss_re_chain_remove_name(char* name);

/* END PROTOTYPES */

#endif /* __PCRE_UTILS_H__ */
