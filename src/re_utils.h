#pragma once

#include <stdint.h>

#include <bsd/sys/queue.h>

#include <rte_memory.h>

#include <pcre.h>
#include <cre2.h>

#include "ioc.h"
#include "nn_queue.h"

/* CONSTANTS */

#define SS_RE_MATCH_MAX  (16 * 3)

/* RE CHAIN */

enum ss_re_type_e {
    SS_RE_TYPE_EMPTY     = 0,
    SS_RE_TYPE_COMPLETE  = 1,
    SS_RE_TYPE_SUBSTRING = 2,
    SS_RE_TYPE_MAX,
};

typedef enum ss_re_type_e ss_re_type_t;

enum ss_re_backend_e {
    SS_RE_BACKEND_EMPTY = 0,
    SS_RE_BACKEND_PCRE  = 1,
    SS_RE_BACKEND_RE2   = 2,
    SS_RE_BACKEND_MAX,
};

typedef enum ss_re_backend_e ss_re_backend_t;

struct ss_re_entry_s {
    uint64_t matches;
    int inverted;
    
    ss_re_backend_t backend;
    ss_re_type_t type;
    
    pcre* pcre_re;
    pcre_extra* pcre_re_extra;
    
    cre2_regexp_t* re2_re;
    
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
    ss_re_entry_t* re_entry;
    ss_ioc_entry_t* ioc_entry;
};

typedef struct ss_re_match_s ss_re_match_t;

/* BEGIN PROTOTYPES */

int ss_re_init(void);
const char* ss_pcre_strerror(int pcre_errno);
ss_re_backend_t ss_re_backend_load(const char* backend_type);
ss_re_type_t ss_re_type_load(const char* re_type);
int ss_re_chain_destroy(void);
int ss_re_chain_add(ss_re_entry_t* re_entry);
int ss_re_chain_remove_index(int index);
int ss_re_chain_remove_name(char* name);
ss_re_entry_t* ss_re_entry_create(json_object* re_json);
int ss_re_entry_destroy(ss_re_entry_t* re_entry);
int ss_re_chain_match(ss_re_match_t* re_match, uint8_t* l4_offset, uint16_t l4_length);
int ss_re_entry_prepare_pcre(json_object* re_json, ss_re_entry_t* re_entry);
int ss_re_chain_match_pcre(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length);
int ss_re_chain_match_pcre_complete(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length);
int ss_re_chain_match_pcre_substring(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length);
int ss_re_entry_prepare_re2(json_object* re_json, ss_re_entry_t* re_entry);
int ss_re_chain_match_re2(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length);
int ss_re_chain_match_re2_complete(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length);
int ss_re_chain_match_re2_substring(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length);

/* END PROTOTYPES */
