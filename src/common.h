#ifndef __COMMON_H__
#define __COMMON_H__

#include <netinet/in.h>

#include <bsd/sys/queue.h>
#include <json-c/json.h>
#include <pcap/pcap.h>
#include <pcre.h>
#include <uthash.h>

/* DATA TYPES */

struct {
    struct sockaddr ip;
    uint8_t mask;
} ss_cidr_s;

/* RE CHAIN */

struct ss_re_entry_s {
    int match_count;
    int invert;
    pcre* re;
    TAILQ_ENTRY(ss_re_entry_s) entry;
};

typedef struct ss_re_entry_s ss_re_entry_t;

TAILQ_HEAD(ss_re_list_s, ss_re_entry_s);
typedef struct ss_re_list_s ss_re_list_t;

struct ss_re_chain_s {
    ss_re_list_t re_list;
};

typedef struct ss_re_chain_s ss_re_chain_t;

struct ss_re_match_s {
    int match_count;
    char** match_list;
    json_object* match_result;
};

typedef struct ss_re_match_s ss_re_match_t;

/* PCAP CHAIN */

struct ss_pcap_match_s {
    struct pcap_pkthdr pcap_header;
    uint8_t* packet;
    json_object* match_result;
};

typedef struct ss_pcap_match_s ss_pcap_match_t;

struct ss_pcap_entry_s {
    int match_count;
    char* filter;
    struct bpf_program bpf_filter;
    TAILQ_ENTRY(ss_pcap_entry_s) entry;
};
typedef struct ss_pcap_entry_s ss_pcap_entry_t;

TAILQ_HEAD(ss_pcap_list_s, ss_pcap_entry_s);
typedef struct ss_pcap_list_s ss_pcap_list_t;

struct ss_pcap_chain_s {
    ss_pcap_list_t pcap_list;
};

typedef struct ss_pcap_chain_s ss_pcap_chain_t;

/* CIDR TABLE */

/* enough to hold [max_ipv6]/128 plus a bit extra */
#define CIDR_LENGTH_MAX 64

struct ss_cidr_entry_s {
    char cidr[CIDR_LENGTH_MAX];
};

typedef struct ss_cidr_entry_s ss_cidr_entry_t;

struct ss_cidr_table_s {
};

typedef struct ss_cidr_table_s ss_cidr_table_t;

/* STRING TRIE */

struct ss_string_trie_s {
};

typedef struct ss_string_trie_s ss_string_trie_t;

/* BEGIN PROTOTYPES */

ss_re_chain_t* ss_re_chain_create(void);
int ss_re_chain_destroy(ss_re_chain_t* re_chain);
ss_re_entry_t* ss_re_entry_create(json_object* re_json);
int ss_re_entry_destroy(ss_re_entry_t* re_entry);
int ss_re_chain_add(ss_re_chain_t* re_chain, ss_re_entry_t* re_entry);
int ss_re_chain_remove_index(ss_re_chain_t* re_chain, int index);
int ss_re_chain_remove_re(ss_re_chain_t* re_chain, char* re);
int ss_re_chain_match(ss_re_chain_t* re_chain, char* input);
ss_pcap_match_t* ss_pcap_match_create(void);
int ss_pcap_match_destroy(ss_pcap_match_t* pcap_match);
ss_pcap_chain_t* ss_pcap_chain_create(void);
int ss_pcap_chain_destroy(ss_pcap_chain_t* pcap_chain);
ss_pcap_entry_t* ss_pcap_entry_create(json_object* pcap_json);
int ss_pcap_entry_destroy(ss_pcap_entry_t* pcap_entry);
int ss_pcap_chain_add(ss_pcap_chain_t* pcap_match, ss_pcap_entry_t* pcap_entry);
int ss_pcap_chain_remove_index(ss_pcap_chain_t* pcap_match, int index);
int ss_pcap_chain_remove_filter(ss_pcap_chain_t* pcap_match, char* filter);
int ss_pcap_match_init(ss_pcap_match_t* pcap_match, struct timeval* time, uint8_t* input, unsigned int length);
int ss_pcap_match(ss_pcap_chain_t* pcap_chain, ss_pcap_match_t* pcap_match);
ss_cidr_table_t* ss_cidr_table_create(json_object* cidr_table_json);
int ss_cidr_table_destroy(ss_cidr_table_t* cidr_table);
ss_cidr_entry_t* ss_cidr_entry_create(json_object* cidr_json);
int ss_cidr_entry_destroy(ss_cidr_entry_t* cidr_entry);
int ss_cidr_table_add(ss_cidr_table_t* cidr_table, ss_cidr_entry_t* cidr_entry);
int ss_cidr_table_remove(ss_cidr_table_t* cidr_table, char* cidr);

/* END PROTOTYPES */

#endif /* __COMMON_H__ */
