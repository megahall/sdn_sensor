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

struct {
    pcre* re;
    int invert;
    TAILQ_ENTRY(ss_re_entry_s) entry;
} ss_re_entry_s;

typedef struct ss_re_entry_s ss_re_entry_t;

TAILQ_HEAD(ss_re_list_s, ss_re_entry_s);
typedef struct ss_re_list_s ss_re_list_t;

struct {
    ss_re_list_t re_list;
} ss_re_chain_s;

typedef struct ss_re_chain_s ss_re_chain_t;

struct {
    char** match_list;
    json_object* match_result;
} ss_re_match_s;

typedef struct ss_re_match_s ss_re_match_t;

/* PCAP CHAIN */

struct {
    struct pcap_pkthdr pcap_header;
    uint8_t* packet;
    json_object* match_result;
} ss_pcap_match_s;

typedef struct ss_pcap_match_s ss_pcap_match_t;

struct {
    char* filter;
    struct bpf_program bpf_filter;
    TAILQ_ENTRY(ss_pcap_entry_s) entry;
} ss_pcap_entry_s;
typedef struct ss_pcap_entry_s ss_pcap_entry_t;

TAILQ_HEAD(ss_pcap_list_s, ss_pcap_entry_s);
typedef struct ss_pcap_list_s ss_pcap_list_t;

struct {
    ss_pcap_list_t pcap_list;
} ss_pcap_chain_s;

typedef struct ss_pcap_chain_s ss_pcap_chain_t;

#endif /* __COMMON_H__ */
