#ifndef __COMMON_H__
#define __COMMON_H__

#include <bsd/sys/queue.h>
#include <json-c/json.h>
#include <pcap/pcap.h>
#include <pcre.h>

#include <rte_log.h>
#include <rte_lpm.h>
#include <rte_mbuf.h>

#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include "ss_icmp6.h"
#include <rte_tcp.h>
#include <rte_udp.h>

/* CONSTANTS */

#define RTE_LOGTYPE_SS RTE_LOGTYPE_USER1

#define SS_INT16_SIZE         2
#define SS_ADDR_STR_SIZE     64

#define SS_V4_ADDR_SIZE       4
#define SS_V6_ADDR_SIZE      16
#define SS_V4_PREFIX_MAX     32
#define SS_V6_PREFIX_MAX    128

/* should be enough for the nanomsg queue URL */
#define NN_URL_MAX 256

/* enough to hold [max_ipv6]/128 plus a bit extra */
#define CIDR_LENGTH_MAX 64

#define ETHER_TYPE_IPV4 ETHER_TYPE_IPv4
#define ETHER_TYPE_IPV6 ETHER_TYPE_IPv6

/* TYPEDEFS */

typedef struct rte_mbuf rte_mbuf_t;

typedef struct rte_hash rte_hash_t;
typedef struct rte_lpm  rte_lpm4_t;
typedef struct rte_lpm6 rte_lpm6_t;

typedef struct icmp_hdr icmpv4_hdr;

/* DATA TYPES */

struct ip4_addr {
    uint32_t addr;
};

typedef struct ip4_addr ip4_addr;

struct ip6_addr {
    uint8_t addr[16];
};

typedef struct ip6_addr ip6_addr;

struct ip_addr {
    uint8_t family;
    uint8_t prefix;
    union {
        struct ip4_addr ipv4;
        struct ip6_addr ipv6;
    };
};

typedef struct ip_addr ip_addr;

struct ss_frame_s {
    unsigned int      port_id;
    rte_mbuf_t        mbuf;
    
    struct ether_hdr* ethernet;
    struct arp_hdr*   arp;
    struct ipv4_hdr*  ipv4;
    struct ipv6_hdr*  ipv6;
    struct icmp_hdr   icmp4;
    struct icmp6_hdr  icmp6;
    struct tcp_hdr    tcp;
    struct udp_hdr    udp;
};

typedef struct ss_frame_s ss_frame_t;

typedef void (*process_packet_fptr)(ss_frame_t*);

struct ss_cidr_s {
    int family;
    //struct sockaddr ip;
    uint8_t mask;
};

typedef struct ss_cidr_s ss_cidr_t;

/* RE CHAIN */

struct ss_re_entry_s {
    int match_count;
    int invert;
    int nn_conn;
    int nn_type;
    char nn_url[NN_URL_MAX];
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
    int nn_conn;
    int nn_type;
    char nn_url[NN_URL_MAX];
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

struct ss_cidr_entry_s {
    int match_count;
    int nn_conn;
    int nn_type;
    char nn_url[NN_URL_MAX];
    char cidr[CIDR_LENGTH_MAX];
};

typedef struct ss_cidr_entry_s ss_cidr_entry_t;

struct ss_cidr_table_s {
    int hash_match4_count;
    int hash_match6_count;
    int cidr_match4_count;
    int cidr_match6_count;
    
    rte_hash_t* hash4_table;
    rte_hash_t* hash6_table;
    rte_lpm4_t* cidr4_table;
    rte_lpm6_t* cidr6_table;
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
