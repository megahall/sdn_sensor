#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>

#include <bsd/sys/queue.h>
#include <json-c/json.h>
#include <pcap/pcap.h>
#include <pcre.h>

/*
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
*/
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <rte_ether.h>
#include <rte_log.h>
#include <rte_lpm.h>
#include <rte_memory.h>
#include <rte_mbuf.h>

/* MACROS */

#define SS_ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

/* CONSTANTS */

#define RTE_LOGTYPE_SS RTE_LOGTYPE_USER1

#define SS_INT16_SIZE         2
#define SS_ADDR_STR_SIZE     64

#define IPV4_ADDR_LEN         4
#define IPV6_ADDR_LEN        16
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

typedef struct ether_addr          eth_addr_t;
typedef struct ether_hdr           eth_hdr_t;
typedef struct ether_arp           arp_hdr_t;
typedef struct iphdr               ip4_hdr_t;
typedef struct ip6_hdr             ip6_hdr_t;
typedef struct icmphdr             icmp4_hdr_t;
typedef struct icmp6_hdr           icmp6_hdr_t;
typedef struct tcp_hdr             tcp_hdr_t;
typedef struct udp_hdr             udp_hdr_t;

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
        struct ip4_addr ip4;
        struct ip6_addr ip6;
    };
};

typedef struct ip_addr ip_addr;

#define ETH_ALEN   6
#define IPV4_ALEN  4
#define IPV6_ALEN 16

struct ether_arp {
    struct  arphdr ea_hdr;         /* fixed-size header */
    uint8_t arp_sha[ETH_ALEN];     /* sender hardware address */
    uint8_t arp_spa[IPV4_ALEN];    /* sender protocol address */
    uint8_t arp_tha[ETH_ALEN];     /* target hardware address */
    uint8_t arp_tpa[IPV4_ALEN];    /* target protocol address */
};
#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op  ea_hdr.ar_op

struct ndp_request_s {
    struct  nd_neighbor_solicit hdr;
    struct  nd_opt_hdr          lhdr;
    union {
        uint8_t nd_addr[ETHER_ADDR_LEN];
        //uint8_t nd_padding[SS_ROUND_UP(ETHER_ADDR_LEN, 8)];
    };
};

typedef struct ndp_request_s ndp_request_t;

#define NDP_ADDR_LEN (SS_ROUND_UP(ETHER_ADDR_LEN, 8))

struct ndp_reply_s {
    struct  nd_neighbor_advert  hdr;
    struct  nd_opt_hdr          lhdr;
    union {
        uint8_t nd_addr[ETHER_ADDR_LEN];
        //uint8_t nd_padding[NDP_ADDR_LEN];
    };
};

typedef struct ndp_reply_s ndp_reply_t;

struct ss_frame_s {
    unsigned int   active;
    unsigned int   port_id;
    unsigned int   length;
    rte_mbuf_t*    mbuf;
    
    eth_hdr_t*     eth;
    arp_hdr_t*     arp;
    ndp_request_t* ndp_rx;
    ndp_reply_t*   ndp_tx;
    ip4_hdr_t*     ip4;
    ip6_hdr_t*     ip6;
    icmp4_hdr_t*   icmp4;
    icmp6_hdr_t*   icmp6;
    tcp_hdr_t*     tcp;
    udp_hdr_t*     udp;
} __rte_cache_aligned;

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
} __rte_cache_aligned;

typedef struct ss_re_entry_s ss_re_entry_t;

TAILQ_HEAD(ss_re_list_s, ss_re_entry_s);
typedef struct ss_re_list_s ss_re_list_t;

struct ss_re_chain_s {
    ss_re_list_t re_list;
} __rte_cache_aligned;

typedef struct ss_re_chain_s ss_re_chain_t;

struct ss_re_match_s {
    int match_count;
    char** match_list;
    json_object* match_result;
} __rte_cache_aligned;

typedef struct ss_re_match_s ss_re_match_t;

/* PCAP CHAIN */

struct ss_pcap_match_s {
    struct pcap_pkthdr pcap_header;
    uint8_t* packet;
    json_object* match_result;
} __rte_cache_aligned;

typedef struct ss_pcap_match_s ss_pcap_match_t;

struct ss_pcap_entry_s {
    int match_count;
    int nn_conn;
    int nn_type;
    char nn_url[NN_URL_MAX];
    char* filter;
    struct bpf_program bpf_filter;
    TAILQ_ENTRY(ss_pcap_entry_s) entry;
} __rte_cache_aligned;
typedef struct ss_pcap_entry_s ss_pcap_entry_t;

TAILQ_HEAD(ss_pcap_list_s, ss_pcap_entry_s);
typedef struct ss_pcap_list_s ss_pcap_list_t;

struct ss_pcap_chain_s {
    ss_pcap_list_t pcap_list;
} __rte_cache_aligned;

typedef struct ss_pcap_chain_s ss_pcap_chain_t;

/* CIDR TABLE */

struct ss_cidr_entry_s {
    int match_count;
    int nn_conn;
    int nn_type;
    char nn_url[NN_URL_MAX];
    char cidr[CIDR_LENGTH_MAX];
} __rte_cache_aligned;

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
} __rte_cache_aligned;

typedef struct ss_cidr_table_s ss_cidr_table_t;

/* STRING TRIE */

struct ss_string_trie_s {
} __rte_cache_aligned;

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
