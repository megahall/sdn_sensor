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
typedef struct rte_mempool rte_mempool_t;

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

struct ip4_addr_s {
    uint32_t addr;
};

typedef struct ip4_addr_s ip4_addr_t;

struct ip6_addr_s {
    uint8_t addr[16];
};

typedef struct ip6_addr_s ip6_addr_t;

struct ip_addr_s {
    uint8_t family;
    uint8_t prefix;
    union {
        ip4_addr_t ip4;
        ip6_addr_t ip6;
    } addr;
};
#define ip4_addr addr.ip4
#define ip6_addr addr.ip6

typedef struct ip_addr_s ip_addr_t;

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

enum direction_e {
    SS_FRAME_RX,
    SS_FRAME_TX,
};

typedef enum direction_e direction_t;

struct ss_frame_s {
    unsigned int   active;
    unsigned int   port_id;
    unsigned int   length;
    direction_t    direction;
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

enum nn_queue_format_e {
    NN_FORMAT_METADATA = 1,
    NN_FORMAT_PACKET   = 2,
};

typedef enum nn_queue_format_e nn_queue_format_t;

struct nn_queue_s {
    int               conn;
    nn_queue_format_t format;
    int               type;
    char              url[NN_URL_MAX];
};

typedef struct nn_queue_s nn_queue_t;

/* RE CHAIN */

struct ss_re_entry_s {
    uint64_t match_count;
    int invert;
    nn_queue_t nn_queue;
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
    uint64_t match_count;
    char** match_list;
    json_object* match_result;
} __rte_cache_aligned;

typedef struct ss_re_match_s ss_re_match_t;

/* PCAP CHAIN */

struct ss_pcap_match_s {
    struct pcap_pkthdr header;
    uint8_t* packet;
    json_object* match_result;
} __rte_cache_aligned;

typedef struct ss_pcap_match_s ss_pcap_match_t;

struct ss_pcap_entry_s {
    struct bpf_program bpf_filter;
    uint64_t match_count;
    nn_queue_t nn_queue;
    char* name;
    char* filter;
    TAILQ_ENTRY(ss_pcap_entry_s) entry;
} __rte_cache_aligned;
typedef struct ss_pcap_entry_s ss_pcap_entry_t;

TAILQ_HEAD(ss_pcap_list_s, ss_pcap_entry_s);
typedef struct ss_pcap_list_s ss_pcap_list_t;

struct ss_pcap_chain_s {
    uint64_t match_count;
    ss_pcap_list_t pcap_list;
} __rte_cache_aligned;

typedef struct ss_pcap_chain_s ss_pcap_chain_t;

/* CIDR TABLE */

struct ss_cidr_entry_s {
    uint64_t match_count;
    nn_queue_t nn_queue;
    char cidr[CIDR_LENGTH_MAX];
} __rte_cache_aligned;

typedef struct ss_cidr_entry_s ss_cidr_entry_t;

struct ss_cidr_table_s {
    uint64_t hash_match4_count;
    uint64_t hash_match6_count;
    uint64_t cidr_match4_count;
    uint64_t cidr_match6_count;
    
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

char* ss_json_string_get(json_object* items, const char* key);
int ss_nn_queue_create(json_object* items, nn_queue_t* nn_queue);
int ss_nn_queue_destroy(nn_queue_t* nn_queue);
int ss_re_chain_destroy(ss_re_chain_t* re_chain);
ss_re_entry_t* ss_re_entry_create(json_object* re_json);
int ss_re_entry_destroy(ss_re_entry_t* re_entry);
int ss_re_chain_add(ss_re_chain_t* re_chain, ss_re_entry_t* re_entry);
int ss_re_chain_remove_index(ss_re_chain_t* re_chain, int index);
int ss_re_chain_remove_re(ss_re_chain_t* re_chain, char* re);
int ss_re_chain_match(ss_re_chain_t* re_chain, char* input);
int ss_pcap_chain_destroy(ss_pcap_chain_t* pcap_chain);
ss_pcap_entry_t* ss_pcap_entry_create(json_object* pcap_json);
int ss_pcap_entry_destroy(ss_pcap_entry_t* pcap_entry);
int ss_pcap_chain_add(ss_pcap_chain_t* pcap_match, ss_pcap_entry_t* pcap_entry);
int ss_pcap_chain_remove_index(ss_pcap_chain_t* pcap_match, int index);
int ss_pcap_chain_remove_filter(ss_pcap_chain_t* pcap_match, char* filter);
int ss_pcap_match_prepare(ss_pcap_match_t* pcap_match, uint8_t* packet, uint16_t length);
int ss_pcap_match(ss_pcap_chain_t* pcap_chain, ss_pcap_match_t* pcap_match);
ss_cidr_table_t* ss_cidr_table_create(json_object* cidr_table_json);
int ss_cidr_table_destroy(ss_cidr_table_t* cidr_table);
ss_cidr_entry_t* ss_cidr_entry_create(json_object* cidr_json);
int ss_cidr_entry_destroy(ss_cidr_entry_t* cidr_entry);
int ss_cidr_table_add(ss_cidr_table_t* cidr_table, ss_cidr_entry_t* cidr_entry);
int ss_cidr_table_remove(ss_cidr_table_t* cidr_table, char* cidr);

/* END PROTOTYPES */

#endif /* __COMMON_H__ */
