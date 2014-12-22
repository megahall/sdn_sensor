#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>

#include <bsd/sys/queue.h>
#include <pcap/pcap.h>

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
#include <rte_lpm6.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include <uthash.h>

#include "ip_utils.h"
#include "nn_queue.h"

/* MACROS */

#define SS_ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

#define SS_CHECK_SELF(fbuf, rv) \
    do { \
        if (!fbuf->data.self) { \
            return rv; \
        } \
    } while(0)

/* CONSTANTS */

#define RTE_LOGTYPE_SS RTE_LOGTYPE_USER1

#define RTE_LOGTYPE_CONF      RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_UTILS     RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_STACK     RTE_LOGTYPE_USER3
#define RTE_LOGTYPE_EXTRACTOR RTE_LOGTYPE_USER4
#define RTE_LOGTYPE_IOC       RTE_LOGTYPE_USER5
#define RTE_LOGTYPE_NM        RTE_LOGTYPE_USER6
#define RTE_LOGTYPE_MD        RTE_LOGTYPE_USER7
#define RTE_LOGTYPE_JSON      RTE_LOGTYPE_USER8

#define SS_INT16_SIZE         2

#define ETH_ALEN              6

#define SS_DNS_NAME_MAX      96
#define SS_DNS_RESULT_MAX     8

#define SS_LPM_RULE_MAX    1024
#define SS_LPM_TBL8S_MAX   (1 << 16)

#define SS_PCRE_MATCH_MAX  (16 * 3)

#define ETHER_TYPE_IPV4 ETHER_TYPE_IPv4
#define ETHER_TYPE_IPV6 ETHER_TYPE_IPv6

#define IPPROTO_ICMPV4 IPPROTO_ICMP

#define L4_PORT_DNS          53
#define L4_PORT_SYSLOG      514
#define L4_PORT_SYSLOG_TLS  601
#define L4_PORT_SFLOW      6343
#define L4_PORT_NETFLOW_1  2055
#define L4_PORT_NETFLOW_2  9995
#define L4_PORT_NETFLOW_3  9996

/* TYPEDEFS */

typedef struct rte_mbuf    rte_mbuf_t;
typedef struct rte_mempool rte_mempool_t;

typedef struct rte_lpm     rte_lpm4_t;
typedef struct rte_lpm6    rte_lpm6_t;

typedef struct ether_addr  eth_addr_t;
typedef struct ether_hdr   eth_hdr_t;
typedef struct ether_arp   arp_hdr_t;
typedef struct iphdr       ip4_hdr_t;
typedef struct ip6_hdr     ip6_hdr_t;
typedef struct icmphdr     icmp4_hdr_t;
typedef struct icmp6_hdr   icmp6_hdr_t;
typedef struct tcphdr      tcp_hdr_t;
typedef struct udphdr      udp_hdr_t;

/* DATA TYPES */

struct eth_vhdr_s {
    uint16_t ether_type;
    uint16_t tag      : 12;
    uint16_t drop     :  1;
    uint16_t priority :  3;
};

typedef struct eth_vhdr_s eth_vhdr_t;

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

struct ndp_reply_s {
    struct  nd_neighbor_advert  hdr;
    struct  nd_opt_hdr          lhdr;
    uint8_t nd_addr[ETHER_ADDR_LEN];
};

typedef struct ndp_reply_s ndp_reply_t;

enum direction_e {
    SS_FRAME_RX = 1,
    SS_FRAME_TX = 2,
    SS_FRAME_MAX,
};

typedef enum direction_e ss_direction_t;

enum ss_answer_type_e {
    SS_TYPE_EMPTY = 0,
    SS_TYPE_NAME  = 1,
    SS_TYPE_IP    = 2,
    SS_TYPE_MAX,
};

typedef enum ss_answer_type_e ss_answer_type_t;

struct ss_answer_s {
    ss_answer_type_t type;
    uint8_t payload[SS_DNS_NAME_MAX];
};

typedef struct ss_answer_s ss_answer_t;

struct ss_metadata_s {
    uint32_t    port_id;
    uint8_t     direction;
    uint8_t     self;
    uint16_t    length;
    uint8_t     smac[ETHER_ADDR_LEN];
    uint8_t     dmac[ETHER_ADDR_LEN];
    uint16_t    eth_type;
    uint8_t     sip[IPV6_ALEN];
    uint8_t     dip[IPV6_ALEN];
    uint8_t     ip_protocol;
    uint8_t     ttl;
    uint16_t    l4_length;
    uint8_t     icmp_type;
    uint8_t     icmp_code;
    uint8_t     tcp_flags;
    uint16_t    sport;
    uint16_t    dport;
    uint8_t     dns_name[SS_DNS_NAME_MAX];
    ss_answer_t dns_answers[SS_DNS_RESULT_MAX];
} __rte_cache_aligned;

typedef struct ss_metadata_s ss_metadata_t;

struct ss_ioc_file_s {
    uint64_t   file_id;
    char*      path;
    nn_queue_t nn_queue;
};

typedef struct ss_ioc_file_s ss_ioc_file_t;

struct ss_frame_s {
    unsigned int   active;
    //unsigned int   port_id;
    //unsigned int   length;
    //direction_t    direction;
    rte_mbuf_t*    mbuf;
    
    eth_hdr_t*     eth;
    eth_vhdr_t*    ethv;
    arp_hdr_t*     arp;
    ndp_request_t* ndp_rx;
    ndp_reply_t*   ndp_tx;
    ip4_hdr_t*     ip4;
    ip6_hdr_t*     ip6;
    icmp4_hdr_t*   icmp4;
    icmp6_hdr_t*   icmp6;
    tcp_hdr_t*     tcp;
    udp_hdr_t*     udp;
    uint8_t*       l4_offset;
    
    ss_metadata_t  data;
} __rte_cache_aligned;

typedef struct ss_frame_s ss_frame_t;

/* PCAP CHAIN */

struct ss_pcap_match_s {
    struct pcap_pkthdr header;
    uint8_t* packet;
} __rte_cache_aligned;

typedef struct ss_pcap_match_s ss_pcap_match_t;

struct ss_pcap_entry_s {
    struct bpf_program bpf_filter;
    uint64_t matches;
    nn_queue_t nn_queue;
    char* name;
    char* filter;
    TAILQ_ENTRY(ss_pcap_entry_s) entry;
} __rte_cache_aligned;

typedef struct ss_pcap_entry_s ss_pcap_entry_t;

TAILQ_HEAD(ss_pcap_list_s, ss_pcap_entry_s);
typedef struct ss_pcap_list_s ss_pcap_list_t;

struct ss_pcap_chain_s {
    uint64_t matches;
    ss_pcap_list_t pcap_list;
} __rte_cache_aligned;

typedef struct ss_pcap_chain_s ss_pcap_chain_t;

/* DNS CHAIN */

struct ss_dns_entry_s {
    uint64_t matches;
    char dns[SS_DNS_NAME_MAX];
    ip_addr_t ip;
    nn_queue_t nn_queue;
    char* name;
    TAILQ_ENTRY(ss_dns_entry_s) entry;
} __rte_cache_aligned;

typedef struct ss_dns_entry_s ss_dns_entry_t;

TAILQ_HEAD(ss_dns_list_s, ss_dns_entry_s);
typedef struct ss_dns_list_s ss_dns_list_t;

struct ss_dns_chain_s {
    uint64_t matches;
    ss_dns_list_t dns_list;
} __rte_cache_aligned;

typedef struct ss_dns_chain_s ss_dns_chain_t;

/* CIDR TABLE */

struct ss_cidr_entry_s {
    UT_hash_handle hh;
    uint64_t matches;
    nn_queue_t nn_queue;
    char* name;
} __rte_cache_aligned;

typedef struct ss_cidr_entry_s ss_cidr_entry_t;

struct ss_cidr_table_s {
    uint64_t hash4_matches;
    uint64_t hash6_matches;
    uint64_t cidr4_matches;
    uint64_t cidr6_matches;
    
    ss_cidr_entry_t* hash4;
    ss_cidr_entry_t* hash6;
    rte_lpm4_t* cidr4;
    rte_lpm6_t* cidr6;
} __rte_cache_aligned;

typedef struct ss_cidr_table_s ss_cidr_table_t;

/* BEGIN PROTOTYPES */

int ss_metadata_prepare(ss_frame_t* fbuf);
ss_direction_t ss_direction_load(const char* direction);
const char* ss_direction_dump(ss_direction_t direction);
int ss_pcap_chain_destroy(void);
ss_pcap_entry_t* ss_pcap_entry_create(json_object* pcap_json);
int ss_pcap_entry_destroy(ss_pcap_entry_t* pcap_entry);
int ss_pcap_chain_add(ss_pcap_entry_t* pcap_entry);
int ss_pcap_chain_remove_index(int index);
int ss_pcap_chain_remove_name(char* name);
int ss_pcap_match_prepare(ss_pcap_match_t* pcap_match, uint8_t* packet, uint16_t length);
int ss_pcap_match(ss_pcap_entry_t* pcap_entry, ss_pcap_match_t* pcap_match);
int ss_dns_chain_destroy(void);
ss_dns_entry_t* ss_dns_entry_create(json_object* dns_json);
int ss_dns_entry_destroy(ss_dns_entry_t* dns_entry);
int ss_dns_chain_add(ss_dns_entry_t* dns_entry);
int ss_dns_chain_remove_index(int index);
int ss_dns_chain_remove_name(char* name);
ss_cidr_table_t* ss_cidr_table_create(json_object* cidr_json);
int ss_cidr_table_destroy(ss_cidr_table_t* cidr_table);
ss_cidr_entry_t* ss_cidr_entry_create(json_object* cidr_json);
int ss_cidr_entry_destroy(ss_cidr_entry_t* cidr_entry);
int ss_cidr_table_add(ss_cidr_table_t* cidr_table, ss_cidr_entry_t* cidr_entry);
int ss_cidr_table_remove(ss_cidr_table_t* cidr_table, char* cidr);

/* END PROTOTYPES */

#endif /* __COMMON_H__ */
