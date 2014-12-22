#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>

#include <bsd/string.h>
#include <bsd/sys/queue.h>

#include <jemalloc/jemalloc.h>

#include <json-c/json.h>
#include <json-c/json_object_private.h>

#include <pcap/pcap.h>

#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_log.h>

#include <uthash.h>

#include "common.h"
#include "ioc.h"
#include "json.h"
#include "sdn_sensor.h"

/* COMMON */

int ss_metadata_prepare(ss_frame_t* fbuf) {
    ss_metadata_t* m = &fbuf->data;
    
    m->port_id     = -1;
    m->direction   = -1;
    m->self        = 0;
    m->length      = 0;
    memset(m->smac, 0, sizeof(m->smac));
    memset(m->dmac, 0, sizeof(m->dmac));
    m->eth_type    = 0x0000;
    memset(m->sip, 0, sizeof(m->sip));
    memset(m->dip, 0, sizeof(m->dip));
    m->ip_protocol = -1;
    m->ttl         = 0;
    m->l4_length   = -1;
    m->icmp_type   = -1;
    m->icmp_code   = -1;
    m->tcp_flags   = 0;
    m->sport       = 0;
    m->dport       = 0;
    memset(m->dns_name, 0, sizeof(m->dns_name));
    memset(m->dns_answers, 0, sizeof(m->dns_answers));
    
    return 0;
}

ss_direction_t ss_direction_load(const char* direction) {
    if (!strcasecmp(direction, "rx")) return SS_FRAME_RX;
    if (!strcasecmp(direction, "tx")) return SS_FRAME_TX;
    return -1;
}

const char* ss_direction_dump(ss_direction_t direction) {
    switch (direction) {
        case SS_FRAME_RX: return "RX";
        case SS_FRAME_TX: return "TX";
        default:          return "UNKNOWN";
    }
}

/* PCAP CHAIN */

int ss_pcap_chain_destroy() {
    ss_pcap_entry_t* pptr;
    ss_pcap_entry_t* ptmp;
    TAILQ_FOREACH_SAFE(pptr, &ss_conf->pcap_chain.pcap_list, entry, ptmp) {
        ss_pcap_entry_destroy(pptr);
        TAILQ_REMOVE(&ss_conf->pcap_chain.pcap_list, pptr, entry);
    }
    return 0;
}

ss_pcap_entry_t* ss_pcap_entry_create(json_object* pcap_json) {
    // mhall
    ss_pcap_entry_t* pcap_entry = NULL;
    int rv                      = -1;
    
    pcap_entry = je_calloc(1, sizeof(ss_pcap_entry_t));
    if (pcap_entry == NULL) {
        fprintf(stderr, "could not allocate pcap entry\n");
        goto error_out;
    }
    
    if (!pcap_json) {
        fprintf(stderr, "empty pcap configuration entry\n");
        goto error_out;
    }
    if (!json_object_is_type(pcap_json, json_type_object)) {
        fprintf(stderr, "pcap_json is not object\n");
        goto error_out;
    }
    
    pcap_entry->name = ss_json_string_get(pcap_json, "name");
    if (pcap_entry->name == NULL) {
        fprintf(stderr, "pcap_entry name is null\n");
        goto error_out;
    }
    pcap_entry->filter = ss_json_string_get(pcap_json, "filter");
    if (pcap_entry->filter == NULL) {
        fprintf(stderr, "pcap_entry filter is null\n");
        goto error_out;
    }
    
    rv = ss_nn_queue_create(pcap_json, &pcap_entry->nn_queue);
    if (rv) {
        fprintf(stderr, "could not allocate pcap nm_queue\n");
        goto error_out;
    }
    
    rv = pcap_compile(ss_pcap, &pcap_entry->bpf_filter, pcap_entry->filter, 1 /* optimize */, PCAP_NETMASK_UNKNOWN);
    if (rv) {
        fprintf(stderr, "could not compile pcap filter [%s]: %s\n",
            pcap_entry->filter, pcap_geterr(ss_pcap));
        goto error_out;
    }
    
    fprintf(stderr, "created pcap entry [%s]\n", pcap_entry->name);
    return pcap_entry;
    
    error_out:
    ss_pcap_entry_destroy(pcap_entry); pcap_entry = NULL;
    return NULL;
}

int ss_pcap_entry_destroy(ss_pcap_entry_t* pcap_entry) {
    if (!pcap_entry) return 0;
    
    ss_nn_queue_destroy(&pcap_entry->nn_queue);
    pcap_entry->matches = 0;
    pcap_freecode(&pcap_entry->bpf_filter);
    
    if (pcap_entry->name)   { je_free(pcap_entry->name);   pcap_entry->name = NULL;   }
    if (pcap_entry->filter) { je_free(pcap_entry->filter); pcap_entry->filter = NULL; }
    
    je_free(pcap_entry);
    pcap_entry = NULL;
    
    return 0;
}

int ss_pcap_chain_add(ss_pcap_entry_t* pcap_entry) {
    TAILQ_INSERT_TAIL(&ss_conf->pcap_chain.pcap_list, pcap_entry, entry);
    return 0;
}

int ss_pcap_chain_remove_index(int index) {
    int counter = 0;
    ss_pcap_entry_t* pptr;
    ss_pcap_entry_t* ptmp;
    TAILQ_FOREACH_SAFE(pptr, &ss_conf->pcap_chain.pcap_list, entry, ptmp) {
        if (counter == index) {
            TAILQ_REMOVE(&ss_conf->pcap_chain.pcap_list, pptr, entry);
            return 0;
        }
        ++counter;
    }
    return -1;
}

int ss_pcap_chain_remove_name(char* name) {
    ss_pcap_entry_t* pptr;
    ss_pcap_entry_t* ptmp;
    TAILQ_FOREACH_SAFE(pptr, &ss_conf->pcap_chain.pcap_list, entry, ptmp) {
        if (!strcasecmp(name, pptr->name)) {
            TAILQ_REMOVE(&ss_conf->pcap_chain.pcap_list, pptr, entry);
            return 0;
        }
    }
    return -1;
}

int ss_pcap_match_prepare(ss_pcap_match_t* pcap_match, uint8_t* packet, uint16_t length) {
    // XXX: set to useless values for speed
    pcap_match->header.ts.tv_sec  = 0;
    pcap_match->header.ts.tv_usec = 0;
    pcap_match->header.caplen     = length;
    pcap_match->header.len        = length;
    pcap_match->packet            = packet;
    return 0;
}

/*
 * Checks for a pcap filter match between a given pcap filter and a given 
 * packet. Returns >0 for match, 0 for non-match, <0 for error.
 */
int ss_pcap_match(ss_pcap_entry_t* pcap_entry, ss_pcap_match_t* pcap_match) {
    int rv = pcap_offline_filter(&pcap_entry->bpf_filter, &pcap_match->header, pcap_match->packet);
    if (rv > 0) __sync_add_and_fetch (&pcap_entry->matches, 1);
    //fprintf(stderr, "pcap_offline_filter rv %d\n", rv);
    return rv;
}

/* DNS CHAIN */

int ss_dns_chain_destroy() {
    ss_dns_entry_t* dptr;
    ss_dns_entry_t* dtmp;
    TAILQ_FOREACH_SAFE(dptr, &ss_conf->dns_chain.dns_list, entry, dtmp) {
        ss_dns_entry_destroy(dptr);
        TAILQ_REMOVE(&ss_conf->dns_chain.dns_list, dptr, entry);
    }
    return 0;
}

ss_dns_entry_t* ss_dns_entry_create(json_object* dns_json) {
    // mhall
    ss_dns_entry_t* dns_entry = NULL;
    int rv                      = -1;
    
    dns_entry = je_calloc(1, sizeof(ss_dns_entry_t));
    if (dns_entry == NULL) {
        fprintf(stderr, "could not allocate dns entry\n");
        goto error_out;
    }
    
    if (!dns_json) {
        fprintf(stderr, "empty dns configuration entry\n");
        goto error_out;
    }
    if (!json_object_is_type(dns_json, json_type_object)) {
        fprintf(stderr, "dns_json is not object\n");
        goto error_out;
    }
    
    dns_entry->name = ss_json_string_get(dns_json, "name");
    if (dns_entry->name == NULL) {
        fprintf(stderr, "dns_entry name is null\n");
        goto error_out;
    }
    
    char* dns = ss_json_string_get(dns_json, "dns");
    if (dns == NULL) {
        memset(&dns_entry->dns, 0, sizeof(dns_entry->dns));
    }
    else {
        strlcpy(dns_entry->dns, dns, sizeof(dns_entry->dns));
    }
    
    const char* ip_str = ss_json_string_get(dns_json, "ip");
    rv = ss_cidr_parse(ip_str, &dns_entry->ip);
    if (rv != 1) {
        memset(&dns_entry->ip, 0, sizeof(dns_entry->ip));
    }
    
    rv = ss_nn_queue_create(dns_json, &dns_entry->nn_queue);
    if (rv) {
        fprintf(stderr, "could not allocate dns nm_queue\n");
        goto error_out;
    }
    
    fprintf(stderr, "created dns entry [%s]\n", dns_entry->name);
    return dns_entry;
    
    error_out:
    ss_dns_entry_destroy(dns_entry); dns_entry = NULL;
    return NULL;
}

int ss_dns_entry_destroy(ss_dns_entry_t* dns_entry) {
    if (!dns_entry) return 0;
    
    ss_nn_queue_destroy(&dns_entry->nn_queue);
    dns_entry->matches = 0;
    if (dns_entry->name) { je_free(dns_entry->name); dns_entry->name = NULL; }
    je_free(dns_entry);
    dns_entry = NULL;
    
    return 0;
}

int ss_dns_chain_add(ss_dns_entry_t* dns_entry) {
    TAILQ_INSERT_TAIL(&ss_conf->dns_chain.dns_list, dns_entry, entry);
    return 0;
}

int ss_dns_chain_remove_index(int index) {
    int counter = 0;
    ss_dns_entry_t* dptr;
    ss_dns_entry_t* dtmp;
    TAILQ_FOREACH_SAFE(dptr, &ss_conf->dns_chain.dns_list, entry, dtmp) {
        if (counter == index) {
            TAILQ_REMOVE(&ss_conf->dns_chain.dns_list, dptr, entry);
            return 0;
        }
        ++counter;
    }
    return -1;
}

int ss_dns_chain_remove_name(char* name) {
    ss_dns_entry_t* dptr;
    ss_dns_entry_t* dtmp;
    TAILQ_FOREACH_SAFE(dptr, &ss_conf->dns_chain.dns_list, entry, dtmp) {
        if (!strcasecmp(name, dptr->name)) {
            TAILQ_REMOVE(&ss_conf->dns_chain.dns_list, dptr, entry);
            return 0;
        }
    }
    return -1;
}

/* CIDR TABLE */

ss_cidr_table_t* ss_cidr_table_create(json_object* cidr_json) {
    ss_cidr_table_t* cidr_table = NULL;
    
    struct rte_lpm6_config lpm6_info = {
        .max_rules    = SS_LPM_RULE_MAX,
        .number_tbl8s = SS_LPM_TBL8S_MAX,
        .flags        = 0,
    };
    
    cidr_table = je_calloc(1, sizeof(ss_cidr_table_t));
    if (cidr_table == NULL) {
        fprintf(stderr, "could not allocate cidr table\n");
        goto error_out;
    }
    
    cidr_table->cidr4 = rte_lpm_create("cidr4", 0, SS_LPM_RULE_MAX, 0);
    cidr_table->cidr6 = rte_lpm6_create("cidr6", 0, &lpm6_info);
    
    return cidr_table;
    
    error_out:
    ss_cidr_table_destroy(cidr_table); cidr_table = NULL;
    return NULL;
}

int ss_cidr_table_destroy(ss_cidr_table_t* cidr_table) {
    ss_cidr_entry_t* cptr;
    ss_cidr_entry_t* ctmp;
    
    if (!cidr_table) return 0;
    
    if (cidr_table->hash4) {
        HASH_ITER(hh, cidr_table->hash4, cptr, ctmp) {
            HASH_DEL(cidr_table->hash4, cptr);
            if (cptr) ss_cidr_entry_destroy(cptr);
        }
    }
    if (cidr_table->hash6) {
        HASH_ITER(hh, cidr_table->hash6, cptr, ctmp) {
            HASH_DEL(cidr_table->hash6, cptr);
            if (cptr) ss_cidr_entry_destroy(cptr);
        }
    }
    
    if (cidr_table->cidr4) {
        rte_lpm_delete_all(cidr_table->cidr4);
    }
    if (cidr_table->cidr6) {
        rte_lpm6_delete_all(cidr_table->cidr6);
    }
    
    return 0;
}

ss_cidr_entry_t* ss_cidr_entry_create(json_object* cidr_json) {
    ss_cidr_entry_t* cidr_entry = NULL;
    
    cidr_entry = je_calloc(1, sizeof(ss_cidr_entry_t));
    if (cidr_entry == NULL) {
        fprintf(stderr, "could not allocate cidr entry\n");
        goto error_out;
    }
    
    cidr_entry->name = ss_json_string_get(cidr_json, "name");
    if (cidr_entry->name == NULL) {
        fprintf(stderr, "pcap_entry name is null\n");
        goto error_out;
    }
    
    error_out:
    ss_cidr_entry_destroy(cidr_entry); cidr_entry = NULL;
    return NULL;
}

int ss_cidr_entry_destroy(ss_cidr_entry_t* cidr_entry) {
    if (!cidr_entry) return 0;
    
    ss_nn_queue_destroy(&cidr_entry->nn_queue);
    cidr_entry->matches = -1;
    if (cidr_entry->name) { je_free(cidr_entry->name); cidr_entry->name = NULL; }
    je_free(cidr_entry);
    
    return 0;
}

int ss_cidr_table_add(ss_cidr_table_t* cidr_table, ss_cidr_entry_t* cidr_entry) {
    return 0;
}

int ss_cidr_table_remove(ss_cidr_table_t* cidr_table, char* cidr) {
    return 0;
}
