#include "common.h"

/* RE CHAIN */

ss_re_chain_t* ss_re_chain_create() {
    return NULL;
}

int ss_re_chain_destroy(ss_re_chain_t* re_chain) {
    return 0;
}
 
int ss_re_chain_add(ss_re_chain_t* re_chain, char* re) {
    return 0;
}
 
int ss_re_chain_remove_index(ss_re_chain_t* re_chain, int index) {
    return 0;
}

int ss_re_chain_remove_re(ss_re_chain_t* re_chain, char* re) {
    return 0;
}

int ss_re_chain_match(ss_re_chain_t* re_chain, char* input) {
    return 0;
}

/* PCAP CHAIN */

ss_pcap_match_t* ss_pcap_match_create() {
    return NULL;
}

int ss_pcap_match_destroy(ss_pcap_match_t* pcap_match) {
    return 0;
}

ss_pcap_chain_t* ss_pcap_chain_create() {
    return NULL;
}

int ss_pcap_chain_destroy(ss_pcap_chain_t* pcap_chain) {
    return 0;
}

int ss_pcap_chain_add(ss_pcap_chain_t* pcap_match, char* filter) {
    return 0;
}

int ss_pcap_chain_remove_index(ss_pcap_chain_t* pcap_match, int index) {
    return 0;
}

int ss_pcap_chain_remove_filter(ss_pcap_chain_t* pcap_match, char* filter) {
    return 0;
}

int ss_pcap_match_init(ss_pcap_match_t* pcap_match, struct timeval* time, uint8_t* input, unsigned int length) {
    pcap_match->pcap_header.ts.tv_sec  = time->tv_sec;
    pcap_match->pcap_header.ts.tv_usec = time->tv_usec;
    pcap_match->pcap_header.caplen     = length;
    pcap_match->pcap_header.len        = length;
    pcap_match->packet                 = input;
    return 0;
}

int ss_pcap_match(ss_pcap_chain_t* pcap_chain, ss_pcap_match_t* pcap_match) {
    return 0;
}

/* CIDR TABLE */

ss_cidr_table_t* ss_cidr_table_create() {
    return NULL;
}

int ss_cidr_table_destroy(ss_cidr_table_t* cidr_table) {
    return 0;
}

int ss_cidr_table_add(ss_cidr_table_t* cidr_table, char* cidr) {
    return 0;
}

int ss_cidr_table_remove(ss_cidr_table_t* cidr_table, char* cidr) {
    return 0;
}
