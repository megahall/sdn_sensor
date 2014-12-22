#define _GNU_SOURCE /* strcasestr */

#include <string.h>

#include <bsd/string.h>
#include <bsd/sys/queue.h>

#include <rte_memory.h>

#include "extractor.h"

#include "common.h"
#include "ioc.h"
#include "metadata.h"
#include "sdn_sensor.h"

// NOTE: this stuff comes from spcdns
#include "dns.h"
#include "mappings.h"

/*
 * Ethernet frame extractor function
 * Match raw traffic against pcap_chain
 * Relay matches to appropriate nm_queue
 */
int ss_extract_eth(ss_frame_t* fbuf) {
    int rv;
    ss_pcap_entry_t* pptr;
    ss_pcap_entry_t* ptmp;
    ss_ioc_entry_t* iptr;
    uint8_t* metadata;
    int mlength;
    ss_pcap_match_t match;
    
    rv = ss_pcap_match_prepare(&match, rte_pktmbuf_mtod(fbuf->mbuf, uint8_t*), rte_pktmbuf_pkt_len(fbuf->mbuf));
    if (rv) {
        RTE_LOG(ERR, EXTRACTOR, "pcap match prepare, rv %d\n", rv);
        goto error_out;
    }
    
    TAILQ_FOREACH_SAFE(pptr, &ss_conf->pcap_chain.pcap_list, entry, ptmp) {
        RTE_LOG(DEBUG, EXTRACTOR, "attempt match port %u frame direction %d against pcap rule %s\n",
            fbuf->data.port_id, fbuf->data.direction, pptr->name);
        rv = ss_pcap_match(pptr, &match);
        if (rv > 0) {
            // match
            RTE_LOG(INFO, EXTRACTOR, "successful match against pcap rule %s\n", pptr->name);
            metadata = ss_metadata_prepare_frame("pcap", pptr->name, &pptr->nn_queue, fbuf, NULL);
            // XXX: for now assume the output is C char*
            mlength = strlen((char*) metadata);
            //printf("metadata: %s\n", metadata);
            rv = ss_nn_queue_send(&pptr->nn_queue, metadata, mlength);
        }
        else if (rv == 0) {
            // no match
            RTE_LOG(DEBUG, EXTRACTOR, "failed match against pcap rule %s\n", pptr->name);
        }
        else {
            // error
            RTE_LOG(ERR, EXTRACTOR, "pcap match returned error %d\n", rv);
        }
    }
    
    iptr = ss_ioc_metadata_match(&fbuf->data);
    if (iptr) {
        // match
        RTE_LOG(NOTICE, EXTRACTOR, "successful ioc match from frame\n");
        ss_ioc_entry_dump_dpdk(iptr);
        nn_queue_t* nn_queue = &ss_conf->ioc_files[iptr->file_id].nn_queue;
        // XXX: figure out what to put into "rule" field
        metadata = ss_metadata_prepare_frame("frame_ioc", NULL, nn_queue, fbuf, iptr);
        // XXX: for now assume the output is C char*
        mlength = strlen((char*) metadata);
        //printf("metadata: %s\n", metadata);
        rv = ss_nn_queue_send(nn_queue, metadata, mlength);
    }
    
    return 0;
    
    error_out:
    RTE_LOG(ERR, EXTRACTOR, "match error port %u frame direction %d\n", fbuf->data.port_id, fbuf->data.direction);
    return -1;
}

int ss_extract_dns(ss_frame_t* fbuf) {
    ss_dns_entry_t* dptr;
    ss_dns_entry_t* dtmp;
    ss_ioc_entry_t* iptr;
    int rv;
    uint8_t* metadata;
    int mlength;
    
    dns_decoded_t   dns_info[DNS_DECODEBUF_4K];
    dns_query_t*    dns_query;
    dns_question_t* dns_question;
    dns_answer_t*   dns_answer;
    ss_answer_t*    ss_answer;
    enum dns_rcode  dns_rv;
    size_t          dns_info_size = sizeof(dns_info);
    
    RTE_LOG(INFO, EXTRACTOR, "decode udp dns packet\n");
    dns_rv = dns_decode(dns_info, &dns_info_size, (dns_packet_t *) fbuf->l4_offset, fbuf->data.l4_length);
    if (dns_rv != RCODE_OKAY) {
        RTE_LOG(ERR, EXTRACTOR, "could not decode udp dns packet\n");
        rte_pktmbuf_dump(stderr, fbuf->mbuf, rte_pktmbuf_pkt_len(fbuf->mbuf));
        return -1;
    }
    dns_query    = (dns_query_t*) dns_info;
    dns_question = &dns_query->questions[0];
    if (dns_question == NULL) {
        RTE_LOG(ERR, EXTRACTOR, "dns question missing in query\n");
        return -1;
    }
    
    RTE_LOG(INFO, EXTRACTOR, "rx dns query for name [%s] type [%s] class [%s]\n",
        dns_question->name, dns_type_text(dns_question->type), dns_class_text(dns_question->class));
    strlcpy((char*) &fbuf->data.dns_name, dns_question->name, SS_DNS_NAME_MAX);
    int ancount = dns_query->ancount;
    if (ancount > SS_DNS_RESULT_MAX) ancount = SS_DNS_RESULT_MAX;
    for (int i = 0; i < ancount; ++i) {
        dns_answer = &dns_query->answers[i];
        rv = ss_extract_dns_atype(&fbuf->data.dns_answers[i], dns_answer);
        if (rv) {
            RTE_LOG(ERR, EXTRACTOR, "rx dns query decode failure for name [%s] answer index [%zd]\n",
                dns_question->name, i);
        }
    }
    
    TAILQ_FOREACH_SAFE(dptr, &ss_conf->dns_chain.dns_list, entry, dtmp) {
        int is_match = 0;
        if (dptr->dns[0] && strcasestr(dns_question->name, dptr->dns)) {
            is_match = 1; goto done;
        }
        for (int i = 0; i < ancount; ++i) {
            ss_answer = &fbuf->data.dns_answers[i];
            switch (ss_answer->type) {
                case SS_TYPE_NAME: {
                    if (dptr->dns[0] && strcasestr((char*) ss_answer->payload, dptr->dns)) {
                        is_match = 1; goto done;
                    }
                    break;
                }
                case SS_TYPE_IP: {
                    if (dptr->ip.family && !memcmp(ss_answer->payload, &dptr->ip, sizeof(ip_addr_t))) {
                        is_match = 1; goto done;
                    }
                    break;
                }
                default: {
                    if (ss_answer->type != SS_TYPE_EMPTY)
                        RTE_LOG(ERR, EXTRACTOR, "unknown ss_answer type %d\n", ss_answer->type);
                    continue;
                }
            }
        }
        done:
        if (!is_match) continue;
        RTE_LOG(NOTICE, EXTRACTOR, "successful match against dns rule %s\n", pptr->name);
        metadata = ss_metadata_prepare_frame("dns_rule", &pptr->nn_queue, fbuf, NULL);
        // XXX: for now assume the output is C string
        mlength = strlen((char*) metadata);
        //printf("metadata: %s\n", metadata);
        rv = ss_nn_queue_send(&pptr->nn_queue, metadata, mlength);
    }

    iptr = ss_ioc_dns_match(&fbuf->data);
    if (iptr) {
        // match
        RTE_LOG(NOTICE, EXTRACTOR, "successful ioc match from dns frame\n");
        ss_ioc_entry_dump_dpdk(iptr);
        nn_queue_t* nn_queue = &ss_conf->ioc_files[iptr->file_id].nn_queue;
        metadata = ss_metadata_prepare_frame("dns_ioc", nn_queue, fbuf, iptr);
        // XXX: for now assume the output is C char*
        mlength = strlen((char*) metadata);
        //printf("metadata: %s\n", metadata);
        rv = ss_nn_queue_send(nn_queue, metadata, mlength);
    }
    
    return 0;
}

int ss_extract_dns_atype(ss_answer_t* result, dns_answer_t* aptr) {
    char*        name  = (char*) result->payload;
    ip_addr_t*   ip    = (ip_addr_t*) result->payload;
    
    result->type = SS_TYPE_EMPTY;
    
    switch(aptr->generic.type) {
        case RR_NS: {
            result->type = SS_TYPE_NAME;
            strlcpy(name, aptr->ns.nsdname, sizeof(result->payload));
            break;
        }
        case RR_A: {
            result->type = SS_TYPE_IP;
            ip->family   = SS_AF_INET4;
            ip->prefix   = 32;
            ip->ip4_addr.addr = aptr->a.address;
            break;
        }
        case RR_AAAA: {
            result->type = SS_TYPE_IP;
            ip->family   = SS_AF_INET6;
            ip->prefix   = 128;
            rte_memcpy(ip->ip6_addr.addr, &aptr->aaaa.address, sizeof(ip->ip6_addr.addr));
            break;
        }
        case RR_CNAME: {
            result->type = SS_TYPE_NAME;
            strlcpy(name, aptr->cname.cname, sizeof(result->payload));
            break;
        }
        case RR_MX: {
            result->type = SS_TYPE_NAME;
            strlcpy(name, aptr->mx.exchange, sizeof(result->payload));
            break;
        }
        case RR_PTR: {
            result->type = SS_TYPE_NAME;
            strlcpy(name, aptr->ptr.ptr, sizeof(result->payload));
            break;
        }
        default: {
            fprintf(stderr, "unknown dns answer type %d\n", aptr->generic.type);
            memset(result, 0, sizeof(ss_answer_t));
            break;
        }
    }
    
    error_out:
    return -1;
}

int ss_extract_syslog(ss_frame_t* fbuf) {
    uint8_t* match_string;
    uint8_t* metadata = NULL;
    int mlength = 0;
    int rv = 0;
    ss_re_match_t re_match;
    
    memset(&re_match, 0, sizeof(re_match));
    
    // exit if the syslog packet was not sent to us
    SS_CHECK_SELF(fbuf, rv);
    
    // place a zero byte at the end of the log message to form a C string
    match_string = (uint8_t*) rte_pktmbuf_append(fbuf->mbuf, 1);
    if (match_string == NULL) {
        RTE_LOG(ERR, EXTRACTOR, "could not append zero byte to syslog message\n");
        return -1;
    }
    *match_string = 0;
    
    RTE_LOG(INFO, EXTRACTOR, "attempt syslog match port %u frame direction %d payload length %hu content %s\n",
        fbuf->data.port_id, fbuf->data.direction,
        fbuf->data.l4_length, (char*) fbuf->l4_offset);
        
    rv = ss_re_chain_match(&re_match, fbuf->l4_offset, fbuf->data.l4_length);
    if (rv <= 0 || re_match.re_entry == NULL) {
        RTE_LOG(DEBUG, EXTRACTOR, "no match against syslog rule %s\n", re_match.re_entry->name);
        return 0;
    }
    
    if (re_match.re_entry->type == SS_RE_TYPE_COMPLETE) {
        // include length of null byte
        metadata = ss_metadata_prepare_syslog("udp_syslog", &re_match.re_entry->nn_queue, fbuf, NULL);
    }
    else if (re_match.re_entry->type == SS_RE_TYPE_SUBSTRING) {
        ss_ioc_entry_dump_dpdk(re_match.ioc_entry);
        // include length of null byte
        metadata = ss_metadata_prepare_syslog("udp_syslog", &re_match.re_entry->nn_queue, fbuf, re_match.ioc_entry);
    }
    
    if (metadata) {
        // XXX: for now assume the output is C char*
        mlength = strlen((char*) metadata);
        rv = ss_nn_queue_send(&re_match.re_entry->nn_queue, metadata, mlength);
    }
    else {
        RTE_LOG(ERR, EXTRACTOR, "unexpected state matching against syslog rule %s\n", re_match.re_entry->name);
        rv = -1;
    }
    
    return rv;
}
