#define _GNU_SOURCE /* strcasestr */

#include <string.h>

#include <bsd/string.h>
#include <bsd/sys/queue.h>

#include <pcre.h>

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
            metadata = ss_metadata_prepare_frame("pcap", &pptr->nn_queue, fbuf, NULL);
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
        metadata = ss_metadata_prepare_frame("frame_ioc", nn_queue, fbuf, iptr);
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
    ss_dns_entry_t* pptr;
    ss_dns_entry_t* ptmp;
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
    size_t ancount = dns_query->ancount;
    if (ancount > SS_DNS_RESULT_MAX) ancount = SS_DNS_RESULT_MAX;
    for (size_t i = 0; i < ancount; ++i) {
        dns_answer = &dns_query->answers[i];
        rv = ss_extract_dns_atype(&fbuf->data.dns_answers[i], dns_answer);
        if (rv) {
            RTE_LOG(ERR, EXTRACTOR, "rx dns query decode failure for name [%s] answer index [%zd]\n",
                dns_question->name, i);
        }
    }
    
    TAILQ_FOREACH_SAFE(pptr, &ss_conf->dns_chain.dns_list, entry, ptmp) {
        int is_match = 0;
        if (pptr->dns[0] && strcasestr(dns_question->name, pptr->dns)) {
            is_match = 1; goto done;
        }
        for (int i = 0; i < SS_DNS_RESULT_MAX; ++i) {
            ss_answer = &fbuf->data.dns_answers[i];
            switch (ss_answer->type) {
                case SS_TYPE_NAME: {
                    if (pptr->dns[0] && strcasestr((char*) ss_answer->payload, pptr->dns)) {
                        is_match = 1; goto done;
                    }
                }
                case SS_TYPE_IP: {
                    if (pptr->ip.family && !memcmp(ss_answer->payload, &pptr->ip, sizeof(ip_addr_t))) {
                        is_match = 1; goto done;
                    }
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
    ss_re_entry_t* rptr;
    ss_re_entry_t* rtmp;
    
    int rv = 0;
    
    // exit if the syslog packet was not sent to us
    SS_CHECK_SELF(fbuf, rv);
    
    // place a zero byte at the end of the log message to form a C string
    match_string  = (uint8_t*) rte_pktmbuf_append(fbuf->mbuf, 1);
    if (match_string == NULL) {
        RTE_LOG(ERR, EXTRACTOR, "could not append zero byte to syslog message\n");
        return -1;
    }
    *match_string = 0;
    
    RTE_LOG(INFO, EXTRACTOR, "attempt syslog match port %u frame direction %d payload length %hu content %s\n",
        fbuf->data.port_id, fbuf->data.direction,
        fbuf->data.l4_length, (char*) fbuf->l4_offset);
    
    TAILQ_FOREACH_SAFE(rptr, &ss_conf->re_chain.re_list, entry, rtmp) {
        RTE_LOG(DEBUG, EXTRACTOR, "attempt re match type %d against syslog rule %s\n",
            rptr->type, rptr->name);
        if (rptr->type == SS_RE_TYPE_COMPLETE) {
            ss_extract_syslog_complete(fbuf, rptr);
        }
        else if (rptr->type == SS_RE_TYPE_SUBSTRING) {
            ss_extract_syslog_substring(fbuf, rptr);
        }
        else {
            RTE_LOG(ERR, EXTRACTOR, "unknown re_type %d\n", rptr->type);
            return -1;
        }
    }
    
    return 0;
}

int ss_extract_syslog_complete(ss_frame_t* fbuf, ss_re_entry_t* rptr) {
    int match_count;
    int match_vector[(0 + 1) * 3];
    uint8_t* metadata;
    int mlength;
    int rv;
        
    match_count = pcre_exec(rptr->re, rptr->re_extra,
                            (char*) fbuf->l4_offset, fbuf->data.l4_length,
                            0, PCRE_NEWLINE_ANYCRLF,
                            match_vector, (0 + 1) * 3);
    
    // flip around match logic if invert flag is set
    if (rptr->inverted) {
        if      (match_count > 0)                   match_count = PCRE_ERROR_NOMATCH;
        else if (match_count == PCRE_ERROR_NOMATCH) match_count = 1;
    }
    
    if (match_count < 0 && match_count != PCRE_ERROR_NOMATCH) {
        RTE_LOG(ERR, EXTRACTOR, "failed complete match error %s against syslog rule %s\n",
            ss_pcre_strerror(match_count), rptr->name);
    }
    else if (match_count == PCRE_ERROR_NOMATCH) {
        RTE_LOG(DEBUG, EXTRACTOR, "no match against syslog rule %s\n", rptr->name);
    }
    else {
        RTE_LOG(NOTICE, EXTRACTOR, "successful complete match for syslog rule %s\n", rptr->name);
        // include length of null byte
        metadata = ss_metadata_prepare_syslog("udp_syslog", &rptr->nn_queue, fbuf, NULL, fbuf->l4_offset, fbuf->data.l4_length + 1);
        // XXX: for now assume the output is C char*
        mlength = strlen((char*) metadata);
        rv = ss_nn_queue_send(&rptr->nn_queue, metadata, mlength);
    }
    
    return 0;
}

int ss_extract_syslog_substring(ss_frame_t* fbuf, ss_re_entry_t* rptr) {
    int match_count;
    int start_point;
    int have_match;
    int match_vector[(0 + 1) * 3];
    uint8_t* match_string;
    ss_ioc_entry_t* iptr;
    uint8_t* metadata;
    int mlength;
    int rv;
    
    pcre_assign_jit_stack(rptr->re_extra, NULL, NULL);
        
    start_point = 0;
    have_match  = 0;
    do {
        match_count = pcre_exec(rptr->re, rptr->re_extra,
                                (char*) fbuf->l4_offset, fbuf->data.l4_length,
                                start_point, PCRE_NEWLINE_ANYCRLF,
                                match_vector, (0 + 1) * 3);
        
        if (match_count == 0 || match_count == PCRE_ERROR_NOMATCH) {
            goto end_loop;
        }
        else if (match_count < 0) {
            RTE_LOG(ERR, EXTRACTOR, "failed substring match error %s against syslog rule %s\n",
                ss_pcre_strerror(match_count), rptr->name);
        }
        
        if (pcre_get_substring((char*) fbuf->l4_offset,
                               match_vector, match_count,
                               0, (const char**) &match_string) >= 0) {
            RTE_LOG(DEBUG, EXTRACTOR, "attempt ioc match against substring %s\n",
                match_string);
            iptr = ss_ioc_syslog_match((char*) match_string, rptr->ioc_type);
            if (iptr) {
                have_match = 1;
                RTE_LOG(NOTICE, EXTRACTOR, "successful ioc match for syslog rule %s against substring %s\n",
                    rptr->name, match_string);
            }
            pcre_free_substring((char*) match_string);
        }
        
        start_point = match_vector[1];
    } while (match_count > 0 && start_point < fbuf->data.l4_length && !have_match);
    
    end_loop:
    if (have_match) {
        RTE_LOG(NOTICE, EXTRACTOR, "successful substring ioc match for syslog rule %s\n", rptr->name);
        ss_ioc_entry_dump_dpdk(iptr);
        // include length of null byte
        metadata = ss_metadata_prepare_syslog("udp_syslog", &rptr->nn_queue, fbuf, iptr, fbuf->l4_offset, fbuf->data.l4_length + 1);
        // XXX: for now assume the output is C char*
        mlength = strlen((char*) metadata);
        rv = ss_nn_queue_send(&rptr->nn_queue, metadata, mlength);
    }
    else {
        // no match
        RTE_LOG(DEBUG, EXTRACTOR, "failed match against syslog rule %s\n", rptr->name);
    }
    
    return 0;
}
