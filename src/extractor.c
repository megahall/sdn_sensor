#include <string.h>

#include <bsd/string.h>
#include <bsd/sys/queue.h>

#include "common.h"
#include "sdn_sensor.h"

#include "dns.h"
#include "mappings.h" // NOTE: comes from spcdns

/*
 * Ethernet frame extractor function
 * Match raw traffic against pcap_chain
 * Relay matches to appropriate nm_queue
 */
int ss_extract_eth(ss_frame_t* fbuf) {
    ss_pcap_entry_t* pptr;
    ss_pcap_entry_t* ptmp;
    int rv;
    uint8_t* metadata;
    int mlength;
    ss_pcap_match_t match;
    
    rv = ss_pcap_match_prepare(&match, rte_pktmbuf_mtod(fbuf->mbuf, uint8_t*), rte_pktmbuf_pkt_len(fbuf->mbuf));
    if (rv) {
        RTE_LOG(ERR, SS, "pcap match prepare, rv %d\n", rv);
        goto error_out;
    }
    
    TAILQ_FOREACH_SAFE(pptr, &ss_conf->pcap_chain.pcap_list, entry, ptmp) {
        RTE_LOG(DEBUG, SS, "attempt match port %u frame direction %d against pcap rule %s\n",
            fbuf->data.port_id, fbuf->data.direction, pptr->name);
        rv = ss_pcap_match(pptr, &match);
        if (rv > 0) {
            // match
            RTE_LOG(INFO, SS, "successful match against pcap rule %s\n", pptr->name);
            metadata = ss_nn_queue_prepare_metadata("ethernet", &pptr->nn_queue, fbuf);
            // XXX: for now assume the output is C char*
            mlength = strlen((char*) metadata);
            //printf("metadata: %s\n", metadata);
            rv = ss_nn_queue_send(&pptr->nn_queue, metadata, mlength);
        }
        else if (rv == 0) {
            // no match
            RTE_LOG(DEBUG, SS, "failed match against pcap rule %s\n", pptr->name);
        }
        else {
            // error
            RTE_LOG(ERR, SS, "pcap match returned error %d\n", rv);
        }
    }
    
    return 0;
    
    error_out:
    RTE_LOG(ERR, SS, "match error port %u frame direction %d\n", fbuf->data.port_id, fbuf->data.direction);
    return -1;
}

int ss_extract_dns(ss_frame_t* fbuf) {
    ss_dns_entry_t* pptr;
    ss_dns_entry_t* ptmp;
    int rv;
    uint8_t* metadata;
    int mlength;
    
    dns_decoded_t   dns_info[DNS_DECODEBUF_4K];
    dns_query_t*    dns_query;
    dns_question_t* dns_question;
    enum dns_rcode  dns_rv;
    size_t          dns_info_size = sizeof(dns_info);
    
    RTE_LOG(INFO, SS, "decode udp dns packet\n");
    dns_rv = dns_decode(dns_info, &dns_info_size, (dns_packet_t *) ((uint8_t*) fbuf->udp + sizeof(udp_hdr_t)), fbuf->data.l4_length);
    if (dns_rv != RCODE_OKAY) {
        RTE_LOG(ERR, SS, "could not decode udp dns packet\n");
        rte_pktmbuf_dump(stderr, fbuf->mbuf, rte_pktmbuf_pkt_len(fbuf->mbuf));
        return -1;
    }
    dns_query    = (dns_query_t*) dns_info;
    dns_question = &dns_query->questions[0];
    if (dns_question == NULL) {
        RTE_LOG(ERR, SS, "dns question missing in query\n");
        return -1;
    }
    RTE_LOG(INFO, SS, "rx dns query for name [%s] type [%s] class [%s]\n",
        dns_question->name, dns_type_text(dns_question->type), dns_class_text(dns_question->class));
    
    strlcpy((char*) &fbuf->data.dns_name, dns_question->name, SS_DNS_NAME_MAX);
    
    TAILQ_FOREACH_SAFE(pptr, &ss_conf->dns_chain.dns_list, entry, ptmp) {
        RTE_LOG(INFO, SS, "successful match against dns rule %s\n", pptr->name);
        metadata = ss_nn_queue_prepare_metadata("dns", &pptr->nn_queue, fbuf);
        // XXX: for now assume the output is C char*
        mlength = strlen((char*) metadata);
        //printf("metadata: %s\n", metadata);
        rv = ss_nn_queue_send(&pptr->nn_queue, metadata, mlength);
    }
    
    return 0;
}
