#include <string.h>

#include <bsd/sys/queue.h>

#include "common.h"
#include "sdn_sensor.h"

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
        RTE_LOG(INFO, SS, "match port %u frame direction %d against pcap rule %s\n",
            fbuf->data.port_id, fbuf->data.direction, pptr->name);
        rv = ss_pcap_match(pptr, &match);
        if (rv > 0) {
            // match
            RTE_LOG(INFO, SS, "frame matched against pcap rule %s\n", pptr->name);
            metadata = ss_nn_queue_prepare_pcap(&pptr->nn_queue, fbuf);
            // XXX: for now assume the output is C char*
            mlength = strlen((char*) metadata);
            rv = ss_nn_queue_send(&pptr->nn_queue, metadata, mlength);
        }
        else if (rv == 0) {
            // no match
            RTE_LOG(INFO, SS, "frame not matched against pcap rule %s\n", pptr->name);
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

int ss_extract_arp(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_ndp(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_ip4(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_ip6(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_icmp4(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_icmp6(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_echo4(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_echo6(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_tcp4(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_tcp6(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_udp4(ss_frame_t* fbuf) {
    return 0;
}

int ss_extract_udp6(ss_frame_t* fbuf) {
    return 0;
}
