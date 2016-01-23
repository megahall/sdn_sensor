// Copyright (c) 2002-2011 InMon Corp.
// Licensed under the terms of the InMon sFlow license.
// http://www.inmon.com/technology/sflowlicense.txt

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <rte_hexdump.h>
#include <rte_log.h>

#include "common.h"
#include "sflow.h"
#include "sflow_cb.h"
#include "sflow_utils.h"

#define NFT_ETHHDR_SIZE 14
#define NFT_MAX_8023_LEN 1500
#define NFT_MIN_SIZE (NFT_ETHHDR_SIZE + sizeof(ip4_hdr_t))
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
#define WIFI_MIN_HDR_SIZE 24
#define SA_MAX_TUNNELNAME_LEN 100
#define SA_MAX_VCNAME_LEN 100
#define SA_MAX_FTN_LEN 100
#define ENC_KEY_BYTES (SFLOW_MAX_MEMCACHE_KEY * 3) + 1

#define SNAP_LLC_SIZE 3
#define SNAP_LLC_0 0xAA
#define SNAP_LLC_1 0xAA
#define SNAP_LLC_2 0x03

#define SFLOW_VERSION_5 5

sflow_sample_cb_t sflow_sample_cb = NULL;

void sflow_decode_link_layer(sflow_sample_t* sample) {
    uint8_t* start = (uint8_t*) sample->header.bytes;
    uint8_t* end = start + sample->header.header_size;
    uint8_t* ptr = start;
    uint16_t type_len;

    // assume not found
    sample->is_ipv4 = false;
    sample->is_ipv6 = false;

    if (sample->header.header_size < NFT_ETHHDR_SIZE) {
        // XXX: not enough for an Ethernet header
        return;
    }

    memcpy(sample->dst_eth, ptr, ETHER_ALEN);
    ptr += sizeof(sample->dst_eth);

    memcpy(sample->src_eth, ptr, ETHER_ALEN);
    ptr += sizeof(sample->src_eth);
    type_len = (uint16_t) (ptr[0] << 8) + ptr[1];
    ptr += sizeof(uint16_t);

    if (type_len == ETHER_TYPE_VLAN) {
        // VLAN: next two bytes
        uint32_t vlan_data = (uint32_t) (ptr[0] << 8) + ptr[1];
        uint32_t vlan = vlan_data & 0x0fff;
        uint32_t priority = vlan_data >> 13;
        ptr += sizeof(uint16_t);
        // _______________________________________
        // |   pri  | c |         vlan-id        |
        // ---------------------------------------
        // [priority = 3bits]
        // [Canonical Format Flag = 1bit]
        // [vlan-id = 12 bits]
        sample->rx_vlan = vlan;
        sample->rx_priority = priority;
        // now get the type_len again (next two bytes)
        type_len = (uint16_t) (ptr[0] << 8) + ptr[1];
        ptr += sizeof(uint16_t);
    }

    // now we're just looking for IP
    if (sample->header.header_size < NFT_MIN_SIZE) {
        // XXX: not enough for an IPv4 header
        return;
    }

    // peek for IPX
    if (type_len == ETHER_TYPE_PUP_1 || type_len == ETHER_TYPE_PUP_2 || type_len == ETHER_TYPE_MIN) {
        int ipx_checksum = (ptr[0] == 0xff && ptr[1] == 0xff);
        int ipx_len = (ptr[2] << 8) + ptr[3];
        if (ipx_checksum &&
                ipx_len >= IPX_HDR_LEN &&
                ipx_len <= (IPX_HDR_LEN + IPX_MAX_DATA))
            // XXX: we don't do anything with IPX here
            return;
    }

    if (type_len <= NFT_MAX_8023_LEN) {
        // assume 802.3+802.2 header
        // check for SNAP
        if (ptr[0] == SNAP_LLC_0 && ptr[1] == SNAP_LLC_1 && ptr[2] == SNAP_LLC_2) {
            ptr += SNAP_LLC_SIZE; // XXX fixup
            if (ptr[0] != 0 ||
                    ptr[1] != 0 ||
                    ptr[2] != 0) {
                sflow_log(sample, "VSNAP_OUI %02X-%02X-%02X\n", ptr[0], ptr[1], ptr[2]);
                // XXX: no further decode for vendor-specific protocol
                return;
            }
            ptr += SNAP_LLC_SIZE;
            // OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895)
            type_len = (uint16_t) (ptr[0] << 8) + ptr[1];
            ptr += sizeof(uint16_t);
        }
        else {
            // XXX: figure out what this is and make constants
            if (ptr[0] == 0x06 &&
                    ptr[1] == 0x06 &&
                    (ptr[2] & 0x01)) {
                // IP over 802.2
                ptr += 3;
                // force the type_len to be IP so we can inline the IP decode below
                type_len = ETHER_TYPE_IPV4;
            }
            else return;
        }
    }

    // assume type_len is an EtherType now
    sample->eth_type = type_len;

    if (type_len == ETHER_TYPE_IPV4) {
        // IPV4
        if ((end - ptr) < (long) sizeof(ip4_hdr_t)) {
            // XXX: ran out of bytes
            return;
        }
        // look at first byte of header
        // _____________________________
        // |   version   |    hdrlen   |
        // -----------------------------
        if ((*ptr >> 4) != 4) {
            // XXX: not version 4
            return;
        }
        if ((*ptr & 15) < 5) {
            // XXX: not IP (header length < 20 bytes)
            return;
        }
        // survived all the tests - store the offset to the start of the ip header
        sample->is_ipv4 = true;
        sample->ipv4_offset = (size_t) (ptr - start);
    }
    else if (type_len == ETHER_TYPE_IPV6) {
        // IPV6
        // look at first byte of header
        if ((*ptr >> 4) != 6) {
            // XXX: not version 6
            return;
        }
        // XXX: other tests?
        // survived all the tests - store the offset to the start of the ip6 header
        sample->is_ipv6 = true;
        sample->ipv6_offset = (size_t) (ptr - start);
    }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
void sflow_decode_mac_80211(sflow_sample_t* sample) {
    uint8_t* start = (uint8_t*) sample->header.bytes;
    uint8_t* end = start + sample->header.header_size;
    uint8_t* ptr = start;

    // assume not found
    sample->is_ipv4 = false;
    sample->is_ipv6 = false;

    if (sample->header.header_size < WIFI_MIN_HDR_SIZE) {
        /* XXX: not enough for an 80211 MAC header */
        return;
    }

    /* [b7..b0][b15..b8] */
    uint16_t fc = (uint16_t) ((ptr[1] << 8) + ptr[0]);
    uint16_t protocol_version = fc & 3;
    uint16_t control = (fc >> 2) & 3;
    uint16_t sub_type = (fc >> 4) & 15;
    uint16_t to_ds = (fc >> 8) & 1;
    uint16_t from_ds = (fc >> 9) & 1;
    uint16_t more_frag = (fc >> 10) & 1;
    uint16_t retry = (fc >> 11) & 1;
    uint16_t pwr_mgt = (fc >> 12) & 1;
    uint16_t more_data = (fc >> 13) & 1;
    uint16_t encrypted = (fc >> 14) & 1;
    uint16_t order = fc >> 15;

    ptr += sizeof(uint16_t);

    /* not in network byte order either? */
    uint16_t duration_id = (uint16_t) ((ptr[1] << 8) + ptr[0]);
    ptr += sizeof(uint16_t);

    switch (control) {
        case 0: {
            // mgmt
            break;
        }
        case 1: {
            // ctrl
            break;
        }
        case 3: {
            // rsvd
            break;
        }
        case 2: {
            // data
            uint8_t* mac_addr_1 = ptr;
            ptr += ETHER_ALEN;
            uint8_t* mac_addr_2 = ptr;
            ptr += ETHER_ALEN;
            uint8_t* mac_addr_3 = ptr;
            ptr += ETHER_ALEN;
            uint32_t sequence = (uint32_t) ((ptr[0] << 8) + ptr[1]);
            ptr += sizeof(uint16_t);

            // ToDS   FromDS   Addr1   Addr2  Addr3   Addr4
            // 0      0        DA      SA     BSSID   N/A (ad-hoc)
            // 0      1        DA      BSSID  SA      N/A
            // 1      0        BSSID   SA     DA      N/A
            // 1      1        RA      TA     DA      SA  (wireless bridge)

            uint8_t* rx_eth = mac_addr_1;
            uint8_t* tx_eth = mac_addr_2;
            uint8_t* smac = NULL;
            uint8_t* dmac = NULL;

            if (to_ds) {
                dmac = mac_addr_3;
                if (from_ds) {
                    smac = ptr; /* macAddr4.  1,1 => (wireless bridge) */
                    ptr += 6;
                }
                else smac = mac_addr_2;  /* 1,0 */
            }
            else {
                dmac = mac_addr_1;
                if (from_ds) smac = mac_addr_3; /* 0,1 */
                else smac = mac_addr_2; /* 0,0 */
            }

            if (smac) {
                memcpy(sample->src_eth, smac, ETHER_ALEN);
            }
            if (dmac) {
                memcpy(sample->dst_eth, smac, ETHER_ALEN);
            }
            if (tx_eth) {
                memcpy(sample->tx_eth, tx_eth, ETHER_ALEN);
            }
            if (rx_eth) {
                memcpy(sample->rx_eth, rx_eth, ETHER_ALEN);
            }
        }
    }
}
#pragma clang diagnostic pop

void sflow_decode_ip_l4(sflow_sample_t* sample, uint8_t* ptr) {
    uint8_t* end = sample->header.bytes + sample->header.header_size;
    if (ptr > (end - 8)) {
        // XXX: not enough header bytes left
        return;
    }

    switch (sample->ip_protocol) {
        case IPPROTO_ICMP: {
            /* ICMP */
            icmp4_hdr_t* icmp = (icmp4_hdr_t*) ptr;
            sample->src_port = icmp->type;
            sample->dst_port = icmp->code;
            sample->payload_offset = (size_t) (ptr + sizeof(icmp) - sample->header.bytes);
            break;
        }
        case IPPROTO_TCP: {
            /* TCP */
            tcp_hdr_t* tcp = (tcp_hdr_t*) ptr;
            int header_bytes;
            sample->src_port = ntohs(tcp->th_sport);
            sample->dst_port = ntohs(tcp->th_dport);
            sample->tcp_flags = tcp->th_flags;
            header_bytes = (tcp->th_off >> 4) * 4;
            ptr += header_bytes;
            sample->payload_offset = (size_t) (ptr - sample->header.bytes);
            break;
        }
        case IPPROTO_UDP: {
            /* UDP */
            udp_hdr_t* udp = (udp_hdr_t*) ptr;
            sample->src_port = ntohs(udp->uh_sport);
            sample->dst_port = ntohs(udp->uh_dport);
            sample->udp_len = ntohs(udp->uh_ulen);
            sample->payload_offset = (size_t) (ptr + sizeof(udp) - sample->header.bytes);
            break;
        }
        default: {
            /* some other protcol */
            sample->payload_offset = (size_t) (ptr - sample->header.bytes);
            break;
        }
    }
}

void sflow_decode_ipv4(sflow_sample_t* sample) {
    if (!sample->is_ipv4) {
        // XXX
        return;
    }

    uint8_t* ptr = sample->header.bytes + sample->ipv4_offset;
    ip4_hdr_t* ip = (ip4_hdr_t*) (sample->header.bytes + sample->ipv4_offset);

    // Value copy all ip elements into sample
    sample->src_ip.type = SFLOW_ADDRESS_TYPE_IP_V4;
    sample->src_ip.ipv4.addr = ip->saddr;
    sample->dst_ip.type = SFLOW_ADDRESS_TYPE_IP_V4;
    sample->dst_ip.ipv4.addr = ip->daddr;
    sample->ip_protocol = ip->protocol;
    sample->ip_tos = ip->tos;
    sample->ip_tot_len = ntohs(ip->tot_len);
    sample->ip_ttl = ip->ttl;

    // check for fragments
    sample->ip_fragoff = ntohs(ip->frag_off) & 0x1FFF;
    if (sample->ip_fragoff == 0) {
        // advance the pointer to the next protocol layer
        // ip header_len is expressed as a number of uint32_t's
        ptr += (ip->ihl & 0x0f) * 4;
        sflow_decode_ip_l4(sample, ptr);
    }
}

void sflow_decode_ipv6(sflow_sample_t* sample) {
    uint16_t payload_len;
    uint32_t label;
    uint32_t next_header;

    if (!sample->is_ipv6) {
        // XXX
        return;
    }

    uint8_t* end = sample->header.bytes + sample->header.header_size;
    uint8_t* ptr = sample->header.bytes + sample->ipv6_offset;

    /* check the version */
    int ip_version = (*ptr >> 4);
    if (ip_version != 6) {
        sflow_log(sample, "header decode error: unexpected IP version: %d\n", ip_version);
        return;
    }

    /* get the tos (priority) */
    sample->ip_tos = *ptr++ & 15;

    /* 24-bit label */
    label = *ptr++;
    label <<= 8;
    label += *ptr++;
    label <<= 8;
    label += *ptr++;
    sample->ip_label = label;

    /* payload */
    payload_len = (uint16_t) ((ptr[0] << 8) + ptr[1]);
    sample->ip_tot_len = payload_len;
    ptr += sizeof(uint16_t);

    /* next header */
    next_header = *ptr++;

    /* TTL */
    sample->ip_ttl = *ptr++;

    /* src and dst address */
    sample->src_ip.type = SFLOW_ADDRESS_TYPE_IP_V6;
    memcpy(&sample->src_ip.ipv6, ptr, IPV6_ALEN);
    ptr += IPV6_ALEN;
    sample->dst_ip.type = SFLOW_ADDRESS_TYPE_IP_V6;
    memcpy(&sample->dst_ip.ipv6, ptr, IPV6_ALEN);
    ptr += IPV6_ALEN;

    /* skip over some common header extensions...
     * http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html
     */
    while (next_header == IPPROTO_HOPOPTS ||
           next_header == IPPROTO_ROUTING ||
           next_header == IPPROTO_FRAGMENT ||
           next_header == IPPROTO_ESP ||
           next_header == IPPROTO_AH ||
           next_header == IPPROTO_DSTOPTS) {
        uint32_t option_len;
        uint32_t skip;
        sflow_log(sample, "ipv6_header_extension: %d\n", next_header);
        next_header = ptr[0];
        /* second byte gives option len in 8-byte chunks, not counting first 8 */
        option_len = 8 * (ptr[1] + 1);
        skip = option_len - 2;
        ptr += skip;
        /* ran off the end of the header */
        if (ptr > end) return;
    }

    /*
     * now that we have eliminated the extension headers, next_header
     * should have what we want to remember as the IP protocol
     */
    sample->ip_protocol = next_header;
    sflow_decode_ip_l4(sample, ptr);
}

void sflow_read_extended_switch(sflow_sample_t* sample) {
    sample->rx_vlan = sflow_get_data_32(sample);
    sample->rx_priority = sflow_get_data_32(sample);
    sample->tx_vlan = sflow_get_data_32(sample);
    sample->tx_priority = sflow_get_data_32(sample);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_SWITCH;
}

void sflow_read_extended_router(sflow_sample_t* sample) {
    sflow_parse_ip(sample, &sample->next_hop);
    sample->src_mask = sflow_get_data_32(sample);
    sample->dst_mask = sflow_get_data_32(sample);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_ROUTER;
}

void sflow_read_extended_gateway(sflow_sample_t* sample) {
    uint32_t segments;
    uint32_t seg;

    sflow_parse_ip(sample, &sample->bgp_next_hop);
    sample->my_as = sflow_get_data_32(sample);
    sample->src_as = sflow_get_data_32(sample);
    sample->src_peer_as = sflow_get_data_32(sample);
    segments = sflow_get_data_32(sample);

    // clear dst_peer_as and dst_as
    // otherwise the values might be left from another sample
    // bug found by Marc Lavine
    sample->dst_peer_as = 0;
    sample->dst_as = 0;

    // XXX: the log code here is weird
    if (segments > 0) {
        sflow_log(sample, "dst_as_path ");
        for (seg = 0; seg < segments; seg++) {
            uint32_t seg_type;
            uint32_t seg_len;
            uint32_t i;
            seg_type = sflow_get_data_32(sample);
            seg_len = sflow_get_data_32(sample);
            for (i = 0; i < seg_len; i++) {
                uint32_t as_number;
                as_number = sflow_get_data_32(sample);
                /* mark the first one as the dst_peer_as */
                if (i == 0 && seg == 0) sample->dst_peer_as = as_number;
                else printf("-");
                /* make sure the AS sets are in parentheses */
                if (i == 0 && seg_type == SFLOW_EXTENDED_AS_SET) sflow_log(sample, "(");
                sflow_log(sample, "%u", as_number);
                /* mark the last one as the dst_as */
                if (seg == (segments - 1) && i == (seg_len - 1)) sample->dst_as = as_number;
            }
            if (seg_type == SFLOW_EXTENDED_AS_SET) sflow_log(sample, ")");
        }
        sflow_log(sample, "\n");
    }
    sflow_log(sample, "dst_as %u\n", sample->dst_as);
    sflow_log(sample, "dst_peer_as %u\n", sample->dst_peer_as);

    sample->communities_len = sflow_get_data_32(sample);
    /* just point at the communities array */
    if (sample->communities_len > 0) sample->communities = sample->offset32;
    /* and skip over it in the input */
    sflow_skip_bytes(sample, sample->communities_len * 4);

    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_GATEWAY;

    // XXX: the log code here is weird
    if (sample->communities_len > 0) {
        for (uint32_t j = 0; j < sample->communities_len; j++) {
            if (j == 0) sflow_log(sample, "bgp_communities ");
            else printf("-");
            printf("%u", ntohl(sample->communities[j]));
        }
        sflow_log(sample, "\n");
    }

    sample->local_pref = sflow_get_data_32(sample);
}

void sflow_read_extended_user(sflow_sample_t* sample) {
    sample->src_user_charset = sflow_get_data_32(sample);
    sample->src_user_len = sflow_parse_string(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN);
    sample->dst_user_charset = sflow_get_data_32(sample);
    sample->dst_user_len = sflow_parse_string(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_USER;
}

void sflow_read_extended_url(sflow_sample_t* sample) {
    sample->url_direction = sflow_get_data_32(sample);
    sample->url_len = sflow_parse_string(sample, sample->url, SA_MAX_EXTENDED_URL_LEN);
    sample->host_len = sflow_parse_string(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_URL;
}

void sflow_read_mpls_label_stack(sflow_sample_t* sample, char* field_name) {
    sflow_label_stack_t label_stack;
    uint32_t label;
    label_stack.depth = sflow_get_data_32(sample);
    // just point at the label_stack array
    if (label_stack.depth > 0) label_stack.stack = (uint32_t*) sample->offset32;
    // and skip over it in the input
    sflow_skip_bytes(sample, label_stack.depth * 4);

    // XXX: the log code here is weird
    if (label_stack.depth > 0) {
        for (uint32_t j = 0; j < label_stack.depth; j++) {
            if (j == 0) sflow_log(sample, "%s ", field_name);
            else printf("-");
            label = ntohl(label_stack.stack[j]);
            sflow_log(sample, "%u.%u.%u.%u",
                    (label >> 12),     /* label */
                    (label >> 9) & 7,  /* experimental */
                    (label >> 8) & 1,  /* bottom of stack */
                    (label &  255));   /* TTL */
        }
        sflow_log(sample, "\n");
    }
}

// XXX: does not store data or map a struct
void sflow_read_extended_mpls(sflow_sample_t* sample) {
    sflow_parse_ip(sample, &sample->mpls_next_hop);
    sflow_read_mpls_label_stack(sample, "mpls_input_stack");
    sflow_read_mpls_label_stack(sample, "mpls_output_stack");
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_MPLS;
}

void sflow_read_extended_nat(sflow_sample_t* sample) {
    sflow_parse_ip(sample, &sample->nat_src_ip);
    sflow_parse_ip(sample, &sample->nat_dst_ip);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_NAT;
}

void sflow_read_extended_nat_port(sflow_sample_t* sample) {
    sample->nat_src_port = sflow_get_data_32(sample);
    sample->nat_dst_port = sflow_get_data_32(sample);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_NAT_PORT;
}

// XXX: does not store data or map a struct
void sflow_read_extended_mpls_tunnel(sflow_sample_t* sample) {
    char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
    uint32_t tunnel_id, tunnel_cos;
    if (sflow_parse_string(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN) > 0) {
        sflow_log(sample, "mpls_tunnel_lsp_name %s\n", tunnel_name);
    }
    tunnel_id = sflow_get_data_32(sample);
    sflow_log(sample, "mpls_tunnel_id %u\n", tunnel_id);
    tunnel_cos = sflow_get_data_32(sample);
    sflow_log(sample, "mpls_tunnel_cos %u\n", tunnel_cos);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

// XXX: does not store data or map a struct
void sflow_read_extended_mpls_vc(sflow_sample_t* sample) {
    char vc_name[SA_MAX_VCNAME_LEN+1];
    uint32_t vll_vc_id, vc_cos;
    if (sflow_parse_string(sample, vc_name, SA_MAX_VCNAME_LEN) > 0) {
        sflow_log(sample, "mpls_vc_name %s\n", vc_name);
    }
    vll_vc_id = sflow_get_data_32(sample);
    sflow_log(sample, "mpls_vll_vc_id %u\n", vll_vc_id);
    vc_cos = sflow_get_data_32(sample);
    sflow_log(sample, "mpls_vc_cos %u\n", vc_cos);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_MPLS_VC;
}

// XXX: does not store data or map a struct
void sflow_read_extended_mpls_ftn(sflow_sample_t* sample) {
    char ftn_descr[SA_MAX_FTN_LEN+1];
    uint32_t ftn_mask;
    if (sflow_parse_string(sample, ftn_descr, SA_MAX_FTN_LEN) > 0) {
        sflow_log(sample, "mpls_ftn_descr %s\n", ftn_descr);
    }
    ftn_mask = sflow_get_data_32(sample);
    sflow_log(sample, "mpls_ftn_mask %u\n", ftn_mask);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_MPLS_FTN;
}

// XXX: does not store data or map a struct
void sflow_read_extended_mpls_ldp_fec(sflow_sample_t* sample) {
    uint32_t fec_addr_prefix_len = sflow_get_data_32(sample);
    sflow_log(sample, "mpls_fec_addr_prefix_len %u\n", fec_addr_prefix_len);
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

// XXX: does not store data or map a struct
void sflow_read_extended_vlan_tunnel(sflow_sample_t* sample) {
    uint32_t lab;
    sflow_label_stack_t label_stack;
    label_stack.depth = sflow_get_data_32(sample);
    // just point at the label_stack array
    if (label_stack.depth > 0) label_stack.stack = (uint32_t*) sample->offset32;
    // and skip over it in the input
    sflow_skip_bytes(sample, label_stack.depth * 4);

    if (label_stack.depth > 0) {
        for (uint32_t j = 0; j < label_stack.depth; j++) {
            if (j == 0) sflow_log(sample, "vlan_tunnel ");
            else printf("-");
            lab = ntohl(label_stack.stack[j]);
            sflow_log(sample, "0x%04x.%u.%u.%u",
                    (lab >> 16),       /* TPI */
                    (lab >> 13) & 7,   /* priority */
                    (lab >> 12) & 1,   /* CFI */
                    (lab & 4095));     /* VLAN */
        }
        sflow_log(sample, "\n");
    }
    sample->extended_data_tag |= SAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

// XXX: does not store data or map a struct
void sflow_read_extended_wifi_payload(sflow_sample_t* sample) {
    sflow_log_next_32(sample, "cipher_suite");
    sflow_read_header(sample);
}

// XXX: does not store data or map a struct
void sflow_read_extended_wifi_rx(sflow_sample_t* sample) {
    uint32_t i;
    uint8_t* bssid;
    char ssid[SFLOW_MAX_SSID_LEN+1];
    if (sflow_parse_string(sample, ssid, SFLOW_MAX_SSID_LEN) > 0) {
        sflow_log(sample, "rx_SSID %s\n", ssid);
    }

    bssid = sample->offset8;
    sflow_log(sample, "rx_BSSID ");
    for (i = 0; i < 6; i++) printf("%02x", bssid[i]);
    printf("\n");
    sflow_skip_bytes(sample, 6);

    sflow_log_next_32(sample, "rx_version");
    sflow_log_next_32(sample, "rx_channel");
    sflow_log_next_64(sample, "rx_speed");
    sflow_log_next_32(sample, "rx_rsni");
    sflow_log_next_32(sample, "rx_rcpi");
    sflow_log_next_32(sample, "rx_packet_uS");
}

// XXX: does not store data or map a struct
void sflow_read_extended_wifi_tx(sflow_sample_t* sample) {
    uint32_t i;
    uint8_t* bssid;
    char ssid[SFLOW_MAX_SSID_LEN+1];
    if (sflow_parse_string(sample, ssid, SFLOW_MAX_SSID_LEN) > 0) {
        sflow_log(sample, "tx_SSID %s\n", ssid);
    }

    bssid = sample->offset8;
    sflow_log(sample, "tx_BSSID ");
    for (i = 0; i < 6; i++) printf("%02x", bssid[i]);
    printf("\n");
    sflow_skip_bytes(sample, 6);

    sflow_log_next_32(sample, "tx_version");
    sflow_log_next_32(sample, "tx_transmissions");
    sflow_log_next_32(sample, "tx_packet_uS");
    sflow_log_next_32(sample, "tx_retrans_uS");
    sflow_log_next_32(sample, "tx_channel");
    sflow_log_next_64(sample, "tx_speed");
    sflow_log_next_32(sample, "tx_power_mW");
}

void sflow_read_extended_aggregation(sflow_sample_t* sample) {
    uint32_t i, pdus = sflow_get_data_32(sample);
    sflow_log(sample, "aggregation_pdus %u\n", pdus);
    for (i = 0; i < pdus; i++) {
        sflow_log(sample, "aggregation_pdu %u\n", i);
        // not sure if this the right one here
        sflow_read_flow_sample(sample, false, i);
    }
}

void sflow_read_header(sflow_sample_t* sample) {
    sample->header.protocol = sflow_get_data_32(sample);
    sample->header.packet_size = sflow_get_data_32(sample);
    sample->header.stripped_size = sflow_get_data_32(sample);
    sample->header.header_size = sflow_get_data_32(sample);

    /* just point at the header */
    sample->header.bytes = sample->offset8;
    sflow_skip_bytes(sample, sample->header.header_size);

    if (rte_get_log_level() >= RTE_LOG_FINEST) {
        rte_hexdump(stderr, "header_bytes", sample->header.bytes, sample->header.header_size);
    }

    switch (sample->header.protocol) {
        /* the header protocol tells us where to jump into the decode */
        case SFLOW_HEADER_ISO88023_ETHERNET: {
            sflow_decode_link_layer(sample);
            break;
        }
        case SFLOW_HEADER_IPV4: {
            sample->is_ipv4 = true;
            sample->ipv4_offset = 0;
            break;
        }
        case SFLOW_HEADER_IPV6: {
            sample->is_ipv6 = true;
            sample->ipv6_offset = 0;
            break;
        }
        case SFLOW_HEADER_IEEE80211_MAC: {
            sflow_decode_mac_80211(sample);
            break;
        }
        case SFLOW_HEADER_ISO88024_TOKENBUS:
        case SFLOW_HEADER_ISO88025_TOKENRING:
        case SFLOW_HEADER_FDDI:
        case SFLOW_HEADER_FRAME_RELAY:
        case SFLOW_HEADER_X25:
        case SFLOW_HEADER_PPP:
        case SFLOW_HEADER_SMDS:
        case SFLOW_HEADER_AAL5:
        case SFLOW_HEADER_AAL5_IP:
        case SFLOW_HEADER_MPLS:
        case SFLOW_HEADER_POS:
        case SFLOW_HEADER_IEEE80211_AMPDU:
        case SFLOW_HEADER_IEEE80211_AMSDU_SUBFRAME: {
            // XXX: what to do?
            RTE_LOG(ERR, EXTRACTOR, "skip decoding obscure header protocol: %u\n", sample->header.protocol);
            break;
        }
        default: {
            RTE_LOG(ERR, EXTRACTOR, "undefined header protocol: %u\n", sample->header.protocol);
            // XXX: what to do?
            break;
        }
    }

    if (sample->is_ipv4) {
        sflow_decode_ipv4(sample);
    }
    else if (sample->is_ipv6) {
        sflow_decode_ipv6(sample);
    }
}

void sflow_read_ethernet(sflow_sample_t* sample, char* prefix) {
    sample->eth_len = sflow_get_data_32(sample);
    sample->header.packet_size = sample->eth_len;
    memcpy(sample->src_eth, sample->offset32, ETHER_ALEN);
    sflow_skip_bytes(sample, ETHER_ALEN);
    memcpy(sample->dst_eth, sample->offset32, ETHER_ALEN);
    sflow_skip_bytes(sample, ETHER_ALEN);
    sample->eth_type = sflow_get_data_32(sample);
}

void sflow_read_ipv4(sflow_sample_t* sample, char* prefix) {
    // just point at the header
    sample->header.bytes = sample->offset8;
    sample->header.header_size = sizeof(sflow_sampled_ipv4_t);
    sflow_skip_bytes(sample, sample->header.header_size);

    sflow_sampled_ipv4_t ipv4;
    memcpy(&ipv4, sample->header.bytes, sizeof(ipv4));
    sample->header.packet_size = ntohl(ipv4.len);
    sample->src_ip.type = SFLOW_ADDRESS_TYPE_IP_V4;
    sample->src_ip.ipv4 = ipv4.src_ip;
    sample->dst_ip.type = SFLOW_ADDRESS_TYPE_IP_V4;
    sample->dst_ip.ipv4 = ipv4.dst_ip;
    sample->ip_protocol = ntohl(ipv4.protocol);
    sample->ip_tos = ntohl(ipv4.tos);
    sample->src_port = ntohl(ipv4.src_port);
    sample->dst_port = ntohl(ipv4.dst_port);
    
    if (sample->ip_protocol == IPPROTO_TCP) {
        sample->tcp_flags = ntohl(ipv4.tcp_flags);
    }
}

void sflow_read_ipv6(sflow_sample_t* sample, char* prefix) {
    // just point at the header
    sample->header.bytes = sample->offset8;
    sample->header.header_size = sizeof(sflow_sampled_ipv6_t);
    sflow_skip_bytes(sample, sample->header.header_size);

    sflow_sampled_ipv6_t ipv6;
    memcpy(&ipv6, sample->header.bytes, sizeof(ipv6));
    sample->header.packet_size = ntohl(ipv6.len);
    sample->src_ip.type = SFLOW_ADDRESS_TYPE_IP_V6;
    memcpy(&sample->src_ip.ipv6, &ipv6.src_ip, IPV6_ALEN);
    sample->dst_ip.type = SFLOW_ADDRESS_TYPE_IP_V6;
    memcpy(&sample->dst_ip.ipv6, &ipv6.dst_ip, IPV6_ALEN);
    sample->ip_protocol = ntohl(ipv6.protocol);
    sample->ip_tos = ntohl(ipv6.priority);
    sample->src_port = ntohl(ipv6.src_port);
    sample->dst_port = ntohl(ipv6.dst_port);

    if (sample->ip_protocol == IPPROTO_TCP) {
        sample->tcp_flags = ntohl(ipv6.tcp_flags);
    }
}

// XXX: does not store data or map a struct
void sflow_read_memcache(sflow_sample_t* sample) {
    char key[SFLOW_MAX_MEMCACHE_KEY+1];
    char enc_key[ENC_KEY_BYTES];
    sflow_log_next_32(sample, "memcache_op_protocol");
    sflow_log_next_32(sample, "memcache_op_cmd");
    if (sflow_parse_string(sample, key, SFLOW_MAX_MEMCACHE_KEY) > 0) {
        sflow_log(sample, "memcache_op_key %s\n", sflow_url_encode(key, enc_key, ENC_KEY_BYTES));
    }
    sflow_log_next_32(sample, "memcache_op_nkeys");
    sflow_log_next_32(sample, "memcache_op_value_bytes");
    sflow_log_next_32(sample, "memcache_op_duration_uS");
    sflow_log_next_32(sample, "memcache_op_status");
}

// XXX: does not store data or map a struct
void sflow_read_http(sflow_sample_t* sample) {
    char uri[SFLOW_HTTP_URI_MAX+1];
    char host[SFLOW_HTTP_HOST_MAX+1];
    char referrer[SFLOW_HTTP_REFERRER_MAX+1];
    char user_agent[SFLOW_HTTP_USER_AGENT_MAX+1];
    char xff[SFLOW_HTTP_XFF_MAX+1];
    char auth_user[SFLOW_HTTP_AUTH_USER_MAX+1];
    char mime_type[SFLOW_HTTP_MIME_TYPE_MAX+1];
    uint32_t method;
    uint32_t protocol;
    uint32_t status;
    uint64_t req_bytes;
    uint64_t resp_bytes;

    method = sflow_log_next_32(sample, "http_method");
    protocol = sflow_log_next_32(sample, "http_protocol");
    if (sflow_parse_string(sample, uri, SFLOW_HTTP_URI_MAX) > 0) {
        sflow_log(sample, "http_uri %s\n", uri);
    }
    if (sflow_parse_string(sample, host, SFLOW_HTTP_HOST_MAX) > 0) {
        sflow_log(sample, "http_host %s\n", host);
    }
    if (sflow_parse_string(sample, referrer, SFLOW_HTTP_REFERRER_MAX) > 0) {
        sflow_log(sample, "http_referrer %s\n", referrer);
    }
    if (sflow_parse_string(sample, user_agent, SFLOW_HTTP_USER_AGENT_MAX) > 0) {
        sflow_log(sample, "http_user_agent %s\n", user_agent);
    }
    if (sample->data_format == SFLOW_FLOW_HTTP2) {
        if (sflow_parse_string(sample, xff, SFLOW_HTTP_XFF_MAX) > 0) {
            sflow_log(sample, "http_xff %s\n", xff);
        }
    }
    if (sflow_parse_string(sample, auth_user, SFLOW_HTTP_AUTH_USER_MAX) > 0) {
        sflow_log(sample, "http_auth_user %s\n", auth_user);
    }
    if (sflow_parse_string(sample, mime_type, SFLOW_HTTP_MIME_TYPE_MAX) > 0) {
        sflow_log(sample, "http_mime_type %s\n", mime_type);
    }
    if (sample->data_format == SFLOW_FLOW_HTTP2) {
        req_bytes = sflow_log_next_64(sample, "http_request_bytes");
    }
    resp_bytes = sflow_log_next_64(sample, "http_bytes");
    sflow_log_next_32(sample, "http_duration_usecs");
    status = sflow_log_next_32(sample, "http_status");
    
    //sflow_log_clf(sample, auth_user, uri, protocol, referrer, user_agent, method, status, resp_bytes);
}

// XXX: does not store data or map a struct
void sflow_read_app(sflow_sample_t* sample) {
    char application[SFLOW_APP_MAX_APPLICATION_LEN];
    char operation[SFLOW_APP_MAX_OPERATION_LEN];
    char attributes[SFLOW_APP_MAX_ATTRIBUTES_LEN];
    char status[SFLOW_APP_MAX_STATUS_LEN];

    if (sflow_parse_string(sample, application, SFLOW_APP_MAX_APPLICATION_LEN) > 0) {
        sflow_log(sample, "application %s\n", application);
    }
    if (sflow_parse_string(sample, operation, SFLOW_APP_MAX_OPERATION_LEN) > 0) {
        sflow_log(sample, "operation %s\n", operation);
    }
    if (sflow_parse_string(sample, attributes, SFLOW_APP_MAX_ATTRIBUTES_LEN) > 0) {
        sflow_log(sample, "attributes %s\n", attributes);
    }
    if (sflow_parse_string(sample, status, SFLOW_APP_MAX_STATUS_LEN) > 0) {
        sflow_log(sample, "status_descr %s\n", status);
    }
    sflow_log_next_64(sample, "request_bytes");
    sflow_log_next_64(sample, "response_bytes");
    sflow_log_next_32(sample, "duration_usec");
    sflow_log(sample, "status %s\n", sflow_app_status_names[sflow_get_data_32(sample)]);
}

// XXX: does not store data or map a struct
void sflow_read_app_ctxt(sflow_sample_t* sample) {
    char application[SFLOW_APP_MAX_APPLICATION_LEN];
    char operation[SFLOW_APP_MAX_OPERATION_LEN];
    char attributes[SFLOW_APP_MAX_ATTRIBUTES_LEN];
    if (sflow_parse_string(sample, application, SFLOW_APP_MAX_APPLICATION_LEN) > 0) {
        sflow_log(sample, "server_context_application %s\n", application);
    }
    if (sflow_parse_string(sample, operation, SFLOW_APP_MAX_OPERATION_LEN) > 0) {
        sflow_log(sample, "server_context_operation %s\n", operation);
    }
    if (sflow_parse_string(sample, attributes, SFLOW_APP_MAX_ATTRIBUTES_LEN) > 0) {
        sflow_log(sample, "server_context_attributes %s\n", attributes);
    }
}

// XXX: does not store data or map a struct
void sflow_read_app_actor_init(sflow_sample_t* sample) {
    char actor[SFLOW_APP_MAX_ACTOR_LEN];
    if (sflow_parse_string(sample, actor, SFLOW_APP_MAX_ACTOR_LEN) > 0) {
        sflow_log(sample, "actor_initiator %s\n", actor);
    }
}

// XXX: does not store data or map a struct
void sflow_read_app_actor_tgt(sflow_sample_t* sample) {
    char actor[SFLOW_APP_MAX_ACTOR_LEN];
    if (sflow_parse_string(sample, actor, SFLOW_APP_MAX_ACTOR_LEN) > 0) {
        sflow_log(sample, "actor_target %s\n", actor);
    }
}

void sflow_read_extended_socket4(sflow_sample_t* sample) {
    sample->ip_protocol = sflow_get_data_32(sample);
    sample->src_ip.type = SFLOW_ADDRESS_TYPE_IP_V4;
    sample->src_ip.ipv4.addr = sflow_get_data_32_nobswap(sample);
    sample->dst_ip.type = SFLOW_ADDRESS_TYPE_IP_V4;
    sample->dst_ip.ipv4.addr = sflow_get_data_32_nobswap(sample);
    sample->src_port = sflow_get_data_32(sample);
    sample->dst_port = sflow_get_data_32(sample);
}

void sflow_read_extended_proxy_socket4(sflow_sample_t* sample) {
    sample->ip_protocol = sflow_get_data_32(sample);
    sample->src_ip.type = SFLOW_ADDRESS_TYPE_IP_V4;
    sample->src_ip.ipv4.addr = sflow_get_data_32_nobswap(sample);
    sample->dst_ip.type = SFLOW_ADDRESS_TYPE_IP_V4;
    sample->dst_ip.ipv4.addr = sflow_get_data_32_nobswap(sample);
    sample->src_port = sflow_get_data_32(sample);
    sample->dst_port = sflow_get_data_32(sample);
}

void sflow_read_extended_socket6(sflow_sample_t* sample) {
    sample->ip_protocol = sflow_get_data_32(sample);
    sample->src_ip.type = SFLOW_ADDRESS_TYPE_IP_V6;
    memcpy(&sample->src_ip.ipv6, sample->offset32, IPV6_ALEN);
    sflow_skip_bytes(sample, IPV6_ALEN);
    sample->dst_ip.type = SFLOW_ADDRESS_TYPE_IP_V6;
    memcpy(&sample->dst_ip.ipv6, sample->offset32, IPV6_ALEN);
    sflow_skip_bytes(sample, IPV6_ALEN);
    sample->src_port = sflow_get_data_32(sample);
    sample->dst_port = sflow_get_data_32(sample);
}

void sflow_read_extended_proxy_socket6(sflow_sample_t* sample) {
    sample->ip_protocol = sflow_get_data_32(sample);
    sample->src_ip.type = SFLOW_ADDRESS_TYPE_IP_V6;
    memcpy(&sample->src_ip.ipv6, sample->offset32, IPV6_ALEN);
    sflow_skip_bytes(sample, IPV6_ALEN);
    sample->dst_ip.type = SFLOW_ADDRESS_TYPE_IP_V6;
    memcpy(&sample->dst_ip.ipv6, sample->offset32, IPV6_ALEN);
    sflow_skip_bytes(sample, IPV6_ALEN);
    sample->src_port = sflow_get_data_32(sample);
    sample->dst_port = sflow_get_data_32(sample);
}

// XXX: does not store data or map a struct
void sflow_read_extended_decap(sflow_sample_t* sample, char* prefix) {
    uint32_t offset = sflow_get_data_32(sample);
    sflow_log(sample, "extended_type %sdecap\n", prefix);
    sflow_log(sample, "%sdecap_inner_header_offset %u\n", prefix, offset);
}

// XXX: does not store data or map a struct
void sflow_read_extended_vni(sflow_sample_t* sample, char* prefix) {
    uint32_t vni = sflow_get_data_32(sample);
    sflow_log(sample, "extended_type %sVNI\n", prefix);
    sflow_log(sample, "%sVNI %u\n", prefix, vni);
}

#define SFLOW_PORT_FORMAT_SHIFT 30
#define SFLOW_PORT_ID_MASK 0x3fffffff

void sflow_read_flow_sample(sflow_sample_t* sample, bool is_expanded, uint32_t s_index) {
    uint32_t elements;
    uint32_t sample_length;
    uint8_t* sample_start;

    sample_length = sflow_get_data_32(sample);
    sample_start = sample->offset8;
    sample->sample_seq_num = sflow_get_data_32(sample);

    if (is_expanded) {
        sample->ds_type = sflow_get_data_32(sample);
        sample->ds_index = sflow_get_data_32(sample);
    }
    else {
        uint32_t sampler_id = sflow_get_data_32(sample);
        sample->ds_type = sampler_id >> 24;
        sample->ds_index = sampler_id & 0x00ffffff;
    }

    sample->sample_rate = sflow_get_data_32(sample);
    sample->sample_pool = sflow_get_data_32(sample);
    sample->drop_count = sflow_get_data_32(sample);

    if (is_expanded) {
        sample->input_port_format = sflow_get_data_32(sample);
        sample->input_port = sflow_get_data_32(sample);
        sample->output_port_format = sflow_get_data_32(sample);
        sample->output_port = sflow_get_data_32(sample);
    }
    else {
        uint32_t input, output;
        input = sflow_get_data_32(sample);
        output = sflow_get_data_32(sample);
        sample->input_port_format = input >> SFLOW_PORT_FORMAT_SHIFT;
        sample->output_port_format = output >> SFLOW_PORT_FORMAT_SHIFT;
        sample->input_port = input & SFLOW_PORT_ID_MASK;
        sample->output_port = output & SFLOW_PORT_ID_MASK;
    }

    elements = sflow_get_data_32(sample);

    uint32_t e_index = 0;
    for (; e_index < elements; e_index++) {
        RTE_LOG(FINE, EXTRACTOR, "read flow element %u/%u\n", e_index + 1, elements);
        sample->data_format = sflow_get_data_32(sample);
        uint32_t length = sflow_get_data_32(sample);
        uint8_t* start = sample->offset8;

        switch (sample->data_format) {
            case SFLOW_FLOW_HEADER:              { sflow_read_header(sample);                     break; }
            case SFLOW_FLOW_ETHERNET:            { sflow_read_ethernet(sample, "");               break; }
            case SFLOW_FLOW_IPV4:                { sflow_read_ipv4(sample, "");                   break; }
            case SFLOW_FLOW_IPV6:                { sflow_read_ipv6(sample, "");                   break; }
            case SFLOW_FLOW_MEMCACHE:            { sflow_read_memcache(sample);                   break; }
            case SFLOW_FLOW_HTTP:                { sflow_read_http(sample);                       break; }
            case SFLOW_FLOW_HTTP2:               { sflow_read_http(sample);                       break; }
            case SFLOW_FLOW_APP:                 { sflow_read_app(sample);                        break; }
            case SFLOW_FLOW_APP_CTXT:            { sflow_read_app_ctxt(sample);                   break; }
            case SFLOW_FLOW_APP_ACTOR_INIT:      { sflow_read_app_actor_init(sample);             break; }
            case SFLOW_FLOW_APP_ACTOR_TGT:       { sflow_read_app_actor_tgt(sample);              break; }
            case SFLOW_FLOW_EXT_SWITCH:          { sflow_read_extended_switch(sample);            break; }
            case SFLOW_FLOW_EXT_ROUTER:          { sflow_read_extended_router(sample);            break; }
            case SFLOW_FLOW_EXT_GATEWAY:         { sflow_read_extended_gateway(sample);           break; }
            case SFLOW_FLOW_EXT_USER:            { sflow_read_extended_user(sample);              break; }
            case SFLOW_FLOW_EXT_URL:             { sflow_read_extended_url(sample);               break; }
            case SFLOW_FLOW_EXT_MPLS:            { sflow_read_extended_mpls(sample);              break; }
            case SFLOW_FLOW_EXT_NAT:             { sflow_read_extended_nat(sample);               break; }
            case SFLOW_FLOW_EXT_NAT_PORT:        { sflow_read_extended_nat_port(sample);          break; }
            case SFLOW_FLOW_EXT_MPLS_TUNNEL:     { sflow_read_extended_mpls_tunnel(sample);       break; }
            case SFLOW_FLOW_EXT_MPLS_VC:         { sflow_read_extended_mpls_vc(sample);           break; }
            case SFLOW_FLOW_EXT_MPLS_FTN:        { sflow_read_extended_mpls_ftn(sample);          break; }
            case SFLOW_FLOW_EXT_MPLS_LDP_FEC:    { sflow_read_extended_mpls_ldp_fec(sample);      break; }
            case SFLOW_FLOW_EXT_VLAN_TUNNEL:     { sflow_read_extended_vlan_tunnel(sample);       break; }
            case SFLOW_FLOW_EXT_80211_PAYLOAD:   { sflow_read_extended_wifi_payload(sample);      break; }
            case SFLOW_FLOW_EXT_80211_RX:        { sflow_read_extended_wifi_rx(sample);           break; }
            case SFLOW_FLOW_EXT_80211_TX:        { sflow_read_extended_wifi_tx(sample);           break; }
            case SFLOW_FLOW_EXT_AGGREGATION:     { sflow_read_extended_aggregation(sample);       break; }
            case SFLOW_FLOW_EXT_SOCKET4:         { sflow_read_extended_socket4(sample);           break; }
            case SFLOW_FLOW_EXT_SOCKET6:         { sflow_read_extended_socket6(sample);           break; }
            case SFLOW_FLOW_EXT_PROXY_SOCKET4:   { sflow_read_extended_proxy_socket4(sample);     break; }
            case SFLOW_FLOW_EXT_PROXY_SOCKET6:   { sflow_read_extended_proxy_socket6(sample);     break; }
            case SFLOW_FLOW_EXT_L2_TUNNEL_OUT:   { sflow_read_ethernet(sample, "tunnel_l2_out_"); break; }
            case SFLOW_FLOW_EXT_L2_TUNNEL_IN:    { sflow_read_ethernet(sample, "tunnel_l2_in_");  break; }
            case SFLOW_FLOW_EXT_IPV4_TUNNEL_OUT: { sflow_read_ipv4(sample, "tunnel_ipv4_out_");   break; }
            case SFLOW_FLOW_EXT_IPV4_TUNNEL_IN:  { sflow_read_ipv4(sample, "tunnel_ipv4_in_");    break; }
            case SFLOW_FLOW_EXT_IPV6_TUNNEL_OUT: { sflow_read_ipv6(sample, "tunnel_ipv6_out_");   break; }
            case SFLOW_FLOW_EXT_IPV6_TUNNEL_IN:  { sflow_read_ipv6(sample, "tunnel_ipv6_in_");    break; }
            case SFLOW_FLOW_EXT_DECAP_OUT:       { sflow_read_extended_decap(sample, "out_");     break; }
            case SFLOW_FLOW_EXT_DECAP_IN:        { sflow_read_extended_decap(sample, "in_");      break; }
            case SFLOW_FLOW_EXT_VNI_OUT:         { sflow_read_extended_vni(sample, "out_");       break; }
            case SFLOW_FLOW_EXT_VNI_IN:          { sflow_read_extended_vni(sample, "in_");        break; }
            default:                             { sflow_skip_tlv(sample, sample->data_format, length, "flow_sample_element"); break; }
        }
        sample->offset8 = start + length;
    }
    sample->offset8 = sample_start + sample_length;

    // called once after all sample elements are processed
    if (sflow_sample_cb) {
        RTE_LOG(FINER, EXTRACTOR, "invoke sflow_sample_cb on flow sample id: %02d\n", s_index);
        sflow_sample_cb(sample, s_index, e_index);
    }

    // XXX: make sure sflow_log_clf is called when sample->client is valid
    //if (sample->client[0]) {
        // printf("%s %s\n", sample->client, sflow_log_buffer.http_log);
    //}    
}

void sflow_read_counters_generic(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->if_counters));
}

void sflow_read_counters_ethernet(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->ethernet));
}

void sflow_read_counters_tokenring(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->tokenring));
}

void sflow_read_counters_vg(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->vg));
}

void sflow_read_counters_vlan(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    sample->rx_vlan = sample->counters->vlan.vlan_id;
    //sflow_skip_bytes(sample, sizeof(sample->counters->vlan));
}

void sflow_read_counters_80211(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->c_80211));
}

void sflow_read_counters_processor(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->processor));
}

void sflow_read_counters_port_name(sflow_sample_t* sample) {
    char ifname[SFLOW_MAX_PORT_NAME_LEN+1];
    if (sflow_parse_string(sample, ifname, SFLOW_MAX_PORT_NAME_LEN) > 0) {
        sflow_log(sample, "ifName %s\n", ifname);
    }
}

void sflow_read_counters_radio(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->radio));
}

// XXX: does not store data or map a struct
void sflow_read_counters_host_id(sflow_sample_t* sample) {
    uint8_t* uuid;
    char hostname[SFLOW_MAX_HOST_NAME_LEN+1];
    char os_release[SFLOW_MAX_OS_RELEASE_LEN+1];
    if (sflow_parse_string(sample, hostname, SFLOW_MAX_HOST_NAME_LEN) > 0) {
        sflow_log(sample, "hostname %s\n", hostname);
    }
    uuid = sample->offset8;
    char* uuid_str = sflow_print_uuid(uuid);
    sflow_log(sample, "UUID %s\n", uuid_str);
    sflow_skip_bytes(sample, 16);
    sflow_log_next_32(sample, "machine_type");
    sflow_log_next_32(sample, "os_name");
    if (sflow_parse_string(sample, os_release, SFLOW_MAX_OS_RELEASE_LEN) > 0) {
        sflow_log(sample, "os_release %s\n", os_release);
    }
}

// XXX: does not store data or map a struct
void sflow_read_counters_adapters(sflow_sample_t* sample) {
    uint8_t* mac;
    uint32_t i, j, if_index, macs;
    uint32_t adapters = sflow_get_data_32(sample);
    for (i = 0; i < adapters; i++) {
        if_index = sflow_get_data_32(sample);
        sflow_log(sample, "adapter_%u_if_index %u\n", i, if_index);
        macs = sflow_get_data_32(sample);
        sflow_log(sample, "adapter_%u_MACs %u\n", i, macs);
        for (j = 0; j < macs; j++) {
            mac = sample->offset8;
            sflow_log(sample, "adapter_%u_MAC_%u %02x%02x%02x%02x%02x%02x\n",
                    i, j,
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            sflow_skip_bytes(sample, 8);
        }
    }
}

void sflow_read_counters_host_parent(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->host_parent));
}

void sflow_read_counters_host_cpu(sflow_sample_t* sample, uint32_t len) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    // three fields were added in December 2014
    //sflow_skip_bytes(sample, len);
}

void sflow_read_counters_host_mem(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->host_mem));
}

void sflow_read_counters_host_disk(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->host_disk));
}

void sflow_read_counters_host_nio(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->host_nio));
}

void sflow_read_counters_host_ip(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->host_ip));
}

void sflow_read_counters_host_icmp(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->host_icmp));
}

void sflow_read_counters_host_tcp(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->host_tcp));
}

void sflow_read_counters_host_udp(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->host_udp));
}

void sflow_read_counters_host_vnode(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->virtual_node));
}

void sflow_read_counters_host_vcpu(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->virtual_cpu));
}

void sflow_read_counters_host_vmem(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->virtual_mem));
}

void sflow_read_counters_host_vdisk(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->virtual_disk));
}

void sflow_read_counters_host_vnio(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->virtual_nio));
}

void sflow_read_counters_gpu_nvml(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->gpu_nvml));
}

void sflow_read_counters_bcm_tables(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->bcm_tables));
}

// XXX: this code is wrong (different memcache struct layouts)
void sflow_read_counters_memcache(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->memcache));
}

// XXX: this code is wrong (different memcache struct layouts)
void sflow_read_counters_memcache2(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->memcache));
}

void sflow_read_counters_http(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->http));
}

// XXX: does not store data or map a struct
void sflow_read_counters_jvm(sflow_sample_t* sample) {
    char vm_name[SFLOW_JVM_MAX_VMNAME_LEN];
    char vendor[SFLOW_JVM_MAX_VENDOR_LEN];
    char version[SFLOW_JVM_MAX_VERSION_LEN];
    if (sflow_parse_string(sample, vm_name, SFLOW_JVM_MAX_VMNAME_LEN) > 0) {
        sflow_log(sample, "jvm_name %s\n", vm_name);
    }
    if (sflow_parse_string(sample, vendor, SFLOW_JVM_MAX_VENDOR_LEN) > 0) {
        sflow_log(sample, "jvm_vendor %s\n", vendor);
    }
    if (sflow_parse_string(sample, version, SFLOW_JVM_MAX_VERSION_LEN) > 0) {
        sflow_log(sample, "jvm_version %s\n", version);
    }
}

void sflow_read_counters_jmx(sflow_sample_t* sample, uint32_t len) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    // two fields added: fds_open, fds_max
    //sflow_skip_bytes(sample, len);
}

// XXX: does not store data or map a struct
void sflow_read_counters_app(sflow_sample_t* sample) {
    char application[SFLOW_APP_MAX_APPLICATION_LEN];
    if (sflow_parse_string(sample, application, SFLOW_APP_MAX_APPLICATION_LEN) > 0) {
        sflow_log(sample, "application %s\n", application);
    }
    sflow_log_next_32(sample, "status_OK");
    sflow_log_next_32(sample, "errors_OTHER");
    sflow_log_next_32(sample, "errors_TIMEOUT");
    sflow_log_next_32(sample, "errors_INTERNAL_ERROR");
    sflow_log_next_32(sample, "errors_BAD_REQUEST");
    sflow_log_next_32(sample, "errors_FORBIDDEN");
    sflow_log_next_32(sample, "errors_TOO_LARGE");
    sflow_log_next_32(sample, "errors_NOT_IMPLEMENTED");
    sflow_log_next_32(sample, "errors_NOT_FOUND");
    sflow_log_next_32(sample, "errors_UNAVAILABLE");
    sflow_log_next_32(sample, "errors_UNAUTHORIZED");
}

void sflow_read_counters_app_resources(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->app_resources));
}

void sflow_read_counters_app_workers(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->app_workers));
}

void sflow_read_counters_vdi(sflow_sample_t* sample) {
    sample->counters = (sflow_counters_type_t*) sample->offset8;
    //sflow_skip_bytes(sample, sizeof(sample->counters->vdi));
}

// XXX: does not store data or map a struct
void sflow_read_counters_lacp(sflow_sample_t* sample) {
    sflow_lacp_port_state_t port_state;
    sflow_log_next_mac(sample, "actorSystemID");
    sflow_log_next_mac(sample, "partnerSystemID");
    sflow_log_next_32(sample, "attachedAggID");
    port_state.all = sflow_get_data_32_nobswap(sample);
    sflow_log(sample, "actorAdminPortState %u\n", port_state.v.actorAdmin);
    sflow_log(sample, "actorOperPortState %u\n", port_state.v.actorOper);
    sflow_log(sample, "partnerAdminPortState %u\n", port_state.v.partnerAdmin);
    sflow_log(sample, "partnerOperPortState %u\n", port_state.v.partnerOper);
    sflow_log_next_32(sample, "LACPDUsRx");
    sflow_log_next_32(sample, "markerPDUsRx");
    sflow_log_next_32(sample, "markerResponsePDUsRx");
    sflow_log_next_32(sample, "unknownRx");
    sflow_log_next_32(sample, "illegalRx");
    sflow_log_next_32(sample, "LACPDUsTx");
    sflow_log_next_32(sample, "markerPDUsTx");
    sflow_log_next_32(sample, "markerResponsePDUsTx");
}

void sflow_read_counters_sample(sflow_sample_t* sample, bool is_expanded, uint32_t s_index) {
    uint32_t sample_length;
    uint32_t elements;
    uint8_t* sample_start;

    sample_length = sflow_get_data_32(sample);
    sample_start = sample->offset8;
    sample->sample_seq_num = sflow_get_data_32(sample);

    if (is_expanded) {
        sample->ds_type = sflow_get_data_32(sample);
        sample->ds_index = sflow_get_data_32(sample);
    }
    else {
        uint32_t sampler_id = sflow_get_data_32(sample);
        sample->ds_type = sampler_id >> 24;
        sample->ds_index = sampler_id & 0x00ffffff;
    }

    elements = sflow_get_data_32(sample);

    for (uint32_t e_index = 0; e_index < elements; e_index++) {
        RTE_LOG(FINER, EXTRACTOR, "read counter element %u/%u\n", e_index + 1, elements);
        sample->data_format = sflow_get_data_32(sample);
        uint32_t length = sflow_get_data_32(sample);
        uint8_t* start = sample->offset8;
        //sflow_log(sample, "counter_block_tag mhall %s\n", sflow_tag_dump(sample->data_format));

        if (rte_get_log_level() >= RTE_LOG_FINEST) {
            rte_hexdump(stderr, "counter_bytes", start, length);
        }

        switch (sample->data_format) {
            case SFLOW_COUNTERS_GENERIC:       { sflow_read_counters_generic(sample);          break; }
            case SFLOW_COUNTERS_ETHERNET:      { sflow_read_counters_ethernet(sample);         break; }
            case SFLOW_COUNTERS_TOKENRING:     { sflow_read_counters_tokenring(sample);        break; }
            case SFLOW_COUNTERS_VG:            { sflow_read_counters_vg(sample);               break; }
            case SFLOW_COUNTERS_VLAN:          { sflow_read_counters_vlan(sample);             break; }
            case SFLOW_COUNTERS_80211:         { sflow_read_counters_80211(sample);            break; }
            case SFLOW_COUNTERS_LACP:          { sflow_read_counters_lacp(sample);             break; }
            case SFLOW_COUNTERS_PROCESSOR:     { sflow_read_counters_processor(sample);        break; }
            case SFLOW_COUNTERS_RADIO:         { sflow_read_counters_radio(sample);            break; }
            case SFLOW_COUNTERS_PORT_NAME:     { sflow_read_counters_port_name(sample);        break; }
            case SFLOW_COUNTERS_HOST_ID:       { sflow_read_counters_host_id(sample);          break; }
            case SFLOW_COUNTERS_ADAPTERS:      { sflow_read_counters_adapters(sample);         break; }
            case SFLOW_COUNTERS_HOST_PARENT:   { sflow_read_counters_host_parent(sample);      break; }
            case SFLOW_COUNTERS_HOST_CPU:      { sflow_read_counters_host_cpu(sample, length); break; }
            case SFLOW_COUNTERS_HOST_MEM:      { sflow_read_counters_host_mem(sample);         break; }
            case SFLOW_COUNTERS_HOST_DISK:     { sflow_read_counters_host_disk(sample);        break; }
            case SFLOW_COUNTERS_HOST_NIO:      { sflow_read_counters_host_nio(sample);         break; }
            case SFLOW_COUNTERS_HOST_IP:       { sflow_read_counters_host_ip(sample);          break; }
            case SFLOW_COUNTERS_HOST_ICMP:     { sflow_read_counters_host_icmp(sample);        break; }
            case SFLOW_COUNTERS_HOST_TCP:      { sflow_read_counters_host_tcp(sample);         break; }
            case SFLOW_COUNTERS_HOST_UDP:      { sflow_read_counters_host_udp(sample);         break; }
            case SFLOW_COUNTERS_VIRT_NODE:     { sflow_read_counters_host_vnode(sample);       break; }
            case SFLOW_COUNTERS_VIRT_CPU:      { sflow_read_counters_host_vcpu(sample);        break; }
            case SFLOW_COUNTERS_VIRT_MEM:      { sflow_read_counters_host_vmem(sample);        break; }
            case SFLOW_COUNTERS_VIRT_DISK:     { sflow_read_counters_host_vdisk(sample);       break; }
            case SFLOW_COUNTERS_VIRT_NIO:      { sflow_read_counters_host_vnio(sample);        break; }
            case SFLOW_COUNTERS_GPU_NVML:      { sflow_read_counters_gpu_nvml(sample);         break; }
            case SFLOW_COUNTERS_BCM_TABLES:    { sflow_read_counters_bcm_tables(sample);       break; }
            case SFLOW_COUNTERS_MEMCACHE:      { sflow_read_counters_memcache(sample);         break; }
            case SFLOW_COUNTERS_MEMCACHE2:     { sflow_read_counters_memcache2(sample);        break; }
            case SFLOW_COUNTERS_HTTP:          { sflow_read_counters_http(sample);             break; }
            case SFLOW_COUNTERS_JVM:           { sflow_read_counters_jvm(sample);              break; }
            case SFLOW_COUNTERS_JMX:           { sflow_read_counters_jmx(sample, length);      break; }
            case SFLOW_COUNTERS_APP:           { sflow_read_counters_app(sample);              break; }
            case SFLOW_COUNTERS_APP_RESOURCES: { sflow_read_counters_app_resources(sample);    break; }
            case SFLOW_COUNTERS_APP_WORKERS:   { sflow_read_counters_app_workers(sample);      break; }
            case SFLOW_COUNTERS_VDI:           { sflow_read_counters_vdi(sample);              break; }
            default: { sflow_skip_tlv(sample, sample->data_format, length, "counters_sample_element"); break; }
        }
        sample->offset8 = start + length;
        // called once after for each sample element
        if (sflow_sample_cb) {
            RTE_LOG(FINER, EXTRACTOR, "invoke sflow_sample_cb on counter sample id: %02d element id: %02d\n", s_index, e_index);
            sflow_sample_cb(sample, s_index, e_index);
        }
    }
    sample->offset8 = sample_start + sample_length;
}

void sflow_read_datagram(sflow_sample_t* sample) {
    uint32_t samples;

    /* check the version */
    sample->sflow_version = sflow_get_data_32(sample);
    if (sample->sflow_version != SFLOW_VERSION_5) {
        RTE_LOG(ERR, EXTRACTOR, "unexpected datagram version number: %u\n",
            sample->sflow_version);
        rte_hexdump(stderr, "sflow_unknown_version_bytes", sample->raw_sample, (uint32_t) sample->raw_sample_len);
    }

    /* get the agent address */
    sflow_parse_ip(sample, &sample->agent_ip);

    /* version 5 has an agent sub-id as well */
    sample->agent_sub_id = sflow_get_data_32(sample);

    sample->packet_seq_num = sflow_get_data_32(sample);
    sample->sys_up_time = sflow_get_data_32(sample);
    samples = sflow_get_data_32(sample);

    RTE_LOG(FINER, EXTRACTOR, "start new sflow datagram\n");
    /* now iterate and pull out the flows and counters samples */
    for (uint32_t s_index = 0; s_index < samples; s_index++) {
        RTE_LOG(FINER, EXTRACTOR, "read sample %u / %u\n", s_index + 1, samples);
        if (sample->offset8 >= sample->end8) {
            RTE_LOG(ERR, EXTRACTOR, "unexpected end of datagram after sample %u/%u\n", s_index, samples);
            rte_hexdump(stderr, "sflow_corrupt_payload_bytes", sample->raw_sample, (uint32_t) sample->raw_sample_len);
        }
        /* just read the tag, then call the approriate decode fn */
        sample->data_format = 0;
        sample->sample_type = sflow_get_data_32(sample);
        bool is_expanded =
            sample->sample_type == SFLOW_FLOW_SAMPLE_EXPANDED ||
            sample->sample_type == SFLOW_COUNTERS_SAMPLE_EXPANDED;
        switch (sample->sample_type) {
            case SFLOW_FLOW_SAMPLE:
            case SFLOW_FLOW_SAMPLE_EXPANDED: {
                sflow_read_flow_sample(sample, is_expanded, s_index);
                break;
            }
            case SFLOW_COUNTERS_SAMPLE:
            case SFLOW_COUNTERS_SAMPLE_EXPANDED: {
                sflow_read_counters_sample(sample, is_expanded, s_index);
                break;
            }
            default: {
                uint32_t skip_length = sflow_get_data_32(sample);
                RTE_LOG(ERR, EXTRACTOR, "unknown sample type: %u of size: %u\n", sample->sample_type, skip_length);
                sflow_skip_tlv(sample, sample->sample_type, skip_length, "unknown_sample");
                break;
            }
        }
    }
}

void sflow_datagram_receive(sflow_sample_t* sample) {
    sample->offset8 = sample->raw_sample;
    sample->end8 = sample->offset8 + sample->raw_sample_len;
    sflow_read_datagram(sample);
}
