// Copyright (c) 2002-2011 InMon Corp.
// Licensed under the terms of the InMon sFlow license.
// http://www.inmon.com/technology/sflowlicense.txt

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>

#include <rte_log.h>

#include "common.h"
#include "ip_utils.h"
#include "sflow.h"
#include "sflow_cb.h"
#include "sflow_utils.h"

char sflow_nybble_to_hex(char x) {
    return (x < 10) ? ('0' + x) : ('A' - 10 + x);
}

#define SFLOW_UUID_LENGTH_MAX 37
static __thread char uuid_buf[SFLOW_UUID_LENGTH_MAX];

char* sflow_print_uuid(uint8_t* u) {
    snprintf(uuid_buf, sizeof(uuid_buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        u[0],  u[1],  u[2],  u[3],  u[4],  u[5],  u[6],  u[7],
        u[8],  u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
    return uuid_buf;
}

char* sflow_url_encode(char* in, char* out, size_t out_len) {
    char c;
    char* r = in;
    char* w = out;
    size_t max_len = (strlen(in) * 3) + 1;
    if (out_len < max_len) return "sflow_url_encode: not enough space";
    while ((c = *r++)) {
        if (isalnum(c)) *w++ = c;
        else if (isspace(c)) *w++ = '+';
        else {
            *w++ = '%';
            *w++ = (char) sflow_nybble_to_hex(c >> 4);
            *w++ = (char) sflow_nybble_to_hex(c & 0x0f);
        }
    }
    *w++ = '\0';
    return out;
}

static __thread char mac_buf[SS_ETHER_STR_MAX];

char* sflow_mac_string(uint8_t* m) {
    snprintf(mac_buf, sizeof(mac_buf), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        m[0], m[1], m[2], m[3], m[4], m[5]);
    return mac_buf;
}

static __thread char ip_buf[SS_IPV6_STR_MAX];

char* sflow_ip_string(sflow_ip_t* ip, char* i, size_t i_len) {
    if (i == NULL) {
        i = ip_buf;
        i_len = sizeof(ip_buf);
    }
    switch (ip->type) {
        case SFLOW_ADDRESS_TYPE_IP_V4: {
            ss_inet_ntop_raw(SS_AF_INET4, (uint8_t*) &ip->ipv4.addr, i, i_len);
            break;
        }
        case SFLOW_ADDRESS_TYPE_IP_V6: {
            ss_inet_ntop_raw(SS_AF_INET6, (uint8_t*) &ip->ipv6.addr, i, i_len);
            break;
        }
        default: {
            snprintf(i, i_len, "SFLOW_ADDRESS_TYPE_UNKNOWN");
            break;
        }
    }
    return i;
}

uint32_t sflow_get_data_32_nobswap(sflow_sample_t* sample) {
    uint32_t ans = *(sample->offset32)++;

    // Don't run off the end of the datagram.
    // Sven Eschenberg found a bug in this code before.

    if (sample->offset8 > sample->end8) {
        // XXX: safety check here???
    }
    return ans;
}

uint32_t sflow_get_data_32(sflow_sample_t* sample) {
    return ntohl(sflow_get_data_32_nobswap(sample));
}

float sflow_get_float(sflow_sample_t* sample) {
    float fl;
    uint32_t reg = sflow_get_data_32(sample);
    memcpy(&fl, &reg, 4);
    return fl;
}

uint64_t sflow_get_data_64(sflow_sample_t* sample) {
    uint64_t tmp_lo, tmp_hi;
    tmp_hi = sflow_get_data_32(sample);
    tmp_lo = sflow_get_data_32(sample);
    return (tmp_hi << 32) + tmp_lo;
}

void sflow_skip_bytes(sflow_sample_t* sample, size_t bytes) {
    size_t words = (bytes + 3) / 4;
    RTE_LOG(FINER, UTILS, "increment offset32 by %lu words\n", words);
    sample->offset32 += words;
    if (bytes > sample->raw_sample_len || sample->offset8 > sample->end8) {
        // XXX: safety check here???
    }
}

uint32_t sflow_log_next_32(sflow_sample_t* sample, char* field_name) {
    uint32_t val = sflow_get_data_32(sample);
    sflow_log(sample, "%s %u\n", field_name, val);
    return val;
}

uint64_t sflow_log_next_64(sflow_sample_t* sample, char* field_name) {
    uint64_t val64 = sflow_get_data_64(sample);
    sflow_log(sample, "%s %"PRIu64"\n", field_name, val64);
    return val64;
}

double sflow_log_next_percentage(sflow_sample_t* sample, char* field_name) {
    uint32_t hundredths = sflow_get_data_32(sample);
    double percentage = -1;
    if (hundredths == (uint32_t)-1) sflow_log(sample, "%s unknown\n", field_name);
    else {
        percentage = (double) hundredths / (double) 100.0;
        sflow_log(sample, "%s %.2f\n", field_name, percentage);
    }
    return percentage;
}

float sflow_log_next_float(sflow_sample_t* sample, char* field_name) {
    float val = sflow_get_float(sample);
    sflow_log(sample, "%s %.3f\n", field_name, val);
    return val;
}

void sflow_log_next_mac(sflow_sample_t* sample, char* field_name) {
    uint8_t* mac = sample->offset8;
    sflow_log(sample, "%s %02x%02x%02x%02x%02x%02x\n", field_name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    sflow_skip_bytes(sample, ETHER_ALEN);
}

uint32_t sflow_parse_string(sflow_sample_t* sample, char* buf, uint32_t buf_len) {
    uint32_t len, read_len;
    len = sflow_get_data_32(sample);
    // truncate if too long
    read_len = (len >= buf_len) ? (buf_len - 1) : len;
    memcpy(buf, sample->offset8, read_len);
    // null terminate
    buf[read_len] = '\0';
    sflow_skip_bytes(sample, len);
    return len;
}

uint32_t sflow_parse_ip(sflow_sample_t* sample, sflow_ip_t* ip) {
    ip->type = sflow_get_data_32(sample);
    if (ip->type == SFLOW_ADDRESS_TYPE_IP_V4)
        ip->ipv4.addr = sflow_get_data_32_nobswap(sample);
    else {
        memcpy(&ip->ipv6.addr, sample->offset8, IPV6_ALEN);
        sflow_skip_bytes(sample, IPV6_ALEN);
    }
    return ip->type;
}

// XXX: no clue what the maximum tag length is
static __thread char tag_buf[SS_IPV6_STR_MAX + 1];
char* sflow_tag_dump(uint32_t tag) {
    snprintf(tag_buf, sizeof(tag_buf), "%u:%u", (tag >> 12), (tag & 0x00000FFF));
    tag_buf[SS_IPV6_STR_MAX - 1] = '\0';
    return tag_buf;
}

char* sflow_sample_type_dump(uint32_t sample_type) {
    switch (sample_type) {
        case SFLOW_FLOW_SAMPLE:              return "SFLOW_FLOW_SAMPLE";
        case SFLOW_COUNTERS_SAMPLE:          return "SFLOW_COUNTERS_SAMPLE";
        case SFLOW_FLOW_SAMPLE_EXPANDED:     return "SFLOW_FLOW_SAMPLE_EXPANDED";
        case SFLOW_COUNTERS_SAMPLE_EXPANDED: return "SFLOW_COUNTERS_SAMPLE_EXPANDED";
        default:                             return "SFLOW_SAMPLE_TYPE_UNKNOWN";
    }
}

char* sflow_ds_type_dump(uint32_t ds_type) {
    switch (ds_type) {
        case SFLOW_DS_IFINDEX: return "SFLOW_DS_IFINDEX";
        case SFLOW_DS_VLAN:    return "SFLOW_DS_VLAN";
        case SFLOW_DS_ENTITY:  return "SFLOW_DS_ENTITY";
        default:               return "SFLOW_DS_UNKNOWN";
    }
}

static __thread char port_buf[128];
char* sflow_port_id_dump(uint32_t format, uint32_t port) {
    //uint32_t format = 0xc0000000 & port_id >> 30;
    //uint32_t port   = 0x3fffffff & port_id >>  0;
    
    // all zero: unknown port ID
    if (format == 0 && port == 0) {
        snprintf(port_buf, sizeof(port_buf), "ID_UNKNOWN");
    }
    else {
        switch (format) {
            case 0: {
                if (port == 0x3FFFFFFF) {
                    snprintf(port_buf, sizeof(port_buf), "ID_SELF");
                }
                else {
                    snprintf(port_buf, sizeof(port_buf), "ID_%06u", port);
                }
                break;
            }
            case 1: {
                if (port <= 255) {
                    snprintf(port_buf, sizeof(port_buf), "ICMP_DROP_%03u", port);
                }
                else if (port == 256) {
                    snprintf(port_buf, sizeof(port_buf), "SFLOW_DROP_UNKNOWN");
                }
                else if (port == 257) {
                    snprintf(port_buf, sizeof(port_buf), "SFLOW_DROP_TTL");
                }
                else if (port == 258) {
                    snprintf(port_buf, sizeof(port_buf), "SFLOW_DROP_ACL");
                }
                else if (port == 259) {
                    snprintf(port_buf, sizeof(port_buf), "SFLOW_DROP_MEMORY");
                }
                else if (port == 260) {
                    snprintf(port_buf, sizeof(port_buf), "SFLOW_DROP_RED");
                }
                else if (port == 261) {
                    snprintf(port_buf, sizeof(port_buf), "SFLOW_DROP_QOS");
                }
                else if (port == 262) {
                    snprintf(port_buf, sizeof(port_buf), "SFLOW_DROP_MTU");
                }
                else {
                    snprintf(port_buf, sizeof(port_buf), "SFLOW_DROP_UNDEFINED");
                }
                break;
            }
            case 2: {
                snprintf(port_buf, sizeof(port_buf), "ID_MULTIPLE_%06u", port);
                break;
            }
            default: {
                snprintf(port_buf, sizeof(port_buf), "ID_FORMAT_UNDEFINED");
                break;
            }
        }
    }

    return port_buf;
}

char* sflow_sample_format_dump(uint32_t sample_type, uint32_t sample_format) {
    switch (sample_type) {
        case SFLOW_FLOW_SAMPLE:
        case SFLOW_FLOW_SAMPLE_EXPANDED:
            return sflow_flow_format_dump(sample_format);
        case SFLOW_COUNTERS_SAMPLE:
        case SFLOW_COUNTERS_SAMPLE_EXPANDED:
            return sflow_counters_format_dump(sample_format);
        default:
            return "SFLOW_SAMPLE_TYPE_UNKNOWN";
    }
}

char* sflow_flow_format_dump(uint32_t sample_format) {
    switch (sample_format) {
        case SFLOW_FLOW_HEADER:              return "SFLOW_FLOW_HEADER";
        case SFLOW_FLOW_ETHERNET:            return "SFLOW_FLOW_ETHERNET";
        case SFLOW_FLOW_IPV4:                return "SFLOW_FLOW_IPV4";
        case SFLOW_FLOW_IPV6:                return "SFLOW_FLOW_IPV6";
        case SFLOW_FLOW_MEMCACHE:            return "SFLOW_FLOW_MEMCACHE";
        case SFLOW_FLOW_HTTP:                return "SFLOW_FLOW_HTTP";
        case SFLOW_FLOW_HTTP2:               return "SFLOW_FLOW_HTTP2";
        case SFLOW_FLOW_APP:                 return "SFLOW_FLOW_APP";
        case SFLOW_FLOW_APP_CTXT:            return "SFLOW_FLOW_APP_CTXT";
        case SFLOW_FLOW_APP_ACTOR_INIT:      return "SFLOW_FLOW_APP_ACTOR_INIT";
        case SFLOW_FLOW_APP_ACTOR_TGT:       return "SFLOW_FLOW_APP_ACTOR_TGT";
        case SFLOW_FLOW_EXT_SWITCH:          return "SFLOW_FLOW_EXT_SWITCH";
        case SFLOW_FLOW_EXT_ROUTER:          return "SFLOW_FLOW_EXT_ROUTER";
        case SFLOW_FLOW_EXT_GATEWAY:         return "SFLOW_FLOW_EXT_GATEWAY";
        case SFLOW_FLOW_EXT_USER:            return "SFLOW_FLOW_EXT_USER";
        case SFLOW_FLOW_EXT_URL:             return "SFLOW_FLOW_EXT_URL";
        case SFLOW_FLOW_EXT_MPLS:            return "SFLOW_FLOW_EXT_MPLS";
        case SFLOW_FLOW_EXT_NAT:             return "SFLOW_FLOW_EXT_NAT";
        case SFLOW_FLOW_EXT_NAT_PORT:        return "SFLOW_FLOW_EXT_NAT_PORT";
        case SFLOW_FLOW_EXT_MPLS_TUNNEL:     return "SFLOW_FLOW_EXT_MPLS_TUNNEL";
        case SFLOW_FLOW_EXT_MPLS_VC:         return "SFLOW_FLOW_EXT_MPLS_VC";
        case SFLOW_FLOW_EXT_MPLS_FTN:        return "SFLOW_FLOW_EXT_MPLS_FTN";
        case SFLOW_FLOW_EXT_MPLS_LDP_FEC:    return "SFLOW_FLOW_EXT_MPLS_LDP_FEC";
        case SFLOW_FLOW_EXT_VLAN_TUNNEL:     return "SFLOW_FLOW_EXT_VLAN_TUNNEL";
        case SFLOW_FLOW_EXT_80211_PAYLOAD:   return "SFLOW_FLOW_EXT_80211_PAYLOAD";
        case SFLOW_FLOW_EXT_80211_RX:        return "SFLOW_FLOW_EXT_80211_RX";
        case SFLOW_FLOW_EXT_80211_TX:        return "SFLOW_FLOW_EXT_80211_TX";
        case SFLOW_FLOW_EXT_AGGREGATION:     return "SFLOW_FLOW_EXT_AGGREGATION";
        case SFLOW_FLOW_EXT_SOCKET4:         return "SFLOW_FLOW_EXT_SOCKET4";
        case SFLOW_FLOW_EXT_SOCKET6:         return "SFLOW_FLOW_EXT_SOCKET6";
        case SFLOW_FLOW_EXT_PROXY_SOCKET4:   return "SFLOW_FLOW_EXT_PROXY_SOCKET4";
        case SFLOW_FLOW_EXT_PROXY_SOCKET6:   return "SFLOW_FLOW_EXT_PROXY_SOCKET6";
        case SFLOW_FLOW_EXT_L2_TUNNEL_OUT:   return "SFLOW_FLOW_EXT_L2_TUNNEL_OUT";
        case SFLOW_FLOW_EXT_L2_TUNNEL_IN:    return "SFLOW_FLOW_EXT_L2_TUNNEL_IN";
        case SFLOW_FLOW_EXT_IPV4_TUNNEL_OUT: return "SFLOW_FLOW_EXT_IPV4_TUNNEL_OUT";
        case SFLOW_FLOW_EXT_IPV4_TUNNEL_IN:  return "SFLOW_FLOW_EXT_IPV4_TUNNEL_IN";
        case SFLOW_FLOW_EXT_IPV6_TUNNEL_OUT: return "SFLOW_FLOW_EXT_IPV6_TUNNEL_OUT";
        case SFLOW_FLOW_EXT_IPV6_TUNNEL_IN:  return "SFLOW_FLOW_EXT_IPV6_TUNNEL_IN";
        case SFLOW_FLOW_EXT_DECAP_OUT:       return "SFLOW_FLOW_EXT_DECAP_OUT";
        case SFLOW_FLOW_EXT_DECAP_IN:        return "SFLOW_FLOW_EXT_DECAP_IN";
        case SFLOW_FLOW_EXT_VNI_OUT:         return "SFLOW_FLOW_EXT_VNI_OUT";
        case SFLOW_FLOW_EXT_VNI_IN:          return "SFLOW_FLOW_EXT_VNI_IN";
        default:                             return "SFLOW_FLOW_UNKNOWN";
    }
}

char* sflow_header_protocol_dump(uint32_t header_protocol) {
    switch (header_protocol) {
        case SFLOW_HEADER_ISO88023_ETHERNET:        return "SFLOW_HEADER_ISO88023_ETHERNET";
        case SFLOW_HEADER_ISO88024_TOKENBUS:        return "SFLOW_HEADER_ISO88024_TOKENBUS";
        case SFLOW_HEADER_ISO88025_TOKENRING:       return "SFLOW_HEADER_ISO88025_TOKENRING";
        case SFLOW_HEADER_FDDI:                     return "SFLOW_HEADER_FDDI";
        case SFLOW_HEADER_FRAME_RELAY:              return "SFLOW_HEADER_FRAME_RELAY";
        case SFLOW_HEADER_X25:                      return "SFLOW_HEADER_X25";
        case SFLOW_HEADER_PPP:                      return "SFLOW_HEADER_PPP";
        case SFLOW_HEADER_SMDS:                     return "SFLOW_HEADER_SMDS";
        case SFLOW_HEADER_AAL5:                     return "SFLOW_HEADER_AAL5";
        case SFLOW_HEADER_AAL5_IP:                  return "SFLOW_HEADER_AAL5_IP";
        case SFLOW_HEADER_IPV4:                     return "SFLOW_HEADER_IPV4";
        case SFLOW_HEADER_IPV6:                     return "SFLOW_HEADER_IPV6";
        case SFLOW_HEADER_MPLS:                     return "SFLOW_HEADER_MPLS";
        case SFLOW_HEADER_POS:                      return "SFLOW_HEADER_POS";
        case SFLOW_HEADER_IEEE80211_MAC:            return "SFLOW_HEADER_IEEE80211_MAC";
        case SFLOW_HEADER_IEEE80211_AMPDU:          return "SFLOW_HEADER_IEEE80211_AMPDU";
        case SFLOW_HEADER_IEEE80211_AMSDU_SUBFRAME: return "SFLOW_HEADER_IEEE80211_AMSDU_SUBFRAME";
        default:                                    return "SFLOW_HEADER_UNKNOWN";
    }
}

char* sflow_counters_format_dump(uint32_t sample_format) {
    switch (sample_format) {
        case SFLOW_COUNTERS_GENERIC:       return "SFLOW_COUNTERS_GENERIC";
        case SFLOW_COUNTERS_ETHERNET:      return "SFLOW_COUNTERS_ETHERNET";
        case SFLOW_COUNTERS_TOKENRING:     return "SFLOW_COUNTERS_TOKENRING";
        case SFLOW_COUNTERS_VG:            return "SFLOW_COUNTERS_VG";
        case SFLOW_COUNTERS_VLAN:          return "SFLOW_COUNTERS_VLAN";
        case SFLOW_COUNTERS_80211:         return "SFLOW_COUNTERS_80211";
        case SFLOW_COUNTERS_LACP:          return "SFLOW_COUNTERS_LACP";
        case SFLOW_COUNTERS_PROCESSOR:     return "SFLOW_COUNTERS_PROCESSOR";
        case SFLOW_COUNTERS_RADIO:         return "SFLOW_COUNTERS_RADIO";
        case SFLOW_COUNTERS_PORT_NAME:     return "SFLOW_COUNTERS_PORT_NAME";
        case SFLOW_COUNTERS_HOST_ID:       return "SFLOW_COUNTERS_HOST_ID";
        case SFLOW_COUNTERS_ADAPTERS:      return "SFLOW_COUNTERS_ADAPTERS";
        case SFLOW_COUNTERS_HOST_PARENT:   return "SFLOW_COUNTERS_HOST_PARENT";
        case SFLOW_COUNTERS_HOST_CPU:      return "SFLOW_COUNTERS_HOST_CPU";
        case SFLOW_COUNTERS_HOST_MEM:      return "SFLOW_COUNTERS_HOST_MEM";
        case SFLOW_COUNTERS_HOST_DISK:     return "SFLOW_COUNTERS_HOST_DISK";
        case SFLOW_COUNTERS_HOST_NIO:      return "SFLOW_COUNTERS_HOST_NIO";
        case SFLOW_COUNTERS_HOST_IP:       return "SFLOW_COUNTERS_HOST_IP";
        case SFLOW_COUNTERS_HOST_ICMP:     return "SFLOW_COUNTERS_HOST_ICMP";
        case SFLOW_COUNTERS_HOST_TCP:      return "SFLOW_COUNTERS_HOST_TCP";
        case SFLOW_COUNTERS_HOST_UDP:      return "SFLOW_COUNTERS_HOST_UDP";
        case SFLOW_COUNTERS_VIRT_NODE:     return "SFLOW_COUNTERS_VIRT_NODE";
        case SFLOW_COUNTERS_VIRT_CPU:      return "SFLOW_COUNTERS_VIRT_CPU";
        case SFLOW_COUNTERS_VIRT_MEM:      return "SFLOW_COUNTERS_VIRT_MEM";
        case SFLOW_COUNTERS_VIRT_DISK:     return "SFLOW_COUNTERS_VIRT_DISK";
        case SFLOW_COUNTERS_VIRT_NIO:      return "SFLOW_COUNTERS_VIRT_NIO";
        case SFLOW_COUNTERS_GPU_NVML:      return "SFLOW_COUNTERS_GPU_NVML";
        case SFLOW_COUNTERS_BCM_TABLES:    return "SFLOW_COUNTERS_BCM_TABLES";
        case SFLOW_COUNTERS_MEMCACHE:      return "SFLOW_COUNTERS_MEMCACHE";
        case SFLOW_COUNTERS_MEMCACHE2:     return "SFLOW_COUNTERS_MEMCACHE2";
        case SFLOW_COUNTERS_HTTP:          return "SFLOW_COUNTERS_HTTP";
        case SFLOW_COUNTERS_JVM:           return "SFLOW_COUNTERS_JVM";
        case SFLOW_COUNTERS_JMX:           return "SFLOW_COUNTERS_JMX";
        case SFLOW_COUNTERS_APP:           return "SFLOW_COUNTERS_APP";
        case SFLOW_COUNTERS_APP_RESOURCES: return "SFLOW_COUNTERS_APP_RESOURCE";
        case SFLOW_COUNTERS_APP_WORKERS:   return "SFLOW_COUNTERS_APP_WORKERS";
        case SFLOW_COUNTERS_VDI:           return "SFLOW_COUNTERS_VDI";
        default: return "SFLOW_COUNTERS_UNKNOWN";
    }
}

char* sflow_counters_direction_dump(uint32_t ifDirection) {
    switch (ifDirection) {
        case 0: return "DIRECTION_UNKNOWN";
        case 1: return "DIRECTION_FULL_DUPLEX";
        case 2: return "DIRECTION_HALF_DUPLEX";
        case 3: return "DIRECTION_RX";
        case 4: return "DIRECTION_TX";
        default: return "DIRECTION_OTHER";
    }
}

// XXX: no clue what the maximum status length is
static __thread char status_buf[SS_IPV6_STR_MAX + 1];
char* sflow_counters_status_dump(uint32_t ifStatus) {
    uint32_t ifAdminStatus = ifStatus & 0x00000001;
    uint32_t ifOperStatus  = ifStatus & 0x00000002;
    
    snprintf(status_buf, sizeof(status_buf), "ifAdminStatus %s, ifOperStatus %s",
        ifAdminStatus ? "UP" : "DOWN",
        ifOperStatus ? "UP" : "DOWN");
    
    return status_buf;
}

void sflow_skip_tlv(sflow_sample_t* sample, uint32_t tag, uint32_t len, char *description) {
    RTE_LOG(INFO, EXTRACTOR, "skipping unknown item %s of type %s and length %u\n",
        description, sflow_tag_dump(tag), len);
    sflow_skip_bytes(sample, len);
}

static uint8_t mapped_prefix[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };
static uint8_t compat_prefix[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

int is_ip4_mapped_ip(ip6_addr_t* ip6, ip4_addr_t* ip4) {
    if (!memcmp(ip6->addr, mapped_prefix, 12) ||
            !memcmp(ip6->addr, compat_prefix, 12)) {
        memcpy(ip4, ip6->addr + 12, 4);
        return true;
    }
    return false;
}
