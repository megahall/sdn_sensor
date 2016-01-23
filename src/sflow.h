/* Copyright (c) 2002-2011 InMon Corp. */
/* Licensed under the terms of the InMon sFlow license. */
/* http://www.inmon.com/technology/sflowlicense.txt */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "ip_utils.h"

#define SFLOW_DEFAULT_HEADER_SIZE 128
#define SFLOW_DEFAULT_COLLECTOR_PORT 6343
#define SFLOW_DEFAULT_SAMPLING_RATE 400

#define SFLOW_MAX_SSID_LEN 256

#define XDRSIZ_SFLOW_EXTENDED_SOCKET4 20

#define XDRSIZ_SFLOW_EXTENDED_SOCKET6 44

#define SFLOW_MAX_MEMCACHE_KEY 255

#define SFLOW_HTTP_URI_MAX 255
#define SFLOW_HTTP_HOST_MAX 64
#define SFLOW_HTTP_REFERRER_MAX 255
#define SFLOW_HTTP_USER_AGENT_MAX 128
#define SFLOW_HTTP_XFF_MAX 64
#define SFLOW_HTTP_AUTH_USER_MAX 32
#define SFLOW_HTTP_MIME_TYPE_MAX 64

#define SFLOW_APP_MAX_APPLICATION_LEN 32
#define SFLOW_APP_MAX_OPERATION_LEN 32
#define SFLOW_APP_MAX_ATTRIBUTES_LEN 255

#define SFLOW_APP_MAX_STATUS_LEN 32
#define SFLOW_APP_MAX_ACTOR_LEN 64

#define SFLOW_MAX_HOST_NAME_LEN 64
#define SFLOW_MAX_OS_RELEASE_LEN 32

#define SFLOW_JVM_MAX_VMNAME_LEN 64
#define SFLOW_JVM_MAX_VENDOR_LEN 32
#define SFLOW_JVM_MAX_VERSION_LEN 32

#define XDRSIZ_JMX_COUNTERS 108
#define XDRSIZ_LACP_COUNTERS 56
#define SFLOW_MAX_PORT_NAME_LEN 255

#define SFLOW_ADD_ELEMENT(_sm, _el) do { (_el)->next = (_sm)->elements; (_sm)->elements = (_el); } while(0)

#define SFLOW_MAX_DATAGRAM_SIZE 1500
#define SFLOW_MIN_DATAGRAM_SIZE 200
#define SFLOW_DEFAULT_DATAGRAM_SIZE 1400

#define SFLOW_DATA_PAD 400

#define SAMPLE_EXTENDED_DATA_SWITCH 1
#define SAMPLE_EXTENDED_DATA_ROUTER 4
#define SAMPLE_EXTENDED_DATA_GATEWAY 8
#define SAMPLE_EXTENDED_DATA_USER 16
#define SAMPLE_EXTENDED_DATA_URL 32
#define SAMPLE_EXTENDED_DATA_MPLS 64
#define SAMPLE_EXTENDED_DATA_NAT 128
#define SAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096
#define SAMPLE_EXTENDED_DATA_NAT_PORT 8192

#define SA_MAX_EXTENDED_USER_LEN 200
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200

#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

#define ETHER_ALEN 6
#define ETHER_ALEN_PADDED 8

// Packet header data

union sflow_ip_value_u {
    ip4_addr_t ipv4;
    ip6_addr_t ipv6;
};

typedef union sflow_ip_value_u sflow_ip_value_t;

enum sflow_ip_type_e {
    SFLOW_ADDRESS_TYPE_UNDEFINED = 0,
    SFLOW_ADDRESS_TYPE_IP_V4 = 1,
    SFLOW_ADDRESS_TYPE_IP_V6 = 2
};

typedef enum sflow_ip_type_e sflow_ip_type_t;

struct sflow_ip_s {
    uint32_t type;           // enum sflow_address_type
    union {
        ip4_addr_t ipv4;
        ip6_addr_t ipv6;
        uint8_t addr[sizeof(ip6_addr_t)];
    };
    // sflow_ip_value_t ip;
};

typedef struct sflow_ip_s sflow_ip_t;

struct sflow_mac_address_s {
    uint8_t mac[ETHER_ALEN];
};

typedef struct sflow_mac_address_s sflow_mac_address_t;

// The header protocol describes the format of the sampled header
enum sflow_header_protocol_e {
    SFLOW_HEADER_ISO88023_ETHERNET        = 1,
    SFLOW_HEADER_ISO88024_TOKENBUS        = 2,
    SFLOW_HEADER_ISO88025_TOKENRING       = 3,
    SFLOW_HEADER_FDDI                     = 4,
    SFLOW_HEADER_FRAME_RELAY              = 5,
    SFLOW_HEADER_X25                      = 6,
    SFLOW_HEADER_PPP                      = 7,
    SFLOW_HEADER_SMDS                     = 8,
    SFLOW_HEADER_AAL5                     = 9,
    SFLOW_HEADER_AAL5_IP                  = 10, // e.g. Cisco AAL5 mux
    SFLOW_HEADER_IPV4                     = 11,
    SFLOW_HEADER_IPV6                     = 12,
    SFLOW_HEADER_MPLS                     = 13,
    SFLOW_HEADER_POS                      = 14,
    SFLOW_HEADER_IEEE80211_MAC            = 15,
    SFLOW_HEADER_IEEE80211_AMPDU          = 16,
    SFLOW_HEADER_IEEE80211_AMSDU_SUBFRAME = 17,
};

typedef enum sflow_header_protocol_e sflow_header_protocol_t;

// raw sampled header

struct sflow_sampled_header_s {
    uint32_t protocol;      // (sflow_header_protocol_t)
    uint32_t packet_size;   // Original length of packet before sampling
    uint32_t stripped_size; // header/trailer bytes stripped by sender
    uint32_t header_size;   // length of sampled header bytes to follow
    uint8_t* bytes;         // Header bytes
};

typedef struct sflow_sampled_header_s sflow_sampled_header_t;

// decoded ethernet header

struct sflow_sampled_ethernet_s {
    uint32_t eth_len;   // The length of the MAC packet excluding lower encaps
    uint8_t src_mac[ETHER_ALEN_PADDED]; // 6 bytes + 2 pad
    uint8_t dst_mac[ETHER_ALEN_PADDED];
    uint32_t eth_type;
};

typedef struct sflow_sampled_ethernet_s sflow_sampled_ethernet_t;

// decoded IP version 4 header

struct sflow_sampled_ipv4_s {
    uint32_t len;         // The length of the IP packet excluding lower encaps
    uint32_t protocol;    // IP Protocol type (for example, TCP = 6, UDP = 17)
    ip4_addr_t src_ip;  // Source IP Address
    ip4_addr_t dst_ip;  // Destination IP Address
    uint32_t src_port;    // TCP/UDP source port number or equivalent
    uint32_t dst_port;    // TCP/UDP destination port number or equivalent
    uint32_t tcp_flags;   // TCP flags
    uint32_t tos;         // IPv4 TOS
};

typedef struct sflow_sampled_ipv4_s sflow_sampled_ipv4_t;

// decoded IP version 6 data

struct sflow_sampled_ipv6_s {
    uint32_t len;          // The length of the IP packet lower layer encaps
    uint32_t protocol;     // IP Protocol type (for example, TCP = 6, UDP = 17)
    ip6_addr_t src_ip;   // Source IP Address
    ip6_addr_t dst_ip;   // Destination IP Address
    uint32_t src_port;     // TCP/UDP source port number or equivalent
    uint32_t dst_port;     // TCP/UDP destination port number or equivalent
    uint32_t tcp_flags;    // TCP flags
    uint32_t priority;     // IPv6 priority
};

typedef struct sflow_sampled_ipv6_s sflow_sampled_ipv6_t;

// Extended data types

// Extended switch data

struct sflow_extended_switch_s {
    uint32_t src_vlan;       // The 802.1Q VLAN id of incomming frame
    uint32_t src_priority;   // The 802.1p priority
    uint32_t dst_vlan;       // The 802.1Q VLAN id of outgoing frame
    uint32_t dst_priority;   // The 802.1p priority
};

typedef struct sflow_extended_switch_s sflow_extended_switch_t;

// Extended router data
struct sflow_extended_router_s {
    sflow_ip_t next_hop; // IP address of next hop router
    uint32_t src_mask;       // Source address prefix mask bits
    uint32_t dst_mask;       // Destination address prefix mask bits
};

typedef struct sflow_extended_router_s sflow_extended_router_t;

// Extended gateway data
enum sflow_extended_as_path_segment_type {
    SFLOW_EXTENDED_AS_SET = 1,      // Unordered set of ASs
    SFLOW_EXTENDED_AS_SEQUENCE = 2  // Ordered sequence of ASs
};

struct sflow_extended_as_path_segment_s {
    uint32_t type; // enum sflow_extended_as_path_segment_type
    uint32_t len;  // number of AS numbers in set/sequence
    union {
        uint32_t* set;
        uint32_t* seq;
    } as;
};

typedef struct sflow_extended_as_path_segment_s sflow_extended_as_path_segment_t;

struct sflow_extended_gateway_s {
    sflow_ip_t next_hop; // address of border router for destination
    uint32_t as;                             // AS number for this gateway
    uint32_t src_as;                         // AS number of source (origin)
    uint32_t src_peer_as;                    // AS number of source peer
    uint32_t dst_as_path_segments;           // number of segments in path
    sflow_extended_as_path_segment_t* dst_as_path; // list of seqs or sets
    uint32_t communities_len;                // number of communities
    uint32_t* communities;                   // set of communities
    uint32_t local_pref;                     // local_pref associated with this route
};

typedef struct sflow_extended_gateway_s sflow_extended_gateway_t;

struct sflow_string_s {
    uint32_t len;
    char* str;
};

typedef struct sflow_string_s sflow_string_t;

// Extended user data

struct sflow_extended_user_s {
    /*
     * MIBEnum value of character set used to encode a string - See RFC 2978
     * Where possible UTF-8 encoding (MIBEnum=106) should be used. A value
     * of zero indicates an unknown encoding.
     */
    uint32_t src_charset;
    sflow_string_t src_user;
    uint32_t dst_charset;
    sflow_string_t dst_user;
};

typedef struct sflow_extended_user_s sflow_extended_user_t;

// Extended URL data
enum sflow_extended_url_direction_e {
    SFLOW_EXTENDED_URL_SRC = 1, // URL is associated with source address
    SFLOW_EXTENDED_URL_DST = 2  // URL is associated with destination address
};

typedef enum sflow_extended_url_direction_e sflow_extended_url_direction_t;

struct sflow_extended_url_s {
    uint32_t direction;   // enum sflow_extended_url_direction
    sflow_string_t url;   // URL associated with the packet flow, URL-encoded
    sflow_string_t host;  // The host field from the HTTP header
};

typedef struct sflow_extended_url_s sflow_extended_url_t;

/*
 * Extended NAT data
 *
 * Packet header records report addresses as seen at the sFlowDataSource.
 * The extended_nat structure reports on translated source and/or destination
 * addesses for this packet. If an address was not translated it should 
 * be equal to that reported for the header.
 */

struct sflow_extended_nat_s {
    sflow_ip_t src;    // Source address
    sflow_ip_t dst;    // Destination address
};

typedef struct sflow_extended_nat_s sflow_extended_nat_t;

struct sflow_extended_nat_port_s {
    uint32_t src_port;
    uint32_t dst_port;
};

typedef struct sflow_extended_nat_port_s sflow_extended_nat_port_t;

// Extended MPLS data

struct sflow_label_stack_s {
    uint32_t depth;
    uint32_t* stack; // first entry is top of stack - see RFC 3032 for encoding
};

typedef struct sflow_label_stack_s sflow_label_stack_t;

struct sflow_extended_mpls_s {
    sflow_ip_t next_hop;        // Address of the next hop
    sflow_label_stack_t in_stack;
    sflow_label_stack_t out_stack;
};

typedef struct sflow_extended_mpls_s sflow_extended_mpls_t;

// Additional Extended MPLS data

struct sflow_extended_mpls_tunnel_s {
    sflow_string_t tunnel_lsp_name; // Tunnel name
    uint32_t tunnel_id;             // Tunnel ID
    uint32_t tunnel_cos;            // Tunnel COS value
};

typedef struct sflow_extended_mpls_tunnel_s sflow_extended_mpls_tunnel_t;

struct sflow_extended_mpls_vc_s {
    sflow_string_t vc_instance_name; // VC instance name
    uint32_t vll_vc_id;        // VLL/VC instance ID
    uint32_t vc_label_cos;     // VC Label COS value
};

typedef struct sflow_extended_mpls_vc_s sflow_extended_mpls_vc_t;

/* 
 * Extended MPLS FEC
 * Definitions from MPLS-FTN-STD-MIB mplsFTNTable
 */

struct sflow_extended_mpls_ftn_s {
    sflow_string_t mpls_ftn_descr;
    uint32_t mpls_ftn_mask;
};

typedef struct sflow_extended_mpls_ftn_s sflow_extended_mpls_ftn_t;

/* 
 * Extended MPLS LVP FEC
 * Definition from MPLS-LDP-STD-MIB mplsFecTable
 * Note: mplsFecAddrType, mplsFecAddr information available
 * from packet header
 */

struct sflow_extended_mpls_ldp_fec_s {
    uint32_t mpls_fec_addr_prefix_len;
};

typedef struct sflow_extended_mpls_ldp_fec_s sflow_extended_mpls_ldp_fec_t;

/* Extended VLAN tunnel information 
 *
 * Record outer VLAN encapsulations that have 
 * been stripped. extended_vlantunnel information 
 * should only be reported if all the following conditions are satisfied: 
 * 1. The packet has nested vlan tags, AND 
 * 2. The reporting device is VLAN aware, AND 
 * 3. One or more VLAN tags have been stripped, either 
 *    because they represent proprietary encapsulations, or 
 *    because switch hardware automatically strips the outer VLAN 
 *    encapsulation. 
 *
 * Reporting extended_vlantunnel information is not a substitute for 
 * reporting extended_switch information. extended_switch data must 
 * always be reported to describe the ingress/egress VLAN information 
 * for the packet. The extended_vlantunnel information only applies to 
 * nested VLAN tags, and then only when one or more tags has been 
 * stripped.
 */ 

typedef sflow_label_stack_t sflow_vlan_stack_t;
struct sflow_extended_vlan_tunnel_s { 
    /*
     * List of stripped 802.1Q TPID/TCI layers.
     * Each TPID,TCI pair is represented as a single 32 bit integer.
     * Layers listed from outermost to innermost.
     */
    sflow_vlan_stack_t stack;
};

typedef struct sflow_extended_vlan_tunnel_s sflow_extended_vlan_tunnel_t;

/*
 * IEEE 802.11 Extension structs
 *
 * The 4-byte cipher_suite identifier follows the format of the cipher suite
 * selector value from the 802.11i (TKIP/CCMP amendment to 802.11i)
 * The most significant three bytes contain the OUI and the least significant
 * byte contains the Suite Type.
 *
 * The currently assigned values are:
 *
 * OUI        |Suite type  |Meaning
 * ----------------------------------------------------
 * 00-0F-AC   | 0          | Use group cipher suite
 * 00-0F-AC   | 1          | WEP-40
 * 00-0F-AC   | 2          | TKIP
 * 00-0F-AC   | 3          | Reserved
 * 00-0F-AC   | 4          | CCMP
 * 00-0F-AC   | 5          | WEP-104
 * 00-0F-AC   | 6-255      | Reserved
 * Vendor OUI | Other      | Vendor specific
 * Other      | Any        | Reserved
 * ----------------------------------------------------
 */
typedef uint32_t sflow_cipher_suite_t;

/*
 * Extended WiFi Payload
 * 
 * Used to provide unencrypted version of 802.11 MAC data. If the MAC data is 
 * not encrypted then the agent must not include an extended_wifi_payload 
 * structure.
 *
 * If 802.11 MAC data is encrypted then the sampled_header structure should 
 * only contain the MAC header (since encrypted data cannot be decoded by the 
 * sFlow receiver). If the sFlow agent has access to the unencrypted payload, 
 * it should add an extended_wifi_payload structure containing the unencrypted 
 * data bytes from the sampled packet header, starting at the beginning of the 
 * 802.2 LLC and not including any trailing encryption footers.
 *
 */
// opaque = flow_data; enterprise = 0; format = 1013

struct sflow_extended_wifi_payload_s {
    sflow_cipher_suite_t cipher_suite;
    sflow_sampled_header_t header;
};

typedef struct sflow_extended_wifi_payload_s sflow_extended_wifi_payload_t;

enum sflow_ieee_80211_version_e {
    IEEE_80211_A = 1,
    IEEE_80211_B = 2,
    IEEE_80211_G = 3,
    IEEE_80211_N = 4,
};

typedef enum sflow_ieee_80211_version_e sflow_ieee_80211_version_t;

// opaque = flow_data; enterprise = 0; format = 1014

struct sflow_extended_wifi_rx_s {
    uint32_t ssid_len;
    char* ssid;
    char bssid[6];                      // BSSID
    sflow_ieee_80211_version_t version; // version
    uint32_t channel;                   // channel number
    uint64_t speed;
    uint32_t rsni;                      // received signal to noise ratio, see dot11FrameRprtRSNI
    uint32_t rcpi;                      // received channel power, see dot11FrameRprtLastRCPI
    uint32_t packet_usecs;              // amount of time that packet occupied RF medium.
};

typedef struct sflow_extended_wifi_rx_s sflow_extended_wifi_rx_t;

// opaque = flow_data; enterprise = 0; format = 1015

struct sflow_extended_wifi_tx_s {
    uint32_t ssid_len;
    char* ssid;              // SSID string
    char  bssid[6];             // BSSID
    sflow_ieee_80211_version_t version;    // version
    /*
     * number of transmissions for sampled packet.
     * 0 = unknown
     * 1 = packet was successfully transmitted on first attempt
     * n > 1 = n - 1 retransmissions
     */
    uint32_t transmissions;
    // amount of time that packet occupied RF medium.
    uint32_t packet_duration_us;
    // amount of time that failed packets occupied RF medium.
    uint32_t retrans_duration_us;
    uint32_t channel;         // channel number
    uint64_t speed;
    uint32_t power_mw;           // transmit power in mW.
};

typedef struct sflow_extended_wifi_tx_s sflow_extended_wifi_tx_t;

// Extended 802.11 Aggregation Data

/*
 * A flow_sample of an aggregated frame would consist of:
 *
 * a packet header for the whole frame
 * any other extended structures that apply (e.g. 80211_tx/rx etc.)
 * an extended_wifi_aggregation structure which would contain:
 *   an array of PDU structures
 *
 * A PDU is simply an array of
 * flow records, in the simplest case a packet header for each PDU,
 * but extended structures could be included as well.
 */

// opaque = flow_data; enterprise = 0; format = 1016

struct sflow_extended_aggregation_s {
    uint32_t num_pdus;
    struct sflow_flow_pdu_s* pdus;
};

typedef struct sflow_extended_aggregation_s sflow_extended_aggregation_t;

/* Extended socket information,
 * Must be filled in for all application transactions associated with
 * a network socket. Omit if transaction associated with IPC.
 */

// IPV4 Socket
// opaque = flow_data; enterprise = 0; format = 2100
struct sflow_extended_socket_ipv4_s {
    uint32_t protocol;      // IP Protocol (e.g. TCP = 6, UDP = 17)
    ip4_addr_t local_ip;  // local IP address
    ip4_addr_t remote_ip; // remote IP address
    uint32_t local_port;    // TCP/UDP local port number or equivalent
    uint32_t remote_port;   // TCP/UDP remote port number of equivalent
};

typedef struct sflow_extended_socket_ipv4_s sflow_extended_socket_ipv4_t;

// IPV6 Socket
// opaque = flow_data; enterprise = 0; format = 2101
struct sflow_extended_socket_ipv6_s {
    uint32_t protocol;      // IP Protocol (e.g. TCP = 6, UDP = 17)
    ip6_addr_t local_ip;  // local IP address
    ip6_addr_t remote_ip; // remote IP address
    uint32_t local_port;    // TCP/UDP local port number or equivalent
    uint32_t remote_port;   // TCP/UDP remote port number of equivalent
};

typedef struct sflow_extended_socket_ipv6_s sflow_extended_socket_ipv6_t;

enum sflow_memcache_protocol_e {
    MEMCACHE_PROT_OTHER   = 0,
    MEMCACHE_PROT_ASCII   = 1,
    MEMCACHE_PROT_BINARY  = 2,
};

typedef enum sflow_memcache_protocol_e sflow_memcache_protocol_t;

enum sflow_memcache_command_e {
    MEMCACHE_CMD_OTHER    = 0,
    MEMCACHE_CMD_SET      = 1,
    MEMCACHE_CMD_ADD      = 2,
    MEMCACHE_CMD_REPLACE  = 3,
    MEMCACHE_CMD_APPEND   = 4,
    MEMCACHE_CMD_PREPEND  = 5,
    MEMCACHE_CMD_CAS      = 6,
    MEMCACHE_CMD_GET      = 7,
    MEMCACHE_CMD_GETS     = 8,
    MEMCACHE_CMD_INCR     = 9,
    MEMCACHE_CMD_DECR     = 10,
    MEMCACHE_CMD_DELETE   = 11,
    MEMCACHE_CMD_STATS    = 12,
    MEMCACHE_CMD_FLUSH    = 13,
    MEMCACHE_CMD_VERSION  = 14,
    MEMCACHE_CMD_QUIT     = 15,
    MEMCACHE_CMD_TOUCH    = 16,
};

typedef enum sflow_memcache_command_e sflow_memcache_command_t;

enum sflow_memcache_operation_status_e {
    MEMCACHE_OP_UNKNOWN      = 0,
    MEMCACHE_OP_OK           = 1,
    MEMCACHE_OP_ERROR        = 2,
    MEMCACHE_OP_CLIENT_ERROR = 3,
    MEMCACHE_OP_SERVER_ERROR = 4,
    MEMCACHE_OP_STORED       = 5,
    MEMCACHE_OP_NOT_STORED   = 6,
    MEMCACHE_OP_EXISTS       = 7,
    MEMCACHE_OP_NOT_FOUND    = 8,
    MEMCACHE_OP_DELETED      = 9,
};

typedef enum sflow_memcache_operation_status_e sflow_memcache_operation_status_t;

struct sflow_sampled_memcache_s {
    uint32_t protocol;       // sflow_memcache_prot
    uint32_t command;        // sflow_memcache_cmd
    sflow_string_t key;      // up to 255 chars
    uint32_t nkeys;
    uint32_t value_bytes;
    uint32_t duration_usecs;
    uint32_t status;         // sflow_sampled_memcache_status
};

typedef struct sflow_sampled_memcache_s sflow_sampled_memcache_t;

enum sflow_http_method_e {
    SFLOW_HTTP_OTHER    = 0,
    SFLOW_HTTP_OPTIONS  = 1,
    SFLOW_HTTP_GET      = 2,
    SFLOW_HTTP_HEAD     = 3,
    SFLOW_HTTP_POST     = 4,
    SFLOW_HTTP_PUT      = 5,
    SFLOW_HTTP_DELETE   = 6,
    SFLOW_HTTP_TRACE    = 7,
    SFLOW_HTTP_CONNECT  = 8,
};

typedef enum sflow_http_method_e sflow_http_method_t;

struct sflow_sampled_http_s {
    sflow_http_method_t method;
    uint32_t protocol;        // 1.1=1001
    sflow_string_t uri;       // URI exactly as it came from the client (up to 255 bytes)
    sflow_string_t host;      // Host value from request header (<= 64 bytes)
    sflow_string_t referrer;  // Referer value from request header (<=255 bytes)
    sflow_string_t useragent; // User-Agent value from request header (<= 128 bytes)
    sflow_string_t xff;       // X-Forwarded-For value from request header (<= 64 bytes)
    sflow_string_t authuser;  // RFC 1413 identity of user (<=32 bytes)
    sflow_string_t mimetype;  // Mime-Type (<=64 bytes)
    uint64_t req_bytes;       // Content-Length of request
    uint64_t resp_bytes;      // Content-Length of response
    uint32_t usecs;           // duration of the operation (microseconds)
    uint32_t status;          // HTTP status code
};

typedef struct sflow_sampled_http_s sflow_sampled_http_t;

enum sflow_app_status_e {
    SFLOW_APP_SUCCESS         = 0,
    SFLOW_APP_OTHER           = 1,
    SFLOW_APP_TIMEOUT         = 2,
    SFLOW_APP_INTERNAL_ERROR  = 3,
    SFLOW_APP_BAD_REQUEST     = 4,
    SFLOW_APP_FORBIDDEN       = 5,
    SFLOW_APP_TOO_LARGE       = 6,
    SFLOW_APP_NOT_IMPLEMENTED = 7,
    SFLOW_APP_NOT_FOUND       = 8,
    SFLOW_APP_UNAVAILABLE     = 9,
    SFLOW_APP_UNAUTHORIZED    = 10,
};

typedef enum sflow_app_status_e sflow_app_status_t;

static const char* sflow_app_status_names[] = {
    "SUCCESS",
    "OTHER",
    "TIMEOUT",
    "INTERNAL_ERROR",
    "BAD_REQUEST",
    "FORBIDDEN",
    "TOO_LARGE",
    "NOT_IMPLEMENTED",
    "NOT_FOUND",
    "UNAVAILABLE",
    "UNATHORIZED"
};

// Operation context
struct sflow_sampled_app_ctxt_s {
    sflow_string_t application;
    sflow_string_t operation;    // type of operation (e.g. authorization, payment)
    sflow_string_t attributes;   // specific attributes associated operation
};

typedef struct sflow_sampled_app_ctxt_s sflow_sampled_app_ctxt_t;


// Sampled Enterprise Operation
// opaque = flow_data; enterprise = 0; format = 2202
struct sflow_sampled_app_s {
    sflow_sampled_app_ctxt_t context; // attributes describing the operation
    sflow_string_t status_descr;      // additional text describing status (e.g. "unknown client")
    uint64_t req_bytes;               // size of request body (exclude headers)
    uint64_t resp_bytes;              // size of response body (exclude headers)
    uint32_t duration_usecs;          // duration of the operation (microseconds)
    sflow_app_status_t status;        // status code
};

typedef struct sflow_sampled_app_s sflow_sampled_app_t;

struct sflow_sampled_app_actor_s {
    sflow_string_t actor;
};


struct sflow_extended_vni_s {
    uint32_t vni; // virtual network identifier
};

typedef struct sflow_extended_vni_s sflow_extended_vni_t;

typedef struct sflow_sampled_app_actor_s sflow_sampled_app_actor_t;

struct sflow_extended_decap_s {
    uint32_t inner_header_offset;
};

typedef struct sflow_extended_decap_s sflow_extended_decap_t;

enum sflow_flow_type_tag_e {
    // enterprise = 0, format = ...
    SFLOW_FLOW_HEADER              = 1,    // Packet headers are sampled
    SFLOW_FLOW_ETHERNET            = 2,    // MAC layer information
    SFLOW_FLOW_IPV4                = 3,    // IP version 4 data
    SFLOW_FLOW_IPV6                = 4,    // IP version 6 data
    SFLOW_FLOW_EXT_SWITCH          = 1001, // Extended switch information
    SFLOW_FLOW_EXT_ROUTER          = 1002, // Extended router information
    SFLOW_FLOW_EXT_GATEWAY         = 1003, // Extended gateway router information
    SFLOW_FLOW_EXT_USER            = 1004, // Extended TACAS/RADIUS user information
    SFLOW_FLOW_EXT_URL             = 1005, // Extended URL information
    SFLOW_FLOW_EXT_MPLS            = 1006, // Extended MPLS information
    SFLOW_FLOW_EXT_NAT             = 1007, // Extended NAT information
    SFLOW_FLOW_EXT_MPLS_TUNNEL     = 1008, // additional MPLS information
    SFLOW_FLOW_EXT_MPLS_VC         = 1009,
    SFLOW_FLOW_EXT_MPLS_FTN        = 1010,
    SFLOW_FLOW_EXT_MPLS_LDP_FEC    = 1011,
    SFLOW_FLOW_EXT_VLAN_TUNNEL     = 1012, // VLAN stack
    SFLOW_FLOW_EXT_80211_PAYLOAD   = 1013,
    SFLOW_FLOW_EXT_80211_RX        = 1014,
    SFLOW_FLOW_EXT_80211_TX        = 1015,
    SFLOW_FLOW_EXT_AGGREGATION     = 1016,
    SFLOW_FLOW_EXT_NAT_PORT        = 1020, // Extended NAT port information
    SFLOW_FLOW_EXT_L2_TUNNEL_OUT   = 1021, // http://sflow.org/sflow_tunnels.txt
    SFLOW_FLOW_EXT_L2_TUNNEL_IN    = 1022,
    SFLOW_FLOW_EXT_IPV4_TUNNEL_OUT = 1023,
    SFLOW_FLOW_EXT_IPV4_TUNNEL_IN  = 1024,
    SFLOW_FLOW_EXT_IPV6_TUNNEL_OUT = 1025,
    SFLOW_FLOW_EXT_IPV6_TUNNEL_IN  = 1026,
    SFLOW_FLOW_EXT_DECAP_OUT       = 1027,
    SFLOW_FLOW_EXT_DECAP_IN        = 1028,
    SFLOW_FLOW_EXT_VNI_OUT         = 1029,
    SFLOW_FLOW_EXT_VNI_IN          = 1030,
    SFLOW_FLOW_EXT_SOCKET4         = 2100,
    SFLOW_FLOW_EXT_SOCKET6         = 2101,
    SFLOW_FLOW_EXT_PROXY_SOCKET4   = 2102,
    SFLOW_FLOW_EXT_PROXY_SOCKET6   = 2103,
    SFLOW_FLOW_MEMCACHE            = 2200,
    SFLOW_FLOW_HTTP                = 2201,
    SFLOW_FLOW_APP                 = 2202, // transaction sample
    SFLOW_FLOW_APP_CTXT            = 2203, // enclosing server context
    SFLOW_FLOW_APP_ACTOR_INIT      = 2204, // initiator
    SFLOW_FLOW_APP_ACTOR_TGT       = 2205, // target
    SFLOW_FLOW_HTTP2               = 2206,
};

typedef enum sflow_flow_type_tag_e sflow_flow_type_tag_t;

union sflow_flow_type_u {
    sflow_sampled_header_t header;
    sflow_sampled_ethernet_t ethernet;
    sflow_sampled_ipv4_t ipv4;
    sflow_sampled_ipv6_t ipv6;
    sflow_extended_switch_t eth_switch;
    sflow_extended_router_t router;
    sflow_extended_gateway_t gateway;
    sflow_extended_user_t user;
    sflow_extended_url_t url;
    sflow_extended_nat_t nat;
    sflow_extended_nat_port_t nat_port;
    sflow_extended_mpls_t mpls;
    sflow_extended_mpls_tunnel_t mpls_tunnel;
    sflow_extended_mpls_vc_t mpls_vc;
    sflow_extended_mpls_ftn_t mpls_ftn;
    sflow_extended_mpls_ldp_fec_t mpls_ldp_fec;
    sflow_extended_vlan_tunnel_t vlan_tunnel;
    sflow_extended_wifi_payload_t wifi_payload;
    sflow_extended_wifi_rx_t wifi_rx;
    sflow_extended_wifi_tx_t wifi_tx;
    sflow_extended_aggregation_t aggregation;
    sflow_extended_socket_ipv4_t socket_ipv4;
    sflow_extended_socket_ipv6_t socket_ipv6;
    sflow_sampled_memcache_t memcache;
    sflow_sampled_http_t http;
    sflow_sampled_app_ctxt_t app_ctxt;
    sflow_sampled_app_t app;
    sflow_sampled_app_actor_t app_actor;
    sflow_extended_vni_t tunnel_vni;
    sflow_extended_decap_t tunnel_decap;
};

typedef union sflow_flow_type_u sflow_flow_type_t;

struct sflow_flow_sample_element_s {
    struct sflow_flow_sample_element* next;
    uint32_t tag;  // sflow_flow_type_tag
    uint32_t len;
    sflow_flow_type_t flow_type;
};

typedef struct sflow_flow_sample_element_s sflow_flow_sample_element_t;

enum sflow_sample_tag_e {
    SFLOW_FLOW_SAMPLE = 1,              // enterprise = 0 : format = 1
    SFLOW_COUNTERS_SAMPLE = 2,          // enterprise = 0 : format = 2
    SFLOW_FLOW_SAMPLE_EXPANDED = 3,     // enterprise = 0 : format = 3
    SFLOW_COUNTERS_SAMPLE_EXPANDED = 4, // enterprise = 0 : format = 4
};

typedef enum sflow_sample_tag_e sflow_sample_tag_t;

struct sflow_flow_pdu_s {
    struct sflow_flow_pdu_s* next;
    uint32_t num_elements;
    sflow_flow_sample_element_t* elements;
};

typedef struct sflow_flow_pdu_s sflow_flow_pdu_t;

enum sflow_ds_type_e {
    SFLOW_DS_IFINDEX = 0,
    SFLOW_DS_VLAN    = 1,
    SFLOW_DS_ENTITY  = 2,
};

typedef enum sflow_ds_type_e sflow_ds_type_t;

// Format of a single flow sample

struct sflow_flow_sample_s {
    /* uint32_t tag;    */         /* sflow_sample_tag -- enterprise = 0 : format = 1 */
    /* uint32_t len; */
    uint32_t sequence_number;      // Incremented with each flow sample generated
    uint32_t source_id;            // fsSourceId
    uint32_t sampling_rate;        // fsPacketSamplingRate
    uint32_t sample_pool;          // packets skipped by sampling process + total number of samples
    uint32_t drops;                // Number of times a packet was dropped
    uint32_t input;                // SNMP ifIndex of input interface, 0 if unknown.
    uint32_t output;
    /*
     * SNMP ifIndex of output interface, 0 if unknown.
     *
     * Set most significant bit to indicate
     * multiple destination interfaces (bcast / mcast.
     *
     * Set lower order bits to indicate number of destination 
     * interfaces.
     *
     *
     * Examples:
     * 0x00000002  indicates ifIndex = 2.
     * 0x00000000  ifIndex unknown.
     * 0x80000007  sent to 7 interfaces.
     * 0x80000000  sent to an unknown # of interfaces greater than 1.
     */
    uint32_t num_elements;
    sflow_flow_sample_element_t* elements;
};

typedef struct sflow_flow_sample_s sflow_flow_sample_t;

struct sflow_flow_sample_expanded_s {
    /* uint32_t tag;    */         /* sflow_sample_tag -- enterprise = 0 : format = 1 */
    /* uint32_t len; */
    uint32_t sequence_number;      // Incremented with each flow sample generated
    uint32_t ds_type;              // EXPANDED
    uint32_t ds_index;             // EXPANDED
    uint32_t sampling_rate;        // fsPacketSamplingRate
    uint32_t sample_pool;          // packets skipped by sampling process + total number of samples)
    uint32_t drops;                // Number of times a packet was dropped
    uint32_t input_format;         // EXPANDED
    uint32_t input;                // SNMP ifIndex of input interface, 0 if unknown
    uint32_t output_format;        // EXPANDED
    uint32_t output;               // SNMP ifIndex of output interface, 0 if unknown
    uint32_t num_elements;
    sflow_flow_sample_element_t* elements;
};

typedef struct sflow_flow_sample_expanded_s sflow_flow_sample_expanded_t;

// Counter types

// Generic interface counters - see RFC 1573, RFC 2233
struct sflow_if_counters_s {
    uint32_t ifIndex;
    uint32_t ifType;
    uint64_t ifSpeed;
    /*
     * Derived from MAU MIB (RFC 2668)
     * 0 = unknown
     * 1 = full-duplex
     * 2 = half-duplex
     * 3 = in
     * 4 = out
     */
    uint32_t ifDirection;
    /*
     * bit field with the following bits assigned:
     * bit 0 = ifAdminStatus (0 = down, 1 = up)
     * bit 1 = ifOperStatus (0 = down, 1 = up)
     */
    uint32_t ifStatus;
    uint64_t ifInOctets;
    uint32_t ifInUcastPkts;
    uint32_t ifInMulticastPkts;
    uint32_t ifInBroadcastPkts;
    uint32_t ifInDiscards;
    uint32_t ifInErrors;
    uint32_t ifInUnknownProtos;
    uint64_t ifOutOctets;
    uint32_t ifOutUcastPkts;
    uint32_t ifOutMulticastPkts;
    uint32_t ifOutBroadcastPkts;
    uint32_t ifOutDiscards;
    uint32_t ifOutErrors;
    uint32_t ifPromiscuousMode;
};

typedef struct sflow_if_counters_s sflow_if_counters_t;

// Ethernet interface counters - see RFC 2358
struct sflow_ethernet_counters_s {
    uint32_t dot3StatsAlignmentErrors;
    uint32_t dot3StatsFCSErrors;
    uint32_t dot3StatsSingleCollisionFrames;
    uint32_t dot3StatsMultipleCollisionFrames;
    uint32_t dot3StatsSQETestErrors;
    uint32_t dot3StatsDeferredTransmissions;
    uint32_t dot3StatsLateCollisions;
    uint32_t dot3StatsExcessiveCollisions;
    uint32_t dot3StatsInternalMacTransmitErrors;
    uint32_t dot3StatsCarrierSenseErrors;
    uint32_t dot3StatsFrameTooLongs;
    uint32_t dot3StatsInternalMacReceiveErrors;
    uint32_t dot3StatsSymbolErrors;
};

typedef struct sflow_ethernet_counters_s sflow_ethernet_counters_t;

// Token ring counters - see RFC 1748
struct sflow_tokenring_counters_s {
    uint32_t dot5StatsLineErrors;
    uint32_t dot5StatsBurstErrors;
    uint32_t dot5StatsACErrors;
    uint32_t dot5StatsAbortTransErrors;
    uint32_t dot5StatsInternalErrors;
    uint32_t dot5StatsLostFrameErrors;
    uint32_t dot5StatsReceiveCongestions;
    uint32_t dot5StatsFrameCopiedErrors;
    uint32_t dot5StatsTokenErrors;
    uint32_t dot5StatsSoftErrors;
    uint32_t dot5StatsHardErrors;
    uint32_t dot5StatsSignalLoss;
    uint32_t dot5StatsTransmitBeacons;
    uint32_t dot5StatsRecoverys;
    uint32_t dot5StatsLobeWires;
    uint32_t dot5StatsRemoves;
    uint32_t dot5StatsSingles;
    uint32_t dot5StatsFreqErrors;
};

typedef struct sflow_tokenring_counters_s sflow_tokenring_counters_t;

// 100 BaseVG interface counters - see RFC 2020
struct sflow_vg_counters_s {
    uint32_t dot12InHighPriorityFrames;
    uint64_t dot12InHighPriorityOctets;
    uint32_t dot12InNormPriorityFrames;
    uint64_t dot12InNormPriorityOctets;
    uint32_t dot12InIPMErrors;
    uint32_t dot12InOversizeFrameErrors;
    uint32_t dot12InDataErrors;
    uint32_t dot12InNullAddressedFrames;
    uint32_t dot12OutHighPriorityFrames;
    uint64_t dot12OutHighPriorityOctets;
    uint32_t dot12TransitionIntoTrainings;
    uint64_t dot12HCInHighPriorityOctets;
    uint64_t dot12HCInNormPriorityOctets;
    uint64_t dot12HCOutHighPriorityOctets;
};

typedef struct sflow_vg_counters_s sflow_vg_counters_t;

struct sflow_vlan_counters_s {
    uint32_t vlan_id;
    uint64_t octets;
    uint32_t ucastPkts;
    uint32_t multicastPkts;
    uint32_t broadcastPkts;
    uint32_t discards;
};

typedef struct sflow_vlan_counters_s sflow_vlan_counters_t;

struct sflow_80211_counters_s {
    uint32_t dot11TransmittedFragmentCount;
    uint32_t dot11MulticastTransmittedFrameCount;
    uint32_t dot11FailedCount;
    uint32_t dot11RetryCount;
    uint32_t dot11MultipleRetryCount;
    uint32_t dot11FrameDuplicateCount;
    uint32_t dot11RTSSuccessCount;
    uint32_t dot11RTSFailureCount;
    uint32_t dot11ACKFailureCount;
    uint32_t dot11ReceivedFragmentCount;
    uint32_t dot11MulticastReceivedFrameCount;
    uint32_t dot11FCSErrorCount;
    uint32_t dot11TransmittedFrameCount;
    uint32_t dot11WEPUndecryptableCount;
    uint32_t dot11QoSDiscardedFragmentCount;
    uint32_t dot11AssociatedStationCount;
    uint32_t dot11QoSCFPollsReceivedCount;
    uint32_t dot11QoSCFPollsUnusedCount;
    uint32_t dot11QoSCFPollsUnusableCount;
    uint32_t dot11QoSCFPollsLostCount;
};

typedef struct sflow_80211_counters_s sflow_80211_counters_t;

// Processor Information
// opaque = counter_data; enterprise = 0; format = 1001

struct sflow_processor_counters_s {
    uint32_t five_sec_cpu;  // 5 second average CPU utilization
    uint32_t one_min_cpu;   // 1 minute average CPU utilization
    uint32_t five_min_cpu;  // 5 minute average CPU utilization
    uint64_t total_memory;  // total memory (in bytes)
    uint64_t free_memory;   // free memory (in bytes)
};

typedef struct sflow_processor_counters_s sflow_processor_counters_t;

struct sflow_radio_counters_s {
    uint32_t elapsed_time;         // elapsed time in ms
    uint32_t on_channel_time;      // time in ms spent on channel
    uint32_t on_channel_busy_time; // time in ms spent on channel and busy
};

typedef struct sflow_radio_counters_s sflow_radio_counters_t;

// host sflow

enum sflow_machine_type_e {
    SFLOW_MACHINE_UNKNOWN = 0,
    SFLOW_MACHINE_OTHER   = 1,
    SFLOW_MACHINE_X86     = 2,
    SFLOW_MACHINE_X86_64  = 3,
    SFLOW_MACHINE_IA64    = 4,
    SFLOW_MACHINE_SPARC   = 5,
    SFLOW_MACHINE_ALPHA   = 6,
    SFLOW_MACHINE_POWERPC = 7,
    SFLOW_MACHINE_M68K    = 8,
    SFLOW_MACHINE_MIPS    = 9,
    SFLOW_MACHINE_ARM     = 10,
    SFLOW_MACHINE_HPPA    = 11,
    SFLOW_MACHINE_S390    = 12
};

typedef enum sflow_machine_type_e sflow_machine_type_t;

enum sflow_os_name_e {
    SFLOW_OS_UNKNOWN   = 0,
    SFLOW_OS_OTHER     = 1,
    SFLOW_OS_LINUX     = 2,
    SFLOW_OS_WINDOWS   = 3,
    SFLOW_OS_DARWIN    = 4,
    SFLOW_OS_HPUX      = 5,
    SFLOW_OS_AIX       = 6,
    SFLOW_OS_DRAGONFLY = 7,
    SFLOW_OS_FREEBSD   = 8,
    SFLOW_OS_NETBSD    = 9,
    SFLOW_OS_OPENBSD   = 10,
    SFLOW_OS_OSF       = 11,
    SFLOW_OS_SOLARIS   = 12
};

typedef enum sflow_os_name_e sflow_os_name_t;

struct sflow_host_id_s {
    sflow_string_t host_name;
    uint8_t uuid[16];
    uint32_t machine_type; // enum sflow_machine_type
    uint32_t os_name;      // enum sflow_os_name
    sflow_string_t os_release;  // max len 32 bytes
};

typedef struct sflow_host_id_s sflow_host_id_t;

struct sflow_adapter_s {
    uint32_t ifIndex;
    uint32_t num_macs;
    sflow_mac_address_t macs[1];
};

typedef struct sflow_adapter_s sflow_adapter_t;

struct sflow_adapter_list_s {
    uint32_t capacity;
    uint32_t num_adapters;
    sflow_adapter_t** adapters;
};

typedef struct sflow_adapter_list_s sflow_adapter_list_t;

struct sflow_host_parent_s {
    uint32_t ds_type;        // sFlowDataSource class
    uint32_t ds_index;       // sFlowDataSource index
};

typedef struct sflow_host_parent_s sflow_host_parent_t;

struct sflow_host_cpu_counters_s {
    float load_one;          // 1 minute load avg.
    float load_five;         // 5 minute load avg.
    float load_fifteen;      // 15 minute load avg.
    uint32_t proc_run;       // running threads
    uint32_t proc_total;     // total threads
    uint32_t cpu_num;        // # CPU cores
    uint32_t cpu_speed;      // speed in MHz of CPU
    uint32_t uptime;         // seconds since last reboot
    uint32_t cpu_user;       // time executing in user mode processes (ms)
    uint32_t cpu_nice;       // time executing niced processs (ms)
    uint32_t cpu_system;     // time executing kernel mode processes (ms)
    uint32_t cpu_idle;       // idle time (ms)
    uint32_t cpu_wio;        // time waiting for I/O to complete (ms)
    uint32_t cpu_intr;       // time servicing interrupts (ms)
    uint32_t cpu_sintr;      // time servicing softirqs (ms)
    uint32_t interrupts;     // interrupt count
    uint32_t contexts;       // context switch count
    uint32_t cpu_steal;      // time spent in other OS instances (virtual env) (ms)
    uint32_t cpu_guest;      // time spent running vcpu for guest OS
    uint32_t cpu_guest_nice; // time spent running vcpu for "niced" guest OS
};

typedef struct sflow_host_cpu_counters_s sflow_host_cpu_counters_t;

struct sflow_host_mem_counters_s {
    uint64_t mem_total;    // total bytes
    uint64_t mem_free;     // free bytes
    uint64_t mem_shared;   // shared bytes
    uint64_t mem_buffers;  // buffers bytes
    uint64_t mem_cached;   // cached bytes
    uint64_t swap_total;   // swap total bytes
    uint64_t swap_free;    // swap free bytes
    uint32_t page_in;      // page in count
    uint32_t page_out;     // page out count
    uint32_t swap_in;      // swap in count
    uint32_t swap_out;     // swap out count
};

typedef struct sflow_host_mem_counters_s sflow_host_mem_counters_t;

struct sflow_host_disk_counters_s {
    uint64_t disk_total;
    uint64_t disk_free;
    uint32_t part_max_used;   // as percent * 100, so 100==1%
    uint32_t reads;           // reads issued
    uint64_t bytes_read;      // bytes read
    uint32_t read_time;       // read time (ms)
    uint32_t writes;          // writes completed
    uint64_t bytes_written;   // bytes written
    uint32_t write_time;      // write time (ms)
};

typedef struct sflow_host_disk_counters_s sflow_host_disk_counters_t;

struct sflow_host_nio_counters_s {
    uint64_t bytes_in;
    uint32_t pkts_in;
    uint32_t errs_in;
    uint32_t drops_in;
    uint64_t bytes_out;
    uint32_t pkts_out;
    uint32_t errs_out;
    uint32_t drops_out;
};

typedef struct sflow_host_nio_counters_s sflow_host_nio_counters_t;

// IP Group - see MIB-II
// opaque = counter_data; enterprise = 0; format = 2007
struct sflow_host_ip_counters_s {
    uint32_t ipForwarding;
    uint32_t ipDefaultTTL;
    uint32_t ipInReceives;
    uint32_t ipInHdrErrors;
    uint32_t ipInAddrErrors;
    uint32_t ipForwDatagrams;
    uint32_t ipInUnknownProtos;
    uint32_t ipInDiscards;
    uint32_t ipInDelivers;
    uint32_t ipOutRequests;
    uint32_t ipOutDiscards;
    uint32_t ipOutNoRoutes;
    uint32_t ipReasmTimeout;
    uint32_t ipReasmReqds;
    uint32_t ipReasmOKs;
    uint32_t ipReasmFails;
    uint32_t ipFragOKs;
    uint32_t ipFragFails;
    uint32_t ipFragCreates;
};

typedef struct sflow_host_ip_counters_s sflow_host_ip_counters_t;

// ICMP Group - see MIB-II
// opaque = counter_data; enterprise = 0; format = 2008
struct sflow_host_icmp_counters_s {
    uint32_t icmpInMsgs;
    uint32_t icmpInErrors;
    uint32_t icmpInDestUnreachs;
    uint32_t icmpInTimeExcds;
    uint32_t icmpInParamProbs;
    uint32_t icmpInSrcQuenchs;
    uint32_t icmpInRedirects;
    uint32_t icmpInEchos;
    uint32_t icmpInEchoReps;
    uint32_t icmpInTimestamps;
    uint32_t icmpInAddrMasks;
    uint32_t icmpInAddrMaskReps;
    uint32_t icmpOutMsgs;
    uint32_t icmpOutErrors;
    uint32_t icmpOutDestUnreachs;
    uint32_t icmpOutTimeExcds;
    uint32_t icmpOutParamProbs;
    uint32_t icmpOutSrcQuenchs;
    uint32_t icmpOutRedirects;
    uint32_t icmpOutEchos;
    uint32_t icmpOutEchoReps;
    uint32_t icmpOutTimestamps;
    uint32_t icmpOutTimestampReps;
    uint32_t icmpOutAddrMasks;
    uint32_t icmpOutAddrMaskReps;
};

typedef struct sflow_host_icmp_counters_s sflow_host_icmp_counters_t;

// TCP Group - see MIB-II
// opaque = counter_data; enterprise = 0; format = 2009
struct sflow_host_tcp_counters_s {
    uint32_t tcpRtoAlgorithm;
    uint32_t tcpRtoMin;
    uint32_t tcpRtoMax;
    uint32_t tcpMaxConn;
    uint32_t tcpActiveOpens;
    uint32_t tcpPassiveOpens;
    uint32_t tcpAttemptFails;
    uint32_t tcpEstabResets;
    uint32_t tcpCurrEstab;
    uint32_t tcpInSegs;
    uint32_t tcpOutSegs;
    uint32_t tcpRetransSegs;
    uint32_t tcpInErrs;
    uint32_t tcpOutRsts;
    uint32_t tcpInCsumErrors;
};

typedef struct sflow_host_tcp_counters_s sflow_host_tcp_counters_t;

// UDP Group - see MIB-II
// opaque = counter_data; enterprise = 0; format = 2010
struct sflow_host_udp_counters_s {
    uint32_t udpInDatagrams;
    uint32_t udpNoPorts;
    uint32_t udpInErrors;
    uint32_t udpOutDatagrams;
    uint32_t udpRcvbufErrors;
    uint32_t udpSndbufErrors;
    uint32_t udpInCsumErrors;
};

typedef struct sflow_host_udp_counters_s sflow_host_udp_counters_t;

// Virtual Node Statistics
// opaque = counter_data; enterprise = 0; format = 2100

struct sflow_virtual_node_counters_s {
    uint32_t mhz;           // expected CPU frequency
    uint32_t cpus;          // the number of active CPUs
    uint64_t memory;        // memory size in bytes
    uint64_t memory_free;   // unassigned memory in bytes
    uint32_t num_domains;   // number of active domains
};

typedef struct sflow_virtual_node_counters_s sflow_virtual_node_counters_t;

// Virtual Domain Statistics
// opaque = counter_data; enterprise = 0; format = 2101

// virtual_domain_state imported from libvirt.h
enum sflow_virtual_domain_state {
    SFLOW_VIRT_DOMAIN_NOSTATE  = 0, // no state
    SFLOW_VIRT_DOMAIN_RUNNING  = 1, // the domain is running
    SFLOW_VIRT_DOMAIN_BLOCKED  = 2, // the domain is blocked on resource
    SFLOW_VIRT_DOMAIN_PAUSED   = 3, // the domain is paused by user
    SFLOW_VIRT_DOMAIN_SHUTDOWN = 4, // the domain is being shut down
    SFLOW_VIRT_DOMAIN_SHUTOFF  = 5, // the domain is shut off
    SFLOW_VIRT_DOMAIN_CRASHED  = 6, // the domain is crashed
};

struct sflow_virtual_cpu_counters_s {
    uint32_t state;     // sflow_virtual_domain_state
    uint32_t cpu_time;  // the CPU time used in ms
    uint32_t cpu_count; // number of virtual CPUs for the domain
};

typedef struct sflow_virtual_cpu_counters_s sflow_virtual_cpu_counters_t;

// Virtual Domain Memory statistics
// opaque = counter_data; enterprise = 0; format = 2102

struct sflow_virtual_mem_counters_s {
    uint64_t memory;      // memory in bytes used by domain
    uint64_t maxMemory;   // memory in bytes allowed
};

typedef struct sflow_virtual_mem_counters_s sflow_virtual_mem_counters_t;

// Virtual Domain Disk statistics
// opaque = counter_data; enterprise = 0; format = 2103

struct sflow_virtual_disk_counters_s {
    uint64_t capacity;   // logical size in bytes
    uint64_t allocation; // current allocation in bytes
    uint64_t available;  // remaining free bytes
    uint32_t rd_req;     // number of read requests
    uint64_t rd_bytes;   // number of read bytes
    uint32_t wr_req;     // number of write requests
    uint64_t wr_bytes;   // number of  written bytes
    uint32_t errs;       // read/write errors
};

typedef struct sflow_virtual_disk_counters_s sflow_virtual_disk_counters_t;

// Virtual Domain Network statistics
// opaque = counter_data; enterprise = 0; format = 2104

struct sflow_virtual_nio_counters_s {
    uint64_t bytes_in;
    uint32_t pkts_in;
    uint32_t errs_in;
    uint32_t drops_in;
    uint64_t bytes_out;
    uint32_t pkts_out;
    uint32_t errs_out;
    uint32_t drops_out;
};

typedef struct sflow_virtual_nio_counters_s sflow_virtual_nio_counters_t;

// NVML statistics
// opaque = counter_data; enterprise = 5703, format=1
struct sflow_gpu_nvml_s {
    uint32_t device_count;  // see nvmlGetDeviceCount
    uint32_t processes;     // see nvmlDeviceGetComputeRunningProcesses
    uint32_t gpu_time;      // total milliseconds in which one or more kernels was executing on GPU
    uint32_t mem_time;      // total milliseconds during which global device memory was being read/written
    uint64_t mem_total;     // bytes. see nvmlDeviceGetMemoryInfo
    uint64_t mem_free;      // bytes. see nvmlDeviceGetMemoryInfo
    uint32_t ecc_errors;    // see nvmlDeviceGetTotalEccErrors
    uint32_t energy;        // mJ. see nvmlDeviceGetPowerUsage
    uint32_t temperature;   // C. maximum across devices - see nvmlDeviceGetTemperature
    uint32_t fan_speed;     // %. maximum across devices - see nvmlDeviceGetFanSpeed
};

typedef struct sflow_gpu_nvml_s sflow_gpu_nvml_t;

// Broadcom switch ASIC table utilizations
// opaque = counter_data; enterprise = 4413 (Broadcom); format = 3
struct sflow_bcm_tables_s {
    uint32_t host_entries;
    uint32_t host_entries_max;
    uint32_t ipv4_entries;
    uint32_t ipv4_entries_max;
    uint32_t ipv6_entries;
    uint32_t ipv6_entries_max;
    uint32_t ipv4_ipv6_entries;
    uint32_t ipv4_ipv6_entries_max;
    uint32_t long_ipv6_entries;
    uint32_t long_ipv6_entries_max;
    uint32_t total_routes;
    uint32_t total_routes_max;
    uint32_t ecmp_next_hops;
    uint32_t ecmp_next_hops_max;
    uint32_t mac_entries;
    uint32_t mac_entries_max;
    uint32_t ipv4_neighbors;
    uint32_t ipv6_neighbors;
    uint32_t ipv4_routes;
    uint32_t ipv6_routes;
    uint32_t acl_ingress_entries;
    uint32_t acl_ingress_entries_max;
    uint32_t acl_ingress_counters;
    uint32_t acl_ingress_counters_max;
    uint32_t acl_ingress_meters;
    uint32_t acl_ingress_meters_max;
    uint32_t acl_ingress_slices;
    uint32_t acl_ingress_slices_max;
    uint32_t acl_egress_entries;
    uint32_t acl_egress_entries_max;
    uint32_t acl_egress_counters;
    uint32_t acl_egress_counters_max;
    uint32_t acl_egress_meters;
    uint32_t acl_egress_meters_max;
    uint32_t acl_egress_slices;
    uint32_t acl_egress_slices_max;
};

typedef struct sflow_bcm_tables_s sflow_bcm_tables_t;

// memcache
// opaque = counter_data; enterprise = 0; format = 2204

struct sflow_memcache_counters_s {
    uint32_t uptime;          // not in 2204
    uint32_t rusage_user;     // not in 2204
    uint32_t rusage_system;   // not in 2204
    uint32_t cmd_get;         // not in 2204
    uint32_t accepting_conns; // not in 2204
    uint32_t cmd_set;
    uint32_t cmd_touch;       // added for 2204
    uint32_t cmd_flush;
    uint32_t get_hits;
    uint32_t get_misses;
    uint32_t delete_hits;
    uint32_t delete_misses;
    uint32_t incr_hits;
    uint32_t incr_misses;
    uint32_t decr_hits;
    uint32_t decr_misses;
    uint32_t cas_hits;
    uint32_t cas_misses;
    uint32_t cas_badval;
    uint32_t auth_cmds;
    uint32_t auth_errors;
    uint32_t threads;
    uint32_t conn_yields;
    uint32_t listen_disabled_num;
    uint32_t curr_connections;
    uint32_t rejected_connections; // added for 2204
    uint32_t total_connections;
    uint32_t connection_structures;
    uint32_t evictions;
    uint32_t reclaimed; // added for 2204
    uint32_t curr_items;
    uint32_t total_items;
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint64_t bytes;
    uint64_t limit_maxbytes; // converted to 64-bit for structure 2204
};

typedef struct sflow_memcache_counters_s sflow_memcache_counters_t;

// http
// opaque = counter_data; enterprise = 0; format = 2201
struct sflow_http_counters_s {
    uint32_t method_option_count;
    uint32_t method_get_count;
    uint32_t method_head_count;
    uint32_t method_post_count;
    uint32_t method_put_count;
    uint32_t method_delete_count;
    uint32_t method_trace_count;
    uint32_t methd_connect_count;
    uint32_t method_other_count;
    uint32_t status_1XX_count;
    uint32_t status_2XX_count;
    uint32_t status_3XX_count;
    uint32_t status_4XX_count;
    uint32_t status_5XX_count;
    uint32_t status_other_count;
};

typedef struct sflow_http_counters_s sflow_http_counters_t;

// Enterprise counters
// opaque = counter_data; enterprise = 0; format = 2202
struct sflow_app_counters_s {
    sflow_string_t application;
    uint32_t status_ok;
    uint32_t errors_other;
    uint32_t errors_timeout;
    uint32_t errors_internal_error;
    uint32_t errors_bad_request;
    uint32_t errors_forbidden;
    uint32_t errors_too_large;
    uint32_t errors_not_implemented;
    uint32_t errors_not_found;
    uint32_t errors_unavailable;
    uint32_t errors_unauthorized;
};

typedef struct sflow_app_counters_s sflow_app_counters_t;

// Enterprise resource counters
// opaque = counter_data; enterprise = 0; format = 2203
struct sflow_app_resources_s {
    uint32_t user_time;   // in milliseconds
    uint32_t system_time; // in milliseconds
    uint64_t mem_used;
    uint64_t mem_max;
    uint32_t fd_open;
    uint32_t fd_max;
    uint32_t conn_open;
    uint32_t conn_max;
};

typedef struct sflow_app_resources_s sflow_app_resources_t;

// Enterprise application workers
// opaque = counter_data; enterprise = 0; format = 2206
struct sflow_app_workers_s {
    uint32_t workers_active;
    uint32_t workers_idle;
    uint32_t workers_max;
    uint32_t req_delayed;
    uint32_t req_dropped;
};

typedef struct sflow_app_workers_s sflow_app_workers_t;

struct sflow_jvm_id_s {
    sflow_string_t vm_name;
    sflow_string_t vm_vendor;
    sflow_string_t vm_version;
};

typedef struct sflow_jvm_id_s sflow_jvm_id_t;

struct sflow_jmx_counters_s {
    uint64_t hmem_initial;
    uint64_t hmem_used;
    uint64_t hmem_committed;
    uint64_t hmem_max;
    uint64_t nhmem_initial;
    uint64_t nhmem_used;
    uint64_t nhmem_committed;
    uint64_t nhmem_max;
    uint32_t gc_count;
    uint32_t gc_ms;
    uint32_t cls_loaded;
    uint32_t cls_total;
    uint32_t cls_unloaded;
    uint32_t comp_ms;
    uint32_t thread_live;
    uint32_t thread_daemon;
    uint32_t thread_started;
    uint32_t fds_open;
    uint32_t fds_max;
};

typedef struct sflow_jmx_counters_s sflow_jmx_counters_t;

struct sflow_vdi_counters_s {
    uint32_t sessions_current;  // number of current sessions
    uint32_t sessions_total;    // total sessions started
    uint32_t sessions_duration; // cumulative session time (in seconds) across all sessions
    uint32_t rx_bytes;          // total bytes received
    uint32_t tx_bytes;          // total bytes sent
    uint32_t rx_packets;        // total packet received
    uint32_t tx_packets;        // total packets sent
    uint32_t rx_packets_lost;   // total received packets lost
    uint32_t tx_packets_lost;   // total sent packets lost
    uint32_t rtt_min_ms;        // minimum RTT across all sessions in ms
    uint32_t rtt_max_ms;        // maximum RTT across all sessions in ms
    uint32_t rtt_avg_ms;        // average RTT across all sessions in ms
    uint32_t audio_rx_bytes;    // total bytes of audio data received
    uint32_t audio_tx_bytes;    // total bytes of audio data sent
    uint32_t audio_tx_limit;    // limit on audio transmission in bps
    uint32_t img_rx_bytes;      // total bytes of imaging data recieved
    uint32_t img_tx_bytes;      // total bytes of imaging data sent
    uint32_t img_frames;        // total image frames encoded
    uint32_t img_qual_min;      // minimum image quality across all sessions, 0 to 100
    uint32_t img_qual_max;      // maximum image quality across all sessions, 0 to 100
    uint32_t img_qual_avg;      // average image quality across all sessions, 0 to 100
    uint32_t usb_rx_bytes;      // total bytes of usb data received
    uint32_t usb_tx_bytes;      // total bytes of usb data sent
};

typedef struct sflow_vdi_counters_s sflow_vdi_counters_t;

// LAG Port Statistics - see IEEE8023-LAG-MIB
// opaque = counter_data; enterprise = 0; format = 7
union sflow_lacp_port_state_u {
    uint32_t all;
    struct {
        uint8_t actorAdmin;
        uint8_t actorOper;
        uint8_t partnerAdmin;
        uint8_t partnerOper;
    } v;
};

typedef union sflow_lacp_port_state_u sflow_lacp_port_state_t;

struct sflow_lacp_counters_s {
    uint8_t actorSystemID[ETHER_ALEN_PADDED];
    uint8_t partnerSystemID[ETHER_ALEN_PADDED];
    uint32_t attachedAggID;
    sflow_lacp_port_state_t portState;
    uint32_t LACPDUsRx;
    uint32_t markerPDUsRx;
    uint32_t markerResponsePDUsRx;
    uint32_t unknownRx;
    uint32_t illegalRx;
    uint32_t LACPDUsTx;
    uint32_t markerPDUsTx;
    uint32_t markerResponsePDUsTx;
};

typedef struct sflow_lacp_counters_s sflow_lacp_counters_t;

// port name
// opaque = counter_data; enterprise = 0; format = 1005
struct sflow_port_name_s {
    sflow_string_t port_name;
};

typedef struct sflow_port_name_s sflow_port_name_t;

// Counters data

enum sflow_counters_type_tag_e {
    /* enterprise = 0, format = ... */
    SFLOW_COUNTERS_GENERIC        = 1,
    SFLOW_COUNTERS_ETHERNET       = 2,
    SFLOW_COUNTERS_TOKENRING     = 3,
    SFLOW_COUNTERS_VG             = 4,
    SFLOW_COUNTERS_VLAN           = 5,
    SFLOW_COUNTERS_80211          = 6,
    SFLOW_COUNTERS_LACP           = 7,
    SFLOW_COUNTERS_PROCESSOR      = 1001,
    SFLOW_COUNTERS_RADIO          = 1002,
    SFLOW_COUNTERS_PORT_NAME      = 1005,
    SFLOW_COUNTERS_HOST_ID        = 2000, // host id
    SFLOW_COUNTERS_ADAPTERS       = 2001, // host adapters
    SFLOW_COUNTERS_HOST_PARENT    = 2002, // host parent
    SFLOW_COUNTERS_HOST_CPU       = 2003, // host cpu
    SFLOW_COUNTERS_HOST_MEM       = 2004, // host memory
    SFLOW_COUNTERS_HOST_DISK      = 2005, // host storage I/O
    SFLOW_COUNTERS_HOST_NIO       = 2006, // host network I/O
    SFLOW_COUNTERS_HOST_IP        = 2007,
    SFLOW_COUNTERS_HOST_ICMP      = 2008,
    SFLOW_COUNTERS_HOST_TCP       = 2009,
    SFLOW_COUNTERS_HOST_UDP       = 2010,
    SFLOW_COUNTERS_VIRT_NODE      = 2100, // host virt node
    SFLOW_COUNTERS_VIRT_CPU       = 2101, // host virt cpu
    SFLOW_COUNTERS_VIRT_MEM       = 2102, // host virt mem
    SFLOW_COUNTERS_VIRT_DISK      = 2103, // host virt storage
    SFLOW_COUNTERS_VIRT_NIO       = 2104, // host virt network I/O
    SFLOW_COUNTERS_JVM            = 2105, // java runtime
    SFLOW_COUNTERS_JMX            = 2106, // java JMX stats
    SFLOW_COUNTERS_MEMCACHE       = 2200, // memcached (deprecated)
    SFLOW_COUNTERS_HTTP           = 2201, // http
    SFLOW_COUNTERS_APP            = 2202,
    SFLOW_COUNTERS_APP_RESOURCES  = 2203,
    SFLOW_COUNTERS_MEMCACHE2      = 2204, // memcached
    SFLOW_COUNTERS_VDI            = 2205,
    SFLOW_COUNTERS_APP_WORKERS    = 2206,
    SFLOW_COUNTERS_GPU_NVML       = (5703 << 12) + 1, // = 23359489
    SFLOW_COUNTERS_BCM_TABLES     = (4413 << 12) + 3, // = 18075651
};

typedef enum sflow_counters_type_tag_e sflow_counters_type_tag_t;

union sflow_counters_type_u {
    sflow_if_counters_t if_counters;
    sflow_ethernet_counters_t ethernet;
    sflow_tokenring_counters_t tokenring;
    sflow_vg_counters_t vg;
    sflow_vlan_counters_t vlan;
    sflow_80211_counters_t c_80211;
    sflow_processor_counters_t processor;
    sflow_port_name_t port_name;
    sflow_radio_counters_t radio;
    sflow_host_id_t host_id;
    sflow_adapter_list_t* adapters;
    sflow_host_parent_t host_parent;
    sflow_host_cpu_counters_t host_cpu;
    sflow_host_mem_counters_t host_mem;
    sflow_host_disk_counters_t host_disk;
    sflow_host_nio_counters_t host_nio;
    sflow_host_ip_counters_t host_ip;
    sflow_host_icmp_counters_t host_icmp;
    sflow_host_tcp_counters_t host_tcp;
    sflow_host_udp_counters_t host_udp;
    sflow_virtual_node_counters_t virtual_node;
    sflow_virtual_cpu_counters_t virtual_cpu;
    sflow_virtual_mem_counters_t virtual_mem;
    sflow_virtual_disk_counters_t virtual_disk;
    sflow_virtual_nio_counters_t virtual_nio;
    sflow_gpu_nvml_t gpu_nvml;
    sflow_bcm_tables_t bcm_tables;
    sflow_memcache_counters_t memcache;
    sflow_http_counters_t http;
    sflow_app_counters_t app;
    sflow_app_resources_t app_resources;
    sflow_app_workers_t app_workers;
    sflow_jvm_id_t jvm;
    sflow_jmx_counters_t jmx;
    sflow_vdi_counters_t vdi;
    sflow_lacp_counters_t lacp;
};

typedef union sflow_counters_type_u sflow_counters_type_t;

struct sflow_counters_sample_element_s {
    struct sflow_counters_sample_element_s* next; // linked list
    uint32_t tag; // sflow_counters_type_tag
    uint32_t len;
    sflow_counters_type_t counter_block;
};

typedef struct sflow_counters_sample_element_s sflow_counters_sample_element_t;

struct sflow_counters_sample_s {
    /* uint32_t tag;    */       /* sflow_sample_tag -- enterprise = 0 : format = 2 */
    /* uint32_t len; */
    uint32_t sequence_number;    // Incremented with each counters sample generated by this source_id
    uint32_t source_id;          // fsSourceId
    uint32_t num_elements;
    sflow_counters_sample_element_t* elements;
};

typedef struct sflow_counters_sample_s sflow_counters_sample_t;

struct sflow_counters_sample_expanded_s {
    /* uint32_t tag;    */       /* sflow_sample_tag -- enterprise = 0 : format = 2 */
    /* uint32_t len; */
    uint32_t sequence_number;    // Incremented with each counters sample generated by this source_id
    uint32_t ds_type;            // EXPANDED
    uint32_t ds_index;           // EXPANDED
    uint32_t num_elements;
    sflow_counters_sample_element_t* elements;
};

typedef struct sflow_counters_sample_expanded_s sflow_counters_sample_expanded_t;

// Format of a sample datagram
enum sflow_datagram_version_e {
    SFLOW_DATAGRAM_VERSION_2 = 2,
    SFLOW_DATAGRAM_VERSION_4 = 4,
    SFLOW_DATAGRAM_VERSION_5 = 5,
};

typedef enum sflow_datagram_version_e sflow_datagram_version_t;

struct sflow_sample_datagram_hdr_s {
    uint32_t datagram_version;      // (enum sflow_Datagram_version) = VERSION_5 = 5
    sflow_ip_t agent_ip;       // IP address of sampling agent
    /*
     * Used to distinguishing between datagram
     * streams from separate agent sub entities
     * within an device.
     */
    uint32_t sub_agent_id;
    uint32_t sequence_number;       // Incremented with each sample datagram generated
    uint32_t uptime;                // current time (ms since last boot at packet TX
    uint32_t num_records;           // Number of TLV flow/counter records to follow
};

typedef struct sflow_sample_datagram_hdr_s sflow_sample_datagram_hdr_t;

typedef struct sflow_sample_data_u sflow_sample_data_t;

struct sflow_sample_s {
    uint32_t sflow_version;
    sflow_ip_t source_ip;
    sflow_ip_t agent_ip;
    uint32_t agent_sub_id;
    uint32_t packet_seq_num;
    uint32_t sys_up_time;

    // the raw pdu
    uint8_t* raw_sample;
    size_t raw_sample_len;
    uint8_t* end8;

    // decode cursor
    union {
        uint8_t* offset8;
        uint32_t* offset32;
    };

    uint32_t sample_type;
    union {
        uint32_t data_format;
        sflow_counters_type_tag_t counters_type;
        sflow_flow_type_tag_t flow_type;
    };

    uint32_t sample_seq_num;
    uint32_t ds_type;
    uint32_t ds_index;
    uint32_t sample_rate;
    uint32_t sample_pool;
    uint32_t drop_count;

    // ports
    uint32_t input_port_format;
    uint32_t input_port;
    uint32_t output_port_format;
    uint32_t output_port;

    // generic interface counter sample
    sflow_counters_type_t* counters;

    // the sampled header
    sflow_sampled_header_t header;

    // header decode
    int is_ipv4;
    size_t ipv4_offset;
    int is_ipv6;
    size_t ipv6_offset;
    size_t payload_offset;
    
    // ethernet
    uint32_t eth_type;
    uint32_t eth_len;
    uint8_t src_eth[ETHER_ALEN];
    uint8_t dst_eth[ETHER_ALEN];

    // 802.11
    uint8_t tx_eth[ETHER_ALEN];
    uint8_t rx_eth[ETHER_ALEN];

    // vlan
    uint32_t rx_vlan;
    uint32_t rx_priority;
    uint32_t internal_priority;
    uint32_t tx_vlan;
    uint32_t tx_priority;
    int vlan_filter_reject;

    // IP, TCP, UDP
    sflow_ip_t src_ip;
    sflow_ip_t dst_ip;
    uint32_t ip_protocol;
    uint32_t ip_tos;
    uint32_t ip_tot_len;
    uint32_t ip_ttl;
    uint32_t ip_label;
    uint32_t ip_fragoff;
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t tcp_flags;
    uint32_t udp_len;

    // extended data fields
    uint32_t num_extended;
    uint32_t extended_data_tag;

    // IP forwarding info
    sflow_ip_t next_hop;
    uint32_t src_mask;
    uint32_t dst_mask;

    // BGP info
    sflow_ip_t bgp_next_hop;
    uint32_t my_as;
    uint32_t src_as;
    uint32_t src_peer_as;
    uint32_t dst_as_path_len;
    uint32_t* dst_as_path;
    uint32_t dst_peer_as;
    uint32_t dst_as;

    uint32_t communities_len;
    uint32_t* communities;
    uint32_t local_pref;

    // user id
    uint32_t src_user_charset;
    uint32_t src_user_len;
    char src_user[SA_MAX_EXTENDED_USER_LEN+1];
    uint32_t dst_user_charset;
    uint32_t dst_user_len;
    char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

    // URL
    char client[SS_IPV6_STR_MAX];
    uint32_t url_direction;
    uint32_t url_len;
    char url[SA_MAX_EXTENDED_URL_LEN+1];
    uint32_t host_len;
    char host[SA_MAX_EXTENDED_HOST_LEN+1];

    // MPLS
    sflow_ip_t mpls_next_hop;

    // NAT
    sflow_ip_t nat_src_ip;
    sflow_ip_t nat_dst_ip;
    uint32_t nat_src_port;
    uint32_t nat_dst_port;
};

typedef struct sflow_sample_s sflow_sample_t;

typedef void (*sflow_sample_cb_t) (sflow_sample_t* sample, uint32_t s_index, uint32_t e_index);
extern sflow_sample_cb_t sflow_sample_cb;

/* BEGIN PROTOTYPES */

void sflow_decode_link_layer(sflow_sample_t* sample);
void sflow_decode_mac_80211(sflow_sample_t* sample);
void sflow_decode_ip_l4(sflow_sample_t* sample, uint8_t* ptr);
void sflow_decode_ipv4(sflow_sample_t* sample);
void sflow_decode_ipv6(sflow_sample_t* sample);
void sflow_read_extended_switch(sflow_sample_t* sample);
void sflow_read_extended_router(sflow_sample_t* sample);
void sflow_read_extended_gateway(sflow_sample_t* sample);
void sflow_read_extended_user(sflow_sample_t* sample);
void sflow_read_extended_url(sflow_sample_t* sample);
void sflow_read_mpls_label_stack(sflow_sample_t* sample, char* field_name);
void sflow_read_extended_mpls(sflow_sample_t* sample);
void sflow_read_extended_nat(sflow_sample_t* sample);
void sflow_read_extended_nat_port(sflow_sample_t* sample);
void sflow_read_extended_mpls_tunnel(sflow_sample_t* sample);
void sflow_read_extended_mpls_vc(sflow_sample_t* sample);
void sflow_read_extended_mpls_ftn(sflow_sample_t* sample);
void sflow_read_extended_mpls_ldp_fec(sflow_sample_t* sample);
void sflow_read_extended_vlan_tunnel(sflow_sample_t* sample);
void sflow_read_extended_wifi_payload(sflow_sample_t* sample);
void sflow_read_extended_wifi_rx(sflow_sample_t* sample);
void sflow_read_extended_wifi_tx(sflow_sample_t* sample);
void sflow_read_extended_aggregation(sflow_sample_t* sample);
void sflow_read_header(sflow_sample_t* sample);
void sflow_read_ethernet(sflow_sample_t* sample, char* prefix);
void sflow_read_ipv4(sflow_sample_t* sample, char* prefix);
void sflow_read_ipv6(sflow_sample_t* sample, char* prefix);
void sflow_read_memcache(sflow_sample_t* sample);
void sflow_read_http(sflow_sample_t* sample);
void sflow_read_app(sflow_sample_t* sample);
void sflow_read_app_ctxt(sflow_sample_t* sample);
void sflow_read_app_actor_init(sflow_sample_t* sample);
void sflow_read_app_actor_tgt(sflow_sample_t* sample);
void sflow_read_extended_socket4(sflow_sample_t* sample);
void sflow_read_extended_proxy_socket4(sflow_sample_t* sample);
void sflow_read_extended_socket6(sflow_sample_t* sample);
void sflow_read_extended_proxy_socket6(sflow_sample_t* sample);
void sflow_read_extended_decap(sflow_sample_t* sample, char* prefix);
void sflow_read_extended_vni(sflow_sample_t* sample, char* prefix);
void sflow_read_flow_sample(sflow_sample_t* sample, _Bool is_expanded, uint32_t s_index);
void sflow_read_counters_generic(sflow_sample_t* sample);
void sflow_read_counters_ethernet(sflow_sample_t* sample);
void sflow_read_counters_tokenring(sflow_sample_t* sample);
void sflow_read_counters_vg(sflow_sample_t* sample);
void sflow_read_counters_vlan(sflow_sample_t* sample);
void sflow_read_counters_80211(sflow_sample_t* sample);
void sflow_read_counters_processor(sflow_sample_t* sample);
void sflow_read_counters_port_name(sflow_sample_t* sample);
void sflow_read_counters_radio(sflow_sample_t* sample);
void sflow_read_counters_host_id(sflow_sample_t* sample);
void sflow_read_counters_adapters(sflow_sample_t* sample);
void sflow_read_counters_host_parent(sflow_sample_t* sample);
void sflow_read_counters_host_cpu(sflow_sample_t* sample, uint32_t len);
void sflow_read_counters_host_mem(sflow_sample_t* sample);
void sflow_read_counters_host_disk(sflow_sample_t* sample);
void sflow_read_counters_host_nio(sflow_sample_t* sample);
void sflow_read_counters_host_ip(sflow_sample_t* sample);
void sflow_read_counters_host_icmp(sflow_sample_t* sample);
void sflow_read_counters_host_tcp(sflow_sample_t* sample);
void sflow_read_counters_host_udp(sflow_sample_t* sample);
void sflow_read_counters_host_vnode(sflow_sample_t* sample);
void sflow_read_counters_host_vcpu(sflow_sample_t* sample);
void sflow_read_counters_host_vmem(sflow_sample_t* sample);
void sflow_read_counters_host_vdisk(sflow_sample_t* sample);
void sflow_read_counters_host_vnio(sflow_sample_t* sample);
void sflow_read_counters_gpu_nvml(sflow_sample_t* sample);
void sflow_read_counters_bcm_tables(sflow_sample_t* sample);
void sflow_read_counters_memcache(sflow_sample_t* sample);
void sflow_read_counters_memcache2(sflow_sample_t* sample);
void sflow_read_counters_http(sflow_sample_t* sample);
void sflow_read_counters_jvm(sflow_sample_t* sample);
void sflow_read_counters_jmx(sflow_sample_t* sample, uint32_t len);
void sflow_read_counters_app(sflow_sample_t* sample);
void sflow_read_counters_app_resources(sflow_sample_t* sample);
void sflow_read_counters_app_workers(sflow_sample_t* sample);
void sflow_read_counters_vdi(sflow_sample_t* sample);
void sflow_read_counters_lacp(sflow_sample_t* sample);
void sflow_read_counters_sample(sflow_sample_t* sample, _Bool is_expanded, uint32_t s_index);
void sflow_read_datagram(sflow_sample_t* sample);
void sflow_datagram_receive(sflow_sample_t* sample);

/* END PROTOTYPES */
