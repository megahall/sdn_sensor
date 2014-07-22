#ifndef __SS_ICMP6_H__
#define __SS_ICMP6_H__

#include <inttypes.h>

struct icmp6_hdr {
    uint8_t  icmp6_type;
    uint8_t  icmp6_code;
    uint16_t icmp6_cksum;
    union {
        uint32_t un_data32[1];
        uint16_t un_data16[2];
        uint8_t  un_data8[4];
        
        struct icmpv6_echo {
            uint16_t identifier;
            uint16_t sequence;
        } u_echo;
        
        struct icmpv6_nd_advt {
            uint32_t reserved:5,
                     override:1,
                     solicited:1,
                     router:1,
                     reserved2:24;
        } u_nd_advt;
        
        struct icmpv6_nd_ra {
            uint8_t  hop_limit;
            uint8_t  reserved:3,
                     router_pref:2,
                     home_agent:1,
                     other:1,
                     managed:1;
            uint16_t rt_lifetime;
        } u_nd_ra;
    } icmp6_dataun;

#define icmp6_identifier       icmp6_dataun.u_echo.identifier
#define icmp6_sequence         icmp6_dataun.u_echo.sequence
#define icmp6_pointer          icmp6_dataun.un_data32[0]
#define icmp6_mtu              icmp6_dataun.un_data32[0]
#define icmp6_unused           icmp6_dataun.un_data32[0]
#define icmp6_maxdelay         icmp6_dataun.un_data16[0]
#define icmp6_router           icmp6_dataun.u_nd_advt.router
#define icmp6_solicited        icmp6_dataun.u_nd_advt.solicited
#define icmp6_override         icmp6_dataun.u_nd_advt.override
#define icmp6_ndiscreserved    icmp6_dataun.u_nd_advt.reserved
#define icmp6_hop_limit        icmp6_dataun.u_nd_ra.hop_limit
#define icmp6_addrconf_managed icmp6_dataun.u_nd_ra.managed
#define icmp6_addrconf_other   icmp6_dataun.u_nd_ra.other
#define icmp6_rt_lifetime      icmp6_dataun.u_nd_ra.rt_lifetime
#define icmp6_router_pref      icmp6_dataun.u_nd_ra.router_pref
};


#define ICMPV6_ROUTER_PREF_LOW     0x3
#define ICMPV6_ROUTER_PREF_MEDIUM  0x0
#define ICMPV6_ROUTER_PREF_HIGH    0x1
#define ICMPV6_ROUTER_PREF_INVALID 0x2

#define ICMPV6_DEST_UNREACH        1
#define ICMPV6_PKT_TOOBIG          2
#define ICMPV6_TIME_EXCEED         3
#define ICMPV6_PARAMPROB           4

#define ICMPV6_INFOMSG_MASK        0x80

#define ICMPV6_ECHO_REQUEST        128
#define ICMPV6_ECHO_REPLY          129
#define ICMPV6_MGM_QUERY           130
#define ICMPV6_MGM_REPORT          131
#define ICMPV6_MGM_REDUCTION       132

#define ICMPV6_NI_QUERY            139
#define ICMPV6_NI_REPLY            140

#define ICMPV6_MLD2_REPORT         143

#define ICMPV6_DHAAD_REQUEST       144
#define ICMPV6_DHAAD_REPLY         145
#define ICMPV6_MOBILE_PREFIX_SOL   146
#define ICMPV6_MOBILE_PREFIX_ADV   147

/*
 *    Codes for Destination Unreachable
 */
#define ICMPV6_NOROUTE             0
#define ICMPV6_ADM_PROHIBITED      1
#define ICMPV6_NOT_NEIGHBOUR       2
#define ICMPV6_ADDR_UNREACH        3
#define ICMPV6_PORT_UNREACH        4
#define ICMPV6_POLICY_FAIL         5
#define ICMPV6_REJECT_ROUTE        6

/*
 *    Codes for Time Exceeded
 */
#define ICMPV6_EXC_HOPLIMIT        0
#define ICMPV6_EXC_FRAGTIME        1

/*
 *    Codes for Parameter Problem
 */
#define ICMPV6_HDR_FIELD           0
#define ICMPV6_UNK_NEXTHDR         1
#define ICMPV6_UNK_OPTION          2

/*
 *    constants for (set|get)sockopt
 */

#define ICMPV6_FILTER              1

/*
 *    ICMPV6 filter
 */

#define ICMPV6_FILTER_BLOCK        1
#define ICMPV6_FILTER_PASS         2
#define ICMPV6_FILTER_BLOCKOTHERS  3
#define ICMPV6_FILTER_PASSONLY     4

struct icmp6_filter {
    uint32_t data[8];
};

/*
 *    Definitions for MLDv2
 */
#define MLD2_MODE_IS_INCLUDE       1
#define MLD2_MODE_IS_EXCLUDE       2
#define MLD2_CHANGE_TO_INCLUDE     3
#define MLD2_CHANGE_TO_EXCLUDE     4
#define MLD2_ALLOW_NEW_SOURCES     5
#define MLD2_BLOCK_OLD_SOURCES     6

#define MLD2_ALL_MCR_INIT { { { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x16 } } }

/* BEGIN PROTOTYPES */


/* END PROTOTYPES */

#endif /* __SS_ICMP6_H__ */
