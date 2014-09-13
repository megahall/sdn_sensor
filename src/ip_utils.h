#ifndef __IP_UTILS_H__
#define __IP_UTILS_H__

#include <stdint.h>
#include <stdio.h>

/* CONSTANTS */

#define SS_PF_INET   2          /* IPv4 */
#define SS_PF_INET4  2          /* IPv4 */
#define SS_PF_INET6 10          /* IPv6 */
#define SS_AF_INET  SS_PF_INET
#define SS_AF_INET4 SS_PF_INET4
#define SS_AF_INET6 SS_PF_INET6

#define SS_INET6_ADDRSTRLEN  46

/* enough to hold [max_ipv6]/128 plus a bit extra */
#define SS_ADDR_STR_MAX      64
#define SS_V4_PREFIX_MAX     32
#define SS_V6_PREFIX_MAX    128

#define IPV4_ALEN             4
#define IPV6_ALEN            16

/* DATA TYPES */

struct ip4_addr_s {
    uint32_t addr;
};

typedef struct ip4_addr_s ip4_addr_t;

struct ip6_addr_s {
    uint8_t addr[16];
};

typedef struct ip6_addr_s ip6_addr_t;

struct ip_addr_s {
    uint8_t family;
    uint8_t prefix;
    union {
        ip4_addr_t ip4;
        ip6_addr_t ip6;
    } addr;
};
#define ip4_addr addr.ip4
#define ip6_addr addr.ip6

typedef struct ip_addr_s ip_addr_t;

/* BEGIN PROTOTYPES */

int ss_dump_cidr(FILE* fd, const char* label, ip_addr_t* ip_addr);
int ss_parse_cidr(const char* input, ip_addr_t* ip_addr);
int ss_inet_pton(int af, const char* src, ip_addr_t* dst);
int ss_inet_pton4(const char* src, uint8_t* dst);
int ss_inet_pton6(const char* src, uint8_t* dst);
const char* ss_inet_ntop(const ip_addr_t* src, char* dst, unsigned int size);
const char* ss_inet_ntop4(const uint8_t* src, char* dst, unsigned int size);
const char* ss_inet_ntop6(const uint8_t* src, char* dst, unsigned int size);

/* END PROTOTYPES */

#endif
