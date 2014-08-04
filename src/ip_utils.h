#ifndef __IP_UTILS_H__
#define __IP_UTILS_H__

#include <stdint.h>
#include <stdio.h>
#include "common.h"

/* CONSTANTS */

#define SS_PF_INET   2          /* IPv4 */
#define SS_PF_INET4  2          /* IPv4 */
#define SS_PF_INET6 10          /* IPv6 */
#define SS_AF_INET  SS_PF_INET
#define SS_AF_INET4 SS_PF_INET4
#define SS_AF_INET6 SS_PF_INET6

#define SS_INET6_ADDRSTRLEN 46

/* BEGIN PROTOTYPES */

int ss_dump_cidr(FILE* fd, const char* label, ip_addr* ip_addr);
int ss_parse_cidr(const char* input, ip_addr* ip_addr);
int ss_inet_pton(int af, const char* src, ip_addr* dst);
int ss_inet_pton4(const char* src, uint8_t* dst);
int ss_inet_pton6(const char* src, uint8_t* dst);
const char* ss_inet_ntop(int af, const void* src, char* dst, unsigned int size);
const char* ss_inet_ntop4(const uint8_t* src, char* dst, unsigned int size);
const char* ss_inet_ntop6(const uint8_t* src, char* dst, unsigned int size);

/* END PROTOTYPES */

#endif /* __IP_UTILS_H__ */
