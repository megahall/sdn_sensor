#ifndef __IP_UTILS_H__
#define __IP_UTILS_H__

/* CONSTANTS */

#define SS_PF_INET   2          /* IPv4 */
#define SS_PF_INET6 10          /* IPv6 */
#define SS_AF_INET  SS_PF_INET
#define SS_AF_INET6 SS_PF_INET6

#define SS_INET6_ADDRSTRLEN 46

/* BEGIN PROTOTYPES */

int ss_inet_pton(int af, const char* src, void* dst);
int ss_inet_pton4(const char* src, unsigned char* dst);
int ss_inet_pton6(const char* src, unsigned char* dst);

/* END PROTOTYPES */

#endif /* __IP_UTILS_H__ */
